package clientbinding

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
)

// The relay-engine subprocess backend.
//
// Connect spawns cmd/winn-datapath and drives the Winn v3 duplex frame channel
// over its stdio pipes: Create/CreateAck to bring the tunnel up, Close/CloseAck
// to bring it down. This is the same argv and the same channel every existing
// host drives, so the proof of this backend is the proof of the shipping engine
// rather than of a second implementation.

// engineEnv names the environment variable that locates the relay engine
// binary. It is how a packaged host points this process at the engine it ships,
// and how a test points it at a freshly built one.
const engineEnv = "WINS_WINN3_ENGINE"

// enginePath returns the configured engine path, or "".
func enginePath() string { return os.Getenv(engineEnv) }

// backendIPC reports whether this target can spawn subprocesses at all. iOS
// forbids it and links cdatapath in-process instead, so the relay carrier is
// not available there.
func backendIPC() bool { return runtime.GOOS != "ios" }

// backendOperational reports whether a relay engine can actually be spawned on
// this build right now: the platform allows subprocesses AND an engine binary
// is configured and present. It is the truth TunnelSupported() and
// TunnelBackendJSON() are built from.
func backendOperational() bool {
	return engineOperational(enginePath())
}

// engineOperational is backendOperational for a given engine path, so that
// Connect checks the engine it will actually spawn (the config's "engine"
// override or $WINS_WINN3_ENGINE), not only the environment's.
func engineOperational(path string) bool {
	if !backendIPC() || path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// connectTimeout bounds the wait for CreateAck. A censored path is slow, but a
// host waiting forever looks identical to a hung engine.
const connectTimeout = 35 * time.Second

// closeTimeout bounds the wait for CloseAck.
const closeTimeout = 10 * time.Second

// processExitWait bounds the wait for the engine process to exit after Close.
const processExitWait = 5 * time.Second

// sessionMu guards the singleton session. This facade carries exactly one
// tunnel at a time, mirroring a host with one device.
var sessionMu sync.Mutex

// active is the live tunnel, or nil.
var active *engineSession

// duplexFrame is one engine-to-host frame produced by the routing goroutine.
type duplexFrame struct {
	opcode  duplex.Opcode
	payload []byte
}

// engineSession owns one engine subprocess and its frame channel.
type engineSession struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	file  *os.File // the handed-over socket, if any; closed on teardown

	writer *duplex.Writer

	mu     sync.Mutex
	status string

	resp     chan duplexFrame
	fatal    chan error
	closeAck chan struct{}
	done     chan struct{}
}

// route drains the engine's stdout and demultiplexes frames. It is the only
// reader of the stream: duplex.Reader latches its first terminal error, so
// exactly one goroutine must own it.
//
// Outbound frames (inner packets toward the host device) are dropped here.
// This backend establishes and carries the tunnel but does not yet install a
// platform device on any build, so there is nowhere to deliver them; they must
// not be buffered without a consumer.
func (e *engineSession) route(stdout io.Reader) {
	reader := duplex.NewReader(stdout, true)
	defer close(e.done)
	for {
		opcode, payload, err := reader.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				select {
				case e.fatal <- err:
				case <-e.done:
				}
			}
			return
		}
		switch opcode {
		case duplex.OpCreateAck, duplex.OpStatusResponse:
			copyPayload := make([]byte, len(payload))
			copy(copyPayload, payload)
			e.setStatus(string(copyPayload))
			select {
			case e.resp <- duplexFrame{opcode: opcode, payload: copyPayload}:
			case <-e.done:
				return
			}
		case duplex.OpCloseAck:
			select {
			case e.closeAck <- struct{}{}:
			case <-e.done:
				return
			}
		case duplex.OpError:
			select {
			case e.fatal <- errors.New(string(payload)):
			case <-e.done:
				return
			}
		case duplex.OpOutbound:
			// no platform device: drop, never buffer without a consumer.
		}
	}
}

func (e *engineSession) setStatus(status string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status = status
}

func (e *engineSession) currentStatus() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

// spawnEngine starts the relay engine and returns once the process is running
// and its frame channel is being drained.
//
// Under -transport stdio the engine opens its own outer socket when the create
// document sets allow_own_socket, OR adopts a descriptor handed over as -udp-fd
// 3 (socketFD >= 0) with allow_own_socket=false. Both are real shapes.
func spawnEngine(engine, keys string, socketFD int) (*engineSession, error) {
	argv := []string{"-transport", "stdio", "-winn3", "-winn3-keys", keys}
	if socketFD >= 0 {
		// ExtraFiles[0] is inherited by the child as fd 3, which is why the
		// engine is told -udp-fd 3.
		argv = append(argv, "-udp-fd", "3")
	}
	cmd := exec.Command(engine, argv...)
	cmd.Stderr = os.Stderr
	var file *os.File
	if socketFD >= 0 {
		file = os.NewFile(uintptr(socketFD), "winn3-engine-socket")
		if file == nil {
			return nil, errors.New("winn v3: engine socket descriptor is not usable")
		}
		cmd.ExtraFiles = []*os.File{file}
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}

	// The binding takes plain ownership of the supplied descriptor: it is now
	// the sole party responsible for closing it, in teardown (reached from
	// Disconnect). The child inherited its own duplicate as fd 3 when Start
	// dup'd ExtraFiles, so closing our copy here never strands the live socket
	// while the tunnel is up.
	sess := &engineSession{
		cmd:      cmd,
		stdin:    stdin,
		file:     file,
		writer:   duplex.NewWriter(stdin),
		resp:     make(chan duplexFrame, 64),
		fatal:    make(chan error, 16),
		closeAck: make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	go sess.route(stdout)
	return sess, nil
}

// teardown sends Close, waits for CloseAck, then reaps the process. It is
// idempotent in effect and is called on every exit path, including a failed
// Connect.
func (e *engineSession) teardown() error {
	result := error(nil)
	if e.writer != nil {
		if err := e.writer.Write(duplex.OpClose, nil); err != nil {
			result = err
		}
		select {
		case <-e.closeAck:
		case err := <-e.fatal:
			if result == nil && err != nil {
				result = err
			}
		case <-e.done:
			// The engine's stdout closed: no CloseAck can follow one route
			// has not already queued, so do not wait out the close budget.
			select {
			case <-e.closeAck:
			case err := <-e.fatal:
				if result == nil && err != nil {
					result = err
				}
			default:
				if result == nil {
					result = errors.New("winn v3: relay engine exited before CloseAck")
				}
			}
		case <-time.After(closeTimeout):
			if result == nil {
				result = errors.New("winn v3: no CloseAck within the close budget")
			}
		}
	}
	if e.stdin != nil {
		if err := e.stdin.Close(); result == nil && err != nil {
			result = err
		}
	}
	if e.cmd != nil && e.cmd.Process != nil {
		waitDone := make(chan struct{})
		go func() {
			_ = e.cmd.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(processExitWait):
			_ = e.cmd.Process.Kill()
			<-waitDone
		}
	}
	if e.done != nil {
		<-e.done
	}
	if e.file != nil {
		_ = e.file.Close()
	}
	return result
}

// parseConnectConfig decodes and validates the Connect document. Unknown
// fields are refused rather than dropped.
func parseConnectConfig(document string) (connectConfig, error) {
	// encoding/json leaves an omitted int at 0, and 0 is stdin. spawnEngine
	// treats EngineSocketFD >= 0 as "hand this descriptor to the child as
	// fd 3", so the omit case must be a negative sentinel, not the zero
	// value. An explicit 0 in the document still decodes as 0.
	cfg := connectConfig{EngineSocketFD: -1}
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if len(cfg.Create) == 0 {
		return cfg, errors.New("connect config requires a create document")
	}
	return cfg, nil
}
