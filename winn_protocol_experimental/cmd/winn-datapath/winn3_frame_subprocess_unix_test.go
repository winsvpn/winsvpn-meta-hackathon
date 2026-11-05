//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The subprocess proof: TWO REAL PROCESSES, started with the argv a host builds.
//
// TestTwoFrameHostsCarryPacketsAcrossARekeyAndAMigration proves the seam's
// behaviour in one address space, where a test can reach a Loop and force a
// migration. This proves the part that cannot be faked in-process: that the
// SHIPPING BINARY, launched with the tokens WinnV3Host.engineArguments builds,
// receives a protected socket over SCM_RIGHTS, speaks the frame channel, and
// carries inner IP packets between two of itself with matching digests.
//
// LOOPBACK ONLY: both carrier sockets bind 127.0.0.1 explicitly, the control
// sockets are unix paths under a temporary directory, and no interface, route or
// utun device on this machine is touched.
func TestTheBinaryCarriesInnerPacketsBetweenTwoHostsOverSCMRights(t *testing.T) {
	binary := buildBinary(t)
	ring := newFrameKeyring(t)

	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}

	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)

	client := startSubprocessEngine(t, binary, ring.clientPath, clientSock)
	gateway := startSubprocessEngine(t, binary, ring.gatewayPath, gatewaySock)

	client.create(t, frameCreate(gatewayAddr, "10.8.1.3", "10.8.1.1", sizing, pathMTU))
	gateway.create(t, frameCreate(clientAddr, "10.8.1.1", "10.8.1.3", sizing, pathMTU))

	ack := client.expectStatus(t, duplex.OpCreateAck)
	if ack.InnerMTU != sizing.InnerMTU || ack.MessageSize != sizing.MessageSize {
		t.Fatalf("CreateAck published inner_mtu=%d message_size=%d, want %d/%d",
			ack.InnerMTU, ack.MessageSize, sizing.InnerMTU, sizing.MessageSize)
	}
	if ack.PromotionReady {
		t.Fatal("the tunnel offered promotion before a packet had arrived")
	}
	_ = gateway.expectStatus(t, duplex.OpCreateAck)

	// A FULL-SIZE inner packet: the one a tunnel sized to its dialled carrier
	// black-holes and a tunnel sized to the plan floor carries.
	full := make([]byte, sizing.InnerMTU-28)
	for i := range full {
		full[i] = byte(i*7 + 3)
	}
	want := digestOf(full)
	packet := ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, full)

	got := client.carryTo(t, gateway, packet, 60*time.Second)
	if d := digestOf(payloadOf(got)); d != want {
		t.Fatalf("the packet arrived with digest %s, want %s", d, want)
	}
	if len(got) != sizing.InnerMTU {
		t.Fatalf("the packet arrived as %d bytes, want the %d-byte floor inner MTU",
			len(got), sizing.InnerMTU)
	}

	reply := []byte("subprocess reply across the frame seam")
	back := gateway.carryTo(t, client, ipv4Packet(
		[4]byte{10, 8, 1, 1}, [4]byte{10, 8, 1, 3}, reply), 30*time.Second)
	if d := digestOf(payloadOf(back)); d != digestOf(reply) {
		t.Fatal("the reply digest does not match")
	}

	// The promotion gate, read exactly as WinnV3StagedStart reads it.
	client.send(t, duplex.OpStatusRequest, nil)
	status := client.expectStatus(t, duplex.OpStatusResponse)
	if !status.PromotionReady || status.GateState != tun.StateCarrying.String() ||
		status.RxPackets == 0 {
		t.Fatalf("the status a host promotes on is wrong: %+v", status)
	}

	client.send(t, duplex.OpClose, nil)
	client.expectCloseAck(t)
	gateway.send(t, duplex.OpClose, nil)
	gateway.expectCloseAck(t)
}

// TestTheBinaryRefusesV3WithoutAKeyDocument is the argv half of the fail-closed
// property: a process told to speak v3 and given no key document must exit,
// not fall through to the relay path.
func TestTheBinaryRefusesV3WithoutAKeyDocument(t *testing.T) {
	binary := buildBinary(t)
	output, err := exec.Command(binary, "-transport", "stdio", "-winn3").CombinedOutput()
	if err == nil {
		t.Fatalf("-winn3 without -winn3-keys started: %s", output)
	}
	if !bytes.Contains(output, []byte("-winn3 needs -winn3-keys")) {
		t.Fatalf("the refusal does not name the missing flag: %s", output)
	}
	// And it names the argv a host must build, so the next lane does not have
	// to read this file to find out.
	if !bytes.Contains(output, []byte("-transport unix -control @NAME")) {
		t.Fatalf("the refusal does not name the argv: %s", output)
	}
}

// --- fixture -------------------------------------------------------------------

// subprocessEngine is one launched binary and the host end of its control
// socket.
//
// The frames are read by a DEDICATED GOROUTINE with no read deadline, because
// duplex.Reader latches its first terminal error on purpose: rejecting a bad
// header still consumes its 16 bytes, so a reader that resynchronised would hand
// back an attacker-chosen frame boundary. A per-read deadline would therefore
// kill the channel the first time nothing was in flight — which is exactly what
// a host waiting through a handshake does.
type subprocessEngine struct {
	control *net.UnixConn
	writer  *duplex.Writer
	stderr  *bytes.Buffer

	acks     chan winn3Status
	statuses chan winn3Status
	outbound chan []byte
	errs     chan string
	closeAck chan struct{}
}

func (e *subprocessEngine) readFrames() {
	reader := duplex.NewReader(e.control, true)
	for {
		opcode, payload, err := reader.Read()
		if err != nil {
			return
		}
		switch opcode {
		case duplex.OpCreateAck, duplex.OpStatusResponse:
			var status winn3Status
			if json.Unmarshal(payload, &status) != nil {
				continue
			}
			sink := e.statuses
			if opcode == duplex.OpCreateAck {
				sink = e.acks
			}
			select {
			case sink <- status:
			default:
			}
		case duplex.OpOutbound:
			select {
			case e.outbound <- append([]byte(nil), payload...):
			default:
			}
		case duplex.OpError:
			select {
			case e.errs <- string(payload):
			default:
			}
		case duplex.OpCloseAck:
			select {
			case e.closeAck <- struct{}{}:
			default:
			}
		}
	}
}

// startSubprocessEngine launches the binary with the ANDROID ARGV.
//
//	engine -transport unix -control PATH -receive-fd -winn3 -winn3-keys PATH
//
// which is WinnAndroidEngineHost.engineArguments plus WinnV3Host.FLAG_WINN3,
// plus the one token this seam adds. The host LISTENS and the engine DIALS,
// which is the direction WinnV3Host records, and the protected socket crosses
// as SCM_RIGHTS ancillary data because a pipe cannot carry a descriptor.
func startSubprocessEngine(
	t *testing.T, binary, keysPath string, socket *net.UDPConn,
) *subprocessEngine {
	t.Helper()

	controlPath := shortSocketPath(t)
	listener, err := net.Listen("unix", controlPath)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	handOver, err := socket.File()
	if err != nil {
		t.Fatalf("duplicate the carrier socket: %v", err)
	}
	t.Cleanup(func() { _ = handOver.Close() })

	command := exec.Command(binary,
		"-transport", "unix", "-control", controlPath, "-receive-fd",
		"-winn3", "-winn3-keys", keysPath)
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept control connection: %v (stderr: %s)", err, stderr)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	control, ok := accepted.(*net.UnixConn)
	if !ok {
		t.Fatal("the accepted connection is not a unix socket")
	}

	rights := syscall.UnixRights(int(handOver.Fd()))
	if _, _, err := control.WriteMsgUnix([]byte{0}, rights, nil); err != nil {
		t.Fatalf("send the protected descriptor: %v", err)
	}
	// The host's own copy goes now: the engine owns the socket from here, which
	// is the same lifetime ParcelFileDescriptor.fromDatagramSocket establishes.
	_ = socket.Close()

	engine := &subprocessEngine{
		control:  control,
		writer:   duplex.NewWriter(control),
		stderr:   stderr,
		acks:     make(chan winn3Status, 8),
		statuses: make(chan winn3Status, 64),
		outbound: make(chan []byte, 512),
		errs:     make(chan string, 64),
		closeAck: make(chan struct{}, 1),
	}
	go engine.readFrames()
	return engine
}

func (e *subprocessEngine) send(t *testing.T, opcode duplex.Opcode, payload []byte) {
	t.Helper()
	if err := e.writer.Write(opcode, payload); err != nil {
		t.Fatalf("write %s: %v (stderr: %s)", opcode, err, e.stderr)
	}
}

func (e *subprocessEngine) create(t *testing.T, document []byte) {
	t.Helper()
	e.send(t, duplex.OpCreate, document)
}

// expectStatus waits for one CreateAck or StatusResponse. An Error frame is
// reported with its text, because a refusal that arrives as a timeout is a
// refusal nobody can act on.
func (e *subprocessEngine) expectStatus(
	t *testing.T, want duplex.Opcode,
) winn3Status {
	t.Helper()
	sink := e.statuses
	if want == duplex.OpCreateAck {
		sink = e.acks
	}
	select {
	case status := <-sink:
		return status
	case refusal := <-e.errs:
		t.Fatalf("the engine refused: %s (stderr: %s)", refusal, e.stderr)
	case <-time.After(30 * time.Second):
		t.Fatalf("no %s within 30s (stderr: %s)", want, e.stderr)
	}
	return winn3Status{}
}

func (e *subprocessEngine) expectCloseAck(t *testing.T) {
	t.Helper()
	select {
	case <-e.closeAck:
	case <-time.After(20 * time.Second):
		t.Fatalf("no CloseAck within 20s (stderr: %s)", e.stderr)
	}
}

// carryTo offers one inner packet and reads it out of the far process.
//
// Retried while the handshake completes: a packet offered before the gate opens
// is dropped FAIL-CLOSED by design, and a test that treated that as a failure
// would be asserting the opposite of the property.
func (e *subprocessEngine) carryTo(
	t *testing.T, to *subprocessEngine, packet []byte, within time.Duration,
) []byte {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		e.send(t, duplex.OpInbound, packet)
		select {
		case got := <-to.outbound:
			return got
		case refusal := <-to.errs:
			t.Fatalf("the far engine refused an inner packet: %s", refusal)
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing reached the far process within %s (stderr: %s / %s)",
				within, e.stderr, to.stderr)
		}
	}
}
