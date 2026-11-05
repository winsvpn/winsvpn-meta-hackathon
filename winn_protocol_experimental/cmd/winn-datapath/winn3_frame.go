package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/dualsign"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The winn/3 frame mode: -winn3.
//
// # What it is
//
// The same duplex frame channel every host already drives for winn/1, carrying
// a different payload. The host owns the tun device; Inbound frames are inner IP
// packets on their way out and Outbound frames are inner IP packets on their way
// in. Create, CreateAck, StatusRequest, StatusResponse, Close, CloseAck and
// Error keep their meanings exactly.
//
// No new opcode, no second framing, no second channel. WINN3_ANDROID_INTEGRATION
// §2.1 reached this by elimination: Android must replace its tun descriptor at
// promotion because there is no API to reconfigure a live VpnService, and
// tun.Config.Device is fixed at tun.New, so a descriptor handed over at create
// time is stale exactly when the tunnel starts working. A channel-backed device
// survives that; a descriptor does not.
//
// # Why this is not a fallback for the desktop hosts
//
// It is the seam, and the two descriptor-based backends in this package
// (loopback-udp, tun-fd, both under -winn3-profile) are optimisations of it for
// hosts that can pass one. Every host that already runs this binary already
// speaks these frames, so frame mode is the one path that needs nothing new on
// any platform. Linux should still prefer tun-fd, where no inner packet crosses
// a socket in cleartext at all.
//
// # The fail-closed property this mode must not lose
//
// There is NO path in this file that falls back to datapath.Open. A -winn3
// process that cannot build a v3 tunnel writes an Error frame and stays without
// one. Starting a relay session in its place would take a session the gateway
// negotiated as winn/3 and put classical AmneziaWG on the wire with nobody told,
// which on this threat model is the worst available outcome and is the exact
// defect found in the Apple providers. WinnV3Host.NO_V3_ENGINE is the host half
// of the same refusal.

// winn3FrameDialTimeout bounds one outer dial. Generous because a censored path
// is slow, bounded because a host waiting forever on a CreateAck looks identical
// to a hung engine.
const winn3FrameDialTimeout = 30 * time.Second

// winn3FrameCloseGrace bounds the wait for the loop to finish after Close.
//
// The driver owns one goroutine per tunnel that can outlive Run if the host
// never closes its device. It cannot move a byte. Waiting forever here would
// turn that known cost into a hang in the host's stopTunnel, which is worse.
const winn3FrameCloseGrace = 2 * time.Second

// winn3RefuseMixedFrameModes is the frame mode's half of the flag rules.
//
// The winn/1 carrier flags are refused for the reason the mode exists:
// -carrier-profile builds an AmneziaWG relay carrier, and v3 replaces AmneziaWG
// outright. A process that had both configured would have two opinions about
// what its payloads are, and the failure mode of guessing wrong is cleartext on
// the wire.
func winn3RefuseMixedFrameModes(opts options, v3 winn3Options) error {
	switch {
	case v3.keys == "":
		return errors.New(
			"-winn3 needs -winn3-keys PATH: the static key, the gateway's " +
				"static key and the admission secret are named by a document " +
				"this process opens itself, because a channel whose payload is " +
				"peer-supplied by construction is not where key material " +
				"belongs. Desktop: -transport stdio -winn3 -winn3-keys PATH. " +
				"Android: -transport unix -control @NAME -receive-fd -winn3 " +
				"-winn3-keys PATH")
	case opts.carrierProfile != "":
		return errors.New(
			"-carrier-profile is a winn/1 carrier and -winn3 is the standalone " +
				"v3 protocol; they are different protocols and this process " +
				"runs one of them")
	case len(opts.carrierFallback) > 0:
		return errors.New("-carrier-fallback is winn/1 only")
	case v3.tunFD >= 0:
		return errors.New(
			"-winn3-tun-fd is the desktop mode's descriptor hand-off; in " +
				"-winn3 frame mode the HOST owns the tun device and pumps " +
				"inner IP packets over the Inbound and Outbound frames, which " +
				"is what lets Android replace its descriptor at promotion " +
				"without the engine noticing")
	case v3.printSizing:
		return errors.New(
			"-winn3-print-sizing is the desktop mode's pre-start hook; in " +
				"-winn3 frame mode the plan comes from the Create frame's " +
				"carrier_classes, so there is no floor to compute until the " +
				"host has sent one. The CreateAck carries inner_mtu and " +
				"message_size, and a create whose inner_mtu is not the floor " +
				"is refused rather than accepted")
	case opts.udpFD >= 0 && opts.receiveFD:
		return errors.New("-receive-fd and -udp-fd are mutually exclusive")
	}
	return nil
}

// runWinn3Frames is the frame mode's entry point.
//
// It mirrors the winn/1 transport selection exactly, because it is the same
// channel: stdio is the Windows shape and unix is the Android one, and only unix
// can carry a descriptor.
func runWinn3Frames(ctx context.Context, opts options, v3 winn3Options) error {
	keys, err := loadWinn3Keys(v3.keys)
	if err != nil {
		return err
	}
	// Modes and roles only. The document names private files and must never be
	// logged whole.
	fmt.Fprintln(os.Stderr, "winn-datapath: "+keys.describeForLog())

	switch opts.transport {
	case "stdio":
		if opts.receiveFD {
			return errors.New(
				"-receive-fd needs -transport unix: a descriptor cannot be " +
					"passed over a pipe")
		}
		if opts.control != "" {
			return errors.New("-control applies only to -transport unix")
		}
		return serveWinn3Frames(ctx, os.Stdin, os.Stdout, keys, opts.udpFD)
	case "unix":
		return runWinn3FramesUnix(ctx, opts, keys)
	default:
		return fmt.Errorf("unknown -transport %q; use stdio or unix", opts.transport)
	}
}

func runWinn3FramesUnix(
	ctx context.Context, opts options, keys winn3Keys,
) error {
	if opts.control == "" {
		return errors.New("-transport unix requires -control PATH")
	}
	conn, err := net.Dial("unix", opts.control)
	if err != nil {
		return fmt.Errorf("connect control socket %q: %w", opts.control, err)
	}
	defer func() { _ = conn.Close() }()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("control socket %q is not a unix stream socket", opts.control)
	}
	_ = unixConn.SetReadBuffer(16 * 1024 * 1024)
	_ = unixConn.SetWriteBuffer(16 * 1024 * 1024)
	descriptor := opts.udpFD
	tcpDescriptor := -1
	channelDescriptor := -1
	if opts.receiveFD {
		descriptor, tcpDescriptor, channelDescriptor, err = receiveV3Descriptors(unixConn)
		if err != nil {
			return err
		}
	}
	var tcpChannel *net.UnixConn
	if channelDescriptor >= 0 {
		file := os.NewFile(uintptr(channelDescriptor), "winn3-tcp-requests")
		channel, channelErr := net.FileConn(file)
		_ = file.Close()
		if channelErr != nil {
			return fmt.Errorf("adopt protected TCP request channel: %w", channelErr)
		}
		var ok bool
		tcpChannel, ok = channel.(*net.UnixConn)
		if !ok {
			_ = channel.Close()
			return errors.New("protected TCP request channel is not a unix socket")
		}
		defer tcpChannel.Close()
	}
	err = serveWinn3FramesWithChannel(ctx, unixConn, unixConn, keys, descriptor, tcpChannel, tcpDescriptor)
	if err != nil && errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// winn3FrameServer is one frame conversation.
//
// One create is one tunnel for the life of the conversation, but not one
// session. A driver.Reconnect supervises it: when a round's session dies the
// supervisor retires that round and builds a fresh session on a fresh carrier
// wrapper over the SAME adopted socket, while the host's tun and its frame
// stream stay open. loop and device are the CURRENT round's; everything a host
// can reach (activeDevice, the pump, statusJSON, shutdown) follows them.
type winn3FrameServer struct {
	keys winn3Keys

	// material is this tunnel generation's recovery copy of the key files,
	// read once by open. Every round after the first builds its session from
	// it and never from the paths, because the Android host erases those files
	// right after CreateAck; see winn3KeyMaterial. It is wiped as soon as no
	// successor can be built: by shutdown right after cancelling (before the
	// bounded wait for the supervisor), and by the supervisor when Run
	// returns. A round asked for after that is refused as terminal.
	materialMu sync.Mutex
	material   winn3KeyMaterial

	// descriptor is the protected outer socket the host handed over, or -1.
	// outerSocket consumes it exactly once; the number is never used again.
	descriptor    int
	tcpDescriptor int
	tcpChannel    *net.UnixConn
	tcpRequestMu  sync.Mutex

	writer *duplex.Writer

	mu        sync.Mutex
	round     *winn3FrameRound
	loop      *driver.Loop
	device    *winn3FrameDevice
	sizing    driver.Sizing
	sessionID string
	cancel    context.CancelFunc
	superDone chan struct{}

	// socket is the adopted (or dialled) outer socket. Every round's carrier
	// wrapper borrows it with OwnsConn false; closeSocket closes it once, when
	// the supervisor finishes.
	socket       *net.UDPConn
	socketOnce   sync.Once
	socketCloses atomic.Int32

	activeDevice atomic.Pointer[winn3FrameDevice]
	runErr       atomic.Pointer[error]
	closed       atomic.Bool

	// recovering is true from a round's end until its successor is published.
	// While it holds, the dead round's counters are not published and a host
	// packet the dead round's device refuses is dropped rather than reported.
	recovering atomic.Bool

	// rounds counts published rounds; droppedRecovering counts host packets
	// dropped while no round was carrying.
	rounds            atomic.Uint64
	droppedRecovering atomic.Uint64

	// roundEnded is set when any round has ended, everProven when a round
	// that ended had delivered, and finished when the supervisor has
	// returned; all guarded by mu. With recovering they are the lifecycle the
	// status document publishes; see driver.Lifecycle.
	roundEnded bool
	everProven bool
	finished   bool

	// sessionTweak, when set, edits every round's session configuration just
	// before the loop is built. Tests only: it is how a test shortens the
	// handshake budget or the liveness probes without a wall-clock wait. Nil
	// in every production path.
	sessionTweak func(*session.Config)

	// statusHook runs in statusJSON right after the owner snapshot is taken
	// and s.mu released; roundEndHook runs in a round's Run after its loop has
	// returned (gate latched down) and before the round's end is recorded.
	// Tests only: they pause the two windows a status can straddle. Nil in
	// every production path.
	statusHook   func()
	roundEndHook func()
}

// serveWinn3Frames runs one conversation to completion.
//
// It returns nil for an orderly shutdown (a Close frame or a clean EOF) and
// always tears the tunnel down before returning, so a host that dies mid-session
// cannot leave a datapath running.
func serveWinn3Frames(
	ctx context.Context,
	input io.Reader,
	output io.Writer,
	keys winn3Keys,
	descriptor int,
	tcpDescriptor ...int,
) error {
	return serveWinn3FramesWithChannel(ctx, input, output, keys, descriptor, nil, tcpDescriptor...)
}

func serveWinn3FramesWithChannel(
	ctx context.Context, input io.Reader, output io.Writer, keys winn3Keys,
	descriptor int, tcpChannel *net.UnixConn, tcpDescriptor ...int,
) error {
	if input == nil || output == nil {
		return errors.New("winn3 frame mode requires both streams")
	}
	bufInput := bufio.NewReaderSize(input, 4*1024*1024)
	bufOutput := bufio.NewWriterSize(output, 4*1024*1024)
	server := newWinn3FrameServer(keys, descriptor, bufOutput, tcpDescriptor...)
	server.tcpChannel = tcpChannel
	defer server.shutdown()
	return server.serve(ctx, bufInput)
}

// newWinn3FrameServer builds one conversation's state.
//
// Separate from serveWinn3Frames so that an end-to-end test can hold the server
// and reach the loop for a migration, which has no frame-channel control today.
func newWinn3FrameServer(
	keys winn3Keys, descriptor int, output io.Writer, tcpDescriptor ...int,
) *winn3FrameServer {
	streamFD := -1
	if len(tcpDescriptor) > 0 {
		streamFD = tcpDescriptor[0]
	}
	return &winn3FrameServer{
		keys:          keys,
		descriptor:    descriptor,
		tcpDescriptor: streamFD,
		writer:        duplex.NewWriter(output),
	}
}

func allocPacket(src []byte) []byte {
	var cp []byte
	if len(src) <= 2048 {
		bp := packetPool.Get().(*[2048]byte)
		cp = bp[:len(src)]
	} else {
		cp = make([]byte, len(src))
	}
	copy(cp, src)
	return cp
}

func (s *winn3FrameServer) flushInboundBatch(batch *[][]byte) error {
	if len(*batch) == 0 {
		return nil
	}
	device := s.activeDevice.Load()
	if device == nil {
		for _, pkt := range *batch {
			if cap(pkt) == 2048 {
				bp := (*[2048]byte)(pkt[:2048])
				packetPool.Put(bp)
			}
		}
		*batch = (*batch)[:0]
		return s.writer.Write(duplex.OpError, []byte("inbound inner packet before create"))
	}
	packets := len(*batch)
	err := device.offerBatch(*batch)
	*batch = (*batch)[:0]
	if err != nil {
		if s.recoveryAbsorbs(device, err, packets) {
			return nil
		}
		return s.writer.Write(duplex.OpError, []byte(err.Error()))
	}
	return nil
}

// recoveryAbsorbs reports whether a refusal from a round's device is only the
// recovery window: that round died and the supervisor is building, or has just
// published, its successor. The packets are dropped and counted, which keeps
// host submissions bounded with nothing queued for a round that does not exist
// yet, and no Error frame is written, because a host reads a closed-device
// Error as the end of the tunnel.
//
// The successor check is what makes the race safe: publish stores the new
// device before it clears recovering, so a submission that loaded the old
// device and lost the race sees one or the other.
func (s *winn3FrameServer) recoveryAbsorbs(
	device *winn3FrameDevice, err error, packets int,
) bool {
	if !errors.Is(err, errWinn3DeviceClosed) || s.closed.Load() {
		return false
	}
	if !s.recovering.Load() && s.activeDevice.Load() == device {
		return false
	}
	s.droppedRecovering.Add(uint64(packets))
	return true
}

// maxInboundBatchPackets mirrors the Kotlin uplink batch packetCapacity.
// It is a slice sizing hint, not a wire value: frames remain independently
// length-prefixed, so the two sides drifting apart wastes capacity and
// nothing more.
const maxInboundBatchPackets = 512

// frameReady reports whether one complete framed message is already buffered
// in the bufio.Reader, ensuring the next read will not block.
func frameReady(r *bufio.Reader) bool {
	if r == nil {
		return false
	}
	if r.Buffered() < duplex.HeaderSize {
		return false
	}
	h, err := r.Peek(duplex.HeaderSize)
	if err != nil {
		return false
	}
	return r.Buffered() >= duplex.HeaderSize+duplex.PayloadLength(h)
}

// serve reads frames until the channel ends.
func (s *winn3FrameServer) serve(ctx context.Context, input io.Reader) error {
	// false: this is the engine, so only host-to-engine opcodes are accepted.
	// Getting this backwards rejects every frame immediately.
	reader := duplex.NewReader(input, false)
	bufInput, _ := input.(*bufio.Reader)
	inboundBatch := make([][]byte, 0, maxInboundBatchPackets)
	defer func() {
		_ = s.flushInboundBatch(&inboundBatch)
	}()

	for {
		if s.closed.Load() {
			return nil
		}
		opcode, payload, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// The channel is already untrustworthy, so telling the peer why is
			// best effort. It is still worth doing: a host that logs the Error
			// payload gets the real reason instead of a bare broken pipe.
			_ = s.writer.Write(duplex.OpError, []byte(err.Error()))
			return err
		}

		if opcode == duplex.OpInbound {
			inboundBatch = append(inboundBatch, allocPacket(payload))
			if len(inboundBatch) >= maxInboundBatchPackets {
				if err := s.flushInboundBatch(&inboundBatch); err != nil {
					return err
				}
			}
		} else {
			if len(inboundBatch) > 0 {
				if err := s.flushInboundBatch(&inboundBatch); err != nil {
					return err
				}
			}
			done, err := s.handle(ctx, opcode, payload)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}

		// Round 46 Treaty (OI-2): flush partial batch immediately before potentially
		// blocking on the next Unix socket read if the buffer does not contain a full frame.
		if len(inboundBatch) > 0 && !frameReady(bufInput) {
			if err := s.flushInboundBatch(&inboundBatch); err != nil {
				return err
			}
		}

		if bufInput != nil {
			for !s.closed.Load() {
				if !frameReady(bufInput) {
					break
				}
				op, pay, err := reader.Read()
				if err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					_ = s.writer.Write(duplex.OpError, []byte(err.Error()))
					return err
				}
				if op == duplex.OpInbound {
					inboundBatch = append(inboundBatch, allocPacket(pay))
					if len(inboundBatch) >= maxInboundBatchPackets {
						if err := s.flushInboundBatch(&inboundBatch); err != nil {
							return err
						}
					}
				} else {
					if len(inboundBatch) > 0 {
						if err := s.flushInboundBatch(&inboundBatch); err != nil {
							return err
						}
					}
					d, err := s.handle(ctx, op, pay)
					if err != nil || d {
						return err
					}
				}
			}
		}

		if len(inboundBatch) > 0 {
			if err := s.flushInboundBatch(&inboundBatch); err != nil {
				return err
			}
		}
	}
}

func (s *winn3FrameServer) handle(
	ctx context.Context, opcode duplex.Opcode, payload []byte,
) (bool, error) {
	switch opcode {
	case duplex.OpCreate:
		return false, s.handleCreate(ctx, payload)
	case duplex.OpInbound:
		return false, s.handleInbound(payload)
	case duplex.OpStatusRequest:
		return false, s.writer.Write(
			duplex.OpStatusResponse, []byte(s.statusJSON("posture")))
	case duplex.OpClose:
		fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.handle] received OpClose from host\n")
		// CloseAck carries no payload by the normative framing. A host that
		// wants final counters sends StatusRequest before Close.
		s.shutdown()
		return true, s.writer.Write(duplex.OpCloseAck, nil)
	default:
		// The reader already rejected unknown and wrong-direction opcodes, so
		// reaching here means this switch and the opcode table disagree.
		return false, fmt.Errorf("unhandled duplex opcode %s", opcode)
	}
}

// handleCreate builds the tunnel, or refuses and builds nothing.
//
// A refusal is an Error frame and NOT a session failure: the host is told why
// and the channel stays open so it can be told again if it retries. What a
// refusal never is, in this file, is a relay tunnel.
func (s *winn3FrameServer) handleCreate(ctx context.Context, payload []byte) error {
	s.mu.Lock()
	already := s.cancel != nil
	s.mu.Unlock()
	if already {
		return s.writer.Write(duplex.OpError, []byte(
			"this session already has an open winn/3 tunnel; one session "+
				"carries exactly one tunnel"))
	}

	// The reader's buffer is reused by the next Read, so the document must be
	// copied before anything can block on it.
	document := append([]byte(nil), payload...)
	if err := s.open(ctx, document); err != nil {
		return s.writer.Write(duplex.OpError, []byte(err.Error()))
	}
	return s.writer.Write(duplex.OpCreateAck, []byte(s.statusJSON("posture")))
}

// open is the whole of create with no framing in it, so every refusal is
// reachable from an ordinary test.
func (s *winn3FrameServer) open(ctx context.Context, document []byte) error {
	plan, err := decodeWinn3Create(
		document, s.descriptor >= 0, s.keys.exclusionDeclared())
	if err != nil {
		return err
	}

	// Read once, here, while the host's files still hold the keys. Every
	// refusal below clears what was acquired: the material, and the first
	// round's own secret copies.
	material, err := s.keys.readMaterial()
	if err != nil {
		return err
	}
	sessionConfig, _, roundSecrets, err := s.keys.sessionConfigFrom(&material)
	if err != nil {
		material.wipe()
		return err
	}
	if err := requireLiveDualAuth(s.keys, sessionConfig); err != nil {
		roundSecrets.clearAll()
		material.wipe()
		return err
	}

	// Everything that can fail without touching the network has now failed. A
	// refusal after the socket is open is a refusal the host has already told
	// its user about.
	socket, err := s.outerSocket(ctx, plan)
	if err != nil {
		roundSecrets.clearAll()
		material.wipe()
		return err
	}

	// The FIRST round is built here, synchronously, so that every refusal it
	// can produce still reaches the host as the Error frame answering Create.
	// Later rounds are the supervisor's.
	runCtx, cancel := context.WithCancel(ctx)
	first, err := s.buildRound(runCtx, plan, socket, sessionConfig, roundSecrets)
	if err != nil {
		cancel()
		_ = socket.Close()
		material.wipe()
		return err
	}

	handed := false
	supervisor, err := driver.NewReconnect(driver.ReconnectConfig{
		Build: func() (driver.Runner, error) {
			if !handed {
				handed = true
				return first, nil
			}
			return s.nextRound(runCtx, plan, socket)
		},
		Attempts:   carrier.DefaultBackoffAttempts,
		ResetAfter: driver.DefaultReconnectResetAfter,
		Terminal:   driver.TerminalRoundError,
		// A client that has never once established reports that now rather
		// than after five more handshake budgets. A gateway round waits for a
		// client by design, so the gateway role keeps the plain budget.
		FailBeforeEstablishment: s.keys.Role != winn3RoleGateway,
	})
	if err != nil {
		cancel()
		_ = first.Close()
		_ = socket.Close()
		material.wipe()
		return err
	}

	fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.open] inner_mtu=%d message_size=%d path_mtu=%d carrier=%s remote=%v\n",
		plan.sizing.InnerMTU, plan.sizing.MessageSize, plan.sizing.PathMTU, first.conn.Class(), plan.remote)

	superDone := make(chan struct{})
	s.mu.Lock()
	s.sizing = plan.sizing
	s.sessionID = plan.doc.SessionID
	s.cancel = cancel
	s.superDone = superDone
	s.socket = socket
	s.mu.Unlock()
	s.materialMu.Lock()
	s.material = material
	s.materialMu.Unlock()
	// Published before CreateAck so the acknowledgement already describes the
	// round the host is about to pump into.
	s.publish(first)

	go func() {
		defer close(superDone)
		runErr := supervisor.Run(runCtx)
		// No round can be built after Run returns, so the recovery copy has
		// no further reader. The last round's own copies went with its Close.
		s.releaseMaterial()
		if !handed {
			// Cancelled before the supervisor took the first round. Close
			// also clears that round's secret copies.
			_ = first.Close()
		}
		if runErr != nil {
			s.runErr.Store(&runErr)
			fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.supervisor] exited with error: %v\n", runErr)
		} else {
			fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.supervisor] exited cleanly\n")
		}
		// The last round is retired and its device is closed. The status
		// document now says blocked, with the cause, without waiting for the
		// host to write another packet; a host packet still meets the
		// closed-device refusal it met before recovery existed.
		s.mu.Lock()
		s.recovering.Store(false)
		s.finished = true
		s.mu.Unlock()
		s.closeSocket()
	}()
	return nil
}

// nextRound builds a round after the first. Its session configuration is built
// afresh from the key material open read, and dual-auth is re-checked against
// it, so a round never inherits a session, a key object or an attestation from
// the one that died. It never re-reads the key files: the Android host has
// erased them by now (see winn3KeyMaterial).
//
// Every refusal here is marked terminal: Build touches no network, so a round
// that cannot be built now cannot be built after a backoff either.
func (s *winn3FrameServer) nextRound(
	ctx context.Context, plan winn3CreatePlan, socket *net.UDPConn,
) (driver.Runner, error) {
	s.materialMu.Lock()
	sessionConfig, _, roundSecrets, err := s.keys.sessionConfigFrom(&s.material)
	s.materialMu.Unlock()
	if err == nil {
		if err = requireLiveDualAuth(s.keys, sessionConfig); err != nil {
			roundSecrets.clearAll()
		}
	}
	var round *winn3FrameRound
	if err == nil {
		// buildRound owns roundSecrets from here: it clears them on failure.
		round, err = s.buildRound(ctx, plan, socket, sessionConfig, roundSecrets)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", driver.ErrReconnectTerminal, err)
	}
	return round, nil
}

// releaseMaterial wipes this tunnel generation's recovery copy. Idempotent.
// It is called only once no successor round may be built; a later nextRound
// is refused with errWinn3KeyMaterialReleased.
func (s *winn3FrameServer) releaseMaterial() {
	s.materialMu.Lock()
	s.material.wipe()
	s.materialMu.Unlock()
}

// buildRound builds one round: a round-owned frame device, a carrier wrapper
// that BORROWS the adopted socket, and a fresh loop. Nothing is published and
// nothing runs; a failure closes what this call opened and never the socket.
//
// secrets are the per-round copies sessionConfigFrom made for sessionConfig.
// The round owns them and clears them in Close; a failure here clears them
// before returning.
func (s *winn3FrameServer) buildRound(
	ctx context.Context, plan winn3CreatePlan, socket *net.UDPConn,
	sessionConfig session.Config, secrets winn3OwnedSecrets,
) (round *winn3FrameRound, err error) {
	defer func() {
		if err != nil {
			secrets.clearAll()
		}
	}()
	device, err := newWinn3FrameDevice(plan.doc.InnerMTU)
	if err != nil {
		return nil, err
	}

	// THE FLOOR, never the dialled class's own ceiling. This is the single
	// assignment the 84-byte black hole turns on, and it is here rather than in
	// any host so that no host can supply a different number.
	//
	// A descriptor the host merely BOUND has no kernel-side peer filter, so the
	// carrier is told the peer explicitly and filters itself. A connected one
	// reports a RemoteAddr and needs neither. Guessing wrong in the permissive
	// direction is a tunnel that accepts datagrams from anywhere, so the test is
	// on the socket rather than on the document.
	//
	// OwnsConn false: the socket outlives this round. Closing it with the
	// round would leave the next round nothing to send on, and the host's
	// descriptor cannot be adopted twice.
	udpConfig := carrier.UDPConfig{
		Conn:           socket,
		OwnsConn:       false,
		MaxMessageSize: plan.sizing.MessageSize,
		PathMTU:        plan.sizing.PathMTU,
	}
	if socket.RemoteAddr() == nil {
		udpConfig.Peer = plan.remote
	}
	conn, err := carrier.NewUDP(udpConfig)
	if err != nil {
		_ = device.Close()
		return nil, err
	}

	// Sink and CarrierFloorMessageSize are deliberately left zero: driver.Config
	// refuses a tun configuration that carries either and pins both itself,
	// which is what stops a host sizing the tunnel to the carrier it dialled.
	tunConfig := tun.Config{
		Assign: plan.assign,
		Device: device,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}

	if s.sessionTweak != nil {
		s.sessionTweak(&sessionConfig)
	}
	build := driver.NewClient
	if s.keys.Role == winn3RoleGateway {
		build = driver.NewGateway
	}
	loop, err := build(driver.Config{
		Session: sessionConfig,
		Sizing:  plan.sizing,
		Carrier: conn,
		Tun:     &tunConfig,
	})
	if err != nil {
		_ = conn.Close()
		_ = device.Close()
		return nil, err
	}
	return &winn3FrameRound{
		s:         s,
		ctx:       ctx,
		remote:    plan.remote,
		admission: sessionConfig.Core.Gateway.AdmissionKeys[0],
		loop:      loop,
		device:    device,
		conn:      conn,
		secrets:   secrets,
	}, nil
}

// winn3FrameRound is one supervised round, the driver.Runner a Reconnect
// drives: one session, one carrier wrapper, one round-owned device.
//
// The device is the round's and not the host's because a device read can stay
// blocked until the device closes, and Loop.Run does not wait for the pump
// that makes it. A device shared across rounds would let the dead round's
// reader take host packets from the live one. Here the dead round's device is
// closed and its reader and output pump joined before the successor is
// published, so exactly one round reads from the host at a time.
type winn3FrameRound struct {
	s         *winn3FrameServer
	ctx       context.Context
	remote    *net.UDPAddr
	admission []byte

	loop   *driver.Loop
	device *winn3FrameDevice
	conn   carrier.Conn

	// secrets are this round's own copies of the key material (the admission
	// secret its session configuration holds, and the dual-auth publics).
	// Close clears them once the loop is closed.
	secrets winn3OwnedSecrets

	// published and pumpDone are guarded by s.mu.
	published bool
	pumpDone  chan struct{}
}

// Run publishes the round and drives its loop.
func (r *winn3FrameRound) Run(ctx context.Context) error {
	if !r.s.publish(r) {
		return context.Canceled
	}
	// Loop.Run runs the write loop on this goroutine (driver/loop.go Run calls
	// writeLoop directly), so pinning here pins every uplink send syscall of
	// this round (arm X2, WINN3_TX_CPU; a no-op when unset).
	unpin := pinTxThread()
	defer unpin()
	fallbackCtx, stopFallback := context.WithCancel(ctx)
	fallbackDone := make(chan struct{})
	if r.s.keys.Role == winn3RoleClient && r.loop.Sizing().Allows(carrier.ClassTCP) {
		go func() {
			defer close(fallbackDone)
			driver.MigrateSilentUDP(fallbackCtx, r.loop, func(dialCtx context.Context) (carrier.Conn, error) {
				fd := -1
				var requestErr error
				if r.s.tcpChannel != nil {
					fd, requestErr = r.s.requestTCPDescriptor(dialCtx)
					if requestErr != nil {
						return nil, requestErr
					}
				} else {
					fd = r.s.takeTCPDescriptor()
				}
				if fd < 0 {
					return nil, errors.New("no protected TCP descriptor")
				}
				raw, err := connectProtectedTCP(dialCtx, fd, r.remote)
				if err != nil {
					return nil, err
				}
				stream, err := carrier.NewStream(carrier.StreamConfig{
					Conn: raw, Secret: r.admission, Role: carrier.RoleClient,
					MaxMessageSize: r.loop.Sizing().MessageSize,
					PathMTU:        r.loop.Sizing().PathMTU,
					TCPFirstFlight: true,
				})
				if err != nil {
					_ = raw.Close()
				}
				return stream, err
			})
		}()
	} else {
		close(fallbackDone)
	}
	err := r.loop.Run(ctx)
	stopFallback()
	<-fallbackDone
	if r.s.roundEndHook != nil {
		r.s.roundEndHook()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.loop.Run] round %d exited with error: %v\n",
			r.s.rounds.Load(), err)
	} else {
		fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.loop.Run] round %d exited cleanly\n",
			r.s.rounds.Load())
	}
	// The loop has latched the gate down. From here until a successor is
	// published this round's counters say nothing about the tunnel.
	r.s.mu.Lock()
	if tn := r.loop.Tunnel(); tn != nil && tn.Stats().RxPackets > 0 {
		r.s.everProven = true
	}
	r.s.roundEnded = true
	r.s.recovering.Store(true)
	r.s.mu.Unlock()
	return err
}

// ProvenFor is the round's loop's, so the supervisor resets its budget on the
// session's evidence.
func (r *winn3FrameRound) ProvenFor() time.Duration { return r.loop.ProvenFor() }

// Established and PeerCloseReason are the round's loop's, so the supervisor
// can fold in whether the round ever established and classify a peer's
// authenticated CLOSE.
func (r *winn3FrameRound) Established() bool { return r.loop.Established() }

func (r *winn3FrameRound) PeerCloseReason() session.CloseReason {
	return r.loop.PeerCloseReason()
}

var (
	_ driver.ProvenRunner      = (*winn3FrameRound)(nil)
	_ driver.EstablishedRunner = (*winn3FrameRound)(nil)
	_ driver.PeerCloseRunner   = (*winn3FrameRound)(nil)
)

// Close retires the round. The order mirrors the loop's own teardown: the
// loop first (the gate is latched and a queued CLOSE is offered to the peer
// while the carrier can still carry it), then the device, which wakes both the
// tun reader and the output pump, then a join on each, then the carrier
// wrappers. The socket is not the round's and stays open.
func (r *winn3FrameRound) Close() error {
	live := r.loop.Carrier()
	_ = r.loop.Close()
	_ = r.device.Close()
	readerRetired := r.device.retireReader(r.ctx)
	r.s.mu.Lock()
	pumpDone := r.pumpDone
	r.s.mu.Unlock()
	pumpRetired := true
	if pumpDone != nil {
		pumpRetired = winn3FrameAwait(r.ctx, pumpDone)
	}
	// The LIVE carrier as well as the one this round built. Loop.Migrate does
	// not close the carrier it replaced, so after a migration the wrapper built
	// here and the carrier the loop ended on are different objects.
	if live != nil && live != r.conn {
		_ = live.Close()
	}
	_ = r.conn.Close()
	// The loop is closed, so its session no longer reads the configuration
	// these back.
	r.secrets.clearAll()
	if !readerRetired || !pumpRetired {
		return fmt.Errorf("round reader or output pump did not retire within %s", winn3FrameCloseGrace)
	}
	return nil
}

// publish makes r the round a host reaches. It is idempotent, and refuses once
// the server has shut down so a round built during a Stop is never exposed.
func (s *winn3FrameServer) publish(r *winn3FrameRound) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return false
	}
	if r.published {
		return true
	}
	r.published = true
	r.pumpDone = make(chan struct{})
	s.round = r
	s.loop = r.loop
	s.device = r.device
	go s.pump(r.device, r.pumpDone)
	// The device before the flag. See recoveryAbsorbs.
	s.activeDevice.Store(r.device)
	s.recovering.Store(false)
	s.rounds.Add(1)
	return true
}

// winn3FrameAwait bounds the join even during recovery. A caller that observes
// false must stop the supervisor rather than publish a successor while the old
// reader or output pump can still run.
func winn3FrameAwait(_ context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-time.After(winn3FrameCloseGrace):
		return false
	}
}

// closeSocket closes the adopted socket, once.
func (s *winn3FrameServer) closeSocket() {
	s.mu.Lock()
	socket := s.socket
	s.mu.Unlock()
	if socket == nil {
		return
	}
	s.socketOnce.Do(func() {
		s.socketCloses.Add(1)
		_ = socket.Close()
	})
}

func (s *winn3FrameServer) takeTCPDescriptor() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	fd := s.tcpDescriptor
	s.tcpDescriptor = -1
	return fd
}

// Sized to 16 MiB to align with the host platform's outer UDP socket buffer
// configuration, preventing clamping down during descriptor adoption.
const outerSocketBufferBytes = 16 * 1024 * 1024

func configureOuterSocketBuffers(udp *net.UDPConn) {
	if udp == nil {
		return
	}
	_ = udp.SetWriteBuffer(outerSocketBufferBytes)
	_ = udp.SetReadBuffer(outerSocketBufferBytes)
}

// outerSocket adopts the host's descriptor, or dials one when the create
// document allows it. Adopting is the norm: on three of five platforms a socket
// this process opened is a socket the host never protected.
func (s *winn3FrameServer) outerSocket(
	ctx context.Context, plan winn3CreatePlan,
) (*net.UDPConn, error) {
	if s.descriptor < 0 {
		// decodeWinn3Create has already refused this combination unless
		// allow_own_socket is set and an exclusion was declared.
		dialCtx, cancel := context.WithTimeout(ctx, winn3FrameDialTimeout)
		defer cancel()
		var dialer net.Dialer
		conn, err := dialer.DialContext(dialCtx, "udp", plan.remote.String())
		if err != nil {
			return nil, err
		}
		udp, ok := conn.(*net.UDPConn)
		if !ok {
			_ = conn.Close()
			return nil, winn3RefuseCreate("dialer returned %T, not a UDP socket", conn)
		}
		configureOuterSocketBuffers(udp)
		return udp, nil
	}

	// os.NewFile takes ownership of the descriptor; net.FilePacketConn DUPS it,
	// so the original must be closed or it leaks for the life of the process.
	file := os.NewFile(uintptr(s.descriptor), "winn3-carrier") //nolint:gosec // received over SCM_RIGHTS
	if file == nil {
		return nil, winn3RefuseCreate(
			"the descriptor handed over is not usable")
	}
	packetConn, err := net.FilePacketConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, winn3RefuseCreate(
			"the descriptor handed over is not a datagram socket: %v", err)
	}
	if closeErr != nil {
		_ = packetConn.Close()
		return nil, winn3RefuseCreate(
			"could not release the descriptor handed over: %v", closeErr)
	}
	udp, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, winn3RefuseCreate(
			"the descriptor handed over is a %T, not a UDP socket", packetConn)
	}
	configureOuterSocketBuffers(udp)
	return udp, nil
}

// currentLoop is the tunnel this session is carrying, or nil before create.
//
// It exists so that the migration path has one accessor rather than several
// readers of a mutex-guarded field. Carrier escalation is NOT wired to the frame
// channel yet: the normative opcode set has no control opcode for it and this
// lane does not own datapath/duplex, so the policy that decides WHEN to escalate
// is the next seam rather than part of this one. See the handoff.
func (s *winn3FrameServer) currentLoop() *driver.Loop {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loop
}

// handleInbound is the host's inner IP packet on its way out.
//
// A packet the device refuses is NOT a session failure: an oversize frame or a
// full queue must not tear down a working tunnel, for the same reason the winn/1
// path treats a rejected datagram as an Error frame rather than an end.
func (s *winn3FrameServer) handleInbound(payload []byte) error {
	device := s.activeDevice.Load()
	if device == nil {
		return s.writer.Write(duplex.OpError,
			[]byte("inbound inner packet before create"))
	}
	if err := device.offer(payload); err != nil {
		if s.recoveryAbsorbs(device, err, 1) {
			return nil
		}
		return s.writer.Write(duplex.OpError, []byte(err.Error()))
	}
	return nil
}

// pump forwards delivered inner packets to the host until the device closes.
func (s *winn3FrameServer) pump(device *winn3FrameDevice, done chan struct{}) {
	defer close(done)
	batch := make([][]byte, 0, 256)
	for {
		packet, err := device.take()
		if err != nil {
			return
		}
		batch = batch[:0]
		if len(packet) > 0 {
			batch = append(batch, packet)
		}

		// Drain up to 255 additional immediately ready packets.
		for len(batch) < 256 {
			pkt, ok := device.tryTake()
			if !ok {
				break
			}
			if len(pkt) > 0 {
				batch = append(batch, pkt)
			}
		}

		started := time.Now()
		if len(batch) > 0 {
			if err := s.writer.WriteOutboundBatch(batch); err != nil {
				for _, pkt := range batch {
					device.recycle(pkt)
				}
				return
			}
			for _, pkt := range batch {
				device.recycle(pkt)
			}
		}

		if err := s.writer.Flush(); err != nil {
			return
		}
		// Telemetry only. The interval covers the copy into the writer and
		// the flush to the host, which is where a host that reads slowly
		// makes this goroutine wait.
		device.noteHostWrite(len(batch), time.Since(started))
	}
}

// statusJSON is the document a host reads its promotion gate off.
//
// It is winn3StatusFrom's, unchanged, so that the frame mode and the desktop
// mode publish the same fields computed by the same function. Two seams that
// each decided promotion for themselves would eventually decide it differently,
// and the obvious way to get it wrong (rx_offered for rx_packets) is the
// difference between "a payload arrived" and "an inner packet was validated and
// reached the host device".
func (s *winn3FrameServer) statusJSON(event string) string {
	s.mu.Lock()
	loop, sizing, sessionID, device := s.loop, s.sizing, s.sessionID, s.device
	recovering, finished, roundEnded, everProven := s.recovering.Load(), s.finished, s.roundEnded, s.everProven
	opened := s.cancel != nil
	if recovering {
		// The round that owned these counters is dead and its successor is not
		// yet published. Its rx_packets proved THAT session, not the next one,
		// so the document describes no round at all: gate closed, no proof.
		loop, device = nil, nil
	}
	s.mu.Unlock()
	if s.statusHook != nil {
		s.statusHook()
	}

	status := winn3StatusFrom(event, loop, sizing, s.keys.OuterSocketExclusion)
	status.SessionID = sessionID
	if opened {
		var runErr error
		if err := s.runErr.Load(); err != nil {
			runErr = *err
		}
		// The gate and counters above were read after the snapshot, so the
		// round can have ended in between: its gate latched down before its
		// end was recorded, or a successor published. The facts below combine
		// the two reads so that neither can regress a proven tunnel: the
		// round's own delivery counter is monotonic and survives its end.
		gateLive := status.GateState != tun.StateDown.String() &&
			status.GateState != tun.StateClosed.String()
		lifecycle, cause := driver.Lifecycle(driver.LifecycleFacts{
			Stopped:         s.closed.Load(),
			Finished:        finished,
			RunErr:          runErr,
			Recovering:      recovering,
			CurrentProven:   status.PromotionReady,
			RoundProvenLive: loop != nil && gateLive && status.RxPackets > 0,
			RoundEnded:      roundEnded,
			EverProven:      everProven || status.RxPackets > 0,
		})
		everProven = everProven || status.RxPackets > 0
		if lifecycle == driver.LifecycleRecovering && loop != nil {
			// The round read here is ending, or is a successor that has
			// proven nothing: no round is proven now, and none of its
			// evidence is published as current.
			loop, device = nil, nil
			status = winn3StatusFrom(event, nil, sizing, s.keys.OuterSocketExclusion)
			status.SessionID = sessionID
		}
		status.Lifecycle, status.LifecycleCause = lifecycle, cause
		winn3HoldCaptureWhileRecovering(&status, everProven)
	}
	if device != nil {
		status.DroppedToEngine = device.droppedToEngine.Load()
		winn3PublishFrameTelemetry(&status, device.telemetry())
	}
	if loop != nil {
		stats := loop.Stats()
		status.RecvBatches = stats.RecvBatches
		status.SendBatches = stats.SendBatches
		status.DataFramesDropped = stats.DataFramesDropped
		status.Rekeys = stats.Rekeys
		status.SendQueueHighWater = stats.DataQueueHighWater
		status.SendQueueDepth = stats.DataQueueDepth
		status.OuterReordered = stats.OuterReordered
		status.OuterLost = stats.OuterLost
		if stats.OuterReordered > 0 {
			status.OuterReorderDepth = append([]uint64(nil), stats.OuterReorderDepth[:]...)
		}
		if c := loop.Carrier(); c != nil {
			cs := c.Stats()
			status.TxGSOCalls = cs.TxGSOCalls
			status.TxGSOSegments = cs.TxGSOSegments
			status.TxBatchCalls = cs.TxBatchCalls
			status.TxGSODisabled = cs.TxGSODisabled
		}
	}
	if err := s.runErr.Load(); err != nil && *err != nil &&
		!errors.Is(*err, context.Canceled) {
		status.Refusal = (*err).Error()
	} else if loop != nil {
		if carrierErr := loop.CarrierErr(); carrierErr != nil {
			status.Refusal = carrierErr.Error()
		}
	}
	encoded, err := winn3EncodeStatus(status)
	if err != nil {
		// A status a host cannot parse must still not widen a posture: every
		// field it reads is absent here, so promotion_ready is Go's zero value
		// on the host's side too, which is bootstrap.
		return `{"event":"refused","posture":"` + winn3PostureBootstrap +
			`","promotion_ready":false,"refusal":"status could not be encoded"}`
	}
	return string(encoded)
}

// winn3PublishFrameTelemetry copies the frame device's queue census into a
// status document. Frame mode only: the desktop document never carries it.
func winn3PublishFrameTelemetry(status *winn3Status, t winn3FrameTelemetry) {
	status.HostQueueDepth = t.HostQueueDepth
	status.HostQueueHighWater = t.HostQueueHighWater
	status.DroppedToHost = t.DroppedToHost
	status.HostWriteBatches = t.HostWriteBatches
	status.HostWritePackets = t.HostWritePackets
	status.HostWriteNanos = t.HostWriteNanos
	status.HostWriteMaxNanos = t.HostWriteMaxNanos
	status.EngineQueueDepth = t.EngineQueueDepth
	status.EngineQueueHighWater = t.EngineQueueHighWater
	status.RingPopCalls = t.Ring.PopCalls
	status.RingPopPackets = t.Ring.PopLenSum
	status.RingWakePark = t.Ring.WakePark
}

func requireLiveDualAuth(keys winn3Keys, cfg session.Config) error {
	edPath := strings.TrimSpace(keys.DualAuthEd25519PubPath)
	mlPath := strings.TrimSpace(keys.DualAuthMLDSA65PubPath)
	if edPath == "" && mlPath == "" {
		return nil
	}
	if !cfg.DualAuth.Expected ||
		len(cfg.DualAuth.Ed25519Public) != dualsign.Ed25519PublicKeySize ||
		len(cfg.DualAuth.MLDSA65Public) != dualsign.MLDSA65PublicKeySize {
		return errors.New(
			"winn3 frame mode refused CreateAck: staged dual-auth public keys were not ingested into the live session")
	}
	return nil
}

// shutdown tears the tunnel down. It is idempotent and is called on every exit
// path, including a frame-decode failure.
func (s *winn3FrameServer) shutdown() {
	fmt.Fprintf(os.Stderr, "winn-debug: [winn3_frame.shutdown] called\n")
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.tcpChannel != nil {
		_ = s.tcpChannel.Close()
	}
	if fd := s.takeTCPDescriptor(); fd >= 0 {
		_ = os.NewFile(uintptr(fd), "winn3-protected-tcp").Close()
	}
	s.mu.Lock()
	s.activeDevice.Store(nil)
	cancel, superDone := s.cancel, s.superDone
	s.mu.Unlock()

	// Nothing before the socket is closed may touch the output writer. Its
	// mutex is held across a blocking write to the host, so a host that has
	// stopped reading would otherwise hold Stop short of cancellation.
	if cancel != nil {
		// Cancel first so the live round's gate latches down and no further
		// inner packet can enter. The supervisor then retires that round
		// (loop, device, reader, pump, carrier wrappers, in Close's order),
		// builds no other, and closes the socket as it exits.
		cancel()
		// No successor may be built after a Stop, so the recovery copy goes
		// now, not when the supervisor gets round to returning: the wait below
		// is bounded and may end first. The live round's own copies are
		// cleared by its Close, which a round stuck past the bound has not run.
		s.releaseMaterial()
		select {
		case <-superDone:
		case <-time.After(2 * winn3FrameCloseGrace):
			// A round that will not finish inside its grace cannot move a
			// byte: its gate is latched. Closing the socket here wakes anything
			// still parked on it; closeSocket is once-only, so the
			// supervisor's own close when it does exit is a no-op.
		}
		s.closeSocket()
	}

	// Last, and bounded: hand the host whatever is buffered. If the writer is
	// held by a write the host is not reading, the flush is abandoned to that
	// goroutine rather than waited for.
	flushed := make(chan struct{})
	go func() {
		_ = s.writer.Flush()
		close(flushed)
	}()
	select {
	case <-flushed:
	case <-time.After(winn3FrameCloseGrace):
	}
}
