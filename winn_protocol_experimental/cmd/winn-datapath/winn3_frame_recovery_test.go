//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// In-engine recovery for the frame host.
//
// A round whose session dies is followed by a fresh session on a fresh carrier
// wrapper over the SAME adopted socket, while the host's frame stream stays open
// and never carries an Error frame for it. Loopback only, as in
// winn3_frame_e2e_test.go.

// TestADeadFrameRoundIsFollowedByAFreshSessionOnTheSameSocket is the whole
// property, end to end, over two real frame hosts.
//
// The gateway ends its session with a CLOSE, which is what a gateway restart
// or a desynchronised receive window looks like from the client. The client
// must build a new session and carry again without the host doing anything.
// The same-socket half is enforced by the gateway, not asserted: its carrier
// filters on the client's address and port, so a client that re-dialled from a
// new socket would never be heard.
func TestADeadFrameRoundIsFollowedByAFreshSessionOnTheSameSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	ring := newFrameKeyring(t)
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)
	client := startFrameEngine(t, ctx, ring.clientKeys, handOver(t, clientSock))
	gateway := startFrameEngine(t, ctx, ring.gatewayKeys, handOver(t, gatewaySock))
	client.create(t, frameCreate(gatewayAddr, "10.8.1.3", "10.8.1.1", sizing, pathMTU))
	gateway.create(t, frameCreate(clientAddr, "10.8.1.1", "10.8.1.3", sizing, pathMTU))
	_ = client.ack(t)
	_ = gateway.ack(t)

	up := func(text string) []byte {
		return ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte(text))
	}
	down := func(text string) []byte {
		return ipv4Packet([4]byte{10, 8, 1, 1}, [4]byte{10, 8, 1, 3}, []byte(text))
	}

	carryPacket(t, client, gateway, up("round one up"), 45*time.Second)
	carryPacket(t, gateway, client, down("round one down"), 20*time.Second)
	before := client.status(t)
	if !before.PromotionReady || before.RxPackets == 0 {
		t.Fatalf("round one never proved itself: %+v", before)
	}
	firstLoop := client.server.currentLoop()
	firstSession := firstLoop.Session()
	firstGateway := gateway.server.currentLoop()

	// The gateway's session ends. Its CLOSE is the client's round dying.
	_ = firstGateway.Close()

	waitUntil(t, 45*time.Second, "a fresh, established client session", func() bool {
		l := client.server.currentLoop()
		return l != nil && l != firstLoop && l.Established()
	})
	if client.server.currentLoop().Session() == firstSession {
		t.Fatal("the recovered round reused the dead round's session")
	}

	// Before round two has carried anything, the status document must not
	// still be proving round one.
	gateway.drain()
	client.drain()
	recovered := client.status(t)
	if recovered.RxPackets != 0 || recovered.PromotionReady {
		t.Fatalf("status after recovery still carries round one's evidence: rx_packets=%d promotion_ready=%v (round one had rx_packets=%d)",
			recovered.RxPackets, recovered.PromotionReady, before.RxPackets)
	}
	// Established but not yet proven: still recovering, and a host that had
	// promoted is told to hold its capture, never to narrow to bootstrap.
	if recovered.Lifecycle != driver.LifecycleRecovering || recovered.Posture != winn3PostureHold {
		t.Fatalf("an unproven successor published lifecycle %q posture %q, want recovering and hold",
			recovered.Lifecycle, recovered.Posture)
	}
	if before.Lifecycle != driver.LifecycleConnected {
		t.Fatalf("round one with delivery proof published lifecycle %q", before.Lifecycle)
	}

	carryPacket(t, client, gateway, up("round two up"), 45*time.Second)
	carryPacket(t, gateway, client, down("round two down"), 20*time.Second)
	after := client.status(t)
	if !after.PromotionReady || after.RxPackets == 0 {
		t.Fatalf("round two did not prove itself: %+v", after)
	}
	if live := client.server.currentLoop().Tunnel().Stats().RxPackets; after.RxPackets > live {
		t.Fatalf("status rx_packets=%d exceeds the live round's %d; it is not the live round's counter",
			after.RxPackets, live)
	}

	// The host stream never saw an Error frame and serve never ended: from the
	// host's side nothing happened except a short outage.
	select {
	case refusal := <-client.errs:
		t.Fatalf("the host was sent an Error frame during recovery: %s", refusal)
	default:
	}
	select {
	case err := <-client.served:
		t.Fatalf("the frame conversation ended during recovery: %v", err)
	default:
	}

	client.close(t)
	gateway.close(t)
}

// startSilentFrameServer opens a gateway-role frame server over a handed-over
// loopback socket with no peer, on a host stream nobody reads unless the test
// starts reading it. A gateway round waits for an initiation forever, so it
// dies only when the test kills it.
func startSilentFrameServer(t *testing.T) (*winn3FrameServer, net.Conn) {
	t.Helper()
	ring := newFrameKeyring(t)
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := loopbackSocket(t)
	_, peer := loopbackSocket(t)
	hostSide, engineSide := net.Pipe()
	s := newWinn3FrameServer(ring.gatewayKeys, handOver(t, sock), engineSide)
	t.Cleanup(func() {
		_ = hostSide.Close()
		_ = engineSide.Close()
		s.shutdown()
	})
	if err := s.open(context.Background(),
		frameCreate(peer, "10.8.1.1", "10.8.1.3", sizing, pathMTU)); err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, hostSide
}

func (s *winn3FrameServer) currentRound() *winn3FrameRound {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.round
}

// TestTheDeadRoundIsRetiredBeforeItsSuccessorIsPublished holds the old round's
// output pump inside a write the host is not reading, and requires that no
// successor appears until that pump has exited. It then requires that host
// packets reach the successor only.
func TestTheDeadRoundIsRetiredBeforeItsSuccessorIsPublished(t *testing.T) {
	s, hostSide := startSilentFrameServer(t)
	r1 := s.currentRound()
	packet := ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte("in flight"))

	// A delivered packet the pump takes and cannot write: the pipe is
	// synchronous and nobody reads the host side.
	if _, err := r1.device.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "the pump to take the packet", func() bool {
		return len(r1.device.toHost) == 0
	})

	_ = r1.loop.Close()
	waitUntil(t, 10*time.Second, "round one to end", func() bool {
		return s.recovering.Load()
	})

	// Host packets during recovery are dropped without an Error frame. An
	// Error frame here would block on the unread pipe, so a hang is the
	// failure as much as a returned error is.
	submitted := make(chan error, 1)
	go func() {
		for range 64 {
			if err := s.handleInbound(packet); err != nil {
				submitted <- err
				return
			}
		}
		submitted <- nil
	}()
	select {
	case err := <-submitted:
		if err != nil {
			t.Fatalf("a host packet during recovery failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a host packet during recovery blocked: it was answered with a frame")
	}
	if s.droppedRecovering.Load() == 0 {
		t.Fatal("no host packet was counted as dropped during recovery")
	}

	// While no round carries, the status describes no round: not the dead
	// one's latched gate and not its counters.
	var during winn3Status
	if err := json.Unmarshal([]byte(s.statusJSON("posture")), &during); err != nil {
		t.Fatal(err)
	}
	if during.GateState != tun.StateClosed.String() || during.PromotionReady || during.MessagesReceived != 0 {
		t.Fatalf("status during recovery describes the dead round: %+v", during)
	}
	if during.Lifecycle != driver.LifecycleRecovering || during.Posture != winn3PostureHold {
		t.Fatalf("status during recovery is lifecycle %q posture %q, want recovering and hold", during.Lifecycle, during.Posture)
	}

	// Longer than any first-window backoff draw. The pump is still stuck, so
	// no successor may exist.
	time.Sleep(1500 * time.Millisecond)
	if s.activeDevice.Load() != r1.device || s.rounds.Load() != 1 {
		t.Fatal("a successor was published while the dead round's pump was still running")
	}

	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	waitUntil(t, 15*time.Second, "a successor round", func() bool {
		d := s.activeDevice.Load()
		return d != nil && d != r1.device
	})
	r2 := s.currentRound()
	if r2 == r1 || r2.loop == r1.loop || r2.device == r1.device || r2.conn == r1.conn {
		t.Fatal("the successor shares a loop, device or carrier wrapper with the dead round")
	}
	if !r1.device.isClosed() {
		t.Fatal("the dead round's device is still open")
	}
	select {
	case <-r1.pumpDone:
	default:
		t.Fatal("the dead round's pump is still running")
	}
	if !r1.device.readMu.TryLock() {
		t.Fatal("a reader is still inside the dead round's device")
	}
	r1.device.readMu.Unlock()

	// Host packets now reach round two and never round one.
	oldReads := r1.loop.Tunnel().Stats().DeviceReads
	newReads := r2.loop.Tunnel().Stats().DeviceReads
	for range 16 {
		if err := s.handleInbound(packet); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, 5*time.Second, "round two to read the host's packets", func() bool {
		return r2.loop.Tunnel().Stats().DeviceReads >= newReads+16
	})
	if got := r1.loop.Tunnel().Stats().DeviceReads; got != oldReads {
		t.Fatalf("the dead round read %d host packets after its successor was published", got-oldReads)
	}
}

// TestAStopStopsEveryRoundAndClosesTheSocketOnce: a Stop during recovery and a
// Stop during a live round both end the supervisor, build nothing afterwards,
// and close the adopted socket exactly once.
func TestAStopStopsEveryRoundAndClosesTheSocketOnce(t *testing.T) {
	for _, during := range []string{"recovery", "a live round"} {
		t.Run(during, func(t *testing.T) {
			s, hostSide := startSilentFrameServer(t)
			go func() { _, _ = io.Copy(io.Discard, hostSide) }()
			r1 := s.currentRound()
			socket := s.socket
			if during == "recovery" {
				_ = r1.loop.Close()
				waitUntil(t, 10*time.Second, "round one to end", func() bool {
					return s.recovering.Load()
				})
			}

			s.shutdown()
			select {
			case <-s.superDone:
			case <-time.After(5 * time.Second):
				t.Fatal("the supervisor did not finish after a Stop")
			}
			rounds := s.rounds.Load()
			time.Sleep(time.Second)
			if got := s.rounds.Load(); got != rounds {
				t.Fatalf("%d rounds published after the Stop", got-rounds)
			}
			if last := s.currentRound(); !last.device.isClosed() {
				t.Fatal("the last round's device is still open after the Stop")
			}
			if !r1.device.isClosed() {
				t.Fatal("round one's device is still open after the Stop")
			}

			s.shutdown()
			s.closeSocket()
			if n := s.socketCloses.Load(); n != 1 {
				t.Fatalf("the adopted socket was closed %d times, want exactly once", n)
			}
			if _, err := socket.Write([]byte{0}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("the adopted socket is still open after the Stop: %v", err)
			}
		})
	}
}

// TestAnExhaustedSupervisorStillEndsTheTunnelLoudly: recovery must not turn a
// tunnel that has truly ended into one that silently eats packets. Once the
// supervisor has finished, a host packet gets the closed-device Error frame it
// got before recovery existed.
func TestAnExhaustedSupervisorStillEndsTheTunnelLoudly(t *testing.T) {
	s, hostSide := startSilentFrameServer(t)
	frames := make(chan duplex.Opcode, 16)
	go func() {
		reader := duplex.NewReader(hostSide, true)
		for {
			op, _, err := reader.Read()
			if err != nil {
				return
			}
			select {
			case frames <- op:
			default:
			}
		}
	}()
	// A terminal refusal from the next Build ends the supervisor at once: the
	// next round's session configuration is refused. (A round no longer
	// re-reads the key files, so a vanished path cannot provoke it; see
	// winn3KeyMaterial.)
	s.refuseNextBuild()
	_ = s.currentRound().loop.Close()
	select {
	case <-s.superDone:
	case <-time.After(10 * time.Second):
		t.Fatal("a terminal build refusal did not end the supervisor")
	}
	if err := s.runErr.Load(); err == nil || !errors.Is(*err, driver.ErrReconnectTerminal) {
		t.Fatalf("the supervisor ended with %v, want the terminal refusal", err)
	}
	// The supervisor's end, and not a later Stop, is what releases the socket.
	if n := s.socketCloses.Load(); n != 1 {
		t.Fatalf("the adopted socket was closed %d times when the supervisor ended, want once", n)
	}
	if err := s.handleInbound(ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case op := <-frames:
			if op == duplex.OpError {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no Error frame after the supervisor ended; the host would never learn the tunnel is gone")
		}
	}
}
