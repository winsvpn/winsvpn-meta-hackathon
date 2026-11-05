//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round A2 v2: a Stop that does not wait on the host's stream, fail-fast for a
// client that never establishes, the lifecycle field, and recovery from a
// liveness death with no CLOSE.

func frameStatus(t *testing.T, s *winn3FrameServer) winn3Status {
	t.Helper()
	var st winn3Status
	if err := json.Unmarshal([]byte(s.statusJSON("posture")), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestAStopWithNoHostReaderIsBounded holds the dead round's output pump in a
// write nobody reads, exactly as the retirement test does, and then Stops
// WITHOUT ever starting a host reader. Stop must still cancel, bound its wait,
// close the socket once, and publish nothing new.
func TestAStopWithNoHostReaderIsBounded(t *testing.T) {
	s, _ := startSilentFrameServer(t)
	r1 := s.currentRound()
	packet := ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte("in flight"))
	if _, err := r1.device.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "the pump to take the packet", func() bool {
		return len(r1.device.toHost) == 0
	})
	_ = r1.loop.Close()
	waitUntil(t, 10*time.Second, "round one to end", func() bool { return s.recovering.Load() })

	started := time.Now()
	stopped := make(chan struct{})
	go func() {
		s.shutdown()
		close(stopped)
	}()
	// Two retirement graces, the supervisor's own grace and the flush grace
	// are the whole budget; anything past it is a Stop waiting on the host.
	bound := 4*winn3FrameCloseGrace + 2*time.Second
	select {
	case <-stopped:
	case <-time.After(bound):
		t.Fatalf("Stop did not complete within %v with the host not reading", bound)
	}
	t.Logf("Stop completed in %v with the output pump blocked", time.Since(started))
	select {
	case <-s.superDone:
	default:
		t.Fatal("Stop returned with the supervisor still running")
	}
	if n := s.rounds.Load(); n != 1 {
		t.Fatalf("%d rounds published; a successor appeared during Stop", n)
	}
	if n := s.socketCloses.Load(); n != 1 {
		t.Fatalf("the socket was closed %d times, want exactly once", n)
	}
	if st := frameStatus(t, s); st.Lifecycle != driver.LifecycleStopped {
		t.Fatalf("lifecycle after Stop is %q, want %q", st.Lifecycle, driver.LifecycleStopped)
	}
}

func TestRecoveryWithNoHostReaderBlocksAfterCloseGrace(t *testing.T) {
	s, _ := startSilentFrameServer(t)
	r1 := s.currentRound()
	packet := ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte("in flight"))
	if _, err := r1.device.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "the output pump to take the packet", func() bool {
		return len(r1.device.toHost) == 0
	})
	_ = r1.loop.Close()
	waitUntil(t, 10*time.Second, "round one to end", func() bool {
		return s.recovering.Load()
	})
	select {
	case <-s.superDone:
	case <-time.After(2*winn3FrameCloseGrace + 2*time.Second):
		t.Fatal("reconnect supervisor waited indefinitely for the blocked output pump")
	}
	if got := s.rounds.Load(); got != 1 {
		t.Fatalf("published %d rounds while the prior output pump was blocked, want 1", got)
	}
	if st := frameStatus(t, s); st.Lifecycle != driver.LifecycleBlocked || st.PromotionReady {
		t.Fatalf("stalled output pump published lifecycle %q, promotion %t", st.Lifecycle, st.PromotionReady)
	}
}

// startSilentFrameClient opens a CLIENT-role frame server whose peer is a
// bound loopback socket that never answers, with its session configuration
// edited by tweak before every round.
func startSilentFrameClient(t *testing.T, tweak func(*session.Config)) *winn3FrameServer {
	t.Helper()
	ring := newFrameKeyring(t)
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := loopbackSocket(t)
	silent, peer := loopbackSocket(t)
	hostSide, engineSide := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	s := newWinn3FrameServer(ring.clientKeys, handOver(t, sock), engineSide)
	s.sessionTweak = tweak
	t.Cleanup(func() {
		_ = hostSide.Close()
		_ = engineSide.Close()
		s.shutdown()
		_ = silent.Close()
	})
	if err := s.open(context.Background(),
		frameCreate(peer, "10.8.1.3", "10.8.1.1", sizing, pathMTU)); err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func shortHandshake(c *session.Config) {
	c.Retry = session.Retry{Base: 50 * time.Millisecond, Cap: 100 * time.Millisecond, Attempts: 2}
}

// TestAFrameClientThatNeverEstablishesIsBlockedAfterOneRound: the first round's
// handshake goes unanswered, the tunnel has never established, so the
// supervisor stops after that one round and the status says blocked, with its
// cause, without the host submitting a packet. It names no reason beyond the
// observation.
func TestAFrameClientThatNeverEstablishesIsBlockedAfterOneRound(t *testing.T) {
	s := startSilentFrameClient(t, shortHandshake)
	if st := frameStatus(t, s); st.Lifecycle != driver.LifecycleConnecting || st.Posture != winn3PostureBootstrap {
		t.Fatalf("a fresh client is %q with posture %q, want connecting and bootstrap", st.Lifecycle, st.Posture)
	}
	select {
	case <-s.superDone:
	case <-time.After(15 * time.Second):
		t.Fatalf("the supervisor was still running after %d rounds", s.rounds.Load())
	}
	if n := s.rounds.Load(); n != 1 {
		t.Fatalf("%d rounds built for a tunnel that never established, want 1", n)
	}
	st := frameStatus(t, s)
	if st.Lifecycle != driver.LifecycleBlocked || st.LifecycleCause != driver.LifecycleCauseNeverEstablished {
		t.Fatalf("lifecycle %q cause %q, want blocked / never_established", st.Lifecycle, st.LifecycleCause)
	}
	if st.PromotionReady || st.Posture != winn3PostureHold {
		t.Fatalf("a blocked tunnel published promotion_ready=%v posture=%q", st.PromotionReady, st.Posture)
	}
	if !strings.HasPrefix(st.Refusal, driver.ErrReconnectNeverEstablished.Error()) ||
		!strings.Contains(st.Refusal, session.ErrCarrierExhausted.Error()) {
		t.Fatalf("refusal %q does not carry the observation and the final round's cause", st.Refusal)
	}
	// The engine's own words are an observation. The session's diagnostic
	// that follows them already says a block and a refusal look the same.
	for _, word := range []string{"censor", "revok"} {
		if strings.Contains(driver.ErrReconnectNeverEstablished.Error()+st.LifecycleCause, word) {
			t.Fatalf("the blocked outcome labels an unanswered handshake as %q", word)
		}
	}
	if n := s.socketCloses.Load(); n != 1 {
		t.Fatalf("socket closed %d times when the supervisor ended, want once", n)
	}
}

// TestASpentBudgetIsAPersistentBlockedStatus: five consecutive rounds end
// without proving themselves (gateway role, which keeps the plain budget), so
// the episode is spent. The document says blocked / budget_spent on every
// request, with no packet submitted, and keeps saying it.
func TestASpentBudgetIsAPersistentBlockedStatus(t *testing.T) {
	s, hostSide := startSilentFrameServer(t)
	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	for round := uint64(1); round <= carrier.DefaultBackoffAttempts; round++ {
		waitUntil(t, 20*time.Second, "the next round", func() bool { return s.rounds.Load() == round })
		if round > 1 {
			if st := frameStatus(t, s); st.Lifecycle != driver.LifecycleRecovering || st.Posture != winn3PostureHold {
				t.Fatalf("round %d published lifecycle %q posture %q, want recovering and hold", round, st.Lifecycle, st.Posture)
			}
		}
		_ = s.currentRound().loop.Close()
	}
	select {
	case <-s.superDone:
	case <-time.After(20 * time.Second):
		t.Fatal("the supervisor did not end after the budget")
	}
	for range 3 {
		st := frameStatus(t, s)
		if st.Lifecycle != driver.LifecycleBlocked || st.LifecycleCause != driver.LifecycleCauseBudgetSpent {
			t.Fatalf("lifecycle %q cause %q, want blocked / budget_spent", st.Lifecycle, st.LifecycleCause)
		}
		if !strings.Contains(st.Refusal, "reconnect budget spent") || st.PromotionReady || st.Posture != winn3PostureHold {
			t.Fatalf("blocked document: refusal %q promotion_ready %v posture %q", st.Refusal, st.PromotionReady, st.Posture)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := s.rounds.Load(); n != carrier.DefaultBackoffAttempts {
		t.Fatalf("%d rounds, want %d", n, carrier.DefaultBackoffAttempts)
	}
}

// TestATerminalRefusalIsBlockedWithoutAPacket: the supervisor ends on a
// terminal Build refusal and the document already says so.
func TestATerminalRefusalIsBlockedWithoutAPacket(t *testing.T) {
	s, hostSide := startSilentFrameServer(t)
	go func() { _, _ = io.Copy(io.Discard, hostSide) }()
	s.refuseNextBuild()
	_ = s.currentRound().loop.Close()
	select {
	case <-s.superDone:
	case <-time.After(10 * time.Second):
		t.Fatal("a terminal build refusal did not end the supervisor")
	}
	st := frameStatus(t, s)
	if st.Lifecycle != driver.LifecycleBlocked || st.LifecycleCause != driver.LifecycleCauseTerminal || st.Refusal == "" {
		t.Fatalf("lifecycle %q cause %q refusal %q, want blocked / terminal with a refusal", st.Lifecycle, st.LifecycleCause, st.Refusal)
	}
}

// TestAFrameSessionThatLosesItsPeerRecovers: an established client session
// whose gateway stops answering, with no CLOSE, dies on its own liveness
// verdict, and a fresh session on the same adopted socket carries again. The
// host's frame stream is the owner throughout: no Error frame, serve still
// running. Probes are shortened through the test hook so this is not a
// minute of wall time.
func TestAFrameSessionThatLosesItsPeerRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ring := newFrameKeyring(t)
	const pathMTU = 1500
	sizing, err := driver.NewSizing(pathMTU, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	clientSock, clientAddr := loopbackSocket(t)
	gatewaySock, gatewayAddr := loopbackSocket(t)
	defer gatewaySock.Close()

	hostSide, engineSide := net.Pipe()
	client := &frameEngine{
		server:   newWinn3FrameServer(ring.clientKeys, handOver(t, clientSock), engineSide),
		stream:   hostSide,
		writer:   duplex.NewWriter(hostSide),
		acks:     make(chan winn3Status, 8),
		statuses: make(chan winn3Status, 64),
		errs:     make(chan string, 64),
		inbound:  make(chan []byte, 512),
		closeAck: make(chan struct{}, 1),
		served:   make(chan error, 1),
	}
	client.server.sessionTweak = func(c *session.Config) {
		c.Silence = session.Draw{Min: 100 * time.Millisecond, Mean: 150 * time.Millisecond, Max: 300 * time.Millisecond}
		c.Probe = session.Draw{Min: 100 * time.Millisecond, Mean: 150 * time.Millisecond, Max: 300 * time.Millisecond}
		c.MaxLostProbes = 2
		// The fixture's key document lowers the volume rekey to 8 messages;
		// a rekey caught in flight by the silence would end the round on its
		// own timeout first. This test is about the liveness verdict.
		c.RekeyAfterMessages = 0
	}
	go func() {
		err := client.server.serve(ctx, engineSide)
		client.server.shutdown()
		_ = engineSide.Close()
		client.served <- err
	}()
	go client.readFrames()
	t.Cleanup(func() { client.stop() })

	gatewayPlan, err := decodeWinn3Create(
		frameCreate(clientAddr, "10.8.1.1", "10.8.1.3", sizing, pathMTU), true, false)
	if err != nil {
		t.Fatal(err)
	}
	type gatewayRound struct {
		loop   *driver.Loop
		device *winn3FrameDevice
		cancel context.CancelFunc
		done   chan struct{}
	}
	startGateway := func() *gatewayRound {
		cfg, _, err := ring.gatewayKeys.sessionConfig()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := carrier.NewUDP(carrier.UDPConfig{
			Conn: gatewaySock, Peer: clientAddr, OwnsConn: false,
			MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
		})
		if err != nil {
			t.Fatal(err)
		}
		device, err := newWinn3FrameDevice(sizing.InnerMTU)
		if err != nil {
			t.Fatal(err)
		}
		tunConfig := tun.Config{
			Assign: gatewayPlan.assign,
			Device: device,
			Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
		}
		loop, err := driver.NewGateway(driver.Config{
			Session: cfg, Sizing: sizing, Carrier: conn, Tun: &tunConfig,
		})
		if err != nil {
			t.Fatal(err)
		}
		runCtx, stop := context.WithCancel(ctx)
		g := &gatewayRound{loop: loop, device: device, cancel: stop, done: make(chan struct{})}
		go func() {
			defer close(g.done)
			_ = loop.Run(runCtx)
			_ = device.Close()
			_ = conn.Close()
		}()
		return g
	}
	up := ipv4Packet([4]byte{10, 8, 1, 3}, [4]byte{10, 8, 1, 1}, []byte("up"))
	carryUp := func(g *gatewayRound, within time.Duration) {
		t.Helper()
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			client.inboundPacket(t, up)
			for wait := time.Now().Add(300 * time.Millisecond); time.Now().Before(wait); {
				if _, ok := g.device.tryTake(); ok {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		t.Fatalf("nothing reached the gateway within %v", within)
	}
	down := ipv4Packet([4]byte{10, 8, 1, 1}, [4]byte{10, 8, 1, 3}, []byte("down"))
	carryDown := func(g *gatewayRound, within time.Duration) {
		t.Helper()
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			_ = g.device.offer(down)
			select {
			case <-client.inbound:
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
		t.Fatalf("nothing reached the client host within %v", within)
	}

	g1 := startGateway()
	client.create(t, frameCreate(gatewayAddr, "10.8.1.3", "10.8.1.1", sizing, pathMTU))
	_ = client.ack(t)
	carryUp(g1, 30*time.Second)
	carryDown(g1, 20*time.Second)
	if st := client.status(t); st.Lifecycle != driver.LifecycleConnected || !st.PromotionReady {
		t.Fatalf("round one proved delivery but published lifecycle %q promotion_ready %v", st.Lifecycle, st.PromotionReady)
	}
	firstLoop := client.server.currentLoop()

	// The gateway goes silent: its loop stops without a CLOSE, and nothing
	// reads its socket until a new gateway session does.
	g1.cancel()
	<-g1.done
	waitUntil(t, 30*time.Second, "round one to die of liveness", func() bool {
		return client.server.currentLoop() != firstLoop || client.server.recovering.Load()
	})
	if err := firstLoop.Session().Err(); !errors.Is(err, session.ErrPeerUnreachable) {
		t.Fatalf("round one ended with %v, want the liveness verdict", err)
	}
	if reason := firstLoop.PeerCloseReason(); reason != 0 {
		t.Fatalf("round one saw a peer CLOSE (%s); this test is about silence", reason)
	}
	if st := client.status(t); st.Lifecycle != driver.LifecycleRecovering || st.PromotionReady || st.Posture != winn3PostureHold || st.RxPackets != 0 {
		t.Fatalf("status after the liveness death: lifecycle %q promotion_ready %v posture %q rx_packets %d",
			st.Lifecycle, st.PromotionReady, st.Posture, st.RxPackets)
	}

	g2 := startGateway()
	defer func() { g2.cancel(); <-g2.done }()
	waitUntil(t, 30*time.Second, "a fresh client session", func() bool {
		l := client.server.currentLoop()
		return l != nil && l != firstLoop && l.Established()
	})
	carryUp(g2, 30*time.Second)
	carryDown(g2, 20*time.Second)
	if st := client.status(t); st.Lifecycle != driver.LifecycleConnected || !st.PromotionReady {
		t.Fatalf("the successor proved delivery but published lifecycle %q promotion_ready %v", st.Lifecycle, st.PromotionReady)
	}
	select {
	case refusal := <-client.errs:
		t.Fatalf("the host was sent an Error frame: %s", refusal)
	default:
	}
	select {
	case err := <-client.served:
		t.Fatalf("the frame conversation ended: %v", err)
	default:
	}
	if n := client.server.socketCloses.Load(); n != 0 {
		t.Fatalf("the adopted socket was closed %d times during recovery", n)
	}
	client.close(t)
}
