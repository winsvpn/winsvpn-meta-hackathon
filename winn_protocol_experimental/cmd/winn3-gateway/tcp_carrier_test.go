package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

func tcpGatewayForTest(t *testing.T, maxSessions int, runFor time.Duration) (string, string, *safeBuffer) {
	t.Helper()
	opts := operatorValueOptions(t)
	opts.plan = "udp,tcp"
	opts.tcpIngress = true // Round W's path is off by default (-tcp-ingress)
	opts.maxSessions = maxSessions
	opts.runFor = runFor
	output := &safeBuffer{}
	done := make(chan error, 1)
	go func() { done <- runServe(opts, output) }()
	t.Cleanup(func() {
		if err := <-done; err != nil {
			t.Errorf("runServe: %v", err)
		}
	})
	return waitListening(t, output, done, 5*time.Second), filepath.Dir(opts.staticPath), output
}

type tcpClientForTest struct {
	loop *driver.Loop
	dev  *testDevice
}

func newCarrierClientForTest(t *testing.T, ctx context.Context, dir string,
	sizing driver.Sizing, conn carrier.Conn) *tcpClientForTest {
	t.Helper()
	static, err := core.NewStaticKey(readTestKey(t, filepath.Join(dir, "client.key")))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := core.NewPublicKey(readTestKey(t, filepath.Join(dir, "static.pub")))
	if err != nil {
		t.Fatal(err)
	}
	dev := newTestDevice(sizing.InnerMTU)
	loop, err := driver.NewClient(driver.Config{
		Session: session.Config{
			Core: core.Config{Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{readTestSecret(t, filepath.Join(dir, "admission.key"))},
				GatewayID:     []byte(testGatewayID),
			}},
			Static: static, GatewayStatic: gw, Padding: core.PadBucket,
		},
		Sizing: sizing, Carrier: conn,
		Tun: &tun.Config{
			Assign: tun.Assignment{V4: netip.MustParseAddr(testClientInner)},
			Device: dev, Clock: driver.SessionClock{Clock: driver.SystemClock{}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = loop.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		_ = loop.Close()
		_ = dev.Close()
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("client loop did not stop")
		}
	})
	return &tcpClientForTest{loop: loop, dev: dev}
}

func tcpCarrierForTest(t *testing.T, endpoint, dir string, sizing driver.Sizing) carrier.Conn {
	t.Helper()
	conn, err := carrier.DialStream(context.Background(), carrier.DialTCP(endpoint), carrier.StreamConfig{
		Secret: readTestSecret(t, filepath.Join(dir, "admission.key")),
		Role:   carrier.RoleClient, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU, TCPFirstFlight: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestTCPCarrierCarriesInnerTrafficBothWays(t *testing.T) {
	endpoint, dir, _ := tcpGatewayForTest(t, 4, 8*time.Second)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	client := newCarrierClientForTest(t, context.Background(), dir, sizing,
		tcpCarrierForTest(t, endpoint, dir, sizing))
	waitFor(t, 4*time.Second, "TCP client carrying", func() bool {
		return client.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	payload := []byte("tcp carrier round trip")
	client.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, payload))
	got := client.dev.take(t, 4*time.Second)
	if !bytes.Equal(got[20:], payload) {
		t.Fatalf("TCP reply payload = %q", got[20:])
	}
}

func TestTCPAdmissionRespectsSharedSessionCap(t *testing.T) {
	endpoint, dir, _ := tcpGatewayForTest(t, 1, 7*time.Second)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	first := newCarrierClientForTest(t, context.Background(), dir, sizing,
		tcpCarrierForTest(t, endpoint, dir, sizing))
	waitFor(t, 4*time.Second, "first TCP client carrying", func() bool {
		return first.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	second := newCarrierClientForTest(t, context.Background(), dir, sizing,
		tcpCarrierForTest(t, endpoint, dir, sizing))
	time.Sleep(1200 * time.Millisecond)
	if second.loop.Tunnel().Gate().State() == tun.StateCarrying {
		t.Fatal("second TCP session bypassed the shared one-session cap")
	}
	if first.loop.Tunnel().Gate().State() != tun.StateCarrying {
		t.Fatal("first TCP session lost its slot")
	}
}

func TestTCPRevocationForcedRelease(t *testing.T) {
	f := newRevokedFixture(t)
	f.ps.conn = f.ps.pipe
	f.ps.pipe = nil
	f.srv.tcpPeers = map[*peerSession]struct{}{f.ps: {}}
	now := time.Now()
	f.ps.revoke = revokeState{stage: revokeStopped, decidedAt: now.Add(-revokedCloseDeadline)}
	var result revokedSweepResult
	f.srv.advanceRevokedTeardown(f.ps, now, &result)
	if result.released != 1 || f.ps.revoke.stage != revokeReleased {
		t.Fatalf("forced TCP release did not finish: result=%+v stage=%d", result, f.ps.revoke.stage)
	}
	if len(f.srv.tcpPeers) != 0 {
		t.Fatal("released TCP peer still occupies its session slot")
	}
}

func TestTCPReleaseBeforeAdmissionDoesNotOccupySlot(t *testing.T) {
	srv, _ := newTestServer(t, 1)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	srv.sizing = sizing
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	stream, err := carrier.NewStream(carrier.StreamConfig{
		Conn: right, Secret: make([]byte, 32), Role: carrier.RoleGateway,
		MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	released := make(chan struct{})
	allowRelease := make(chan struct{})
	defer close(allowRelease)
	srv.holdTCPRelease = func() {
		close(released)
		<-allowRelease
	}
	srv.afterTCPStart = func(ps *peerSession, err error) {
		if err != nil {
			t.Fatalf("start TCP peer: %v", err)
		}
		cancel()
		select {
		case <-released:
		case <-time.After(3 * time.Second):
			t.Fatal("TCP loop did not begin release before admission")
		}
	}
	srv.admitTCP(ctx, &tcpAccepted{stream: stream, fallback: func() {}})
	srv.mu.Lock()
	occupied := len(srv.tcpPeers)
	building := srv.building
	srv.mu.Unlock()
	if occupied != 0 || building != 0 {
		t.Fatalf("released TCP loop occupies %d slots with %d builds", occupied, building)
	}
}

func TestResponsiveUDPDoesNotDialTCPFallback(t *testing.T) {
	endpoint, dir, _ := tcpGatewayForTest(t, 4, 6*time.Second)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ResolveUDPAddr("udp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := carrier.DialUDP(context.Background(), carrier.UDPConfig{
		Remote: remote, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newCarrierClientForTest(t, ctx, dir, sizing, udp)
	var dialed atomic.Int32
	go driver.MigrateSilentUDP(ctx, client.loop, func(context.Context) (carrier.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("responsive UDP unexpectedly requested TCP")
	})
	waitFor(t, 4*time.Second, "responsive UDP client carrying", func() bool {
		return client.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	time.Sleep(1100 * time.Millisecond)
	if got := dialed.Load(); got != 0 {
		t.Fatalf("responsive UDP path dialed TCP %d times", got)
	}
}

func TestUDPSilenceMigratesToTCPWithinFourSeconds(t *testing.T) {
	endpoint, dir, _ := tcpGatewayForTest(t, 32, 48*time.Second)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	durations := make([]time.Duration, 20)
	admission := readTestSecret(t, filepath.Join(dir, "admission.key"))
	for n := range durations {
		udp, err := carrier.DialUDP(context.Background(), carrier.UDPConfig{
			Remote:         silent.LocalAddr().(*net.UDPAddr),
			MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		client := newCarrierClientForTest(t, ctx, dir, sizing, udp)
		started := time.Now()
		go driver.MigrateSilentUDP(ctx, client.loop, func(dialCtx context.Context) (carrier.Conn, error) {
			return carrier.DialStream(dialCtx, carrier.DialTCP(endpoint), carrier.StreamConfig{
				Secret: admission,
				Role:   carrier.RoleClient, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU, TCPFirstFlight: true,
			})
		})
		waitFor(t, 4*time.Second, "UDP-drop TCP fallback", func() bool {
			return client.loop.Tunnel().Gate().State() == tun.StateCarrying
		})
		durations[n] = time.Since(started)
		cancel()
		_ = client.loop.Close()
		_ = client.loop.Carrier().Close()
	}
	for _, elapsed := range durations {
		if elapsed > 4*time.Second {
			t.Fatalf("fallback exceeded four seconds: %v", durations)
		}
	}
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	t.Logf("fallback p50=%v p95=%v max=%v", sorted[9], sorted[18], sorted[19])
	t.Logf("20 UDP-drop fallback durations: %v", durations)
}

func TestTCPSessionTablePressureReclaimsAnUnopenableSlot(t *testing.T) {
	srv, _ := newTestServer(t, 1)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	srv.sizing = sizing
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	stream, err := carrier.NewStream(carrier.StreamConfig{
		Conn: right, Secret: make([]byte, 32), Role: carrier.RoleGateway,
		MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); srv.closeAll() }()
	ps, err := srv.startPeerSession(ctx, &peerSession{
		remote: netip.MustParseAddrPort("127.0.0.1:9"), done: make(chan struct{}),
	}, stream, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	srv.tcpPeers = map[*peerSession]struct{}{ps: {}}
	srv.mu.Unlock()

	from := netip.MustParseAddrPort("127.0.0.1:10")
	if _, err := srv.sessionFor(ctx, from); err == nil {
		t.Fatal("an active TCP session did not hold the shared session cap")
	}
	if _, err := ps.loop.Session().Deliver([]byte{0}); err != nil {
		t.Fatalf("deliver unopenable handshake: %v", err)
	}
	if ps.loop.Session().ReclaimView().Unopenable == 0 {
		t.Fatal("the TCP half-open session did not record the unopenable handshake")
	}
	udp, err := srv.sessionFor(ctx, from)
	if err != nil {
		t.Fatalf("UDP admission after TCP reclaim: %v", err)
	}
	srv.mu.Lock()
	tcpSlots, udpSlots := len(srv.tcpPeers), len(srv.peers)
	srv.mu.Unlock()
	if tcpSlots != 0 || udpSlots != 1 || udp == nil || srv.reclaimed.Load() != 1 {
		t.Fatalf("after TCP reclaim: tcp=%d udp=%d reclaimed=%d", tcpSlots, udpSlots, srv.reclaimed.Load())
	}
	waitFor(t, 3*time.Second, "reclaimed TCP resources to close", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return len(srv.retiring) == 0
	})
}

func TestSupersedePairsIncludeTCPInBothCarrierOrders(t *testing.T) {
	olderAt := time.Now().Add(-time.Minute)
	newerAt := time.Now().Add(-time.Second)
	peer := []byte("same client key")
	makeView := func(ps *peerSession, tcp bool, at time.Time) slotView {
		return slotView{ps: ps, tcp: tcp, view: session.ReclaimView{
			State: session.StateEstablished, Established: true,
			PeerStatic: peer, CurGenAt: at, LastAuthRecv: at.Add(time.Millisecond),
		}}
	}
	for _, olderTCP := range []bool{false, true} {
		older := &peerSession{}
		newer := &peerSession{}
		views := []slotView{
			makeView(older, olderTCP, olderAt),
			makeView(newer, !olderTCP, newerAt),
		}
		pairs := supersedePairs(views, func(v slotView) bool { return v.ps == newer })
		if len(pairs) != 1 || pairs[0].old.ps != older || pairs[0].newer.ps != newer {
			t.Fatalf("olderTCP=%v: cross-carrier supersede pairs = %+v", olderTCP, pairs)
		}
	}
}

func TestConfirmedTCPSessionSupersedesOlderTCPSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := newReclaimRig(t, 4, nil)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	r.srv.sizing = sizing
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open TCP loopback listener: %v", err)
	}
	r.srv.tcp = newTCPIngress(listener, r.opts.admission, r.srv.sessionCfg, sizing)
	t.Cleanup(func() { _ = r.srv.tcp.Close() })
	r.serve(t, ctx)
	waitFor(t, 3*time.Second, "TCP admission gate", func() bool {
		return r.srv.tcp.admission.Load() != nil
	})
	endpoint := listener.Addr().String()
	start := func() *tcpClientForTest {
		return newCarrierClientForTest(t, ctx, r.opts.dir, sizing,
			tcpCarrierForTest(t, endpoint, r.opts.dir, sizing))
	}
	olderClient := start()
	waitFor(t, 4*time.Second, "older TCP client carrying", func() bool {
		return olderClient.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	r.srv.mu.Lock()
	var older *peerSession
	for ps := range r.srv.tcpPeers {
		older = ps
	}
	r.srv.mu.Unlock()
	if older == nil {
		t.Fatal("older TCP session was not entered in the table")
	}
	newerClient := start()
	waitFor(t, 4*time.Second, "newer TCP client carrying", func() bool {
		return newerClient.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	newerClient.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, []byte("confirm newer")))
	_ = newerClient.dev.take(t, 4*time.Second)
	r.srv.mu.Lock()
	var newer *peerSession
	for ps := range r.srv.tcpPeers {
		if ps != older {
			newer = ps
		}
	}
	r.srv.mu.Unlock()
	if newer == nil {
		t.Fatal("newer TCP session was not entered in the table")
	}
	waitFor(t, 4*time.Second, "newer TCP session confirmed usable", func() bool {
		return confirmedUsable(newer.loop.Session().ReclaimView())
	})
	if n := r.srv.supersedeOnce(func(v slotView) bool { return v.ps == newer }); n != 1 {
		t.Fatalf("supersede retired %d TCP sessions, want 1", n)
	}
	r.srv.mu.Lock()
	_, olderPresent := r.srv.tcpPeers[older]
	_, newerPresent := r.srv.tcpPeers[newer]
	r.srv.mu.Unlock()
	if olderPresent || !newerPresent || !older.loop.Session().State().Terminal() {
		t.Fatalf("TCP supersede: old present=%v newer present=%v old state=%s",
			olderPresent, newerPresent, older.loop.Session().State())
	}
	newerClient.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, []byte("after supersede")))
	_ = newerClient.dev.take(t, 4*time.Second)
}
