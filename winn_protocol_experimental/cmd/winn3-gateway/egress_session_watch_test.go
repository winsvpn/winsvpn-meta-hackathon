package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round CM3 Turn 3 (GPT-6 Sol OI-CM3-1): a known session's route narrows
// after admission. The stub stands for the kernel; the netns test in
// egress_session_watch_netns_linux_test.go changes a real route.

// egressFixture is a server with a running read loop and one carrying
// client over conn. The client socket is dialled by dial (the netns test
// dials from another namespace).
type egressFixture struct {
	srv *server
	cli *testClient
}

func newEgressFixture(t *testing.T, ctx context.Context, conn *net.UDPConn, dial func(func())) *egressFixture {
	t.Helper()
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	sessionCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	srv := &server{
		conn: conn, sizing: sizing, sessionCfg: sessionCfg, assign: assign, maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
		egressGuard: &clientEgressGuard{lookup: egressLookupFor(gwAddr), datagram: plannedIPv4Datagram(sizing)},
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	t.Cleanup(func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	})
	var cli *testClient
	dial(func() {
		cli = startTestClient(t, ctx, testClientOpts{
			dir: dir, gwAddr: gwAddr,
			gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
			admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
			sizing:        sizing, inner: testClientInner,
		})
	})
	waitFor(t, 40*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	return &egressFixture{srv: srv, cli: cli}
}

func (f *egressFixture) sessions() int {
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()
	return len(f.srv.peers)
}

func loopbackConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestSweepEgressClosesAnEstablishedSessionWhoseRouteNarrowed(t *testing.T) {
	stub := &clientEgressStub{}
	installClientEgressStub(t, stub)
	logs := &safeBuffer{}
	savedLog := egressLog
	egressLog = logs
	t.Cleanup(func() { egressLog = savedLog })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newEgressFixture(t, ctx, loopbackConn(t), func(fn func()) { fn() })
	closing := map[*peerSession]struct{}{}

	if n := f.srv.sweepEgress(time.Now(), closing); n != 0 || f.sessions() != 1 {
		t.Fatalf("wide route: sweep closed %d, sessions %d; want 0 and 1", n, f.sessions())
	}
	asked, _ := stub.record()
	if len(asked) == 0 || asked[len(asked)-1].Addr() != netip.MustParseAddr("127.0.0.1") || asked[len(asked)-1].Port() == 0 {
		t.Fatalf("the sweep did not ask about the live client's address and port: %v", asked)
	}

	// The route narrows after admission; the client's address is unchanged.
	// The close request is held (counted, not yet delivered) so a second
	// sweep meets the same session still in the table.
	var ps *peerSession
	f.srv.mu.Lock()
	for _, p := range f.srv.peers {
		ps = p
	}
	f.srv.mu.Unlock()
	requests := 0
	ps.egressClose.closeRequest = func() error { requests++; return nil }
	stub.allNarrow.Store(true)
	n := f.srv.sweepEgress(time.Now(), closing)
	out := string(logs.snapshot())
	if n != 1 || f.srv.egressClosed.Load() != 1 || requests != 1 {
		t.Fatalf("narrowed route: sweep closed %d, egress_mtu_closed %d, close requests %d; want 1, 1, 1",
			n, f.srv.egressClosed.Load(), requests)
	}
	if line := lineWith(out, "closing a session"); !strings.Contains(line, "now routes through ts1 (mtu 1400") ||
		strings.Contains(line, "127.0.0.1") {
		t.Fatalf("close log %q", line)
	}
	// A second sweep while the close is in flight neither recounts nor
	// re-requests it.
	if n := f.srv.sweepEgress(time.Now(), closing); n != 0 || f.srv.egressClosed.Load() != 1 || requests != 1 {
		t.Fatalf("second sweep: closed %d, total %d, close requests %d", n, f.srv.egressClosed.Load(), requests)
	}
	_ = ps.loop.Close() // deliver the held close
	waitFor(t, 10*time.Second, "the closed session to leave the table", func() bool { return f.sessions() == 0 })
	waitFor(t, 10*time.Second, "the client gate to leave carrying", func() bool {
		return f.cli.loop.Tunnel().Gate().State() != tun.StateCarrying
	})
	if st := f.srv.status(); st.EgressMTUClosed != 1 {
		t.Fatalf("status egress_mtu_closed = %d, want 1", st.EgressMTUClosed)
	}
}

// The watch sweeps on a change notification, coalesces a burst inside the
// minimum gap, and sweeps on the backstop interval without notifications.
func TestRunEgressWatchPacing(t *testing.T) {
	stub := &clientEgressStub{}
	installClientEgressStub(t, stub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newEgressFixture(t, ctx, loopbackConn(t), func(fn func()) { fn() })
	asked := func() int { a, _ := stub.record(); return len(a) }
	base := asked()

	changed := make(chan struct{}, 1)
	tick := make(chan time.Time)
	watchCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); f.srv.runEgressWatch(watchCtx, changed, tick) }()
	defer func() { stop(); <-done }()

	changed <- struct{}{}
	waitFor(t, 2*time.Second, "a sweep after a change notification", func() bool { return asked() == base+1 })
	// A second notification inside the gap is not swept yet...
	changed <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	if got := asked(); got != base+1 {
		t.Fatalf("a notification inside the %v gap swept at once (%d lookups)", egressSweepMinGap, got-base)
	}
	// ...but on the next tick after the gap it is.
	time.Sleep(egressSweepMinGap)
	tick <- time.Now()
	waitFor(t, 2*time.Second, "the pending sweep on the next tick", func() bool { return asked() == base+2 })
	// No notification, backstop not due: no sweep.
	tick <- time.Now()
	time.Sleep(100 * time.Millisecond)
	if got := asked(); got != base+2 {
		t.Fatalf("a tick before the backstop interval swept (%d lookups)", got-base)
	}
	// Backstop due (after the gap, which also applies to it).
	time.Sleep(egressSweepMinGap)
	tick <- time.Now().Add(egressRecheckInterval + time.Second)
	waitFor(t, 2*time.Second, "the backstop sweep", func() bool { return asked() == base+3 })
}

// A committed close that does not end Run is escalated after
// revokedCloseDeadline: the loop context is cancelled.
func TestAdvanceEgressTeardownEscalates(t *testing.T) {
	stops := 0
	ps := &peerSession{done: make(chan struct{}), stop: func() { stops++ }}
	now := time.Now()
	ps.egressClose = egressCloseState{stage: revokeCloseRequested, decidedAt: now}
	closing := map[*peerSession]struct{}{ps: {}}
	s := &server{}
	s.advanceEgressTeardown(now.Add(revokedCloseDeadline-time.Millisecond), closing)
	if stops != 0 || ps.egressClose.stage != revokeCloseRequested {
		t.Fatalf("escalated before the deadline: stops %d stage %d", stops, ps.egressClose.stage)
	}
	s.advanceEgressTeardown(now.Add(revokedCloseDeadline), closing)
	if stops != 1 || ps.egressClose.stage != revokeStopped {
		t.Fatalf("after the deadline: stops %d stage %d, want 1 and stopped", stops, ps.egressClose.stage)
	}
	close(ps.done)
	s.advanceEgressTeardown(now.Add(3*revokedCloseDeadline), closing)
	if len(closing) != 0 || stops != 1 {
		t.Fatalf("a session whose Run returned is still tracked (%d) or was stopped again (%d)", len(closing), stops)
	}
}

// Through runServe: the watch runs on serve's context and closes a carrying
// client's session when its route narrows (here on the backstop, shortened).
func TestRunServeClosesASessionWhoseRouteNarrowed(t *testing.T) {
	savedInterval, savedTick := egressRecheckInterval, egressWatchTick
	egressRecheckInterval, egressWatchTick = 300*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { egressRecheckInterval, egressWatchTick = savedInterval, savedTick })
	stub := &clientEgressStub{}
	installClientEgressStub(t, stub)
	opts := ingressOptions(t, 8*time.Second)
	g := startIngressGateway(t, opts)
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ResolveUDPAddr("udp4", g.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	car, err := carrier.DialUDP(t.Context(), carrier.UDPConfig{Remote: remote, MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU})
	if err != nil {
		t.Fatal(err)
	}
	client := newCarrierClientForTest(t, t.Context(), g.dir, sizing, car)
	waitFor(t, 5*time.Second, "the client to carry", func() bool {
		return client.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	stub.allNarrow.Store(true)
	waitFor(t, 5*time.Second, "the client gate to leave carrying", func() bool {
		return client.loop.Tunnel().Gate().State() != tun.StateCarrying
	})
	st := g.stopped(t)
	if st.EgressMTUClosed < 1 || st.Admitted != 1 {
		t.Fatalf("egress_mtu_closed=%d admitted=%d, want >=1 and 1", st.EgressMTUClosed, st.Admitted)
	}
}
