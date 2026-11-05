package main

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// A close request that fails is retried on later sweeps; after
// revokedCloseRetries failures the sweep falls back to local teardown.
func TestFailedCloseRequestIsRetriedThenTornDownLocally(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	var calls atomic.Int32
	f.ps.revoke.closeRequest = func() error {
		calls.Add(1)
		return errors.New("injected close failure")
	}
	start := time.Now()
	f.revoke(t)
	f.srv.closeRevokedSessions(start)
	due := start.Add(revokedSessionGrace)
	for i := 0; i < revokedCloseRetries-1; i++ {
		res := f.srv.closeRevokedSessions(due.Add(time.Duration(i) * time.Second))
		if res.closeFailed != 1 || res.stopped != 0 {
			t.Fatalf("attempt %d: %+v, want one failure and no teardown yet", i+1, res)
		}
	}
	if got := f.stops.Load(); got != 0 {
		t.Fatalf("torn down before the retries were spent: stops = %d", got)
	}
	res := f.srv.closeRevokedSessions(due.Add(time.Duration(revokedCloseRetries) * time.Second))
	if res.closeFailed != 1 || res.stopped != 1 {
		t.Fatalf("final attempt: %+v, want the failure and a local teardown", res)
	}
	if got := calls.Load(); got != revokedCloseRetries {
		t.Fatalf("close requested %d times, want %d", got, revokedCloseRetries)
	}
	if got := f.stops.Load(); got != 1 {
		t.Fatalf("local teardown did not cancel the loop context: stops = %d", got)
	}
}

// A failed request followed by a successful one commits the close without any
// local teardown.
func TestCloseRequestRetrySucceeds(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	var calls atomic.Int32
	f.ps.revoke.closeRequest = func() error {
		if calls.Add(1) == 1 {
			return errors.New("injected close failure")
		}
		return f.gw.Close()
	}
	start := time.Now()
	f.revoke(t)
	f.srv.closeRevokedSessions(start)
	due := start.Add(revokedSessionGrace)
	if res := f.srv.closeRevokedSessions(due); res.closeFailed != 1 {
		t.Fatalf("first attempt: %+v", res)
	}
	if res := f.srv.closeRevokedSessions(due.Add(time.Second)); res.closeRequested != 1 {
		t.Fatalf("retry: %+v, want the close committed", res)
	}
	if f.gatewayOpen(t) || f.stops.Load() != 0 {
		t.Fatalf("state %v, stops %d", f.gw.Session().State(), f.stops.Load())
	}
}

// The gateway's revocation signal is the ordinary sealed CLOSE. It must be
// accepted only as sent, by the session it was sealed for. The AEAD, token
// window and replay filter it rides are pinned in winn3/core
// (session_test.go TestTransportReplayRejected, TestCorruptedMessageDoesNotConsumeToken,
// TestTransportShortAndForeignMessages); this pins the same properties for a
// CLOSE specifically, at the session layer the client actually runs.
func TestGatewayCloseIsAuthenticated(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	// A second, independent session between the same two static keys.
	gw2, cli2 := f.newPair(t)

	if err := f.gw.Session().Close(); err != nil {
		t.Fatal(err)
	}
	closeMsg, err := f.gw.Session().Poll()
	if err != nil || closeMsg == nil {
		t.Fatalf("no CLOSE was sealed: %v", err)
	}
	genuine := append([]byte(nil), closeMsg...)

	stillOpen := func(t *testing.T, d *session.Driver, what string) {
		t.Helper()
		if d.State() != session.StateEstablished || d.PeerCloseReason() != 0 {
			t.Fatalf("%s: client state %v, peer close reason %v", what, d.State(), d.PeerCloseReason())
		}
	}
	for _, at := range []int{0, core.DemuxTokenSize, len(genuine) / 2, len(genuine) - 1} {
		mod := append([]byte(nil), genuine...)
		mod[at] ^= 0x01
		_, _ = f.cli.Session().Deliver(mod)
		stillOpen(t, f.cli.Session(), "modified CLOSE")
	}
	_, _ = f.cli.Session().Deliver(genuine[:len(genuine)-1])
	stillOpen(t, f.cli.Session(), "truncated CLOSE")
	forged := make([]byte, len(genuine))
	if _, err := rand.Read(forged); err != nil {
		t.Fatal(err)
	}
	_, _ = f.cli.Session().Deliver(forged)
	stillOpen(t, f.cli.Session(), "forged CLOSE")
	_, _ = cli2.Session().Deliver(genuine)
	stillOpen(t, cli2.Session(), "cross-session CLOSE")

	// Positive control: the genuine CLOSE ends the session it was sealed for.
	_, _ = f.cli.Session().Deliver(genuine)
	if !f.cli.Session().State().Terminal() || f.cli.Session().PeerCloseReason() != session.CloseNormal {
		t.Fatalf("genuine CLOSE: state %v, reason %v", f.cli.Session().State(), f.cli.Session().PeerCloseReason())
	}
	// Replay into the other session after the first has ended.
	_, _ = cli2.Session().Deliver(genuine)
	stillOpen(t, cli2.Session(), "replayed CLOSE from an ended session")
	pumpPair(t, cli2.Session(), gw2.Session())
	stillOpen(t, cli2.Session(), "second session after the replay")
}

// ---------------------------------------------------------------------------
// Running loops. Both ends run driver.Loop.Run over a pair of in-memory pipes
// whose gateway-to-client (and optionally client-to-gateway) direction can be
// cut, so a CLOSE can be lost exactly as a censor or a bad path would lose it.
// ---------------------------------------------------------------------------

type runningPair struct {
	f         *revokedFixture
	srv       *server
	ps        *peerSession
	gw, cli   *driver.Loop
	gwDone    chan struct{}
	cliDone   chan struct{}
	cutToCli  atomic.Bool
	cutToGw   atomic.Bool
	cliRunErr error
	cancelAll context.CancelFunc
}

// quickLiveness makes a client notice a silent gateway within about a second
// instead of about half a minute.
func quickLiveness(cfg *session.Config) {
	cfg.Silence = session.Draw{Min: 40 * time.Millisecond, Mean: 60 * time.Millisecond, Max: 100 * time.Millisecond}
	cfg.Probe = session.Draw{Min: 40 * time.Millisecond, Mean: 60 * time.Millisecond, Max: 100 * time.Millisecond}
	cfg.MaxLostProbes = 2
}

// onceCloseInner makes fakeInner's Close idempotent under concurrency, as
// every production device's Close is (reflector, gatewayForwardDevice and
// resolverDevice all use sync.Once). fakeInner checks then closes, which
// panics when two releasePeer calls overlap, and those do overlap here: the
// independent teardown and the Run goroutine's own release.
type onceCloseInner struct {
	*fakeInner
	once sync.Once
}

func (d *onceCloseInner) Close() error {
	d.once.Do(func() { _ = d.fakeInner.Close() })
	return nil
}

func newRunningPair(t *testing.T) *runningPair {
	t.Helper()
	f := newRevokedFixture(t)
	p := &runningPair{f: f, gwDone: make(chan struct{}), cliDone: make(chan struct{})}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	var gwPipe, cliPipe *carrier.Pipe
	gwPipe, err = carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: testPathMTU, MaxMessageSize: sizing.MessageSize, Depth: (&server{}).pipeInboxDepth(),
		Out: func(msg []byte) error {
			if p.cutToCli.Load() {
				return nil
			}
			_ = cliPipe.Deliver(msg)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cliPipe, err = carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: testPathMTU, MaxMessageSize: sizing.MessageSize, Depth: (&server{}).pipeInboxDepth(),
		Out: func(msg []byte) error {
			if p.cutToGw.Load() {
				return nil
			}
			_ = gwPipe.Deliver(msg)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := core.NewStaticKey(readTestKey(t, filepath.Join(f.dir, "client.key")))
	if err != nil {
		t.Fatal(err)
	}
	gatewayKey, err := core.NewPublicKey(readTestKey(t, filepath.Join(f.dir, "static.pub")))
	if err != nil {
		t.Fatal(err)
	}
	cliCfg := session.Config{Core: f.gwCfg.Core, Static: clientKey, GatewayStatic: gatewayKey, Padding: core.PadBucket}
	quickLiveness(&cliCfg)
	p.gw, err = driver.NewGateway(driver.Config{Session: f.gwCfg, Sizing: sizing, Carrier: gwPipe})
	if err != nil {
		t.Fatal(err)
	}
	p.cli, err = driver.NewClient(driver.Config{Session: cliCfg, Sizing: sizing, Carrier: cliPipe})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancelAll = cancel
	gwCtx, gwStop := context.WithCancel(ctx)
	p.ps = &peerSession{
		loop: p.gw, pipe: gwPipe, dev: &onceCloseInner{fakeInner: newFakeInner(1400)}, stop: gwStop,
		done: make(chan struct{}), remote: netip.MustParseAddrPort("192.0.2.1:40000"),
	}
	p.srv = &server{peerRegistry: f.srv.peerRegistry, peers: map[netip.AddrPort]*peerSession{p.ps.remote: p.ps}}
	// The same shape as newSession's Run goroutine, including its ORDER:
	// ps.done is closed by a defer, so only after releasePeer has run
	// (main.go newSession). The sweep skips sessions whose done is closed.
	go func() {
		defer close(p.gwDone)
		defer close(p.ps.done)
		_ = p.gw.Run(gwCtx)
		p.srv.releasePeer(p.ps.remote, p.ps)
	}()
	go func() {
		defer close(p.cliDone)
		p.cliRunErr = p.cli.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = p.cli.Close()
		_ = p.gw.Close()
		_ = cliPipe.Close()
		_ = gwPipe.Close()
		<-p.gwDone
		<-p.cliDone
	})
	waitUntil(t, 5*time.Second, "both ends established", func() bool {
		return p.gw.Session().State() == session.StateEstablished && p.cli.Session().State() == session.StateEstablished
	})
	return p
}

func waitUntil(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func chanClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// sweepUntilClosed drives the sweep on synthetic time until the gateway round
// has ended, the way the serve ticker would.
func (p *runningPair) sweepUntilClosed(t *testing.T) {
	t.Helper()
	start := time.Now()
	for i := 0; i <= 40 && !chanClosed(p.gwDone); i++ {
		p.srv.closeRevokedSessions(start.Add(time.Duration(i) * time.Second))
		time.Sleep(10 * time.Millisecond)
	}
	waitUntil(t, 5*time.Second, "the gateway round to end", func() bool { return chanClosed(p.gwDone) })
}

// Closure with both loops running, with the sweep's REAL close request
// overlapping a registry reload and an independent teardown of the same
// session. Coordination is by barriers, never by sleeps:
//
//  1. the sweep records its first unauthorized observation (asserted);
//  2. the sweep is run at the due-close boundary; the close-request hook,
//     which wraps the real driver.Loop.Close, parks the sweep at a barrier
//     the moment it enters the close-request path;
//  3. registry reload churn and an independent releasePeer are started and
//     meet the sweep at a common start barrier, so all three overlap;
//  4. the test asserts the close was attempted exactly once through the
//     sweep's path, that the sweep reported it, and that teardown completed.
//
// With the sweep's close action disabled, step 2 never happens and the test
// fails at the "entered the close-request path" wait. Run under -race.
func TestRevokedCloseWithRunningLoopsConcurrentWithReloadAndTeardown(t *testing.T) {
	t.Parallel()
	p := newRunningPair(t)

	entered := make(chan struct{})
	start := make(chan struct{})
	var attempts atomic.Int32
	p.ps.revoke.closeRequest = func() error {
		attempts.Add(1)
		close(entered)
		<-start
		return p.gw.Close()
	}

	// 1. First unauthorized observation.
	p.f.revoke(t)
	t0 := time.Now()
	if res := p.srv.closeRevokedSessions(t0); res != (revokedSweepResult{}) {
		t.Fatalf("first observation acted: %+v", res)
	}
	if p.ps.revoke.unauthorizedSince.IsZero() {
		t.Fatal("the sweep did not record an unauthorized observation")
	}
	if p.gw.Session().State() != session.StateEstablished {
		t.Fatalf("gateway left ESTABLISHED on the first observation: %v", p.gw.Session().State())
	}

	// 2. The due-close boundary, on its own goroutine so it can be parked.
	sweepDone := make(chan revokedSweepResult, 1)
	go func() { sweepDone <- p.srv.closeRevokedSessions(t0.Add(revokedSessionGrace)) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep never entered its close-request path at the due-close boundary")
	}

	// 3. Reload and independent teardown, released together with the close.
	var wg sync.WaitGroup
	ready := make(chan struct{}, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		bodies := []string{`{"version":1,"peers":[`, `{"peers":[],"version":1}`}
		for i := 0; i < 64; i++ {
			replaceAuthority(t, p.f.path, bodies[i%2])
			dueAuthorityRefresh(p.srv.peerRegistry)
			_ = p.srv.peerAuthorized(p.f.key)
		}
	}()
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		p.srv.releasePeer(p.ps.remote, p.ps)
	}()
	<-ready
	<-ready
	close(start)

	// 4. Outcomes.
	var res revokedSweepResult
	select {
	case res = <-sweepDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep did not return after its close request was released")
	}
	wg.Wait()
	if got := attempts.Load(); got != 1 {
		t.Fatalf("close attempted %d times through the sweep's path, want 1", got)
	}
	if res.closeRequested != 1 || res.closeFailed != 0 {
		t.Fatalf("sweep result %+v, want exactly one committed close request", res)
	}
	waitUntil(t, 10*time.Second, "the gateway round and its release to complete", func() bool {
		return chanClosed(p.gwDone) && chanClosed(p.ps.done)
	})
	p.srv.mu.Lock()
	remaining := len(p.srv.peers)
	p.srv.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("teardown left %d session(s) in the demux table", remaining)
	}
	if dev, ok := p.ps.dev.(*onceCloseInner); !ok || !chanClosed(dev.done) {
		t.Fatal("teardown did not close the session's device")
	}
	waitUntil(t, 10*time.Second, "the client to leave ESTABLISHED", func() bool {
		return p.cli.Session().State() != session.StateEstablished
	})
	// A later sweep must leave a finished session alone.
	if res := p.srv.closeRevokedSessions(t0.Add(3 * revokedSessionGrace)); res != (revokedSweepResult{}) {
		t.Fatalf("sweep acted on a finished session: %+v", res)
	}
}

// The CLOSE is lost. The client must still leave "connected" through its own
// detection (silence timer, then unanswered liveness probes), never by
// waiting for a gateway message that will not come.
func TestClientLeavesConnectedWhenTheGatewayCloseIsLost(t *testing.T) {
	t.Parallel()
	p := newRunningPair(t)
	p.f.revoke(t)
	p.cutToCli.Store(true)
	p.sweepUntilClosed(t)
	waitUntil(t, 10*time.Second, "the client's own detection to end its round", func() bool { return chanClosed(p.cliDone) })
	if reason := p.cli.Session().PeerCloseReason(); reason != 0 {
		t.Fatalf("client reports a peer CLOSE (%v) it cannot have received", reason)
	}
	if !p.cli.Session().State().Terminal() {
		t.Fatalf("client round ended in state %v", p.cli.Session().State())
	}
	if p.cliRunErr == nil {
		t.Fatal("client round ended without an error, so its supervisor would read it as a clean close")
	}
}

// Ordering 1: the client's detection fires first (the path dies), THEN the
// gateway sweep closes its side. The late close must not disturb the client.
func TestClientDetectionBeforeGatewayClose(t *testing.T) {
	t.Parallel()
	p := newRunningPair(t)
	p.cutToCli.Store(true)
	p.cutToGw.Store(true)
	waitUntil(t, 10*time.Second, "the client's detection", func() bool { return chanClosed(p.cliDone) })
	stateBefore := p.cli.Session().State()
	p.f.revoke(t)
	p.sweepUntilClosed(t)
	if got := p.cli.Session().State(); got != stateBefore || p.cli.Session().PeerCloseReason() != 0 {
		t.Fatalf("late gateway close changed the client: %v -> %v, reason %v",
			stateBefore, got, p.cli.Session().PeerCloseReason())
	}
}

// Ordering 2: the gateway close arrives first; the client's detection, which
// would have fired had the close been lost, must not fire afterwards.
func TestGatewayCloseBeforeClientDetection(t *testing.T) {
	t.Parallel()
	p := newRunningPair(t)
	p.f.revoke(t)
	p.sweepUntilClosed(t)
	waitUntil(t, 5*time.Second, "the client to take the CLOSE", func() bool { return chanClosed(p.cliDone) })
	if reason := p.cli.Session().PeerCloseReason(); reason != session.CloseNormal {
		t.Fatalf("client peer close reason = %v, want %v", reason, session.CloseNormal)
	}
	p.cutToCli.Store(true)
	p.cutToGw.Store(true)
	time.Sleep(500 * time.Millisecond) // several client liveness budgets
	if p.cli.Session().State() != session.StateClosed || p.cli.Session().PeerCloseReason() != session.CloseNormal {
		t.Fatalf("client detection re-fired after the close: state %v, reason %v",
			p.cli.Session().State(), p.cli.Session().PeerCloseReason())
	}
}

// The resolver's refusals and suppressions are visible to the operator, not
// only to the client that stops getting answers.
func TestResolverAuthorizationCountersAreVisible(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	release := make(chan struct{})
	up := startCountingUpstream(t, release, true)
	d := f.resolverDevice(t, up.addr, 2*time.Second)
	if _, err := d.WritePacket(dnsQueryFrom(t, revokedTestInner, 0x7777)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 3*time.Second, "the authorized query to reach the upstream", func() bool { return up.queries.Load() == 1 })
	f.revoke(t)
	if _, err := d.WritePacket(dnsQueryFrom(t, revokedTestInner, 0x7778)); err != nil {
		t.Fatal(err)
	}
	close(release)
	stats := waitResolverStats(t, d.res, func(s resolverStats) bool {
		return s.Unauthorized == 1 && s.ReplySuppressed == 1
	})
	if stats.Answered != 0 || stats.Claimed != 2 || up.queries.Load() != 1 {
		t.Fatalf("stats %+v, upstream queries %d", stats, up.queries.Load())
	}
}
