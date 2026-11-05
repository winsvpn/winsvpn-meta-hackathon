package main

import (
	"bytes"
	"context"
	"net"
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
	"winsvpn.local/winnprotocol/winn3/tun"
)

// These tests are the L22b table-full scenario in miniature: a gateway at its
// -max-sessions ceiling, a slot held by something that will never carry again,
// and a real client that must still be admitted. Each one uses only symbols the
// pre-fix tree already had, so each is red on it and green after.

type reclaimRig struct {
	srv    *server
	gwAddr *net.UDPAddr
	opts   testClientOpts
}

func newReclaimRig(t *testing.T, maxSessions int, tweak func(*session.Config)) *reclaimRig {
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
	if tweak != nil {
		tweak(&sessionCfg)
	}
	assign, err := parseAssignment(testGatewayInner, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	return &reclaimRig{
		srv: &server{
			conn:        conn,
			sizing:      sizing,
			sessionCfg:  sessionCfg,
			assign:      assign,
			maxSessions: maxSessions,
			peers:       make(map[netip.AddrPort]*peerSession),
		},
		gwAddr: gwAddr,
		opts: testClientOpts{
			dir: dir, gwAddr: gwAddr,
			gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
			admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
			sizing:        sizing, inner: testClientInner,
		},
	}
}

// serve runs the whole server, ticker included, until the test ends.
func (r *reclaimRig) serve(t *testing.T, ctx context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = r.srv.serve(ctx, new(bytes.Buffer)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
	})
}

func (r *reclaimRig) sessions() int {
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	return len(r.srv.peers)
}

func (r *reclaimRig) onlySession(t *testing.T) *peerSession {
	t.Helper()
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	if len(r.srv.peers) != 1 {
		t.Fatalf("the gateway holds %d sessions, want 1", len(r.srv.peers))
	}
	for _, ps := range r.srv.peers {
		return ps
	}
	return nil
}

func carrying(cli *testClient) bool {
	return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
}

// killSilently is the client that leaves without a CLOSE: its socket goes away
// and nothing is said. Closing the carrier first means the CLOSE that the
// harness's own cleanup later queues has nowhere to go.
func killSilently(cli *testClient) { _ = cli.car.Close() }

// TestNoiseFromNewAddressesBuysNoSession: a datagram that fails the admission
// tag must not allocate a session, whatever its length. Before the admission
// screen, one byte from each new source port built a session and held a
// ceiling slot for the whole 23.5 s handshake budget.
func TestNoiseFromNewAddressesBuysNoSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)

	for _, n := range []int{1, 128, 1024} {
		c, err := net.DialUDP("udp4", nil, r.gwAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(bytes.Repeat([]byte{0x5a}, n)); err != nil {
			t.Fatal(err)
		}
	}
	// The read loop handles datagrams one at a time, and each one ends either
	// screened (Strangers) or built (Built), so once the two sum to three every
	// datagram's outcome is final. No sleep: v4 slept 300 ms and hoped.
	waitFor(t, supersedeSafety, "the gateway to classify three datagrams", func() bool {
		st := r.srv.status()
		return st.Datagrams >= 3 && st.Strangers+st.Built >= 3
	})
	st := r.srv.status()
	if st.Sessions != 0 || st.Built != 0 {
		t.Fatalf("three unadmissible datagrams built %d sessions and hold %d slots; noise "+
			"must buy nothing (strangers=%d)", st.Built, st.Sessions, st.Strangers)
	}
	if st.Strangers < 3 {
		t.Fatalf("strangers = %d, want 3", st.Strangers)
	}
}

// TestAFullTableAdmitsARealClientOverAFailedHalfOpen: the only slot is held by
// a session that was handed something it could not open and can only time
// out. A real client must be admitted inside its own retry budget.
func TestAFullTableAdmitsARealClientOverAFailedHalfOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := newReclaimRig(t, 1, nil)

	ps, err := r.srv.sessionFor(ctx, netip.MustParseAddrPort("127.0.0.1:9"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.pipe.Deliver(bytes.Repeat([]byte{0xa5}, 200)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the half-open session to refuse the junk", func() bool {
		return ps.loop.Session().Stats().Unopenable > 0
	})
	r.serve(t, ctx)

	cli := startTestClient(t, ctx, r.opts)
	waitFor(t, 15*time.Second, "a real client to carry past a failed half-open", func() bool {
		return carrying(cli)
	})
	if got := r.onlySession(t); got == ps {
		t.Fatal("the failed half-open still holds the only slot")
	}
}

// TestAFullTableReclaimsASessionSilentForTwoProbeCeilings: the only slot is
// held by an established session whose client left without a CLOSE. The
// gateway's MaxLostProbes is set so high that its liveness ladder would never
// free the slot during this test, so only the reclaim rule can admit the next
// client.
func TestAFullTableReclaimsASessionSilentForTwoProbeCeilings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := newReclaimRig(t, 1, func(c *session.Config) {
		c.Probe = session.Draw{Min: 200 * time.Millisecond, Mean: 400 * time.Millisecond, Max: time.Second}
		c.MaxLostProbes = 1000
	})
	r.serve(t, ctx)

	first := startTestClient(t, ctx, r.opts)
	waitFor(t, 20*time.Second, "the first client to carry", func() bool { return carrying(first) })
	old := r.onlySession(t)
	killSilently(first)

	// Two probe ceilings of authenticated silence, plus slack.
	time.Sleep(2500 * time.Millisecond)
	second := startTestClient(t, ctx, r.opts)
	waitFor(t, 15*time.Second, "the next client to carry once the dead session went silent", func() bool {
		return carrying(second)
	})
	if got := r.onlySession(t); got == old {
		t.Fatal("the silent session still holds the only slot")
	}
}

// TestALiveSessionIsNeverReclaimed is the anti-vacuity arm of the test above:
// same configuration, but the first client stays alive and answers probes. The
// newcomer must be refused and the live session must keep its slot.
func TestALiveSessionIsNeverReclaimed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := newReclaimRig(t, 1, func(c *session.Config) {
		c.Probe = session.Draw{Min: 200 * time.Millisecond, Mean: 400 * time.Millisecond, Max: time.Second}
		c.MaxLostProbes = 1000
	})
	r.serve(t, ctx)

	first := startTestClient(t, ctx, r.opts)
	waitFor(t, 20*time.Second, "the first client to carry", func() bool { return carrying(first) })
	old := r.onlySession(t)

	time.Sleep(2500 * time.Millisecond)
	second := startTestClient(t, ctx, r.opts)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if carrying(second) {
			t.Fatal("a newcomer was admitted by displacing a live session")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := r.onlySession(t); got != old {
		t.Fatal("the live session lost its slot")
	}
	if !carrying(first) {
		t.Fatal("the live client stopped carrying")
	}
}

// supersedeSafety is the OUTER safety bound on every wait in the supersede
// tests. It is not a timing budget any assertion depends on: each wait below
// ends on an event (a client carrying, an inner round trip coming back, a state
// the gateway reports), and this bound only stops a broken build from hanging.
// Fix 1 v4's tests instead waited 10 s for the gateway to confirm a session with
// no inner traffic, which only a liveness timer can do: the gateway's or the
// client's first probe, a truncated exponential draw with a 3 s floor, a 8 s
// mean and a 20 s ceiling. Lane L23b measured 12 of 160 such sessions taking
// over 10 s (evidence/e1_*), which is the intermittent failure.
const supersedeSafety = 90 * time.Second

// roundTrip sends one inner packet from cli to the gateway's inner address and
// waits for the reflector's answer. The answer proves the gateway OPENED an
// authenticated message from cli under the current generation's keys, after
// that generation established on the gateway (the client sends DATA only once
// it holds the final flight, which the gateway assembles, and so establishes,
// first). That is exactly confirmedUsable, reached by an event instead of by
// waiting for a probe timer.
func roundTrip(t *testing.T, cli *testClient, tag string) {
	t.Helper()
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, []byte(tag)))
	_ = cli.dev.take(t, supersedeSafety)
}

// TestSupersedeRetiresTheOlderSameKeySessionEndToEnd drives supersedeOnce with
// two real established sessions of the SAME client key and an injected
// forwarding-ownership predicate (the Linux forwarding device does not run on
// this host, so ownership is supplied directly). The older session must be
// retired, removed from the table at once, and torn down; the newer must stay.
func TestSupersedeRetiresTheOlderSameKeySessionEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)
	older, newer, olderCli, newerCli := twoSameKeyConfirmed(t, ctx, r)
	owns := func(v slotView) bool { return v.ps == newer }

	// The older session's client has moved to the newer session, so it stops
	// sending: this is the real supersede shape.
	killSilently(olderCli)
	n, refusals := supersedeJustified(t, r, older, owns)
	if n != 1 {
		t.Fatalf("supersedeOnce retired %d sessions, want 1", n)
	}
	if r.inPeers(older) {
		t.Fatal("the superseded session is still in the table")
	}
	waitFor(t, supersedeSafety, "the superseded session to end", func() bool {
		return older.loop.Session().State().Terminal()
	})
	if newer.loop.Session().State().Terminal() {
		t.Fatal("the confirmed newer session was retired")
	}
	if !r.inPeers(newer) {
		t.Fatal("the confirmed newer session left the table")
	}
	// The replacement still carries after the supersede.
	roundTrip(t, newerCli, "after-supersede")
	t.Logf("supersede committed after %d straggler refusal(s)", refusals)
}

// supersedeJustified runs supersedeOnce until it commits, and fails the test on
// any refusal the victim did not cause. After its client is gone the victim's
// last datagrams may still be in flight or queued on the gateway, and each one
// that opens moves the victim's sequence, which correctly makes the commit
// refuse (the victim must be reclassified). Nothing else may: the replacement's
// own traffic must never defer supersede (Round Q Turn 4, OI-Q4), so a refusal
// while the victim's sequence stood still is a failure. The victim's client is
// gone, so its stragglers are finite and this ends.
func supersedeJustified(t *testing.T, r *reclaimRig, victim *peerSession, owns func(slotView) bool) (n, refusals int) {
	t.Helper()
	return sweepJustified(t, victim, func() int { return r.srv.supersedeOnce(owns) })
}

// sweepJustified is supersedeJustified over any supersede sweep (supersedeOnce
// with an injected predicate, or the production reclaimSupersededSessions).
func sweepJustified(t *testing.T, victim *peerSession, sweep func() int) (n, refusals int) {
	t.Helper()
	for deadline := time.Now().Add(supersedeSafety); ; {
		before, ok := viewOfSlot(victim.remoteAddrPort(), victim)
		if !ok {
			t.Fatal("could not snapshot the victim")
		}
		if n = sweep(); n != 0 {
			return n, refusals
		}
		after, ok := viewOfSlot(victim.remoteAddrPort(), victim)
		if !ok || after.view.Seq == before.view.Seq {
			t.Fatalf("supersedeOnce refused although the victim did not move (seq %d, state %s): "+
				"only a victim receive may defer a supersede", before.view.Seq, after.view.State)
		}
		if refusals++; time.Now().After(deadline) {
			t.Fatalf("the victim kept receiving for %s after its client was gone (%d refusals)",
				supersedeSafety, refusals)
		}
	}
}

// twoSameKeyConfirmed starts two clients on the same key, drives one inner
// round trip through each so the gateway holds two CONFIRMED-USABLE sessions of
// that key, and returns the older and newer gateway peerSessions plus the two
// clients. Every wait ends on an event; supersedeSafety only bounds a hang.
func twoSameKeyConfirmed(t *testing.T, ctx context.Context, r *reclaimRig) (older, newer *peerSession, a, b *testClient) {
	t.Helper()
	a = startTestClient(t, ctx, r.opts)
	waitFor(t, supersedeSafety, "the first client to carry", func() bool { return carrying(a) })
	roundTrip(t, a, "confirm-a")
	b = startTestClient(t, ctx, r.opts)
	waitFor(t, supersedeSafety, "the second client to carry", func() bool { return carrying(b) })
	roundTrip(t, b, "confirm-b")
	// Both round trips have returned, and confirmation is monotone (LastAuthRecv
	// only advances and CurGenAt changes only on a fresh re-initiation, which
	// nothing here sends), so this holds on the first read. It stays a check,
	// not an assumption.
	waitFor(t, supersedeSafety, "two confirmed-usable sessions of the same key", func() bool {
		views := r.srv.slotViews()
		if len(views) != 2 || !confirmedUsable(views[0].view) || !confirmedUsable(views[1].view) {
			return false
		}
		if !bytes.Equal(views[0].view.PeerStatic, views[1].view.PeerStatic) {
			t.Fatal("the two sessions are not of the same client key")
		}
		x, y := views[0], views[1]
		if x.view.CurGenAt.After(y.view.CurGenAt) {
			x, y = y, x
		}
		older, newer = x.ps, y.ps
		return true
	})
	return older, newer, a, b
}

func (r *reclaimRig) inPeers(ps *peerSession) bool {
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	for _, p := range r.srv.peers {
		if p == ps {
			return true
		}
	}
	return false
}

// TestSupersedeRefusedWhenReplacementTerminatesBeforeCommit is Gap 2: the newer
// session is chosen as the replacement, then terminates before the commit, and
// the older session must NOT be retired against a replacement that is gone.
func TestSupersedeRefusedWhenReplacementTerminatesBeforeCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)
	older, newer, _, _ := twoSameKeyConfirmed(t, ctx, r)

	owns := func(v slotView) bool { return v.ps == newer }
	pairs := supersedePairs(r.srv.slotViews(), owns)
	if len(pairs) != 1 || pairs[0].old.ps != older || pairs[0].newer.ps != newer {
		t.Fatalf("selection did not propose {older,newer}: %d pairs", len(pairs))
	}

	// The replacement terminates between selection and commit.
	_ = newer.loop.Close()
	waitFor(t, supersedeSafety, "the replacement to terminate", func() bool {
		return newer.loop.Session().State().Terminal()
	})

	if r.srv.retireSupersededOld(pairs[0], owns) {
		t.Fatal("the older session was retired against a replacement that had terminated")
	}
	if !r.inPeers(older) {
		t.Fatal("the older session was removed although the supersede was refused")
	}
	if older.loop.Session().State().Terminal() {
		t.Fatal("the older, still-working session is terminal after a refused supersede")
	}
}

// TestSupersedeSkipsReplacementWhoseHandshakeNeverCompletes is Gap 2's
// incomplete-replacement case: a second session of the same key authenticates
// its initiation but the client's post-quantum flight never arrives, so it never
// establishes and is never a valid replacement. The older, working session must
// be preserved.
func TestSupersedeSkipsReplacementWhoseHandshakeNeverCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)

	a := startTestClient(t, ctx, r.opts)
	waitFor(t, supersedeSafety, "the working client to carry", func() bool { return carrying(a) })
	older := r.onlySession(t)

	// A valid initiation of the SAME key from a fresh source, then silence: the
	// gateway authenticates it and awaits the post-quantum flight that never
	// comes, so this second session never establishes.
	raw, err := net.DialUDP("udp4", nil, r.gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Write(capturedInitiation(t, r.opts.dir, r.srv.sessionCfg)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, supersedeSafety, "the gateway to hold the incomplete second session", func() bool {
		return r.sessions() == 2
	})

	// No newer ESTABLISHED session of the key exists, so nothing is superseded.
	if n := r.srv.supersedeOnce(func(slotView) bool { return true }); n != 0 {
		t.Fatalf("supersedeOnce retired %d sessions against an unestablished replacement", n)
	}
	if !r.inPeers(older) {
		t.Fatal("the working session was retired against a replacement that never established")
	}
	if !carrying(a) {
		t.Fatal("the working client stopped carrying")
	}
}

// TestSupersedeRefusedWhileReplacementDoesNotOwnForwarding is the ownership arm:
// the replacement is established AND confirmed usable, but it does not own the
// key's inner address in the forwarding table (its client has not yet sent the
// uplink that moves it), so the older working session must be preserved.
func TestSupersedeRefusedWhileReplacementDoesNotOwnForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)
	older, newer, olderCli, _ := twoSameKeyConfirmed(t, ctx, r)

	nv, ok := viewOfSlot(newer.remoteAddrPort(), newer)
	if !ok || !nv.view.Established || !nv.view.Authenticated || !confirmedUsable(nv.view) {
		t.Fatalf("the replacement is not an established, authenticated, confirmed session: %+v", nv.view)
	}
	if n := r.srv.supersedeOnce(func(slotView) bool { return false }); n != 0 {
		t.Fatalf("supersedeOnce retired %d sessions although the replacement never took forwarding", n)
	}
	if !r.inPeers(older) {
		t.Fatal("the working session was retired against a replacement that never took forwarding")
	}
	if older.loop.Session().State().Terminal() {
		t.Fatal("the working session is terminal after a refused supersede")
	}
	roundTrip(t, olderCli, "older-still-works")
}

// finalFlightDropper is an on-path relay between ONE client and the gateway. It
// forwards every client datagram, forwards exactly ONE gateway datagram (the
// handshake response), and drops every later gateway datagram, counting them.
//
// By causality the first gateway datagram to a fresh address is the response:
// the gateway sends nothing to an address before its initiation authenticates,
// and it cannot assemble its final post-quantum flight (PQ_CT) before the
// client's PQ_EK, which the client sends only after it has the response. So the
// relay always drops the responder's final flight and everything after it,
// while the gateway, which establishes when it ASSEMBLES that flight, becomes
// established and authenticated.
type finalFlightDropper struct {
	down *net.UDPConn // the client dials this
	up   *net.UDPConn // dialled to the gateway; the gateway sees this address

	forwardedDown atomic.Int64
	droppedDown   atomic.Int64
	client        atomic.Pointer[net.UDPAddr]
}

func newFinalFlightDropper(t *testing.T, gw *net.UDPAddr) *finalFlightDropper {
	t.Helper()
	down, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, gw)
	if err != nil {
		_ = down.Close()
		t.Fatal(err)
	}
	f := &finalFlightDropper{down: down, up: up}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client to gateway: forward everything
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, from, err := down.ReadFromUDP(buf)
			if err != nil {
				return
			}
			f.client.Store(from)
			_, _ = up.Write(buf[:n])
		}
	}()
	go func() { // gateway to client: forward only the first datagram
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			cli := f.client.Load()
			if cli == nil || f.forwardedDown.Load() >= 1 {
				f.droppedDown.Add(1)
				continue
			}
			f.forwardedDown.Add(1)
			_, _ = down.WriteToUDP(buf[:n], cli)
		}
	}()
	t.Cleanup(func() {
		_ = down.Close()
		_ = up.Close()
		wg.Wait()
	})
	return f
}

// TestSupersedeSkipsEstablishedReplacementThatDroppedItsFinalFlight is Turn 3
// point 4, with a REAL dropped responder final flight. The replacement client's
// handshake runs through finalFlightDropper: the gateway gets the initiation and
// the client's PQ_EK, ASSEMBLES its final PQ_CT flight (which is when the
// responder counts as established), and the relay drops that flight, so the
// client never establishes and never carries. On the gateway the replacement is
// therefore the NEWEST established, authenticated session of the key, and it
// has never opened anything under its post-handshake keys.
//
// Supersede must preserve the older working session even when the forwarding
// predicate claims the replacement owns the key's address (the adversarial
// case): only confirmed usability stands between an assembled-but-undelivered
// final flight and retiring the working session.
func TestSupersedeSkipsEstablishedReplacementThatDroppedItsFinalFlight(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)

	a := startTestClient(t, ctx, r.opts)
	waitFor(t, supersedeSafety, "the working client to carry", func() bool { return carrying(a) })
	roundTrip(t, a, "older-before")
	older := r.onlySession(t)

	relay := newFinalFlightDropper(t, r.gwAddr)
	viaRelay := r.opts
	viaRelay.gwAddr = relay.down.LocalAddr().(*net.UDPAddr)
	b := startTestClient(t, ctx, viaRelay)
	relayAddr := netip.MustParseAddrPort(relay.up.LocalAddr().String())

	// Event: the gateway's replacement session is established and authenticated.
	var newer *peerSession
	waitFor(t, supersedeSafety, "the replacement to establish on the gateway", func() bool {
		r.srv.mu.Lock()
		ps := r.srv.peers[relayAddr]
		r.srv.mu.Unlock()
		if ps == nil {
			return false
		}
		v, ok := viewOfSlot(relayAddr, ps)
		if ok && v.view.Established && v.view.Authenticated {
			newer = ps
			return true
		}
		return false
	})

	// The final flight was really dropped: the gateway sealed PQ chunks, the relay
	// forwarded only the response and dropped what followed, and the client is
	// still initiating, not carrying.
	if st := newer.loop.Session().Stats(); st.PQChunksSent == 0 {
		t.Fatal("the replacement established without sending a post-quantum flight")
	}
	waitFor(t, supersedeSafety, "the relay to drop the responder's final flight", func() bool {
		return relay.forwardedDown.Load() == 1 && relay.droppedDown.Load() >= 1
	})
	if carrying(b) {
		t.Fatal("the replacement client carries although its final flight was dropped")
	}
	if st := b.loop.Session().State(); st == session.StateEstablished || st == session.StateRekeying {
		t.Fatalf("the replacement client is %s although its final flight was dropped", st)
	}

	// The replacement authenticated BEFORE supersede runs, it is the newest
	// established session of the key, and it is not confirmed usable.
	nv, ok := viewOfSlot(relayAddr, newer)
	if !ok || !nv.view.Authenticated || !nv.view.Established {
		t.Fatalf("the replacement is not an established, authenticated session: %+v", nv.view)
	}
	ov, ok := viewOfSlot(older.remoteAddrPort(), older)
	if !ok || !ov.view.Established || !bytes.Equal(ov.view.PeerStatic, nv.view.PeerStatic) ||
		!ov.view.CurGenAt.Before(nv.view.CurGenAt) {
		t.Fatal("the replacement is not the newer established session of the older session's key")
	}
	// Read the raw driver fields, not the policy predicate under test: nothing has
	// opened on the replacement since it established.
	if nv.view.LastAuthRecv.After(nv.view.CurGenAt) {
		t.Fatal("the replacement opened a post-handshake message although its client never got the final flight")
	}

	// Adversarial ownership: claim the replacement owns forwarding.
	owns := func(v slotView) bool { return v.ps == newer }
	if n := r.srv.supersedeOnce(owns); n != 0 {
		t.Fatalf("supersedeOnce retired %d sessions against a replacement whose final flight was dropped", n)
	}
	if !r.inPeers(older) {
		t.Fatal("the working session was retired against a replacement whose final flight was dropped")
	}
	if older.loop.Session().State().Terminal() {
		t.Fatal("the working session is terminal after a refused supersede")
	}
	roundTrip(t, a, "older-after")
}

// TestBlockedTeardownHoldsReservationAndAwaitReports is Gap 3 with a REAL
// blocked releasePeer and concurrent release callers. It proves the
// completion-ownership contract: the reservation is held until resource teardown
// completes, concurrent callers do not free it early or twice, and awaitRetiring
// distinguishes a timed-out wait from a successful drain.
func TestBlockedTeardownHoldsReservationAndAwaitReports(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newReclaimRig(t, 8, nil)

	// Gate the resource teardown inside releasePeer so a real retirement is held
	// mid-flight, with its reservation still charged.
	gate := make(chan struct{})
	r.srv.releaseGate = gate
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
		r.srv.closeAll()
	})

	// A real reclaimable half-open victim.
	victim, err := r.srv.sessionFor(ctx, netip.MustParseAddrPort("127.0.0.1:7"))
	if err != nil {
		t.Fatal(err)
	}
	if err := victim.pipe.Deliver(bytes.Repeat([]byte{0xa5}, 200)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the half-open to refuse the junk", func() bool {
		return victim.loop.Session().Stats().Unopenable > 0
	})
	v, ok := viewOfSlot(netip.MustParseAddrPort("127.0.0.1:7"), victim)
	if !ok {
		t.Fatal("could not snapshot the victim")
	}
	// awaitRetiring calls stop() on every session it has taken from s.retiring,
	// before it waits on that session. Wrap the victim's stop (before anything
	// runs concurrently with the field) so the test can release the gate only
	// once a waiting awaitRetiring really holds the victim: an event, where v4
	// slept 200 ms and hoped the waiter had started.
	var armed atomic.Bool
	awaiting := make(chan struct{}, 1)
	origStop := victim.stop
	victim.stop = func() {
		if armed.Load() {
			select {
			case awaiting <- struct{}{}:
			default:
			}
		}
		origStop()
	}
	// retireSlot reserves the victim and cancels its context; its Run goroutine
	// then calls releasePeer, which blocks on the gate with the reservation held.
	if !r.srv.retireSlot(v) {
		t.Fatal("the victim was not retired")
	}
	// A concurrent forced release (Round M's path) also calls releasePeer; it
	// must block in releaseOnce.Do behind the first caller, not free early.
	go r.srv.releasePeer(victim.remoteAddrPort(), victim)

	// The reservation is held while teardown is blocked: it is not freed, and a
	// fresh retirement cannot reuse it beyond the bound.
	reserved := func() int {
		r.srv.mu.Lock()
		defer r.srv.mu.Unlock()
		return len(r.srv.retiring)
	}
	if reserved() != 1 {
		t.Fatalf("reservation count is %d while teardown is blocked, want 1", reserved())
	}
	time.Sleep(300 * time.Millisecond)
	if reserved() != 1 {
		t.Fatalf("the reservation was freed or duplicated while teardown was blocked: %d", reserved())
	}

	// Timeout outcome: awaitRetiring cannot drain the blocked teardown.
	d0, t0 := r.srv.awaitRetiring()
	if d0 != 0 || t0 != 1 {
		t.Fatalf("awaitRetiring while blocked reported drained=%d timedOut=%d, want 0 and 1", d0, t0)
	}

	// Successful-drain outcome: unblock teardown while awaitRetiring waits.
	type res struct{ d, to int }
	ch := make(chan res, 1)
	armed.Store(true)
	go func() {
		d, to := r.srv.awaitRetiring()
		ch <- res{d, to}
	}()
	select {
	case <-awaiting:
	case <-time.After(supersedeSafety):
		t.Fatal("awaitRetiring never took the blocked victim")
	}
	close(gate)
	select {
	case got := <-ch:
		if got.d != 1 || got.to != 0 {
			t.Fatalf("awaitRetiring after unblock reported drained=%d timedOut=%d, want 1 and 0", got.d, got.to)
		}
	case <-time.After(supersedeSafety):
		t.Fatal("awaitRetiring did not return after the teardown was unblocked")
	}

	// The reservation is freed exactly once, after teardown completed.
	waitFor(t, 5*time.Second, "the reservation to be freed after teardown", func() bool {
		return reserved() == 0
	})
}

// TestReclaimRefusesWhenTrafficResumesBetweenSelectionAndCommit is property 1
// end to end: a victim is SELECTED (its coherent snapshot taken), authenticated
// traffic then resumes on it, and the COMMIT against that stale snapshot is
// REFUSED, leaving the session in the table and alive.
//
// The snapshot-then-traffic-then-commit ordering is exactly the race window:
// retireSlot re-checks the snapshot's sequence under the driver lock, and the
// authenticated round trip in between has moved it.
func TestReclaimRefusesWhenTrafficResumesBetweenSelectionAndCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := newReclaimRig(t, 1, func(c *session.Config) {
		c.Probe = session.Draw{Min: 200 * time.Millisecond, Mean: 400 * time.Millisecond, Max: time.Second}
		c.MaxLostProbes = 1000
	})
	r.serve(t, ctx)
	first := startTestClient(t, ctx, r.opts)
	waitFor(t, 20*time.Second, "the first client to carry", func() bool { return carrying(first) })
	victim := r.onlySession(t)
	addr := victim.remoteAddrPort()

	// SELECT: take the coherent snapshot a reclaim would carry into its commit.
	selected, ok := viewOfSlot(addr, victim)
	if !ok {
		t.Fatal("could not snapshot the victim")
	}

	// Traffic RESUMES between selection and commit: an authenticated inner
	// round trip moves the victim's sequence past the snapshot's.
	first.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, []byte("resume")))
	_ = first.dev.take(t, 10*time.Second)
	waitFor(t, 5*time.Second, "the victim's sequence to move", func() bool {
		cur, ok := viewOfSlot(addr, victim)
		return ok && cur.view.Seq != selected.view.Seq
	})

	// COMMIT against the stale snapshot: refused.
	if r.srv.retireSlot(selected) {
		t.Fatal("retireSlot committed against a snapshot a resumed receive had already moved")
	}
	if r.onlySession(t) != victim {
		t.Fatal("the victim left the table on a refused retirement")
	}
	if victim.loop.Session().State().Terminal() {
		t.Fatal("the victim session is terminal after a refused retirement")
	}
}

// TestRetirementIsBounded is property 4: the retiring population cannot exceed
// retirementAllowance. With the allowance already full of placeholder entries, a
// retirement of a real reclaimable victim is refused and the victim keeps its
// slot.
func TestRetirementIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newReclaimRig(t, 4, nil)

	// One real, reclaimable victim: a half-open session handed junk it cannot
	// open, which classifies reclaimFailed.
	victim, err := r.srv.sessionFor(ctx, netip.MustParseAddrPort("127.0.0.1:7"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.srv.closeAll() })
	if err := victim.pipe.Deliver(bytes.Repeat([]byte{0xa5}, 200)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the half-open to refuse the junk", func() bool {
		return victim.loop.Session().Stats().Unopenable > 0
	})

	// Fill the retiring set to the bound with placeholders.
	r.srv.mu.Lock()
	r.srv.retiring = make(map[*peerSession]struct{}, retirementAllowance)
	for i := 0; i < retirementAllowance; i++ {
		r.srv.retiring[&peerSession{}] = struct{}{}
	}
	r.srv.mu.Unlock()

	v, ok := viewOfSlot(netip.MustParseAddrPort("127.0.0.1:7"), victim)
	if !ok {
		t.Fatal("could not snapshot the victim")
	}
	if r.srv.retireSlot(v) {
		t.Fatal("a retirement was committed past the retirement allowance")
	}
	r.srv.mu.Lock()
	_, still := r.srv.peers[netip.MustParseAddrPort("127.0.0.1:7")]
	r.srv.mu.Unlock()
	if !still {
		t.Fatal("the victim left the table although its retirement was refused at the bound")
	}
	if victim.loop.Session().State().Terminal() {
		t.Fatal("the victim was terminated although its retirement was refused at the bound")
	}
	// Drain placeholders so closeAll does not wait on fake sessions.
	r.srv.mu.Lock()
	r.srv.retiring = nil
	r.srv.mu.Unlock()
}

// TestReflectorModeNeverSupersedes: without -forward nothing binds a key to one
// inner address, so two live sessions of one key are both kept. This is also
// the configuration TestServerCarriesRealClients runs two clients in.
func TestReflectorModeNeverSupersedes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)

	first := startTestClient(t, ctx, r.opts)
	waitFor(t, 20*time.Second, "the first client to carry", func() bool { return carrying(first) })
	second := startTestClient(t, ctx, r.opts)
	waitFor(t, 20*time.Second, "the second client to carry", func() bool { return carrying(second) })
	time.Sleep(3 * time.Second)
	if n := r.sessions(); n != 2 {
		t.Fatalf("the gateway holds %d sessions, want 2: reflector mode retired a session", n)
	}
}

// admissibleForeignInitiation is an initiation that passes gwCfg's admission
// tag and can never authenticate: it is sealed to a freshly generated gateway
// static key, so ReadInitiation refuses it at the static-key decryption. Each
// call carries a fresh ephemeral, so no two are replays of each other.
func admissibleForeignInitiation(t *testing.T, gwCfg session.Config) []byte {
	t.Helper()
	cli, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, err := core.NewPublicKey(wrong.Public())
	if err != nil {
		t.Fatal(err)
	}
	ini, err := core.NewInitiator(core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: gwCfg.Core.Gateway.AdmissionKeys,
		GatewayID:     gwCfg.Core.Gateway.GatewayID,
	}}, cli, wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestSupersedeRefusedWhenReplacementLeftTheTable is Round Q Turn 4 OI-Q2.
// releasePeer removes a session from s.peers BEFORE it closes that session's
// loop and device, and the forwarding entry is forgotten only on device close.
// In that window the replacement's driver is still live and the forwarding
// table can still name it, yet it no longer holds a gateway slot. The commit
// must refuse: the old session is the key's only session left in the table.
// Here the detachment is made directly (the replacement is deleted from
// s.peers, its driver left live) and ownership is claimed true throughout.
func TestSupersedeRefusedWhenReplacementLeftTheTable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)
	older, newer, olderCli, _ := twoSameKeyConfirmed(t, ctx, r)
	owns := func(v slotView) bool { return v.ps == newer }

	pairs := supersedePairs(r.srv.slotViews(), owns)
	if len(pairs) != 1 || pairs[0].old.ps != older || pairs[0].newer.ps != newer {
		t.Fatalf("selection did not propose {older,newer}: %d pairs", len(pairs))
	}

	// releasePeer's first step, alone: the replacement leaves s.peers while its
	// loop, driver and device stay up.
	r.srv.mu.Lock()
	if r.srv.peers[pairs[0].newer.addr] != newer {
		r.srv.mu.Unlock()
		t.Fatal("fixture: the replacement is not in the table under its selected address")
	}
	delete(r.srv.peers, pairs[0].newer.addr)
	r.srv.mu.Unlock()
	if st := newer.loop.Session().State(); st != session.StateEstablished && st != session.StateRekeying {
		t.Fatalf("fixture: the detached replacement's driver is %s, want live", st)
	}
	if !owns(pairs[0].newer) {
		t.Fatal("fixture: ownership predicate is not true")
	}

	if r.srv.retireSupersededOld(pairs[0], owns) {
		t.Fatal("the older session was retired against a replacement that no longer holds a slot")
	}
	if !r.inPeers(older) {
		t.Fatal("the older session left the table although the supersede was refused")
	}
	if older.loop.Session().State().Terminal() {
		t.Fatal("the older session is terminal after a refused supersede")
	}
	roundTrip(t, olderCli, "older-still-works")

	// Anti-vacuity: put the replacement back and the same supersede commits.
	r.srv.mu.Lock()
	r.srv.peers[pairs[0].newer.addr] = newer
	r.srv.mu.Unlock()
	killSilently(olderCli)
	if n, _ := supersedeJustified(t, r, older, owns); n != 1 {
		t.Fatalf("with the replacement back in the table supersede retired %d, want 1", n)
	}
	if r.inPeers(older) {
		t.Fatal("the older session is still in the table after the restored supersede")
	}
}

// divertingRelay is an on-path relay between ONE client and the gateway. It
// forwards both directions; while divert is set, client datagrams are queued
// on diverted instead of being forwarded, so a test can hand a FRESH,
// never-delivered authenticated datagram to the gateway session at a moment of
// its choosing.
type divertingRelay struct {
	down *net.UDPConn
	up   *net.UDPConn

	divert   atomic.Bool
	diverted chan []byte
	client   atomic.Pointer[net.UDPAddr]
}

func newDivertingRelay(t *testing.T, gw *net.UDPAddr) *divertingRelay {
	t.Helper()
	down, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, gw)
	if err != nil {
		_ = down.Close()
		t.Fatal(err)
	}
	f := &divertingRelay{down: down, up: up, diverted: make(chan []byte, 64)}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, from, err := down.ReadFromUDP(buf)
			if err != nil {
				return
			}
			f.client.Store(from)
			if f.divert.Load() {
				select {
				case f.diverted <- append([]byte(nil), buf[:n]...):
				default:
				}
				continue
			}
			_, _ = up.Write(buf[:n])
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			if cli := f.client.Load(); cli != nil {
				_, _ = down.WriteToUDP(buf[:n], cli)
			}
		}
	}()
	t.Cleanup(func() {
		_ = down.Close()
		_ = up.Close()
		wg.Wait()
	})
	return f
}

// TestSupersedeIsNotStarvedByABusyReplacement is Round Q Turn 4 OI-Q4, the
// sustained-traffic liveness test. The replacement carries a continuous inner
// stream for the whole test, and on EVERY sweep the test makes that traffic
// land inside the window between selection and commit: at the commit's
// ownership check (which runs under s.mu, after selection and before
// CommitSupersede) it hands the replacement's gateway session one fresh
// authenticated datagram of that stream and waits until the replacement's
// sequence has moved. That is the worst case of a busy replacement, made
// deterministic.
//
// A commit that requires the replacement's selected sequence to stand still
// defers supersede on every such sweep, for ever. The replacement's validity
// (identity, generation, state, confirmation, ordering) is unchanged by an
// authenticated receive, so the supersede must commit, and only a victim
// receive may defer it (supersedeJustified).
func TestSupersedeIsNotStarvedByABusyReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*supersedeSafety)
	defer cancel()
	r := newReclaimRig(t, 8, nil)
	r.serve(t, ctx)

	a := startTestClient(t, ctx, r.opts)
	waitFor(t, supersedeSafety, "the older client to carry", func() bool { return carrying(a) })
	roundTrip(t, a, "confirm-a")
	older := r.onlySession(t)

	relay := newDivertingRelay(t, r.gwAddr)
	viaRelay := r.opts
	viaRelay.gwAddr = relay.down.LocalAddr().(*net.UDPAddr)
	b := startTestClient(t, ctx, viaRelay)
	waitFor(t, supersedeSafety, "the replacement client to carry", func() bool { return carrying(b) })
	roundTrip(t, b, "confirm-b")
	relayAddr := netip.MustParseAddrPort(relay.up.LocalAddr().String())
	r.srv.mu.Lock()
	newer := r.srv.peers[relayAddr]
	r.srv.mu.Unlock()
	if newer == nil {
		t.Fatal("the replacement is not in the table under the relay's address")
	}

	// Sustained traffic through the replacement for the rest of the test.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	pkt := testIPv4(t, testClientInner, testGatewayInner, make([]byte, 512))
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case b.dev.in <- pkt:
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-b.dev.out:
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	killSilently(a)

	// Every other ownership call is a commit (supersedePairs asks once for the
	// one candidate, then retireSupersededOld asks again at commit).
	calls, injected := 0, 0
	owns := func(v slotView) bool {
		if v.ps != newer {
			return false
		}
		calls++
		if calls%2 == 1 {
			return true // selection
		}
		before := newer.loop.Session().ReclaimView().Seq
		relay.divert.Store(true)
		defer relay.divert.Store(false)
		var dg []byte
		select {
		case dg = <-relay.diverted:
		case <-time.After(supersedeSafety):
			t.Error("the busy replacement produced no datagram to inject")
			return true
		}
		if err := newer.pipe.Deliver(dg); err != nil {
			t.Errorf("injecting the replacement's datagram: %v", err)
			return true
		}
		for deadline := time.Now().Add(supersedeSafety); newer.loop.Session().ReclaimView().Seq == before; {
			if time.Now().After(deadline) {
				t.Error("the injected datagram never opened on the replacement")
				return true
			}
			time.Sleep(time.Millisecond)
		}
		injected++
		return true
	}
	n, refusals := supersedeJustified(t, r, older, owns)
	if n != 1 {
		t.Fatalf("supersede retired %d sessions, want 1", n)
	}
	if injected == 0 || injected != calls/2 {
		t.Fatalf("the replacement received inside %d of %d commit windows, want all of them", injected, calls/2)
	}
	if r.inPeers(older) {
		t.Fatal("the superseded session is still in the table")
	}
	if newer.loop.Session().State().Terminal() || !r.inPeers(newer) {
		t.Fatal("the busy replacement was retired or left the table")
	}
	t.Logf("supersede committed on sweep %d with the replacement receiving inside every commit window (%d victim-caused refusals)", refusals+1, refusals)
}
