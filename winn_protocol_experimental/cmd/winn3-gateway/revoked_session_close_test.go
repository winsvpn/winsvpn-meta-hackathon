package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Every test in this file observes behaviour only (session states, what the
// client receives, what reaches an upstream, what ReadPacket returns), never a
// symbol the fix introduces, so the same file compiles against the unfixed
// gateway and shows which properties it lacked.

const revokedTestInner = "10.10.0.14"

// revokedFixture is one ESTABLISHED gateway/client pair whose gateway session
// sits in a server's peer table with a live registry. Neither loop runs: the
// test pumps Poll/Deliver by hand, so no socket and no TUN is needed.
type revokedFixture struct {
	srv   *server
	ps    *peerSession
	gw    *driver.Loop
	cli   *driver.Loop
	path  string
	body  string
	key   []byte
	stops atomic.Int32
	dev   *fakeInner
	gwCfg session.Config
	dir   string
}

func registryBody(key []byte, notAfter int64) string {
	return fmt.Sprintf(`{"version":1,"peers":[{"static_public":%q,"inner_v4":%q,"not_after":%d}]}`,
		base64.StdEncoding.EncodeToString(key), revokedTestInner, notAfter)
}

func newRevokedFixture(t *testing.T) *revokedFixture {
	return newRevokedFixtureExpiring(t, 0)
}

func newRevokedFixtureExpiring(t *testing.T, notAfter int64) *revokedFixture {
	t.Helper()
	dir := t.TempDir()
	if err := runKeygen(dir, io.Discard); err != nil {
		t.Fatal(err)
	}
	key := readTestKey(t, filepath.Join(dir, "client.pub"))
	body := registryBody(key, notAfter)
	path := writeRegistry(t, body)
	registry, err := newPeerRegistry(path, netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	gwCfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}, registry)
	if err != nil {
		t.Fatal(err)
	}
	f := &revokedFixture{path: path, body: body, key: key, gwCfg: gwCfg, dir: dir}
	f.gw, f.cli = f.newPair(t)
	pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: testPathMTU})
	if err != nil {
		t.Fatal(err)
	}
	f.dev = newFakeInner(1400)
	f.ps = &peerSession{
		loop:   f.gw,
		pipe:   pipe,
		dev:    f.dev,
		done:   make(chan struct{}),
		remote: netip.MustParseAddrPort("192.0.2.1:40000"),
		stop:   func() { f.stops.Add(1) },
	}
	f.srv = &server{
		peerRegistry: registry,
		peers:        map[netip.AddrPort]*peerSession{f.ps.remote: f.ps},
	}
	return f
}

// newPair establishes a fresh gateway/client pair under this fixture's keys.
func (f *revokedFixture) newPair(t *testing.T) (*driver.Loop, *driver.Loop) {
	t.Helper()
	clientKey, err := core.NewStaticKey(readTestKey(t, filepath.Join(f.dir, "client.key")))
	if err != nil {
		t.Fatal(err)
	}
	gatewayKey, err := core.NewPublicKey(readTestKey(t, filepath.Join(f.dir, "static.pub")))
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	newLoop := func(cfg session.Config, build func(driver.Config) (*driver.Loop, error)) *driver.Loop {
		pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, PathMTU: testPathMTU})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pipe.Close() })
		loop, err := build(driver.Config{Session: cfg, Sizing: sizing, Carrier: pipe})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = loop.Close() })
		return loop
	}
	gw := newLoop(f.gwCfg, driver.NewGateway)
	cli := newLoop(session.Config{
		Core: f.gwCfg.Core, Static: clientKey, GatewayStatic: gatewayKey, Padding: core.PadBucket,
	}, driver.NewClient)
	pumpPair(t, cli.Session(), gw.Session())
	if cli.Session().State() != session.StateEstablished || gw.Session().State() != session.StateEstablished ||
		!bytes.Equal(gw.Session().PeerStatic(), f.key) {
		t.Fatal("fixture failed to establish the authenticated client key")
	}
	return gw, cli
}

// pumpPair moves every queued message in both directions until both are quiet.
func pumpPair(t *testing.T, a, b *session.Driver) {
	t.Helper()
	for round := 0; round < 64; round++ {
		moved := false
		for _, pair := range [][2]*session.Driver{{a, b}, {b, a}} {
			for count := 0; count < 64; count++ {
				msg, err := pair[0].Poll()
				if err != nil {
					t.Fatal(err)
				}
				if msg == nil {
					break
				}
				moved = true
				if _, err := pair[1].Deliver(msg); err != nil && !pair[1].State().Terminal() {
					t.Fatal(err)
				}
			}
		}
		if !moved {
			return
		}
	}
}

func (f *revokedFixture) pump(t *testing.T) { pumpPair(t, f.cli.Session(), f.gw.Session()) }

// revoke publishes the France snapshot and makes the next lookup see it.
func (f *revokedFixture) revoke(t *testing.T) {
	t.Helper()
	replaceAuthority(t, f.path, `{"peers":[],"version":1}`)
	dueAuthorityRefresh(f.srv.peerRegistry)
}

// restoreQuietly republishes the binding WITHOUT making the next lookup due:
// a lookup within registryFreshness still answers from the cached snapshot.
func (f *revokedFixture) restoreQuietly(t *testing.T) {
	t.Helper()
	replaceAuthority(t, f.path, f.body)
}

func (f *revokedFixture) gatewayOpen(t *testing.T) bool {
	t.Helper()
	switch f.gw.Session().State() {
	case session.StateEstablished, session.StateRekeying:
		return true
	}
	return false
}

// The France failure, 2026-09-23 17:09:35 UTC: the hub replaced the registry
// with {"peers":[],"version":1} under an ESTABLISHED session. Unfixed, the
// session stayed ESTABLISHED indefinitely and the client read "connected"
// while every transit packet was refused.
func TestRevokedPeerSessionIsClosedAfterGrace(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	start := time.Now()
	f.srv.closeRevokedSessions(start)
	if !f.gatewayOpen(t) {
		t.Fatal("authorized session closed")
	}
	f.revoke(t)
	f.srv.closeRevokedSessions(start)
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace - time.Millisecond))
	if !f.gatewayOpen(t) {
		t.Fatalf("closed inside the grace: %v", f.gw.Session().State())
	}
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace))
	if f.gatewayOpen(t) {
		t.Fatal("revoked session still open past the grace")
	}
	f.pump(t)
	if !f.cli.Session().State().Terminal() {
		t.Fatalf("client never saw the gateway end the session: state %v", f.cli.Session().State())
	}
	if reason := f.cli.Session().PeerCloseReason(); reason != session.CloseNormal {
		t.Fatalf("client peer close reason = %v, want %v", reason, session.CloseNormal)
	}
}

// Restoration observed by a sweep inside the grace resets the interval, and a
// later outage is measured from its own first observation.
func TestRestoredPeerInsideGraceKeepsSession(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	start := time.Now()
	f.revoke(t)
	f.srv.closeRevokedSessions(start)
	f.restoreQuietly(t)
	dueAuthorityRefresh(f.srv.peerRegistry)
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace / 2))
	f.revoke(t)
	later := start.Add(revokedSessionGrace + time.Second)
	f.srv.closeRevokedSessions(later)
	f.srv.closeRevokedSessions(later.Add(revokedSessionGrace - time.Millisecond))
	if !f.gatewayOpen(t) {
		t.Fatalf("a new outage inherited the old clock: state %v", f.gw.Session().State())
	}
}

// Astra's counterexample (Round M, OI-M2): a negative snapshot cached at 9.5 s,
// a restoration at 9.9 s and a sweep at 10 s. The due sweep must revalidate
// freshly and keep the restored peer. No refresh is forced by the test.
func TestRestorationJustBeforeTheDeadlineIsSeenWithoutAForcedRefresh(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	start := time.Now()
	f.revoke(t)
	f.srv.closeRevokedSessions(start)
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace - 500*time.Millisecond))
	f.restoreQuietly(t)
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace))
	if !f.gatewayOpen(t) {
		t.Fatalf("closed a peer the registry had already restored: state %v", f.gw.Session().State())
	}
}

// A malformed replacement clears every binding (peer_registry.go
// finishRefreshLocked). A valid replacement before the deadline, again with no
// forced refresh, must keep the session; a malformed file that persists must
// not.
func TestMalformedRegistryRecoveredBeforeTheDeadlineKeepsSession(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	start := time.Now()
	replaceAuthority(t, f.path, `{"version":1,"peers":[`)
	dueAuthorityRefresh(f.srv.peerRegistry)
	f.srv.closeRevokedSessions(start)
	f.restoreQuietly(t)
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace))
	if !f.gatewayOpen(t) {
		t.Fatalf("closed after the registry recovered: state %v", f.gw.Session().State())
	}
}

func TestPersistentlyMalformedRegistryClosesTheSession(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	start := time.Now()
	replaceAuthority(t, f.path, `{"version":1,"peers":[`)
	dueAuthorityRefresh(f.srv.peerRegistry)
	f.srv.closeRevokedSessions(start)
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace))
	if f.gatewayOpen(t) {
		t.Fatal("session survived a registry that stayed malformed past the grace")
	}
}

// Expiry needs no file change: not_after is checked on every lookup.
func TestExpiredBindingClosesTheSessionAfterGrace(t *testing.T) {
	t.Parallel()
	expires := time.Now().Unix() + 2
	f := newRevokedFixtureExpiring(t, expires)
	for time.Now().Unix() < expires {
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	f.srv.closeRevokedSessions(start)
	if !f.gatewayOpen(t) {
		t.Fatal("closed on the first unauthorized observation")
	}
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace))
	if f.gatewayOpen(t) {
		t.Fatal("expired binding's session still open past the grace")
	}
}

// Without -forward there is no registry and nothing to revoke.
func TestRevokedSessionSweepIsInertWithoutRegistry(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	f.srv.peerRegistry = nil
	f.srv.closeRevokedSessions(time.Now().Add(time.Hour))
	if !f.gatewayOpen(t) {
		t.Fatal("sweep without a registry closed a session")
	}
}

// A close that was requested but never ended Run must fall back to bounded
// local teardown: first the loop context is cancelled (ps.stop), then, if Run
// still has not returned, the session is released from the demux table and
// its device closed. The fixture's Run never runs, so ps.done never closes.
func TestUnfinishedCloseFallsBackToBoundedLocalTeardown(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	start := time.Now()
	f.revoke(t)
	f.srv.closeRevokedSessions(start)
	decided := start.Add(revokedSessionGrace)
	f.srv.closeRevokedSessions(decided)
	if f.gatewayOpen(t) {
		t.Fatal("close was never requested")
	}
	if got := f.stops.Load(); got != 0 {
		t.Fatalf("context cancelled before the close had a chance: %d", got)
	}
	f.srv.closeRevokedSessions(decided.Add(time.Second))
	if got := f.stops.Load(); got != 0 {
		t.Fatalf("context cancelled inside the close deadline: %d", got)
	}
	stageTwo := decided.Add(6 * time.Second)
	f.srv.closeRevokedSessions(stageTwo)
	if got := f.stops.Load(); got != 1 {
		t.Fatalf("local teardown did not cancel the loop context: stops = %d", got)
	}
	f.srv.closeRevokedSessions(stageTwo.Add(6 * time.Second))
	f.srv.mu.Lock()
	remaining := len(f.srv.peers)
	f.srv.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("a session whose Run never returned still holds its demux slot: %d", remaining)
	}
	select {
	case <-f.dev.done:
	default:
		t.Fatal("released session's device was not closed")
	}
}

// ---------------------------------------------------------------------------
// DNS: the resolver must apply registry authorization independently of the
// session-teardown grace. Wiring matches newSession in -forward mode: the
// resolver wraps the forward device bound to the authenticated gateway loop.
// ---------------------------------------------------------------------------

// countingUpstream is a UDP DNS stub that counts queries and answers each one
// only when release is closed (immediately if release is nil).
type countingUpstream struct {
	addr    netip.AddrPort
	queries atomic.Int32
}

func startCountingUpstream(t *testing.T, release <-chan struct{}, answer bool) *countingUpstream {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	u := &countingUpstream{addr: pc.LocalAddr().(*net.UDPAddr).AddrPort()}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			u.queries.Add(1)
			if !answer {
				continue
			}
			reply := append([]byte(nil), buf[:n]...)
			reply[2] |= 0x80
			go func() {
				if release != nil {
					<-release
				}
				_, _ = pc.WriteToUDP(reply, from)
			}()
		}
	}()
	return u
}

func (f *revokedFixture) resolverDevice(t *testing.T, upstream netip.AddrPort, timeout time.Duration) *resolverDevice {
	t.Helper()
	fwd := newGatewayForwardDevice(&fakeInnerWriter{}, newForwardTable(), 1373, f.srv.peerRegistry)
	fwd.bind(f.gw)
	r := newGatewayResolver(mustAddr(t, testGatewayInner), upstream, timeout, 4)
	d := newResolverDevice(fwd, r, 1373)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func dnsQueryFrom(t *testing.T, src string, id uint16) []byte {
	t.Helper()
	return udpPacket(t, mustAddr(t, src), mustAddr(t, testGatewayInner), 53000, dnsPort, dnsQueryBytes(id))
}

// readReply returns the next packet ReadPacket delivers within wait, or nil.
func readReply(t *testing.T, d *resolverDevice, wait time.Duration) []byte {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, tun.MaxIPPacket)
		n, err := d.ReadPacket(buf)
		if err != nil {
			got <- nil
			return
		}
		got <- append([]byte(nil), buf[:n]...)
	}()
	select {
	case pkt := <-got:
		return pkt
	case <-time.After(wait):
		return nil
	}
}

func TestResolverAnswersTheAuthorizedPeer(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	up := startCountingUpstream(t, nil, true)
	d := f.resolverDevice(t, up.addr, 2*time.Second)
	if _, err := d.WritePacket(dnsQueryFrom(t, revokedTestInner, 0x1111)); err != nil {
		t.Fatal(err)
	}
	if readReply(t, d, 3*time.Second) == nil {
		t.Fatal("authorized peer got no DNS answer")
	}
}

// During the teardown grace the session is alive, but the peer is revoked:
// no query may reach the upstream and no answer may come back.
func TestResolverRefusesARevokedPeerDuringTheGrace(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	up := startCountingUpstream(t, nil, true)
	d := f.resolverDevice(t, up.addr, 2*time.Second)
	f.revoke(t)
	start := time.Now()
	f.srv.closeRevokedSessions(start)
	f.srv.closeRevokedSessions(start.Add(revokedSessionGrace / 2))
	if !f.gatewayOpen(t) {
		t.Fatal("fixture precondition: the session should still be inside its grace")
	}
	if _, err := d.WritePacket(dnsQueryFrom(t, revokedTestInner, 0x2222)); err != nil {
		t.Fatal(err)
	}
	if pkt := readReply(t, d, 500*time.Millisecond); pkt != nil {
		t.Fatal("revoked peer received a DNS answer during the grace")
	}
	if got := up.queries.Load(); got != 0 {
		t.Fatalf("revoked peer's query reached the upstream %d time(s)", got)
	}
}

// Identity comes from the session, not the packet: an authorized peer may not
// resolve from an inner address the registry did not issue to it.
func TestResolverRefusesAnAuthorizedPeerUsingAnotherInnerAddress(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	up := startCountingUpstream(t, nil, true)
	d := f.resolverDevice(t, up.addr, 2*time.Second)
	if _, err := d.WritePacket(dnsQueryFrom(t, "10.10.0.15", 0x3333)); err != nil {
		t.Fatal(err)
	}
	if pkt := readReply(t, d, 500*time.Millisecond); pkt != nil {
		t.Fatal("peer resolved from an address it was not issued")
	}
	if got := up.queries.Load(); got != 0 {
		t.Fatalf("query from an unissued address reached the upstream %d time(s)", got)
	}
}

// Revoked while the upstream exchange is outstanding: the upstream answer must
// not be delivered.
func TestResolverSuppressesAnAnswerRevokedWhileOutstanding(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	release := make(chan struct{})
	up := startCountingUpstream(t, release, true)
	d := f.resolverDevice(t, up.addr, 2*time.Second)
	if _, err := d.WritePacket(dnsQueryFrom(t, revokedTestInner, 0x4444)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for up.queries.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if up.queries.Load() != 1 {
		t.Fatal("fixture precondition: the authorized query never reached the upstream")
	}
	f.revoke(t)
	close(release)
	if pkt := readReply(t, d, time.Second); pkt != nil {
		t.Fatal("an answer to a peer revoked mid-exchange was delivered")
	}
}

// The same for a SYNTHESISED reply: the upstream never answers, the resolver
// times out and would send SERVFAIL, but the peer was revoked meanwhile.
func TestResolverSuppressesASynthesisedServFailAfterRevocation(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	up := startCountingUpstream(t, nil, false)
	d := f.resolverDevice(t, up.addr, 300*time.Millisecond)
	if _, err := d.WritePacket(dnsQueryFrom(t, revokedTestInner, 0x5555)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for up.queries.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	f.revoke(t)
	if pkt := readReply(t, d, time.Second); pkt != nil {
		t.Fatal("a synthesised SERVFAIL reached a peer revoked before delivery")
	}
}

// A reply already queued when authorization is withdrawn is suppressed at
// delivery, the last point before it would enter the tunnel.
func TestResolverSuppressesAQueuedAnswerRevokedBeforeDelivery(t *testing.T) {
	t.Parallel()
	f := newRevokedFixture(t)
	up := startCountingUpstream(t, nil, true)
	d := f.resolverDevice(t, up.addr, 2*time.Second)
	if _, err := d.WritePacket(dnsQueryFrom(t, revokedTestInner, 0x6666)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for d.res.answered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if d.res.answered.Load() != 1 {
		t.Fatal("fixture precondition: the answer was never queued")
	}
	f.revoke(t)
	if pkt := readReply(t, d, 500*time.Millisecond); pkt != nil {
		t.Fatal("a queued answer was delivered after its authorization was withdrawn")
	}
}
