package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// These tests pin what cmd/winn3-gateway actually does when the OUTER endpoint
// changes mid-session. They are not a claim that this is the protocol's
// intended roam behaviour.
//
// The protocol library (winn3/gateway.Table.Dispatch) is address-free:
// netlab.TestGatewayDispatchIsAddressFree measured 128/128 with the source
// changing between every datagram. THIS binary does not use that table. It
// indexes server.peers by netip.AddrPort, and newSession closes Pipe.Out over
// the AddrPort that created the session. A NAT rebind is therefore a miss,
// not a SetPeer.

// TestALiveSessionIsNotFoundAfterTheOuterEndpointChanges is the demux miss.
//
// Same host, new source port: the shape a NAT rebind actually has. The live
// session stays under the old AddrPort; sessionFor on the new one builds a
// second session rather than rebinding the first; nothing calls latchDown.
func TestALiveSessionIsNotFoundAfterTheOuterEndpointChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, _ := newTestServer(t, 8)
	t.Cleanup(srv.closeAll)

	old := netip.MustParseAddrPort("127.0.0.1:40001")
	moved := netip.MustParseAddrPort("127.0.0.1:40002")

	ps, err := srv.sessionFor(ctx, old)
	if err != nil {
		t.Fatalf("sessionFor(old): %v", err)
	}
	if !srv.known(old) {
		t.Fatal("the session was not recorded under the address that created it")
	}
	if srv.known(moved) {
		t.Fatal("the session was found under a different outer endpoint; this binary indexes by AddrPort, so a rebind must miss")
	}
	if got := len(srv.peers); got != 1 {
		t.Fatalf("peers = %d, want 1", got)
	}

	// An outer-address miss does not latch the gate down. The session has not
	// handshook, so the gate is not carrying yet; the load-bearing check is
	// that it is not StateDown-because-of-the-miss (latchDown sets down).
	if ps.loop.Tunnel() == nil {
		t.Fatal("the original loop has no tun layer")
	}
	if ps.loop.Session().State() == session.StateFailed {
		t.Fatal("the original session failed when a different outer endpoint was merely considered")
	}

	ps2, err := srv.sessionFor(ctx, moved)
	if err != nil {
		t.Fatalf("sessionFor(moved): %v", err)
	}
	if ps2 == ps {
		t.Fatal("sessionFor reused the live session for a new outer endpoint")
	}
	if got := len(srv.peers); got != 2 {
		t.Fatalf("peers = %d, want 2 (old session kept, new session built)", got)
	}
	if !srv.known(old) {
		t.Fatal("the original session was evicted when a new outer endpoint appeared")
	}
	if ps.loop.Session().State() == session.StateFailed ||
		ps.loop.Session().State() == session.StateClosed {
		t.Fatalf("the original session became %s after a second outer endpoint was admitted; a miss must not tear it down",
			ps.loop.Session().State())
	}
}

// TestADataSizedRoamIsAStrangerAndLeavesTheGateCarrying drives the read loop.
//
// After a real handshake the client's NAT mapping is simulated by a second
// socket sending a datagram too large to be an initiation (the common case
// for a full-size data packet). The binary must:
//
//   - count it as a stranger (couldBeInitiation is false, known is false)
//   - not construct a second session
//   - leave the original session's gate in StateCarrying
//
// The gate dropping on a roam would be a different, worse bug: the tunnel
// would report down while the session was still established and the client
// was still sending.
func TestADataSizedRoamIsAStrangerAndLeavesTheGateCarrying(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

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
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()

	srv := &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	cli := startTestClient(t, ctx, testClientOpts{
		dir: dir, gwAddr: gwAddr,
		gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
		admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
		sizing:        sizing, inner: testClientInner,
	})
	waitFor(t, 40*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	payload := []byte("roam-behaviour pre-move round trip")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, payload))
	back := cli.dev.take(t, 40*time.Second)
	if !bytes.Equal(back[20:], payload) {
		t.Fatalf("pre-roam round trip payload is %q, want %q; the session was not live", back[20:], payload)
	}
	waitFor(t, 20*time.Second, "the gateway to hold one carrying session", func() bool {
		st := srv.status()
		return st.Sessions == 1 && st.Carrying >= 1
	})

	before := srv.status()
	if before.Strangers != 0 {
		t.Fatalf("fixture: strangers is %d before the roam, want 0", before.Strangers)
	}

	roamer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer roamer.Close()
	// A full-size data packet is larger than MaxHandshakeMessage (1024).
	if _, err := roamer.Write(make([]byte, core.MaxHandshakeMessage+1)); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, "the roam datagram to be counted as a stranger", func() bool {
		return srv.status().Strangers > 0
	})
	time.Sleep(300 * time.Millisecond)

	after := srv.status()
	if after.Sessions != 1 {
		t.Fatalf("a data-sized roam bought a new session: sessions %d -> %d", before.Sessions, after.Sessions)
	}
	if after.Built != before.Built {
		t.Fatalf("a data-sized roam constructed a session: built %d -> %d", before.Built, after.Built)
	}
	if cli.loop.Tunnel().Gate().State() != tun.StateCarrying {
		t.Fatalf("the client gate dropped to %s on a gateway-side demux miss; a roam must not close the gate immediately",
			cli.loop.Tunnel().Gate().State())
	}
	if after.Carrying < 1 {
		t.Fatalf("the gateway-side carrying count dropped to %d; the original session's gate was closed by the miss",
			after.Carrying)
	}
}

// TestForwardTableSurvivesWithoutAnOuterEndpointKey is the inner-address
// invariant.
//
// forwardTable is keyed by inner ADDRESS ALONE. An outer 5-tuple change is
// not an argument this type accepts, so a roam cannot drop a mapping except
// by some caller invoking forget (which only gatewayForwardDevice.Close does,
// and only for addresses that device learned). Learn, then do nothing a roam
// could do at this layer, and the mapping must still be there.
func TestForwardTableSurvivesWithoutAnOuterEndpointKey(t *testing.T) {
	tbl := newForwardTable()
	loop := fakeLoop()
	inner := mustAddr(t, "10.64.0.2")
	tbl.learn(inner, loop)

	got, ok := tbl.lookup(inner)
	if !ok || got != loop {
		t.Fatalf("lookup after learn: got=%v ok=%v", got, ok)
	}
	st := tbl.Stats()
	if st.Size != 1 || st.Forgotten != 0 || st.Collisions != 0 {
		t.Fatalf("a table that has only learned should not have forgotten or collided: %+v", st)
	}

	// A second session at a different INNER address must not disturb the first.
	other := fakeLoop()
	tbl.learn(mustAddr(t, "10.64.0.3"), other)
	got, ok = tbl.lookup(inner)
	if !ok || got != loop {
		t.Fatalf("learning a different inner address displaced the roam survivor: got=%v ok=%v", got, ok)
	}

	// Close of a device that never learned `inner` must not forget it.
	dev := newGatewayForwardDevice(&fakeInnerWriter{}, tbl, 1400)
	dev.bind(other)
	if _, err := dev.WritePacket(ipv4Packet(t, "10.64.0.3", "8.8.8.8")); err != nil {
		t.Fatal(err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	got, ok = tbl.lookup(inner)
	if !ok || got != loop {
		t.Fatalf("closing a different session's device forgot the roam survivor: got=%v ok=%v", got, ok)
	}
}

// TestAnInitiationSizedRoamAllocatesASecondSession is the other read-loop
// branch: a datagram from a new AddrPort that passes the admission screen
// calls sessionFor and builds a new session. The original is not replaced.
//
// It used to be ANY datagram of initiation size, which is how a PING-sized
// packet after a rebind spent a session slot without recovering the live
// tunnel. Since the admission screen, an initiation-sized datagram that fails
// the admission tag is a stranger and buys nothing; the first half of this
// test pins that.
func TestAnInitiationSizedRoamAllocatesASecondSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, gwAddr := newTestServer(t, 8)
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = srv.conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	old := netip.MustParseAddrPort("127.0.0.1:41001")
	if _, err := srv.sessionFor(ctx, old); err != nil {
		t.Fatal(err)
	}
	if got := len(srv.peers); got != 1 {
		t.Fatalf("fixture: peers = %d, want 1", got)
	}

	roamer, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer roamer.Close()
	if _, err := roamer.Write([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the one-byte roam to be counted as a stranger", func() bool {
		return srv.status().Strangers > 0
	})
	if st := srv.status(); st.Sessions != 1 || st.Built != 1 {
		t.Fatalf("a one-byte datagram that fails the admission tag bought a session: sessions=%d built=%d",
			st.Sessions, st.Built)
	}
	if _, err := roamer.Write(admissibleForeignInitiation(t, srv.sessionCfg)); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, "a second session to be built for the initiation-sized roam", func() bool {
		return srv.status().Sessions == 2
	})
	if !srv.known(old) {
		t.Fatal("the original session was evicted by the initiation-sized roam")
	}
	st := srv.status()
	if st.Built != 2 {
		t.Fatalf("built = %d, want 2", st.Built)
	}
}

// TestAuthenticatedFullSizeDataAfterAClientRebindIsAStrangerAndBothGatesStayCarrying
// is the worst realistic roam failure this binary currently has, and the one
// TestADataSizedRoamIsAStrangerAndLeavesTheGateCarrying does not cover.
//
// That sibling sends unauthenticated junk from a third socket. A real NAT
// rebind is the LIVE client sending authenticated transport from a new source
// port, same session keys. This test does that: after a carrying round-trip it
// Loop.Migrates the client onto a freshly dialled UDP socket (new local port)
// and offers a full-size inner packet.
//
// What the binary must do today, which is a defect pin not an intended
// behaviour:
//
//   - count the rebound datagram as a stranger (known is false, length >
//     MaxHandshakeMessage so couldBeInitiation is false)
//   - not insert the new AddrPort into server.peers
//   - not echo the inner packet
//   - leave BOTH gates in StateCarrying
//
// That last point is the fail-open: the user sees a tunnel that reports up
// while every full-size flow has vanished, which is indistinguishable from a
// censor dropping the path. Replies still leave via Pipe.Out closed over the
// ORIGINAL AddrPort at newSession; the client's reader is now on the new
// socket, so even a demux hit would black-hole the return path.
//
// The intended protocol path is winn3/gateway.Table.Dispatch (address-free)
// plus carrier.UDP.SetPeer from the source of a datagram that opened under
// the session AEAD. Neither is on this binary's readLoop.
func TestAuthenticatedFullSizeDataAfterAClientRebindIsAStrangerAndBothGatesStayCarrying(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

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
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()

	srv := &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	cli := startTestClient(t, ctx, testClientOpts{
		dir: dir, gwAddr: gwAddr,
		gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
		admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
		sizing:        sizing, inner: testClientInner,
	})
	waitFor(t, 40*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	pre := []byte("authenticated-rebind pre-move round trip")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, pre))
	back := cli.dev.take(t, 40*time.Second)
	if !bytes.Equal(back[20:], pre) {
		t.Fatalf("pre-rebind round trip payload is %q, want %q; the session was not live", back[20:], pre)
	}
	waitFor(t, 20*time.Second, "the gateway to hold one carrying session", func() bool {
		st := srv.status()
		return st.Sessions == 1 && st.Carrying >= 1
	})

	rebound, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rebound.Close() })
	local, ok := rebound.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		t.Fatal("the rebound socket has no UDP local address")
	}
	ap := local.AddrPort()
	if srv.known(ap) {
		t.Skip("kernel reused the live client's source port; this run cannot distinguish a roam from the original mapping")
	}

	newCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn:           rebound,
		OwnsConn:       true,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		t.Fatalf("NewUDP(rebound): %v", err)
	}
	if _, err := cli.loop.Migrate(newCar); err != nil {
		t.Fatalf("client Loop.Migrate onto the rebound socket: %v", err)
	}
	if got := cli.loop.Stats().Migrations; got != 1 {
		t.Fatalf("client Migrations = %d after Migrate, want 1; the rebind did not take", got)
	}

	before := srv.status()
	if before.Strangers != 0 {
		t.Fatalf("fixture: strangers is %d before the authenticated rebind, want 0", before.Strangers)
	}

	// Inner packet large enough that the sealed transport message exceeds
	// MaxHandshakeMessage (so couldBeInitiation is false) but small enough
	// that PadBucket still has room under the plan floor. Filling InnerMTU
	// exactly would leave no pad budget and the client might never Send.
	const reboundPayload = 1000
	minFramed := core.TransportOverhead() + 3 + 20 + reboundPayload
	if minFramed <= core.MaxHandshakeMessage {
		t.Fatalf("fixture: min framed size %d is not above MaxHandshakeMessage %d; this would take the initiation-sized branch",
			minFramed, core.MaxHandshakeMessage)
	}
	if 20+reboundPayload > sizing.InnerMTU {
		t.Fatalf("fixture: inner packet %d exceeds InnerMTU %d", 20+reboundPayload, sizing.InnerMTU)
	}
	full := make([]byte, reboundPayload)
	for i := range full {
		full[i] = byte(i)
	}
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, full))

	waitFor(t, 10*time.Second, "the authenticated rebound datagram to be counted as a stranger", func() bool {
		return srv.status().Strangers > 0
	})

	echo := tryTakeDevice(cli.dev, 3*time.Second)
	if echo != nil {
		t.Fatalf("the rebound full-size packet echoed %d bytes; a NAT rebind against this binary must black-hole it", len(echo))
	}

	after := srv.status()
	if after.Sessions != 1 {
		t.Fatalf("an authenticated rebind bought a new session: sessions %d -> %d", before.Sessions, after.Sessions)
	}
	if after.Built != before.Built {
		t.Fatalf("an authenticated rebind constructed a session: built %d -> %d", before.Built, after.Built)
	}
	if srv.known(ap) {
		t.Fatal("the rebound AddrPort was inserted into server.peers; readLoop must not sessionFor a data-sized stranger")
	}
	if cli.loop.Tunnel().Gate().State() != tun.StateCarrying {
		t.Fatalf("the client gate dropped to %s on an authenticated rebind; both gates staying carrying is the fail-open",
			cli.loop.Tunnel().Gate().State())
	}
	if after.Carrying < 1 {
		t.Fatalf("the gateway-side carrying count dropped to %d; the original session's gate was closed by the miss",
			after.Carrying)
	}
}

// tryTakeDevice waits up to within for an inbound inner packet. Unlike
// testDevice.take it returns nil on timeout so a test can assert that a
// black-hole happened rather than treating silence as a harness failure.
func tryTakeDevice(d *testDevice, within time.Duration) []byte {
	select {
	case p := <-d.out:
		return p
	case <-time.After(within):
		return nil
	}
}

// TestTokenDemuxRoamRebindsAndEchoes verifies that when demux is set to token,
// a live session whose outer UDP endpoint changes mid-session authenticates
// the incoming datagram, rebinds the peer address, and successfully echoes
// traffic back to the new endpoint without dropping the session.
func TestTokenDemuxRoamRebindsAndEchoes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer conn.Close()

	srv := &server{
		conn:        conn,
		sizing:      sizing,
		sessionCfg:  sessionCfg,
		assign:      assign,
		maxSessions: 8,
		demux:       "token",
		peers:       make(map[netip.AddrPort]*peerSession),
	}
	readDone := make(chan error, 1)
	go func() { readDone <- srv.readLoop(ctx) }()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-readDone
		srv.closeAll()
	}()

	gwAddr := conn.LocalAddr().(*net.UDPAddr)
	cli := startTestClient(t, ctx, testClientOpts{
		dir: dir, gwAddr: gwAddr,
		gatewayPublic: readTestKey(t, filepath.Join(dir, "static.pub")),
		admission:     readTestSecret(t, filepath.Join(dir, "admission.key")),
		sizing:        sizing, inner: testClientInner,
	})
	waitFor(t, 40*time.Second, "the client gate to carry", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})
	pre := []byte("token-demux pre-move round trip")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, pre))
	back := cli.dev.take(t, 40*time.Second)
	if !bytes.Equal(back[20:], pre) {
		t.Fatalf("pre-rebind round trip payload is %q, want %q; the session was not live", back[20:], pre)
	}
	waitFor(t, 20*time.Second, "the gateway to hold one carrying session", func() bool {
		st := srv.status()
		return st.Sessions == 1 && st.Carrying >= 1
	})

	rebound, err := net.DialUDP("udp4", nil, gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rebound.Close() })
	local, ok := rebound.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		t.Fatal("the rebound socket has no UDP local address")
	}
	ap := local.AddrPort()
	if srv.known(ap) {
		t.Skip("kernel reused the live client's source port; this run cannot distinguish a roam from the original mapping")
	}

	newCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn:           rebound,
		OwnsConn:       true,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		t.Fatalf("NewUDP(rebound): %v", err)
	}
	if _, err := cli.loop.Migrate(newCar); err != nil {
		t.Fatalf("client Loop.Migrate onto the rebound socket: %v", err)
	}
	if got := cli.loop.Stats().Migrations; got != 1 {
		t.Fatalf("client Migrations = %d after Migrate, want 1; the rebind did not take", got)
	}

	before := srv.status()
	if before.Strangers != 0 {
		t.Fatalf("fixture: strangers is %d before the authenticated rebind, want 0", before.Strangers)
	}

	post := []byte("token-demux post-rebind round trip successfully rebounded")
	cli.dev.offer(t, testIPv4(t, testClientInner, testGatewayInner, post))

	echo := cli.dev.take(t, 20*time.Second)
	if echo == nil {
		t.Fatal("the rebound packet was not echoed back after migration under -demux=token")
	}
	if !bytes.Equal(echo[20:], post) {
		t.Fatalf("post-rebind echoed payload is %q, want %q", echo[20:], post)
	}

	after := srv.status()
	if after.Strangers != 0 {
		t.Fatalf("strangers was incremented to %d under token demux, want 0", after.Strangers)
	}
	if !srv.known(ap) {
		t.Fatal("the rebound AddrPort was not learned in server.peers under token demux")
	}
	if after.Sessions != 1 {
		t.Fatalf("session count changed across roam: %d, want 1", after.Sessions)
	}
}
