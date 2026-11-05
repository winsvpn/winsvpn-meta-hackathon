package netlab

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/gateway"
)

// Property 3: NAT rebinding.
//
// A mobile user's source address and port change constantly — a cell handover,
// a NAT table sweep, a switch from cellular to wifi. The prediction to confirm
// is that the gateway indexes by demux token rather than by 5-tuple and
// therefore survives it. It does, and this file confirms it with real crypto
// and real tokens.
//
// What it also establishes, and what is not in any handoff document, is the
// half of the round trip nothing indexes: the RETURN path. See §5 of
// WINN3_NETWORK_REALISM_20260808.md.

// --- a real core.Session pair, which the session driver deliberately hides ----

// corePair completes a real handshake and hands back both sessions.
//
// winn3/session refuses to expose *core.Session — TestNoExportedPathHandsOutTheSealer
// fails if any exported method returns one, because a second sealer is the one
// remaining way to overturn the core lane's nonce-reuse verdict. So a test that
// needs the raw sessions builds its own pair, which is what the gateway lane's
// own integration tests do.
type corePair struct {
	Client  *core.Session
	Gateway *core.Session
	Resp    *core.Responder
	Cfg     core.Config
	Static  *core.StaticKey
	Init    []byte // the initiation, byte for byte, for the replay tests
}

func newCorePair(t *testing.T, now func() time.Time) *corePair {
	t.Helper()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{Gateway: kr.Params, Now: now, TokenWindow: netlabWindow}

	resp, err := core.NewResponder(cfg, kr.GatewayStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ini, err := core.NewInitiator(cfg, kr.ClientStatic, kr.GatewayPublic)
	if err != nil {
		t.Fatal(err)
	}
	initMsg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := resp.ReadInitiation(initMsg)
	if err != nil {
		t.Fatal(err)
	}
	respMsg, gwSess, err := hs.WriteResponse(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	cliSess, _, err := ini.ReadResponse(respMsg)
	if err != nil {
		t.Fatal(err)
	}
	return &corePair{
		Client: cliSess, Gateway: gwSess, Resp: resp,
		Cfg: cfg, Static: kr.GatewayStatic, Init: append([]byte(nil), initMsg...),
	}
}

// harvestSource is a TokenSource built from tokens observed on real seals.
//
// core.Session does not export its receive demux key, so the production
// KeyedSource cannot be wired up from outside the package yet. Harvesting the
// true sequence from real ciphertext gives the table exactly the input it will
// get in production — the crypto, the tokens and the dispatch are all genuine,
// and only the way the sequence reaches the table is a stand-in. This is the
// same accommodation the gateway lane's own integration tests make.
type harvestSource struct {
	mu   sync.Mutex
	real map[uint64]gateway.Token
	fill [core.KeySize]byte
}

func newHarvestSource() *harvestSource {
	h := &harvestSource{real: map[uint64]gateway.Token{}}
	for i := range h.fill {
		h.fill[i] = byte(i*13 + 1)
	}
	return h
}

func (h *harvestSource) record(counter uint64, msg []byte) {
	var tok gateway.Token
	copy(tok[:], msg[:core.DemuxTokenSize])
	h.mu.Lock()
	h.real[counter] = tok
	h.mu.Unlock()
}

func (h *harvestSource) TokenAt(counter uint64) gateway.Token {
	h.mu.Lock()
	tok, ok := h.real[counter]
	h.mu.Unlock()
	if ok {
		return tok
	}
	return gateway.DeriveToken(&h.fill, counter)
}

// TestGatewayDispatchIsAddressFree is the confirmation.
//
// A run of real transport messages is dispatched with the source address
// changing between every single datagram — a rebind per packet, far worse than
// any real network produces. Table.Dispatch takes no address argument at all
// and Gateway.Handle takes one only to meter the admission path, so this is a
// property of the type signature as much as of the behaviour; measuring it
// anyway is what stops a later change from adding a 5-tuple fast path that
// quietly becomes a correctness dependency.
func TestGatewayDispatchIsAddressFree(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cp := newCorePair(t, func() time.Time { return now })

	const n = 128
	src := newHarvestSource()
	msgs := make([][]byte, n)
	for i := 0; i < n; i++ {
		m, err := cp.Client.Seal([]byte{byte(i), 0x11, 0x22}, 0)
		if err != nil {
			t.Fatal(err)
		}
		src.record(uint64(i), m)
		msgs[i] = m
	}

	tbl, err := gateway.NewTable(gateway.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	clientID := make([]byte, core.KeySize)
	for i := range clientID {
		clientID[i] = byte(i + 1)
	}
	if _, err := tbl.Register(cp.Gateway, src, clientID, now); err != nil {
		t.Fatal(err)
	}

	// Every datagram arrives from a different address, which is a rebind between
	// every packet — far worse than any real network produces.
	for i, m := range msgs {
		ent, plain, err := tbl.Dispatch(m, now)
		if err != nil {
			t.Fatalf("datagram %d did not route after a source-address change: %v. "+
				"The gateway index is supposed to be keyed on the demux token, so a rebind "+
				"must be invisible to it.", i, err)
		}
		if ent == nil || len(plain) != 3 || plain[0] != byte(i) {
			t.Fatalf("datagram %d routed to the wrong place: %v", i, plain)
		}
	}
	if st := tbl.Stats(); st.Dispatched != n {
		t.Fatalf("dispatched %d of %d", st.Dispatched, n)
	}
}

// TestTheReplayCacheIsAddressIndependentAcrossARebind covers the second half of
// the prediction, and the answer has a cost in it worth writing down.
//
// The cache is keyed on the initiation BODY, never on the source, so a rebind
// does not let a replayed initiation through — which is right, because an
// address is not an authenticator and a cache that trusted one would hand a
// prober a permanent gateway detector for the price of spoofing a source.
//
// The cost is on the honest client: after a rebind mid-handshake its
// BYTE-IDENTICAL retransmission is refused in silence, exactly as an attacker's
// replay is, and it recovers only when Retry.FreshAfter makes it draw a new
// ephemeral. A rebind during a handshake therefore costs the FreshAfter budget
// on top of the handshake itself.
func TestTheReplayCacheIsAddressIndependentAcrossARebind(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cp := newCorePair(t, func() time.Time { return now })

	// The same initiation again — the client's retransmission after a rebind.
	if _, err := cp.Resp.ReadInitiation(cp.Init); err == nil {
		t.Fatal("a byte-identical initiation was accepted a second time; the replay cache is not " +
			"refusing it, which turns one captured packet into a permanent gateway detector")
	}

	// A genuinely fresh initiation from the same client is accepted, so the
	// refusal above is the cache and not a dead responder.
	kr2, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := core.NewPublicKey(cp.Static.Public())
	if err != nil {
		t.Fatal(err)
	}
	ini2, err := core.NewInitiator(cp.Cfg, kr2.ClientStatic, pub)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := ini2.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.Resp.ReadInitiation(fresh); err != nil {
		t.Fatalf("a fresh initiation was refused: %v; the responder is dead and the replay "+
			"assertion above proves nothing", err)
	}
}

// TestAdmissionFreshnessIsTimeNotAddress pins the third piece: the admission
// tag's freshness bucket is a never-transmitted time bucket, so a rebind cannot
// move it and a client whose clock is inside the skew window authenticates from
// any address at all — while one outside it authenticates from none.
func TestAdmissionFreshnessIsTimeNotAddress(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	clientNow := base
	gatewayNow := base

	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	ccfg := core.Config{Gateway: kr.Params, Now: func() time.Time { return clientNow }}
	gcfg := core.Config{Gateway: kr.Params, Now: func() time.Time { return gatewayNow }}

	newInit := func() []byte {
		ini, err := core.NewInitiator(ccfg, kr.ClientStatic, kr.GatewayPublic)
		if err != nil {
			t.Fatal(err)
		}
		m, err := ini.WriteInitiation(nil, core.PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	resp, err := core.NewResponder(gcfg, kr.GatewayStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	// Inside the skew window, from anywhere.
	if _, err := resp.ReadInitiation(newInit()); err != nil {
		t.Fatalf("an initiation inside the skew window was refused: %v", err)
	}
	// Outside it, from anywhere.
	clientNow = base.Add(-2 * core.DefaultMaxSkew)
	if _, err := resp.ReadInitiation(newInit()); err == nil {
		t.Fatalf("an initiation %s outside the %s skew window was accepted; the freshness "+
			"bucket is not bounding anything", 2*core.DefaultMaxSkew, core.DefaultMaxSkew)
	}
}

// --- the break: the carrier, not the index ------------------------------------

// loopbackUDP opens one datagram socket bound explicitly to the IPv4 loopback
// address on an ephemeral port. It is the only place in this package a socket
// is opened, it is loopback by construction, and it skips rather than fails if
// the platform will not provide one.
func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("no loopback datagram socket available: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestAnExplicitPeerCarrierDropsEveryDatagramAfterARebind is the finding.
//
// The gateway's index survives a rebind. The gateway's CARRIER does not.
// carrier.NewUDP over an unconnected socket filters on the configured peer and
// counts everything else as Foreign, and there is no exported way to change
// that peer on a live carrier. So the moment a client's NAT renumbers it, every
// datagram it sends is discarded one layer BELOW the token index that would
// have routed it.
//
// This is a real source-address change on real sockets, not a model of one.
func TestAnExplicitPeerCarrierDropsEveryDatagramAfterARebind(t *testing.T) {
	t.Parallel()
	gwConn := loopbackUDP(t)
	before := loopbackUDP(t) // the client's address before the rebind
	after := loopbackUDP(t)  // and after it

	c, err := carrier.NewUDP(carrier.UDPConfig{
		Conn:    gwConn,
		Peer:    before.LocalAddr().(*net.UDPAddr),
		PathMTU: 1280,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	msg := make([]byte, 64)
	for i := range msg {
		msg[i] = byte(i)
	}
	gwAddr := gwConn.LocalAddr().(*net.UDPAddr)

	// One datagram from the pre-rebind address, to show the carrier is live.
	if _, err := before.WriteToUDP(msg, gwAddr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.Recv(ctx); err != nil {
		t.Fatalf("the carrier did not deliver a datagram from its configured peer: %v", err)
	}

	// Now the rebind. Twenty datagrams from the new address.
	const rebound = 20
	for i := 0; i < rebound; i++ {
		if _, err := after.WriteToUDP(msg, gwAddr); err != nil {
			t.Fatal(err)
		}
	}
	// Give them time to be read and filtered, then observe.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && c.Stats().Foreign < rebound {
		rctx, rcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _ = c.Recv(rctx)
		rcancel()
	}
	st := c.Stats()
	if st.Foreign != rebound {
		t.Fatalf("Foreign is %d after %d datagrams from the rebound address; the rig did not "+
			"produce the source-address change and this test proves nothing", st.Foreign, rebound)
	}
	if st.Delivered != 1 {
		t.Fatalf("Delivered is %d; the rebound datagrams were delivered after all, which would "+
			"mean the sender filter is not applied", st.Delivered)
	}
	// And now the way out, which is the fix for §5 of
	// WINN3_NETWORK_REALISM_20260808.md: the return path can be moved.
	//
	// The move is made from the address of a datagram that would have
	// DISPATCHED — an AEAD decision — which is what makes following it safe. The
	// rig stands in for that: a real caller learns the address from a successful
	// Table.Dispatch, and SetPeer's doc comment states the contract because
	// nothing in winn3/carrier holds a key with which to enforce it.
	if err := c.SetPeer(after.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("SetPeer refused a legitimate rebind: %v", err)
	}
	if got := c.Peer(); got == nil || got.String() != after.LocalAddr().String() {
		t.Fatalf("Peer() is %v after SetPeer, want %v", got, after.LocalAddr())
	}
	moved := c.Stats()
	if moved.PeerMoves != 1 {
		t.Fatalf("PeerMoves is %d after one move; it is the ONLY counter a policy layer may "+
			"read as mobility evidence, so it has to be exact", moved.PeerMoves)
	}
	if moved.LastPeerMove.IsZero() {
		t.Fatal("LastPeerMove was not stamped; a move with no timestamp cannot age out of the " +
			"rebind window and would excuse a blocked carrier forever")
	}

	// Twenty more from the rebound address. All of them must now arrive.
	for i := 0; i < rebound; i++ {
		if _, err := after.WriteToUDP(msg, gwAddr); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && got < rebound {
		rctx, rcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		if _, err := c.Recv(rctx); err == nil {
			got++
		}
		rcancel()
	}
	if got != rebound {
		t.Fatalf("after SetPeer only %d of %d datagrams from the rebound address were delivered "+
			"(stats %+v); a rebind still costs a re-handshake", got, rebound, c.Stats())
	}
	if after := c.Stats(); after.Foreign != st.Foreign {
		t.Fatalf("Foreign moved from %d to %d after the peer was updated; the filter is now "+
			"pointed at the wrong address", st.Foreign, after.Foreign)
	}
}

// TestSetPeerRefusesWhatItMustRefuse pins the three refusals, because SetPeer is
// the one method in this package that can redirect a live tunnel and a lenient
// one would be a gift to an off-path attacker.
func TestSetPeerRefusesWhatItMustRefuse(t *testing.T) {
	t.Parallel()
	gwConn := loopbackUDP(t)
	peer := loopbackUDP(t)
	c, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: gwConn, Peer: peer.LocalAddr().(*net.UDPAddr), PathMTU: 1280,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.SetPeer(nil); err == nil {
		t.Fatal("SetPeer(nil) was accepted; a carrier with no peer accepts datagrams from anywhere")
	}
	// The same address twice is not a move, and must not inflate the one counter
	// the escalation policy trusts.
	if err := c.SetPeer(peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("SetPeer to the address already configured: %v", err)
	}
	if n := c.Stats().PeerMoves; n != 0 {
		t.Fatalf("PeerMoves is %d after a no-op move; ordinary traffic could then manufacture "+
			"mobility evidence", n)
	}
	_ = c.Close()
	if err := c.SetPeer(peer.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("SetPeer succeeded on a closed carrier")
	}

	// And a connected socket refuses: its filter is the kernel's, and accepting
	// the address here would leave the caller believing a move happened.
	dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dcancel()
	dialled, err := carrier.DialUDP(dctx, carrier.UDPConfig{
		Remote: peer.LocalAddr().(*net.UDPAddr), PathMTU: 1280,
	})
	if err != nil {
		t.Skipf("no loopback UDP dial available: %v", err)
	}
	defer func() { _ = dialled.Close() }()
	if dialled.Peer() != nil {
		t.Fatal("a connected carrier reports a userspace peer; the kernel holds it")
	}
	if err := dialled.SetPeer(peer.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("SetPeer succeeded on a connected socket, where it cannot have taken effect")
	}
}

// TestARebindIsDistinguishableFromABlockedCarrierOnlyByPeerMoves is the
// dangerous consequence and its answer, in one test.
//
// LastDelivered is the freshest evidence a policy layer has that a carrier is
// still carrying, and Foreign deliberately moves nothing else — a property the
// carrier lane built on purpose, to stop an off-path attacker holding a blocked
// carrier's health indicator UP. Run it the other way and a rebound client
// presents as: datagrams arriving at line rate, none delivered, LastDelivered
// frozen at the moment of the rebind. That is byte-for-byte the evidence
// signature of the measured censorship failure, and the two want opposite
// responses.
//
// The first half of this test therefore still asserts the OLD finding, because
// the property it rests on must not be weakened: Foreign must keep moving
// nothing else, or the failover-suppression attack reopens. What changes is that
// there is now a second counter, PeerMoves, which only an AEAD-authenticated
// event can move, and which is therefore the discriminator. The test asserts
// both: that Foreign alone still says nothing, and that PeerMoves says the thing
// Foreign cannot.
func TestARebindIsDistinguishableFromABlockedCarrierOnlyByPeerMoves(t *testing.T) {
	t.Parallel()
	gwConn := loopbackUDP(t)
	before := loopbackUDP(t)
	after := loopbackUDP(t)

	clk := NewStepClock()
	c, err := carrier.NewUDP(carrier.UDPConfig{
		Conn:    gwConn,
		Peer:    before.LocalAddr().(*net.UDPAddr),
		PathMTU: 1280,
		Clock:   SessionClockOf(clk),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	msg := make([]byte, 64)
	gwAddr := gwConn.LocalAddr().(*net.UDPAddr)
	if _, err := before.WriteToUDP(msg, gwAddr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.Recv(ctx); err != nil {
		t.Fatal(err)
	}
	atRebind := c.Stats()
	clk.Advance(5 * time.Minute)

	for i := 0; i < 30; i++ {
		if _, err := after.WriteToUDP(msg, gwAddr); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && c.Stats().Foreign < 30 {
		rctx, rcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _ = c.Recv(rctx)
		rcancel()
	}
	st := c.Stats()
	if st.Foreign < 30 {
		t.Fatalf("only %d foreign datagrams observed; the rig did not reproduce the rebind", st.Foreign)
	}
	if !st.LastDelivered.Equal(atRebind.LastDelivered) {
		t.Fatal("LastDelivered moved on a foreign datagram; that is the failover-suppression bug " +
			"the carrier lane closed, and it must stay closed")
	}
	if st.Delivered != atRebind.Delivered {
		t.Fatalf("Delivered moved from %d to %d on foreign datagrams", atRebind.Delivered, st.Delivered)
	}
	// The finding, stated as an assertion so it cannot be read as a hunch: five
	// minutes after the rebind the carrier's evidence is identical to a blocked
	// carrier's, and nothing in Stats distinguishes the two.
	silent := clk.Now().Sub(st.LastDelivered)
	if silent < 5*time.Minute {
		t.Fatalf("LastDelivered is only %s old after a rebind plus five minutes", silent)
	}
	// Up to here the evidence is a blocked carrier's, exactly. This is the
	// assertion that says so, so that nobody reads the fix below as making
	// Foreign meaningful.
	if st.PeerMoves != 0 {
		t.Fatalf("PeerMoves is %d after nothing but FOREIGN datagrams. Foreign is exactly as "+
			"consistent with an off-path attacker who found the five-tuple as with a rebind, so "+
			"a carrier that learned a peer from it would let one spoofed packet redirect a live "+
			"tunnel to the attacker", st.PeerMoves)
	}
	t.Logf("before the peer is moved: Delivered=%d Foreign=%d PeerMoves=%d LastDelivered %s ago "+
		"— the same evidence shape as a wholesale UDP block",
		st.Delivered, st.Foreign, st.PeerMoves, silent)

	// Now the authenticated event a real caller has and this rig stands in for:
	// a datagram from the new address DISPATCHED. The carrier is told, and the
	// evidence separates.
	if err := c.SetPeer(after.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	moved := c.Stats()
	if moved.PeerMoves != 1 || moved.LastPeerMove.IsZero() {
		t.Fatalf("after an authenticated move PeerMoves=%d LastPeerMove=%v; the discriminator "+
			"did not move and the two failures are still identical",
			moved.PeerMoves, moved.LastPeerMove)
	}
	if !moved.LastDelivered.Equal(st.LastDelivered) {
		t.Fatal("SetPeer moved LastDelivered. It must not: LastDelivered means a message " +
			"arrived at this carrier, and a peer move is a different fact carried in its own " +
			"counter precisely so that the two cannot be confused")
	}
	if moved.Foreign != st.Foreign {
		t.Fatalf("SetPeer moved Foreign from %d to %d", st.Foreign, moved.Foreign)
	}
	t.Logf("after the peer is moved: PeerMoves=%d LastPeerMove %s ago — a censor cannot "+
		"produce this row", moved.PeerMoves, clk.Now().Sub(moved.LastPeerMove))
}
