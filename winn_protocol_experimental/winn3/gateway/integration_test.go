package gateway

import (
	"bytes"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestRealSessionsRouteThroughTheTable is the whole package against real
// cryptography: real handshakes, real ChaCha20-Poly1305 transport messages,
// real demux tokens taken off real ciphertexts, and one table picking the right
// session out of many from eight bytes.
func TestRealSessionsRouteThroughTheTable(t *testing.T) {
	h := newRealHarness(t, silentCfg())

	const clients, msgs = 8, 24
	cs := make([]*client, clients)
	for i := range cs {
		cs[i] = h.newClient(t, i, msgs)
	}
	tbl := h.gw.Table()
	if got := tbl.Sessions(); got != clients {
		t.Fatalf("%d sessions registered, want %d", got, clients)
	}

	// Interleaved, so a table that routed by arrival order would be caught.
	for m := 0; m < msgs; m++ {
		for i, c := range cs {
			ent, plain, err := tbl.Dispatch(c.msgs[m], h.clock())
			if err != nil {
				t.Fatalf("client %d message %d did not route: %v", i, m, err)
			}
			if ent != c.entry {
				t.Fatalf("client %d message %d routed to session %d", i, m, ent.ID())
			}
			want := []byte{byte(m), byte(m >> 8), 0x5A}
			if !bytes.Equal(plain, want) {
				t.Fatalf("client %d message %d opened as %x, want %x", i, m, plain, want)
			}
		}
	}
	if got := tbl.Stats().Dispatched; got != clients*msgs {
		t.Fatalf("Dispatched is %d, want %d", got, clients*msgs)
	}
	// Every session earned its way past the initial window by carrying traffic.
	for i, c := range cs {
		if c.entry.Window() <= 16 {
			t.Fatalf("client %d still has a %d-token window after %d authenticated messages",
				i, c.entry.Window(), msgs)
		}
	}
}

// TestRealReplayIsAbsorbedByTheIndexAndNeverReachesTheCrypto.
//
// The demux window IS the replay filter, so a replayed transport message should
// die at the index without the session's AEAD ever being asked. That is worth
// measuring rather than assuming: it is the difference between a replay costing
// a map lookup and a replay costing a Poly1305 verification, which at flood
// rates is the difference between a nuisance and an outage.
func TestRealReplayIsAbsorbedByTheIndexAndNeverReachesTheCrypto(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	c := h.newClient(t, 1, 4)
	tbl := h.gw.Table()

	if _, _, err := tbl.Dispatch(c.msgs[0], h.clock()); err != nil {
		t.Fatalf("the genuine message did not route: %v", err)
	}
	before := tbl.Stats()
	for i := 0; i < 1000; i++ {
		if _, _, err := tbl.Dispatch(c.msgs[0], h.clock()); err == nil {
			t.Fatal("a replayed transport message routed")
		}
	}
	after := tbl.Stats()
	if after.OpenFailed != before.OpenFailed {
		t.Fatalf("%d replays reached the session's cryptography; the index must absorb them",
			after.OpenFailed-before.OpenFailed)
	}
	if after.Missed-before.Missed != 1000 {
		t.Fatalf("%d of 1000 replays were counted as index misses", after.Missed-before.Missed)
	}
}

// TestRealCorruptedCopyDoesNotInvalidateTheGenuineOne, against real AEAD.
func TestRealCorruptedCopyDoesNotInvalidateTheGenuineOne(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	c := h.newClient(t, 1, 8)
	tbl := h.gw.Table()

	for i := range c.msgs {
		bad := append([]byte(nil), c.msgs[i]...)
		bad[len(bad)-1] ^= 0x01
		if _, _, err := tbl.Dispatch(bad, h.clock()); err == nil {
			t.Fatalf("a corrupted copy of message %d was accepted", i)
		}
	}
	for i, m := range c.msgs {
		if _, _, err := tbl.Dispatch(m, h.clock()); err != nil {
			t.Fatalf("genuine message %d was refused after a corrupted copy preceded it: %v", i, err)
		}
	}
}

// TestTheGatewayWindowIsTheBindingConstraint records the honest cost of the
// memory decision, against real sessions, rather than leaving it as a claim.
//
// core keeps its own private receive window — 1024 tokens by default — and the
// gateway keeps a smaller one. The gateway's is therefore what decides which
// packets survive reordering, and a message the gateway's window has slid past
// is dropped even though core would still have opened it. That is the price of
// the smaller window and it is paid in reordering tolerance, not in security.
//
// It is also the argument for the two-accessor seam in the handoff document:
// with it, core's window disappears and the gateway stops paying for a second
// copy of a structure only one of them is allowed to use.
func TestTheGatewayWindowIsTheBindingConstraint(t *testing.T) {
	cfg := silentCfg()
	cfg.InitialWindow = 16
	cfg.MaxWindow = 16
	h := newRealHarness(t, cfg)
	c := h.newClient(t, 1, 32)
	tbl := h.gw.Table()

	// A jump to counter 15 forces the gateway's 16-token window to [8,24).
	if _, _, err := tbl.Dispatch(c.msgs[15], h.clock()); err != nil {
		t.Fatalf("counter 15 did not route: %v", err)
	}
	if got := c.entry.Low(); got != 8 {
		t.Fatalf("the gateway window's low edge is %d, want 8", got)
	}

	// Counter 3 now falls outside the gateway's window and is dropped.
	if _, _, err := tbl.Dispatch(c.msgs[3], h.clock()); err == nil {
		t.Fatal("a counter below the gateway's window edge was routed")
	}

	// But core, whose window is 1024 wide and whose low edge is still 0, would
	// have opened exactly that message. This is the measurement that turns the
	// claim into a fact.
	if _, err := c.gwSess.Open(c.msgs[3]); err != nil {
		t.Fatalf("core refused a message the gateway's window is supposed to be the "+
			"only thing rejecting: %v", err)
	}
}

// TestFrontDoorCarriesBothMessageClasses. One carrier, one entry point, and no
// type byte on the wire to tell an initiation from a transport message: the
// gateway has to decide by trying, and it has to get both right.
func TestFrontDoorCarriesBothMessageClasses(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	c := h.newClient(t, 1, 8)

	for i, m := range c.msgs {
		res := h.gw.Handle(m, []byte("peer"), h.clock())
		if res.Kind != KindTransport {
			t.Fatalf("transport message %d was classified as %s", i, res.Kind)
		}
		if res.Reply != nil {
			t.Fatal("a transport message produced a reply")
		}
	}
	res := h.gw.Handle(h.initiation(t), []byte("peer"), h.clock())
	if res.Kind != KindHandshake || res.Reply == nil {
		t.Fatalf("an initiation arriving on the same carrier was classified as %s", res.Kind)
	}
	if got := h.gw.Table().Sessions(); got != 2 {
		t.Fatalf("%d sessions, want 2", got)
	}
}

// TestARealSessionSurvivesItsOwnRekey. core resets its window to counter zero
// under a new demux key when it ratchets; the table has to be told, and this is
// the sequence a session driver has to follow.
func TestARealSessionSurvivesItsOwnRekey(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	c := h.newClient(t, 1, 4)
	tbl := h.gw.Table()

	for _, m := range c.msgs {
		if _, _, err := tbl.Dispatch(m, h.clock()); err != nil {
			t.Fatalf("epoch-0 message did not route: %v", err)
		}
	}

	// Both ends ratchet on the same shared secret, at the same point in the
	// stream, which is the session driver's job.
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	if err := c.sess.Rekey(secret); err != nil {
		t.Fatalf("client rekey: %v", err)
	}
	if err := c.gwSess.Rekey(secret); err != nil {
		t.Fatalf("gateway rekey: %v", err)
	}
	if c.gwSess.Epoch() != 1 {
		t.Fatalf("core epoch is %d after a rekey, want 1", c.gwSess.Epoch())
	}

	// Harvest the new epoch's token sequence and re-base the table's window.
	next := newHarvestSource(4242)
	var fresh [][]byte
	for i := 0; i < 8; i++ {
		msg, err := c.sess.Seal([]byte{0xE1, byte(i)}, 0)
		if err != nil {
			t.Fatalf("Seal in the new epoch: %v", err)
		}
		next.record(uint64(i), msg)
		fresh = append(fresh, msg)
	}
	if err := c.entry.Rekeyed(next); err != nil {
		t.Fatalf("Rekeyed: %v", err)
	}

	for i, m := range fresh {
		ent, plain, err := tbl.Dispatch(m, h.clock())
		if err != nil {
			t.Fatalf("post-rekey message %d did not route: %v", i, err)
		}
		if ent != c.entry {
			t.Fatalf("post-rekey message %d routed to the wrong session", i)
		}
		if !bytes.Equal(plain, []byte{0xE1, byte(i)}) {
			t.Fatalf("post-rekey message %d opened as %x", i, plain)
		}
	}
	// An epoch-0 message must not route in epoch 1. It cannot: its token is not
	// in the new window and core would refuse it anyway.
	if _, _, err := tbl.Dispatch(c.msgs[0], h.clock()); err == nil {
		t.Fatal("an epoch-0 message routed after the ratchet")
	}
}

// TestTheTableHoldsNoSocketAndNoTimer. The core package pins the equivalent
// property for itself; this package inherits the discipline, because a timer
// here would be a timer nobody could make deterministic and a socket here would
// be a socket the carrier does not control.
// TestIntegrationRealSessionsWindowsArePrivateAcrossPeers is a multi-peer
// window assertion: three real sessions share one table, and each one's window
// state moves by its own traffic and nothing else.
//
// It is the negative of the obvious routing test: TestRealSessionsRoute... above
// proves that a datagram reaches the session that owns it; this one proves that
// a session's window does not move because a DIFFERENT session carried traffic.
// One peer's message lands out of order and force-advances its own low edge to
// 8; the in-order peer must remain at low 0 with nothing opened.
// TestIntegrationPeerWindowsGrowIndependentlyAcrossSessions is the growth
// counterpart of the privacy test above: two real sessions share one table,
// and memory is handed out against authenticated packets per session, never
// shared across the table. This is the answer to "can one peer's traffic buy
// another peer a bigger window" at the table layer — routing can be trusted,
// but growth is where an index bug could let a busy peer feed off a quiet one.
//
// It is the negative of TestGrowthIsBoughtWithAuthenticatedPackets (which is a
// single-session test): here a busy peer's window grows from its OWN 16-opens
// while a silent co-resident peer's window stays at 16, and the silent peer
// still routes its whole pre-sealed run afterwards without moving the busy
// peer's state at all.
func TestIntegrationPeerWindowsGrowIndependentlyAcrossSessions(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	tbl := h.gw.Table()

	// busy seals 24 real messages; silent seals only 8 and carries none until
	// the end. Both are real core sessions in the same table as the busy peer.
	busy := h.newClient(t, 1, 24)
	silent := h.newClient(t, 2, 8)

	// The silent session has done nothing yet: it holds its initial window,
	// with nothing opened and a low edge still at zero.
	if got := silent.entry.Opened(); got != 0 {
		t.Fatalf("silent peer opened %d messages before any of its own arrived", got)
	}
	if got := silent.entry.Window(); got != 16 {
		t.Fatalf("silent peer holds a %d-token window before carrying traffic, want 16", got)
	}
	if got := silent.entry.Low(); got != 0 {
		t.Fatalf("silent peer low edge is %d before carrying traffic, want 0", got)
	}
	if got := tbl.IndexedTokens(); got != 32 {
		t.Fatalf("two 16-token initial windows should reserve 32 tokens, got %d", got)
	}

	// The busy session earns its growth by its own traffic: 20 in-order opens
	// buy the first doubling (16 -> 32) exactly when the 16th opens.
	var priorInline uint64
	for i := 0; i < 20; i++ {
		ent, _, err := tbl.Dispatch(busy.msgs[i], h.clock())
		if err != nil {
			t.Fatalf("busy peer message %d did not route: %v", i, err)
		}
		if ent != busy.entry {
			t.Fatalf("busy peer message %d routed to another session", i)
		}
		priorInline = silent.entry.Opened()
		if priorInline != 0 {
			t.Fatalf("silent peer opened %d messages while another session carried traffic", priorInline)
		}
	}
	if got := busy.entry.Window(); got != 32 {
		t.Fatalf("busy peer window is %d after 20 opens of its own traffic, want 32", got)
	}
	if got := silent.entry.Window(); got != 16 {
		t.Fatalf("busy peer's growth moved the silent peer to a %d-token window, want 16", got)
	}

	// The silent peer's own full run still routes, each message advancing only
	// its own low edge, and the busy peer's window and open count stay put.
	for i, m := range silent.msgs {
		ent, _, err := tbl.Dispatch(m, h.clock())
		if err != nil {
			t.Fatalf("silent peer message %d did not route: %v", i, err)
		}
		if ent != silent.entry {
			t.Fatalf("silent peer message %d routed to another session", i)
		}
		if got := silent.entry.Opened(); got != uint64(i+1) {
			t.Fatalf("silent peer opened %d messages after %d deliveries", got, i+1)
		}
		if got := busy.entry.Window(); got != 32 {
			t.Fatalf("busy peer window moved to %d because of another session's traffic", got)
		}
		if got := busy.entry.Opened(); got != 20 {
			t.Fatalf("busy peer opened %d messages from another session's traffic, want 20", got)
		}
	}
	if got := silent.entry.Low(); got != uint64(len(silent.msgs)) {
		t.Fatalf("silent peer low edge is %d, want %d", got, len(silent.msgs))
	}
	// The silent peer has only 8 opens, below the 16 that would buy a doubling,
	// so it stays at 16 while the busy peer is at 32: 16+32 = 48 reserved.
	if got := tbl.IndexedTokens(); got != 48 {
		t.Fatalf("reserved capacity is %d, want a 32-token busy window plus a 16-token silent window", got)
	}
}

func TestIntegrationRealSessionsWindowsArePrivateAcrossPeers(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	tbl := h.gw.Table()

	// jump will receive counter 15 first; order receives every message in
	// sequence. Both are real core sessions over real tokens.
	jump := h.newClient(t, 1, 24)
	order := h.newClient(t, 2, 8)
	if jump.entry.ID() == order.entry.ID() {
		t.Fatal("two distinct registrations share one session id")
	}

	// Deliver the out-of-order message first. With a 16-token window the force
	// advance bounds reordering tolerance to size/2 - 1 = 7, so counter 15
	// slides the low edge to 15-8+1 = 8.
	ent, _, err := tbl.Dispatch(jump.msgs[15], h.clock())
	if err != nil {
		t.Fatalf("the out-of-order message did not route: %v", err)
	}
	if ent != jump.entry {
		t.Fatalf("the out-of-order message routed to the wrong session")
	}
	if got := jump.entry.Low(); got != 8 {
		t.Fatalf("jump peer window low edge is %d, want 8", got)
	}

	// The in-order peer must be untouched by the other session's traffic.
	if got := order.entry.Opened(); got != 0 {
		t.Fatalf("in-order peer opened %d messages before any of its own arrived", got)
	}
	if got := order.entry.Low(); got != 0 {
		t.Fatalf("in-order peer window moved to %d because of another session's traffic", got)
	}

	// Now deliver the in-order peer's full run. Each message advances its own
	// low edge by exactly one, and the jump peer's state must not move at all.
	for i, m := range order.msgs {
		e, _, err := tbl.Dispatch(m, h.clock())
		if err != nil {
			t.Fatalf("in-order peer message %d did not route: %v", i, err)
		}
		if e != order.entry {
			t.Fatalf("in-order peer message %d routed to the wrong session", i)
		}
		if got := order.entry.Opened(); got != uint64(i+1) {
			t.Fatalf("in-order peer opened %d messages after %d deliveries", got, i+1)
		}
	}
	if got := order.entry.Low(); got != uint64(len(order.msgs)) {
		t.Fatalf("in-order peer low edge is %d, want %d", got, len(order.msgs))
	}
	if got := jump.entry.Low(); got != 8 {
		t.Fatalf("jump peer's low edge moved to %d from another session's traffic", got)
	}
	if got := jump.entry.Opened(); got != 1 {
		t.Fatalf("jump peer opened %d messages, want 1", got)
	}
	if got := tbl.Stats().Dispatched; got != 9 {
		t.Fatalf("Dispatched is %d, want 9", got)
	}
	if got := tbl.Sessions(); got != 2 {
		t.Fatalf("%d sessions on the table, want 2", got)
	}
}

// TestIntegrationThreePeersEachEarnTheirOwnWindow is the three-peer
// arithmetic counterpart of the two-peer tests above: three real sessions
// share one table and each reaches a DIFFERENT window size, entirely from its
// own authenticated traffic. It is the answer to "can one peer's traffic buy
// another peer a window" taken three ways at once — if growth were pooled or if
// the index credited the wrong session, no single peer would land on exactly
// the size its own open count earns and the reserved-token bill would not be
// the plain sum of the three independently-earned windows.
func TestIntegrationThreePeersEachEarnTheirOwnWindow(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	tbl := h.gw.Table()

	// Each peer pre-seals its own run of real transport messages and routes
	// them interleaved across rounds, so no peer's arithmetic can ride on
	// arrival order: a runs the longest, b the shortest, c in between.
	a := h.newClient(t, 1, 70)
	b := h.newClient(t, 2, 12)
	c := h.newClient(t, 3, 20)
	if a.entry.ID() == b.entry.ID() || a.entry.ID() == c.entry.ID() || b.entry.ID() == c.entry.ID() {
		t.Fatal("three distinct registrations share a session id")
	}

	const (
		wantA = 64 // 16 -> 32 at the 16th open, 32 -> 64 at the 48th, then stops at 70
		wantB = 16 // never reaches 16 opens
		wantC = 32 // reaches the first doubling at 16 opens
	)

	for i := 0; i < len(a.msgs); i++ {
		if ent, _, err := tbl.Dispatch(a.msgs[i], h.clock()); err != nil {
			t.Fatalf("peer a message %d did not route: %v", i, err)
		} else if ent != a.entry {
			t.Fatalf("peer a message %d routed to another session", i)
		}
		if i < len(b.msgs) {
			if ent, _, err := tbl.Dispatch(b.msgs[i], h.clock()); err != nil {
				t.Fatalf("peer b message %d did not route: %v", i, err)
			} else if ent != b.entry {
				t.Fatalf("peer b message %d routed to another session", i)
			}
		}
		if i < len(c.msgs) {
			if ent, _, err := tbl.Dispatch(c.msgs[i], h.clock()); err != nil {
				t.Fatalf("peer c message %d did not route: %v", i, err)
			} else if ent != c.entry {
				t.Fatalf("peer c message %d routed to another session", i)
			}
		}
	}

	// Every peer landed on exactly the window its own open count earns, and no
	// peer's window, low edge or open count moved because of another's traffic.
	if got := a.entry.Window(); got != wantA {
		t.Fatalf("peer a window is %d after %d own opens, want %d", got, a.entry.Opened(), wantA)
	}
	if got := a.entry.Opened(); got != 70 {
		t.Fatalf("peer a opened %d messages, want 70", got)
	}
	if got := a.entry.Low(); got != 70 {
		t.Fatalf("peer a low edge is %d, want 70", got)
	}
	if got := b.entry.Window(); got != wantB {
		t.Fatalf("peer b window is %d after %d own opens, want %d", got, b.entry.Opened(), wantB)
	}
	if got := b.entry.Opened(); got != 12 {
		t.Fatalf("peer b opened %d messages, want 12", got)
	}
	if got := b.entry.Low(); got != 12 {
		t.Fatalf("peer b low edge is %d, want 12", got)
	}
	if got := c.entry.Window(); got != wantC {
		t.Fatalf("peer c window is %d after %d own opens, want %d", got, c.entry.Opened(), wantC)
	}
	if got := c.entry.Opened(); got != 20 {
		t.Fatalf("peer c opened %d messages, want 20", got)
	}
	if got := c.entry.Low(); got != 20 {
		t.Fatalf("peer c low edge is %d, want 20", got)
	}

	// The memory bill is the plain sum of the three independently-earned
	// windows: 64 + 16 + 32 = 112. If growth were shared, the bill would not be
	// per-session and the table would be reserving more than one session earned.
	if got := tbl.IndexedTokens(); got != wantA+wantB+wantC {
		t.Fatalf("three peers reserve %d tokens, want the sum %d of their separately-earned windows",
			got, wantA+wantB+wantC)
	}
	if got := tbl.Stats().Dispatched; got != 70+12+20 {
		t.Fatalf("Dispatched is %d, want %d", got, 70+12+20)
	}
	if got := tbl.Sessions(); got != 3 {
		t.Fatalf("%d sessions on the table, want 3", got)
	}
}

func TestTheTableHoldsNoSocketAndNoTimer(t *testing.T) {
	// Nothing in the package may reach for the clock on its own: every entry
	// point takes time as a parameter, and the one Config field that supplies a
	// clock is injected. This is asserted structurally in the source scan test
	// and behaviourally here: a table driven entirely with a frozen clock does
	// not evict, does not throttle differently and does not drift.
	cfg := silentCfg()
	cfg.IdleTimeout = time.Second
	tbl := testTable(t, cfg)
	_, f := registerFake(t, tbl, 1)

	for i := 0; i < 1000; i++ {
		deliver(t, tbl, f, uint64(i))
	}
	if n := tbl.EvictIdle(fixedNow); n != 0 {
		t.Fatalf("a frozen clock evicted %d sessions", n)
	}
	if n := tbl.EvictIdle(fixedNow.Add(2 * time.Second)); n != 1 {
		t.Fatalf("advancing the injected clock evicted %d sessions, want 1", n)
	}
	if core.TransportOverhead() != core.DemuxTokenSize+2+core.AEADTagSize {
		t.Fatal("the transport overhead this package gates on has changed shape")
	}
}
