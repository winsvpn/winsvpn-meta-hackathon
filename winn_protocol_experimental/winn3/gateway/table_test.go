package gateway

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestConfigRefusesWhatCannotWork. A gateway that half-works at three in the
// morning is worse than one that refuses to start.
func TestConfigRefusesWhatCannotWork(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"initial below minimum", Config{InitialWindow: 16, MinWindow: 32, MaxWindow: 64}},
		{"max below initial", Config{InitialWindow: 64, MaxWindow: 32}},
		{"min below core floor", Config{MinWindow: 4, InitialWindow: 4, MaxWindow: 64}},
		{"max above core ceiling", Config{MaxWindow: core.MaxTokenWindow + 1}},
		{"no sessions", Config{MaxSessions: -1}},
		{"no sessions per client", Config{MaxSessionsPerClient: -1}},
		{"budget below one window", Config{TokenBudget: 1}},
		{"negative idle timeout", Config{IdleTimeout: -time.Second}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewTable(c.cfg); !errors.Is(err, ErrConfig) {
				t.Fatalf("NewTable accepted %+v (err=%v)", c.cfg, err)
			}
		})
	}
	if _, err := NewTable(Config{}); err != nil {
		t.Fatalf("the zero Config must be a working default: %v", err)
	}
}

// TestDefaultsAreTheDocumentedOnes pins the memory decision itself. These four
// numbers are the gateway's bill; if one of them moves, the arithmetic in the
// handoff document is wrong and this test says so.
func TestDefaultsAreTheDocumentedOnes(t *testing.T) {
	var c Config
	if c.initialWindow() != 32 || c.maxWindow() != 256 || c.minWindow() != 16 {
		t.Fatalf("window defaults are %d/%d/%d, the document says 32/256/16",
			c.initialWindow(), c.maxWindow(), c.minWindow())
	}
	if c.maxSessions() != 10000 || c.maxPerClient() != 4 {
		t.Fatalf("session defaults are %d/%d, the document says 10000/4", c.maxSessions(), c.maxPerClient())
	}
	if c.tokenBudget() != 10000*256 {
		t.Fatalf("default budget is %d, want MaxSessions*MaxWindow", c.tokenBudget())
	}
	if c.shards() != 64 {
		t.Fatalf("default shard count is %d, want 64", c.shards())
	}
	// The shard count is rounded up to a power of two and capped at 256,
	// because a token has 256 possible leading bytes and the index does no
	// hashing.
	if got := (Config{Shards: 100}).shards(); got != 128 {
		t.Fatalf("Shards=100 resolved to %d, want 128", got)
	}
	if got := (Config{Shards: 4096}).shards(); got != 256 {
		t.Fatalf("Shards=4096 resolved to %d, want the 256 cap", got)
	}
}

// TestDispatchRoutesAcrossManySessions is the whole point of the package: one
// gateway, many clients, and an eight-byte PRF output picking the right one.
func TestDispatchRoutesAcrossManySessions(t *testing.T) {
	const sessions = 400
	cfg := smallCfg()
	cfg.MaxSessions = sessions
	tbl := testTable(t, cfg)

	ents := make([]*Entry, sessions)
	fakes := make([]*fakeSession, sessions)
	for i := 0; i < sessions; i++ {
		ents[i], fakes[i] = registerFake(t, tbl, i)
	}
	if got := tbl.MapEntries(); got != sessions*16 {
		t.Fatalf("index holds %d tokens for %d sessions of 16, want %d", got, sessions, sessions*16)
	}

	// Interleave, so that no session ever sees a contiguous run and a table
	// that quietly routed by arrival order would be caught.
	for c := uint64(0); c < 12; c++ {
		for i := 0; i < sessions; i++ {
			ent, _, err := tbl.Dispatch(fakes[i].message(c), fixedNow)
			if err != nil {
				t.Fatalf("session %d counter %d did not route: %v", i, c, err)
			}
			if ent != ents[i] {
				t.Fatalf("session %d counter %d was routed to session %d", i, c, ent.ID())
			}
		}
	}
	// Every session's cryptography was called exactly once per message: the
	// index found the right owner first time, it did not try candidates.
	for i, f := range fakes {
		if got := f.openCalls(); got != 12 {
			t.Fatalf("session %d's Open was called %d times for 12 messages", i, got)
		}
	}
}

// TestPerClientCapStopsOneSubscriberTakingTheTable.
func TestPerClientCapStopsOneSubscriberTakingTheTable(t *testing.T) {
	cfg := smallCfg()
	cfg.MaxSessionsPerClient = 3
	tbl := testTable(t, cfg)

	same := clientKey(7)
	for i := 0; i < 3; i++ {
		f, src := newFake(i)
		if _, err := tbl.Register(f, src, same, fixedNow); err != nil {
			t.Fatalf("session %d for one client should be allowed: %v", i, err)
		}
	}
	f, src := newFake(99)
	if _, err := tbl.Register(f, src, same, fixedNow); !errors.Is(err, ErrCapacity) {
		t.Fatalf("the fourth session for one client returned %v, want ErrCapacity", err)
	}
	// A different subscriber is unaffected: the cap is per client, not global.
	if _, err := tbl.Register(f, src, clientKey(8), fixedNow); err != nil {
		t.Fatalf("a different client was refused: %v", err)
	}
	if got := tbl.Stats().Refused; got != 1 {
		t.Fatalf("Refused is %d, want 1", got)
	}
}

// TestFullTableEvictsTheIdlestRatherThanRefusingTheNewcomer.
//
// This is a values decision as much as an engineering one and it is worth
// naming: the client that cannot connect is a person, and an abandoned session
// holding their slot is not a reason to turn them away.
func TestFullTableEvictsTheIdlestRatherThanRefusingTheNewcomer(t *testing.T) {
	cfg := smallCfg()
	cfg.MaxSessions = 3
	tbl := testTable(t, cfg)

	var ents []*Entry
	for i := 0; i < 3; i++ {
		f, src := newFake(i)
		e, err := tbl.Register(f, src, clientKey(i), fixedNow.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("Register(%d): %v", i, err)
		}
		ents = append(ents, e)
	}
	f, src := newFake(9)
	e, err := tbl.Register(f, src, clientKey(9), fixedNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("a full table refused a newcomer instead of evicting: %v", err)
	}
	if !ents[0].Closed() {
		t.Fatal("the idlest session was not the one evicted")
	}
	if ents[1].Closed() || ents[2].Closed() {
		t.Fatal("a session that was not the idlest was evicted")
	}
	if tbl.Sessions() != 3 {
		t.Fatalf("%d sessions after an eviction and an admission, want 3", tbl.Sessions())
	}
	if got := tbl.IndexedTokens(); got != 3*16 {
		t.Fatalf("reserved capacity is %d after an eviction, want 48", got)
	}
	_ = e

	// With eviction disabled the table refuses instead, and says so.
	cfg.DisableEvictOnAdmit = true
	tbl2 := testTable(t, cfg)
	for i := 0; i < 3; i++ {
		f, src := newFake(i)
		if _, err := tbl2.Register(f, src, clientKey(i), fixedNow); err != nil {
			t.Fatalf("Register(%d): %v", i, err)
		}
	}
	f2, src2 := newFake(9)
	if _, err := tbl2.Register(f2, src2, clientKey(9), fixedNow); !errors.Is(err, ErrCapacity) {
		t.Fatalf("with eviction disabled a full table returned %v, want ErrCapacity", err)
	}
}

// TestFullTableWithSpentBudgetStaysAdmissibleWhenEvictionIsOn. The front
// door's pre-check must agree with Register: a full table whose sessions hold
// the whole token budget still admits by evicting the idlest, so admissible
// must not refuse on the pre-eviction token count.
func TestFullTableWithSpentBudgetStaysAdmissibleWhenEvictionIsOn(t *testing.T) {
	cfg := smallCfg()
	cfg.MaxSessions = 2
	cfg.MaxWindow = cfg.InitialWindow // budget = 2 initial windows, spent by 2 sessions
	tbl := testTable(t, cfg)
	for i := 0; i < 2; i++ {
		registerFake(t, tbl, i)
	}
	if got, want := tbl.IndexedTokens(), 2*cfg.InitialWindow; got != want {
		t.Fatalf("IndexedTokens = %d, want %d (budget spent)", got, want)
	}
	if !tbl.admissible(clientKey(9)) {
		t.Fatal("a full table with eviction on reports no room, so Gateway.Handle refuses a client Register would admit")
	}
	f, src := newFake(9)
	if _, err := tbl.Register(f, src, clientKey(9), fixedNow.Add(time.Second)); err != nil {
		t.Fatalf("Register on a full table with eviction on: %v", err)
	}

	cfg.DisableEvictOnAdmit = true
	tbl2 := testTable(t, cfg)
	for i := 0; i < 2; i++ {
		registerFake(t, tbl2, i)
	}
	if tbl2.admissible(clientKey(9)) {
		t.Fatal("with eviction disabled a full table reports itself admissible")
	}
}

// TestEvictIdleReclaimsOnlyTheSilent, and — the part that matters — a session
// stays alive only by producing messages that authenticate. An attacker cannot
// keep a session resident by sending it noise, because noise never reaches the
// clock.
func TestEvictIdleReclaimsOnlyTheSilent(t *testing.T) {
	cfg := smallCfg()
	cfg.IdleTimeout = time.Minute
	tbl := testTable(t, cfg)

	quiet, quietF := registerFake(t, tbl, 1)
	busy, busyF := registerFake(t, tbl, 2)

	later := fixedNow.Add(30 * time.Second)
	if _, _, err := tbl.Dispatch(busyF.message(0), later); err != nil {
		t.Fatalf("the busy session did not route: %v", err)
	}
	// Noise aimed at the quiet session: a token it does not own, and a
	// corrupted copy of one it does.
	noise := quietF.message(0)
	noise[len(noise)-1] ^= 0xFF
	for i := 0; i < 100; i++ {
		if _, _, err := tbl.Dispatch(noise, later); err == nil {
			t.Fatal("corrupted noise was delivered")
		}
	}

	// The sweep is one second past a sixty-second timeout, and that margin is
	// deliberate HERE: this test's subject is whether noise renews a lease, so
	// the quiet session must be unambiguously idle however the sweep compares.
	// It is not this test's job to hold the boundary and it must not be
	// tightened to sixty seconds as a way of testing it — that instant is
	// owned, from both sides and one tick either way, by
	// TestASessionIsIdleTheInstantItHasBeenSilentForTheWholeTimeout in
	// idleboundary_test.go.
	if n := tbl.EvictIdle(fixedNow.Add(61 * time.Second)); n != 1 {
		t.Fatalf("EvictIdle took %d sessions, want 1", n)
	}
	if !quiet.Closed() {
		t.Fatal("the silent session survived; noise must not renew a session's lease")
	}
	if busy.Closed() {
		t.Fatal("the session that opened a message was evicted")
	}
	if got := tbl.IndexedTokens(); got != 16 {
		t.Fatalf("reserved capacity is %d after one of two sessions was evicted, want 16", got)
	}
	if n := tbl.EvictIdle(fixedNow.Add(61 * time.Second)); n != 0 {
		t.Fatalf("a second sweep took %d more sessions", n)
	}
}

// TestClosedTableIsInert.
func TestClosedTableIsInert(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)
	tbl.Close()

	if !e.Closed() {
		t.Fatal("Close left a session live")
	}
	if got := tbl.MapEntries(); got != 0 {
		t.Fatalf("%d tokens survived Close", got)
	}
	if deliver(t, tbl, f, 0) {
		t.Fatal("a closed table still routes")
	}
	f2, src2 := newFake(2)
	if _, err := tbl.Register(f2, src2, clientKey(2), fixedNow); !errors.Is(err, ErrClosed) {
		t.Fatalf("Register on a closed table returned %v, want ErrClosed", err)
	}
	if tbl.admissible(clientKey(2)) {
		t.Fatal("a closed table reports itself admissible")
	}
	tbl.Close() // idempotent
}

// TestRegisterRejectsNonsense.
func TestRegisterRejectsNonsense(t *testing.T) {
	tbl := testTable(t, smallCfg())
	f, src := newFake(1)
	if _, err := tbl.Register(nil, src, clientKey(1), fixedNow); !errors.Is(err, ErrConfig) {
		t.Fatalf("Register(nil opener) returned %v", err)
	}
	if _, err := tbl.Register(f, nil, clientKey(1), fixedNow); !errors.Is(err, ErrConfig) {
		t.Fatalf("Register(nil source) returned %v", err)
	}
}

// TestBudgetRefusesRegistrationBeforeItRefusesGrowth. When even an initial
// window will not fit, the table says no — silently, from the front door's
// point of view — rather than overcommitting.
func TestBudgetRefusesRegistrationBeforeItRefusesGrowth(t *testing.T) {
	cfg := smallCfg()
	cfg.TokenBudget = 40 // two initial windows, no room for a third
	tbl := testTable(t, cfg)

	for i := 0; i < 2; i++ {
		registerFake(t, tbl, i)
	}
	if tbl.admissible(clientKey(3)) {
		t.Fatal("the table reports room for a session its budget cannot seat")
	}
	f, src := newFake(3)
	if _, err := tbl.Register(f, src, clientKey(3), fixedNow); !errors.Is(err, ErrCapacity) {
		t.Fatalf("Register past the budget returned %v, want ErrCapacity", err)
	}
	if got := tbl.Stats().BudgetHit; got == 0 {
		t.Fatal("BudgetHit was not incremented; memory pressure must be visible")
	}
}

// TestShortDatagramsAreRejectedBeforeAnyLookup. The cheapest possible rejection
// is a length compare, and it must come first: a flood of one-byte datagrams
// must not touch the index at all.
func TestShortDatagramsAreRejectedBeforeAnyLookup(t *testing.T) {
	tbl := testTable(t, smallCfg())
	registerFake(t, tbl, 1)

	for n := 0; n < core.TransportOverhead(); n++ {
		if _, _, err := tbl.Dispatch(make([]byte, n), fixedNow); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("a %d-byte datagram returned %v", n, err)
		}
	}
	s := tbl.Stats()
	if s.TooShort != uint64(core.TransportOverhead()) {
		t.Fatalf("TooShort is %d, want %d", s.TooShort, core.TransportOverhead())
	}
	if s.Missed != 0 {
		t.Fatalf("%d short datagrams reached the index; the length gate is not first", s.Missed)
	}
}

// TestStatsAccountForEveryDecision. A gateway whose degradation is invisible is
// a gateway whose degradation is a surprise.
func TestStatsAccountForEveryDecision(t *testing.T) {
	tbl := testTable(t, smallCfg())
	_, f := registerFake(t, tbl, 1)

	deliver(t, tbl, f, 0)       // dispatched
	deliver(t, tbl, f, 0)       // missed (replay)
	f.reject[1] = true          //
	deliver(t, tbl, f, 1)       // open failed
	tbl.Dispatch(nil, fixedNow) //nolint // too short

	s := tbl.Stats()
	if s.Dispatched != 1 || s.Missed != 1 || s.OpenFailed != 1 || s.TooShort != 1 {
		t.Fatalf("stats are %+v; want one of each of dispatched/missed/openfailed/tooshort", s)
	}
	if s.Sessions != 1 || s.IndexedTokens != 16 || s.TokenBudget != tbl.cfg.tokenBudget() {
		t.Fatalf("stats sizes are wrong: %+v", s)
	}
	if fmt.Sprint(KindDropped, KindTransport, KindHandshake) != "dropped transport handshake" {
		t.Fatalf("Kind strings drifted: %v %v %v", KindDropped, KindTransport, KindHandshake)
	}
}

// TestTableAttributesOnPathReplayFromTheGatewayAddressNotPromoted is the edge
// case where the replay is hardest to tell from a genuine datagram: a byte-for-
// byte copy whose token is still on the same path, as if the gateway's own
// address had fed the captured packet straight back.
//
// The table resolves by token alone, so it has nothing to distinguish "the
// gateway re-sent my packet" from "the gateway sent a new one" except the
// window. The token of an opened message is erased when it is consumed, so the
// copy must come back finding nothing: attributed as a Miss, never silently
// promoted into a second Dispatch, and -- the accounting edge -- never mis-
// classified as an AEAD OpenFailed either. A replay is not a corrupt datagram;
// it is a consumed one.
func TestTableAttributesOnPathReplayFromTheGatewayAddressNotPromoted(t *testing.T) {
	tbl := testTable(t, smallCfg())
	ent, f := registerFake(t, tbl, 1)

	replay := f.message(0) // the datagram an on-path observer captures
	got, plain, err := tbl.Dispatch(replay, fixedNow)
	if err != nil || got == nil || plain == nil {
		t.Fatalf("the genuine first arrival did not dispatch: got=%v plain=%v err=%v", got, plain, err)
	}
	if got != ent {
		t.Fatalf("the genuine arrival routed to session %d, want %d", got.ID(), ent.ID())
	}
	if s := tbl.Stats(); s.Dispatched != 1 || s.Missed != 0 {
		t.Fatalf("after the genuine arrival stats=%+v, want Dispatched=1 Missed=0", s)
	}

	// The on-path copy arrives a second time. It must be refused outright --
	// not promoted to a second delivery -- and attributed as a Miss.
	got2, plain2, err2 := tbl.Dispatch(replay, fixedNow)
	if err2 == nil {
		t.Fatal("the on-path replay was silently promoted to a successful dispatch")
	}
	if !errors.Is(err2, ErrNoRoute) {
		t.Fatalf("the on-path replay returned %v, want ErrNoRoute", err2)
	}
	if got2 != nil || plain2 != nil {
		t.Fatalf("the on-path replay returned entry=%v plain=%v, a promoted success", got2, plain2)
	}
	s := tbl.Stats()
	if s.Dispatched != 1 {
		t.Fatalf("a replay was counted as a Dispatch; stats=%+v", s)
	}
	if s.Missed != 1 {
		t.Fatalf("the on-path replay was not attributed as a Miss; stats=%+v", s)
	}
	if s.OpenFailed != 0 {
		t.Fatalf("a consumed-token replay is a Miss, not an OpenFailed; stats=%+v", s)
	}
}
