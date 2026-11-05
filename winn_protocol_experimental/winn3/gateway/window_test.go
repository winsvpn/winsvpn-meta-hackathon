package gateway

import (
	"errors"
	"testing"
	"time"
)

// deliver pushes one synthetic message for a counter through the table and
// reports whether it was routed and opened.
func deliver(t *testing.T, tbl *Table, f *fakeSession, counter uint64) bool {
	t.Helper()
	ent, plain, err := tbl.Dispatch(f.message(counter), fixedNow)
	if err != nil {
		if !errors.Is(err, ErrNoRoute) && !errors.Is(err, ErrSession) {
			t.Fatalf("Dispatch(counter=%d) returned %v, which is not a miss (ErrNoRoute) or an AEAD refusal (ErrSession)", counter, err)
		}
		return false
	}
	if ent == nil || plain == nil {
		t.Fatalf("Dispatch(counter=%d) succeeded with a nil entry or plaintext", counter)
	}
	return true
}

func smallCfg() Config {
	return Config{
		InitialWindow: 16,
		MaxWindow:     64,
		MinWindow:     16,
		MaxSessions:   64,
		Now:           func() time.Time { return fixedNow },
	}
}

// TestWindowPublishesExactlyTheInitialRun. A session that has proved nothing
// yet must hold InitialWindow tokens and not one more: this is the whole
// bounded-precomputation property, measured at the index rather than asserted
// in a comment.
func TestWindowPublishesExactlyTheInitialRun(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	if got := tbl.MapEntries(); got != 16 {
		t.Fatalf("index holds %d tokens, want exactly the 16-token initial window", got)
	}
	if got := tbl.IndexedTokens(); got != 16 {
		t.Fatalf("reserved capacity is %d, want 16", got)
	}
	if got := e.Window(); got != 16 {
		t.Fatalf("window is %d, want 16", got)
	}
	for c := uint64(0); c < 16; c++ {
		if _, ctr, ok := tbl.Lookup(f.src.TokenAt(c)); !ok || ctr != c {
			t.Fatalf("counter %d is not indexed", c)
		}
	}
	if _, _, ok := tbl.Lookup(f.src.TokenAt(16)); ok {
		t.Fatal("counter 16 is indexed, but it is one past the window")
	}
}

// TestInOrderDeliverySlidesTheWindow.
func TestInOrderDeliverySlidesTheWindow(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	for c := uint64(0); c < 6; c++ {
		if !deliver(t, tbl, f, c) {
			t.Fatalf("counter %d did not route", c)
		}
	}
	if got := e.Low(); got != 6 {
		t.Fatalf("low edge is %d after six in-order messages, want 6", got)
	}
	if got := tbl.MapEntries(); got != 16 {
		t.Fatalf("index holds %d tokens after sliding, want the window size 16", got)
	}
	// The window has moved, so its new high counters are now routable and its
	// old ones are not.
	if _, _, ok := tbl.Lookup(f.src.TokenAt(21)); !ok {
		t.Fatal("counter 21 should be indexed after the window slid to [6,22)")
	}
	if _, _, ok := tbl.Lookup(f.src.TokenAt(22)); ok {
		t.Fatal("counter 22 is past the high edge and must not be indexed")
	}
}

// TestOutOfOrderWithinTheWindowIsAccepted. Reordering tolerance is the thing
// the window is spending memory on; if it did not tolerate reordering there
// would be no reason to keep more than one token.
func TestOutOfOrderWithinTheWindowIsAccepted(t *testing.T) {
	tbl := testTable(t, smallCfg())
	_, f := registerFake(t, tbl, 1)

	for _, c := range []uint64{3, 1, 0, 2} {
		if !deliver(t, tbl, f, c) {
			t.Fatalf("counter %d did not route despite being inside the window", c)
		}
	}
}

// TestConsumedTokenIsGoneForever is the replay filter, and it is exact: there
// is no bitmap, the token is simply erased. A replayed transport message is
// therefore indistinguishable from noise, which is what stops a captured
// packet being a probe.
func TestConsumedTokenIsGoneForever(t *testing.T) {
	tbl := testTable(t, smallCfg())
	_, f := registerFake(t, tbl, 1)

	if !deliver(t, tbl, f, 2) {
		t.Fatal("first copy did not route")
	}
	before := f.openCalls()
	for i := 0; i < 5; i++ {
		if deliver(t, tbl, f, 2) {
			t.Fatal("a replayed message routed")
		}
	}
	if f.openCalls() != before {
		t.Fatalf("a replay reached the session's cryptography %d times; the index must absorb it",
			f.openCalls()-before)
	}
	if _, _, ok := tbl.Lookup(f.src.TokenAt(2)); ok {
		t.Fatal("the consumed token is still indexed")
	}
}

// TestOneLostPacketDoesNotPinTheWindow.
//
// Without the force-advance rule a single permanently lost datagram at the low
// edge would freeze the window and every later counter would be refused: one
// dropped packet would end the session. This is the test that would fail.
func TestOneLostPacketDoesNotPinTheWindow(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	// Counter 0 is lost forever. Everything after it must keep working, for
	// far more counters than the window is wide.
	for c := uint64(1); c < 200; c++ {
		if !deliver(t, tbl, f, c) {
			t.Fatalf("counter %d did not route; the window is pinned at low=%d", c, e.Low())
		}
	}
	if e.Low() == 0 {
		t.Fatal("the low edge never moved past the lost packet")
	}
}

// TestForceAdvanceBoundsReorderingToHalfAWindow pins the cost of the rule
// above, rather than pretending it is free: a message that arrives after the
// window has been forced past it is dropped, silently, like everything else.
func TestForceAdvanceBoundsReorderingToHalfAWindow(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	// Window is [0,16). A counter at 15 forces the low edge to 15-8+1 = 8.
	if !deliver(t, tbl, f, 15) {
		t.Fatal("counter 15 did not route")
	}
	if got := e.Low(); got != 8 {
		t.Fatalf("low edge is %d after a jump to 15 in a 16-token window, want 8", got)
	}
	if deliver(t, tbl, f, 7) {
		t.Fatal("counter 7 routed even though the window was forced past it")
	}
	if !deliver(t, tbl, f, 8) {
		t.Fatal("counter 8 is the new low edge and must still route")
	}
}

// TestAFailedOpenConsumesNothing.
//
// A corrupted or forged copy of a packet must not invalidate the genuine one
// that arrives after it. core holds this for its own window; the table has to
// hold it independently, because the table is what erases the token.
func TestAFailedOpenConsumesNothing(t *testing.T) {
	tbl := testTable(t, smallCfg())
	_, f := registerFake(t, tbl, 1)

	f.reject[3] = true
	if deliver(t, tbl, f, 3) {
		t.Fatal("a message the session refused was reported as delivered")
	}
	if _, _, ok := tbl.Lookup(f.src.TokenAt(3)); !ok {
		t.Fatal("a refused message consumed its token; the genuine packet can now never arrive")
	}
	delete(f.reject, 3)
	if !deliver(t, tbl, f, 3) {
		t.Fatal("the genuine packet did not route after a corrupted copy preceded it")
	}
	if got := tbl.Stats().OpenFailed; got != 1 {
		t.Fatalf("OpenFailed is %d, want 1", got)
	}
}

// TestGrowthIsBoughtWithAuthenticatedPackets.
//
// This is the answer to “can an attacker force unbounded precomputation” at the
// table layer. A window doubles only after the session has opened another
// window's worth of messages, each of which required the session key. A peer
// that opens a session and sends nothing holds the initial window and never
// more.
func TestGrowthIsBoughtWithAuthenticatedPackets(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	if got := e.Window(); got != 16 {
		t.Fatalf("a session that has proved nothing holds a %d-token window", got)
	}
	// Fifteen authenticated messages is not enough to earn the sixteenth token.
	for c := uint64(0); c < 15; c++ {
		deliver(t, tbl, f, c)
	}
	if got := e.Window(); got != 16 {
		t.Fatalf("window grew to %d after only 15 opens; growth must cost a full window", got)
	}
	deliver(t, tbl, f, 15)
	if got := e.Window(); got != 32 {
		t.Fatalf("window is %d after 16 opens, want 32", got)
	}
	for c := uint64(16); c < 48; c++ {
		deliver(t, tbl, f, c)
	}
	if got := e.Window(); got != 64 {
		t.Fatalf("window is %d after 48 opens, want the 64-token ceiling", got)
	}
	for c := uint64(48); c < 300; c++ {
		deliver(t, tbl, f, c)
	}
	if got := e.Window(); got != 64 {
		t.Fatalf("window grew past its ceiling to %d", got)
	}
	if got := tbl.IndexedTokens(); got != 64 {
		t.Fatalf("reserved capacity %d does not match the window %d", got, e.Window())
	}
	if got := tbl.MapEntries(); got != 64 {
		t.Fatalf("index holds %d tokens, want 64", got)
	}
}

// TestGrowthRemapsTheConsumedRing.
//
// Doubling the window changes the counter-to-slot mapping of the consumed ring,
// so the ring has to be rewritten rather than reallocated empty. If it were
// reallocated, a counter that had already been consumed would look unconsumed
// and the low edge would stall one short — which is exactly what this test
// measures, because a stalled low edge is visible and a lost bit is not.
func TestGrowthRemapsTheConsumedRing(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	// Fifteen in-order opens leave the window at [15,31) and one short of the
	// sixteenth open that buys the doubling.
	for c := uint64(0); c < 15; c++ {
		if !deliver(t, tbl, f, c) {
			t.Fatalf("counter %d did not route", c)
		}
	}
	if e.Low() != 15 || e.Window() != 16 {
		t.Fatalf("setup is wrong: low=%d window=%d, want 15 and 16", e.Low(), e.Window())
	}

	// The sixteenth open is counter 16, arriving before 15. It both triggers
	// the doubling AND is the consumed bit that has to survive it.
	if !deliver(t, tbl, f, 16) {
		t.Fatal("counter 16 did not route")
	}
	if e.Window() != 32 {
		t.Fatalf("window is %d after 16 opens, want 32", e.Window())
	}
	if e.Low() != 15 {
		t.Fatalf("low edge is %d; counter 15 is still outstanding so it must stay at 15", e.Low())
	}

	// Now the straggler arrives. A correctly remapped ring still remembers that
	// 16 was consumed, so the low edge retires 15 AND 16 and lands on 17. A ring
	// that lost the bit stops at 16.
	if !deliver(t, tbl, f, 15) {
		t.Fatal("the straggler at counter 15 did not route")
	}
	if got := e.Low(); got != 17 {
		t.Fatalf("low edge is %d after the straggler; a remapped ring retires through 16 and lands on 17", got)
	}
	for c := uint64(17); c < 120; c++ {
		if !deliver(t, tbl, f, c) {
			t.Fatalf("counter %d did not route after the ring was remapped", c)
		}
	}
}

// TestGrowthStopsAtTheTokenBudget is the memory-pressure decision, made
// visible: at the budget the windows stop growing and the sessions keep
// working. Nothing panics, nothing is evicted, and the degradation is a smaller
// reordering tolerance.
func TestGrowthStopsAtTheTokenBudget(t *testing.T) {
	cfg := smallCfg()
	cfg.TokenBudget = 40 // two 16-token initial windows plus eight spare
	tbl := testTable(t, cfg)

	e1, f1 := registerFake(t, tbl, 1)
	_, f2 := registerFake(t, tbl, 2)
	if got := tbl.IndexedTokens(); got != 32 {
		t.Fatalf("two initial windows should reserve 32 tokens, got %d", got)
	}

	for c := uint64(0); c < 64; c++ {
		deliver(t, tbl, f1, c)
	}
	if e1.Window() != 16 {
		t.Fatalf("window grew to %d despite the budget having only 8 spare tokens", e1.Window())
	}
	if tbl.Stats().BudgetHit == 0 {
		t.Fatal("a growth was declined but BudgetHit was never incremented; the operator cannot see the pressure")
	}
	// Both sessions still carry traffic. That is the point of the decision.
	for c := uint64(64); c < 128; c++ {
		if !deliver(t, tbl, f1, c) {
			t.Fatalf("session 1 stopped working at the budget, counter %d", c)
		}
		if !deliver(t, tbl, f2, c-64) {
			t.Fatalf("session 2 stopped working at the budget, counter %d", c-64)
		}
	}
	if got := tbl.IndexedTokens(); got > 40 {
		t.Fatalf("reserved capacity %d exceeded the budget 40", got)
	}
}

// TestRekeyedRebasesTheWindow. core resets its receive window to counter zero
// under a fresh demux key on every ratchet. If the table did not, every packet
// after a rekey would be dropped.
func TestRekeyedRebasesTheWindow(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	for c := uint64(0); c < 16; c++ {
		deliver(t, tbl, f, c)
	}
	oldSrc := f.src
	before := tbl.IndexedTokens()

	newSrc := NewKeyedSource(keyFor(99))
	if err := e.Rekeyed(newSrc); err != nil {
		t.Fatalf("Rekeyed: %v", err)
	}
	f.src = newSrc
	f.opened = map[uint64]bool{}

	if e.Low() != 0 {
		t.Fatalf("low edge is %d after a rekey, want 0", e.Low())
	}
	if e.Epoch() != 1 {
		t.Fatalf("epoch is %d after one rekey, want 1", e.Epoch())
	}
	if got := tbl.IndexedTokens(); got != before {
		t.Fatalf("reserved capacity changed across a rekey: %d then %d", before, got)
	}
	if _, _, ok := tbl.Lookup(oldSrc.TokenAt(20)); ok {
		t.Fatal("an old-epoch token is still indexed after a rekey")
	}
	for c := uint64(0); c < 24; c++ {
		if !deliver(t, tbl, f, c) {
			t.Fatalf("counter %d did not route in the new epoch", c)
		}
	}
	if got := tbl.MapEntries(); got != e.Window() {
		t.Fatalf("index holds %d tokens for a %d-token window after a rekey", got, e.Window())
	}
}

// TestRekeyedRejectsNonsense.
func TestRekeyedRejectsNonsense(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, _ := registerFake(t, tbl, 1)

	if err := e.Rekeyed(nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("Rekeyed(nil) returned %v, want ErrConfig", err)
	}
	tbl.Remove(e)
	if err := e.Rekeyed(NewKeyedSource(keyFor(3))); !errors.Is(err, ErrClosed) {
		t.Fatalf("Rekeyed on a retired entry returned %v, want ErrClosed", err)
	}
}

// TestRemoveReturnsEveryToken. A session that leaves must take its whole
// window with it, or the gateway leaks its memory bill one session at a time.
func TestRemoveReturnsEveryToken(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)
	for c := uint64(0); c < 32; c++ {
		deliver(t, tbl, f, c)
	}

	tbl.Remove(e)
	if got := tbl.MapEntries(); got != 0 {
		t.Fatalf("%d tokens survived the session that owned them", got)
	}
	if got := tbl.IndexedTokens(); got != 0 {
		t.Fatalf("reserved capacity is %d after the only session left", got)
	}
	if !e.Closed() {
		t.Fatal("the entry does not report itself closed")
	}
	if deliver(t, tbl, f, 40) {
		t.Fatal("a removed session still routes")
	}
	// Idempotent: eviction and an explicit Remove can race in a real gateway.
	tbl.Remove(e)
	tbl.Remove(nil)
	if got := tbl.IndexedTokens(); got != 0 {
		t.Fatalf("a second Remove double-released the budget: %d", got)
	}
}
