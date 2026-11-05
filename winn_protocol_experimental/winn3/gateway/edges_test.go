package gateway

import (
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestEntryAccessorsReportWhatTheOperatorNeeds. These are the numbers an
// operator and a session driver read; a counter nothing can read is a counter
// nobody maintains.
func TestEntryAccessorsReportWhatTheOperatorNeeds(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)

	if e.Opener() != Opener(f) {
		t.Fatal("Opener does not return the session that was registered")
	}
	if got := e.Opened(); got != 0 {
		t.Fatalf("a new entry reports %d opened messages", got)
	}
	if got := e.LastSeen(); !got.Equal(fixedNow) {
		t.Fatalf("LastSeen is %s at registration, want %s", got, fixedNow)
	}

	at := fixedNow.Add(90 * time.Second)
	if _, _, err := tbl.Dispatch(f.message(0), at); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := e.Opened(); got != 1 {
		t.Fatalf("Opened is %d after one message", got)
	}
	if got := e.LastSeen(); !got.Equal(at) {
		t.Fatalf("LastSeen is %s after a message at %s", got, at)
	}
	// A message that does not open must not move the clock: liveness is bought
	// with the session key and nothing else.
	f.reject[1] = true
	tbl.Dispatch(f.message(1), at.Add(time.Hour)) //nolint:errcheck
	if got := e.LastSeen(); !got.Equal(at) {
		t.Fatalf("a message that failed to open moved LastSeen to %s", got)
	}
}

// TestTheDefaultClockIsTheWallClock covers the one place this package is
// allowed to reach for time.Now: the injected clock's fallback.
func TestTheDefaultClockIsTheWallClock(t *testing.T) {
	var c Config
	before := time.Now()
	got := c.clock()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("the default clock returned %s, outside [%s, %s]", got, before, after)
	}
	fixed := Config{Now: func() time.Time { return fixedNow }}
	if !fixed.clock().Equal(fixedNow) {
		t.Fatal("an injected clock was ignored")
	}
}

// TestNewRefusesAnIncompleteGateway.
func TestNewRefusesAnIncompleteGateway(t *testing.T) {
	h := newRealHarness(t, silentCfg())

	if _, err := New(silentCfg(), testGatewayPathMTU, nil, h.binder()); !errors.Is(err, ErrConfig) {
		t.Fatalf("New with no responder returned %v", err)
	}
	if _, err := New(silentCfg(), testGatewayPathMTU, h.resp, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("New with no binder returned %v", err)
	}
	bad := silentCfg()
	bad.MaxWindow = core.MaxTokenWindow + 1
	if _, err := New(bad, testGatewayPathMTU, h.resp, h.binder()); !errors.Is(err, ErrConfig) {
		t.Fatalf("New with an impossible table config returned %v", err)
	}
}

// TestAnExplicitSourceCellCountIsHonoured, and rounded to a power of two so the
// mask index is valid.
func TestAnExplicitSourceCellCountIsHonoured(t *testing.T) {
	cfg := silentCfg()
	cfg.SourceCells = 100
	cfg.SourceRate = 1
	cfg.SourceBurst = 1
	h := newRealHarness(t, cfg)
	if got := len(h.gw.guard.cells); got != 128 {
		t.Fatalf("SourceCells=100 produced %d cells, want 128", got)
	}
	if got := cellsOf(0); got != DefaultSourceCells {
		t.Fatalf("cellsOf(0) is %d, want the default", got)
	}
	// A guard with no cells, or an unmetered one, must allow everything rather
	// than divide by zero.
	var none *sourceGuard
	if !none.allow([]byte("x"), fixedNow) {
		t.Fatal("a nil guard refused")
	}
	var nobucket *bucket
	if !nobucket.allow(fixedNow) {
		t.Fatal("a nil bucket refused")
	}
}

// TestAnOversizedDatagramIsDroppedBeforeTheAdmissionBudget. A datagram longer
// than any initiation can be must never spend a token from a budget that real
// clients are competing for.
func TestAnOversizedDatagramIsDroppedBeforeTheAdmissionBudget(t *testing.T) {
	cfg := silentCfg()
	cfg.AdmissionRate = 1
	cfg.AdmissionBurst = 1
	h := newRealHarness(t, cfg)

	huge := make([]byte, core.MaxHandshakeMessage+1)
	for i := 0; i < 100; i++ {
		mustBeSilent(t, h.gw.Handle(huge, []byte("peer"), h.clock()), "an oversized datagram")
	}
	if got := h.gw.Stats().Throttled; got != 0 {
		t.Fatalf("%d oversized datagrams reached the budget; the length gate must come first", got)
	}
	// The budget is untouched, so a real client still gets in.
	if res := h.gw.Handle(h.initiation(t), []byte("peer"), h.clock()); res.Kind != KindHandshake {
		t.Fatalf("a real client was starved by oversized noise: %s", res.Kind)
	}
}

// TestABinderThatReturnsNothingIsTreatedAsAFailure. A binder that reports no
// error but hands back nothing would otherwise register a nil opener and panic
// on the first datagram.
func TestABinderThatReturnsNothingIsTreatedAsAFailure(t *testing.T) {
	h := newRealHarness(t, silentCfg())
	empty := func(*core.Session) (Opener, TokenSource, error) { return nil, nil, nil }
	gw, err := New(silentCfg(), testGatewayPathMTU, h.resp, empty)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(gw.Table().Close)

	mustBeSilent(t, gw.Handle(h.initiation(t), []byte("peer"), h.clock()), "a binder that returned nothing")
	if got := gw.Table().Sessions(); got != 0 {
		t.Fatalf("%d sessions from a binder that produced nothing", got)
	}
}

// TestGrowthClampsToTheCeilingRatherThanOvershooting. A window that doubled
// past MaxWindow would reserve memory the operator did not agree to.
func TestGrowthClampsToTheCeilingRatherThanOvershooting(t *testing.T) {
	cfg := smallCfg()
	cfg.InitialWindow = 16
	cfg.MaxWindow = 24 // not a power of two, so the doubling must clamp
	tbl := testTable(t, cfg)
	e, f := registerFake(t, tbl, 1)

	for c := uint64(0); c < 64; c++ {
		deliver(t, tbl, f, c)
	}
	if got := e.Window(); got != 24 {
		t.Fatalf("window is %d, want it clamped to the 24-token ceiling", got)
	}
	if got := tbl.IndexedTokens(); got != 24 {
		t.Fatalf("reserved capacity is %d, want 24", got)
	}
}

// TestConsumingACounterOutsideTheWindowIsANoOp.
//
// Reached in production when a colliding candidate is stale: the index still
// names a counter the entry's window has already slid past. It must change
// nothing rather than corrupting the ring.
func TestConsumingACounterOutsideTheWindowIsANoOp(t *testing.T) {
	tbl := testTable(t, smallCfg())
	e, f := registerFake(t, tbl, 1)
	for c := uint64(0); c < 40; c++ {
		deliver(t, tbl, f, c)
	}
	low, window, entries := e.Low(), e.Window(), tbl.MapEntries()

	e.mu.Lock()
	e.consumeLocked(low - 1)              // below the low edge
	e.consumeLocked(low + uint64(window)) // above the high edge
	e.mu.Unlock()

	if e.Low() != low || e.Window() != window {
		t.Fatalf("an out-of-window consume moved the window from (%d,%d) to (%d,%d)",
			low, window, e.Low(), e.Window())
	}
	if got := tbl.MapEntries(); got != entries {
		t.Fatalf("an out-of-window consume changed the index from %d to %d entries", entries, got)
	}
	for c := low; c < low+uint64(window); c++ {
		if _, _, ok := tbl.Lookup(f.src.TokenAt(c)); !ok {
			t.Fatalf("counter %d was erased by an out-of-window consume", c)
		}
	}
}

// TestOwnersOfAnUnknownTokenIsEmpty.
func TestOwnersOfAnUnknownTokenIsEmpty(t *testing.T) {
	tbl := testTable(t, smallCfg())
	registerFake(t, tbl, 1)
	var tok Token
	copy(tok[:], []byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0})
	if got := tbl.Owners(tok); got != nil {
		t.Fatalf("Owners of an unindexed token returned %v", got)
	}
}

// TestRegisterOnAClosedTableAfterAnEviction covers the recheck that stops a
// registration completing into a table that was closed while it was evicting a
// victim to make room.
func TestRegisterOnAClosedTableAfterAnEviction(t *testing.T) {
	cfg := smallCfg()
	cfg.MaxSessions = 1
	tbl := testTable(t, cfg)
	registerFake(t, tbl, 1)

	// Close between the eviction and the completion is what the recheck is for;
	// serially, the closed table simply refuses.
	tbl.Close()
	f, src := newFake(2)
	if _, err := tbl.Register(f, src, clientKey(2), fixedNow); !errors.Is(err, ErrClosed) {
		t.Fatalf("Register on a closed table returned %v", err)
	}
}

// TestABucketRefillsButNeverPastItsBurst.
func TestABucketRefillsButNeverPastItsBurst(t *testing.T) {
	b := newBucket(10, 5)
	for i := 0; i < 5; i++ {
		if !b.allow(fixedNow) {
			t.Fatalf("token %d of a 5-token burst was refused", i)
		}
	}
	if b.allow(fixedNow) {
		t.Fatal("the sixth token of a 5-token burst was allowed")
	}
	// An hour later the bucket is full, not overflowing.
	later := fixedNow.Add(time.Hour)
	n := 0
	for b.allow(later) {
		n++
		if n > 100 {
			t.Fatal("the bucket refilled past its burst")
		}
	}
	if n != 5 {
		t.Fatalf("an hour of refill produced %d tokens, want the 5-token burst", n)
	}
}
