package core

import (
	"testing"
	"time"
)

// TestReplayWindowBoundaryRejectsOldNonceAcceptsCurrent pins both edges of the
// handshake replay window at nanosecond precision.
//
// The replay cache is what decides whether a captured initiation is still a
// replay by the time it is delivered again. The handshake body is the nonce:
// it carries a per-handshake ephemeral public key, so every genuine handshake
// hashes differently and a retransmission of the same body is the "old nonce".
// That decision has exactly one boundary in it — `seen` compares elapsed time
// against the lifetime with a strict `<` — and this test walks it:
//
//   - a body recorded at T is rejected again for every instant strictly inside
//     [T, T+lifetime), including T itself (the near edge) and T+lifetime−1ns;
//   - a body the cache has never seen is accepted at every one of those
//     instants, including the far edge;
//   - both verdicts at the same instant, so the test is asserting the cache
//     discriminates by body, not that "the cache returns false";
//   - at exactly T+lifetime the old nonce stops being flagged, which is the
//     instant the admission tag stops verifying, so the cache never forgets a
//     body the tag would still accept and never pins one the tag has released.
//
// This is deliberately a unit test of the replayWindow cache rather than a
// third re-run of TestReplayedInitiationRejected: the accept path itself is
// already proven there. What nothing else pins is the exact far edge — the
// existing expiry test checks +1h and so cannot see an off-by-one at +lifetime.
func TestReplayWindowBoundaryRejectsOldNonceAcceptsCurrent(t *testing.T) {
	lifetime := 30 * time.Second
	c := mustReplayCache(t, lifetime)
	base := fixedNow

	var old, current [32]byte
	old[0] = 0x01
	current[0] = 0x02

	// Record the old nonce's first (accepted) delivery at the window's start.
	if err := c.remember(old, base); err != nil {
		t.Fatal(err)
	}

	// Near edge. The cache's first call also primes its sweep timestamp to
	// `base` (the zero-Time gap is larger than the lifetime), so every call
	// below inside [base, base+lifetime] reaches the raw `seen` comparison
	// rather than a sweep deleting the entry first and deciding for it.
	if c.seen(current, base) {
		t.Fatal("a current nonce, never seen, is reported as a replay at the window start")
	}
	if !c.seen(old, base) {
		t.Fatal("an old nonce is not rejected at the instant it was recorded")
	}

	// Far edge, one nanosecond inside the window: the same instant yields two
	// opposite verdicts, which is the property that makes this a boundary test
	// rather than an emptiness check.
	edgeIn := base.Add(lifetime - time.Nanosecond)
	if c.seen(current, edgeIn) {
		t.Fatal("a current nonce is reported as a replay at the far edge, inside the window")
	}
	if !c.seen(old, edgeIn) {
		t.Fatal("the old nonce is no longer rejected one nanosecond before the window closes")
	}

	// At exactly the lifetime the window is closed: the same old nonce that was
	// rejected a nanosecond ago is released. Losing this strictness by one
	// comparison operator would hold the body in the cache one instant past the
	// admission window it exists to cover.
	if c.seen(old, base.Add(lifetime)) {
		t.Fatal("the old nonce is still flagged at exactly the lifetime; the replay " +
			"window has not closed at the instant the admission window lapses")
	}
}

// TestTokenWindowRejectsOldNoncesAcrossThePacketBoundary pins the transport
// anti-replay window to the instant the uint64 counter namespace wraps past its
// ceiling — "the packet boundary".
//
// A per-packet counter is the transport nonce: a session replays a packet
// exactly by delivering an already-consumed counter again, and the window is
// the filter that must reject it. This test runs the whole walk with the window
// parked within a window-width of the ceiling, so the wrap is exercised rather
// than assumed unreachable. The counter-only window is used because it own no
// token map: the anti-replay filter here is shared verbatim with the indexed
// window, and TestTheCounterOnlyWindowAgreesWithTheIndexedOne already proves
// the two decide identically.
//
// Before the fix, every in-window counter — including the low edge itself — was
// read as out of range: the literal `counter < low || counter >= low+size`
// overflowed `low+size` to a small value at the ceiling, and both comparisons
// rejected valid counters deterministically at exactly the boundary this test
// walks. The membership test is now the modular forward distance
// (counter − low) mod 2^64 in [0, size), which is wrap-safe by construction.
func TestTokenWindowRejectsOldNoncesAcrossThePacketBoundary(t *testing.T) {
	const size = 16
	w := newCounterWindow(size)
	const max = ^uint64(0)

	// Park the window straddling the ceiling: low = max−8 = 2^64−9, so the
	// 16-slot window covers {2^64−9 … 2^64−1, 0 … 6}.
	w.low = max - 8

	// At the wrap the filter's two duties must hold at the same instant:
	// an old nonce from the previous cycle (below the low edge) is rejected,
	// and a fresh in-window counter is accepted.
	for _, c := range []uint64{max - 10, max - 9} {
		if w.holds(c) {
			t.Fatalf("old nonce %d (below the wrapped low) is accepted as new", c)
		}
	}
	for _, c := range []uint64{max - 8, max - 1, 0, 1, 6} {
		if !w.holds(c) {
			t.Fatalf("in-window counter %d is rejected at the wrap", c)
		}
	}

	// Walk the low edge across the ceiling, consuming each counter exactly
	// once. Every re-delivery of a consumed counter is a replay and must be
	// rejected, both before and after the low edge wraps the namespace.
	seq := []uint64{
		max - 8, max - 7, max - 6, max - 5, max - 4, max - 3,
		max - 2, max - 1, max, 0, 1, 2, 3, 4, 5, 6,
	}
	for _, c := range seq {
		if !w.holds(c) {
			t.Fatalf("counter %d was not accepted on its first delivery", c)
		}
		w.consume(c)
		if w.holds(c) {
			t.Fatalf("replayed nonce %d was re-accepted after consume", c)
		}
	}

	// After the walk the low edge has wrapped to 7; the window now owns
	// {7 … 22}. The replay of the just-retired old nonce 6 fails, while the
	// freshly admitted high edge 22 is live and the next counter is not.
	if w.low != 7 {
		t.Fatalf("low edge is %d after the wrap, expected 7", w.low)
	}
	if w.holds(6) {
		t.Fatal("replayed nonce 6, retired just before the wrap, is re-accepted")
	}
	if !w.holds(7) || !w.holds(22) {
		t.Fatal("an in-window counter was lost as the window wrapped")
	}
	if w.holds(23) {
		t.Fatal("a counter past the wrapped high edge is admitted")
	}
}

// TestTokenWindowWrappedHighEdgeStillHasAToken proves the indexed window still
// maps a token for the counter admitted at the high edge when the low edge
// crosses the uint64 ceiling — the retireLow change. The old guard
// `next >= w.low` was there to dodge the overflow, but at the ceiling it
// silently dropped the very token the window needs: it admitted the counter
// `next` into the slots but refused to name it, so an indexed window would
// reject — not accept — the wrapped high edge after a slide.
func TestTokenWindowWrappedHighEdgeStillHasAToken(t *testing.T) {
	const size = 16
	var key [KeySize]byte
	w := newTokenWindow(&key, size)
	const max = ^uint64(0)

	// Park the indexed window at the ceiling and rebuild its token index to be
	// consistent with that low edge (the constructor builds it for low==0).
	w.low = max - 8
	w.tokens = make(map[[DemuxTokenSize]byte]uint64, size)
	for i := uint64(0); i < uint64(size); i++ {
		w.tokens[demuxToken(&key, w.low+i)] = w.low + i
	}

	// Slide low forward across the wrap by consuming each counter in turn,
	// from the parked low edge up through the last counter before the wrap.
	for c := w.low; ; c++ {
		w.consume(c)
		if c == 6 {
			break
		}
	}

	// The counter admitted at the high edge as the window crossed the ceiling
	// must resolve a token, so an indexed window can actually accept it.
	tok22 := demuxToken(&key, 22)
	if _, ok := w.lookup(tok22[:]); !ok {
		t.Fatalf("the wrapped high edge 22 has no token after the slide; low=%d", w.low)
	}
	if w.low != 7 {
		t.Fatalf("low edge is %d after the wrap, expected 7", w.low)
	}
}
