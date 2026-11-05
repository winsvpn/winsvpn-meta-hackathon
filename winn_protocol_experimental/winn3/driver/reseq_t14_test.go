package driver

import (
	"testing"
	"time"
)

// TUNNEL-SPEED-2 Turn 14, the fourth defect beside Sol's three: when the
// byte or inner-packet bound refuses a message that fills a hole INSIDE the
// held span, the bound path releases everything held (which advances the
// frontier past the highest held counter) and then sets the frontier to the
// refused message's counter plus one, which is lower. The frontier walks
// backwards over counters already delivered, so the next in-order message is
// taken for a gap and held until the time bound releases it: one 3 ms stall
// per such event, and outer_reordered counts the stall as an inversion.
func TestT14ResequencerBoundReleaseInsideTheSpanNeverMovesTheFrontierBack(t *testing.T) {
	var r resequencer
	// A hold budget of 5 bytes: two 2-byte messages hold (m4, m3), and the
	// third, m2, filling the hole in front of them, would cross it.
	r.configure(ReseqConfig{Enabled: true, HoldBytes: 5, HoldMessages: 128,
		HoldTime: time.Hour, HoldInner: 1024})
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	if got := messages(r.resequence(slotsFor(f.add(0), f.add(4)), f, now)); !equal(got, []string{"m0"}) {
		t.Fatalf("setup output: %v", got)
	}
	if got := r.resequence(slotsFor(f.add(3)), f, now); len(got) != 0 || r.heldBytes != 4 {
		t.Fatalf("m3 should hold beside m4 under a 5-byte bound: output=%v held=%d", messages(got), r.heldBytes)
	}
	// m2 crosses the bound: the holds go out in counter order, then m2, and
	// the frontier must stand at 5, past everything delivered, not at 3.
	got := messages(r.resequence(slotsFor(f.add(2)), f, now))
	if !equal(got, []string{"m3", "m4", "m2"}) || r.holds() {
		t.Fatalf("bound release inside the span: output=%v holds=%t", got, r.holds())
	}
	if r.next != 5 {
		t.Fatalf("frontier after the bound release is %d, want 5 (the counter after the highest delivered)", r.next)
	}
	// The late m1 is delivered at once (frontier already past it), and the
	// in-order m5 is delivered at once instead of being held for counters 3
	// and 4, which were already delivered.
	if got := messages(r.resequence(slotsFor(f.add(1)), f, now)); !equal(got, []string{"m1"}) {
		t.Fatalf("late m1: %v", got)
	}
	if got := messages(r.resequence(slotsFor(f.add(5)), f, now)); !equal(got, []string{"m5"}) || r.holds() {
		t.Fatalf("in-order m5 after the bound release: output=%v holds=%t next=%d", got, r.holds(), r.next)
	}
}

// The same release through the message bound (a newcomer beyond the ring)
// already moved the frontier forward; this pins that the repair keeps it so.
func TestT14ResequencerMessageBoundReleaseStillAdvancesTheFrontier(t *testing.T) {
	var r resequencer
	r.configure(ReseqConfig{Enabled: true, HoldMessages: 2})
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	_ = r.resequence(slotsFor(f.add(0), f.add(2)), f, now)
	got := messages(r.resequence(slotsFor(f.add(9)), f, now))
	if !equal(got, []string{"m2", "m9"}) || r.holds() || r.next != 10 {
		t.Fatalf("message-bound release: output=%v holds=%t next=%d", got, r.holds(), r.next)
	}
}
