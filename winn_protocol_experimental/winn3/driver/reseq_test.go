package driver

import (
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// fakeCounters is a counterResolver over a counter->message map, for driving
// the resequencer without crypto. Message bytes are the counter's decimal
// text, so delivery order reads directly off the output.
type fakeCounters struct {
	counters map[string]uint64
	epoch    uint32
}

func (f *fakeCounters) ReceiveCounter(msg []byte) (uint64, bool) {
	c, ok := f.counters[string(msg)]
	return c, ok
}

func (f *fakeCounters) ReceiveEpoch() uint32 { return f.epoch }

func (f *fakeCounters) add(c uint64) []byte {
	msg := []byte(timeText(c))
	f.counters[string(msg)] = c
	return msg
}

func timeText(c uint64) string {
	if c == 0 {
		return "m0"
	}
	digits := []byte{}
	for c > 0 {
		digits = append([]byte{byte('0' + c%10)}, digits...)
		c /= 10
	}
	return "m" + string(digits)
}

func slotsFor(msgs ...[]byte) []session.ReceiveSlot {
	out := make([]session.ReceiveSlot, len(msgs))
	for i, m := range msgs {
		out[i] = session.ReceiveSlot{Message: m}
	}
	return out
}

func messages(slots []session.ReceiveSlot) []string {
	out := []string{}
	for _, s := range slots {
		out = append(out, string(s.Message))
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func enabledReseq() *resequencer {
	var r resequencer
	r.configure(ReseqConfig{Enabled: true})
	return &r
}

func TestResequencerDisabledReturnsFreshSlots(t *testing.T) {
	var r resequencer
	r.configure(ReseqConfig{})
	f := &fakeCounters{counters: map[string]uint64{}}
	slots := slotsFor(f.add(0), f.add(1))
	now := time.Now()
	got := r.resequence(slots, f, now)
	if len(got) != 2 || &got[0] != &slots[0] {
		t.Fatalf("disabled resequencer must return the caller's slots unchanged: %v", messages(got))
	}
}

func TestResequencerInOrderPathHoldsNothingAndAllocatesNothing(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	batch := slotsFor(f.add(0), f.add(1), f.add(2), f.add(3))
	got := r.resequence(batch, f, now)
	if !equal(messages(got), []string{"m0", "m1", "m2", "m3"}) {
		t.Fatalf("in-order delivery was reordered: %v", messages(got))
	}
	if r.holds() {
		t.Fatalf("in-order stream left %d messages held", len(r.ring))
	}
	// The fast path must not allocate: feed another in-order batch and count.
	f.add(4)
	batch2 := slotsFor([]byte("m4"))
	allocs := testing.AllocsPerRun(100, func() {
		got2 := r.resequence(batch2, f, now)
		if len(got2) != 1 || string(got2[0].Message) != "m4" {
			t.Fatalf("in-order single message was not passed through: %v", messages(got2))
		}
	})
	if allocs > 0.5 {
		t.Fatalf("in-order path allocated %.1f per message; the agreed bound is no copy or allocation", allocs)
	}
}

func TestResequencerHoldsAGapAndReleasesInCounterOrderWhenItCloses(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	// 0 passes, 2 and 3 are held (1 missing), then 1 arrives.
	got := r.resequence(slotsFor(f.add(0), f.add(2), f.add(3)), f, now)
	if !equal(messages(got), []string{"m0"}) {
		t.Fatalf("held messages leaked into delivery: %v", messages(got))
	}
	if !r.holds() || len(r.ring) != 2 {
		t.Fatalf("after holding 2 and 3 with 1 missing, ring len is %d", len(r.ring))
	}
	got = r.resequence(slotsFor(f.add(1)), f, now.Add(time.Millisecond))
	if !equal(messages(got), []string{"m1", "m2", "m3"}) {
		t.Fatalf("gap close did not release the run in counter order: %v", messages(got))
	}
	if r.holds() {
		t.Fatal("run released but ring not empty")
	}
}

func TestResequencerEnforcesTheTimeBound(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	t0 := time.Now()
	got := r.resequence(slotsFor(f.add(0), f.add(2)), f, t0)
	if !equal(messages(got), []string{"m0"}) {
		t.Fatalf("unexpected delivery: %v", messages(got))
	}
	if !r.holds() {
		t.Fatal("2 should be held")
	}
	if exp := t0.Add(ReseqHoldTime); !r.deadline().Equal(exp) {
		t.Fatalf("deadline is %v, want %v", r.deadline(), exp)
	}
	rel := r.releaseExpired(t0.Add(ReseqHoldTime - time.Microsecond))
	if rel != nil {
		t.Fatalf("release fired before the bound: %v", messages(rel))
	}
	rel = r.releaseExpired(t0.Add(ReseqHoldTime))
	if rel == nil || !equal(messages(rel), []string{"m2"}) {
		t.Fatalf("time bound did not release the hold: %v", rel)
	}
	if r.holds() {
		t.Fatal("hold survived its release")
	}
}

func TestResequencerEnforcesTheMessageBound(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	// 0 passes; then hold exactly ReseqHoldMessages messages (2..129, 1
	// missing): the bound allows holding this many and no more.
	var msgs [][]byte
	msgs = append(msgs, f.add(0))
	for c := uint64(2); c <= uint64(1+ReseqHoldMessages); c++ {
		msgs = append(msgs, f.add(c))
	}
	got := r.resequence(slotsFor(msgs...), f, now)
	if !equal(messages(got), []string{"m0"}) {
		t.Fatalf("at the bound, held messages leaked inline: %v", messages(got))
	}
	if !r.holds() || len(r.ring) != ReseqHoldMessages {
		t.Fatalf("the bound must allow exactly %d held, ring holds %d", ReseqHoldMessages, len(r.ring))
	}
	// One more message beyond the bound: everything held releases in
	// counter order and the newcomer delivers after them.
	got = r.resequence(slotsFor(f.add(uint64(1 + ReseqHoldMessages + 1))), f, now)
	want := []string{"m2"}
	for c := 3; c <= 1+ReseqHoldMessages+1; c++ {
		want = append(want, "m"+itoa(c))
	}
	if !equal(messages(got), want) {
		t.Fatalf("message bound did not release in counter order: %v want %v", messages(got), want)
	}
	if r.holds() {
		t.Fatal("holds survived the bound's release")
	}
}

func TestResequencerEnforcesTheByteBound(t *testing.T) {
	var r resequencer
	// A hold budget of 3 bytes: one 2-byte message holds, the second would
	// cross the byte bound and releases everything.
	r.configure(ReseqConfig{Enabled: true, HoldBytes: 3, HoldMessages: 128,
		HoldTime: time.Hour, HoldInner: 1024})
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	got := r.resequence(slotsFor(f.add(0), f.add(2)), f, now)
	if !equal(messages(got), []string{"m0"}) {
		t.Fatalf("unexpected: %v", messages(got))
	}
	if !r.holds() {
		t.Fatal("m2 (2 bytes) should have held under a 3-byte bound")
	}
	got = r.resequence(slotsFor(f.add(4)), f, now)
	if r.holds() {
		t.Fatalf("byte bound not enforced: %d bytes held", r.heldBytes)
	}
	if !equal(messages(got), []string{"m2", "m4"}) {
		t.Fatalf("byte-bound release must deliver the hold then the newcomer: %v", messages(got))
	}
}

func TestResequencerDeliversLateAuthenticatedMessagesNeverDrops(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	// 0, then 2 held, then the time bound releases it (frontier 3), then 1
	// arrives late for a passed frontier: delivered immediately.
	_ = r.resequence(slotsFor(f.add(0), f.add(2)), f, now)
	rel := r.releaseExpired(now.Add(ReseqHoldTime))
	if rel == nil || !equal(messages(rel), []string{"m2"}) {
		t.Fatalf("time bound release: %v", rel)
	}
	got := r.resequence(slotsFor(f.add(1)), f, now.Add(2*ReseqHoldTime))
	if !equal(messages(got), []string{"m1"}) {
		t.Fatalf("late authenticated message was dropped or held: %v", messages(got))
	}
}

func TestResequencerReleasesEverythingOnEpochChange(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	_ = r.resequence(slotsFor(f.add(0), f.add(2), f.add(3)), f, now)
	if !r.holds() {
		t.Fatal("expected holds")
	}
	f.epoch = 7
	fresh := slotsFor(f.add(0)) // new epoch restarts counters at 0
	got := r.resequence(fresh, f, now.Add(time.Millisecond))
	if !equal(messages(got), []string{"m2", "m3", "m0"}) {
		t.Fatalf("epoch change must release holds first, then the fresh message: %v", messages(got))
	}
	if r.holds() {
		t.Fatal("holds survived the epoch change")
	}
}

func TestResequencerPassesUnresolvableMessagesThroughInPlace(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	noise := []byte("noise")
	got := r.resequence(slotsFor(f.add(0), noise, f.add(1)), f, now)
	if !equal(messages(got), []string{"m0", "noise", "m1"}) {
		t.Fatalf("noise must ride in arrival order: %v", messages(got))
	}
}

func TestResequencerDuplicatesOfAHeldCounterDeliverInline(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	first := r.resequence(slotsFor(f.add(0), f.add(2)), f, now)
	if !equal(messages(first), []string{"m0"}) || !r.holds() {
		t.Fatalf("setup: %v holds=%v", messages(first), r.holds())
	}
	// A duplicate outer datagram of counter 2 while 2 is held.
	dup := r.resequence(slotsFor([]byte("m2")), f, now.Add(time.Millisecond))
	if !equal(messages(dup), []string{"m2"}) {
		t.Fatalf("duplicate was swallowed: %v", messages(dup))
	}
	if !r.holds() {
		t.Fatal("the held original must keep its place")
	}
}

// TestResequencerEpochChangeInitializesNewFrontierAndReordersFirstBatch. The
// first batch of a new epoch is resequenced under that epoch: it sets the new
// frontier, so a gap right after it is held, and an inversion inside it is
// repaired rather than passed through.
func TestResequencerEpochChangeInitializesNewFrontierAndReordersFirstBatch(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	_ = r.resequence(slotsFor(f.add(0), f.add(2), f.add(3)), f, now)
	if !r.holds() {
		t.Fatal("expected holds in epoch 0")
	}

	// Epoch 7 begins with counter 0 in batch 1, then counter 2 (ahead of the
	// missing counter 1) in batch 2. Batch 1 releases the old holds [m2 m3],
	// emits [m0] and sets the new frontier to 1, so batch 2 holds m2.
	f.epoch = 7
	got := r.resequence(slotsFor(f.add(0)), f, now.Add(time.Millisecond))
	if !equal(messages(got), []string{"m2", "m3", "m0"}) {
		t.Fatalf("epoch change batch 1: got %v, want [m2 m3 m0]", messages(got))
	}
	got2 := r.resequence(slotsFor(f.add(2)), f, now.Add(2*time.Millisecond))
	if len(got2) != 0 || !r.holds() {
		t.Fatalf("second batch in new epoch did not hold the gap after m0: got=%v holds=%v next=%d",
			messages(got2), r.holds(), r.next)
	}
	got3 := r.resequence(slotsFor(f.add(1)), f, now.Add(3*time.Millisecond))
	if !equal(messages(got3), []string{"m1", "m2"}) || r.holds() {
		t.Fatalf("closing the gap in the new epoch: got=%v holds=%v", messages(got3), r.holds())
	}

	// Epoch 8 starts with an out-of-order first batch [m0 m2].
	f.epoch = 8
	got4 := r.resequence(slotsFor(f.add(0), f.add(2)), f, now.Add(4*time.Millisecond))
	if !equal(messages(got4), []string{"m0"}) || !r.holds() {
		t.Fatalf("first batch of a new epoch did not hold m2: got=%v holds=%v", messages(got4), r.holds())
	}
}
