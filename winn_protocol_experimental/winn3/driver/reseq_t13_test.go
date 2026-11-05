package driver

import (
	"encoding/binary"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

func TestT13ResequencerSparseGapClosesWithoutWaitingForTimer(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	if got := messages(r.resequence(slotsFor(f.add(0), f.add(4)), f, now)); !equal(got, []string{"m0"}) {
		t.Fatalf("setup output: %v", got)
	}
	if got := r.resequence(slotsFor(f.add(3)), f, now); len(got) != 0 {
		t.Fatalf("counter 3 passed the gap: %v", messages(got))
	}
	if got := messages(r.resequence(slotsFor(f.add(1)), f, now)); !equal(got, []string{"m1"}) {
		t.Fatalf("first hole output: %v", got)
	}
	got := messages(r.resequence(slotsFor(f.add(2)), f, now))
	if !equal(got, []string{"m2", "m3", "m4"}) || r.holds() {
		t.Fatalf("closed sparse gap: output=%v holds=%t next=%d", got, r.holds(), r.next)
	}
}

func TestT13ResequencerFillingAnExistingSpanDoesNotExceedMessageBound(t *testing.T) {
	var r resequencer
	r.configure(ReseqConfig{Enabled: true, HoldMessages: 3})
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	_ = r.resequence(slotsFor(f.add(0), f.add(4)), f, now)
	if got := r.resequence(slotsFor(f.add(3)), f, now); len(got) != 0 {
		t.Fatalf("filling a hole enlarged no span but flushed: %v", messages(got))
	}
	got := messages(r.resequence(slotsFor(f.add(1), f.add(2)), f, now))
	if !equal(got, []string{"m1", "m2", "m3", "m4"}) || r.holds() {
		t.Fatalf("bounded sparse gap: output=%v holds=%t", got, r.holds())
	}
}

func TestT13ResequencerSecondGapGetsItsOwnDeadline(t *testing.T) {
	r := enabledReseq()
	f := &fakeCounters{counters: map[string]uint64{}}
	now := time.Now()
	_ = r.resequence(slotsFor(f.add(0), f.add(2)), f, now)
	_ = r.resequence(slotsFor(f.add(1)), f, now.Add(time.Millisecond))
	if r.holds() {
		t.Fatal("first gap did not close")
	}
	later := now.Add(time.Second)
	got := messages(r.resequence(slotsFor(f.add(3), f.add(5)), f, later))
	if !equal(got, []string{"m3"}) || !r.holds() {
		t.Fatalf("new gap inherited the old deadline: output=%v holds=%t", got, r.holds())
	}
	if want := later.Add(ReseqHoldTime); !r.deadline().Equal(want) {
		t.Fatalf("new gap deadline=%v want=%v", r.deadline(), want)
	}
}

func TestT13ResequencerAllSixCounterPermutations(t *testing.T) {
	order := []uint64{1, 2, 3, 4, 5, 6}
	var visit func(int)
	visit = func(index int) {
		if index < len(order) {
			for i := index; i < len(order); i++ {
				order[index], order[i] = order[i], order[index]
				visit(index + 1)
				order[index], order[i] = order[i], order[index]
			}
			return
		}
		r := enabledReseq()
		f := &fakeCounters{counters: map[string]uint64{}}
		now := time.Now()
		got := messages(r.resequence(slotsFor(f.add(0)), f, now))
		for _, counter := range order {
			got = append(got, messages(r.resequence(slotsFor(f.add(counter)), f, now))...)
		}
		want := []string{"m0", "m1", "m2", "m3", "m4", "m5", "m6"}
		if !equal(got, want) || r.holds() {
			t.Fatalf("permutation %v: output=%v holds=%t next=%d", order, got, r.holds(), r.next)
		}
	}
	visit(0)
}

func TestT13ResequencerSparseGapWithAuthenticatedMessages(t *testing.T) {
	p := newSessionPair(t, nil)
	p.exchange()
	var wire [][]byte
	for i := byte(0); i < 5; i++ {
		if err := p.cli.Enqueue([]byte{i}); err != nil {
			t.Fatal(err)
		}
		batch := p.seal(p.cli)
		if len(batch) != 1 {
			t.Fatalf("message %d: got %d sealed messages, want 1", i, len(batch))
		}
		wire = append(wire, batch[0])
	}
	first, ok := p.gw.ReceiveCounter(wire[0])
	if !ok {
		t.Fatal("first sealed counter did not resolve")
	}
	r := enabledReseq()
	r.live, r.next, r.epoch = true, first, p.gw.ReceiveEpoch()
	before := p.gw.Stats()
	var got []byte
	for _, index := range []int{0, 4, 3, 1, 2} {
		for _, slot := range r.resequence(slotsFor(wire[index]), p.gw, p.clk.Now()) {
			inner, err := p.gw.Deliver(slot.Message)
			if err != nil {
				t.Fatal(err)
			}
			for _, packet := range inner {
				got = append(got, packet...)
			}
		}
	}
	if string(got) != string([]byte{0, 1, 2, 3, 4}) || r.holds() {
		t.Fatalf("authenticated delivery: packets=%v holds=%t", got, r.holds())
	}
	after := p.gw.Stats()
	if after.OuterReordered != before.OuterReordered || after.OuterLost != before.OuterLost {
		t.Fatalf("repaired delivery changed authenticated disorder/loss: before=(%d,%d) after=(%d,%d)",
			before.OuterReordered, before.OuterLost, after.OuterReordered, after.OuterLost)
	}
}

type t13BenchCounters struct{}

func (t13BenchCounters) ReceiveCounter(msg []byte) (uint64, bool) {
	return binary.BigEndian.Uint64(msg), true
}

func (t13BenchCounters) ReceiveEpoch() uint32 { return 0 }

func BenchmarkT13ResequenceInOrder(b *testing.B) {
	const count = 32
	slots := make([]session.ReceiveSlot, count)
	for i := range slots {
		slots[i].Message = make([]byte, 1402)
		binary.BigEndian.PutUint64(slots[i].Message, uint64(i))
	}
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
			var r resequencer
			r.configure(ReseqConfig{Enabled: enabled})
			now := time.Now()
			b.SetBytes(count * 1402)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.live, r.next = true, 0
				if got := r.resequence(slots, t13BenchCounters{}, now); len(got) != count {
					b.Fatalf("in-order batch returned %d slots", len(got))
				}
			}
		})
	}
}
