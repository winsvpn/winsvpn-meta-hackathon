package carrier

import (
	"context"
	"testing"
	"time"
	"unsafe"
)

// TUNNEL-SPEED-2 Turn 13: the inbox sojourn is the one figure that says what
// standing delay the uplink inbox DEPTH adds, as opposed to the radio, the
// phone's own queues and the path, none of which a loaded ping through the
// tunnel can separate (Bv, 2026-10-11: upload loaded p95 649 ms with the
// inbox high water at 3,463, against 170 to 202 ms in two runs whose high
// water was 6,071 and 7,176). It is scored from the admission time Deliver
// already reads for LastDelivered to the Recv or RecvBatch that takes the
// message out, so a queue nobody drains scores nothing.

func TestPipeInboxSojournIsScoredFromAdmissionToRead(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Clock: clock, Depth: 16})
	if err != nil {
		t.Fatalf("NewPipe: %v", err)
	}
	defer func() { _ = p.Close() }()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := p.Deliver(message(200, byte(i))); err != nil {
			t.Fatalf("deliver %d: %v", i, err)
		}
	}
	// Arrival alone scores nothing: the sojourn is a property of the read.
	if s := p.Stats(); s.InboxSojourn != [InboxSojournBuckets]uint64{} || s.InboxSojournMaxUS != 0 {
		t.Fatalf("sojourn moved before any read: %+v max %d", s.InboxSojourn, s.InboxSojournMaxUS)
	}

	clock.advance(5 * time.Millisecond)
	msgs := make([]BatchMsg, 8)
	for i := range msgs {
		msgs[i].Payload = make([]byte, 2048)
	}
	n, err := p.RecvBatch(ctx, msgs)
	if err != nil || n != 3 {
		t.Fatalf("RecvBatch = %d, %v; want 3, nil", n, err)
	}
	s := p.Stats()
	// 5 ms is 50 units of 100 us: 2^5 <= 50 < 2^6, bucket 5 ([3.2, 6.4) ms).
	var want [InboxSojournBuckets]uint64
	want[5] = 3
	if s.InboxSojourn != want {
		t.Fatalf("sojourn histogram after a 5 ms wait = %v, want %v", s.InboxSojourn, want)
	}
	if s.InboxSojournMaxUS != 5000 {
		t.Fatalf("InboxSojournMaxUS = %d, want 5000", s.InboxSojournMaxUS)
	}

	// A message read in the same instant it was admitted lands in bucket 0
	// and leaves the maximum where it was. The scalar Recv path scores too.
	if err := p.Deliver(message(200, 9)); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if _, err := p.Recv(ctx); err != nil {
		t.Fatalf("Recv: %v", err)
	}
	s = p.Stats()
	want[0] = 1
	if s.InboxSojourn != want {
		t.Fatalf("sojourn histogram after an immediate read = %v, want %v", s.InboxSojourn, want)
	}
	if s.InboxSojournMaxUS != 5000 {
		t.Fatalf("InboxSojournMaxUS moved to %d on a shorter wait", s.InboxSojournMaxUS)
	}

	// A longer wait raises the maximum and fills the last bucket.
	if err := p.Deliver(message(200, 10)); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	clock.advance(300 * time.Millisecond)
	if n, err := p.RecvBatch(ctx, msgs); err != nil || n != 1 {
		t.Fatalf("RecvBatch = %d, %v; want 1, nil", n, err)
	}
	s = p.Stats()
	want[InboxSojournBuckets-1] = 1
	if s.InboxSojourn != want {
		t.Fatalf("sojourn histogram after a 300 ms wait = %v, want %v", s.InboxSojourn, want)
	}
	if s.InboxSojournMaxUS != 300000 {
		t.Fatalf("InboxSojournMaxUS = %d, want 300000", s.InboxSojournMaxUS)
	}
}

func TestInboxSojournBucketEdges(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d    time.Duration
		want int
	}{
		{-time.Second, 0},
		{0, 0},
		{199 * time.Microsecond, 0},
		{200 * time.Microsecond, 1},
		{399 * time.Microsecond, 1},
		{400 * time.Microsecond, 2},
		{3200 * time.Microsecond, 5},
		{6399 * time.Microsecond, 5},
		{102400 * time.Microsecond, 10},
		{204799 * time.Microsecond, 10},
		{204800 * time.Microsecond, InboxSojournBuckets - 1},
		{time.Hour, InboxSojournBuckets - 1},
	}
	for _, c := range cases {
		if got := inboxSojournBucket(c.d); got != c.want {
			t.Errorf("inboxSojournBucket(%v) = %d, want %d", c.d, got, c.want)
		}
	}
}

// The gateway bills one PipeSlotBytes per inbox slot. The admission time
// doubled the slot from one pointer to two words; a third field here would
// move every session's bill and must show up in this pin.
func TestPipeSlotBytesIsTwoWords(t *testing.T) {
	t.Parallel()
	if word := int(unsafe.Sizeof(uintptr(0))); PipeSlotBytes != 2*word {
		t.Fatalf("PipeSlotBytes = %d, want %d (a slab pointer and an int64 admission time)", PipeSlotBytes, 2*word)
	}
}
