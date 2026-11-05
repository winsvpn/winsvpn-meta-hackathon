package carrier

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// assertRetained verifies the NEGATIVE half of "delivered intact": a message a
// caller already received must still hold its bytes after the carrier has
// delivered later datagrams. A receive buffer that is aliased rather than
// copied would hand every Recv a view of the same backing array, so the FIRST
// message would silently turn into the LAST one the moment a later read landed —
// byte-identical to a reorder, and invisible to any test that checks a message
// the instant it arrives. Recv must therefore copy.
func assertRetained(t *testing.T, retained, want []byte, label string) {
	t.Helper()
	if len(retained) != len(want) {
		t.Fatalf("%s: retained %d bytes, want %d: a delivered message changed size after a later read",
			label, len(retained), len(want))
	}
	if !bytes.Equal(retained, want) {
		t.Fatalf("%s: a previously delivered message was overwritten by a later read; the carrier aliases its receive buffer",
			label)
	}
}

// TestSSPCarrierReorderingProbe is the standalone reordering guarantee of the
// datagram carrier, in carrier-netlab-independent isolation. It is deliberately
// NOT driven through the netlab rig: the property it nails down lives entirely
// in this package, and importing the rig to assert it would make the guarantee
// and its instrument share one failure surface.
//
// The carrier carries no sequence number (see udp.go's doc comment) and imposes
// no ordering. It is the session frame layer that must tolerate reordering, so
// the carrier's own contract is narrower and must be asserted independently:
// every datagram that arrives is delivered exactly once, intact, one per Recv,
// and in ARRIVAL order — never re-sorted into some numbering and never coalesced
// into or dropped from the stream. That arrival-order forwarding is the exact
// precondition netlab's reorder discipline stands on: the frame layer re-sorts
// into token order with its force-advance rule (winn3/core/replay.go), and it can
// only repair a displacement if the carrier handed every displaced datagram
// through intact and in the order it landed. Asserting the carrier forwards in
// socket order is therefore asserting that netlab's reorder repair is possible.
//
// That distinction has teeth because the two failure modes look identical to a
// user who is being censored. A gateway that re-sorts by an invented sequence,
// or that waits for a "next" packet already consumed by the frame layer, turns
// every genuinely-reordered datagram into a silently-lost one — and on this
// protocol a silently-lost datagram is indistinguishable from the state
// dropping the path. So the carrier must be order-agnostic: it hands each
// datagram through in the order the socket delivers it.
//
// The test writes a deliberately non-monotonic tag sequence (5,2,4,1,3,0) and
// asserts the read side returns the same arrival order. If the carrier imposed
// any numbering it would re-sort to 0..5 and this test would go red.
func TestSSPCarrierReorderingProbe(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		t.Parallel()
		a, b, _, _ := udpPair(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Arrival order is deliberately non-monotonic, simulating a stream the
		// session frame layer would have to reorder: tags 5 before 0, etc.
		arrival := []int{5, 2, 4, 1, 3, 0}
		for _, k := range arrival {
			if err := a.Send(ctx, message(120, byte(k))); err != nil {
				t.Fatalf("send tag %d: %v", k, err)
			}
		}

		var gotBytes int64
		var retained []byte
		for i, k := range arrival {
			got, err := b.Recv(ctx)
			if err != nil {
				t.Fatalf("recv %d (want tag %d): %v", i, k, err)
			}
			want := message(120, byte(k))
			if len(got) != len(want) {
				t.Fatalf("recv %d delivered %d bytes, want %d: a datagram was coalesced or truncated",
					i, len(got), len(want))
			}
			for j := range want {
				if got[j] != want[j] {
					t.Fatalf("recv %d byte %d is %#x, want %#x: the carrier reordered or corrupted the datagram",
						i, j, got[j], want[j])
				}
			}
			if i == 0 {
				retained = got
			}
			gotBytes += int64(len(got))
		}

		s := b.Stats()
		if s.Delivered != uint64(len(arrival)) {
			t.Fatalf("Delivered is %d, want %d: a datagram was dropped or coalesced", s.Delivered, len(arrival))
		}
		if s.DeliveredBytes != uint64(gotBytes) {
			t.Fatalf("DeliveredBytes is %d, want %d", s.DeliveredBytes, gotBytes)
		}
		if int64(s.DeliveredBytes) != int64(len(arrival))*120 {
			t.Fatalf("the carrier added or lost bytes: DeliveredBytes %d for %d messages of 120",
				s.DeliveredBytes, len(arrival))
		}
		if s.Foreign != 0 {
			t.Fatalf("Foreign is %d; the configured peer's own datagrams were filtered", s.Foreign)
		}
		assertRetained(t, retained, message(120, byte(arrival[0])), "explicit-peer probe")
	})
}

// TestSSPCarrierReorderingConnectedSocket is the same reordering guarantee on the
// other half of the carrier: the connected-socket path DialUDP produces, where
// the peer filter lives in the kernel rather than in userspace. It is likewise
// netlab-independent, on loopback, with no postural code involved.
//
// The two peer modes are not the same code path for this property. On the
// explicit-peer path Recv compares each source address itself and is where a
// userspace reorder-bug would live; on the connected path the socket was already
// told who it talks to, so a reorder-bug there would have to be a genuine mistake
// in the read loop rather than in the filter. Asserting the guarantee in both
// modes means an ordering defect cannot hide behind whichever mode a given test
// happened to drive.
//
// The client below is a connected carrier; the "gateway" is a raw loopback socket
// writing directly into that connected socket's local port. The read side must
// hand each datagram through in the order the socket delivered it — never
// re-sorted into a numbering, and never coalesced or dropped.
func TestSSPCarrierReorderingConnectedSocket(t *testing.T) {
	t.Parallel()
	gw := loopbackUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := DialUDP(ctx, UDPConfig{Remote: gw.LocalAddr().(*net.UDPAddr), Clock: newFakeClock()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Deliberately non-monotonic arrival order, the same sequence the explicit
	// peer test drives: tags 5 before 0, etc. On a connected socket the sender is
	// the kernel's peer, so every write is acceptable to the socket; the question
	// is only whether Recv reports the arrival order or invents a numbering.
	arrival := []int{5, 2, 4, 1, 3, 0}
	for _, k := range arrival {
		if _, err := gw.WriteToUDP(message(120, byte(k)), c.conn.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("gateway write tag %d: %v", k, err)
		}
	}

	var gotBytes int64
	var retained []byte
	for i, k := range arrival {
		got, err := c.Recv(ctx)
		if err != nil {
			t.Fatalf("recv %d (want tag %d): %v", i, k, err)
		}
		want := message(120, byte(k))
		if len(got) != len(want) {
			t.Fatalf("recv %d delivered %d bytes, want %d: a datagram was coalesced or truncated",
				i, len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("recv %d byte %d is %#x, want %#x: the carrier reordered or corrupted the datagram",
					i, j, got[j], want[j])
			}
		}
		if i == 0 {
			retained = got
		}
		gotBytes += int64(len(got))
	}

	s := c.Stats()
	if s.Delivered != uint64(len(arrival)) {
		t.Fatalf("Delivered is %d, want %d: a datagram was dropped or coalesced", s.Delivered, len(arrival))
	}
	if s.DeliveredBytes != uint64(gotBytes) {
		t.Fatalf("DeliveredBytes is %d, want %d", s.DeliveredBytes, gotBytes)
	}
	if int64(s.DeliveredBytes) != int64(len(arrival))*120 {
		t.Fatalf("the carrier added or lost bytes: DeliveredBytes %d for %d messages of 120",
			s.DeliveredBytes, len(arrival))
	}
	if s.Foreign != 0 {
		t.Fatalf("Foreign is %d on a connected socket; the kernel is the only filter and it was fed by the gateway",
			s.Foreign)
	}
	assertRetained(t, retained, message(120, byte(arrival[0])), "connected socket")
}

// TestSSPCarrierReorderBurstPipe drives the reordering guarantee through the
// queue-backed carrier, which is the exact seam a gateway's demultiplexer calls
// when a datagram arrives: the demultiplexer reads the socket into ONE buffer
// and calls Deliver once per message, so every delivery in a burst hands the
// same backing array with new contents. Deliver must copy, not alias: if it
// handed the caller's slice through, every queued message would silently become
// the last one written — byte-identical to a reorder, and invisible to any test
// that checks a message the instant it arrives, because the write side re-fills
// the same array between orders. This test delivers a full non-monotonic burst
// from one reused buffer and requires the read side to return each message
// distinct, intact, exactly once, and in the order Deliver was called.
//
// The mutation-check need this proves is live: replacing Deliver's
// make+copy with a plain alias must make this test go red, because with an
// alias all n queued messages point at the last tag written.
func TestSSPCarrierReorderBurstPipe(t *testing.T) {
	t.Parallel()
	a, b, err := NewPipePair(PipeConfig{Class: ClassUDP})
	if err != nil {
		t.Fatalf("pipe pair: %v", err)
	}
	defer func() { _ = a.Close(); _ = b.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A burst of 64 messages. (i*7)%64 is a full permutation of 0..63 with a
	// deliberately non-monotonic, bursty tag order — 6 before 1, 55 before 48 —
	// so the read side cannot recover the arrival sequence by walking a range.
	const n = 64
	arrival := make([]int, n)
	for i := range arrival {
		arrival[i] = (i * 7) % n
	}

	// Every delivery reuses one buffer, exactly as a demultiplexer that reads
	// the socket into a single array does. Each Send re-fills that array before
	// handing it to Deliver; if Deliver aliased the slice instead of copying,
	// all n queued messages would point at the LAST tag written.
	buf := make([]byte, 120)
	for _, k := range arrival {
		want := message(120, byte(k))
		copy(buf, want)
		if err := a.Send(ctx, buf); err != nil {
			t.Fatalf("send tag %d: %v", k, err)
		}
	}

	var gotBytes int64
	var retained []byte
	for i, k := range arrival {
		got, err := b.Recv(ctx)
		if err != nil {
			t.Fatalf("recv %d (want tag %d): %v", i, k, err)
		}
		want := message(120, byte(k))
		if len(got) != len(want) {
			t.Fatalf("recv %d delivered %d bytes, want %d: a datagram was coalesced or truncated",
				i, len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("recv %d byte %d is %#x, want %#x: the carrier reordered or corrupted the datagram",
					i, j, got[j], want[j])
			}
		}
		if i == 0 {
			retained = got
		}
		gotBytes += int64(len(got))
	}

	as := a.Stats()
	if as.Sent != uint64(len(arrival)) {
		t.Fatalf("Sent is %d, want %d", as.Sent, len(arrival))
	}
	if as.SentBytes != uint64(len(arrival)*120) {
		t.Fatalf("SentBytes is %d, want %d", as.SentBytes, len(arrival)*120)
	}
	s := b.Stats()
	if s.Delivered != uint64(len(arrival)) {
		t.Fatalf("Delivered is %d, want %d: a datagram was dropped or coalesced", s.Delivered, len(arrival))
	}
	if s.DeliveredBytes != uint64(gotBytes) {
		t.Fatalf("DeliveredBytes is %d, want %d", s.DeliveredBytes, gotBytes)
	}
	if int64(s.DeliveredBytes) != int64(len(arrival))*120 {
		t.Fatalf("the carrier added or lost bytes: DeliveredBytes %d for %d messages of 120",
			s.DeliveredBytes, len(arrival))
	}
	assertRetained(t, retained, message(120, byte(arrival[0])), "pipe burst")
}

// TestSSPCarrierReorderBurstLoss drives the arrival-order guarantee across a
// reordered burst WITH LOSS — the situation a real censored or congested path
// produces. The two earlier probes reorder every datagram but drop none: the
// stream is displaced, yet complete. A lossy path is a different failure shape,
// and it is the one that most plausibly tricks a carrier into an out-of-order
// drop: the gap (the lost burst) is indistinguishable, at the datagram layer,
// from a datagram that simply has not arrived yet. If a carrier gated a "next"
// counter, or waited on an expected antecedent before forwarding, the LOST
// datagrams' successors would arrive out of order, be mistaken for the missing
// ones' placeholders, and be dropped as duplicates or as "ahead of the window" —
// and the frame layer above (winn3/core/replay.go) cannot repair a displacement
// it is never handed, so a tolerated reorder becomes a silently lost message.
//
// The rig: 64 logical tags, a contiguous BURST of 16 lost (never sent at all),
// and the 48 survivors delivered to the socket in a deliberately non-monotonic
// order with the gap present. The carrier must hand through every one of the 48
// survivors intact, exactly once, one per Recv, in ARRIVAL order — and must
// report exactly 48 delivered. It must neither drop a survivor because it
// arrived out of order nor deliver anything that was never sent.
func TestSSPCarrierReorderBurstLoss(t *testing.T) {
	t.Parallel()
	a, b, _, _ := udpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const total = 64
	// A contiguous burst lost from the middle of the logical stream: tags
	// [24, 40). These are NEVER sent, so the read side sees a real gap, not a
	// packet that is merely slow.
	lost := make(map[int]bool, 16)
	for tag := 24; tag < 40; tag++ {
		lost[tag] = true
	}

	// (i*7)%64 is a full permutation of 0..63; skipping the lost tags leaves a
	// non-monotonic arrival order of the 48 survivors with the burst gap present.
	// 6 arrives before 1, 55 before 48 — the read side cannot recover order by
	// walking a range, and the missing burst occupies the tags the survivors wrap
	// around.
	arrival := make([]int, 0, total-16)
	for i := 0; i < total; i++ {
		tag := (i * 7) % total
		if lost[tag] {
			continue
		}
		arrival = append(arrival, tag)
	}
	if len(arrival) != 48 {
		t.Fatalf("setup: expected 48 survivors, got %d", len(arrival))
	}

	// Prove the arrival order is genuinely disordered: if it were sorted this
	// would not be a reorder test at all.
	disordered := false
	for i := 1; i < len(arrival); i++ {
		if arrival[i] < arrival[i-1] {
			disordered = true
			break
		}
	}
	if !disordered {
		t.Fatalf("setup: survivor arrival order is monotonic; this is not a reorder test")
	}

	for _, tag := range arrival {
		if err := a.Send(ctx, message(120, byte(tag))); err != nil {
			t.Fatalf("send tag %d: %v", tag, err)
		}
	}

	var gotBytes int64
	var retained []byte
	for i, tag := range arrival {
		got, err := b.Recv(ctx)
		if err != nil {
			t.Fatalf("recv %d (want survivor tag %d): %v", i, tag, err)
		}
		want := message(120, byte(tag))
		if len(got) != len(want) {
			t.Fatalf("recv %d delivered %d bytes, want %d: a datagram was coalesced or truncated",
				i, len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("recv %d byte %d is %#x, want %#x: the carrier reordered or corrupted the datagram",
					i, j, got[j], want[j])
			}
		}
		if i == 0 {
			retained = got
		}
		gotBytes += int64(len(got))
	}

	s := b.Stats()
	// The heart of the burst-loss property: EXACTLY the survivors are delivered,
	// in arrival order. A carrier that drops an out-of-order datagram loses a
	// survivor because of the gap and reports < 48; a carrier that coalesces or
	// invents reports something else.
	if s.Delivered != uint64(len(arrival)) {
		t.Fatalf("Delivered is %d, want %d: over a burst with loss, an out-of-order survivor was dropped (or one was invented)",
			s.Delivered, len(arrival))
	}
	if s.DeliveredBytes != uint64(gotBytes) {
		t.Fatalf("DeliveredBytes is %d, want %d", s.DeliveredBytes, gotBytes)
	}
	if int64(s.DeliveredBytes) != int64(len(arrival))*120 {
		t.Fatalf("the carrier added or lost bytes: DeliveredBytes %d for %d survivors of 120",
			s.DeliveredBytes, len(arrival))
	}
	if s.Foreign != 0 {
		t.Fatalf("Foreign is %d; the configured peer's own datagrams were filtered", s.Foreign)
	}
	assertRetained(t, retained, message(120, byte(arrival[0])), "burst-loss")
}
