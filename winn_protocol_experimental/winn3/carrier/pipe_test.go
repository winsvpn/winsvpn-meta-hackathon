package carrier

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// flowMsg builds a plausible 64-byte Winn3 message whose first eight bytes are
// the datagram's sequence number, big-endian. The flow extractor reads it back.
func flowMsg(seq uint64) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint64(b, seq)
	for i := 8; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}

func flowSeqOf(msg []byte) uint64 {
	return binary.BigEndian.Uint64(msg[:8])
}

// TestPipeFlowHandlingReorderAndLoss is the flow-handling branch of the
// queue-backed carrier. A gateway demultiplexer calls Deliver once per datagram
// in socket order; the datagrams of one session can arrive reordered and a
// single one can be lost in transit. The Pipe must not try to repair either —
// it has no key and reorder repair belongs to the token-window layer above it —
// but it MUST observe both and count them on arrival, so a policy layer can see
// the raw shape of the flow rather than a set of counters that hide a reorder
// or a gap. The negative half is just as load-bearing: because these counters
// move on Deliver and never on Recv, a slow reader cannot manufacture
// reordering or loss any more than it can manufacture a delivery.
func TestPipeFlowHandlingReorderAndLoss(t *testing.T) {
	t.Parallel()

	// A pipe whose extractor reads the sequence a gateway would have to re-sort
	// by. The datagrams are still forwarded intact and in arrival order.
	newFlowPipe := func(t *testing.T) *Pipe {
		t.Helper()
		p, err := NewPipe(PipeConfig{Class: ClassUDP, Seq: flowSeqOf})
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}

	// --- Reorder, no loss ------------------------------------------------
	// Arrival order is deliberately non-monotonic: 3 before 1 before 4 before 2.
	// The Pipe must forward each intact in arrival order (never re-sort) and
	// count the out-of-order arrivals on the fly, with zero inferred loss —
	// there is no hole above the in-order frontier in this sequence.
	t.Run("reorder", func(t *testing.T) {
		p := newFlowPipe(t)
		arrival := []uint64{3, 1, 4, 2}
		for _, s := range arrival {
			if err := p.Deliver(flowMsg(s)); err != nil {
				t.Fatalf("deliver seq %d: %v", s, err)
			}
		}
		f := p.Flow()
		if f.Reordered != 2 {
			t.Fatalf("Reordered is %d, want 2 (seq 1 before 3, seq 2 before 4)", f.Reordered)
		}
		if f.Lost != 0 {
			t.Fatalf("Lost is %d under pure reorder; a reorder was mistaken for a gap", f.Lost)
		}
		// Every datagram survived intact and in arrival order. Re-sorting to
		// repair the flow, or dropping an out-of-order datagram, would remove
		// the information the frame layer needs — this must not happen.
		for i, s := range arrival {
			got, err := p.Recv(context.Background())
			if err != nil {
				t.Fatalf("recv %d (want seq %d): %v", i, s, err)
			}
			if flowSeqOf(got) != s {
				t.Fatalf("recv %d is seq %d, want %d: the carrier re-sorted the flow", i, flowSeqOf(got), s)
			}
		}
	})

	// --- A single lost datagram -----------------------------------------
	// Datagrams 1 and 3 arrive; datagram 2 never does. The stream is
	// unambiguous about what that is: by the time 3 arrives, 2 has not, so the
	// flow has a single gap. The Pipe must count exactly one lost datagram and
	// zero reordering, and still deliver both survivors intact.
	t.Run("single_lost_datagram", func(t *testing.T) {
		p := newFlowPipe(t)
		if err := p.Deliver(flowMsg(1)); err != nil {
			t.Fatalf("deliver seq 1: %v", err)
		}
		if err := p.Deliver(flowMsg(3)); err != nil {
			t.Fatalf("deliver seq 3: %v", err)
		}
		f := p.Flow()
		if f.Lost != 1 {
			t.Fatalf("Lost is %d, want 1 (seq 2 never arrived)", f.Lost)
		}
		if f.Reordered != 0 {
			t.Fatalf("Reordered is %d under a single loss; a gap was mistaken for a reorder", f.Reordered)
		}
		if s := p.Stats(); s.Delivered != 2 {
			t.Fatalf("Delivered is %d, want 2; the carrier invented the lost datagram", s.Delivered)
		}
		for i, want := range []uint64{1, 3} {
			got, err := p.Recv(context.Background())
			if err != nil {
				t.Fatalf("recv %d (want seq %d): %v", i, want, err)
			}
			if flowSeqOf(got) != want {
				t.Fatalf("recv %d is seq %d, want %d", i, flowSeqOf(got), want)
			}
		}
	})

	// --- The counters move on arrival, never on read ---------------------
	// Reading the survivors back must not move Reordered or Lost. A slow
	// reader would otherwise look like fresh reordering/loss to the policy
	// layer, the same shape of false signal as a delivery counter that moved
	// on the host's read.
	t.Run("counters_move_on_arrival", func(t *testing.T) {
		p := newFlowPipe(t)
		for _, s := range []uint64{2, 1} {
			if err := p.Deliver(flowMsg(s)); err != nil {
				t.Fatalf("deliver seq %d: %v", s, err)
			}
		}
		before := p.Flow()
		if before.Reordered != 1 {
			t.Fatalf("Reordered is %d before reading, want 1", before.Reordered)
		}
		if _, err := p.Recv(context.Background()); err != nil {
			t.Fatalf("recv: %v", err)
		}
		if _, err := p.Recv(context.Background()); err != nil {
			t.Fatalf("recv: %v", err)
		}
		after := p.Flow()
		if after.Reordered != before.Reordered || after.Lost != before.Lost {
			t.Fatalf("reading moved the flow counters: before %+v, after %+v", before, after)
		}
	})

	// --- No extractor means no observation --------------------------------
	// A plain queue has no way to know the flow reordered or lost anything,
	// and it must report exactly that rather than a guessed number.
	t.Run("no_extractor_reports_zero", func(t *testing.T) {
		p, err := NewPipe(PipeConfig{Class: ClassUDP})
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		defer func() { _ = p.Close() }()
		if err := p.Deliver(message(200, 1)); err != nil {
			t.Fatalf("deliver: %v", err)
		}
		f := p.Flow()
		if f.Reordered != 0 || f.Lost != 0 {
			t.Fatalf("Flow() is %+v with no extractor; a blind queue guessed at the flow", f)
		}
	})
}

// TestArrivalCountersMoveOnArrivalNotOnRead is the sibling lane's bug, caught
// at this layer before it can be written.
//
// The escalation lane shipped a verdict sourced from a counter that moved on the
// HOST'S READ rather than on arrival. On that path the consequence was a
// misleading status field. On this one it would be worse: a policy layer asking
// "has anything arrived recently" would be told about how promptly this process
// drained a queue, so a busy handset would look like a censored one and would
// tear down a live tunnel to rebuild it on a slower carrier.
//
// The test sends and reads nothing.
func TestArrivalCountersMoveOnArrivalNotOnRead(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	a, b, err := NewPipePair(PipeConfig{Class: ClassUDP, Clock: clock})
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	defer func() { _ = a.Close(); _ = b.Close() }()

	ctx := context.Background()
	const n = 5
	for i := 0; i < n; i++ {
		clock.advance(time.Second)
		if err := a.Send(ctx, message(200, byte(i))); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	s := b.Stats()
	if s.Delivered != n {
		t.Fatalf("Delivered is %d after %d arrivals and zero reads; "+
			"the counter moves on the read, not on arrival", s.Delivered, n)
	}
	if s.DeliveredBytes != uint64(n*200) {
		t.Fatalf("DeliveredBytes is %d, want %d", s.DeliveredBytes, n*200)
	}
	if s.LastDelivered.IsZero() {
		t.Fatal("LastDelivered did not move on arrival")
	}
	arrivalTime := s.LastDelivered

	// Reading must not move it again, or a slow reader would look like fresh
	// network activity.
	clock.advance(time.Hour)
	for i := 0; i < n; i++ {
		if _, err := b.Recv(ctx); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
	}
	if got := b.Stats().LastDelivered; !got.Equal(arrivalTime) {
		t.Fatal("reading the queue moved LastDelivered")
	}
	if got := b.Stats().Delivered; got != n {
		t.Fatalf("Delivered is %d after reading; the read counted a second time", got)
	}
}

// TestPipeDropsRatherThanBlocking.
//
// A full inbox drops and counts. Blocking would backpressure a gateway's
// demultiplexer, and a demultiplexer that stalls on one slow session stalls
// every session on that socket — turning one unlucky client into an outage.
func TestPipeDropsRatherThanBlocking(t *testing.T) {
	t.Parallel()
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Depth: 2})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()

	for i := 0; i < 2; i++ {
		if err := p.Deliver(message(100, byte(i))); err != nil {
			t.Fatalf("deliver %d: %v", i, err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- p.Deliver(message(100, 9)) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrQueueFull) {
			t.Fatalf("a full inbox returned %v, want ErrQueueFull", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Deliver blocked on a full inbox")
	}
	if s := p.Stats(); s.Delivered != 2 || s.RecvErrors != 1 {
		t.Fatalf("counters are %+v", s)
	}
}

// The inbox high water is the deepest occupancy at any admission, and a
// read does not lower it.
func TestPipeInboxHighWater(t *testing.T) {
	t.Parallel()
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Depth: 8})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()
	for i := 0; i < 5; i++ {
		if err := p.Deliver(message(100, byte(i))); err != nil {
			t.Fatalf("deliver %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := p.Recv(context.Background()); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
	}
	if err := p.Deliver(message(100, 9)); err != nil {
		t.Fatal(err)
	}
	if s := p.Stats(); s.InboxHighWater != 5 {
		t.Fatalf("inbox high water %d, want 5 (the deepest admission, not the current 3)", s.InboxHighWater)
	}
}

// TestPipeRefusalsAndLifecycle.
func TestPipeRefusalsAndLifecycle(t *testing.T) {
	t.Parallel()
	if _, err := NewPipe(PipeConfig{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("a pipe with no class returned %v", err)
	}
	if _, err := NewPipe(PipeConfig{
		Class: ClassUDP, MaxMessageSize: session.MessageFloor() - 1,
	}); !errors.Is(err, ErrSizeBelowFloor) {
		t.Fatalf("below floor returned %v", err)
	}
	if _, err := NewPipe(PipeConfig{
		Class: ClassUDP, MaxMessageSize: 9000, PathMTU: 1280,
	}); !errors.Is(err, ErrSizeAbovePath) {
		t.Fatalf("above path returned %v", err)
	}
	if _, _, err := NewPipePair(PipeConfig{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("a pair with no class returned %v", err)
	}

	p, err := NewPipe(PipeConfig{Class: ClassTLS})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if p.Class() != ClassTLS {
		t.Fatalf("class is %s", p.Class())
	}
	ctx := context.Background()
	if err := p.Send(ctx, nil); !errors.Is(err, ErrMessageEmpty) {
		t.Fatalf("empty send returned %v", err)
	}
	if err := p.Send(ctx, message(p.MaxMessageSize()+1, 1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize send returned %v", err)
	}
	if err := p.Deliver(message(p.MaxMessageSize()+1, 1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize deliver returned %v", err)
	}
	if err := p.Deliver(nil); !errors.Is(err, ErrMessageEmpty) {
		t.Fatalf("empty deliver returned %v, want ErrMessageEmpty", err)
	}
	if err := p.SetMaxMessageSize(600); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if p.MaxMessageSize() != 600 {
		t.Fatalf("ceiling is %d", p.MaxMessageSize())
	}
	if err := p.SetMaxMessageSize(9000); !errors.Is(err, ErrSizeAbovePath) {
		t.Fatalf("above path returned %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := p.Send(cancelled, message(100, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled send returned %v", err)
	}
	if _, err := p.Recv(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recv returned %v", err)
	}
	// A Recv with nothing queued blocks until the deadline.
	tctx, tcancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer tcancel()
	if _, err := p.Recv(tctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("an empty Recv returned %v", err)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if err := p.Send(ctx, message(100, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("send after close returned %v", err)
	}
	if err := p.Deliver(message(100, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("deliver after close returned %v", err)
	}
	if _, err := p.Recv(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("recv after close returned %v", err)
	}
	if err := p.SetMaxMessageSize(600); !errors.Is(err, ErrClosed) {
		t.Fatalf("resize after close returned %v", err)
	}
}

// TestPipeSendErrorsAreCounted.
func TestPipeSendErrorsAreCounted(t *testing.T) {
	t.Parallel()
	boom := errors.New("dropped")
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Out: func([]byte) error { return boom }})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()
	if err := p.Send(context.Background(), message(100, 1)); !errors.Is(err, boom) {
		t.Fatalf("send returned %v", err)
	}
	if s := p.Stats(); s.SendErrors != 1 || s.Sent != 0 {
		t.Fatalf("counters are %+v", s)
	}
}

// TestPipeWithNoSinkModelsTheMeasuredBlock.
//
// A nil Out is not a stub, it is the measured scenario: under `-p udp -j DROP`
// the socket opens, every write succeeds, and nothing arrives. That is why
// failover cannot be driven by errors, and it is worth having a carrier that
// reproduces the shape exactly.
func TestPipeWithNoSinkModelsTheMeasuredBlock(t *testing.T) {
	t.Parallel()
	p, err := NewPipe(PipeConfig{Class: ClassUDP})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()

	ctx := context.Background()
	for i := 0; i < 24; i++ {
		if err := p.Send(ctx, message(200, byte(i))); err != nil {
			t.Fatalf("send %d returned an error; a censored carrier produces none: %v", i, err)
		}
	}
	s := p.Stats()
	if s.Sent != 24 || s.SendErrors != 0 {
		t.Fatalf("counters are %+v; a silent block must look like success at the socket", s)
	}
	if s.Delivered != 0 || !s.LastDelivered.IsZero() {
		t.Fatal("a carrier that received nothing reports a delivery")
	}
	// This is exactly the evidence escalation.go reasons over: everything sent,
	// nothing arrived, no error anywhere.
}

// TestQueueFullIsNotAConfigError.
//
// ErrQueueFull used to be wrap(ErrConfig, ...), so errors.Is(err, ErrConfig)
// was true for a full inbox. A caller that treats ErrConfig as "do not retry"
// would then drop a live session the first time the demultiplexer outran the
// reader. A full inbox is backpressure, not an invalid configuration.
func TestQueueFullIsNotAConfigError(t *testing.T) {
	t.Parallel()
	if errors.Is(ErrQueueFull, ErrConfig) {
		t.Fatal("ErrQueueFull is a wrap of ErrConfig; a full inbox is not invalid configuration")
	}
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Depth: 1})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()
	if err := p.Deliver(message(100, 1)); err != nil {
		t.Fatalf("first deliver: %v", err)
	}
	err = p.Deliver(message(100, 2))
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full inbox returned %v, want ErrQueueFull", err)
	}
	if errors.Is(err, ErrConfig) {
		t.Fatal("a full-inbox error still classifies as ErrConfig")
	}
}

func BenchmarkPipeDeliverAndRecvBatch(b *testing.B) {
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Depth: 1024})
	if err != nil {
		b.Fatalf("NewPipe: %v", err)
	}
	defer func() { _ = p.Close() }()
	ctx := context.Background()
	const batchSize = 32
	sendPayload := make([]byte, 1400)
	recvMsgs := make([]BatchMsg, batchSize)
	for i := range recvMsgs {
		recvMsgs[i] = BatchMsg{Payload: make([]byte, 1500)}
	}

	b.SetBytes(int64(batchSize * 1400))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < batchSize; j++ {
			if err := p.Deliver(sendPayload); err != nil {
				b.Fatalf("Deliver: %v", err)
			}
		}
		total := 0
		for total < batchSize {
			n, err := p.RecvBatch(ctx, recvMsgs[total:])
			if err != nil {
				b.Fatalf("RecvBatch: %v", err)
			}
			total += n
		}
	}
}

func TestPipeDeliverWithRetry(t *testing.T) {
	t.Parallel()
	p, err := NewPipe(PipeConfig{Class: ClassUDP, Depth: 2})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()

	for i := 0; i < 2; i++ {
		if err := p.Deliver(message(100, byte(i))); err != nil {
			t.Fatalf("deliver %d: %v", i, err)
		}
	}

	// Inbox is now full (2/2). A delayed reader will drain it.
	drained := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Microsecond)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = p.Recv(ctx)
		close(drained)
	}()

	// DeliverWithRetry should succeed once the reader drains one slot.
	if err := p.DeliverWithRetry(message(100, 99), 10); err != nil {
		t.Fatalf("DeliverWithRetry failed on transiently full inbox: %v", err)
	}
	<-drained
	if s := p.Stats(); s.Delivered != 3 || s.RecvErrors != 0 {
		t.Fatalf("expected 3 delivered and 0 recv errors, got: %+v", s)
	}
}

