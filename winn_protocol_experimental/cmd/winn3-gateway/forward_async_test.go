package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests cover -forward-async-write (forward_async.go) with no kernel
// interface: fakeAsyncShared stands in for sharedGatewayTun and routes writes
// through the real tunWriteQueues, so ordering, backpressure and teardown are
// the production code's, and only the final write(2) is a recording.

// fakeAsyncShared records what each queue wrote, in order. A closed gate makes
// every write wait for it, which is how a test holds a writer mid-write.
type fakeAsyncShared struct {
	q       *tunWriteQueues
	queues  int
	gate    chan struct{}
	entered chan int

	mu  sync.Mutex
	got map[int][][]byte
}

func newFakeAsyncShared(queues, depth int, async bool) *fakeAsyncShared {
	f := &fakeAsyncShared{queues: queues, got: make(map[int][][]byte), entered: make(chan int, 1<<16)}
	if async {
		f.q = newTunWriteQueues(queues, depth, 64, f.writeQueue, nil)
		// Every submit within an hour of construction is a burst, so these
		// tests exercise the handoff path. The inline decision has its own
		// tests below, which set gap themselves.
		f.q.gap = time.Hour
	}
	return f
}

// queueFor stands in for sharedGatewayTun.queueFor: the destination's last
// octet names the flow, and so the queue.
func (f *fakeAsyncShared) queueFor(pkt []byte) int { return int(pkt[19]) % f.queues }

func (f *fakeAsyncShared) writeQueue(q int, pkt []byte) (int, error) {
	f.entered <- q
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	f.got[q] = append(f.got[q], append([]byte(nil), pkt...))
	f.mu.Unlock()
	return len(pkt), nil
}

func (f *fakeAsyncShared) write(pkt []byte) (int, error) { return f.writeQueue(f.queueFor(pkt), pkt) }
func (f *fakeAsyncShared) asyncWrites() bool             { return f.q != nil }
func (f *fakeAsyncShared) writeTracked(p *atomic.Int64, pkt []byte) (int, error) {
	return f.q.submit(f.queueFor(pkt), p, pkt)
}

func (f *fakeAsyncShared) written(q int) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.got[q]...)
}

// seqPacket is ipv4Packet plus a 4-byte sequence number after the header.
func seqPacket(t *testing.T, dst string, seq uint32) []byte {
	t.Helper()
	pkt := ipv4Packet(t, "10.64.0.2", dst)
	return binary.BigEndian.AppendUint32(pkt, seq)
}

func waitEntered(t *testing.T, f *fakeAsyncShared) {
	t.Helper()
	select {
	case <-f.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no writer entered write(2)")
	}
}

func TestAsyncTunWritesKeepEachFlowInSubmissionOrder(t *testing.T) {
	f := newFakeAsyncShared(2, 4, true)
	dev := newGatewayForwardDevice(f, newForwardTable(), 1400)
	dev.bind(fakeLoop())
	const n = 4000
	for i := uint32(0); i < n; i++ {
		dst := "8.8.8.1"
		if i%3 == 0 {
			dst = "8.8.8.2"
		}
		if _, err := dev.WritePacket(seqPacket(t, dst, i)); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if p := dev.pending.Load(); p != 0 {
		t.Fatalf("Close returned with %d packets still pending", p)
	}
	total := 0
	for q := 0; q < 2; q++ {
		last := int64(-1)
		for _, pkt := range f.written(q) {
			seq := int64(binary.BigEndian.Uint32(pkt[20:]))
			if seq <= last {
				t.Fatalf("queue %d wrote sequence %d after %d: a flow was reordered", q, seq, last)
			}
			last = seq
			total++
		}
	}
	st := f.q.stats()
	if total != n || st.Written != n || st.Failed != 0 {
		t.Fatalf("wrote %d of %d (stats %+v); every accepted packet must be written once", total, n, st)
	}
	f.q.close()
}

func TestAsyncTunWriteCopiesThePacketBeforeReturning(t *testing.T) {
	f := newFakeAsyncShared(1, 4, true)
	f.gate = make(chan struct{})
	var pending atomic.Int64
	pkt := seqPacket(t, "8.8.8.1", 7)
	want := append([]byte(nil), pkt...)
	if _, err := f.writeTracked(&pending, pkt); err != nil {
		t.Fatal(err)
	}
	// The session reuses its scratch the moment WritePacket returns.
	for i := range pkt {
		pkt[i] = 0xAA
	}
	waitEntered(t, f)
	close(f.gate)
	f.q.close()
	got := f.written(0)
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Fatalf("wrote %x, want %x: the queue must own a copy", got, want)
	}
}

func TestAsyncTunWriteBlocksWhenFullInsteadOfDropping(t *testing.T) {
	const depth = 2
	f := newFakeAsyncShared(1, depth, true)
	f.gate = make(chan struct{})
	var pending atomic.Int64
	if _, err := f.writeTracked(&pending, seqPacket(t, "8.8.8.1", 0)); err != nil {
		t.Fatal(err)
	}
	waitEntered(t, f) // the writer now holds packet 0 inside write(2)
	for i := uint32(1); i <= depth; i++ {
		if _, err := f.writeTracked(&pending, seqPacket(t, "8.8.8.1", i)); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.writeTracked(&pending, seqPacket(t, "8.8.8.1", depth+1))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a submit to a full queue returned (%v) instead of blocking", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(f.gate)
	if err := <-done; err != nil {
		t.Fatalf("blocked submit failed once the queue drained: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for pending.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	st := f.q.stats()
	if pending.Load() != 0 || st.Written != depth+2 {
		t.Fatalf("pending %d stats %+v: backpressure must not lose packets", pending.Load(), st)
	}
	f.q.close()
}

func TestGatewayForwardDeviceCloseWaitsForItsQueuedWrites(t *testing.T) {
	f := newFakeAsyncShared(1, 8, true)
	f.gate = make(chan struct{})
	dev := newGatewayForwardDevice(f, newForwardTable(), 1400)
	dev.bind(fakeLoop())
	for i := uint32(0); i < 3; i++ {
		if _, err := dev.WritePacket(seqPacket(t, "8.8.8.1", i)); err != nil {
			t.Fatal(err)
		}
	}
	closed := make(chan struct{})
	go func() {
		_ = dev.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while the session still had packets queued")
	case <-time.After(50 * time.Millisecond):
	}
	close(f.gate)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the queue drained")
	}
	if got := len(f.written(0)); got != 3 || dev.pending.Load() != 0 {
		t.Fatalf("wrote %d of 3, pending %d, when Close returned", got, dev.pending.Load())
	}
	f.q.close()
}

// TestAsyncTunWriteCloseWritesTheQueueAndLaterSubmitsGoInline: revision 3.2
// never drops. Packets queued when close begins are written by their writer
// before it exits, and a submit after close takes the synchronous path. A
// writer that finishes a write after stop is closed chooses at random between
// the queue and the stop signal, so its drain branch runs only in some
// iterations; 50 iterations make missing it about 2^-50.
func TestAsyncTunWriteCloseWritesTheQueueAndLaterSubmitsGoInline(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		f := newFakeAsyncShared(1, 8, true)
		f.gate = make(chan struct{})
		var pending atomic.Int64
		for i := uint32(0); i < 3; i++ {
			if _, err := f.writeTracked(&pending, seqPacket(t, "8.8.8.1", i)); err != nil {
				t.Fatal(err)
			}
		}
		waitEntered(t, f)
		stopped := make(chan struct{})
		go func() {
			f.q.close()
			close(stopped)
		}()
		time.Sleep(5 * time.Millisecond)
		close(f.gate)
		<-stopped
		if st := f.q.stats(); st.Written != 3 || pending.Load() != 0 {
			t.Fatalf("iteration %d: stats %+v pending %d after close: every queued packet must be written, not dropped",
				iter, st, pending.Load())
		}
		if n, err := f.writeTracked(&pending, seqPacket(t, "8.8.8.1", 9)); err != nil || n == 0 {
			t.Fatalf("iteration %d: submit after close = %d, %v; want the inline write", iter, n, err)
		}
		if st := f.q.stats(); st.Inline != 1 || st.Queued != 3 || pending.Load() != 0 || len(f.written(0)) != 4 {
			t.Fatalf("iteration %d: stats %+v pending %d written %d: a submit after close must be written inline, never queued",
				iter, st, pending.Load(), len(f.written(0)))
		}
	}
}

// TestAsyncTunWriteSubmitRacingCloseNeverStrandsAPacket is the Round X
// OI-XB3 race, made deterministic: a hook between submit's "still open?"
// check and its channel send starts close and gives it time to finish if it
// can. Revision 3.1 let close drain the queue and its writer exit inside that
// window, so the send then stranded the packet and the session's pending
// count. Now close must wait for the send, and the packet must be written.
func TestAsyncTunWriteSubmitRacingCloseNeverStrandsAPacket(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		var mu sync.Mutex
		var got int
		w := newTunWriteQueues(1, 4, 64, func(int, []byte) (int, error) {
			mu.Lock()
			got++
			mu.Unlock()
			return 64, nil
		}, nil)
		w.gap = time.Hour // hand off
		closed := make(chan struct{})
		w.testHookBeforeEnqueue = func() {
			go func() {
				w.close()
				close(closed)
			}()
			time.Sleep(10 * time.Millisecond) // ample for an unguarded close to finish
		}
		var pending atomic.Int64
		if n, err := w.submit(0, &pending, make([]byte, 64)); err != nil || n != 64 {
			t.Fatalf("iteration %d: submit = %d, %v", iter, n, err)
		}
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: close did not return", iter)
		}
		mu.Lock()
		written := got
		mu.Unlock()
		if pending.Load() != 0 || written != 1 {
			t.Fatalf("iteration %d: after close, pending %d and %d written: a packet enqueued across close was stranded",
				iter, pending.Load(), written)
		}
	}
}

// TestAsyncTunWriteConcurrentSubmitAndCloseLosesNothing: many sessions submit
// (a mix of inline and handoff) while close runs at a random moment. Every
// packet is written exactly once and every session's pending count is zero.
func TestAsyncTunWriteConcurrentSubmitAndCloseLosesNothing(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		var mu sync.Mutex
		seen := make(map[uint64]int)
		w := newTunWriteQueues(2, 4, 16, func(_ int, pkt []byte) (int, error) {
			mu.Lock()
			seen[binary.BigEndian.Uint64(pkt)]++
			mu.Unlock()
			return len(pkt), nil
		}, nil)
		if iter%2 == 1 {
			w.gap = time.Hour
		} else {
			w.gap = 0
		}
		const sessions, each = 8, 300
		pendings := make([]atomic.Int64, sessions)
		var wg sync.WaitGroup
		for s := 0; s < sessions; s++ {
			wg.Add(1)
			go func(s int) {
				defer wg.Done()
				for i := 0; i < each; i++ {
					pkt := binary.BigEndian.AppendUint64(nil, uint64(s*each+i))
					if _, err := w.submit(s%2, &pendings[s], pkt); err != nil {
						t.Errorf("submit: %v", err)
						return
					}
				}
			}(s)
		}
		time.Sleep(time.Duration(iter%5) * time.Millisecond)
		w.close()
		wg.Wait()
		for s := range pendings {
			if p := pendings[s].Load(); p != 0 {
				t.Fatalf("iteration %d: session %d left %d pending", iter, s, p)
			}
		}
		if len(seen) != sessions*each {
			t.Fatalf("iteration %d: %d distinct packets written, want %d", iter, len(seen), sessions*each)
		}
		for k, c := range seen {
			if c != 1 {
				t.Fatalf("iteration %d: packet %d written %d times", iter, k, c)
			}
		}
	}
}

func TestGatewayForwardDeviceWritesSynchronouslyWhenAsyncIsOff(t *testing.T) {
	f := newFakeAsyncShared(1, 8, false)
	dev := newGatewayForwardDevice(f, newForwardTable(), 1400)
	dev.bind(fakeLoop())
	if _, err := dev.WritePacket(seqPacket(t, "8.8.8.1", 1)); err != nil {
		t.Fatal(err)
	}
	// No queue exists: the packet was written before WritePacket returned.
	if got := len(f.written(0)); got != 1 || dev.pending.Load() != 0 {
		t.Fatalf("flag off: wrote %d, pending %d; want the synchronous write", got, dev.pending.Load())
	}
}

func TestForwardAsyncWriteWithoutForwardIsRefused(t *testing.T) {
	err := run([]string{"-mode", "serve", "-listen", "127.0.0.1:0", "-inner-v4", "10.64.0.1", "-forward-async-write"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-forward-async-write") {
		t.Fatalf("got %v, want the -forward-async-write refusal", err)
	}
}

func TestTunGSOWithoutForwardIsRefused(t *testing.T) {
	err := run([]string{"-mode", "serve", "-listen", "127.0.0.1:0", "-inner-v4", "10.64.0.1", "-tun-gso"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-tun-gso") {
		t.Fatalf("got %v, want the -tun-gso refusal", err)
	}
}

// TestAsyncTunWriteQueuesStayWithinTheirBill fills every queue the shared
// device can have, with every writer held mid-write, and requires the live
// heap they add to stay inside the term sharedLiveBytes bills for them.
func TestAsyncTunWriteQueuesStayWithinTheirBill(t *testing.T) {
	gate := make(chan struct{})
	write := func(int, []byte) (int, error) { <-gate; return 0, nil }
	pkt := make([]byte, 1373)
	h0, _ := liveHeapAndStack()
	a0 := totalAlloc()
	w := newTunWriteQueues(maxGatewayTunQueues, tunWriteQueueDepth, len(pkt), write, nil)
	w.gap = time.Hour // handoff only: this test fills the queues
	// -tun-gso's per-writer buffers are inside the same bill: allocate them.
	w.enableGSO(func(int, []byte) (int, error) { <-gate; return 0, nil })
	var pending atomic.Int64
	for q := 0; q < maxGatewayTunQueues; q++ {
		// depth queued plus the one each writer holds inside write.
		for i := 0; i <= tunWriteQueueDepth; i++ {
			if _, err := w.submit(q, &pending, pkt); err != nil {
				t.Fatal(err)
			}
		}
	}
	a1 := totalAlloc()
	h1, _ := liveHeapAndStack()
	grew := int64(h1) - int64(h0)
	allocated := int64(a1 - a0)
	bill := int64(asyncTunWriteBill())
	slabs := int64(maxGatewayTunQueues * (tunWriteQueueDepth + 1) * len(pkt))
	t.Logf("%d queues x %d packets held %d B live, %d B allocated (payload %d B); billed %d B",
		maxGatewayTunQueues, tunWriteQueueDepth+1, grew, allocated, slabs, bill)
	// Anti-vacuity: filling the queues must have allocated at least the packet
	// bytes they hold, or the bound below proves nothing. Allocation, not the
	// live delta, is the witness: other packages' garbage freed by the same
	// collection can hide part of the live growth (measured on Linux arm64).
	if allocated < slabs {
		t.Fatalf("filling the queues allocated %d B for %d B of queued packets: the test is not exercising them", allocated, slabs)
	}
	if grew > bill {
		t.Fatalf("full queues hold %d B, above their %d B bill", grew, bill)
	}
	close(gate)
	w.close()
	runtime.KeepAlive(w)
	runtime.KeepAlive(pkt)
}

// --- revision 2: inline when idle, hand off while busy ---------------------

// holdingShared is a fake whose write blocks for any packet whose sequence
// number is in hold, until release(seq). It records write order per queue.
type holdingShared struct {
	*fakeAsyncShared
	hmu  sync.Mutex
	hold map[uint32]chan struct{}
	in   chan uint32
}

func newHoldingShared(gap time.Duration, hold ...uint32) *holdingShared {
	h := &holdingShared{fakeAsyncShared: &fakeAsyncShared{queues: 1, got: make(map[int][][]byte), entered: make(chan int, 1<<10)},
		hold: make(map[uint32]chan struct{}), in: make(chan uint32, 64)}
	for _, q := range hold {
		h.hold[q] = make(chan struct{})
	}
	h.q = newTunWriteQueues(1, 8, 64, h.writeHeld, nil)
	h.q.gap = gap
	return h
}

func (h *holdingShared) writeHeld(q int, pkt []byte) (int, error) {
	seq := binary.BigEndian.Uint32(pkt[20:])
	h.hmu.Lock()
	ch := h.hold[seq]
	h.hmu.Unlock()
	h.in <- seq
	if ch != nil {
		<-ch
	}
	h.mu.Lock()
	h.got[q] = append(h.got[q], append([]byte(nil), pkt...))
	h.mu.Unlock()
	return len(pkt), nil
}

func (h *holdingShared) release(seq uint32) {
	h.hmu.Lock()
	close(h.hold[seq])
	h.hmu.Unlock()
}

func (h *holdingShared) waitIn(t *testing.T, seq uint32) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-h.in:
			if got == seq {
				return
			}
		case <-deadline:
			t.Fatalf("packet %d never reached write(2)", seq)
		}
	}
}

// submitAsync submits from its own goroutine and returns a channel that
// yields once submit returns.
func (h *holdingShared) submitAsync(t *testing.T, pending *atomic.Int64, seq uint32) chan error {
	pkt := seqPacket(t, "8.8.8.1", seq)
	done := make(chan error, 1)
	go func() {
		_, err := h.q.submit(0, pending, pkt)
		done <- err
	}()
	return done
}

func returnsWithin(t *testing.T, done chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return: it was written inline behind a held write", what)
	}
}

// drained waits until nothing handed off is still pending. close drops what
// is queued, so a test that checks what was written must wait first.
func drained(t *testing.T, pending *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for pending.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d handed-off packets never written", pending.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *holdingShared) order() []uint32 {
	var out []uint32
	for _, pkt := range h.written(0) {
		out = append(out, binary.BigEndian.Uint32(pkt[20:]))
	}
	return out
}

func TestAsyncTunWriteGoesInlineWhenTheQueueIsIdle(t *testing.T) {
	h := newHoldingShared(0)
	var pending atomic.Int64
	for seq := uint32(1); seq <= 3; seq++ {
		if _, err := h.q.submit(0, &pending, seqPacket(t, "8.8.8.1", seq)); err != nil {
			t.Fatal(err)
		}
		// Inline means written before submit returned, with nothing queued.
		if got := len(h.written(0)); got != int(seq) {
			t.Fatalf("after submit %d, %d written: an idle queue must write inline", seq, got)
		}
	}
	st := h.q.stats()
	if st.Inline != 3 || st.Queued != 0 || pending.Load() != 0 {
		t.Fatalf("stats %+v pending %d: want 3 inline, 0 queued", st, pending.Load())
	}
	h.q.close()
}

func TestAsyncTunWriteHandsOffWhileAWriteIsInFlight(t *testing.T) {
	h := newHoldingShared(0, 100)
	var pending atomic.Int64
	x := h.submitAsync(t, &pending, 100) // idle queue: inline, held in write(2)
	h.waitIn(t, 100)
	returnsWithin(t, h.submitAsync(t, &pending, 1), "submit while a write is in flight")
	if st := h.q.stats(); st.Queued != 1 || st.Inline != 0 {
		t.Fatalf("stats %+v: a submit while another write is in flight must be handed off", st)
	}
	h.release(100)
	returnsWithin(t, x, "held inline write")
	drained(t, &pending)
	// Once the handoff has been written the queue is idle again, and the
	// next packet goes inline: the in-flight count must fall back to zero.
	if _, err := h.q.submit(0, &pending, seqPacket(t, "8.8.8.1", 2)); err != nil {
		t.Fatal(err)
	}
	h.q.close()
	if st := h.q.stats(); st.Inline != 2 || st.Written != 1 {
		t.Fatalf("stats %+v: want two inline writes and one queue write", st)
	}
}

func TestAsyncTunWriteHandsOffABurstEvenWhenIdle(t *testing.T) {
	h := newHoldingShared(time.Hour)
	var pending atomic.Int64
	for seq := uint32(1); seq <= 2; seq++ {
		if _, err := h.q.submit(0, &pending, seqPacket(t, "8.8.8.1", seq)); err != nil {
			t.Fatal(err)
		}
		h.waitIn(t, seq)
		deadline := time.Now().Add(2 * time.Second)
		for pending.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	// The queue was idle (inflight 0) before the second submit, but the two
	// arrived inside the burst gap: one session at speed must stay pipelined.
	if st := h.q.stats(); st.Inline != 0 || st.Queued != 2 {
		t.Fatalf("stats %+v: submits inside the burst gap must be handed off", st)
	}
	h.q.close()
}

// TestAsyncTunWriteNeverReordersAFlowAcrossInlineAndHandoff: packet 1 of a
// flow is handed off (another write was in flight) and held inside write(2);
// the other write then finishes, so only packet 1 is in flight when packet 2
// arrives. Packet 2 must queue behind it, not go inline ahead of it.
func TestAsyncTunWriteNeverReordersAFlowAcrossInlineAndHandoff(t *testing.T) {
	h := newHoldingShared(0, 100, 1)
	var pending atomic.Int64
	x := h.submitAsync(t, &pending, 100) // another flow, inline, held
	h.waitIn(t, 100)
	returnsWithin(t, h.submitAsync(t, &pending, 1), "packet 1 (handed off)")
	h.waitIn(t, 1) // the queue's writer now holds packet 1 in write(2)
	h.release(100)
	returnsWithin(t, x, "the other flow's inline write")
	returnsWithin(t, h.submitAsync(t, &pending, 2), "packet 2")
	h.release(1)
	drained(t, &pending)
	h.q.close()
	var flow []uint32
	for _, seq := range h.order() {
		if seq != 100 {
			flow = append(flow, seq)
		}
	}
	if len(flow) != 2 || flow[0] != 1 || flow[1] != 2 {
		t.Fatalf("flow written as %v, want [1 2]: packet 2 overtook a packet still in flight", flow)
	}
}

func TestWriteInlineDecision(t *testing.T) {
	gap := 20 * time.Microsecond
	for _, c := range []struct {
		inflight int
		since    time.Duration
		want     bool
	}{
		{0, gap, true}, {0, time.Second, true}, {0, gap - 1, false},
		{1, time.Second, false}, {2, time.Second, false},
	} {
		if got := writeInline(c.inflight, c.since, gap); got != c.want {
			t.Errorf("writeInline(%d, %v) = %v, want %v", c.inflight, c.since, got, c.want)
		}
	}
}

// --- revision 2: the forward table's peer-key cache -------------------------

func TestForwardTableCachesAPrivateCopyOfThePeerKeyAtLearn(t *testing.T) {
	f := newAuthorityFixture(t, time.Now().Add(time.Hour).Unix())
	f.table.mu.Lock()
	c, ok := f.table.peers[f.addr]
	f.table.mu.Unlock()
	if !ok || c.loop != f.loop || !bytes.Equal(c.peer, f.key) {
		t.Fatalf("after learn the cache holds %+v (present %v); want this loop and its peer key", c, ok)
	}
	if live := f.loop.Session().PeerStatic(); len(live) > 0 && &live[0] == &c.peer[0] {
		t.Fatal("the cache aliases the session's own peer key slice instead of copying it")
	}
}

func TestForwardTableLookupUsesTheCacheOnlyForItsOwnLoop(t *testing.T) {
	f := newAuthorityFixture(t, time.Now().Add(time.Hour).Unix())
	wrong := bytes.Repeat([]byte{7}, len(f.key))
	// A cache entry for the current loop is authoritative: a key the registry
	// does not bind to this address must refuse, proving lookup reads it.
	f.table.mu.Lock()
	f.table.peers[f.addr] = cachedPeer{loop: f.loop, peer: wrong}
	f.table.mu.Unlock()
	if _, ok := f.table.lookup(f.addr); ok {
		t.Fatal("lookup ignored the cached peer key for its own loop")
	}
	// An entry naming another loop is stale and must not be used.
	f.table.mu.Lock()
	f.table.peers[f.addr] = cachedPeer{loop: nil, peer: wrong}
	f.table.mu.Unlock()
	if got, ok := f.table.lookup(f.addr); !ok || got != f.loop {
		t.Fatal("lookup used a cached key recorded for a different loop")
	}
}

func TestForwardTableForgetDropsTheCachedPeerKey(t *testing.T) {
	f := newAuthorityFixture(t, time.Now().Add(time.Hour).Unix())
	f.table.forget(f.addr, f.loop)
	f.table.mu.Lock()
	_, ok := f.table.peers[f.addr]
	f.table.mu.Unlock()
	if ok {
		t.Fatal("forget left the departed session's peer key in the cache")
	}
}

// TestAsyncTunWriteKeepsFlowOrderAcrossClose is Round X Turn 2 (Seat C,
// OI-XB3), made deterministic with hooks. Packet 0 of a flow is held inside
// the writer's write(2) and packet 1 is queued behind it; close then marks
// the queues closed (testHookClosed), and packet 2 of the same flow is
// submitted. Revision 3.2 wrote packet 2 inline at once, ahead of packet 1.
// Now packet 2 must wait for the drain, so the flow is written 0, 1, 2.
func TestAsyncTunWriteKeepsFlowOrderAcrossClose(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		h := newHoldingShared(time.Hour, 0) // hand off; hold seq 0 in write(2)
		var pending atomic.Int64
		returnsWithin(t, h.submitAsync(t, &pending, 0), "packet 0")
		h.waitIn(t, 0)
		returnsWithin(t, h.submitAsync(t, &pending, 1), "packet 1 (queued behind 0)")
		marked := make(chan struct{})
		h.q.testHookClosed = func() { close(marked) }
		closeDone := make(chan struct{})
		go func() {
			h.q.close()
			close(closeDone)
		}()
		<-marked
		p2 := h.submitAsync(t, &pending, 2)
		// Give an unguarded inline write ample time to land before the
		// held packet is released.
		time.Sleep(10 * time.Millisecond)
		h.release(0)
		returnsWithin(t, p2, "packet 2 (after close)")
		<-closeDone
		if got := h.order(); len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
			t.Fatalf("iteration %d: flow written as %v, want [0 1 2]: a post-close inline write overtook a queued packet", iter, got)
		}
		if pending.Load() != 0 {
			t.Fatalf("iteration %d: %d pending after close", iter, pending.Load())
		}
	}
}

// --- revision 3.4: cross-queue order at close, and IPv4 fragments -------------

// globalHold is a fake with N queues that records ONE global write order and
// holds, inside write(2), any packet whose sequence number is in hold.
type globalHold struct {
	q    *tunWriteQueues
	mu   sync.Mutex
	got  []uint32
	hold map[uint32]chan struct{}
	in   chan uint32
}

func newGlobalHold(queues int, gap time.Duration, hold ...uint32) *globalHold {
	g := &globalHold{hold: make(map[uint32]chan struct{}), in: make(chan uint32, 64)}
	for _, h := range hold {
		g.hold[h] = make(chan struct{})
	}
	g.q = newTunWriteQueues(queues, 8, 64, func(_ int, pkt []byte) (int, error) {
		seq := binary.BigEndian.Uint32(pkt[20:])
		g.mu.Lock()
		ch := g.hold[seq]
		g.mu.Unlock()
		g.in <- seq
		if ch != nil {
			<-ch
		}
		g.mu.Lock()
		g.got = append(g.got, seq)
		g.mu.Unlock()
		return len(pkt), nil
	}, nil)
	g.q.gap = gap
	return g
}

func (g *globalHold) order() []uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint32(nil), g.got...)
}

func (g *globalHold) waitIn(t *testing.T, seq uint32) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-g.in:
			if got == seq {
				return
			}
		case <-deadline:
			t.Fatalf("packet %d never reached write(2)", seq)
		}
	}
}

func (g *globalHold) submitAsync(queue int, pending *atomic.Int64, pkt []byte) chan error {
	done := make(chan error, 1)
	go func() {
		_, err := g.q.submit(queue, pending, pkt)
		done <- err
	}()
	return done
}

// fragment marks pkt as an IPv4 fragment: more-fragments, or (last) a bare
// nonzero offset.
func fragment(pkt []byte, last bool) []byte {
	p := append([]byte(nil), pkt...)
	if last {
		p[6], p[7] = 0x00, 0xb9 // offset 185 * 8 = 1480, MF clear
	} else {
		p[6], p[7] = 0x20, 0x00 // MF set, offset 0
	}
	return p
}

func wantOrder(t *testing.T, iter int, got []uint32, want ...uint32) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("iteration %d: wrote %v, want %v", iter, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("iteration %d: wrote %v, want %v: a write overtook a packet accepted before it on another queue", iter, got, want)
		}
	}
}

// TestAsyncTunWritePostCloseWriteToAnIdleQueueWaitsForEveryWriter is Seat
// C's Turn 3 counterexample: queue 0 holds packet 0 in write(2) and packet 1
// behind it; close begins; a packet submitted to IDLE queue 1 must still wait
// until queue 0 has drained. Revision 3.3's idle inline path wrote it at once.
func TestAsyncTunWritePostCloseWriteToAnIdleQueueWaitsForEveryWriter(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		g := newGlobalHold(2, time.Hour, 0)
		var pending atomic.Int64
		returnsWithin(t, g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 0)), "packet 0")
		g.waitIn(t, 0)
		returnsWithin(t, g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 1)), "packet 1")
		marked := make(chan struct{})
		g.q.testHookClosed = func() { close(marked) }
		closeDone := make(chan struct{})
		go func() { g.q.close(); close(closeDone) }()
		<-marked
		g.q.gap = 0 // queue 1 is idle and outside any burst: rev3.3 would write inline now
		p2 := g.submitAsync(1, &pending, seqPacket(t, "8.8.8.2", 2))
		time.Sleep(10 * time.Millisecond)
		g.mu.Lock()
		close(g.hold[0])
		g.mu.Unlock()
		returnsWithin(t, p2, "packet 2 (idle queue, after close)")
		<-closeDone
		wantOrder(t, iter, g.order(), 0, 1, 2)
	}
}

// TestAsyncTunWriteFragmentWaitsForEveryEarlierPacket: an IPv4 fragment may be
// placed on a different queue than the rest of its flow (queueFor sees no
// ports in a non-first fragment), so it must not be written until every packet
// accepted before it, on every queue, has been. Both fragment shapes: more-
// fragments set, and a last fragment (offset only).
func TestAsyncTunWriteFragmentWaitsForEveryEarlierPacket(t *testing.T) {
	for _, last := range []bool{false, true} {
		for iter := 0; iter < 30; iter++ {
			g := newGlobalHold(2, time.Hour, 0)
			var pending atomic.Int64
			returnsWithin(t, g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 0)), "packet 0")
			g.waitIn(t, 0)
			returnsWithin(t, g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 1)), "packet 1")
			g.q.gap = 0 // queue 1 idle: an unguarded fragment would go inline at once
			f := g.submitAsync(1, &pending, fragment(seqPacket(t, "8.8.8.1", 2), last))
			time.Sleep(10 * time.Millisecond)
			g.mu.Lock()
			close(g.hold[0])
			g.mu.Unlock()
			returnsWithin(t, f, "the fragment")
			deadline := time.Now().Add(2 * time.Second)
			for len(g.order()) < 3 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			wantOrder(t, iter, g.order(), 0, 1, 2)
			if st := g.q.stats(); st.Inline != 1 || st.Queued != 2 {
				t.Fatalf("last=%v iteration %d: stats %+v: the fragment must be written inline, never queued", last, iter, st)
			}
			g.q.close()
		}
	}
}

func TestIsIPv4Fragment(t *testing.T) {
	base := seqPacket(t, "8.8.8.1", 1)
	df := append([]byte(nil), base...)
	df[6], df[7] = 0x40, 0x00 // DF only
	for _, c := range []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"unfragmented", base, false},
		{"DF only", df, false},
		{"more fragments", fragment(base, false), true},
		{"last fragment (offset only)", fragment(base, true), true},
		{"short", base[:10], false},
		{"IPv6", append([]byte{0x60}, make([]byte, 39)...), false},
	} {
		if got := isIPv4Fragment(c.pkt); got != c.want {
			t.Errorf("%s: isIPv4Fragment = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAsyncTunWriteCloseBeginningAfterTheOpenCheckStillWaitsForTheDrain covers
// the window between submit's lock-free "closing?" check and the handoff
// path's locked check: close begins inside it (hook). The handoff path must
// then still wait for the drain before its inline write, so packet 2 of the
// flow follows packets 0 and 1 queued on the same queue.
func TestAsyncTunWriteCloseBeginningAfterTheOpenCheckStillWaitsForTheDrain(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		g := newGlobalHold(1, time.Hour, 0)
		var pending atomic.Int64
		returnsWithin(t, g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 0)), "packet 0")
		g.waitIn(t, 0)
		returnsWithin(t, g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 1)), "packet 1")
		closeDone := make(chan struct{})
		g.q.testHookAfterCloseCheck = func() {
			marked := make(chan struct{})
			g.q.testHookClosed = func() { close(marked) }
			go func() { g.q.close(); close(closeDone) }()
			<-marked
		}
		p2 := g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 2))
		time.Sleep(10 * time.Millisecond)
		g.mu.Lock()
		close(g.hold[0])
		g.mu.Unlock()
		returnsWithin(t, p2, "packet 2")
		<-closeDone
		wantOrder(t, iter, g.order(), 0, 1, 2)
	}
}

// TestAsyncTunWriteSubmitAfterACloseThatCompletedInItsWindowIsWrittenInline:
// a submit passes the lock-free "closing?" check, then close runs to
// completion inside the window (hook), so every writer has exited. The
// handoff path's locked check must see closed and write inline; enqueueing
// would strand the packet and its pending count.
func TestAsyncTunWriteSubmitAfterACloseThatCompletedInItsWindowIsWrittenInline(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		g := newGlobalHold(1, time.Hour)
		var pending atomic.Int64
		g.q.testHookAfterCloseCheck = func() { g.q.close() }
		returnsWithin(t, g.submitAsync(0, &pending, seqPacket(t, "8.8.8.1", 0)), "the packet")
		if st := g.q.stats(); pending.Load() != 0 || st.Queued != 0 || st.Inline != 1 || len(g.order()) != 1 {
			t.Fatalf("iteration %d: stats %+v pending %d written %v: after close completed, the packet must be written inline",
				iter, st, pending.Load(), g.order())
		}
	}
}

// TestAsyncTunWriteIdleQueueRacingCloseWaitsForTheDrain is Sol-S1-T1-1 (Round
// S1 review, Turn 1), made deterministic: queue 0 holds packet 0 in write(2)
// and packet 1 behind it; a submit to IDLE queue 1 passes the lock-free
// "closing?" check, close then marks the queues closed (hook), and only then
// does the submit take its inline decision. Turn 1 wrote packet 2 at once,
// outside the lifecycle hold, ahead of the packets queue 0 was still draining.
func TestAsyncTunWriteIdleQueueRacingCloseWaitsForTheDrain(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		g := newGlobalHold(2, time.Hour, 0)
		var pending atomic.Int64

		returnsWithin(t,
			g.submitAsync(0, &pending, seqPacket(t, "192.0.2.1", 0)),
			"packet 0")
		g.waitIn(t, 0)
		returnsWithin(t,
			g.submitAsync(0, &pending, seqPacket(t, "192.0.2.1", 1)),
			"packet 1")

		g.q.gap = 0
		closeDone := make(chan struct{})
		g.q.testHookAfterCloseCheck = func() {
			marked := make(chan struct{})
			g.q.testHookClosed = func() { close(marked) }
			go func() {
				g.q.close()
				close(closeDone)
			}()
			<-marked
		}

		p2 := g.submitAsync(1, &pending, seqPacket(t, "192.0.2.1", 2))
		time.Sleep(10 * time.Millisecond)

		g.mu.Lock()
		close(g.hold[0])
		g.mu.Unlock()

		returnsWithin(t, p2, "idle queue packet")
		<-closeDone
		wantOrder(t, iter, g.order(), 0, 1, 2)
		if pending.Load() != 0 {
			t.Fatalf("iteration %d: pending=%d", iter, pending.Load())
		}
	}
}

// TestAsyncTunWriteCloseWaitsForAnInlineWriteInProgress is the mechanism
// behind Sol-S1-T1-1: an inline write, idle-queue or fragment, holds the
// lifecycle lock until write(2) returns, so close cannot mark the queues
// closed while it is in progress. Turn 1 held nothing on either path, so close
// began in the middle of the write.
func TestAsyncTunWriteCloseWaitsForAnInlineWriteInProgress(t *testing.T) {
	for _, frag := range []bool{false, true} {
		for iter := 0; iter < 20; iter++ {
			g := newGlobalHold(2, 0, 2) // gap 0: queue 1 is idle; hold seq 2 in write(2)
			var pending atomic.Int64
			pkt := seqPacket(t, "192.0.2.1", 2)
			if frag {
				pkt = fragment(pkt, false)
			}
			p2 := g.submitAsync(1, &pending, pkt)
			g.waitIn(t, 2)

			marked := make(chan struct{})
			g.q.testHookClosed = func() { close(marked) }
			closeDone := make(chan struct{})
			go func() {
				g.q.close()
				close(closeDone)
			}()
			select {
			case <-marked:
				t.Fatalf("fragment=%v iteration %d: close marked the queues closed during an inline write", frag, iter)
			case <-time.After(10 * time.Millisecond):
			}

			g.mu.Lock()
			close(g.hold[2])
			g.mu.Unlock()
			returnsWithin(t, p2, "the inline packet")
			<-closeDone
			if st := g.q.stats(); st.Inline != 1 || st.Queued != 0 || pending.Load() != 0 {
				t.Fatalf("fragment=%v iteration %d: stats %+v pending %d: want one inline write", frag, iter, st, pending.Load())
			}
		}
	}
}
