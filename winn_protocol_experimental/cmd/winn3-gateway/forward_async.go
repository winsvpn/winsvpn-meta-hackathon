package main

import (
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// This file is -forward-async-write: the forward direction's kernel write
// moved off the session goroutine and onto one writer goroutine per shared
// TUN queue. It is portable and carries no build tag, like the rest of
// forward.go, so its ordering, backpressure and teardown properties are tested
// on any OS; forward_linux.go only wires it to the real queue descriptors.
//
// # Why
//
// Measured on the L63 rig (2026-09-26, Linux 6.8 arm64 VM, one session): the
// uplink stops scaling at about 1.5 to 1.65 Gbit/s whether the gateway has 2
// or 4 CPUs, with the per-session inbox overflowing while the process uses
// about 1.1 of its CPUs. The saturated goroutine is the session's
// driver.Loop.readLoop, and 55% of its CPU is the one write(2) per packet this
// file takes away from it (a TUN write also runs the kernel's whole forward
// path for that packet before it returns). The remainder, the batch open and
// commit, stays where it is. Without this, a gateway with more cores than one
// session can use carries that session no faster.
//
// # Ordering
//
// A packet is queued to the SAME queue index the synchronous path writes it
// to (sharedGatewayTun.queueFor, the inner source and port hash), and each
// queue has exactly one writer goroutine draining a FIFO. Packets of one flow
// therefore reach the kernel in the order the session delivered them, exactly
// as they did when the session wrote them itself. Packets of two different
// flows on two queues may now be written in either order relative to each
// other, which nothing above the IP layer can observe as reordering.
//
// # Inline when idle (revision 2)
//
// Handing EVERY packet to a writer costs a goroutine wakeup per packet, and at
// low packet rates that wakeup is all the handoff buys: revision 1 raised
// loaded RTT p50 by 0.2 to 1 ms on the rig's cellular profile, where the
// gateway was 2 to 13% busy. So submit writes the packet itself, on the
// session's goroutine exactly as the synchronous path does, when the queue is
// idle: nothing of it queued or being written (inflight == 0) and no submit
// to it within tunWriteInlineGap. It hands off only while the queue is busy,
// which is when the pipelining pays for the wakeup.
//
// The gap term is what keeps one busy session pipelined. A session's own
// inline write is synchronous, so by the time it submits its next packet its
// previous one is always done and inflight alone would read idle forever:
// every packet would go inline and one session could again use one core. A
// submit less than tunWriteInlineGap after the previous one is a burst, and a
// burst is handed off.
//
// Ordering (revision 3.4, precisely): per-flow order holds because (1) a
// flow's packets are submitted by one goroutine, its session's readLoop, and
// (2) sharedGatewayTun.queueFor maps every unfragmented packet of a flow to
// one queue (TCP and UDP by source and ports, other IPv4 by source, IPv6 to
// queue 0; the queue count is fixed at startup). A non-first IPv4 fragment
// carries no ports, so queueFor can map it to a different queue than the
// rest of its flow. Therefore a fragment is never handed off: it waits until
// every packet already accepted on EVERY queue has been written, then is
// written inline (fragmentBarrier). Within one queue, inline is allowed only
// when inflight is zero, and inflight counts
// every packet from acceptance until its write(2) returns,
// inline writes included. A flow's packets are submitted by one goroutine (its
// session's readLoop), so a later packet of a flow can never be written inline
// while an earlier one is still queued or in write(2).
//
// # Backpressure and latency
//
// A full queue BLOCKS the submitting session rather than dropping: the session
// goroutine was already blocked for the length of every write(2), so this adds
// no new loss point, and the inbox in front of the session keeps its role as
// the only place uplink overload is shed. The depth is small on purpose. A
// queue holds at most tunWriteQueueDepth packets, about 0.3 ms of writes at
// the measured 2.2 us per write, so the standing delay it can add is far below
// the round-trip repeatability the Round X acceptance rule measures against.
//
// # Teardown (revisions 3.2 and 3.3)
//
// Every packet accepted here is written: by its queue's writer, or, once the
// shared device has begun shutting down, inline by the submitting session, as
// the synchronous path would. No packet is ever enqueued after close begins,
// and (3.3) no inline write happens after close begins until every writer has
// written everything it still held: a later packet of a flow must not
// overtake an earlier one still queued for a draining writer (Round X Turn 2,
// Seat C, OI-XB3).
// A lifecycle lock makes that exact: submit holds it (shared) from its
// "still open?" check until the packet is written or enqueued, whichever
// path it takes (the idle inline write, the fragment barrier and its inline
// write, or the channel send), and close takes it (exclusive) to mark the
// queues closed before it stops the writers. So close cannot begin between
// an open check and the write it allowed (Round S1 review, Sol-S1-T1-1: the
// idle inline path wrote outside the hold), and a send can never land in a
// queue whose writer has already drained it and exited (Round X re-vote,
// Seat C, OI-XB3: revision 3.1 had that window, and it stranded the packet
// and its session's pending count). The writers, when stopped, write
// whatever is still queued before they exit.
//
// Per session: gatewayForwardDevice.Close waits for every packet its session
// queued to be written before it returns, so after Close nothing more of that
// session reaches the kernel. The one difference from the synchronous
// path is the window between the tun gate latching down (driver.Loop.Run) and
// Close (releasePeer, immediately after Run returns): packets the session had
// already validated, authorized and queued may still be written inside that
// window, where the synchronous path had written them before the gate closed.
// No packet is validated or authorized after the gate closes either way.

// maxGatewayTunQueues bounds how many IFF_MULTI_QUEUE descriptors the shared
// device opens, and so how many writer goroutines this file can start.
const maxGatewayTunQueues = 4

// tunWriteQueueDepth is each queue's FIFO depth. See the file doc.
const tunWriteQueueDepth = 128

// tunWriteInlineGap is how long a queue must have gone without a submit
// before an idle queue's packet is written inline. 20 us is a 50,000 packet/s
// instantaneous rate on one queue, about 550 Mbit/s of full-size packets;
// below it the handoff wakeup costs more than it can save. See the file doc.
const tunWriteInlineGap = 20 * time.Microsecond

// tunWriteSlabBill is what one queued packet can hold live: a pooled slab
// sized to the interface MTU, which is at most the 2 KiB this bills.
const tunWriteSlabBill = 2048

// asyncTunWriteBill is the process-wide live memory -forward-async-write can
// hold: every queue full, plus the packet inside each writer's write(2), each
// in a slab billed at tunWriteSlabBill, plus the channel backing. A session
// blocked on a full queue holds one more slab of its own; that term scales
// with sessions and is billed per session (asyncSubmitSessionBill). It is
// billed whether or not the flag is on, which only makes the bill larger.
// -tun-gso adds one frame buffer and one run's views and items per writer.
func asyncTunWriteBill() int {
	item := int(unsafe.Sizeof(tunWriteItem{}))
	view := int(unsafe.Sizeof([]byte(nil)))
	gso := vnetHdrLen + gsoMaxIPTotal + gsoMaxMembers*(view+item)
	return maxGatewayTunQueues * ((tunWriteQueueDepth+1)*tunWriteSlabBill + tunWriteQueueDepth*item + gso)
}

// asyncSubmitSessionBill is the slab one session holds while its submit waits
// on a full queue (see submit).
const asyncSubmitSessionBill = tunWriteSlabBill

// tunWriteItem is one queued packet.
type tunWriteItem struct {
	buf     *[]byte
	n       int
	pending *atomic.Int64
}

// tunQueueState is one queue's inline-or-handoff bookkeeping. See the file doc.
type tunQueueState struct {
	mu         sync.Mutex
	inflight   int   // accepted and not yet written; inline writes included
	lastSubmit int64 // ns since tunWriteQueues.epoch of the previous submit

	// accepted counts packets handed to this queue's writer (counted before
	// the channel send) and done counts those the writer has finished,
	// written or refused. fragmentBarrier waits for done to reach a snapshot
	// of accepted on every queue.
	accepted atomic.Uint64
	done     atomic.Uint64
}

// writeInline is the inline-or-handoff decision, kept pure so tests and
// mutants address it directly: inline only when nothing of this queue is
// queued or being written, and the queue is not in a burst.
func writeInline(inflight int, sinceLast, gap time.Duration) bool {
	return inflight == 0 && sinceLast >= gap
}

// tunWriteQueues is the writer side of -forward-async-write.
type tunWriteQueues struct {
	write  func(queue int, pkt []byte) (int, error)
	onFail func()

	// gap is tunWriteInlineGap in production; tests set it. epoch anchors
	// the monotonic clock lastSubmit is read against.
	gap   time.Duration
	epoch time.Time
	state []tunQueueState

	queues  []chan tunWriteItem
	stop    chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
	slabs   sync.Pool

	// life orders every submit's write or enqueue (inline, fragment or
	// handoff) against close; see the file doc. closed is written only
	// under life held exclusively. drained is closed once every writer has
	// written what it held and returned; a submit that finds the queues
	// closed waits on it before its inline write.
	life      sync.RWMutex
	closed    bool
	drained   chan struct{}
	drainOnce sync.Once
	// closing is closed, readable without the lock: once set, every submit
	// waits for drained before writing (revision 3.4; Round X Turn 3, Seat
	// C, OI-XB3: the idle-queue inline path used to bypass drained).
	closing atomic.Bool

	// testHookBeforeEnqueue, when set by a test, runs between submit's
	// "still open?" check and its channel send: the exact window a close
	// must not be able to slip into.
	testHookBeforeEnqueue func()
	// testHookClosed, when set by a test, runs in close right after the
	// queues are marked closed and before the writers are stopped.
	testHookClosed func()
	// testHookAfterCloseCheck, when set by a test, runs in submit right
	// after its lock-free "closing?" check found the queues open: the window
	// in which close can begin before submit takes life.
	testHookAfterCloseCheck func()

	inline  atomic.Uint64
	queued  atomic.Uint64
	written atomic.Uint64
	failed  atomic.Uint64

	// -tun-gso (tun_gso.go). writeGSO is nil when it is off. Each writer
	// coalesces runs of its own queued items; gsoBufs and gsoViews are that
	// writer's scratch, touched by no other goroutine.
	writeGSO    func(queue int, frame []byte) (int, error)
	gsoBufs     [][]byte
	gsoViews    [][][]byte
	gsoItems    [][]tunWriteItem
	gsoFrames   atomic.Uint64
	gsoSegments atomic.Uint64
}

// enableGSO turns on coalescing in the writers. Call it right after
// newTunWriteQueues, before any submit: the writers read writeGSO only once
// an item arrives.
func (w *tunWriteQueues) enableGSO(write func(queue int, frame []byte) (int, error)) {
	w.gsoBufs = make([][]byte, len(w.queues))
	w.gsoViews = make([][][]byte, len(w.queues))
	w.gsoItems = make([][]tunWriteItem, len(w.queues))
	for i := range w.queues {
		w.gsoBufs[i] = make([]byte, vnetHdrLen+gsoMaxIPTotal)
		w.gsoViews[i] = make([][]byte, 0, gsoMaxMembers)
		w.gsoItems[i] = make([]tunWriteItem, 0, gsoMaxMembers)
	}
	w.writeGSO = write
}

// newTunWriteQueues starts one writer goroutine per queue. write is the
// synchronous write of one packet to one queue descriptor; onFail, when
// non-nil, is called once per packet the kernel refused.
func newTunWriteQueues(queues, depth, slabLen int, write func(int, []byte) (int, error), onFail func()) *tunWriteQueues {
	if queues < 1 {
		queues = 1
	}
	if depth < 1 {
		depth = 1
	}
	w := &tunWriteQueues{write: write, onFail: onFail, stop: make(chan struct{}), drained: make(chan struct{}),
		gap: tunWriteInlineGap, epoch: time.Now(), state: make([]tunQueueState, queues)}
	w.slabs.New = func() any {
		b := make([]byte, slabLen)
		return &b
	}
	w.queues = make([]chan tunWriteItem, queues)
	for i := range w.queues {
		w.queues[i] = make(chan tunWriteItem, depth)
	}
	w.wg.Add(queues)
	for i := range w.queues {
		go w.run(i)
	}
	return w
}

// submit writes pkt inline when its queue is idle or the queues are closing,
// and otherwise copies and queues it (see the file doc). pending is the
// submitting session's count of packets queued and not yet written; it is
// incremented here and decremented by the writer. An inline write never
// touches pending: it is complete when submit returns.
func (w *tunWriteQueues) submit(queue int, pending *atomic.Int64, pkt []byte) (int, error) {
	if queue < 0 || queue >= len(w.queues) {
		queue = 0
	}
	if w.closing.Load() {
		// Close has begun: every writer on every queue writes what it
		// held before any packet is written inline.
		<-w.drained
		return w.writeInlineAccounted(queue, pkt)
	}
	if w.testHookAfterCloseCheck != nil {
		w.testHookAfterCloseCheck()
	}
	// The shared hold covers every path below, the inline write and the
	// fragment barrier as well as the enqueue: close cannot begin while a
	// write decided here is still unwritten (Round S1 review, Sol-S1-T1-1:
	// the idle inline path used to write after close had begun, ahead of
	// packets the writers were still draining).
	w.life.RLock()
	if w.closed {
		// Shutting down: nothing will be enqueued after this, so this
		// packet takes the synchronous path, but only once every writer
		// has written what it still held, so that it cannot overtake an
		// earlier packet of its own flow.
		w.life.RUnlock()
		<-w.drained
		return w.writeInlineAccounted(queue, pkt)
	}
	if isIPv4Fragment(pkt) {
		w.fragmentBarrier()
		n, err := w.writeInlineAccounted(queue, pkt)
		w.life.RUnlock()
		return n, err
	}
	st := &w.state[queue]
	now := int64(time.Since(w.epoch))
	st.mu.Lock()
	// lastSubmit starts at the epoch, so a queue's first submit reads the
	// whole time since construction as its gap.
	since := time.Duration(now - st.lastSubmit)
	st.lastSubmit = now
	inline := writeInline(st.inflight, since, w.gap)
	st.inflight++
	st.mu.Unlock()
	if inline {
		n, err := w.writeInline(queue, pkt)
		w.life.RUnlock()
		return n, err
	}
	bp := w.slabs.Get().(*[]byte)
	if cap(*bp) < len(pkt) {
		b := make([]byte, len(pkt))
		bp = &b
	}
	*bp = (*bp)[:len(pkt)]
	copy(*bp, pkt)
	it := tunWriteItem{buf: bp, n: len(pkt), pending: pending}
	pending.Add(1)
	if w.testHookBeforeEnqueue != nil {
		w.testHookBeforeEnqueue()
	}
	// May block while the queue is full: its writer is still running, since
	// close cannot mark the queues closed, let alone stop the writers, while
	// this shared hold lasts.
	w.state[queue].accepted.Add(1)
	w.queues[queue] <- it
	w.queued.Add(1)
	w.life.RUnlock()
	return len(pkt), nil
}

// isIPv4Fragment reports whether pkt is an IPv4 fragment: more-fragments set
// or a nonzero fragment offset. Such a packet may carry no transport header,
// so queueFor cannot place it with the rest of its flow.
func isIPv4Fragment(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	return (uint16(pkt[6])<<8|uint16(pkt[7]))&0x3fff != 0
}

// fragmentBarrier returns once every packet accepted so far, on every queue,
// has been written or refused. It waits only for work that already exists
// (at most one full queue per writer), so it cannot starve.
func (w *tunWriteQueues) fragmentBarrier() {
	targets := make([]uint64, len(w.state))
	for i := range w.state {
		targets[i] = w.state[i].accepted.Load()
	}
	for i := range w.state {
		for w.state[i].done.Load() < targets[i] {
			time.Sleep(20 * time.Microsecond)
		}
	}
}

// writeInlineAccounted is writeInline for a submit that did not take the
// inline decision: it counts the packet in flight on its queue first.
func (w *tunWriteQueues) writeInlineAccounted(queue int, pkt []byte) (int, error) {
	st := &w.state[queue]
	st.mu.Lock()
	st.inflight++
	st.mu.Unlock()
	return w.writeInline(queue, pkt)
}

// writeInline is the synchronous path, on the caller's goroutine. A refusal
// is returned to WritePacket, which counts it exactly as it counts a
// synchronous one, so onFail is not called here.
func (w *tunWriteQueues) writeInline(queue int, pkt []byte) (int, error) {
	n, err := w.write(queue, pkt)
	w.release(queue)
	w.inline.Add(1)
	if err != nil || n != len(pkt) {
		w.failed.Add(1)
	}
	return n, err
}

// release ends one accepted packet's life on queue.
func (w *tunWriteQueues) release(queue int) {
	st := &w.state[queue]
	st.mu.Lock()
	st.inflight--
	st.mu.Unlock()
}

func (w *tunWriteQueues) run(queue int) {
	defer w.wg.Done()
	ch := w.queues[queue]
	for {
		select {
		case it := <-ch:
			if w.writeGSO != nil {
				w.doRun(queue, it, ch)
				continue
			}
			w.do(queue, it)
		case <-w.stop:
			// close marked the queues closed before stopping us, so
			// nothing can be enqueued any more: write what is left.
			for {
				select {
				case it := <-ch:
					w.do(queue, it)
				default:
					return
				}
			}
		}
	}
}

// doRun takes it plus whatever else this queue already holds (up to
// gsoMaxMembers), and writes them in FIFO order: each coalescible run as one
// GSO frame, everything else one packet at a time through do. A frame the
// kernel refuses falls back to per-packet writes of its members, so the loss
// profile is never worse than without -tun-gso.
func (w *tunWriteQueues) doRun(queue int, first tunWriteItem, ch chan tunWriteItem) {
	items := append(w.gsoItems[queue][:0], first)
	for len(items) < gsoMaxMembers {
		select {
		case it := <-ch:
			items = append(items, it)
			continue
		default:
		}
		break
	}
	views := w.gsoViews[queue][:0]
	for _, it := range items {
		views = append(views, (*it.buf)[:it.n])
	}
	for i := 0; i < len(items); {
		run := gsoRun(views[i:])
		if run < 2 {
			w.do(queue, items[i])
			i++
			continue
		}
		frame := buildGSO(views[i:i+run], w.gsoBufs[queue])
		n, err := w.writeGSO(queue, frame)
		// The frame is plaintext, like the slabs: clear it before anything
		// else can observe the queue as drained.
		clear(frame)
		if err != nil || n != len(frame) {
			for _, it := range items[i : i+run] {
				w.do(queue, it)
			}
			i += run
			continue
		}
		w.gsoFrames.Add(1)
		w.gsoSegments.Add(uint64(run))
		for _, it := range items[i : i+run] {
			w.written.Add(1)
			w.recycle(it)
			w.release(queue)
			w.state[queue].done.Add(1)
		}
		i += run
	}
	clear(views)
	clear(items)
	w.gsoViews[queue] = views[:0]
	w.gsoItems[queue] = items[:0]
}

func (w *tunWriteQueues) do(queue int, it tunWriteItem) {
	n, err := w.write(queue, (*it.buf)[:it.n])
	if err != nil || n != it.n {
		w.failed.Add(1)
		if w.onFail != nil {
			w.onFail()
		}
	} else {
		w.written.Add(1)
	}
	w.recycle(it)
	w.release(queue)
	w.state[queue].done.Add(1)
}

// recycle clears the packet bytes before the slab returns to the pool, as the
// pipe does for its own slabs, and only then releases the session's count, so
// a Close that observes zero pending also observes no plaintext in flight.
func (w *tunWriteQueues) recycle(it tunWriteItem) {
	clear((*it.buf)[:it.n])
	w.slabs.Put(it.buf)
	it.pending.Add(-1)
}

// close marks the queues closed (later submits write inline, after the
// drain), stops the writers, which write whatever is still queued, waits for
// them, and then releases the waiting inline writers. It is idempotent.
func (w *tunWriteQueues) close() {
	w.life.Lock()
	w.closed = true
	w.closing.Store(true)
	w.life.Unlock()
	if w.testHookClosed != nil {
		w.testHookClosed()
	}
	w.stopped.Do(func() { close(w.stop) })
	w.wg.Wait()
	w.drainOnce.Do(func() { close(w.drained) })
}

// tunWriteQueueStats is the -forward-async-write half of the shared device's
// status. Every field is zero, and omitted, when the flag is off.
type tunWriteQueueStats struct {
	Inline  uint64 `json:"async_inline,omitempty"`
	Queued  uint64 `json:"async_queued,omitempty"`
	Written uint64 `json:"async_written,omitempty"`
	Failed  uint64 `json:"async_write_failed,omitempty"`
	// GSOFrames and GSOSegments count -tun-gso super packets and the queued
	// packets they carried. Omitted when the flag is off.
	GSOFrames   uint64 `json:"tun_gso_frames,omitempty"`
	GSOSegments uint64 `json:"tun_gso_segments,omitempty"`
}

func (w *tunWriteQueues) stats() tunWriteQueueStats {
	if w == nil {
		return tunWriteQueueStats{}
	}
	return tunWriteQueueStats{
		Inline:      w.inline.Load(),
		Queued:      w.queued.Load(),
		Written:     w.written.Load(),
		Failed:      w.failed.Load(),
		GSOFrames:   w.gsoFrames.Load(),
		GSOSegments: w.gsoSegments.Load(),
	}
}

// trackedWriter is implemented by a shared device that may complete a write
// after returning. gatewayForwardDevice uses it, when present and enabled, so
// that its Close can wait for its own queued packets.
type trackedWriter interface {
	asyncWrites() bool
	writeTracked(pending *atomic.Int64, pkt []byte) (int, error)
}
