package session

import (
	"time"
	"unsafe"

	"winsvpn.local/winnprotocol/winn3/aqm"
)

// Send-queue fair queueing (SetSendQueueFQ).
//
// TUNNEL-SPEED-2 Turn 5. On Canada (census/T_A1_*, G-C build) the single FIFO
// send queue with CoDel still rose from 0 to 8,192 inner packets within a
// second or two of each download burst and refused 1,164 to 4,761 inner
// packets a second at the cap, while CoDel shed only 2 to 233 a second: the
// RFC 8289 control law adds one drop per interval/sqrt(count), which cannot
// answer 32 TCP flows overshooting together. Every probe (the loaded ping to
// 1.1.1.1) waited behind that whole FIFO: 8,192 at the measured 58,000 to
// 67,000 sealed messages a second is 122 to 141 ms.
//
// This is the FQ-CoDel shape (RFC 8290) on the plaintext queue, with the three
// properties the TUNNEL-SPEED round asked of any flow queue:
//   - bounded storage: fqBuckets buckets in a fixed array and one node per
//     queued packet in fixed arrays of SendQueue entries, allocated once;
//   - one hash key for every packet of a flow: the source and destination
//     addresses only, never ports, so a non-first IPv4 fragment (no ports) and
//     the rest of its datagram land in the same bucket;
//   - the 8,192 capacity is unchanged: at the cap the head of the fattest
//     bucket is dropped (counted in DataQueueOverflow), never the arrival, so
//     a sparse flow is not refused because bulk filled the queue.
//
// Dequeue is deficit round robin with a new-flows list served first, so a
// sparse flow (a probe, DNS, a fresh connection) waits for at most one quantum
// per active bucket instead of the whole bulk backlog. Each bucket runs its own
// CoDel at target 5 ms / interval 100 ms on its head. Packets move from here to
// the driver's ready FIFO (d.data, which session/batch.go seals unchanged) a
// readyWindow at a time, just before each poll.

const (
	fqBuckets   = 1024
	fqQuantum   = 1514
	readyWindow = 64
)

type fqBucket struct {
	head, tail int32 // node indices, -1 when empty
	count      int32
	bytes      int
	deficit    int
	codel      aqm.CoDel
	list       int8  // 0 idle, 1 new list, 2 old list
	nextB      int32 // next bucket on its list, -1 at the tail
}

type fqList struct{ head, tail int32 }

type sendFQ struct {
	pkt  [][]byte
	at   []time.Duration
	next []int32
	free int32

	buckets          [fqBuckets]fqBucket
	newList, oldList fqList
	total            int
	seed             uint32
	target, interval time.Duration
}

func newSendFQ(capacity int, target, interval time.Duration, seed uint32) *sendFQ {
	q := &sendFQ{
		pkt:      make([][]byte, capacity),
		at:       make([]time.Duration, capacity),
		next:     make([]int32, capacity),
		seed:     seed,
		target:   target,
		interval: interval,
		newList:  fqList{-1, -1},
		oldList:  fqList{-1, -1},
	}
	for i := range q.next {
		q.next[i] = int32(i + 1)
	}
	if capacity > 0 {
		q.next[capacity-1] = -1
	} else {
		q.free = -1
	}
	for i := range q.buckets {
		q.buckets[i] = fqBucket{head: -1, tail: -1, nextB: -1, codel: aqm.NewCoDel(target, interval)}
	}
	return q
}

// fqKey hashes the source and destination addresses of an inner IP packet.
// Ports are deliberately excluded (see the file comment).
func (q *sendFQ) fqKey(p []byte) int {
	h := 2166136261 ^ q.seed
	mix := func(b []byte) {
		for _, c := range b {
			h ^= uint32(c)
			h *= 16777619
		}
	}
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		mix(p[12:20])
	case len(p) >= 40 && p[0]>>4 == 6:
		mix(p[8:40])
	}
	return int(h % fqBuckets)
}

func (l *fqList) push(q *sendFQ, b int32) {
	q.buckets[b].nextB = -1
	if l.tail < 0 {
		l.head = b
	} else {
		q.buckets[l.tail].nextB = b
	}
	l.tail = b
}

func (l *fqList) pop(q *sendFQ) int32 {
	b := l.head
	l.head = q.buckets[b].nextB
	if l.head < 0 {
		l.tail = -1
	}
	q.buckets[b].nextB = -1
	return b
}

// enqueue stores p, which the caller has already copied into a pooled buffer.
// It reports false only when no node is free; the caller makes room first.
func (q *sendFQ) enqueue(p []byte, at time.Duration) bool {
	n := q.free
	if n < 0 {
		return false
	}
	q.free = q.next[n]
	q.pkt[n], q.at[n], q.next[n] = p, at, -1
	b := int32(q.fqKey(p))
	bk := &q.buckets[b]
	if bk.tail < 0 {
		bk.head = n
	} else {
		q.next[bk.tail] = n
	}
	bk.tail = n
	bk.count++
	bk.bytes += len(p)
	q.total++
	if bk.list == 0 {
		bk.list = 1
		bk.deficit = fqQuantum
		q.newList.push(q, b)
	}
	return true
}

// popHead removes and returns the head packet of bucket b.
func (q *sendFQ) popHead(b int32) ([]byte, time.Duration) {
	bk := &q.buckets[b]
	n := bk.head
	p, at := q.pkt[n], q.at[n]
	bk.head = q.next[n]
	if bk.head < 0 {
		bk.tail = -1
	}
	bk.count--
	bk.bytes -= len(p)
	q.total--
	q.pkt[n], q.at[n] = nil, 0
	q.next[n] = q.free
	q.free = n
	return p, at
}

// dropFattest drops the head of the bucket holding the most bytes and returns
// it for recycling. Only active buckets are scanned.
func (q *sendFQ) dropFattest() []byte {
	best, bestBytes := int32(-1), -1
	for _, l := range []fqList{q.newList, q.oldList} {
		for b := l.head; b >= 0; b = q.buckets[b].nextB {
			if q.buckets[b].count > 0 && q.buckets[b].bytes > bestBytes {
				best, bestBytes = b, q.buckets[b].bytes
			}
		}
	}
	if best < 0 {
		return nil
	}
	p, _ := q.popHead(best)
	return p
}

// dequeue returns the next packet by DRR with per-bucket CoDel, recycling
// every packet CoDel drops through drop. It returns nil when nothing is queued.
func (q *sendFQ) dequeue(now time.Duration, drop func([]byte)) []byte {
	for {
		var l *fqList
		switch {
		case q.newList.head >= 0:
			l = &q.newList
		case q.oldList.head >= 0:
			l = &q.oldList
		default:
			return nil
		}
		b := l.head
		bk := &q.buckets[b]
		if bk.deficit <= 0 {
			bk.deficit += fqQuantum
			l.pop(q)
			bk.list = 2
			q.oldList.push(q, b)
			continue
		}
		if bk.count == 0 {
			l.pop(q)
			if l == &q.newList {
				// RFC 8290: an emptied new flow moves to the old list once,
				// so it cannot rejoin the new list at every packet.
				bk.list = 2
				q.oldList.push(q, b)
			} else {
				bk.list = 0
				bk.codel.Empty()
			}
			continue
		}
		p, at := q.popHead(b)
		if bk.codel.Decide(now, now-at, int(bk.count)+1) {
			drop(p)
			continue
		}
		bk.deficit -= len(p)
		return p
	}
}

// each visits every queued packet.
func (q *sendFQ) each(f func([]byte)) {
	for b := range q.buckets {
		for n := q.buckets[b].head; n >= 0; n = q.next[n] {
			f(q.pkt[n])
		}
	}
}

// drain removes every queued packet, handing each to f.
func (q *sendFQ) drain(f func([]byte)) {
	for b := int32(0); b < fqBuckets; b++ {
		for q.buckets[b].count > 0 {
			p, _ := q.popHead(b)
			f(p)
		}
		q.buckets[b].list, q.buckets[b].nextB, q.buckets[b].deficit = 0, -1, 0
		q.buckets[b].codel = aqm.NewCoDel(q.target, q.interval)
	}
	q.newList, q.oldList = fqList{-1, -1}, fqList{-1, -1}
}

// queuedDataLen is every inner packet accepted and not yet sealed: the ready
// FIFO plus, under SetSendQueueFQ, the flow queues. Callers hold d.mu.
func (d *Driver) queuedDataLen() int {
	n := len(d.data)
	if d.fq != nil {
		n += d.fq.total
	}
	return n
}

// SendFQBytes is the live storage SetSendQueueFQ allocates for a SendQueue of
// capacity, on top of the packet slabs the send queue already bills (the
// flow queues and the ready FIFO together never hold more than SendQueue
// packets, fqAdmit): the sendFQ struct with its 1024 buckets, and one slice
// header, one enqueue time and one free-list link per slot. Each of the four
// allocations is a large object at production sizes, so each is rounded up to
// the runtime's 8 KiB page.
func SendFQBytes(capacity int) int {
	c := max(capacity, readyWindow)
	page := func(n int) int { return (n + 8191) &^ 8191 }
	return page(int(unsafe.Sizeof(sendFQ{}))) +
		page(c*int(unsafe.Sizeof([]byte(nil)))) +
		page(c*int(unsafe.Sizeof(time.Duration(0)))) +
		page(c*int(unsafe.Sizeof(int32(0))))
}

// SetSendQueueFQ replaces the single send FIFO with per-host-pair fair
// queueing and per-bucket CoDel at the RFC 8289 defaults. The SendQueue
// capacity is unchanged. The FIFO cull (CullSendQueue) stands down, because
// the buckets carry their own. Call it before data is queued; it cannot be
// turned off again on a live session.
func (d *Driver) SetSendQueueFQ() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fq != nil {
		return
	}
	d.fqBase = d.cfg.Clock.Now()
	d.fq = newSendFQ(max(d.cfg.SendQueue, readyWindow), aqm.DefaultTarget, aqm.DefaultInterval,
		uint32(d.fqBase.UnixNano()))
	d.fqOn.Store(true)
}

// fqAdmit stores one copied inner packet in the flow queues, making room at
// the cap by dropping the head of the fattest bucket. Callers hold d.mu.
func (d *Driver) fqAdmit(p []byte) error {
	if d.queuedDataLen() >= d.cfg.SendQueue {
		old := d.fq.dropFattest()
		if old != nil {
			d.recycleDataBuf(old)
		} else if len(d.data) > 0 {
			// Every queued packet is already in the ready window (SendQueue
			// at or below readyWindow): drop its head, never the arrival.
			d.consumeQueuedData(1)
		} else {
			d.recycleDataBuf(p)
			return ErrQueueFull
		}
		d.stats.DataQueueOverflow++
	}
	if !d.fq.enqueue(p, d.cfg.Clock.Now().Sub(d.fqBase)) {
		d.recycleDataBuf(p)
		return ErrQueueFull
	}
	return nil
}

// FillSendWindow moves up to readyWindow packets from the flow queues into
// the ready FIFO that the sealers read, by DRR with per-bucket CoDel, and
// reports how many CoDel dropped (also counted in DataQueueDropped). The pump
// calls it before every poll. It does nothing unless SetSendQueueFQ was called.
func (d *Driver) FillSendWindow() int {
	if !d.fqOn.Load() {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fq == nil || !d.dataMayFlow() || d.fq.total == 0 {
		return 0
	}
	wall := d.cfg.Clock.Now()
	now := wall.Sub(d.fqBase)
	shed := 0
	drop := func(p []byte) {
		d.recycleDataBuf(p)
		shed++
	}
	for len(d.data) < readyWindow {
		p := d.fq.dequeue(now, drop)
		if p == nil {
			break
		}
		// d.dataAt mirrors d.data entry for entry (sendqueue_codel.go); the
		// ready window carries the time it entered the window.
		d.appendQueuedData(p)
		d.appendQueuedAt(wall)
	}
	d.stats.DataQueueDropped += uint64(shed)
	return shed
}
