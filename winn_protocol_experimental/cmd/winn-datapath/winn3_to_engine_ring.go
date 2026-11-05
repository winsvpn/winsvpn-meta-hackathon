package main

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// winn3DrainLowWaterDefault is 1: a packet that is already queued is drained
// now. It was 16, which parked the tun reader for up to winn3DrainMaxPark
// whenever fewer than 16 uplink packets were waiting, because a push only
// signals on 0 to 1 and on crossing the low-water mark. That park put up to
// 250 microseconds, and its jitter, on every sparse uplink packet (a ping, an
// interactive keystroke, the ACK stream of a download) and bought batching
// only where none was needed: under a bulk upload the host already hands
// pushes of up to 512 packets, and the write loop batches whatever the
// session queue holds when it wakes. WINN3_DRAIN_LOW_WATER still sets the old
// gate for an A/B run.
const (
	winn3RingPushBatch        = 512
	winn3RingPopBatch         = 256
	winn3DrainLowWaterDefault = 1
	winn3DrainLowWater        = winn3DrainLowWaterDefault
	winn3DrainMaxPark         = 250 * time.Microsecond
)

var ringTimerPool = sync.Pool{
	New: func() any {
		t := time.NewTimer(time.Hour)
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		return t
	},
}

// toEngineRing is a lock-batched circular ring buffer for the uplink queue with
// transmit drain gating (txDrainGate) to prevent carrier batch starvation.
// It replaces the scalar Go channel to eliminate per-packet mutex contention
// and cross-core cache-line bouncing at wire speed.
// It transfers slice headers under its mutex, keeping payload copies and
// packetPool recycling strictly outside the critical section.
type toEngineRing struct {
	mu            sync.Mutex
	notify        chan struct{}
	storage       [][]byte
	mask          int
	head          int
	count         int
	closed        bool
	lowWater      int
	maxPark       time.Duration
	wakeThreshold atomic.Uint64
	wakeZero      atomic.Uint64
	wakePark      atomic.Uint64
	popLenSum     atomic.Uint64
	popCalls      atomic.Uint64

	// highWater is the deepest the ring has been since it was built. It is
	// raised under mu by the single producer and read without it, so it is a
	// monotone census of the standing uplink queue, not an instant reading.
	highWater atomic.Uint64
}

func newToEngineRing(capacity int) *toEngineRing {
	if capacity <= 0 || (capacity&(capacity-1)) != 0 {
		panic("toEngine ring capacity must be a positive power of two")
	}
	lw := winn3DrainLowWaterDefault
	if envVal := os.Getenv("WINN3_DRAIN_LOW_WATER"); envVal != "" {
		if v, err := strconv.Atoi(envVal); err == nil && v > 0 {
			lw = v
		}
	}
	if lw > capacity {
		lw = capacity
	}
	r := &toEngineRing{
		storage:  make([][]byte, capacity),
		mask:     capacity - 1,
		notify:   make(chan struct{}, 1),
		lowWater: lw,
		maxPark:  winn3DrainMaxPark,
	}
	return r
}

func (r *toEngineRing) signalNotify() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// pushBatch enqueues multiple slice headers under a single mutex lock.
// It applies tail drop if the ring would overflow: the newest packets are
// dropped and the existing head is preserved.
// Returns (acceptedCount, isOpen).
func (r *toEngineRing) pushBatch(packets [][]byte) (int, bool) {
	if len(packets) == 0 {
		return 0, true
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, false
	}
	available := len(r.storage) - r.count
	n := len(packets)
	if n > available {
		n = available
	}
	oldCount := r.count
	if n > 0 {
		tail := (r.head + r.count) & r.mask
		first := len(r.storage) - tail
		if first > n {
			first = n
		}
		copy(r.storage[tail:tail+first], packets[:first])
		if second := n - first; second > 0 {
			copy(r.storage[:second], packets[first:n])
		}
		r.count += n
	}
	newCount := r.count
	r.noteDepthLocked(newCount)
	r.mu.Unlock()

	if oldCount == 0 {
		r.wakeZero.Add(1)
		r.signalNotify()
	} else if oldCount < r.lowWater && newCount >= r.lowWater {
		r.wakeThreshold.Add(1)
		r.signalNotify()
	}
	return n, true
}

// noteDepthLocked raises the high-water mark. Called with mu held, so the
// compare and the store cannot interleave with another producer's.
func (r *toEngineRing) noteDepthLocked(depth int) {
	if d := uint64(depth); d > r.highWater.Load() {
		r.highWater.Store(d)
	}
}

// pushOne enqueues a single packet.
// Returns (accepted, isOpen).
func (r *toEngineRing) pushOne(pkt []byte) (accepted, open bool) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false, false
	}
	if r.count == len(r.storage) {
		r.mu.Unlock()
		return false, true
	}
	oldCount := r.count
	r.storage[(r.head+r.count)&r.mask] = pkt
	r.count++
	newCount := r.count
	r.noteDepthLocked(newCount)
	r.mu.Unlock()

	if oldCount == 0 {
		r.wakeZero.Add(1)
		r.signalNotify()
	} else if oldCount < r.lowWater && newCount >= r.lowWater {
		r.wakeThreshold.Add(1)
		r.signalNotify()
	}
	return true, true
}

// popBatch blocks until at least one packet is queued or the ring is closed,
// then moves up to len(dst) slice headers out under one lock acquisition.
// When fewer than lowWater packets are queued, it parks for up to maxPark
// to accumulate burst packets, preventing carrier batch starvation.
// Returns (drainedCount, isOpenOrHasBacklog).
// Reports (0, false) only when the ring is both closed and empty.
func (r *toEngineRing) popBatch(dst [][]byte) (int, bool) {
	if len(dst) == 0 {
		return 0, true
	}
	for {
		r.mu.Lock()
		if r.closed && r.count == 0 {
			r.mu.Unlock()
			return 0, false
		}
		if r.count >= r.lowWater || (r.closed && r.count > 0) {
			return r.drainLocked(dst)
		}
		if r.count > 0 {
			r.mu.Unlock()
			t := ringTimerPool.Get().(*time.Timer)
			t.Reset(r.maxPark)
			select {
			case <-r.notify:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				ringTimerPool.Put(t)
				continue
			case <-t.C:
				ringTimerPool.Put(t)
				r.wakePark.Add(1)
				r.mu.Lock()
				if r.count > 0 {
					return r.drainLocked(dst)
				}
				r.mu.Unlock()
				continue
			}
		}
		r.mu.Unlock()
		<-r.notify
	}
}

func (r *toEngineRing) drainLocked(dst [][]byte) (int, bool) {
	n := r.count
	if n > len(dst) {
		n = len(dst)
	}
	first := len(r.storage) - r.head
	if first > n {
		first = n
	}
	copy(dst[:first], r.storage[r.head:r.head+first])
	for i := r.head; i < r.head+first; i++ {
		r.storage[i] = nil
	}
	if second := n - first; second > 0 {
		copy(dst[first:n], r.storage[:second])
		for i := 0; i < second; i++ {
			r.storage[i] = nil
		}
	}
	r.head = (r.head + n) & r.mask
	r.count -= n
	remainder := r.count
	r.popCalls.Add(1)
	r.popLenSum.Add(uint64(n))
	r.mu.Unlock()

	if remainder > 0 {
		r.signalNotify()
	}
	return n, true
}

// popOne blocks until one packet is available or the ring is closed and empty.
func (r *toEngineRing) popOne() ([]byte, bool) {
	for {
		r.mu.Lock()
		if r.closed && r.count == 0 {
			r.mu.Unlock()
			return nil, false
		}
		if r.count > 0 {
			pkt := r.storage[r.head]
			r.storage[r.head] = nil
			r.head = (r.head + 1) & r.mask
			r.count--
			remainder := r.count
			r.mu.Unlock()
			if remainder > 0 {
				r.signalNotify()
			}
			return pkt, true
		}
		r.mu.Unlock()
		<-r.notify
	}
}

// close marks the ring closed and wakes every waiter.
func (r *toEngineRing) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.mu.Unlock()
	r.signalNotify()
}

// drain returns all remaining queued packets, leaving the ring empty.
// Called during Close after the frame pump has terminated.
func (r *toEngineRing) drain() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return nil
	}
	out := make([][]byte, r.count)
	first := len(r.storage) - r.head
	if first > r.count {
		first = r.count
	}
	copy(out[:first], r.storage[r.head:r.head+first])
	for i := r.head; i < r.head+first; i++ {
		r.storage[i] = nil
	}
	if second := r.count - first; second > 0 {
		copy(out[first:], r.storage[:second])
		for i := 0; i < second; i++ {
			r.storage[i] = nil
		}
	}
	r.head = 0
	r.count = 0
	return out
}

// depth returns the current number of packets in the ring.
func (r *toEngineRing) depth() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// RingTelemetry captures atomic counters measuring batch occupancy and wake attribution.
type RingTelemetry struct {
	WakeThreshold uint64
	WakeZero      uint64
	WakePark      uint64
	PopLenSum     uint64
	PopCalls      uint64
	HighWater     uint64
}

func (r *toEngineRing) Telemetry() RingTelemetry {
	return RingTelemetry{
		WakeThreshold: r.wakeThreshold.Load(),
		WakeZero:      r.wakeZero.Load(),
		WakePark:      r.wakePark.Load(),
		PopLenSum:     r.popLenSum.Load(),
		PopCalls:      r.popCalls.Load(),
		HighWater:     r.highWater.Load(),
	}
}
