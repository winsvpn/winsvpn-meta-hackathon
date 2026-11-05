package session

import (
	"math"
	"time"
)

// This file is item 6 of the tunnel-speed deferral table: CoDel queue
// management on the session send queue. The queue is where the gateway's
// downlink stands (measured on Canada 2026-10-09: send_queue_depth at its
// 8192 cap in 8 of 10 runs, ens3 fq backlog to 10,617 packets, loaded ping
// p95 206 to 242 ms against 60 to 78 idle, throughput steady at 717 to
// 789 Mbit/s with no loss): a standing FIFO that inner TCP cannot see past.
// Tail drop at Config.SendQueue only fires at the very top of that queue, so
// TCP fills all of it and keeps it filled. CoDel drops from the HEAD when the
// head's sojourn exceeds the target for long enough, which turns the queue
// depth TCP settles at from "the whole queue" into "about one target's worth
// of packets", without shrinking the capacity (item 8's first capacity-only
// rule: the 8192 slots stay; nothing here lowers any cap).
//
// The drop point is the DEQUEUE side, as in CoDel proper: CullSendQueue runs
// on the pump's drain path (driver.Loop.drain calls it at the top of every
// iteration, stalled or not), where the head packet's sojourn is knowable and
// where dropping is one fewer seal rather than a silent refusal the enqueue
// side would count as ErrQueueFull. Inner TCP reacts to the induced loss the
// way it reacts to any loss: the far sender's window shrinks toward the true
// bandwidth-delay product and the queue drains. The counter is
// Stats.DataQueueDropped, published by the gateway as send_queue_dropped.

// SendQueueCoDelTarget is the sojourn above which the queue is considered
// standing. 5 ms is the value fq_codel ships: at the gateway's ~800 Mbit/s
// downlink that is about 350 standing packets, and a probe or ACK queued
// behind them waits one target, not the whole queue.
const SendQueueCoDelTarget = 5 * time.Millisecond

// SendQueueCoDelInterval is how long the head sojourn must stay above the
// target before dropping begins, and the base of the drop schedule while it
// stays above it (the schedule divides by sqrt(count), CoDel's Newton step).
const SendQueueCoDelInterval = 100 * time.Millisecond

// sendQueueCoDelMaxDrop bounds one cull pass so a very stale queue cannot
// spend an unbounded slice of one drain emptying itself.
const sendQueueCoDelMaxDrop = 64

// codelState is the drop schedule. All fields are guarded by d.mu.
type codelState struct {
	dropping   bool
	count      int
	firstAbove time.Time
	dropNext   time.Time
}

// appendQueuedAt mirrors appendQueuedData's storage moves for the enqueue-time
// ring, so d.dataAt[i] is always the time d.data[i] was enqueued. Callers hold
// d.mu and append exactly one entry per appendQueuedData call. consumeQueuedData
// and discardQueuedData keep the two rings aligned on the way out.
func (d *Driver) appendQueuedAt(t time.Time) {
	if len(d.dataAt) == cap(d.dataAt) {
		if cap(d.dataAtBase) > 0 && len(d.dataAt) <= cap(d.dataAtBase)/2 {
			storage := d.dataAtBase[:cap(d.dataAtBase)]
			n := copy(storage, d.dataAt)
			d.dataAt = storage[:n]
		} else {
			d.dataAt = append(d.dataAt, t)
			d.dataAtBase = d.dataAt[:0]
			return
		}
	}
	d.dataAt = append(d.dataAt, t)
}

// cullSendQueueLocked is CoDel at the dequeue point. Callers hold d.mu.
//
// Sojourn is measured on the packet currently at the head: the one the next
// drain would seal first. The schedule is CoDel's: enter drop state after the
// sojourn has exceeded the target for one interval, then drop from the head on
// a Newton-accelerated schedule (interval / sqrt(count)) while it stays
// above, leaving drop state the moment it dips below. A queue that never
// stands is never touched: zero sojourn takes the early return, and the
// in-order path allocates and copies nothing here.
func (d *Driver) cullSendQueueLocked(now time.Time) {
	if len(d.data) == 0 {
		d.codel.dropping = false
		d.codel.count = 0
		d.codel.firstAbove = time.Time{}
		return
	}
	if !d.dataMayFlow() {
		// A rekey hold or a closing state freezes the queue for reasons of
		// its own; aging those packets would drop them for standing in a
		// queue the session itself has paused.
		return
	}
	for i := 0; i < sendQueueCoDelMaxDrop; i++ {
		sojourn := now.Sub(d.dataAt[0])
		if sojourn <= SendQueueCoDelTarget {
			d.codel.dropping = false
			d.codel.count = 0
			d.codel.firstAbove = time.Time{}
			return
		}
		if d.codel.firstAbove.IsZero() {
			d.codel.firstAbove = now
			d.codel.dropping = false
			d.codel.count = 0
			return
		}
		if !d.codel.dropping {
			if now.Sub(d.codel.firstAbove) < SendQueueCoDelInterval {
				return
			}
			d.codel.dropping = true
			d.codel.count = 0
			d.codel.dropNext = now
		}
		if now.Before(d.codel.dropNext) {
			return
		}
		d.codel.count++
		d.stats.DataQueueDropped++
		d.consumeQueuedData(1)
		if len(d.data) == 0 {
			d.codel.dropping = false
			d.codel.count = 0
			d.codel.firstAbove = time.Time{}
			return
		}
		d.codel.dropNext = now.Add(time.Duration(
			float64(SendQueueCoDelInterval) / math.Sqrt(float64(d.codel.count))))
	}
}

// CullSendQueue drops head packets whose sojourn exceeds the CoDel target on
// the standard CoDel schedule. The pump calls it once per drain iteration,
// including iterations that go on to find the carrier stalled, so a queue that
// is standing because the carrier is refusing still ages and still sheds.
func (d *Driver) CullSendQueue(now time.Time) {
	if d.fqOn.Load() {
		// SetSendQueueFQ: each bucket runs its own CoDel (sendfq.go), and
		// d.data is only the short ready window, so the FIFO cull stands down.
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cullSendQueueLocked(now)
}
