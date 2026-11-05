// Package aqm holds queue-management state machines that own no queue.
//
// A caller keeps its own FIFO and timestamps; this package only answers, for
// the packet at the head of that FIFO, whether to drop it instead of
// dequeuing it. Keeping the queue out of here is what lets the same state
// machine sit on the gateway's per-session receive inbox (winn3/carrier.Pipe)
// and on a session's send queue (winn3/session.Driver) without either of them
// changing its buffer layout or its allocation behaviour.
package aqm

import (
	"math"
	"time"
)

// Defaults are RFC 8289's: a 5 ms sojourn target and a 100 ms interval.
const (
	DefaultTarget   = 5 * time.Millisecond
	DefaultInterval = 100 * time.Millisecond
)

// CoDel is the RFC 8289 dequeue-side controller.
//
// Times are durations on the caller's monotonic clock (an offset from any
// fixed origin). The zero value is disabled; Enabled reports whether both
// Target and Interval are positive. CoDel is not safe for concurrent use: the
// caller serialises Decide with its own dequeue.
//
// Decide is called once for each packet that reaches the head of the queue,
// immediately before it would be dequeued. A true answer means the caller
// drops that packet and calls Decide again for the new head, exactly the
// RFC's drop-and-re-examine loop. A queue of one packet is never dropped
// (RFC 8289 section 5.2, MAXPACKET, counted in packets here), so an
// otherwise idle queue cannot be emptied by the controller.
type CoDel struct {
	Target   time.Duration
	Interval time.Duration

	above      bool          // sojourn has been at or above Target since firstAbove-Interval
	firstAbove time.Duration // when okToDrop may first become true
	dropping   bool
	dropNext   time.Duration
	count      uint32
	lastCount  uint32
}

// NewCoDel returns a controller with the given target and interval.
func NewCoDel(target, interval time.Duration) CoDel {
	return CoDel{Target: target, Interval: interval}
}

// Enabled reports whether the controller is configured.
func (c *CoDel) Enabled() bool { return c.Target > 0 && c.Interval > 0 }

// Dropping reports whether the controller is in its dropping state.
func (c *CoDel) Dropping() bool { return c.dropping }

// Count is the RFC's drop count for the current or most recent dropping state.
func (c *CoDel) Count() uint32 { return c.count }

func (c *CoDel) controlLaw(t time.Duration) time.Duration {
	n := c.count
	if n == 0 {
		n = 1
	}
	return t + time.Duration(float64(c.Interval)/math.Sqrt(float64(n)))
}

// okToDrop is the RFC's dodequeue verdict for one head packet.
func (c *CoDel) okToDrop(now, sojourn time.Duration, backlog int) bool {
	if sojourn < c.Target || backlog <= 1 {
		c.above = false
		return false
	}
	if !c.above {
		c.above = true
		c.firstAbove = now + c.Interval
		return false
	}
	return now >= c.firstAbove
}

// Decide answers whether the head packet, which has waited sojourn and has
// backlog packets in the queue including itself, is dropped at time now.
func (c *CoDel) Decide(now, sojourn time.Duration, backlog int) bool {
	if !c.Enabled() {
		return false
	}
	ok := c.okToDrop(now, sojourn, backlog)
	if c.dropping {
		if !ok {
			c.dropping = false
			return false
		}
		if now >= c.dropNext {
			c.count++
			c.dropNext = c.controlLaw(c.dropNext)
			return true
		}
		return false
	}
	if !ok {
		return false
	}
	c.dropping = true
	delta := c.count - c.lastCount
	if delta > 1 && now-c.dropNext < 16*c.Interval {
		c.count = delta
	} else {
		c.count = 1
	}
	c.dropNext = c.controlLaw(now)
	c.lastCount = c.count
	return true
}

// Empty records that the queue was observed empty. It clears the
// above-target timer, as the RFC's dodequeue does on an empty queue, so a
// packet that arrives after an idle period starts a fresh interval.
func (c *CoDel) Empty() {
	c.above = false
}
