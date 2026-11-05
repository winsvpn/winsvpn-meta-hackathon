package driver

import (
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// This file is item 5 of the tunnel-speed deferral table: a per-session
// receive resequencer that restores counter order between the carrier and the
// session's open path. Triggered on Canada 2026-10-09 by R = delta
// outer_reordered / delta messages_received of 6.9 to 8.7% (U0) rising to 15
// to 16% (U3) against the agreed 0.5% bar. This buffer repairs bounded
// inversions before authenticated delivery while retaining parallel crypto
// workers and flow-affine TUN writers. It does not locate their source.
// Test G measured much less disorder with raw UDP than with the tunnel;
// sender batching and endpoint receive processing remain hypotheses until
// matched measurements isolate them.
//
// # The bounds (prior round's item 5, each enforced on its own)
//
//   - time: a message is held at most ReseqHoldTime (3 ms). The read loop
//     arms its receive with the hold deadline while anything is held, so the
//     timer fires even when nothing new arrives.
//   - messages: at most ReseqHoldMessages (128) held.
//   - bytes: at most ReseqHoldBytes (256 KiB) held.
//   - inner packets: at most ReseqHoldInnerPackets (192) held, estimated at
//     max(1, len(msg)/64) per message (a full message carries one inner
//     packet of ~1.3 KiB; a small-packet message carries up to ~21 of ~43
//     bytes each; the estimate errs toward holding less).
//
// When any bound would be exceeded, everything held is RELEASED in counter
// order (delivered, never dropped) and the frontier advances past it: the
// bounds cap added delay, never delivery. A late authenticated message that
// arrives after the frontier passed it is delivered immediately: holding it
// could not restore order, and dropping it would convert bounded reordering
// into unbounded loss.
//
// # The fast path
//
// With nothing held and every message in order, resequence returns the
// caller's slots unchanged: no copy, no allocation, no timer. The cost it
// cannot avoid is one token-window lookup per message (Session.ResolveCounter
// under the receive mutex), about a hundred nanoseconds, paid so disorder can
// be recognized before delivery. Epoch installs and session replacements
// restart counters at zero; both change Driver.ReceiveEpoch, and on a change
// everything held is released at once and the frontier resets to the next
// arriving counter.
//
// # Counters
//
// The resequencer moves nothing itself. outer_reordered and outer_lost count
// at consumeKnown, and consumeKnown now sees counter order for every message
// the resequencer held, so outer_reordered FALLS by exactly the inversions
// repaired; a hold that times out leaves the inversion in the count, which is
// the honest report of an inversion the bound could not repair.

// ReseqConfig enables and bounds the receive resequencer. The zero value is
// disabled, which is the previous behaviour exactly: no lookups, no timer, no
// holds.
type ReseqConfig struct {
	Enabled bool
	// HoldMessages, HoldTime, HoldBytes and HoldInnerPackets are the enforced
	// hold bounds. Zero values take the constants below.
	HoldMessages int
	HoldTime     time.Duration
	HoldBytes    int
	HoldInner    int
}

const (
	// ReseqHoldMessages is the message bound of the hold (item 5: 128).
	ReseqHoldMessages = 128
	// ReseqHoldTime is the time bound of the hold (item 5: 3 ms).
	ReseqHoldTime = 3 * time.Millisecond
	// ReseqHoldBytes is the byte bound of the hold (item 5: a byte bound;
	// 256 KiB is 2x the message bound at the 1402-byte plan message size,
	// so the message bound binds first at full-size messages and this one
	// binds first for small-packet messages).
	ReseqHoldBytes = 256 << 10
	// ReseqHoldInnerPackets is the inner-packet bound of the hold (item 5:
	// an inner-packet bound; 192 is 1.5x the message bound, matching the
	// estimate's worst case of 1.5 inner packets per held message on a
	// mixed bulk/ACK flow).
	ReseqHoldInnerPackets = 192
	// reseqInnerEstimateDenominator is the bytes-per-inner-packet estimate:
	// a full message carries one ~1.3 KiB inner packet, so len/64
	// overestimates the packet count of bulk traffic by ~20x and lands
	// within 1.5x on ACK-dense traffic.
	reseqInnerEstimateDenominator = 64
)

// reseqHold is one held message. The message is an owned copy: the caller's
// receive buffer is reused as soon as this batch returns, so holding past the
// batch requires the copy. The copy is the hold path's cost, not the in-order
// path's.
type reseqHold struct {
	msg   []byte
	inner int
}

// resequencer is one loop's reorder state. It is not safe for concurrent use;
// exactly the loop's readLoop goroutine touches it.
type resequencer struct {
	enabled   bool
	holdMsgs  int
	holdTime  time.Duration
	holdBytes int
	holdInner int

	// live is false until the first resolvable message sets the frontier.
	live  bool
	next  uint64
	epoch uint32

	// ring holds messages by distance ahead of the frontier: ring[i] is the
	// message with counter next+i+1 (index 0 is the first MISSING counter).
	// len(ring) is the number of consecutive counters from next+1 that are
	// held; holes inside that run close as their messages arrive, and a
	// message further ahead than len(ring) (given the bounds) is delivered
	// immediately rather than held.
	ring      []reseqHold
	heldBytes int
	heldInner int
	since     time.Time

	// merge stages the released-holds-plus-fresh delivery order. It is
	// reused across calls and never shrinks below the high-water mark of a
	// burst; it is empty and untouched on the in-order path.
	merge []session.ReceiveSlot
	// released stages holds being released, reused the same way.
	released []session.ReceiveSlot
}

// configure applies the config's bounds and defaults. Called once from
// newLoop; the zero config leaves the resequencer disabled.
func (r *resequencer) configure(cfg ReseqConfig) {
	*r = resequencer{}
	if !cfg.Enabled {
		return
	}
	r.enabled = true
	r.holdMsgs = cfg.HoldMessages
	if r.holdMsgs <= 0 {
		r.holdMsgs = ReseqHoldMessages
	}
	r.holdTime = cfg.HoldTime
	if r.holdTime <= 0 {
		r.holdTime = ReseqHoldTime
	}
	r.holdBytes = cfg.HoldBytes
	if r.holdBytes <= 0 {
		r.holdBytes = ReseqHoldBytes
	}
	r.holdInner = cfg.HoldInner
	if r.holdInner <= 0 {
		r.holdInner = ReseqHoldInnerPackets
	}
}

func (r *resequencer) holds() bool { return len(r.ring) > 0 }

// deadline is when the oldest hold must be released by.
func (r *resequencer) deadline() time.Time {
	if !r.holds() || r.since.IsZero() {
		return time.Time{}
	}
	return r.since.Add(r.holdTime)
}

// counterResolver is the one thing the resequencer needs from the session.
type counterResolver interface {
	ReceiveCounter(msg []byte) (uint64, bool)
	ReceiveEpoch() uint32
}

// resequence merges the freshly received slots with previously held messages
// into delivery order and returns the slots to deliver now. Held input slots
// are copied into the ring and MUST NOT also be delivered by the caller: the
// returned slice is the complete delivery set for this call. Fresh slots in
// the returned slice are borrowed from the caller and must be delivered
// before its next receive; released holds are owned by the resequencer and
// must be delivered the same way (they are replaced on the next call).
//
// The returned slice aliases r.merge or fresh itself; the caller treats it as
// borrow-and-deliver.
func (r *resequencer) resequence(fresh []session.ReceiveSlot, sess counterResolver, now time.Time) []session.ReceiveSlot {
	if !r.enabled {
		return fresh
	}
	if e := sess.ReceiveEpoch(); e != r.epoch {
		// A new epoch (rekey) or a replaced core session restarts counters.
		// Release everything held first: delivered, never dropped. Then
		// resequence fresh under the new epoch, so its first batch is
		// ordered and sets the new frontier.
		var prev []session.ReceiveSlot
		r.releaseHeld(func(s session.ReceiveSlot) { prev = append(prev, s) })
		r.epoch = e
		r.live = false
		if len(prev) > 0 {
			return append(prev, r.resequence(fresh, sess, now)...)
		}
	}
	if !r.holds() {
		// Fast path candidate: in-order stream with nothing held.
		inOrder := true
		for i := range fresh {
			c, ok := sess.ReceiveCounter(fresh[i].Message)
			if !ok {
				continue
			}
			if !r.live {
				r.live, r.next = true, c
			} else if c != r.next {
				inOrder = false
				break
			}
			r.next++
		}
		if inOrder {
			return fresh
		}
	}
	return r.reorderSlow(fresh, sess, now)
}

// reorderSlow is the path taken once anything is held or out of order. It
// walks the fresh slots, holds those ahead of the frontier, releases run
// after run as holes close, and returns the merged delivery order.
func (r *resequencer) reorderSlow(fresh []session.ReceiveSlot, sess counterResolver, now time.Time) []session.ReceiveSlot {
	r.merge = r.merge[:0]
	appendFresh := func(s session.ReceiveSlot) {
		r.merge = append(r.merge, s)
	}
	for i := range fresh {
		c, ok := sess.ReceiveCounter(fresh[i].Message)
		if !ok {
			// Noise, replay, pre-handshake: deliver in place, in arrival
			// order, exactly as the non-resequenced path would.
			appendFresh(fresh[i])
			continue
		}
		if !r.live {
			r.live, r.next = true, c
		}
		switch {
		case c == r.next:
			appendFresh(fresh[i])
			r.next++
			r.drainHeld(appendFresh)
		case c < r.next:
			// Late for a frontier already past it: delivered immediately,
			// never dropped, never held.
			appendFresh(fresh[i])
		default:
			ahead := c - r.next // >= 1
			idx := int(ahead - 1)
			if idx >= r.holdMsgs || r.wouldExceed(fresh[i].Message, idx+1) {
				// Beyond a bound this message cannot be held: release
				// everything held in counter order, deliver this one, and
				// advance the frontier past it.
				r.releaseHeld(appendFresh)
				appendFresh(fresh[i])
				// The frontier only moves forward: releaseHeld already set
				// it past the highest held counter, and a bound crossed by
				// a message INSIDE the span (the byte or inner-packet bound
				// refusing a message that fills a hole) must not pull it
				// back below counters just delivered, or the next in-order
				// message is held for a hole that is not there until the
				// time bound releases it (TUNNEL-SPEED-2 Turn 14).
				if c+1 > r.next {
					r.next = c + 1
				}
				r.drainHeld(appendFresh)
				continue
			}
			for len(r.ring) <= idx {
				r.ring = append(r.ring, reseqHold{})
			}
			if r.ring[idx].msg == nil {
				msg := make([]byte, len(fresh[i].Message))
				copy(msg, fresh[i].Message)
				if r.since.IsZero() {
					r.since = now
				}
				r.ring[idx] = reseqHold{msg: msg, inner: r.estimateInner(msg)}
				r.heldBytes += len(msg)
				r.heldInner += r.ring[idx].inner
			} else {
				// A duplicate of a held counter (a retransmission of an
				// outer datagram): deliver it in place; the held original
				// keeps its place.
				appendFresh(fresh[i])
			}
		}
		// Enforce the time bound after each message: a burst that fills the
		// ring must not extend the oldest hold's age past HoldTime.
		if r.holds() && !r.since.IsZero() && now.Sub(r.since) >= r.holdTime {
			r.releaseHeld(appendFresh)
		}
	}
	// Bounds enforced on their own even when no further message arrives:
	// message and inner bounds can only be crossed by holding, which the
	// checks above refuse; the byte bound is re-checked here so a single
	// huge small-packet message cannot cross it either. It cannot, given
	// wouldExceed, but the explicit re-check keeps each bound's enforcement
	// auditable in one place per bound.
	if r.heldBytes > r.holdBytes || r.heldInner > r.holdInner || len(r.ring) > r.holdMsgs {
		r.releaseHeld(appendFresh)
	}
	return r.merge
}

// wouldExceed reports whether holding msg at span would cross a bound.
// Filling a hole inside the existing ring does not enlarge its span.
func (r *resequencer) wouldExceed(msg []byte, span int) bool {
	if max(len(r.ring), span) > r.holdMsgs {
		return true
	}
	if r.heldBytes+len(msg) > r.holdBytes {
		return true
	}
	return r.heldInner+r.estimateInner(msg) > r.holdInner
}

func (r *resequencer) estimateInner(msg []byte) int {
	n := len(msg) / reseqInnerEstimateDenominator
	if n < 1 {
		n = 1
	}
	return n
}

// drainHeld releases held messages while the frontier's next counter is held.
// It closes runs of consecutive counters; holes stop it.
func (r *resequencer) drainHeld(emit func(session.ReceiveSlot)) {
	for len(r.ring) > 0 {
		if r.ring[0].msg == nil {
			// The caller advanced next by consuming the missing counter.
			// This empty slot now represents next itself. Remove it so
			// the remaining ring again starts at next+1.
			r.ring = r.ring[1:]
			break
		}
		r.emitHead(emit)
		r.next++
	}
	if !r.holds() {
		// A later gap must start its own hold timer.
		r.since = time.Time{}
	}
}

// releaseHeld releases everything held in counter order and advances the
// frontier past the highest held counter. With nothing held it changes
// nothing, not the frontier either.
func (r *resequencer) releaseHeld(emit func(session.ReceiveSlot)) {
	entry, last, emitted := r.next, r.next, false
	for i := range r.ring {
		if r.ring[i].msg != nil {
			r.emitAt(i, emit)
			last = entry + uint64(i) + 1 // ring[i] holds counter entry+i+1
			emitted = true
		}
	}
	r.ring = r.ring[:0]
	r.heldBytes = 0
	r.heldInner = 0
	r.since = time.Time{}
	if emitted {
		r.next = last + 1
	}
}

// releaseAll is releaseHeld with the fresh slots appended after, for epoch
// changes and timer expiries, where the held set must go out first.
func (r *resequencer) releaseAll(fresh []session.ReceiveSlot, now time.Time) []session.ReceiveSlot {
	r.merge = r.merge[:0]
	r.releaseHeld(func(s session.ReceiveSlot) { r.merge = append(r.merge, s) })
	r.merge = append(r.merge, fresh...)
	out := r.merge
	r.merge = nil
	return out
}

// emitHead emits ring[0] and removes it, shifting the ring's base.
func (r *resequencer) emitHead(emit func(session.ReceiveSlot)) {
	h := r.ring[0]
	r.heldBytes -= len(h.msg)
	r.heldInner -= h.inner
	emit(r.slotFor(h.msg))
	r.ring[0] = reseqHold{}
	r.ring = r.ring[1:]
}

// emitAt emits ring[i] in place, leaving a hole, for releaseHeld's ordered
// sweep. Accounting is settled by releaseHeld.
func (r *resequencer) emitAt(i int, emit func(session.ReceiveSlot)) {
	emit(r.slotFor(r.ring[i].msg))
	r.ring[i] = reseqHold{}
}

// slotFor wraps an owned message in a ReceiveSlot for deliverReceiveBatch.
// Scratch and Packets are allocated per release (the hold path, not the
// in-order path); DeliverBatch requires Scratch to cover the message body and
// Packets to cover its maximum frame count.
func (r *resequencer) slotFor(msg []byte) session.ReceiveSlot {
	return session.ReceiveSlot{
		Message: msg,
		Scratch: make([]byte, len(msg)),
		Packets: make([][]byte, 0, len(msg)/3+1),
	}
}

// releaseExpired releases everything held when the oldest hold has reached the
// time bound. Called by the read loop when its armed receive deadline fires.
func (r *resequencer) releaseExpired(now time.Time) []session.ReceiveSlot {
	if !r.holds() {
		return nil
	}
	if !r.since.IsZero() && now.Sub(r.since) < r.holdTime {
		return nil
	}
	out := r.releaseAll(nil, now)
	return out
}
