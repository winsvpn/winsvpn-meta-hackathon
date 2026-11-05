package netlab

import (
	"sync"
)

// Impairment is what one direction of a link does to the messages crossing it.
//
// Every rule is keyed on the message ORDINAL rather than on a wall clock or on
// an unseeded draw, so a run is reproducible and a break point is a number. The
// one stochastic rule (LossPermille) is driven by a seeded generator that lives
// in this struct's Link, never by math/rand's global source.
//
// The zero value is a perfect link, which is loopback, which is what every
// proof before this package had.
type Impairment struct {
	// --- path MTU ------------------------------------------------------------

	// MaxOuterPacket is the largest OUTER packet the path carries. A message
	// whose outer packet exceeds it is DROPPED, and Offer still returns nil.
	//
	// Returning success is the whole point. A constrained path with DF set does
	// not report anything to the sender through the socket: every write
	// succeeds, the datagram is discarded by a router, and the only evidence is
	// an ICMP message that a censoring middlebox is under no obligation to
	// forward. A shim that returned an error here would be modelling a
	// courteous network and would prove nothing about the black hole.
	MaxOuterPacket int

	// OuterOverhead is what the carrier wraps around a message: 28 for UDP over
	// IPv4, 48 for UDP over IPv6, and the stream figures from
	// WINN3_CARRIERS_20260808.md §5.2 for TCP and TLS. Zero means the message
	// is measured bare, which models a link whose MTU is expressed in message
	// bytes.
	OuterOverhead int

	// --- loss ----------------------------------------------------------------

	// DropFrom and DropCount drop a contiguous run of ordinals, one-based and
	// inclusive of DropFrom. This is the burst-loss instrument: a run longer
	// than the token window is the outage the session lane's teardown decision
	// exists for.
	DropFrom  uint64
	DropCount uint64

	// DropEvery drops every Nth message. Ordinary loss, not an outage.
	DropEvery uint64

	// LossPermille is random loss in parts per thousand, drawn from this Link's
	// own seeded generator.
	LossPermille int

	// --- reorder -------------------------------------------------------------

	// ReorderAt and ReorderPeriod select which messages are held, and
	// ReorderDistance is how far behind they are released. Displacement is
	// EXACT: a message held at relative ordinal k is delivered immediately
	// after relative ordinal k+ReorderDistance, so the receiver sees it exactly
	// ReorderDistance messages late.
	//
	// This is the instrument the force-advance rule is measured with, and it is
	// exact on purpose. A shuffling shim measures a distribution; this measures
	// a boundary, which is the difference between "tolerates about half a
	// window" and "tolerates 127 and fails at 128".
	//
	// ReorderAt holds exactly one message; ReorderPeriod holds one in every N.
	// Both are relative to the moment Arm was called, so a test reads as "the
	// fifth message after the path degraded" rather than as an absolute count
	// that includes the handshake.
	ReorderAt       uint64
	ReorderPeriod   uint64
	ReorderDistance uint64

	// --- duplication ---------------------------------------------------------

	// DuplicateEvery delivers every Nth message twice. A duplicate is what a
	// retransmitting middlebox and a replaying attacker both produce, and the
	// token window is supposed to be an exact replay filter, so the second copy
	// must be refused without costing the session anything.
	DuplicateEvery uint64
}

// LinkStats is what one direction of a link did. Every counter moves at the
// moment the shim acts, so a test can assert that the impairment it configured
// was actually applied rather than assuming it.
type LinkStats struct {
	// Offered is messages handed to the link.
	Offered uint64
	// Delivered is messages handed on to the far side, including duplicates.
	Delivered uint64

	// DroppedOversize, DroppedBurst, DroppedPeriodic and DroppedRandom split
	// the loss by cause. Splitting them is what makes "the impairment was real"
	// checkable: a test that asserts a total could be satisfied by the wrong
	// rule firing.
	DroppedOversize uint64
	DroppedBurst    uint64
	DroppedPeriodic uint64
	DroppedRandom   uint64

	// Duplicated is extra copies emitted.
	Duplicated uint64

	// Reordered is messages released out of order, and MaxDisplacement is the
	// largest number of messages any one of them was released behind.
	Reordered       uint64
	MaxDisplacement uint64

	// Held is messages currently sitting in the reorder buffer.
	Held int

	// MaxOuterSeen is the largest outer packet the link was offered, whether or
	// not it survived. It is the instrument for the migration trap: a full-size
	// flow that stops arriving must be shown to have been OFFERED at full size.
	MaxOuterSeen int

	// SinkRefused is messages emit handed to sink that sink rejected
	// (ErrQueueFull, ErrClosed, ErrMessageTooLarge). Offer still returns nil:
	// a UDP write succeeded. Delivered still counts them, because from the
	// sender's socket they left. A test that asserts the books without this
	// counter cannot see a full inbox eating the far side of a "delivered"
	// message.
	SinkRefused uint64
}

// Link is one direction of an impaired path.
//
// It sits between two carrier.Pipe instances: the sender's Pipe.Send calls
// Offer, and Offer calls the receiver's Pipe.Deliver. That is the same seam a
// gateway demultiplexer uses, so the bytes crossing it are the real sealed
// messages and not a stand-in.
type Link struct {
	mu sync.Mutex

	sink func(msg []byte) error
	tap  func(msg []byte)

	imp   Impairment
	armed bool
	base  uint64 // the absolute ordinal Arm was called at

	n     uint64 // messages offered, one-based and absolute
	rng   uint64 // seeded generator state
	held  []heldMsg
	stats LinkStats
}

type heldMsg struct {
	msg       []byte
	ordinal   uint64 // relative
	releaseAt uint64 // relative; release once rel reaches this
}

// NewLink builds one direction. sink is the far side's arrival hook —
// (*carrier.Pipe).Deliver in every rig here. seed makes LossPermille
// reproducible; it is unused when there is no random loss.
func NewLink(sink func(msg []byte) error, seed uint64) *Link {
	if seed == 0 {
		seed = 0x9E3779B97F4A7C15
	}
	return &Link{sink: sink, rng: seed}
}

// Arm installs an impairment and turns it on.
//
// Impairment is armed rather than configured at construction because a
// handshake has to complete before most of these properties mean anything: a
// reorder buffer that holds the initiation is a rig that measures nothing but
// its own deadlock. Arming mid-session is also the realistic shape — a handset
// that walked out of a building, not one that started in a tunnel.
func (l *Link) Arm(imp Impairment) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.imp = imp
	l.armed = true
	l.base = l.n
}

// Disarm turns the impairment off and releases anything held, in the order it
// was held, so a test can prove a stall was the impairment rather than a wedge.
func (l *Link) Disarm() {
	l.mu.Lock()
	held := l.held
	l.held = nil
	l.armed = false
	l.imp = Impairment{}
	sink := l.sink
	l.stats.Held = 0
	l.mu.Unlock()

	for _, h := range held {
		if sink != nil {
			if err := sink(h.msg); err != nil {
				l.mu.Lock()
				l.stats.SinkRefused++
				l.mu.Unlock()
			}
		}
		l.mu.Lock()
		l.stats.Delivered++
		l.mu.Unlock()
	}
}

// Tap installs an observer that sees every message OFFERED to the link,
// impaired or not.
//
// It is the passive tap an adversary on the path already has, and it exists so
// that the injection tests can spray REAL ciphertext rather than random bytes.
// Random bytes are the easy case: they fail the length check or miss the token
// index and cost nothing. Captured ciphertext is the case a censor can actually
// produce, and it is the one that reaches the AEAD.
func (l *Link) Tap(fn func(msg []byte)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tap = fn
}

// Stats snapshots what this direction did.
func (l *Link) Stats() LinkStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Held = len(l.held)
	return s
}

// Offer is the sender's entry point. It is what a carrier.PipeConfig.Out field
// is set to.
//
// It returns nil for every drop. See Impairment.MaxOuterPacket for why that is
// the only honest choice: the measured censorship failure and a DF-set path MTU
// black hole both present as "every write succeeded and nothing arrived", and a
// shim that reported an error would be modelling a network that does not exist
// where this protocol has to work.
func (l *Link) Offer(msg []byte) error {
	l.mu.Lock()

	l.n++
	l.stats.Offered++
	if l.tap != nil {
		l.tap(append([]byte(nil), msg...))
	}

	outer := len(msg) + l.imp.OuterOverhead
	if outer > l.stats.MaxOuterSeen {
		l.stats.MaxOuterSeen = outer
	}

	if !l.armed {
		sink := l.sink
		l.stats.Delivered++
		l.mu.Unlock()
		if sink == nil {
			return nil
		}
		return sink(msg)
	}
	rel := l.n - l.base

	// 1. The path MTU gate, first, because a packet the path cannot carry never
	//    reaches the impairments below it in a real network either.
	if l.imp.MaxOuterPacket > 0 && outer > l.imp.MaxOuterPacket {
		l.stats.DroppedOversize++
		out := l.releaseDueLocked(rel)
		l.stats.Delivered += uint64(len(out))
		l.mu.Unlock()
		return l.emit(out)
	}

	// 2. Loss.
	switch {
	case l.imp.DropCount > 0 && rel >= l.imp.DropFrom && rel < l.imp.DropFrom+l.imp.DropCount:
		l.stats.DroppedBurst++
		out := l.releaseDueLocked(rel)
		l.stats.Delivered += uint64(len(out))
		l.mu.Unlock()
		return l.emit(out)
	case l.imp.DropEvery > 0 && rel%l.imp.DropEvery == 0:
		l.stats.DroppedPeriodic++
		out := l.releaseDueLocked(rel)
		l.stats.Delivered += uint64(len(out))
		l.mu.Unlock()
		return l.emit(out)
	case l.imp.LossPermille > 0 && int(l.next()%1000) < l.imp.LossPermille:
		l.stats.DroppedRandom++
		out := l.releaseDueLocked(rel)
		l.stats.Delivered += uint64(len(out))
		l.mu.Unlock()
		return l.emit(out)
	}

	// 3. Reorder. The held message is released after exactly ReorderDistance
	//    later messages have crossed, which is the displacement the receiver's
	//    force-advance rule sees.
	if l.imp.ReorderDistance > 0 && l.holdsLocked(rel) {
		cp := append([]byte(nil), msg...)
		l.held = append(l.held, heldMsg{
			msg:       cp,
			ordinal:   rel,
			releaseAt: rel + l.imp.ReorderDistance,
		})
		l.mu.Unlock()
		return nil
	}

	out := [][]byte{msg}
	if l.imp.DuplicateEvery > 0 && rel%l.imp.DuplicateEvery == 0 {
		l.stats.Duplicated++
		out = append(out, msg)
	}
	out = append(out, l.releaseDueLocked(rel)...)
	l.stats.Delivered += uint64(len(out))
	l.mu.Unlock()
	return l.emit(out)
}

// holdsLocked reports whether the message at relative ordinal rel is one the
// reorder rule holds back.
func (l *Link) holdsLocked(rel uint64) bool {
	if l.imp.ReorderAt > 0 && rel == l.imp.ReorderAt {
		return true
	}
	if l.imp.ReorderPeriod > 0 && rel%l.imp.ReorderPeriod == 0 {
		return true
	}
	return false
}

// releaseDueLocked pulls every held message whose release ordinal has arrived.
// It is called on EVERY offer, including dropped ones, because a real network
// that drops a packet does not also freeze the packets behind it.
func (l *Link) releaseDueLocked(now uint64) [][]byte {
	if len(l.held) == 0 {
		return nil
	}
	var out [][]byte
	keep := l.held[:0]
	for _, h := range l.held {
		if now >= h.releaseAt {
			d := now - h.ordinal
			if d > l.stats.MaxDisplacement {
				l.stats.MaxDisplacement = d
			}
			l.stats.Reordered++
			out = append(out, h.msg)
			continue
		}
		keep = append(keep, h)
	}
	l.held = keep
	return out
}

func (l *Link) emit(msgs [][]byte) error {
	if len(msgs) == 0 {
		return nil
	}
	l.mu.Lock()
	sink := l.sink
	l.mu.Unlock()
	if sink == nil {
		return nil
	}
	for _, m := range msgs {
		if err := sink(m); err != nil {
			// A full inbox is the receiver's business and is counted there. It
			// is not a send failure: the sender's socket accepted the bytes.
			// SinkRefused is what makes that drop visible on THIS side of the
			// seam, so a books-balance test cannot pass while the far side
			// silently refused.
			l.mu.Lock()
			l.stats.SinkRefused++
			l.mu.Unlock()
			continue
		}
	}
	return nil
}

// next is splitmix64. It is here rather than math/rand because winn3 bans the
// standard library's non-cryptographic generator from its own source, and
// because a rig whose loss pattern cannot be reproduced from a seed is a rig
// whose failures cannot be re-run.
func (l *Link) next() uint64 {
	l.rng += 0x9E3779B97F4A7C15
	z := l.rng
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}
