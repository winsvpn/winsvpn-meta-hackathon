package gateway

import (
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one session's presence in the table: its forward token window, its
// crypto, and the accounting that decides how much of the gateway's memory it
// is allowed to hold.
//
// The window here mirrors the algorithm in core's private tokenWindow — insert
// a forward run of tokens, erase one when it is consumed, slide the low edge,
// and force the low edge forward when a counter arrives at least half a window
// ahead so that one permanently lost packet cannot pin the session. The
// reordering that survives that force-advance is `size/2 − 1`, not `size/2`;
// see consumeLocked. It is
// mirrored rather than shared because core does not export it; the handoff
// document records what that duplication costs and the two accessors that would
// end it.
type Entry struct {
	id     SessionID
	tbl    *Table
	client [32]byte
	open   Opener

	// openAt is the same session seen through the wider interface, resolved once
	// at registration and nil when the Opener does not implement it.
	//
	// Once, and not per datagram, because this is the hot path: the interface an
	// Opener satisfies is a property of its type and cannot change between two
	// packets of one session, so asking again for every arriving datagram would
	// be work on the gateway's busiest path buying an answer that is already
	// known. It is also what makes the choice auditable — Entry.OpenerAt reports
	// it, and a session cannot silently be driven through two different paths at
	// different moments of its life.
	openAt OpenerAt

	// lastSeen is nanoseconds, and it moves only when a message OPENS.
	//
	// That is the whole anti-liveness-forgery property: an attacker cannot keep
	// a session from being evicted, because touching lastSeen requires
	// producing a message that authenticates under that session's key.
	lastSeen atomic.Int64

	// budgetHeld is this entry's outstanding reservation against the table's
	// token budget, in tokens. It tracks exactly what this entry has taken from
	// Table.reserve: the initial window at registration, plus every growth.
	//
	// It is atomic and deliberately NOT guarded by e.mu. Admission has to hand a
	// victim's tokens back while it still holds t.mu — that is the whole point of
	// releaseBudget — and taking e.mu there would put the table's hottest lock
	// behind an entry's slowest one, because retireAll holds e.mu across a whole
	// window's worth of token derivation.
	budgetHeld atomic.Int64

	mu       sync.Mutex
	src      TokenSource
	size     int
	low      uint64
	consumed []bool
	opened   uint64
	growAt   uint64
	epoch    uint64
	closed   bool
}

// ID reports the session's local identity. It is never on the wire.
func (e *Entry) ID() SessionID { return e.id }

// Opener returns the session's crypto half, for a caller that holds an Entry
// and needs to seal a reply.
func (e *Entry) Opener() Opener { return e.open }

// OpenerAt returns the session's crypto half through the wider interface, or
// nil if this Opener does not implement it.
//
// It is an accessor rather than a bool because an operator asking "is this
// session paying for its window twice?" is asking about the object, and because
// a nil answer is the whole diagnosis: an Opener that does not implement OpenAt
// cannot be configured with core.CallerOwnsTokenWindow, and one that is
// configured that way but reaches this table as a plain Opener would fail every
// packet. That mismatch is a silent total outage for one session, so it is worth
// being able to see from outside.
func (e *Entry) OpenerAt() OpenerAt { return e.openAt }

// Window reports the current forward window size: the session's reordering
// tolerance and its share of the gateway's memory bill.
func (e *Entry) Window() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.size
}

// Low reports the lowest counter the window still accepts.
func (e *Entry) Low() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.low
}

// Opened reports how many messages have authenticated. It is the currency the
// session pays for a bigger window with.
func (e *Entry) Opened() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.opened
}

// LastSeen reports the last instant a message opened.
func (e *Entry) LastSeen() time.Time { return time.Unix(0, e.lastSeen.Load()) }

// Closed reports whether the entry has been retired.
func (e *Entry) Closed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

// publish inserts count tokens starting at the given counter. The caller must
// hold e.mu, or must not yet have published the entry.
func (e *Entry) publish(from uint64, count int) {
	for i := 0; i < count; i++ {
		c := from + uint64(i)
		if e.tbl.insert(e.src.TokenAt(c), slot{ent: e, counter: c}) {
			e.tbl.stats.collisions.Add(1)
		}
	}
}

// deliver tries this entry against a datagram whose token it owns.
//
// It returns the plaintext and true only if the session's own cryptography
// accepted the message. A message whose token matched but whose AEAD did not
// consumes nothing: a corrupted or forged copy must never invalidate the
// genuine packet that arrives after it.
//
// The counter the index resolved is handed to the session when the session can
// take it. Nothing else changes: the counter tells the session where to look,
// the session's AEAD decides whether to accept, and this function learns the
// answer only as a bool. In particular the token is NOT re-derived from the
// counter and compared with the one on the wire — see OpenerAt for why that is
// forbidden rather than merely wasteful — and the counter is passed through
// unexamined, because examining it here would be the table asserting something
// about authenticity that only the AEAD is allowed to assert.
func (e *Entry) deliver(msg []byte, counter uint64, now time.Time) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, false
	}
	var plain []byte
	var err error
	if e.openAt != nil {
		plain, err = e.openAt.OpenAt(msg, counter)
	} else {
		plain, err = e.open.Open(msg)
	}
	if err != nil {
		return nil, false
	}
	e.consumeLocked(counter)
	e.opened++
	e.lastSeen.Store(now.UnixNano())
	e.maybeGrowLocked()
	return plain, true
}

// consumeLocked retires a counter and slides the window.
//
// The force-advance rule is core's and the reasoning is core's: without it, one
// permanently lost packet at the low edge would pin the window forever and
// every counter past low+size would be refused, so a single dropped datagram
// would end the session. Forcing bounds reordering tolerance, which is the same
// trade a sliding-bitmap filter makes implicitly.
//
// The bound is `size/2 − 1`, NOT `size/2`, and the difference is the `+1` two
// lines below: consuming counter c retires the low edge to `c − half + 1`, so a
// message displaced by exactly `half` is already below the edge when it
// arrives. At this package's DefaultMaxWindow of 256 the tolerance is therefore
// 127, and at core's DefaultTokenWindow of 1024 it is 511. The network-realism
// lane swept the boundary and measured that cliff; it had been documented as
// `size/2` in three places, this comment among them. The window is one
// NARROWER than was advertised, never wider, so this was a documentation defect
// and not a security one — but a reader sizing a window against a measured
// reordering depth would have been off by one in the direction that loses
// packets. See core's tokenWindow.consume for the same note at the original.
func (e *Entry) consumeLocked(counter uint64) {
	if counter < e.low || counter >= e.low+uint64(e.size) {
		return
	}
	e.tbl.erase(e.src.TokenAt(counter), e, counter)
	e.consumed[int(counter%uint64(e.size))] = true

	if half := uint64(e.size / 2); counter >= e.low+half {
		e.forceAdvanceLocked(counter - half + 1)
	}
	for e.consumed[int(e.low%uint64(e.size))] {
		e.retireLowLocked()
	}
}

func (e *Entry) retireLowLocked() {
	idx := int(e.low % uint64(e.size))
	e.consumed[idx] = false
	e.tbl.erase(e.src.TokenAt(e.low), e, e.low)
	e.low++
	next := e.low + uint64(e.size) - 1
	if next >= e.low { // overflow guard at the counter ceiling
		if e.tbl.insert(e.src.TokenAt(next), slot{ent: e, counter: next}) {
			e.tbl.stats.collisions.Add(1)
		}
	}
}

func (e *Entry) forceAdvanceLocked(newLow uint64) {
	for e.low < newLow {
		e.retireLowLocked()
	}
}

// maybeGrowLocked doubles the window once the session has opened another
// window's worth of messages.
//
// This is the answer to “can an attacker force unbounded precomputation” at the
// table layer. Memory is handed out against authenticated packets, one window
// at a time, so a peer that opens ten thousand sessions and sends nothing holds
// ten thousand *initial* windows and never more. Growth also stops dead at the
// gateway's token budget, which is the memory-pressure decision: sessions keep
// working with a smaller reordering tolerance rather than the gateway keeping
// its tolerance and running out of memory.
func (e *Entry) maybeGrowLocked() {
	max := e.tbl.cfg.maxWindow()
	if e.size >= max || e.opened < e.growAtLocked() {
		return
	}
	next := e.size * 2
	if next > max {
		next = max
	}
	added := next - e.size
	if !e.tbl.reserve(int64(added)) {
		e.tbl.stats.budgetHit.Add(1)
		return
	}
	// Recorded immediately, so that whoever releases this entry returns the
	// grown reservation and not the one it registered with.
	e.budgetHeld.Add(int64(added))

	grown := make([]bool, next)
	for c := e.low; c < e.low+uint64(e.size); c++ {
		grown[int(c%uint64(next))] = e.consumed[int(c%uint64(e.size))]
	}
	from := e.low + uint64(e.size)
	e.consumed = grown
	e.size = next
	e.growAt = e.opened + uint64(next)
	e.publish(from, added)
	e.tbl.stats.grown.Add(1)
}

func (e *Entry) growAtLocked() uint64 {
	if e.growAt == 0 {
		return uint64(e.size)
	}
	return e.growAt
}

// Rekeyed re-bases the window onto a new epoch's demux key.
//
// core resets its receive window to counter zero under a fresh demux key on
// every ratchet, so the gateway must too or the two stop agreeing and every
// subsequent packet is dropped. The session driver calls this at exactly the
// point it calls core's ratchet. The earned window size survives — the session
// has already paid for it — and so does the eviction clock.
func (e *Entry) Rekeyed(src TokenSource) error {
	if src == nil {
		return errWrap(ErrConfig, "Rekeyed needs a TokenSource")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	e.retireWindowLocked()
	e.src = src
	e.low = 0
	e.epoch++
	for i := range e.consumed {
		e.consumed[i] = false
	}
	e.publish(0, e.size)
	return nil
}

// Epoch reports how many times this entry has been re-based.
func (e *Entry) Epoch() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.epoch
}

// retireWindowLocked withdraws every token this entry currently owns, without
// touching the budget reservation.
func (e *Entry) retireWindowLocked() {
	for i := 0; i < e.size; i++ {
		c := e.low + uint64(i)
		e.tbl.erase(e.src.TokenAt(c), e, c)
	}
}

// releaseBudget hands this entry's outstanding reservation back to the table's
// token budget, exactly once.
//
// Exactly-once is the Swap: whichever caller reads the non-zero value is the one
// that returns it, and every later caller reads zero and returns nothing. That
// matters because two callers legitimately race here — admission releases a
// victim's budget the instant it evicts it, and retireAll releases whatever is
// left when the window is actually torn down.
//
// Lock-free is not an optimisation, it is the correctness requirement. Register
// calls this while holding t.mu so that removing a session and returning its
// tokens are one indivisible step; if this needed e.mu it could block on a
// concurrent retireAll that holds e.mu across a full window of token derivation,
// and the whole table would queue behind it.
func (e *Entry) releaseBudget() {
	if n := e.budgetHeld.Swap(0); n > 0 {
		e.tbl.release(n)
	}
}

// retireAll withdraws every token and hands the window's capacity back to the
// budget. It is idempotent, because eviction and an explicit Remove can race.
//
// The budget may already have gone back — Register returns a victim's tokens
// under t.mu, before it ever calls this — in which case releaseBudget is a
// no-op and this call is purely the teardown of the index entries.
func (e *Entry) retireAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.retireWindowLocked()
	e.closed = true
	e.releaseBudget()
	if w, ok := e.open.(interface{ Wipe() }); ok {
		w.Wipe()
	}
	if w, ok := e.src.(interface{ Wipe() }); ok {
		w.Wipe()
	}
}
