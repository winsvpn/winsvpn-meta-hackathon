package carrier

import (
	"context"
	"sync"
	"time"
)

// deadlineArm keeps ONE cancellation watcher alive across many socket
// operations instead of building and tearing down a fresh one per call.
//
// # What the per-call version cost
//
// The original armRead/armWrite pair ran, on every RecvBatch and every
// SendBatch: one SetDeadline, one channel allocation, one context.AfterFunc
// registration (which allocates a node and takes the parent context's mutex),
// then on the way out one stop() deregistration and a second SetDeadline. At a
// gigabit with 64-datagram batches that is roughly 1,400 registrations a second
// in each direction. MEASURED, Galaxy S26 Ultra (SM-S948U1), 2026-09-17,
// alloc_objects profile of BenchmarkBatchCarrierLoopThroughput: armRead and
// armWrite together produced 481,000 of the 2,541,000 objects the whole
// datapath allocated, 19% of every allocation, to watch a context that changes
// once per carrier.
//
// # Why one registration per context is the right number
//
// The watcher exists for exactly one event: the carrier's context being
// cancelled while a read or a write is parked in the kernel. That context is
// created once per carrier generation and cancelled once, at migration or
// teardown. Registering it per datagram batch re-establishes the same watch on
// the same context tens of thousands of times for a single event.
//
// So hold() keys on context IDENTITY. The same context re-applies nothing; a
// different one releases the old watch and installs a new one, resetting the
// socket deadline as it goes so a context that was cancelled cannot leave
// aLongTimeAgo installed for its successor.
//
// # The race the per-call version was defending against, and why it is gone
//
// The old unarm did `if !stop() { <-finished }` before restoring the deadline
// to zero, because otherwise a cancellation firing concurrently could write
// aLongTimeAgo AFTER the restore and wedge the socket permanently. Holding the
// watch removes the restore, and with it the race: once the context is
// cancelled the deadline stays in the past, which is precisely the state a
// cancelled carrier should be in. Nothing reads this socket except through the
// carrier, and the carrier is dead.
//
// # Deadlines set behind this cache's back
//
// RecvBatch's portable fallback loop sets a 50 microsecond read deadline
// between datagrams. That write is invisible here, so a fallback that returned
// without restoring would leave a deadline in the past and every later read
// would fail instantly. reapply() is how that path hands the socket back: it
// reinstalls whatever this cache believes is current.
type deadlineArm struct {
	mu       sync.Mutex
	ctx      context.Context
	stop     func() bool
	finished chan struct{}
	applied  time.Time
	held     bool
}

// noopUnarm is returned by hold. The watch outlives the call by design, so
// there is nothing for the caller to undo; the closure stays in the signature
// so both call sites read the same as they did before.
func noopUnarm() {}

// hold installs the context's deadline on the socket and makes sure exactly one
// watcher will push that deadline into the past if the context is cancelled.
//
// set is SetReadDeadline or SetWriteDeadline. The two directions have their own
// deadlineArm so that a parked read cannot interfere with a write's deadline.
func (a *deadlineArm) hold(ctx context.Context, set func(time.Time) error) func() {
	deadline, _ := ctx.Deadline()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.held && a.ctx == ctx {
		if !a.applied.Equal(deadline) {
			_ = set(deadline)
			a.applied = deadline
		}
		return noopUnarm
	}
	a.releaseLocked()
	_ = set(deadline)
	a.applied = deadline
	a.ctx = ctx
	a.held = true
	if ctx.Done() == nil {
		// context.Background and its kin can never be cancelled, so a watcher
		// on one is a registration that is guaranteed never to fire. The
		// deadline is still applied above: a context with a deadline but no
		// Done channel does not exist, but applying it unconditionally means
		// this branch never has to reason about that.
		return noopUnarm
	}
	finished := make(chan struct{})
	a.finished = finished
	a.stop = context.AfterFunc(ctx, func() {
		_ = set(aLongTimeAgo)
		close(finished)
	})
	return noopUnarm
}

// reapply reinstalls the deadline this cache believes is installed.
//
// It is for code that sets its own deadline on the same socket for its own
// reasons and must hand it back in the state it found it.
func (a *deadlineArm) reapply(set func(time.Time) error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.held {
		_ = set(a.applied)
	}
}

// release drops the watcher. Close calls it so that a carrier torn down while
// its context is still live does not leave a node on that context's list.
func (a *deadlineArm) release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseLocked()
}

func (a *deadlineArm) releaseLocked() {
	if a.stop != nil {
		if !a.stop() {
			// The watcher is already running. Wait for it rather than racing
			// its SetDeadline against the caller's next one.
			<-a.finished
		}
		a.stop = nil
		a.finished = nil
	}
	a.ctx = nil
	a.held = false
	a.applied = time.Time{}
}
