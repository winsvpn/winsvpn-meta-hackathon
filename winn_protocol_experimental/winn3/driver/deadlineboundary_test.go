package driver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// This package owns the only timer in v3, so it owns the instant a deadline
// arrives, and until this file nothing measured what happens ON that instant.
//
// The pair is split across two packages. winn3/session ARMS: a fresh gateway is
// INITIATING and NextDeadline reports phaseAt, which is the construction instant
// plus one whole client retry budget. This package CONSUMES: waitForWork takes
// `deadline.Sub(now) <= 0` as "already due; do not build a timer, the next Poll
// consumes it". Both halves have to agree about the boundary instant, and a
// disagreement there does not fail — it spins.
//
// TestWaitForWorkHandlesEveryDeadlineShape covers the three SHAPES a deadline
// can take, and it reaches the "already past" shape by advancing 24 hours
// against the default budget of 23.5 s. That margin is right for what it is
// about: three structurally different branches, told apart unambiguously. But
// 24 hours never lands on the instant, and measured on 2026-08-09 with
// `go test -overlay` the whole driver package stayed green (exit 0, no
// --- FAIL: line) with `d <= 0` narrowed to `d < 0`.
//
// That narrowing is exactly the ingredient that produced the flake which failed
// 18 of 30 concurrent runs across five tests. winn3/session's inflight probe
// armed at `at + Probe.Max` and expired on `> Probe.Max`; on the boundary
// instant the deadline said "due now" and the expiry declined to act, so this
// loop returned promptly, consumed nothing, and came straight back. On a real
// clock time moves underneath the spin and it is invisible. On an injected clock
// nothing moves, and the write loop spends its maxSpins budget and exits.
//
// So the two tests below are deliberately different in kind. The first asserts
// the boundary one tick either way. The second asserts the quantity the defect
// actually produced: wake-ups spent against a clock that is held still.

// countingClock is a stepClock that records every timer the loop asks it for.
//
// The count is the measurement, not decoration. "Returned promptly" cannot tell
// the two branches apart at the boundary: stepClock fires a non-positive
// duration immediately, on purpose, so that a loop spinning on a zero-length
// wait cannot hide inside the fake — and time.NewTimer does the same. The only
// externally visible difference between `d <= 0` and `d < 0` on the instant
// itself is whether a timer was built at all, which is precisely what
// waitForWork's own contract line promises not to do.
type countingClock struct {
	*stepClock

	tmu   sync.Mutex
	built []time.Duration
}

func newCountingClock() *countingClock { return &countingClock{stepClock: newStepClock()} }

func (c *countingClock) NewTimer(d time.Duration) Timer {
	c.tmu.Lock()
	c.built = append(c.built, d)
	c.tmu.Unlock()
	return c.stepClock.NewTimer(d)
}

// reset forgets the timers built so far, so that a measurement covers one call
// and not the fixture's construction.
func (c *countingClock) reset() {
	c.tmu.Lock()
	c.built = nil
	c.tmu.Unlock()
}

func (c *countingClock) timersBuilt() []time.Duration {
	c.tmu.Lock()
	defer c.tmu.Unlock()
	return append([]time.Duration(nil), c.built...)
}

var _ Clock = (*countingClock)(nil)

// boundaryRetry is the retry schedule these two tests pin. It is stated rather
// than defaulted so that the budget below is a number this file owns.
var boundaryRetry = session.Retry{Base: 5 * time.Second, Cap: 20 * time.Second, Attempts: 6}

// boundaryBudget is handshakeBudget(boundaryRetry): 5+10+20+20+20+20 of backoff,
// plus one Cap of slack.
const boundaryBudget = 115 * time.Second

// budgetOf is a second implementation of winn3/session's handshakeBudget, and
// duplicating four lines is the entire point of it.
//
// Every row below is expressed relative to what NextDeadline reports, so a
// change that moved the ARMING — the session handing out phaseAt+1ns rather
// than phaseAt — would move all three rows with it and be invisible. An
// independently computed instant is the only anchor that makes the arming half
// assertable from this side of the package boundary, and it is the same thing
// winn3/session's own probe boundary test does when it pins NextDeadline to
// sent+Probe.Max exactly.
func budgetOf(r session.Retry) time.Duration {
	total := time.Duration(0)
	w := r.Base
	for i := 0; i < r.Attempts; i++ {
		total += w
		if w < r.Cap {
			w *= 2
			if w > r.Cap {
				w = r.Cap
			}
		}
	}
	return total + r.Cap
}

// boundaryGateway builds a gateway loop that is INITIATING, on a clock nothing
// but the test can move, and returns it with the instant it was built at.
func boundaryGateway(t *testing.T, clk *countingClock) (*endpoint, time.Time) {
	t.Helper()
	start := clk.Now()
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	gw := newGatewayEndpoint(t, newKeyring(t), endpointOpts{
		sizing: planSizing(t), carrier: pipe, clock: clk, noTun: true,
		tweak: func(c *session.Config) { c.Retry = boundaryRetry },
	})

	// The fixture asserts its own arithmetic before anything relies on it.
	if got := budgetOf(boundaryRetry); got != boundaryBudget {
		t.Fatalf("this file's own budget arithmetic gives %s for Retry{%s, %s, %d}, and the file is "+
			"written against %s", got, boundaryRetry.Base, boundaryRetry.Cap, boundaryRetry.Attempts,
			boundaryBudget)
	}
	// The ARMING side of the pair, asserted exactly and against an instant this
	// file computed rather than against whatever the session chose to report.
	dl := gw.loop.Session().NextDeadline()
	if want := start.Add(boundaryBudget); !dl.Equal(want) {
		t.Fatalf("a fresh gateway's deadline is %s; it was built at %s and one client budget is %s "+
			"(Retry %s base, %s cap, %d attempts), so the wake belongs at %s — a difference of %s. "+
			"The gateway never retransmits: this deadline IS the bound on how long a half-open "+
			"session holds state, and moving it moves every row below with it.",
			dl.UTC(), start.UTC(), boundaryBudget, boundaryRetry.Base, boundaryRetry.Cap,
			boundaryRetry.Attempts, want.UTC(), dl.Sub(want))
	}
	return gw, start
}

// TestWaitForWorkTreatsTheDeadlineInstantItselfAsDue pins the wait one tick
// either side of the instant it is waiting for.
//
// The middle row is the one that matters. The row before it exists so that a
// mutation which simply stopped waiting altogether cannot read as a pass, and
// the row after it is the shape the existing suite already covers by a margin.
func TestWaitForWorkTreatsTheDeadlineInstantItselfAsDue(t *testing.T) {
	for _, tc := range []struct {
		name string
		// offset from the deadline: negative is short of it.
		offset     time.Duration
		wantDue    bool
		wantTimers []time.Duration
	}{
		{"one tick short of the deadline", -1, false, []time.Duration{1}},
		{"exactly on the deadline", 0, true, nil},
		{"one tick past the deadline", 1, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := newCountingClock()
			gw, start := boundaryGateway(t, clk)
			dl := gw.loop.Session().NextDeadline()

			clk.Advance(boundaryBudget + tc.offset)
			// Again the fixture checks itself: a clock that is not where this
			// row says would make the row pass for the wrong reason.
			if got := dl.Sub(clk.Now()); got != -tc.offset {
				t.Fatalf("the clock is %s from the deadline, wanted %s (built at %s, deadline %s, "+
					"clock now %s)", got, -tc.offset, start.UTC(), dl.UTC(), clk.Now().UTC())
			}

			// Measure this call and not the fixture's construction.
			clk.reset()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- gw.loop.waitForWork(ctx) }()

			if tc.wantDue {
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("waitForWork returned %v at exactly %s from its deadline", err, -tc.offset)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("waitForWork slept at %s from its deadline and nothing can wake it: the "+
						"clock is nailed to %s, the deadline is %s, and this loop is the only thing "+
						"that could move either. A deadline that has ARRIVED is due; the next Poll "+
						"consumes it.", -tc.offset, clk.Now().UTC(), dl.UTC())
				}
			} else {
				select {
				case err := <-done:
					t.Fatalf("waitForWork returned %v with its deadline still %s in the future "+
						"(clock %s, deadline %s); a loop that does not wait for a deadline it can "+
						"see is a loop that polls a handset flat",
						err, dl.Sub(clk.Now()), clk.Now().UTC(), dl.UTC())
				case <-time.After(250 * time.Millisecond):
				}
				cancel()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("waitForWork returned %v on cancellation, want context.Canceled", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("waitForWork did not return on cancellation while %s short of its deadline",
						dl.Sub(clk.Now()))
				}
			}

			built := clk.timersBuilt()
			if !sameDurations(built, tc.wantTimers) {
				t.Fatalf("at %s from its deadline waitForWork built %d timer(s) %s, want %d %s. "+
					"waitForWork's contract on a deadline that has arrived is that it builds NO timer "+
					"— `d <= 0` means the next Poll consumes it — and whether a timer was built is the "+
					"only thing that distinguishes an inclusive test from an exclusive one here, "+
					"because both fakes and time.NewTimer fire a zero-length wait immediately.",
					-tc.offset, len(built), showDurations(built),
					len(tc.wantTimers), showDurations(tc.wantTimers))
			}
		})
	}
}

// TestTheGatewayDeadlineDoesNotHotSpinOnItsOwnBoundary is the failure this shape
// actually produces, reproduced at the layer that produces it.
//
// It is deliberately not "the call returns". A call that returns is exactly what
// the defect looked like from above: the loop returned promptly every time and
// simply never made progress. So the assertion is the number of wake-ups spent
// against a clock that is held still, which is the quantity maxSpins is counting
// when it kills the write loop, and the clock is the control — if it moved, this
// loop was not the loop the real caller runs and the count means nothing.
func TestTheGatewayDeadlineDoesNotHotSpinOnItsOwnBoundary(t *testing.T) {
	clk := newCountingClock()
	gw, _ := boundaryGateway(t, clk)
	dl := gw.loop.Session().NextDeadline()

	// Park the clock EXACTLY on the deadline and leave it there. Nothing below
	// moves it, so every wake has to be paid for out of the loop's own budget.
	clk.Advance(boundaryBudget)
	frozen := clk.Now()
	if !frozen.Equal(dl) {
		t.Fatalf("the clock is at %s and the deadline is %s, a difference of %s; this test is only "+
			"about the instant they coincide", frozen.UTC(), dl.UTC(), frozen.Sub(dl))
	}

	// Loop.writeLoop, reduced to the three lines that matter. syncGate is left
	// out because this endpoint has no tun; everything else is the real one,
	// including the order — drain, then the terminal check, then the wait.
	ctx := context.Background()
	wakes, spins := 0, 0
	for {
		wakes++
		moved, err := gw.loop.drain(ctx)
		if err != nil {
			t.Fatalf("drain on wake %d: %v", wakes, err)
		}
		if gw.loop.Session().State().Terminal() {
			break
		}
		if moved > 0 {
			spins = 0
		} else {
			spins++
		}
		if spins > maxSpins {
			st := gw.loop.Session().State()
			t.Fatalf("the write loop woke %d times and spent %d of them moving nothing, without the "+
				"clock moving at all (still %s, %s of injected time elapsed). The session is %s, "+
				"NextDeadline keeps reporting %s — which is not in the future of %s — and the Poll it "+
				"schedules does not consume it. That is the arm/expire disagreement: the deadline is "+
				"armed AT the instant and something downstream excludes it.",
				wakes, spins, clk.Now().UTC(), clk.Now().Sub(frozen), st,
				gw.loop.Session().NextDeadline().UTC(), clk.Now().UTC())
		}
		if err := gw.loop.waitForWork(ctx); err != nil {
			t.Fatalf("waitForWork on wake %d: %v", wakes, err)
		}
	}

	// The clock is the control.
	if elapsed := clk.Now().Sub(frozen); elapsed != 0 {
		t.Fatalf("the injected clock advanced by %s during a wait that must not advance it", elapsed)
	}
	if wakes != 1 || spins != 0 {
		t.Fatalf("the boundary cost %d wake(s) and %d empty wake(s) against a frozen clock, want "+
			"exactly 1 and 0: one wake to consume the deadline it was woken for, and no wake at all "+
			"that moved nothing", wakes, spins)
	}

	// And it stopped spinning because the deadline was CONSUMED, not because
	// something upstream stopped scheduling it — which would be the wrong cure.
	st := gw.loop.Session().State()
	if st != session.StateFailed {
		t.Fatalf("the gateway is %s one client budget after it was built; a gateway never retransmits, "+
			"so it waits out exactly one budget and then drops the half-open session", st)
	}
	if got := gw.loop.Session().LocalCloseReason(); got != session.CloseProtocolError {
		t.Fatalf("the half-open session closed with reason %s, want %s", got, session.CloseProtocolError)
	}
	if err := gw.loop.Session().Err(); !errors.Is(err, session.ErrPeerUnreachable) {
		t.Fatalf("a gateway that timed out waiting for a client reports %v, want ErrPeerUnreachable", err)
	}
	if dl := gw.loop.Session().NextDeadline(); !dl.IsZero() {
		t.Fatalf("a terminal session still schedules a deadline at %s; the caller would come straight "+
			"back", dl.UTC())
	}
}

func sameDurations(got, want []time.Duration) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func showDurations(ds []time.Duration) string {
	if len(ds) == 0 {
		return "[]"
	}
	out := "["
	for i, d := range ds {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprint(d)
	}
	return out + "]"
}
