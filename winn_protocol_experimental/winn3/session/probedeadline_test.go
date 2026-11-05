package session

import (
	"testing"
	"time"
)

// The probe deadline and the probe expiry have to agree about the boundary
// instant, and for a while they did not.
//
// NextDeadline arms an outstanding probe's wake at `st.at + Probe.Max`. The
// expiry in tickEstablished asked `now.Sub(st.at) > Probe.Max` — strictly
// greater. Those two disagree on exactly one instant, the boundary itself, and
// on that instant the driver says "due now" and then declines to do the work.
//
// winn3/driver.Loop.waitForWork takes `deadline.Sub(now) <= 0` as "already due;
// the next Poll consumes it" and returns WITHOUT building a timer. When the Poll
// does not consume it, the loop comes straight back to the same deadline. On a
// real clock the spin is invisible because time moves underneath it. On an
// injected clock nothing moves, because the only goroutine that can move it is
// the test's own and it is inside the loop; the write loop then spends its
// maxSpins=4096 budget and exits, after which the session reports `established`
// with a nil error forever and every assertion above it is reading a corpse.
//
// Which side is wrong is settled by the rest of the package rather than by
// taste. Every other deadline here is armed with `now.Add(d)` and fired with an
// INCLUSIVE test — silenceAt and probeAt at `!now.Before(...)`, rekeyAt at
// `!now.Before(...)`, rekeyEnd and phaseAt likewise, and the probe spacing at
// `now.Sub(lastOpened) >= probeEvery`. winn3/driver's own consumer is inclusive
// too (`d <= 0` is "due"). The inflight probe was the only exclusive one.
//
// Probe.Max also has a documented meaning that the exclusive form contradicts.
// It is a Draw ceiling — drawTruncExp clamps into [Min, Max] and validate
// refuses Max <= Min — and the liveness budget is quoted throughout the stack as
// MaxLostProbes x Probe.Max (dpbridge.bridge, netlab/burstloss_test, and
// config.go's own "eighty seconds worst case" for 4 x 20 s). Under `>` the real
// worst case is MaxLostProbes x (Probe.Max + 1ns) and Max is not a maximum. So
// the expiry moved to `>=` and the arming was left alone; arming at
// `at + Probe.Max + 1` would have agreed with itself just as well and would have
// made every one of those documented figures wrong by a nanosecond per probe.

// TestAProbeIsLostTheInstantItHasBeenOutstandingForProbeMax pins the boundary
// from both sides, so that a later edit cannot move it in either direction
// without saying so.
func TestAProbeIsLostTheInstantItHasBeenOutstandingForProbeMax(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		age      func(max time.Duration) time.Duration
		wantLost bool
	}{
		{"one tick short of the ceiling", func(m time.Duration) time.Duration { return m - 1 }, false},
		{"exactly on the ceiling", func(m time.Duration) time.Duration { return m }, true},
		{"one tick past the ceiling", func(m time.Duration) time.Duration { return m + 1 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := established(t, func(cli, gw *Config) {
				quietConfig(cli)
				quietConfig(gw)
				// Nothing but the outstanding probe may be due, so that what the
				// deadline reports below is unambiguously this probe's.
				cli.Silence = silentDraw()
				gw.Silence = silentDraw()
			})
			d := p.cli

			d.mu.Lock()
			now := p.clk.Now()
			max := d.cfg.Probe.Max
			age := tc.age(max)
			sent := now.Add(-age)
			// The fixture asserts its own arithmetic. A backdate that is not the
			// age it claims would make every row below pass for the wrong reason.
			if got := now.Sub(sent); got != age {
				d.mu.Unlock()
				t.Fatalf("fixture is %s old, wanted %s (Probe.Max is %s)", got, age, max)
			}
			tok := [pingTokenSize]byte{1}
			d.inflight[tok] = probeState{at: sent, wide: true}
			d.lastOpened = sent.Add(-time.Second)
			d.mu.Unlock()

			// What the driver tells its caller to wake at. This is the arming
			// side of the pair, and it is asserted exactly: if a future fix moves
			// the arming instead of the comparison, this is where it shows up.
			dl := d.NextDeadline()
			if want := sent.Add(max); !dl.Equal(want) {
				t.Fatalf("NextDeadline is %s; the outstanding probe was sent at %s and Probe.Max is %s, "+
					"so the wake belongs at %s", dl.UTC(), sent.UTC(), max, want.UTC())
			}

			if _, err := d.Poll(); err != nil {
				t.Fatalf("poll: %v", err)
			}

			d.mu.Lock()
			_, stillInflight := d.inflight[tok]
			lost, probesLost := d.lost, d.stats.ProbesLost
			d.mu.Unlock()

			gotLost := !stillInflight
			if gotLost != tc.wantLost {
				t.Fatalf("a probe outstanding for %s (Probe.Max is %s) was lost=%v, want %v. "+
					"Probe.Max is the CEILING on how long a probe may go unanswered, so the "+
					"budget is spent at the ceiling, not one tick past it: MaxLostProbes x "+
					"Probe.Max is quoted as an exact worst case across this stack.",
					age, max, gotLost, tc.wantLost)
			}
			if want := boolToInt(tc.wantLost); lost != want || probesLost != uint64(want) {
				t.Fatalf("lost=%d ProbesLost=%d after a %s-old probe, want %d and %d",
					lost, probesLost, age, want, want)
			}
		})
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestTheProbeDeadlineDoesNotHotSpinOnItsOwnBoundary is the failure the
// boundary actually produced, reproduced at the layer that produced it.
//
// It is deliberately not "the call returns". A call that returns is exactly what
// the defect looked like from above; the loop returned promptly every time and
// simply never made progress. So the assertion is the number of wake-ups spent
// against a clock that is held still, which is the quantity winn3/driver's
// maxSpins guard is counting when it kills both write loops.
func TestTheProbeDeadlineDoesNotHotSpinOnItsOwnBoundary(t *testing.T) {
	t.Parallel()

	p := established(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.Silence = silentDraw()
		gw.Silence = silentDraw()
	})
	d := p.cli

	d.mu.Lock()
	start := p.clk.Now()
	max := d.cfg.Probe.Max
	sent := start.Add(-max) // exactly on the boundary
	tok := [pingTokenSize]byte{1}
	d.inflight[tok] = probeState{at: sent, wide: true}
	d.lastOpened = sent.Add(-time.Second)
	d.mu.Unlock()

	// winn3/driver.Loop.waitForWork + drain, reduced to the two lines that
	// matter, with the clock nailed to `start`. A wake that finds the deadline in
	// the future is where the real loop builds a timer and sleeps, so that is the
	// loop's exit; anything else is a wake that must have moved the driver
	// forward under its own power, because nothing else here can.
	const spinBound = 4096 // winn3/driver.maxSpins
	wakes := 0
	for {
		dl := d.NextDeadline()
		if dl.IsZero() || dl.After(p.clk.Now()) {
			break
		}
		for i := 0; i < 512; i++ {
			msg, err := d.Poll()
			if err != nil {
				t.Fatalf("poll on wake %d: %v", wakes+1, err)
			}
			if msg == nil {
				break
			}
		}
		wakes++
		if wakes > spinBound {
			d.mu.Lock()
			n, lost := len(d.inflight), d.lost
			d.mu.Unlock()
			t.Fatalf("the loop woke %d times without the clock moving (still %s, %s of injected time "+
				"elapsed); %d probes are still inflight and %d have been counted lost. NextDeadline "+
				"keeps reporting %s, which is not in the future, and the Poll it schedules does not "+
				"consume it — the deadline is armed at sent+Probe.Max (%s) and the expiry excludes "+
				"that instant.",
				wakes, p.clk.Now().UTC(), p.clk.Now().Sub(start), n, lost, d.NextDeadline().UTC(), max)
		}
	}

	// The clock is the control. If it moved, the loop above was not the loop the
	// driver's real caller runs and the wake count below means nothing.
	if elapsed := p.clk.Now().Sub(start); elapsed != 0 {
		t.Fatalf("the injected clock advanced by %s during a wait that must not advance it", elapsed)
	}
	if wakes != 1 {
		t.Fatalf("the boundary cost %d wakes against a frozen clock, want exactly 1: one wake to "+
			"consume the deadline it was woken for", wakes)
	}

	d.mu.Lock()
	_, stillInflight := d.inflight[tok]
	lost := d.lost
	d.mu.Unlock()
	if stillInflight || lost != 1 {
		t.Fatalf("after the wake the probe is inflight=%v and lost=%d; the loop stopped spinning "+
			"without the probe actually expiring, which would be the wrong cure", stillInflight, lost)
	}
	if dl := d.NextDeadline(); !dl.IsZero() && !dl.After(start) {
		t.Fatalf("NextDeadline still reports %s, which is not in the future of %s; the caller would "+
			"come straight back", dl.UTC(), start.UTC())
	}
}

// TestTheDeadPathBudgetStillLandsExactlyOnMaxLostProbes guards the behaviour the
// boundary fix is most likely to damage.
//
// Moving an expiry from `>` to `>=` makes probes expire marginally sooner, and
// the failure mode to be afraid of is a teardown that now fires early, or one
// that stops firing at all. MaxLostProbes is 4 and the contract is exact: three
// expired probes are not a teardown, the fourth is.
func TestTheDeadPathBudgetStillLandsExactlyOnMaxLostProbes(t *testing.T) {
	t.Parallel()

	p := established(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.Silence = silentDraw()
		gw.Silence = silentDraw()
		cli.MaxLostProbes = DefaultMaxLostProbes
	})
	d := p.cli

	d.mu.Lock()
	if d.cfg.MaxLostProbes != 4 {
		d.mu.Unlock()
		t.Fatalf("MaxLostProbes is %d; this test is written against the documented 4", d.cfg.MaxLostProbes)
	}
	max := d.cfg.Probe.Max
	d.mu.Unlock()

	// Every probe is expired at exactly the boundary, one at a time, and the
	// state is read after each. A peer that answers nothing sends nothing, so
	// lastOpened stays behind the probes throughout.
	for i := 1; i <= 4; i++ {
		d.mu.Lock()
		now := p.clk.Now()
		sent := now.Add(-max)
		d.inflight[[pingTokenSize]byte{byte(i)}] = probeState{at: sent, wide: true}
		if i == 1 {
			d.lastOpened = sent.Add(-time.Second)
		}
		d.mu.Unlock()

		if _, err := d.Poll(); err != nil {
			t.Fatalf("poll on probe %d: %v", i, err)
		}

		d.mu.Lock()
		lost, state := d.lost, d.state
		d.mu.Unlock()
		if lost != i {
			t.Fatalf("after expiring probe %d the driver has counted %d lost", i, lost)
		}
		wantDown := i >= 4
		if gone := state != StateEstablished; gone != wantDown {
			t.Fatalf("state is %s after %d lost probes of a %d-probe budget; want torn down=%v",
				state, lost, 4, wantDown)
		}
	}

	if got := p.cli.LocalCloseReason(); got != CloseDesynchronised {
		t.Errorf("close reason is %s, want %s", got, CloseDesynchronised)
	}
}
