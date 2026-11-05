package session

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestSessionHasNoTimersOrSockets is the structural guard, mirroring the core's
// test of the same shape.
//
// The core must hold no timer and no socket so a carrier can be swapped under a
// live session; the driver must hold none for the same reason plus one more.
// The timing policy lives HERE and only here. The measured 25.000-second
// zero-jitter keepalive was a timer in the wrong layer, and a package that can
// wake itself will eventually grow a second schedule that disagrees with the
// first.
//
// math/rand is banned alongside them. An observer who can guess the seed
// predicts every keepalive, which turns a memoryless schedule back into a
// metronome that merely looks random — and would pass every statistical test in
// jitter_test.go, because those measure the shape of the distribution and not
// the predictability of the stream.
func TestSessionHasNoTimersOrSockets(t *testing.T) {
	banned := []string{
		"time.Tick",
		"time.NewTicker",
		"time.NewTimer",
		"time.After(",
		"time.Sleep",
		"math/rand",
		"go func",
		`"net"`,
		`"net/`,
		`"os"`,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, b := range banned {
			if bytes.Contains(src, []byte(b)) {
				t.Errorf("%s references %s; the session driver must hold no timer, no socket and no weak RNG", name, b)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no production files were checked; this guard has no teeth")
	}
}

// --- the metronome detector -------------------------------------------------

// metronomeVerdict names the reason a series of inter-packet intervals looks
// like a clock, or returns "" if it does not.
//
// Four independent checks, because each alone is cheap to satisfy by accident:
// how many distinct values there are, how concentrated the most common value is,
// how wide the spread is relative to the mean, and whether one interval predicts
// the next. A periodogram spike shows up in at least one of them.
func metronomeVerdict(intervals []time.Duration) string {
	if len(intervals) < 32 {
		return "too few intervals to judge"
	}
	counts := make(map[time.Duration]int, len(intervals))
	var sum float64
	for _, v := range intervals {
		counts[v]++
		sum += float64(v)
	}
	mean := sum / float64(len(intervals))

	if distinct := float64(len(counts)) / float64(len(intervals)); distinct < 0.5 {
		return fmt.Sprintf("only %d distinct interval values across %d fires", len(counts), len(intervals))
	}
	worst, worstN := time.Duration(0), 0
	for v, n := range counts {
		if n > worstN {
			worstN, worst = n, v
		}
	}
	if frac := float64(worstN) / float64(len(intervals)); frac > 0.10 {
		return fmt.Sprintf("interval %s holds %.1f%% of the fires", worst, frac*100)
	}

	var varsum float64
	for _, v := range intervals {
		d := float64(v) - mean
		varsum += d * d
	}
	sd := math.Sqrt(varsum / float64(len(intervals)))
	if cv := sd / mean; cv < 0.25 {
		return fmt.Sprintf("coefficient of variation is only %.3f", cv)
	}

	for lag := 1; lag <= 8 && lag < len(intervals)/4; lag++ {
		var num float64
		for i := 0; i+lag < len(intervals); i++ {
			num += (float64(intervals[i]) - mean) * (float64(intervals[i+lag]) - mean)
		}
		if r := num / varsum; math.Abs(r) > 0.25 {
			return fmt.Sprintf("autocorrelation %.3f at lag %d", r, lag)
		}
	}
	return ""
}

// TestMetronomeDetectorHasTeeth feeds the detector the exact failure it exists
// to find, plus two near misses, and requires it to object to all three.
//
// A passing invariant test that could never fail is worse than no test at all,
// so the guard is checked before it is trusted. The 25.000-second series is the
// measurement from a real handset that this protocol was redesigned to stop
// producing.
func TestMetronomeDetectorHasTeeth(t *testing.T) {
	fixed := make([]time.Duration, 256)
	for i := range fixed {
		fixed[i] = 25 * time.Second
	}
	if v := metronomeVerdict(fixed); v == "" {
		t.Error("the detector accepted a 25.000-second zero-jitter metronome")
	}

	// A metronome with a millisecond of dither: distinct values, but no spread.
	dithered := make([]time.Duration, 256)
	for i := range dithered {
		dithered[i] = 25*time.Second + time.Duration(i%7)*time.Millisecond
	}
	if v := metronomeVerdict(dithered); v == "" {
		t.Error("the detector accepted a metronome with cosmetic dither")
	}

	// A sawtooth: wide spread, plenty of distinct values, but perfectly
	// predictable from the previous interval.
	saw := make([]time.Duration, 256)
	for i := range saw {
		saw[i] = time.Duration(5+(i%40)) * time.Second
	}
	if v := metronomeVerdict(saw); v == "" {
		t.Error("the detector accepted a fully predictable sawtooth")
	}
}

// --- the virtual-time budget invariant --------------------------------------
//
// THE INVARIANT, stated once, here, next to the rigs it governs:
//
//	A rig that advances an INJECTED clock must have a stated VIRTUAL-TIME
//	budget, and that budget must sit STRICTLY BELOW the shortest period of
//	every timer the test is not trying to exercise.
//
// The budget is virtual time, never a step count, a real-time deadline or a
// "settle until quiet" call. Those three are the shape this class of defect
// takes: each of them bounds the rig in a currency that has no relationship to
// the periods of the timers in the code under test, so the amount of virtual
// time that reaches the driver is whatever falls out — and one day it is enough
// for a timer the test never meant to touch to fire inside the measurement.
//
// Measured, twice, in this tree on 2026-08-09:
//
//   - netlab: Settle was bounded only in REAL time, so 60 s of it poured about
//     3.5 h of virtual time into a session, tripped winn3/driver's maxSpins=4096
//     guard and killed both write loops. One defect, five failing test names,
//     18 of 30 runs under six-way concurrency.
//
//   - here: soloEmissions was bounded by maxSteps=4_000_000 at a 100 ms step —
//     a 400,000 s budget — while quietConfig parked Probe at only {1h, 2h, 3h}.
//     The run actually spends about 4,900 s, so Probe.Min was crossed on EVERY
//     run and the only question was whether the draw came in under it. A probe
//     then fired inside a window meant to measure the silence timer alone and
//     split one silence interval in two, which reads as a keepalive interval
//     below DefaultSilenceMin. Measured 14 failures in 200 runs (7.0 %), every
//     one of them at a virtual elapsed past Probe.Min.
//
// The two halves of the fix are inseparable and that is the point: a budget is
// meaningless without the timer periods it is checked against, so requireQuietBudget
// reads the periods off the DRIVER'S OWN CONFIG rather than trusting a constant,
// and soloEmissions DERIVES its budget from the draw it is measuring rather than
// naming a number.

// quietHorizon is where quietConfig parks every timer it silences.
//
// It is not "a large number": it is the ceiling every quietConfig test's virtual
// budget must stay under, and requireQuietBudget enforces that rather than
// trusting it. The largest budget any rig in this package derives is
// soloEmissions' 300 x (45 s + 100 ms) = 3 h 45 m 30 s, so the margin is visible
// here instead of implied — and if a future test needs more, the check fires and
// this constant is where the answer goes.
const quietHorizon = 24 * time.Hour

// quietConfig removes everything except the silence timer from the emission
// schedule, so a measurement of keepalive spacing measures only the silence
// timer.
//
// "Removes" is the contract, and quietHorizon is what makes it true. The probe
// draw used to be {1h, 2h, 3h}, which removed nothing from a rig that spends
// 4,900 s: see the invariant above.
func quietConfig(c *Config) {
	c.Probe = Draw{Min: quietHorizon, Mean: 2 * quietHorizon, Max: 3 * quietHorizon}
	c.MaxLostProbes = 1 << 20
	c.RekeyInterval = Draw{Min: quietHorizon, Mean: 2 * quietHorizon, Max: 3 * quietHorizon}
	c.RekeyAfterMessages = core.RejectAfterMessages
	c.RekeyAfterBytes = 1 << 60
}

// exercises names a schedule the caller is deliberately driving, so the budget
// check skips it. Naming it is the whole safety property: "not trying to
// exercise" has to be a statement the test makes, not something the helper
// guesses, or the check would either block the tests that mean to drive a
// schedule or wave through the ones that do not.
type exercises string

const (
	exercisesProbe exercises = "Probe.Min"
	exercisesRekey exercises = "RekeyInterval.Min"
)

// requireQuietBudget holds the invariant for one driver: it refuses to let a rig
// run if the virtual time that rig may inject reaches any timer the caller has
// not declared it is exercising.
//
// The periods are read off the driver's LIVE config, not off quietHorizon, so a
// test that overrides Probe or RekeyInterval after quietConfig is checked
// against what it actually configured — which is the half of "chosen together"
// that a bare constant cannot give you. Probe.Min and RekeyInterval.Min are the
// only two entry points: every other schedule in this driver is downstream of
// one of them (the probe budget needs a probe, RekeyTimeout needs a rekey) or of
// the handshake, which is over before any of these rigs start.
func requireQuietBudget(t *testing.T, d *Driver, budget time.Duration, exercised ...exercises) {
	t.Helper()
	d.mu.Lock()
	probe, rekey := d.cfg.Probe.Min, d.cfg.RekeyInterval.Min
	d.mu.Unlock()
	for _, tm := range []struct {
		name   exercises
		period time.Duration
	}{
		{exercisesProbe, probe},
		{exercisesRekey, rekey},
	} {
		skip := false
		for _, e := range exercised {
			if e == tm.name {
				skip = true
			}
		}
		if skip || budget < tm.period {
			continue
		}
		t.Fatalf("this rig may inject %s of virtual time and %s is %s, so a timer the test has not "+
			"declared it is exercising can fire inside the measurement (over by %s). A rig's "+
			"virtual-time budget must sit strictly below the shortest period of every timer it is "+
			"not trying to exercise: lower the budget, raise quietHorizon (%s) past it, or — if "+
			"this rig really does mean to drive that schedule — say so by passing %q.",
			budget, tm.name, tm.period, budget-tm.period, quietHorizon, tm.name)
	}
}

// soloEmissions advances the clock in fixed steps, polling one driver and
// discarding whatever it emits, and returns the instants at which it emitted.
//
// The budget is DERIVED, not chosen. want emissions of the silence timer cost at
// most want x Silence.Max, plus one step of polling granularity each, so that sum
// is the most virtual time this loop can inject — and it is computed from the
// very draw the caller is measuring, which is what "chosen together" means. There
// is no step count: the old maxSteps was 4,000,000, a number with no relationship
// to anything, and it is what let this loop run past a probe.
func soloEmissions(t *testing.T, d *Driver, clk *testClock, step time.Duration, want int) []time.Time {
	t.Helper()
	d.mu.Lock()
	silenceMax := d.cfg.Silence.Max
	d.mu.Unlock()
	budget := time.Duration(want) * (silenceMax + step)
	requireQuietBudget(t, d, budget)

	start := clk.Now()
	var at []time.Time
	for len(at) < want && clk.Now().Sub(start) < budget {
		for {
			msg, err := d.Poll()
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if msg == nil {
				break
			}
			at = append(at, clk.Now())
		}
		clk.Advance(step)
	}
	if len(at) < want {
		t.Fatalf("observed %d of %d emissions in %s of injected virtual time; the budget is spent. "+
			"It is %s = %d x (Silence.Max %s + step %s), which is the most %d fires of this draw can "+
			"cost, so falling short means the driver stopped emitting rather than that the rig ran out",
			len(at), want, clk.Now().Sub(start), budget, want, silenceMax, step, want)
	}
	return at
}

func intervals(at []time.Time) []time.Duration {
	out := make([]time.Duration, 0, len(at))
	for i := 1; i < len(at); i++ {
		out = append(out, at[i].Sub(at[i-1]))
	}
	return out
}

// TestKeepaliveIsNotAMetronome is the F2 test: it measures what the driver
// actually puts on the wire when a session is idle and runs the same detector
// over it that TestMetronomeDetectorHasTeeth proved has teeth.
func TestKeepaliveIsNotAMetronome(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
	})
	p.establish()

	// Isolate the client so its emissions are its own silence timer and nothing
	// else: no PONGs to prompt it, no gateway traffic to reset it. soloEmissions
	// bounds itself in VIRTUAL time and checks that bound against the probe and
	// rekey schedules, so "nothing else" is enforced rather than assumed.
	start := p.clk.Now()
	at := soloEmissions(t, p.cli, p.clk, 100*time.Millisecond, 300)
	iv := intervals(at)
	if len(iv) < 250 {
		t.Fatalf("only observed %d keepalive intervals", len(iv))
	}
	if v := metronomeVerdict(iv); v != "" {
		t.Errorf("the driver's idle keepalive looks like a clock: %s", v)
	}
	for i, d := range iv {
		if d < DefaultSilenceMin || d > DefaultSilenceMax+200*time.Millisecond {
			// Every quantity here is measured. An interval below the floor means
			// something OTHER than the silence timer emitted inside the window,
			// and the elapsed figure is what says which: past Probe.Min and it is
			// a probe, which is the defect this rig's budget exists to prevent.
			t.Fatalf("keepalive interval %d of %d is %s, outside the configured support "+
				"[%s, %s]; it ends at %s of injected virtual time, of %s total, against a "+
				"Probe.Min of %s",
				i, len(iv), d, DefaultSilenceMin, DefaultSilenceMax+200*time.Millisecond,
				at[i+1].Sub(start), p.clk.Now().Sub(start), quietHorizon)
		}
	}
	if p.cli.Stats().PingsSent == 0 {
		t.Fatal("no PINGs were sent; this test measured nothing")
	}
}

// TestSilenceTimerNeverFiresOnAnActiveFlow is the other half of F2, and it is
// the half a metronome fails by definition.
//
// A silence timer measures time since the last packet THIS side sent, so a flow
// that is sending has nothing to keep alive and emits no keepalive at all. There
// is no "keepalive-sized packet" to count because there is no keepalive.
func TestSilenceTimerNeverFiresOnAnActiveFlow(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
	})
	p.establish()

	payload := make([]byte, 200)
	// One second of virtual time per packet, well inside the 5-second floor of
	// the silence draw, for twenty virtual minutes.
	//
	// The assertion below is PingsSent == 0, so a probe firing inside this window
	// would read as the silence timer misbehaving on an active flow — the same
	// misattribution the metronome test suffered. The budget is stated and checked
	// rather than left to the arithmetic being small enough today.
	const rounds, roundStep = 1200, time.Second
	requireQuietBudget(t, p.cli, rounds*roundStep)
	for i := 0; i < rounds; i++ {
		if err := p.cli.Enqueue(payload); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		for {
			msg, err := p.cli.Poll()
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if msg == nil {
				break
			}
		}
		p.clk.Advance(roundStep)
	}
	if n := p.cli.Stats().PingsSent; n != 0 {
		t.Errorf("an active flow emitted %d keepalives over %s of virtual time; a silence timer "+
			"must emit none", n, rounds*roundStep)
	}
	if n := p.cli.Stats().DataFramesSent; n != rounds {
		t.Errorf("sent %d data frames, want %d", n, rounds)
	}
}

// TestAProbeFiresOnlyOnceInboundHasGoneQuiet pins the half of the probe rule
// that the slot alone does not satisfy.
//
// tickEstablished separates two things on purpose: the probe SLOT always re-arms
// (so a healthy busy session never leaves probeAt in the past and never makes the
// caller's loop spin), and the probe only FIRES when inbound has actually gone
// quiet. Collapsing the two — `probeDue := probeSlot` — makes a perfectly healthy
// session emit a liveness probe on every slot, which is both pointless traffic
// and a new timing signature on a flow that is already carrying.
//
// It is here because a mutation found nothing asserting it. The whole package
// passed with the quiet condition deleted: every test that watched probes had
// inbound quiet by construction, and every test with live inbound had the probe
// schedule pushed out of reach. So the two halves were each covered and the
// relationship between them was not.
//
// The second phase is what stops this passing vacuously. A test that only showed
// "no probes while busy" would also pass against a driver that never probes at
// all, so the inbound flow is stopped at the end and a probe is REQUIRED to
// appear.
func TestAProbeFiresOnlyOnceInboundHasGoneQuiet(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		// The client's probe slot comes due constantly, so "no probe fired" can
		// only be the quiet condition holding it back.
		cli.Probe = Draw{Min: time.Second, Mean: 2 * time.Second, Max: 3 * time.Second}
		// and its silence timer is parked, so every PING the client sends is a
		// liveness probe rather than a keepalive.
		cli.Silence = silentDraw()
	})
	p.establish()

	// The probe schedule is deliberately driven here, so it is declared; nothing
	// else may fire inside either phase.
	const busyRounds, busyStep = 60, 500 * time.Millisecond
	const quietRounds, quietStep = 20, time.Second
	requireQuietBudget(t, p.cli, busyRounds*busyStep+quietRounds*quietStep, exercisesProbe)

	// Phase 1: the gateway keeps talking, so inbound never goes quiet.
	for i := 0; i < busyRounds; i++ {
		if err := p.gw.Enqueue([]byte("inbound")); err != nil {
			t.Fatalf("gateway enqueue %d: %v", i, err)
		}
		p.run()
		p.clk.Advance(busyStep)
	}
	if n := p.cli.Stats().PingsSent; n != 0 {
		p.cli.mu.Lock()
		every := p.cli.probeEvery
		p.cli.mu.Unlock()
		t.Fatalf("a session whose inbound never went quiet emitted %d liveness probes over %s of "+
			"virtual time (probe spacing %s, %d inbound messages opened). The slot re-arming is "+
			"not the same event as the probe firing: a busy session has nothing to ask",
			n, busyRounds*busyStep, every, p.cli.Stats().MessagesReceived)
	}
	if got := p.cli.Stats().MessagesReceived; got == 0 {
		t.Fatal("the client opened nothing during the busy phase, so inbound was never live and " +
			"this test measured nothing")
	}

	// Phase 2: inbound stops. The same slot must now produce a probe, or phase 1
	// proved only that this driver never probes.
	for i := 0; i < quietRounds && p.cli.Stats().PingsSent == 0; i++ {
		p.clk.Advance(quietStep)
		for {
			msg, err := p.cli.Poll()
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if msg == nil {
				break
			}
		}
	}
	if n := p.cli.Stats().PingsSent; n == 0 {
		t.Fatalf("no probe fired in %s of silence with a probe spacing of at most %s; phase 1 above "+
			"then proves nothing, because a driver that never probes would pass it",
			quietRounds*quietStep, 3*time.Second)
	}
}

// TestRatchetCutsAreQuiet pins the epoch-cut rule.
//
// core.Session installs one epoch at a time, so the instant one end ratchets,
// anything the other end sent under the old epoch becomes unopenable. The cut is
// only safe if neither end emits anything OPTIONAL across it. This test drives a
// full handshake, a post-quantum ratchet and a rekey on an otherwise idle
// session and requires that not one message failed to open at either end.
//
// It is a class-of-error test: any future frame that starts being emitted during
// Initiating or Rekeying will show up here as a lost message, without anyone
// having to remember to test that specific frame.
func TestRatchetCutsAreQuiet(t *testing.T) {
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		// A rekey after a handful of messages, so the cut happens inside the
		// test rather than in fifteen virtual minutes.
		cli.RekeyAfterMessages = 4
		gw.RekeyAfterMessages = 4
	})
	p.establish()

	if p.cli.Stats().Unopenable != 0 || p.gw.Stats().Unopenable != 0 {
		t.Fatalf("the post-quantum cut lost messages: client %d, gateway %d",
			p.cli.Stats().Unopenable, p.gw.Stats().Unopenable)
	}

	payload := []byte("across the cut")
	for i := 0; i < 12; i++ {
		if err := p.cli.Enqueue(payload); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		p.run()
		p.clk.Advance(time.Second)
	}

	if p.cli.Stats().Rekeys == 0 && p.gw.Stats().Rekeys == 0 {
		t.Fatal("no rekey happened; this test measured nothing")
	}
	if p.cli.Epoch() < 2 || p.gw.Epoch() < 2 {
		t.Fatalf("epochs did not advance past the post-quantum ratchet: client %d, gateway %d",
			p.cli.Epoch(), p.gw.Epoch())
	}
	if p.cli.Epoch() != p.gw.Epoch() {
		t.Fatalf("epochs diverged: client %d, gateway %d", p.cli.Epoch(), p.gw.Epoch())
	}
	if u := p.cli.Stats().Unopenable; u != 0 {
		t.Errorf("client could not open %d messages across a ratchet cut", u)
	}
	if u := p.gw.Stats().Unopenable; u != 0 {
		t.Errorf("gateway could not open %d messages across a ratchet cut", u)
	}
	if got := len(p.atGw); got != 12 {
		t.Errorf("gateway received %d inner packets, want 12", got)
	}
}

// TestEveryEmittedMessageFitsTheCarrier is a class-of-error test on assembly and
// shaping together: whatever the frame mix, whatever the padding draw, no
// message may exceed the carrier's ceiling or fall below the floor.
//
// A carrier that is handed an oversized message either drops it silently or
// fragments it, and a fragmented Winn3 message is itself a distinctive
// fingerprint.
func TestEveryEmittedMessageFitsTheCarrier(t *testing.T) {
	const mtu = 700
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.MaxMessageSize = mtu
		gw.MaxMessageSize = mtu
	})
	p.establish()

	floor := core.TransportOverhead() + frameHeaderSize
	sizes := []int{1, 40, 200, 500, mtu - core.TransportOverhead() - frameHeaderSize}
	seen := 0
	for round := 0; round < 60; round++ {
		n := sizes[round%len(sizes)]
		if err := p.cli.Enqueue(make([]byte, n)); err != nil {
			t.Fatalf("enqueue %d bytes: %v", n, err)
		}
		for {
			msg, err := p.cli.Poll()
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if msg == nil {
				break
			}
			if len(msg) > mtu {
				t.Fatalf("emitted a %d-byte message, carrier ceiling is %d", len(msg), mtu)
			}
			if len(msg) < floor {
				t.Fatalf("emitted a %d-byte message, below the %d-byte floor", len(msg), floor)
			}
			seen++
		}
		p.clk.Advance(time.Second)
	}
	if seen < 60 {
		t.Fatalf("only observed %d messages", seen)
	}
	// The largest inner packet must not have been refused.
	tooBig := mtu - core.TransportOverhead() - frameHeaderSize + 1
	if err := p.cli.Enqueue(make([]byte, tooBig)); err == nil {
		t.Error("a packet one byte past the payload budget was accepted")
	}
}
