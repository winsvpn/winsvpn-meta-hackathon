package carrier

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

// The reconnect-timing suite.
//
// A client that redials on a fixed schedule while a censor drops its traffic is
// emitting a periodogram spike as clean as the 25.000-second keepalive that
// characterised the protocol this replaces — cleaner, in fact, because a retry
// burst is a SYN and a SYN is visible without any payload inspection at all.
//
// The detector below is the shape the session lane used on its silence timer,
// and like theirs it is fed known-bad series and required to reject them.

// metronomeVerdict is what the four-part detector concluded.
type metronomeVerdict struct {
	distinct    int
	modalShare  float64
	cv          float64
	maxAutocorr float64
}

// detectMetronome runs four independent statistics over a series of intervals.
//
// Four rather than one because each catches something the others miss: a
// dithered metronome has many distinct values but a tiny coefficient of
// variation; a sawtooth has a large one but strong autocorrelation; a clamped
// draw has both and a modal spike.
func detectMetronome(d []time.Duration) metronomeVerdict {
	if len(d) == 0 {
		return metronomeVerdict{}
	}
	counts := map[time.Duration]int{}
	var sum float64
	for _, v := range d {
		counts[v]++
		sum += float64(v)
	}
	mean := sum / float64(len(d))

	modal := 0
	for _, c := range counts {
		if c > modal {
			modal = c
		}
	}
	var varsum float64
	for _, v := range d {
		diff := float64(v) - mean
		varsum += diff * diff
	}
	cv := 0.0
	if mean != 0 {
		cv = math.Sqrt(varsum/float64(len(d))) / mean
	}

	maxAuto := 0.0
	for lag := 1; lag <= 8 && lag < len(d); lag++ {
		var num float64
		for i := 0; i+lag < len(d); i++ {
			num += (float64(d[i]) - mean) * (float64(d[i+lag]) - mean)
		}
		if varsum != 0 {
			r := math.Abs(num / varsum)
			if r > maxAuto {
				maxAuto = r
			}
		}
	}
	return metronomeVerdict{
		distinct:    len(counts),
		modalShare:  float64(modal) / float64(len(d)),
		cv:          cv,
		maxAutocorr: maxAuto,
	}
}

// looksLikeAMetronome applies the thresholds.
func (v metronomeVerdict) looksLikeAMetronome(n int) bool {
	switch {
	case v.distinct < n/4:
		return true
	case v.modalShare > 0.10:
		return true
	case v.cv < 0.25:
		return true
	case v.maxAutocorr > 0.60:
		return true
	}
	return false
}

// TestMetronomeDetectorHasTeeth feeds the detector three known-bad series and
// requires it to reject all three.
//
// The first is the measured failure itself: a keepalive at exactly 25.000
// seconds. The second is the cosmetic fix somebody always proposes — the same
// metronome with a few milliseconds of dither, which defeats an equality check
// and nothing else. The third is a predictable ramp, which has plenty of
// variance and is still a clock an observer can lock onto.
func TestMetronomeDetectorHasTeeth(t *testing.T) {
	t.Parallel()
	const n = 300
	series := map[string][]time.Duration{}

	fixed := make([]time.Duration, n)
	for i := range fixed {
		fixed[i] = 25 * time.Second
	}
	series["the measured 25.000-second series"] = fixed

	dithered := make([]time.Duration, n)
	for i := range dithered {
		dithered[i] = 25*time.Second + time.Duration(i%7)*time.Millisecond
	}
	series["a metronome with millisecond dither"] = dithered

	saw := make([]time.Duration, n)
	for i := range saw {
		saw[i] = time.Duration(1+i%10) * time.Second
	}
	series["a predictable sawtooth"] = saw

	clamped := make([]time.Duration, n)
	for i := range clamped {
		// The session lane's near-miss: a clamped exponential parking a large
		// share of draws on exactly the lower bound.
		if i%100 < 28 {
			clamped[i] = 5 * time.Second
		} else {
			clamped[i] = time.Duration(5+i%40) * time.Second
		}
	}
	series["a clamped exponential with an atom at the bound"] = clamped

	for name, s := range series {
		v := detectMetronome(s)
		if !v.looksLikeAMetronome(len(s)) {
			t.Errorf("the detector accepted %s: %+v", name, v)
		}
	}
}

// TestBackoffIsNotAMetronome runs the detector over real draws.
//
// The steady state is what matters: once the window has saturated at Cap, every
// draw is uniform on (0, Cap), and that is the series a censor would see from a
// client that has been blocked for a while.
func TestBackoffIsNotAMetronome(t *testing.T) {
	t.Parallel()
	b := Backoff{Base: DefaultBackoffBase, Cap: DefaultBackoffCap, Attempts: 64}
	rnd := &countingRand{}
	const n = 400
	d := make([]time.Duration, n)
	for i := range d {
		v, err := b.Delay(20, rnd) // saturated window
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		d[i] = v
	}
	v := detectMetronome(d)
	if v.looksLikeAMetronome(n) {
		t.Fatalf("the backoff series looks like a metronome: %+v", v)
	}
}

// TestBackoffHasNoAtomAtTheCap is the session lane's near-miss, checked here.
//
// The obvious "exponential with jitter" is `min(cap, base<<n)` with a clamp,
// which puts a probability atom on the cap: past saturation every draw IS the
// cap. At the shipping defaults that is a fixed 8.000-second reconnect for the
// whole fleet — the 25.000-second metronome slowed down. Full jitter cannot do
// that, and this test proves it by running the clamping implementation and
// requiring the detector to object.
func TestBackoffHasNoAtomAtTheCap(t *testing.T) {
	t.Parallel()
	b := Backoff{Base: DefaultBackoffBase, Cap: DefaultBackoffCap, Attempts: 64}
	const n = 400

	// The implementation this package refuses.
	clamped := make([]time.Duration, n)
	for i := range clamped {
		clamped[i] = b.window(20)
	}
	if !detectMetronome(clamped).looksLikeAMetronome(n) {
		t.Fatal("the detector accepted the clamped implementation; it has no teeth")
	}

	// And the one it uses.
	rnd := &countingRand{}
	got := make([]time.Duration, n)
	atCap := 0
	atZero := 0
	for i := range got {
		v, err := b.Delay(20, rnd)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		got[i] = v
		if v >= b.Cap {
			atCap++
		}
		if v <= 0 {
			atZero++
		}
	}
	if atCap != 0 {
		t.Fatalf("%d of %d draws landed on or above the cap", atCap, n)
	}
	if atZero != 0 {
		t.Fatalf("%d of %d draws landed on or below zero", atZero, n)
	}
	if detectMetronome(got).looksLikeAMetronome(n) {
		t.Fatal("full jitter produced a metronome")
	}
}

// TestBackoffWindowDoublesAndSaturates.
func TestBackoffWindowDoublesAndSaturates(t *testing.T) {
	t.Parallel()
	b := Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 10}
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 8 * time.Second, 8 * time.Second,
	}
	for i, w := range want {
		if got := b.window(i); got != w {
			t.Fatalf("window(%d) = %v, want %v", i, got, w)
		}
	}
	// A window that overflowed would come back negative or tiny; the guard is
	// worth a case because the arithmetic is a shift in disguise.
	if got := b.window(200); got != 8*time.Second {
		t.Fatalf("window(200) = %v, want the cap", got)
	}
	// A cap that is not a power-of-two multiple of the base must still be
	// respected exactly.
	odd := Backoff{Base: 300 * time.Millisecond, Cap: time.Second, Attempts: 5}
	for i := 0; i < 8; i++ {
		if got := odd.window(i); got > odd.Cap {
			t.Fatalf("window(%d) = %v exceeds cap %v", i, got, odd.Cap)
		}
	}
}

// TestBackoffValidationRefusesAFixedInterval.
//
// Base == Cap collapses the schedule's spread. The draw would still be
// non-degenerate, but a caller writing it has almost certainly misunderstood
// what the type is for, so it is refused rather than silently accepted — the
// same choice session.Draw.validate makes for Min == Max.
func TestBackoffValidationRefusesAFixedInterval(t *testing.T) {
	t.Parallel()
	cases := []Backoff{
		{Base: -1, Cap: time.Second, Attempts: 3},
		{Base: 2 * time.Second, Cap: time.Second, Attempts: 3},
		{Base: time.Second, Cap: time.Second, Attempts: 3},
	}
	for i, b := range cases {
		if err := b.validate(); !errors.Is(err, ErrConfig) {
			t.Fatalf("case %d accepted: %v", i, err)
		}
	}
	// Attempts is validated through Delay, which fills the other defaults.
	if _, err := (Backoff{Base: time.Second, Cap: 2 * time.Second, Attempts: -1}).
		Delay(0, &countingRand{}); err != nil {
		t.Fatalf("a negative attempt count should be defaulted by orDefault, got %v", err)
	}
	if _, err := (Backoff{}).Delay(-1, &countingRand{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("a negative attempt index was accepted: %v", err)
	}
	if _, err := (Backoff{}).Delay(0, &failingRand{}); err == nil {
		t.Fatal("an entropy failure was papered over")
	}
	// Zero fields take the shipping defaults.
	def := Backoff{}.orDefault()
	if def.Base != DefaultBackoffBase || def.Cap != DefaultBackoffCap ||
		def.Attempts != DefaultBackoffAttempts {
		t.Fatalf("defaults are %+v", def)
	}
}

// TestRedialSpendsTheBudgetAndStops is §4.2's hard attempt cap.
//
// The measured failure was 24 retries and 100 % loss. A schedule that never
// abandons a dead transport is not resilience, it is a beacon with a
// recognisable cadence — and it is the reason the previous protocol's users had
// no working tunnel and a very visible one.
func TestRedialSpendsTheBudgetAndStops(t *testing.T) {
	t.Parallel()
	dialErr := errors.New("blocked")
	attempts := 0
	var slept []time.Duration
	sleep := func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	b := Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 5}
	_, err := Redial(context.Background(), b, &countingRand{}, sleep,
		func(context.Context) (Conn, error) {
			attempts++
			return nil, dialErr
		})
	if !errors.Is(err, dialErr) {
		t.Fatalf("Redial returned %v, want the last dial error", err)
	}
	if attempts != 5 {
		t.Fatalf("%d attempts, want exactly the cap of 5", attempts)
	}
	if len(slept) != 4 {
		t.Fatalf("%d waits for 5 attempts, want 4", len(slept))
	}
	// No two waits the same, and none of them the cap.
	seen := map[time.Duration]bool{}
	for i, d := range slept {
		if d >= b.Cap || d <= 0 {
			t.Fatalf("wait %d is %v, outside the open interval (0, %v)", i, d, b.Cap)
		}
		if seen[d] {
			t.Fatalf("wait %d repeated a previous value (%v); the schedule is not drawn", i, d)
		}
		seen[d] = true
	}
}

// TestRedialStopsOnSuccessAndOnCancellation.
func TestRedialStopsOnSuccessAndOnCancellation(t *testing.T) {
	t.Parallel()
	pipe, err := NewPipe(PipeConfig{Class: ClassUDP})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	attempts := 0
	sleep := func(context.Context, time.Duration) error { return nil }
	got, err := Redial(context.Background(), Backoff{}, &countingRand{}, sleep,
		func(context.Context) (Conn, error) {
			attempts++
			if attempts < 3 {
				return nil, errors.New("blocked")
			}
			return pipe, nil
		})
	if err != nil {
		t.Fatalf("Redial: %v", err)
	}
	if got != Conn(pipe) {
		t.Fatal("Redial returned a different carrier")
	}
	if attempts != 3 {
		t.Fatalf("%d attempts, want 3", attempts)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Redial(ctx, Backoff{}, &countingRand{}, nil,
		func(context.Context) (Conn, error) { return nil, errors.New("x") }); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled Redial returned %v", err)
	}
	// A sleeper that reports cancellation must stop the loop.
	stopErr := errors.New("stopped")
	if _, err := Redial(context.Background(), Backoff{}, &countingRand{},
		func(context.Context, time.Duration) error { return stopErr },
		func(context.Context) (Conn, error) { return nil, errors.New("x") }); !errors.Is(err, stopErr) {
		t.Fatalf("a stopping sleeper returned %v", err)
	}
}

// TestRedialRefusals.
func TestRedialRefusals(t *testing.T) {
	t.Parallel()
	if _, err := Redial(context.Background(), Backoff{}, nil, nil, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("a nil dialer returned %v", err)
	}
	bad := Backoff{Base: time.Second, Cap: time.Second, Attempts: 1}
	if _, err := Redial(context.Background(), bad, nil, nil,
		func(context.Context) (Conn, error) { return nil, nil }); !errors.Is(err, ErrConfig) {
		t.Fatalf("a fixed-interval backoff returned %v", err)
	}
	// An entropy failure between attempts must stop rather than degrade.
	if _, err := Redial(context.Background(), Backoff{}, &failingRand{},
		func(context.Context, time.Duration) error { return nil },
		func(context.Context) (Conn, error) { return nil, errors.New("x") }); err == nil {
		t.Fatal("an entropy failure between attempts was papered over")
	}
}

// TestRealSleepHonoursCancellationAndZero keeps the default sleeper honest.
func TestRealSleepHonoursCancellationAndZero(t *testing.T) {
	t.Parallel()
	if err := realSleep(context.Background(), 0); err != nil {
		t.Fatalf("a zero sleep returned %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := realSleep(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("a zero sleep on a cancelled context returned %v", err)
	}
	if err := realSleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("a long sleep on a cancelled context returned %v", err)
	}
	start := time.Now()
	if err := realSleep(context.Background(), 5*time.Millisecond); err != nil {
		t.Fatalf("sleep: %v", err)
	}
	if time.Since(start) < 4*time.Millisecond {
		t.Fatal("realSleep returned early")
	}
}

// TestRedialRefusesANilCarrier.
//
// A dial func that returns (nil, nil) used to be treated as success, so Redial
// handed the caller a nil Conn with no error. The next Send would panic, which
// on this path is a datapath crash rather than a refused dial.
func TestRedialRefusesANilCarrier(t *testing.T) {
	t.Parallel()
	c, err := Redial(context.Background(), Backoff{Base: time.Millisecond, Cap: time.Second, Attempts: 1},
		nil, nil, func(context.Context) (Conn, error) { return nil, nil })
	if c != nil {
		t.Fatal("Redial returned a non-nil carrier for a nil dial result")
	}
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("a nil carrier returned %v, want ErrConfig", err)
	}
}
