package session

import (
	"crypto/rand"
	"math"
	"testing"
	"time"
)

// clampDraw is the WRONG implementation — sample an exponential, clamp into
// range — kept in the test file so that the detectors below can be shown to
// reject it. A guard that cannot fail is worse than no guard, because it turns
// an unverified claim into a verified-looking one.
func clampDraw(u float64, d Draw) time.Duration {
	x := -float64(d.Mean) * math.Log(1-u)
	if x < float64(d.Min) {
		x = float64(d.Min)
	}
	if x > float64(d.Max) {
		x = float64(d.Max)
	}
	return time.Duration(x)
}

func defaultSilence() Draw {
	return Draw{Min: DefaultSilenceMin, Mean: DefaultSilenceMean, Max: DefaultSilenceMax}
}

// modalFraction reports the largest share any single value holds in a sample.
func modalFraction(vals []time.Duration) (time.Duration, float64) {
	counts := make(map[time.Duration]int, len(vals))
	for _, v := range vals {
		counts[v]++
	}
	var best time.Duration
	worst := 0
	for v, n := range counts {
		if n > worst {
			worst, best = n, v
		}
	}
	return best, float64(worst) / float64(len(vals))
}

// TestSilenceDrawHasNoAtomAtBounds is the test that catches the clamping bug
// class, and it is the most important test in this file.
//
// With Min 5 s, Mean 15 s and Max 45 s, a clamped exponential puts roughly 28 %
// of every fleet's draws on exactly 5.000 s and roughly 5 % on exactly 45.000 s.
// That is not "jittered": it is two metronomes instead of one, and it would have
// replaced a 25.000-second spike with a 5.000-second spike for more than a
// quarter of all keepalives. The inverse-CDF sampler has no atom anywhere.
func TestSilenceDrawHasNoAtomAtBounds(t *testing.T) {
	d := defaultSilence()
	const n = 20000

	vals := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		v, err := drawTruncExp(rand.Reader, d)
		if err != nil {
			t.Fatal(err)
		}
		if v < d.Min || v > d.Max {
			t.Fatalf("draw %s outside [%s,%s]", v, d.Min, d.Max)
		}
		if v == d.Min || v == d.Max {
			t.Fatalf("draw landed exactly on a truncation bound (%s); the clamp is reachable", v)
		}
		vals = append(vals, v)
	}
	if val, frac := modalFraction(vals); frac > 0.001 {
		t.Errorf("value %s holds %.3f of the sample; a truncated-exponential draw has no atom", val, frac)
	}

	// The detector's teeth: the clamping implementation must fail it.
	clamped := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		u, err := unitOpen(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		clamped = append(clamped, clampDraw(u, d))
	}
	val, frac := modalFraction(clamped)
	if frac <= 0.001 {
		t.Fatalf("the clamping implementation was not detected (modal %s holds %.4f); this test has no teeth", val, frac)
	}
	if val != d.Min {
		t.Errorf("expected the clamp atom at Min=%s, found it at %s", d.Min, val)
	}
}

// TestSilenceDrawIsMemoryless checks the shape, not just the bounds.
//
// Two properties are asserted because either alone is easy to satisfy by
// accident: the sample mean must be near the truncated distribution's true mean,
// and consecutive draws must be uncorrelated. A generator that walked a fixed
// list of "random-looking" values would pass a bounds check and fail both of
// these.
func TestSilenceDrawIsMemoryless(t *testing.T) {
	d := defaultSilence()
	const n = 40000

	vals := make([]float64, n)
	for i := range vals {
		v, err := drawTruncExp(rand.Reader, d)
		if err != nil {
			t.Fatal(err)
		}
		vals[i] = float64(v)
	}

	// Analytic mean of an exponential with rate l truncated to [a,b]:
	//   a + 1/l - (b-a) * e^{-l(b-a)} / (1 - e^{-l(b-a)})
	a, b, m := float64(d.Min), float64(d.Max), float64(d.Mean)
	z := (b - a) / m
	want := a + m - (b-a)*math.Exp(-z)/(1-math.Exp(-z))

	var sum float64
	for _, v := range vals {
		sum += v
	}
	got := sum / float64(n)
	if rel := math.Abs(got-want) / want; rel > 0.02 {
		t.Errorf("sample mean %s differs from the truncated-exponential mean %s by %.1f%%",
			time.Duration(got), time.Duration(want), rel*100)
	}

	// Lag-1 autocorrelation. Memoryless means the next draw tells you nothing
	// about the last one.
	var num, den float64
	for i := 0; i < n; i++ {
		den += (vals[i] - got) * (vals[i] - got)
	}
	for i := 0; i+1 < n; i++ {
		num += (vals[i] - got) * (vals[i+1] - got)
	}
	if r := num / den; math.Abs(r) > 0.03 {
		t.Errorf("lag-1 autocorrelation is %.4f; consecutive draws are not independent", r)
	}
}

// TestSilenceDrawDegradesToUniform pins the limit behaviour of the sampler.
//
// When the mean is very large relative to the range, the truncated exponential
// IS the uniform distribution on that range. The Log1p/Expm1 form reaches that
// limit smoothly; a naive exp()-difference form loses it to catastrophic
// cancellation and starts returning the lower bound, which would be an atom
// again, appearing only under an unusual configuration.
func TestSilenceDrawDegradesToUniform(t *testing.T) {
	d := Draw{Min: time.Second, Mean: 1e6 * time.Second, Max: 3 * time.Second}
	const n = 20000
	buckets := make([]int, 4)
	for i := 0; i < n; i++ {
		v, err := drawTruncExp(rand.Reader, d)
		if err != nil {
			t.Fatal(err)
		}
		frac := float64(v-d.Min) / float64(d.Max-d.Min)
		idx := int(frac * 4)
		if idx > 3 {
			idx = 3
		}
		buckets[idx]++
	}
	for i, c := range buckets {
		if frac := float64(c) / n; frac < 0.20 || frac > 0.30 {
			t.Errorf("quarter %d holds %.3f of the draws; the large-mean limit is not uniform", i, frac)
		}
	}
}

func TestDrawValidationRejectsAMetronome(t *testing.T) {
	cases := []struct {
		name string
		d    Draw
	}{
		{"min equals max", Draw{Min: time.Second, Mean: time.Second, Max: time.Second}},
		{"max below min", Draw{Min: 2 * time.Second, Mean: time.Second, Max: time.Second}},
		{"zero min", Draw{Min: 0, Mean: time.Second, Max: 2 * time.Second}},
		{"zero mean", Draw{Min: time.Second, Mean: 0, Max: 2 * time.Second}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// orDefault is not applied: these are explicit values, and a
			// configuration that collapses the support to a point must be
			// refused rather than silently accepted as "jitter".
			if err := c.d.validate("test"); err == nil {
				t.Fatalf("Draw %+v was accepted", c.d)
			}
		})
	}
}

// TestBackoffIsFullJitter checks the shape of the retry schedule.
//
// Full jitter means uniform on [0, window], so about half of every attempt's
// draws land below half the window. "Exponential plus a little noise" would
// concentrate near the window and fail this, and a fleet retrying on a narrow
// band around a growing value is still a recognisable cadence.
func TestBackoffIsFullJitter(t *testing.T) {
	r := Retry{Base: 500 * time.Millisecond, Cap: 8 * time.Second, Attempts: 5}
	const n = 4000
	for attempt := 0; attempt < 6; attempt++ {
		window := float64(r.Base) * math.Pow(2, float64(attempt))
		if window > float64(r.Cap) {
			window = float64(r.Cap)
		}
		low := 0
		var maxSeen time.Duration
		for i := 0; i < n; i++ {
			v, err := drawBackoff(rand.Reader, r, attempt)
			if err != nil {
				t.Fatal(err)
			}
			if float64(v) > window {
				t.Fatalf("attempt %d drew %s, above the %s window", attempt, v, time.Duration(window))
			}
			if v < 0 {
				t.Fatalf("attempt %d drew a negative delay %s", attempt, v)
			}
			if float64(v) < window/2 {
				low++
			}
			if v > maxSeen {
				maxSeen = v
			}
		}
		if frac := float64(low) / n; frac < 0.45 || frac > 0.55 {
			t.Errorf("attempt %d put %.3f of draws in the lower half; full jitter is uniform", attempt, frac)
		}
		if float64(maxSeen) < window*0.9 {
			t.Errorf("attempt %d never got near its %s window (max %s); the window is not being used",
				attempt, time.Duration(window), maxSeen)
		}
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	r := Retry{Base: time.Second, Cap: 4 * time.Second, Attempts: 8}
	// The observed maximum over many draws approximates the window, which must
	// double until it reaches the cap and then stop.
	prev := time.Duration(0)
	for attempt := 0; attempt < 6; attempt++ {
		var maxSeen time.Duration
		for i := 0; i < 3000; i++ {
			v, err := drawBackoff(rand.Reader, r, attempt)
			if err != nil {
				t.Fatal(err)
			}
			if v > maxSeen {
				maxSeen = v
			}
		}
		if maxSeen > r.Cap {
			t.Fatalf("attempt %d exceeded the cap: %s > %s", attempt, maxSeen, r.Cap)
		}
		if attempt > 0 && maxSeen < prev {
			// Allow the cap plateau, but never a shrink below the cap.
			if maxSeen < r.Cap*9/10 {
				t.Errorf("attempt %d window shrank: %s after %s", attempt, maxSeen, prev)
			}
		}
		prev = maxSeen
	}
}

func TestDrawIntnIsUnbiased(t *testing.T) {
	const n = 60000
	const k = 7
	counts := make([]int, k)
	for i := 0; i < n; i++ {
		v, err := drawIntn(rand.Reader, k)
		if err != nil {
			t.Fatal(err)
		}
		if v < 0 || v >= k {
			t.Fatalf("drawIntn returned %d, outside [0,%d)", v, k)
		}
		counts[v]++
	}
	want := float64(n) / k
	for i, c := range counts {
		if rel := math.Abs(float64(c)-want) / want; rel > 0.06 {
			t.Errorf("bucket %d holds %d, %.1f%% off uniform", i, c, rel*100)
		}
	}
	if v, err := drawIntn(rand.Reader, 1); err != nil || v != 0 {
		t.Errorf("drawIntn(1) = %d, %v; want 0, nil", v, err)
	}
	if v, err := drawIntn(rand.Reader, 0); err != nil || v != 0 {
		t.Errorf("drawIntn(0) = %d, %v; want 0, nil", v, err)
	}
}

func TestUnitOpenNeverReachesItsBounds(t *testing.T) {
	for i := 0; i < 100000; i++ {
		u, err := unitOpen(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if u <= 0 || u >= 1 {
			t.Fatalf("unitOpen returned %v, outside the open interval", u)
		}
	}
}

// TestDrawsFailClosedOnEntropyFailure: a draw that quietly fell back to a weak
// source on entropy failure would convert a memoryless schedule into a
// predictable one exactly when nobody is looking.
func TestDrawsFailClosedOnEntropyFailure(t *testing.T) {
	bad := failingReader{}
	if _, err := drawTruncExp(bad, defaultSilence()); err == nil {
		t.Error("drawTruncExp succeeded with a dead entropy source")
	}
	if _, err := drawBackoff(bad, Retry{Base: time.Second, Cap: time.Second, Attempts: 1}, 0); err == nil {
		t.Error("drawBackoff succeeded with a dead entropy source")
	}
	if _, err := drawToken(bad); err == nil {
		t.Error("drawToken succeeded with a dead entropy source")
	}
	if _, err := drawIntn(bad, 5); err == nil {
		t.Error("drawIntn succeeded with a dead entropy source")
	}
	if _, err := unitOpen(bad); err == nil {
		t.Error("unitOpen succeeded with a dead entropy source")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errFakeEntropy }

var errFakeEntropy = errStr("entropy source is unavailable")

type errStr string

func (e errStr) Error() string { return string(e) }
