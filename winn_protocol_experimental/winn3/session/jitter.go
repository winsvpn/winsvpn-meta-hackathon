package session

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
)

func wrap(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...)
}

// pingTokenSize is the size of the opaque token a PING carries and a PONG
// echoes. Its only job is to match a reply to a probe, so eight bytes is ample:
// a collision costs one mis-attributed round-trip sample.
const pingTokenSize = 8

// randUint64 draws eight bytes from the configured source.
//
// A failure here is fatal to the caller rather than papered over. Falling back
// to a weaker source on entropy failure would silently convert a memoryless
// schedule into a predictable one, which is the failure this package exists to
// prevent, and it would do so exactly when nobody is watching.
func randUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// unitOpen draws a uniform float in the OPEN interval (0,1).
//
// Open at both ends on purpose. The truncated-exponential inverse CDF maps 0 to
// exactly Min and 1 to exactly Max, so a closed interval would put a small but
// real probability atom on each bound — a value that recurs fleet-wide at a
// predictable rate, which is the same failure class as a fixed interval, only
// sparser. Fifty-three bits shifted by a half step keeps both ends unreachable.
func unitOpen(r io.Reader) (float64, error) {
	v, err := randUint64(r)
	if err != nil {
		return 0, err
	}
	return (float64(v>>11) + 0.5) / (1 << 53), nil
}

// drawTruncExp samples a truncated exponential on [d.Min, d.Max] with the
// untruncated mean d.Mean, by inverse CDF.
//
// This is the single most important function in the package's timing defence,
// so the reasoning is worth stating in full.
//
// The naive implementation — sample an exponential and clamp it into range — is
// wrong in a way that is invisible in a unit test that only checks bounds. With
// Min 5 s, Mean 15 s and Max 45 s, clamping puts about 28 % of all draws on
// exactly 5.000 s and about 5 % on exactly 45.000 s. That is a periodogram
// spike at two frequencies instead of one. It would have replaced a
// 25.000-second metronome with a 5.000-second one for a third of all fires.
//
// The inverse CDF of the exponential truncated to [a,b] with rate 1/m is
//
//	x = a - m * ln(1 + u * (exp(-(b-a)/m) - 1))
//
// which is continuous on (a,b) with no atom anywhere. Written with Log1p and
// Expm1 it is also numerically stable at both extremes: as m grows large
// relative to b-a the expression degrades smoothly to a uniform draw on [a,b],
// which is the correct limit, with no special case.
//
// TestSilenceDrawHasNoAtomAtBounds fails against the clamping implementation.
func drawTruncExp(r io.Reader, d Draw) (time.Duration, error) {
	u, err := unitOpen(r)
	if err != nil {
		return 0, err
	}
	a := float64(d.Min)
	b := float64(d.Max)
	m := float64(d.Mean)

	x := a - m*math.Log1p(u*math.Expm1(-(b-a)/m))

	// Defensive only. The algebra above cannot leave [a,b] for u in (0,1), and
	// TestSilenceDrawHasNoAtomAtBounds proves the clamp is never reached by
	// requiring that no draw ever lands on either bound.
	if x < a {
		x = a
	}
	if x > b {
		x = b
	}
	return time.Duration(x), nil
}

// drawBackoff returns one full-jitter exponential backoff delay.
//
// The delay is uniform on [0, min(cap, base * 2^attempt)] — full jitter, not
// "exponential plus noise". Decorrelating retries across a fleet matters as much
// as the growth: a synchronised retry cadence is a fleet-wide timing signature
// even when each individual delay is increasing.
func drawBackoff(r io.Reader, ret Retry, attempt int) (time.Duration, error) {
	if attempt < 0 {
		attempt = 0
	}
	window := float64(ret.Base)
	// Cheap saturating shift; 62 doublings exceed any plausible cap already.
	for i := 0; i < attempt && window < float64(ret.Cap); i++ {
		window *= 2
	}
	if window > float64(ret.Cap) {
		window = float64(ret.Cap)
	}
	u, err := unitOpen(r)
	if err != nil {
		return 0, err
	}
	return time.Duration(u * window), nil
}

// drawToken draws an opaque PING token.
func drawToken(r io.Reader) ([pingTokenSize]byte, error) {
	var t [pingTokenSize]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return t, err
	}
	return t, nil
}

// drawIntn returns a uniform integer in [0,n) without modulo bias.
func drawIntn(r io.Reader, n int) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	limit := uint64(n)
	// Rejection sampling. rem is 2^64 mod limit, computed without needing 2^64;
	// everything at or below maxUint-rem lies in a whole number of limit-sized
	// blocks, so the modulo of an accepted draw is unbiased.
	const maxUint = ^uint64(0)
	rem := (maxUint%limit + 1) % limit
	bound := maxUint - rem
	for {
		v, err := randUint64(r)
		if err != nil {
			return 0, err
		}
		if v <= bound {
			return int(v % limit), nil
		}
	}
}
