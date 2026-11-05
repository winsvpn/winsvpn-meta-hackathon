package carrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// Reconnect timing.
//
// §4.2 answers the measured 24-retry failure with one sentence, and it is a
// sentence about shape as much as about count:
//
//	Handshake retransmission is exponential with full jitter and a hard attempt
//	cap. After K failures on one carrier the session manager MUST change carrier
//	class, not merely retry. A retry schedule that never abandons a dead
//	transport is not resilience; it is a beacon with a recognisable cadence.
//
// The beacon is the part that is easy to lose sight of. A client that redials
// every 8.000 seconds while a censor drops its traffic is emitting a periodogram
// spike as clean as the 25.000-second keepalive that characterised the previous
// protocol — cleaner, in fact, because the retry burst is a SYN and a SYN is
// visible without any payload inspection at all. So the delay between dial
// attempts is drawn, never fixed, and the draw has no probability atom anywhere.
//
// Full jitter — uniform on (0, min(Cap, Base·2^n)) — is the shape §4.2 names and
// it is atom-free by construction, which matters here more than elsewhere: the
// session lane's silence timer nearly shipped a CLAMPED exponential that would
// have parked about 28 % of every fleet's draws on exactly 5.000 s, replacing one
// metronome with a sparser one. A uniform draw on an open interval cannot do
// that. TestBackoffHasNoAtomAtTheCap runs the clamping implementation and
// requires the detector to object, so the claim is measured rather than asserted.

const (
	// DefaultBackoffBase is the first window. §4.2's retry policy and the
	// session driver's own Retry.Base agree on this number deliberately: two
	// layers retrying on two schedules produce a beat frequency, which is a
	// third cadence neither layer chose.
	DefaultBackoffBase = 500 * time.Millisecond

	// DefaultBackoffCap bounds the window. Beyond it every draw is uniform on
	// (0, Cap), which is the steady state a long block settles into.
	DefaultBackoffCap = 8 * time.Second

	// DefaultBackoffAttempts is the hard cap. Spending it is the §4.2 signal to
	// change carrier CLASS rather than keep retrying, and this package reports
	// that upward rather than acting on it.
	DefaultBackoffAttempts = 5
)

// Backoff is §4.2's exponential-with-full-jitter schedule and its hard attempt
// cap.
type Backoff struct {
	// Base is the first window.
	Base time.Duration
	// Cap bounds the window however many attempts have failed.
	Cap time.Duration
	// Attempts is the hard cap on dial attempts before the caller must change
	// carrier class.
	Attempts int
}

// orDefault fills the zero fields.
func (b Backoff) orDefault() Backoff {
	if b.Base <= 0 {
		b.Base = DefaultBackoffBase
	}
	if b.Cap <= 0 {
		b.Cap = DefaultBackoffCap
	}
	if b.Attempts <= 0 {
		b.Attempts = DefaultBackoffAttempts
	}
	return b
}

// validate refuses a configuration that would collapse the schedule to a point.
//
// Base == Cap with no jitter would be a fixed interval, and a fixed interval is
// the failure this type exists to prevent. The draw makes even Base == Cap
// non-degenerate, but a caller writing that has almost certainly misunderstood
// what the type is for, so it is refused rather than silently accepted — the
// same choice session.Draw.validate makes for Min == Max.
func (b Backoff) validate() error {
	if b.Base <= 0 {
		return wrap(ErrConfig, "backoff base %v is not positive", b.Base)
	}
	if b.Cap < b.Base {
		return wrap(ErrConfig, "backoff cap %v is below base %v", b.Cap, b.Base)
	}
	if b.Cap == b.Base {
		return wrap(ErrConfig,
			"backoff cap equals base (%v): a schedule with no spread is a fixed reconnect interval", b.Base)
	}
	if b.Attempts <= 0 {
		return wrap(ErrConfig, "backoff attempts %d is not positive", b.Attempts)
	}
	return nil
}

// Delay draws the wait before dial attempt n (zero-based).
//
// Uniform on the OPEN interval (0, window). Open at both ends for the reason
// session.unitOpen is: a closed interval puts a small but real probability atom
// on each bound, and a value that recurs fleet-wide at a predictable rate is the
// same failure class as a fixed interval, only sparser.
func (b Backoff) Delay(attempt int, rnd io.Reader) (time.Duration, error) {
	b = b.orDefault()
	if err := b.validate(); err != nil {
		return 0, err
	}
	if attempt < 0 {
		return 0, wrap(ErrConfig, "attempt %d is negative", attempt)
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	window := b.window(attempt)
	u, err := unitOpen(rnd)
	if err != nil {
		// Fatal rather than papered over, for the reason session.randUint64
		// gives: falling back to a weaker source on entropy failure silently
		// converts a memoryless schedule into a predictable one, exactly when
		// nobody is watching.
		return 0, err
	}
	return time.Duration(u * float64(window)), nil
}

// window is min(Cap, Base·2^attempt), computed without overflowing.
func (b Backoff) window(attempt int) time.Duration {
	w := b.Base
	for i := 0; i < attempt; i++ {
		if w >= b.Cap/2 {
			return b.Cap
		}
		w *= 2
	}
	if w > b.Cap {
		return b.Cap
	}
	return w
}

// unitOpen draws a uniform float in the OPEN interval (0,1).
//
// Open at both ends, and the arithmetic that makes it so is worth stating
// because the obvious version is off by one ulp at the top.
//
// The idiomatic construction takes 53 bits and shifts by a half step:
// (float64(v>>11) + 0.5) / (1<<53). It is open at zero. It is NOT open at one:
// float64 has a 53-bit significand, so for v>>11 == 2^53−1 the sum 2^53−0.5 is
// exactly halfway between two representable values, rounds to even — upward, to
// 2^53 — and the quotient is exactly 1.0. That is a probability atom at the top
// of the support, reached once in 2^53 draws.
//
// At that magnitude it is unobservable and it is not a defect anywhere it
// currently appears. It is avoided here anyway, for one line, because the
// failure mode of a bound-atom in this family of draws is precisely what the
// session lane's silence timer nearly shipped, and a construction that is exactly
// open needs no argument about magnitude at all. Taking 52 bits leaves 2^52−0.5
// representable, so the quotient is 1 − 2^−53 and the bound is unreachable.
// TestUnitOpenNeverReachesABound checks both extremes of the input rather than a
// sample, and fails against the 53-bit version.
func unitOpen(r io.Reader) (float64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(b[:])
	return (float64(v>>12) + 0.5) / (1 << 52), nil
}

// SleepFunc waits for d or until ctx is done. Injected so that redial timing is
// deterministic in tests without this package owning a clock.
type SleepFunc func(ctx context.Context, d time.Duration) error

// realSleep is the default SleepFunc.
func realSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// DialFunc opens the transport a stream carrier will run over.
//
// A DialFunc is how TLS enters this package without this package building TLS:
// internal/tlsconfig is the single typed entry point for every client
// *tls.Config in this tree, and a second one here would be a second ClientHello
// to keep in step with a moving standard library. The composition is
//
//	dial := func(ctx context.Context) (net.Conn, error) {
//	    return (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", addr)
//	}
//
// with cfg from internal/tlsconfig. §3 of the handoff records why the hello is
// left stock — a Go client behind a CDN sits in an enormous cover population,
// and mimicry is a treadmill that is worse to fall off than never to start.
type DialFunc func(ctx context.Context) (net.Conn, error)

// DialTCP is a DialFunc for a bare TCP connection.
//
// Bare TCP is for tests and for a deployment behind an L4 fronting service that
// forwards by SNI without terminating TLS. A hostile network wants TLS.
func DialTCP(addr string) DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// DialStream opens a transport and wraps it in the §4.2 record layer.
func DialStream(ctx context.Context, dial DialFunc, cfg StreamConfig) (*Stream, error) {
	if dial == nil {
		return nil, wrap(ErrConfig, "no dial function")
	}
	if cfg.Conn != nil {
		return nil, wrap(ErrConfig, "DialStream opens the connection; leave StreamConfig.Conn nil")
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Conn = conn
	s, err := NewStream(cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return s, nil
}

// Redial dials until it succeeds or the attempt cap is spent, waiting a
// full-jitter delay between attempts.
//
// When the cap is spent it returns the last dial error. It does NOT pick a
// different carrier: spending the budget is §4.2's signal to change carrier
// class, and choosing the class belongs to datapath/escalation.go, which reasons
// over the whole plan rather than over one carrier's luck.
func Redial(
	ctx context.Context,
	b Backoff,
	rnd io.Reader,
	sleep SleepFunc,
	dial func(context.Context) (Conn, error),
) (Conn, error) {
	if dial == nil {
		return nil, wrap(ErrConfig, "no dial function")
	}
	b = b.orDefault()
	if err := b.validate(); err != nil {
		return nil, err
	}
	if sleep == nil {
		sleep = realSleep
	}
	var last error
	for attempt := 0; attempt < b.Attempts; attempt++ {
		if attempt > 0 {
			d, err := b.Delay(attempt-1, rnd)
			if err != nil {
				return nil, err
			}
			if err := sleep(ctx, d); err != nil {
				return nil, err
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, err := dial(ctx)
		if err == nil {
			if c == nil {
				return nil, wrap(ErrConfig, "dial returned a nil carrier")
			}
			return c, nil
		}
		last = err
	}
	return nil, last
}
