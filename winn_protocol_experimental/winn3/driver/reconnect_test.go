package driver

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The reconnect-supervisor suite.
//
// The primitives this sits on — carrier.Backoff, session.Retry — are already
// atom-free and capped, and their own suites prove it. What this file proves is
// that the supervisor actually spaces whole-tunnel rebuilds with that schedule:
// a dropped session is followed by an exponential, full-jitter, capped wait,
// never by an immediate rebuild (a storm) and never by a fixed cadence (a
// pattern an observer can lock onto and block).
//
// The detector and its teeth follow the shape the carrier lane uses for its own
// backoff suite: the wrong implementations (clamped at the cap, fixed at the
// base) are fed to the detector and required to be rejected, so a guard that
// cannot fail is not mistaken for evidence.

// stubRunner is a Runner whose Run returns immediately with a preset result and
// whose Close records that it ran. A round that dies the instant it is driven is
// exactly what an on-path adversary who drops every packet produces.
type stubRunner struct {
	err    error
	closed atomic.Bool
}

func (s *stubRunner) Run(context.Context) error { return s.err }

func (s *stubRunner) Close() error {
	s.closed.Store(true)
	return nil
}

// exhaustRuns runs ONE supervisor to its round budget and returns the drawn
// delays, so a test can read the schedule exactly as the supervisor used it.
// The round dies immediately, which is the adversary's best case.
func exhaustRuns(t *testing.T, b carrier.Backoff, attempts int) (err error, sleeps []time.Duration) {
	t.Helper()
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			return &stubRunner{err: errors.New("peer unreachable")}, nil
		},
		Backoff:  b,
		Attempts: attempts,
		Sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	runErr := rc.Run(context.Background())
	return runErr, sleeps
}

// backoffWindow mirrors carrier.Backoff.window: min(Cap, Base·2^n), computed
// the same way, so a mutation that removes the cap has a number to disagree
// with.
func backoffWindow(b carrier.Backoff, n int) time.Duration {
	w := b.Base
	for i := 0; i < n; i++ {
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

// TestReconnectSpacesEveryRoundWithABackoffDraw is the piece with no counterpart
// below it.
//
// carrier.Backoff.Delay being correct is worth nothing if the supervisor does
// not actually wait each draw before the next round. This drives a supervisor
// whose tunnel dies instantly, records every delay it waited, and checks each
// one against the window that round should draw from: inside (0, window(n)),
// never the window, never zero. The per-round window bound is what makes the
// "always the first window" and "always the cap" mutations fail on the first
// assert whether or not the statistical tests happen to catch them.
func TestReconnectSpacesEveryRoundWithABackoffDraw(t *testing.T) {
	b := carrier.Backoff{Base: 500 * time.Millisecond, Cap: 8 * time.Second, Attempts: 8}
	const rounds = 6
	err, sleeps := exhaustRuns(t, b, rounds+1)
	if !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("exhausted run returned %v, want ErrReconnectExhausted", err)
	}
	if len(sleeps) != rounds {
		t.Fatalf("%d delays drawn for %d rounds, want %d", len(sleeps), rounds, rounds)
	}
	for n, d := range sleeps {
		window := backoffWindow(b, n)
		if d <= 0 {
			t.Fatalf("round %d waited %v, non-positive", n, d)
		}
		if d >= window {
			t.Fatalf("round %d waited %v, not below the %v window; the draw is not open at the top",
				n, d, window)
		}
		if d >= b.Cap {
			t.Fatalf("round %d waited %v, at or above the %v cap", n, d, b.Cap)
		}
	}
	if sleeps[0] == sleeps[1] {
		t.Fatalf("round 0 and round 1 drew the same delay (%v); the draw is not jittered", sleeps[0])
	}
}

// TestReconnectExponentialGrowthReachesAndThenSitsOnTheCap samples the window
// itself: the largest delay per round index must grow by roughly a factor of
// two until it saturates at the cap, and every draw must stay inside the round's
// window while still reaching into its lower fifth (full jitter, not "exponential
// plus noise").
func TestReconnectExponentialGrowthReachesAndThenSitsOnTheCap(t *testing.T) {
	b := carrier.Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 8}
	const runs = 60
	rows := make([][]time.Duration, 6)
	for i := range rows {
		rows[i] = make([]time.Duration, 0, runs)
	}
	for run := 0; run < runs; run++ {
		err, sleeps := exhaustRuns(t, b, 7) // 7 rounds -> delays for rounds 0..5
		if !errors.Is(err, ErrReconnectExhausted) {
			t.Fatalf("run %d returned %v", run, err)
		}
		for n := range rows {
			rows[n] = append(rows[n], sleeps[n])
		}
	}
	windows := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 8 * time.Second, 8 * time.Second,
	}
	var prevMax time.Duration
	for n, win := range windows {
		var max, min time.Duration
		min = win
		for _, d := range rows[n] {
			if d > max {
				max = d
			}
			if d < min {
				min = d
			}
			if d >= win || d <= 0 {
				t.Fatalf("round %d drew %v, outside (0, %v)", n, d, win)
			}
		}
		// The observed maximum must sit near the window: with 60 uniform draws
		// it is essentially never below 85% of it.
		if max < win*85/100 {
			t.Fatalf("round %d maximum %v is well below its %v window; the schedule is not reaching it",
				n, max, win)
		}
		// Full jitter keeps the minimum down in every window, saturated ones
		// included; "exponential plus a little noise" would fail this.
		if min > win/5 {
			t.Fatalf("round %d minimum %v is above a fifth of its %v window; the draw is not full jitter",
				n, min, win)
		}
		if n > 0 && win < b.Cap && max < prevMax*15/10 {
			t.Fatalf("round %d maximum %v did not grow from round %d's %v", n, max, n-1, prevMax)
		}
		prevMax = max
	}
}

type verdict struct {
	distinct    int
	modalShare  float64
	cv          float64
	maxAutocorr float64
}

// detectMetronome is the same four-statistic detector the carrier lane uses:
// each statistic alone admits one bad family, and together they admit none of
// the ones measured in this protocol's history.
func detectMetronome(d []time.Duration) verdict {
	if len(d) == 0 {
		return verdict{}
	}
	counts := make(map[time.Duration]int, len(d))
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
			if r := math.Abs(num / varsum); r > maxAuto {
				maxAuto = r
			}
		}
	}
	return verdict{distinct: len(counts), modalShare: float64(modal) / float64(len(d)), cv: cv, maxAutocorr: maxAuto}
}

func (v verdict) metronome(n int) bool {
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

// TestReconnectDelaysAreNotAMetronome runs the detector over the saturated tail
// of a long session and requires the WRONG implementations to be rejected by
// the same detector, so the guard has teeth.
//
// The saturated tail is the series a censor actually sees: a client blocked
// long enough that every window is the cap draws uniform on (0, Cap). A clamped
// supervisor would emit the cap as a constant — the 25-second keepalive
// metronome slowed to eight seconds — and this is where that reads as a pattern.
func TestReconnectDelaysAreNotAMetronome(t *testing.T) {
	b := carrier.Backoff{Base: 500 * time.Millisecond, Cap: 8 * time.Second, Attempts: 8}
	err, sleeps := exhaustRuns(t, b, 250)
	if !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("exhausted run returned %v", err)
	}
	// Saturation: rounds 0..3 have windows 0.5/1/2/4s; from round 4 on the
	// window is the cap. The tail is the only part uniform on (0, Cap).
	const firstSaturated = 4
	if len(sleeps) < firstSaturated+120 {
		t.Fatalf("only %d delays, need a saturated tail of ~120", len(sleeps))
	}
	tail := sleeps[firstSaturated:]
	for i, d := range tail {
		if d >= b.Cap || d <= 0 {
			t.Fatalf("saturated draw %d is %v, outside (0, %v)", i, d, b.Cap)
		}
	}
	if v := detectMetronome(tail); v.metronome(len(tail)) {
		t.Fatalf("the reconnect series looks like a metronome: %+v", v)
	}

	// Teeth: the wrong shapes this guard exists to reject.
	cases := []struct {
		name string
		ser  []time.Duration
	}{
		{"clamped at the cap", func() []time.Duration {
			out := make([]time.Duration, len(tail))
			for i := range out {
				out[i] = b.Cap
			}
			return out
		}()},
		{"fixed at the base", func() []time.Duration {
			out := make([]time.Duration, len(tail))
			for i := range out {
				out[i] = b.Base
			}
			return out
		}()},
		{"dithered metronome", func() []time.Duration {
			out := make([]time.Duration, len(tail))
			for i := range out {
				out[i] = b.Cap + time.Duration(i%7)*time.Millisecond
			}
			return out
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v := detectMetronome(c.ser); !v.metronome(len(c.ser)) {
				t.Fatalf("the detector accepted a %s (%+v); it has no teeth", c.name, v)
			}
		})
	}
}

// TestReconnectStopsOnContextCancellation: a user's Stop must end the loop and
// must not be read as a failure to back off from. A cancelled context must also
// interrupt a pending wait rather than sit out an honest backoff draw.
func TestReconnectStopsOnContextCancellation(t *testing.T) {
	var builds atomic.Int64
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds.Add(1)
			return &stubRunner{err: errors.New("peer unreachable")}, nil
		},
		Backoff: carrier.Backoff{Base: time.Second, Cap: 4 * time.Second, Attempts: 8},
		Clock:   &blockingClock{},
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rc.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run on a cancelled context returned %v, want context.Canceled", err)
	}
	if builds.Load() != 0 {
		t.Fatalf("%d builds happened on a cancelled context, want none", builds.Load())
	}
}

// blockingClock is a Clock whose timers never fire on their own. It exists so a
// test can prove the supervisor returns on a cancelled context rather than
// waiting out a drawn delay.
type blockingClock struct{}

func (b *blockingClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func (b *blockingClock) NewTimer(d time.Duration) Timer { return &neverTimer{} }

type neverTimer struct{}

func (n *neverTimer) C() <-chan time.Time { return make(chan time.Time) }
func (n *neverTimer) Stop()               {}

// TestReconnectHonourTheRoundBudget: Attempts rounds is the §4.2 change-carrier
// signal. The supervisor must build exactly that many times, wait between each
// pair, and return ErrReconnectExhausted wrapping the round's cause.
func TestReconnectHonourTheRoundBudget(t *testing.T) {
	var builds atomic.Int64
	boom := errors.New("the carrier class is dead")
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds.Add(1)
			return &stubRunner{err: boom}, nil
		},
		Backoff:  carrier.Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 8},
		Attempts: 4,
		Sleep:    func(_ context.Context, _ time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	err = rc.Run(context.Background())
	if !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("Run returned %v, want ErrReconnectExhausted", err)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the exhausted error does not wrap the round's cause: %v", err)
	}
	if got := builds.Load(); got != 4 {
		t.Fatalf("%d builds for a budget of 4, want exactly 4", got)
	}
	st := rc.Stats()
	if st.Builds != 4 || st.Failed != 4 || st.Delays != 3 {
		t.Fatalf("stats are %+v, want 4 builds / 4 failed / 3 delays", st)
	}

	// A budget of 1 must build once and never wait.
	rc2, err := NewReconnect(ReconnectConfig{
		Build:    func() (Runner, error) { return &stubRunner{err: boom}, nil },
		Backoff:  carrier.Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 8},
		Attempts: 1,
		Sleep: func(context.Context, time.Duration) error {
			t.Fatal("a budget of 1 must not wait")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	if err := rc2.Run(context.Background()); !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("one-shot Run returned %v", err)
	}
}

// TestReconnectRebuildsAfterEveryDeathIncludingAGracefulClose pins the contract
// that only a cancelled context is not a reconnect reason: a peer CLOSE (Run
// returning nil) must be followed by a rebuild just like a failure, because a
// tunnel that does not re-establish after a close stays down after the peer
// restarts.
func TestReconnectRebuildsAfterEveryDeathIncludingAGracefulClose(t *testing.T) {
	round := 0
	var buildMu sync.Mutex
	builds := 0
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			buildMu.Lock()
			defer buildMu.Unlock()
			round++
			r := &stubRunner{err: errors.New("peer unreachable")}
			if round == 1 || round == 2 {
				r.err = nil // graceful close
			}
			builds++
			return r, nil
		},
		Backoff:  carrier.Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 8},
		Attempts: 3,
		Sleep:    func(_ context.Context, _ time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	err = rc.Run(context.Background())
	if !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("Run returned %v, want ErrReconnectExhausted", err)
	}
	buildMu.Lock()
	defer buildMu.Unlock()
	if builds != 3 {
		t.Fatalf("%d rebuilds; each graceful close must be followed by one", builds)
	}
}

// TestReconnectDoesNotStormUnderAFastFailingSession is the property in the lane
// task, measured with a real clock and the default wait.
//
// An on-path adversary who drops every packet produces rounds that die the
// instant they start. A supervisor with no backoff would spin those rounds as
// fast as it could — a reconnect storm that is itself a beacon. This one places
// each rebuild a drawn delay apart, and once the windows saturate the rate is
// bounded by the cap. The window is short and the bounds wide so this is a storm
// detector, not a benchmark: if the wait between rounds disappears (mutant), the
// build count is hundreds of thousands and this fails by orders of magnitude.
func TestReconnectDoesNotStormUnderAFastFailingSession(t *testing.T) {
	b := carrier.Backoff{Base: 2 * time.Millisecond, Cap: 32 * time.Millisecond, Attempts: 1 << 20}
	var builds atomic.Int64
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds.Add(1)
			return &stubRunner{err: errors.New("dropped")}, nil
		},
		Backoff:  b,
		Attempts: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(250 * time.Millisecond)
		cancel()
	}()
	_ = rc.Run(ctx)
	got := builds.Load()
	if got < 3 {
		t.Fatalf("only %d rebuilds in 250 ms; the supervisor is not re-establishing", got)
	}
	if got > 500 {
		t.Fatalf("%d rebuilds in 250 ms; the reconnect schedule is a storm", got)
	}
}

// TestReconnectDefaultWaitGoesThroughTheClock closes the loop that the whole
// schedule stays deterministic: with the injected Sleep absent, the wait must
// go through the package Clock so the fake-clock rigs can drive it. A second
// build is not allowed until the drawn delay has passed on the Clock.
func TestReconnectDefaultWaitGoesThroughTheClock(t *testing.T) {
	var builds atomic.Int64
	clk := newStepClock()
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds.Add(1)
			return &stubRunner{err: errors.New("dropped")}, nil
		},
		Backoff: carrier.Backoff{Base: time.Second, Cap: 4 * time.Second, Attempts: 8},
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rc.Run(ctx) }()
	waitFor(t, time.Second, "the first build", func() bool { return builds.Load() == 1 })

	select {
	case err := <-done:
		t.Fatalf("the supervisor returned %v before its clock advanced", err)
	default:
	}
	if builds.Load() != 1 {
		t.Fatalf("%d builds before the first backoff window elapsed; no wait happened", builds.Load())
	}
	waitFor(t, time.Second, "the reconnect timer to be registered", func() bool {
		return clk.pendingTimers() == 1
	})

	clk.Advance(5 * time.Second)
	waitFor(t, time.Second, "the second build after the clock advanced", func() bool {
		return builds.Load() == 2
	})
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v after cancel, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// carrierTracker records every carrier the supervisor builds and whether it was
// closed before the next one was adopted. A stale carrier still live while a
// fresh one is built is a double-open — two sessions on the wire at once, which
// is the exact leak the reconnect contract exists to prevent (a fresh session
// on a fresh carrier must not be built over one that never came down).
type carrierTracker struct {
	mu         sync.Mutex
	live       map[int]bool
	nextID     int
	built      int
	closed     int
	doubleOpen int
}

func (c *carrierTracker) build() (Runner, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// At the moment a new carrier is adopted, every earlier carrier must already
	// be down. Any one still live is a stale carrier being left open.
	for _, open := range c.live {
		if open {
			c.doubleOpen++
		}
	}
	id := c.nextID
	c.nextID++
	c.live[id] = true
	c.built++
	return &trackedCarrier{tracker: c, id: id, err: errors.New("peer unreachable")}, nil
}

func (c *carrierTracker) snapshot() (built, closed, doubleOpen int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.built, c.closed, c.doubleOpen
}

type trackedCarrier struct {
	tracker *carrierTracker
	id      int
	err     error
}

func (t *trackedCarrier) Run(context.Context) error { return t.err }

func (t *trackedCarrier) Close() error {
	t.tracker.mu.Lock()
	defer t.tracker.mu.Unlock()
	if t.tracker.live[t.id] {
		t.tracker.live[t.id] = false
		t.tracker.closed++
	}
	return nil
}

// TestReconnectTearsDownStaleCarrierBeforeAdoptingANewOne proves the ordering
// the whole supervisor depends on: a carrier whose session died is closed
// before the next round builds a new one.
//
// The failure mode this guards against is the double-open: a supervisor that
// builds a fresh carrier without first shutting the previous one leaves two
// tunnels live at once — the stale one still holds the host's route and the
// fresh one is adopted on top of it. Deleting the Close call in Run (the
// mutation this lane is built to catch) leaves every prior carrier live, and
// this test goes red on the very first stale adoption.
func TestReconnectTearsDownStaleCarrierBeforeAdoptingANewOne(t *testing.T) {
	tr := &carrierTracker{live: map[int]bool{}}
	rc, err := NewReconnect(ReconnectConfig{
		Build:    tr.build,
		Backoff:  carrier.Backoff{Base: time.Second, Cap: 8 * time.Second, Attempts: 8},
		Attempts: 5,
		Sleep:    func(_ context.Context, _ time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewReconnect: %v", err)
	}
	if err := rc.Run(context.Background()); !errors.Is(err, ErrReconnectExhausted) {
		t.Fatalf("Run returned %v, want ErrReconnectExhausted", err)
	}
	built, closed, doubleOpen := tr.snapshot()
	if built != 5 {
		t.Fatalf("%d carriers built for a budget of 5, want exactly 5", built)
	}
	if doubleOpen != 0 {
		t.Fatalf("%d double-open(s): a stale carrier was still live when a new one was adopted", doubleOpen)
	}
	if closed != 5 {
		t.Fatalf("%d carriers torn down for %d built; every carrier must be closed as its round ends", closed, built)
	}
}

// --- the real-socket kill + rebind rig ---------------------------------------

// shortHardware shortens the session's handshake retry schedule and liveness
// probes so a socket-kill rig spends milliseconds, not the 8 s default cap, on
// a handshake nobody answers.
//
// It does not make an ESTABLISHED session notice a killed socket in tens of
// milliseconds. The first send after the kill is refused, the loop retains the
// sealed bytes and freezes new sealing (and with it the session's timers), and
// the loop fails only when that retention has lasted carrierStallLimit, 2 s.
// That freeze, not the liveness schedule here, is how round 0 ends in these
// rigs.
func shortHardware(c *session.Config) {
	c.Retry = session.Retry{
		Base:     5 * time.Millisecond,
		Cap:      50 * time.Millisecond,
		Attempts: 5,
	}
	c.Probe = session.Draw{
		Min:  10 * time.Millisecond,
		Mean: 20 * time.Millisecond,
		Max:  30 * time.Millisecond,
	}
	c.MaxLostProbes = 2
}

// newNoTunClientLoop builds the initiating half of a tunnel with no tun layer,
// for rigs that only need the session to establish. ConsoleLoops are real: a
// real handshake runs, but no kernel device or host posture is created.
func newNoTunClientLoop(kr *keyring, sz Sizing, car carrier.Conn) (*Loop, error) {
	return newNoTunClientLoopOn(kr, sz, car, SystemClock{})
}

// newNoTunClientLoopOn is newNoTunClientLoop on clk, which is the loop's clock
// and, through it, the session's.
func newNoTunClientLoopOn(kr *keyring, sz Sizing, car carrier.Conn, clk Clock) (*Loop, error) {
	cfg := session.Config{
		Core:          core.Config{Gateway: kr.params},
		Static:        kr.cliStatic,
		GatewayStatic: kr.gwPublic,
		Padding:       core.PadBucket,
	}
	shortHardware(&cfg)
	return NewClient(Config{Session: cfg, Sizing: sz, Carrier: car, Clock: clk})
}

// reserveLoopbackPort grabs an ephemeral loopback datagram port and releases it,
// leaving that number free to be re-bound repeatedly. UDP carries no connection
// state, so the same local port can be re-bound immediately after a close on
// every platform this protocol targets; a rig that raced another process for the
// number would show up as a foreign peer, which the supervisor has no way to
// notice, so the reservation makes it deterministic.
func reserveLoopbackPort(t *testing.T, ip net.IP) int {
	t.Helper()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	return port
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

// rigRound is one socket-kill rig round: the round's *Loop plus the carrier and
// socket the rig built for it.
//
// Loop.Close does not close the carrier it was given; the caller owns it, and
// Reconnect only calls Runner.Close. A bare *Loop Runner therefore left every
// round's socket bound to the rig's fixed local port: after a failed round
// each later Build was refused with "address already in use", and even the
// final successful round's socket stayed open after the test. Close releases
// the carrier and the socket after the loop's own teardown, which is where the
// loop may still offer a queued CLOSE to the carrier. Embedding *Loop keeps the
// loop's optional runner interfaces visible to Reconnect.
type rigRound struct {
	*Loop
	car  carrier.Conn
	conn *net.UDPConn
}

var (
	_ ProvenRunner      = (*rigRound)(nil)
	_ EstablishedRunner = (*rigRound)(nil)
	_ PeerCloseRunner   = (*rigRound)(nil)
)

func (r *rigRound) Close() error {
	err := r.Loop.Close()
	_ = r.car.Close()
	_ = r.conn.Close()
	return err
}

// requireClientPortReleased fails if the rig's fixed client port is still bound
// once the supervisor has stopped. Every round binds that one port, so a bind
// here proves no round's socket outlived its round. Call it only after Run
// has returned, before any t.Cleanup fallback has had a chance to hide a leak.
func requireClientPortReleased(t *testing.T, ip net.IP, port int) {
	t.Helper()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		t.Fatalf("client port %d is still bound after the supervisor stopped: a round's socket was not released: %v", port, err)
	}
	_ = probe.Close()
}

// joinSupervisor cancels a rig's supervisor and waits until its Run has
// returned. The rigs defer it right after starting the supervisor, so it runs
// on every exit path, an early Fatal included, and it runs before any t.Cleanup:
// defers finish before cleanups start, and this one does not return until Run
// has. No Build can therefore allocate a socket after the rig's socket
// fallbacks have run. A long wait logs a diagnostic every `every` and keeps
// waiting; it is never treated as completion, and the process-level test
// timeout bounds a real deadlock. Callers must not hold a lock Build takes.
func joinSupervisor(t testing.TB, cancel context.CancelFunc, exited <-chan struct{}, every time.Duration) {
	t.Helper()
	cancel()
	for waited := time.Duration(0); ; {
		select {
		case <-exited:
			return
		case <-time.After(every):
			waited += every
			t.Logf("still waiting for the reconnect supervisor to stop, %v after cancellation", waited)
		}
	}
}

// TestRigShutdownJoinsTheSupervisorBeforeSocketFallbacks proves the ordering
// joinSupervisor exists for, with a Build held AFTER the supervisor's context
// check. The rig goroutine then ends early (SkipNow, which unwinds through the
// same runtime.Goexit path as Fatal, so defers run and then cleanups), and the
// held Build is released only after the join's diagnostic interval has passed
// many times over. The Build allocates a socket and registers its t.Cleanup
// fallback the way both rigs do, and returns a Runner whose Close does NOT
// release it, as a bare *Loop did.
//
// With a join that gives up on a timer, the rig's cleanups run while Build is
// still held; the late socket and its late fallback come after them, the
// fallback never runs, and the port is still bound when the supervisor stops.
// With a real join, cleanup waits for Run, the fallback runs, and the port is
// free.
func TestRigShutdownJoinsTheSupervisorBeforeSocketFallbacks(t *testing.T) {
	loopback := net.IPv4(127, 0, 0, 1)
	port := reserveLoopbackPort(t, loopback)

	var (
		mu     sync.Mutex
		events []string
	)
	record := func(e string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}

	held := make(chan struct{})
	release := make(chan struct{})
	runExited := make(chan struct{})
	const every = 20 * time.Millisecond

	t.Run("rig", func(rt *testing.T) {
		rt.Cleanup(func() { record("fallback cleanups ran") })
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rc, err := NewReconnect(ReconnectConfig{
			Build: func() (Runner, error) {
				close(held)
				<-release
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: port})
				if err != nil {
					return nil, err
				}
				rt.Cleanup(func() { _ = conn.Close() })
				record("build allocated a socket")
				return &stubRunner{}, nil
			},
			Attempts: 1,
		})
		if err != nil {
			rt.Fatal(err)
		}
		go func() { _ = rc.Run(ctx); close(runExited) }()
		defer joinSupervisor(rt, cancel, runExited, every)

		<-held
		time.AfterFunc(10*every, func() { close(release) })
		rt.SkipNow()
	})

	select {
	case <-runExited:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor never returned after its held Build was released")
	}
	mu.Lock()
	got := append([]string(nil), events...)
	mu.Unlock()
	want := []string{"build allocated a socket", "fallback cleanups ran"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("events %q, want %q: the rig's cleanups ran before its supervisor had stopped", got, want)
	}
	requireClientPortReleased(t, loopback, port)
}

// stepRoundZeroUntilRebuilt advances ONLY the killed round's clock until the
// supervisor has built the next round.
//
// Both socket-kill rigs give every client round, and the gateway, a stepClock of
// its own. Round 0 notices its dead socket only when its clock moves: a probe
// falls due, the send is refused, and the refused bytes are held for
// carrierStallLimit before the loop fails and Run returns. Every later round and
// the gateway keep a clock that never moves, so no handshake retransmission,
// handshake give-up, liveness verdict or half-open expiry can fire on them.
//
// On wall clocks the rigs were a race against the machine. The shortened
// schedule gives a round's handshake five full-jitter draws of at most 5, 10,
// 20, 40 and 50 ms per phase (at most 125 ms, mean 62.5 ms, and far less at the
// low tail) to hear from a gateway that must also run on the same loaded CPU.
// One round that lost that race made the exact-count predicates below
// unsatisfiable, and the test then waited out its 20 s bound. Measured under
// GOMAXPROCS=2 with two spinning goroutines, the rebind test failed 8 of 10 runs
// with -race and 10 of 10 without. With frozen clocks the first rebuild can only
// establish or hang, and a hang is a real defect the bound still reports.
func stepRoundZeroUntilRebuilt(t *testing.T, clk0 *stepClock, rebuilt func() bool) {
	t.Helper()
	start := clk0.Now()
	deadline := time.Now().Add(20 * time.Second)
	for !rebuilt() {
		if !time.Now().Before(deadline) {
			t.Fatalf("no second round was built after %v of round 0's stepped time: the lost carrier was never rebuilt",
				clk0.Now().Sub(start))
		}
		clk0.Advance(carrierStallLimit / 20)
		time.Sleep(time.Millisecond)
	}
}

// TestReconnectRebindsToTheSamePeerAfterTheCarrierSocketIsKilled is the
// socket-level form of the reconnect contract. A client whose carrier socket is
// killed — a lost carrier — must come back up against the SAME peer over a
// FRESH socket, and the re-established session must return to established; it
// must not give up, and it must not reuse the dead socket.
//
// The rig is real: two datagram sockets on the loopback interface, a live
// gateway with its own session, and a supervisor driving a real handshake per
// round. Because the client dials from a fixed local port and UDP rebinds that
// port freely, the gateway's return path is constant across the kill — this is
// "socket killed, re-bound" in the literal sense, not a stub pretending.
//
// Time is the rig's, not the machine's; see stepRoundZeroUntilRebuilt.
//
// The teeth, each a mutation this guard exists to catch:
//
//   - Deleting the rebuild in Run (return after the first round) leaves
//     builds == 1 and the session dead after the kill; this test demands a
//     second build to the same peer AND a second established state.
//   - Deleting the fresh socket (rebinding the old one) fails the new-socket
//     and same-local-port asserts before any stub could.
func TestReconnectRebindsToTheSamePeerAfterTheCarrierSocketIsKilled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	loopback := net.IPv4(127, 0, 0, 1)
	cliPort := reserveLoopbackPort(t, loopback)

	gwConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer gwConn.Close()
	gwAddr := gwConn.LocalAddr().(*net.UDPAddr)

	// The gateway answers the client's fixed local port for the whole test, so
	// it never needs a NAT-rebind bookkeeping move either.
	gwCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: gwConn, Peer: &net.UDPAddr{IP: loopback, Port: cliPort},
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, clock: newStepClock(),
		local: gatewayAddr(), router: clientAddr(),
	})
	defer gw.stop()
	gw.start(ctx)

	var (
		guard  sync.Mutex
		loops  []*Loop
		conns  []*net.UDPConn
		peers  []*net.UDPAddr
		clocks []*stepClock
		builds int
	)
	buildRound := func() (*rigRound, *net.UDPConn, *net.UDPAddr, *stepClock, error) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: cliPort})
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// Fallback for a Fatal or a partial construction; rigRound.Close is the
		// normal release. Closing a closed socket is harmless.
		t.Cleanup(func() { _ = conn.Close() })
		car, err := carrier.NewUDP(carrier.UDPConfig{
			Conn: conn, Peer: gwAddr,
			MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU, OwnsConn: true,
		})
		if err != nil {
			_ = conn.Close()
			return nil, nil, nil, nil, err
		}
		clk := newStepClock()
		l, err := newNoTunClientLoopOn(kr, sz, car, clk)
		if err != nil {
			_ = conn.Close()
			return nil, nil, nil, nil, err
		}
		return &rigRound{Loop: l, car: car, conn: conn}, conn, car.Peer(), clk, nil
	}

	done := make(chan error, 1)
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			guard.Lock()
			defer guard.Unlock()
			r, conn, peer, clk, err := buildRound()
			if err != nil {
				return nil, err
			}
			builds++
			loops = append(loops, r.Loop)
			conns = append(conns, conn)
			peers = append(peers, peer)
			clocks = append(clocks, clk)
			return r, nil
		},
		Backoff:  carrier.Backoff{Base: 5 * time.Millisecond, Cap: 50 * time.Millisecond, Attempts: 8},
		Attempts: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	runExited := make(chan struct{})
	go func() { done <- rc.Run(ctx); close(runExited) }()
	defer joinSupervisor(t, cancel, runExited, 5*time.Second)

	// lastEstablished reports whether the most recently built loop reached the
	// established state. Callers hold guard.
	lastEstablished := func() bool {
		if len(loops) == 0 {
			return false
		}
		return loops[len(loops)-1].Session().State() == session.StateEstablished
	}

	// Round 0 establishes over a real socket to the real gateway. The poll locks
	// around each read so the supervisor's own Build (which locks too) is never
	// starved by a wait held open by the test.
	round0Up := func() bool {
		guard.Lock()
		defer guard.Unlock()
		return builds == 1 && lastEstablished()
	}
	waitFor(t, 20*time.Second, "round 0 to establish", round0Up)

	guard.Lock()
	if len(peers) != 1 || len(conns) != 1 || conns[0].LocalAddr() == nil {
		guard.Unlock()
		t.Fatal("round 0 did not bind a socket")
	}
	if got := peers[0].String(); got != gwAddr.String() {
		guard.Unlock()
		t.Fatalf("round 0 dialled peer %s, want %s", got, gwAddr)
	}
	killed := conns[0]
	clk0 := clocks[0]
	guard.Unlock()

	// Kill the carrier socket. Round 0's session must give up so Run returns
	// and the supervisor rebuilds; stepping round 0's clock is what lets it.
	if err := killed.Close(); err != nil {
		t.Fatalf("closing the client socket: %v", err)
	}
	stepRoundZeroUntilRebuilt(t, clk0, func() bool {
		guard.Lock()
		defer guard.Unlock()
		return builds >= 2
	})

	rebound := func() bool {
		guard.Lock()
		defer guard.Unlock()
		return builds == 2 && lastEstablished()
	}
	waitFor(t, 20*time.Second, "a fresh socket to re-establish with the same peer", rebound)

	guard.Lock()
	if builds != 2 {
		got := builds
		guard.Unlock()
		t.Fatalf("%d builds after one socket kill, want exactly 2: the first lost carrier must be rebuilt once and stay up", got)
	}
	if !sameUDPAddr(peers[len(peers)-1], gwAddr) {
		dialled := peers[len(peers)-1].String()
		guard.Unlock()
		t.Fatalf("the rebuild dialled peer %s, want the same peer %s", dialled, gwAddr)
	}
	if len(conns) < 2 || conns[len(conns)-1] == killed {
		guard.Unlock()
		t.Fatal("the rebuild reused the killed socket instead of a fresh one")
	}
	if got := conns[len(conns)-1].LocalAddr().(*net.UDPAddr).Port; got != cliPort {
		guard.Unlock()
		t.Fatalf("the rebuild rebound to local port %d, want the same %d", got, cliPort)
	}
	if !lastEstablished() {
		st := loops[len(loops)-1].Session().State()
		guard.Unlock()
		t.Fatalf("the re-established session is %s, want established", st)
	}
	guard.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor did not stop after cancellation")
	}
	requireClientPortReleased(t, loopback, cliPort)
}

// TestReconnectReSeamsTheDatapathAfterACarrierRebind closes the last gap in the
// reconnect contract: the previous socket-kill test drove a client loop with NO
// tun layer, so it proved the session re-establishes on a fresh socket but never
// exercised the seam between the session and the datapath.
//
// The "seam" is the frameSink adapter in sink.go — the thing that hands inner
// packets from winn3/tun to the session and back. A reconnect that rebuilt a
// fresh session but failed to re-seam it to a live datapath would look
// established and carry nothing: the session's counters climb while the host
// device stays silent. That is the silent-refusal family again, one layer up
// from the one v3_reconnect_bug fixed.
//
// This rig therefore builds each round with a REAL tun layer whose host device
// is a real loopback UDP socket. The gateway offers an inner packet into the
// seam before the kill; the host must receive it. Then the carrier socket is
// killed, the supervisor rebuilds, and the same offer is repeated against the
// rebuilt round: the host must receive a second inner packet, delivered through
// the NEW round's session and its NEW seam, not through the dead one.
//
// Teeth: none of the assertions can go green from the old round. The old round's
// Run has returned and its tun pump has stopped, so only the live rebuilt loop
// writes to the host device — a re-seam that connected the fresh session to
// nothing (or to a stale, closed device) delivers no second packet and this
// fails. The rebuilt loop is also asserted to be a distinct object with its own
// device, and the rebuild must reach established against the SAME still-live
// gateway, which is the responder re-initiation path exercised end-to-end.
//
// Time is the rig's, not the machine's; see stepRoundZeroUntilRebuilt.
func TestReconnectReSeamsTheDatapathAfterACarrierRebind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	loopback := net.IPv4(127, 0, 0, 1)
	cliPort := reserveLoopbackPort(t, loopback)

	// The host seam: a real loopback datagram socket that receives the client's
	// decrypted inner packets. Each round's client device writes to this port.
	host, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer host.Close()
	hostPort := host.LocalAddr().(*net.UDPAddr).Port

	// The responder: a real gateway over a real UDP socket, alive for the whole
	// test. It keeps ONE session per peer, so the rebuilt client re-initiates
	// against a still-established responder — the admission path v3_reconnect_bug
	// fixed must be reachable through the real datapath here.
	gwConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skipf("cannot open a loopback datagram socket: %v", err)
	}
	defer gwConn.Close()
	gwAddr := gwConn.LocalAddr().(*net.UDPAddr)
	gwCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: gwConn, Peer: &net.UDPAddr{IP: loopback, Port: cliPort},
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, clock: newStepClock(),
		local: gatewayAddr(), router: clientAddr(),
	})
	defer gw.stop()
	gw.start(ctx)

	var (
		guard   sync.Mutex
		loops   []*Loop
		devices []*dsSeamDevice
		conns   []*net.UDPConn
		peers   []*net.UDPAddr
		clocks  []*stepClock
		builds  int
	)
	buildRound := func() (Runner, error) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: cliPort})
		if err != nil {
			return nil, err
		}
		// Fallback for a Fatal or a partial construction; rigRound.Close is the
		// normal release. Closing a closed socket is harmless.
		t.Cleanup(func() { _ = conn.Close() })
		car, err := carrier.NewUDP(carrier.UDPConfig{
			Conn: conn, Peer: gwAddr,
			MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU, OwnsConn: true,
		})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		dev := newDSSeamDevice(t, hostPort, sz.InnerMTU)
		cfg := session.Config{
			Core:          core.Config{Gateway: kr.params},
			Static:        kr.cliStatic,
			GatewayStatic: kr.gwPublic,
			Padding:       core.PadBucket,
		}
		shortHardware(&cfg)
		clk := newStepClock()
		l, err := NewClient(Config{
			Session: cfg,
			Sizing:  sz,
			Carrier: car,
			Clock:   clk,
			Tun: &tun.Config{
				Assign:    tun.Assignment{V4: clientAddr(), RouterV4: gatewayAddr()},
				Device:    dev,
				Clock:     SessionClock{Clock: clk},
				ICMPBurst: 4,
			},
		})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		guard.Lock()
		loops = append(loops, l)
		devices = append(devices, dev)
		conns = append(conns, conn)
		peers = append(peers, car.Peer())
		clocks = append(clocks, clk)
		builds++
		guard.Unlock()
		return &rigRound{Loop: l, car: car, conn: conn}, nil
	}

	rc, err := NewReconnect(ReconnectConfig{
		Build:    buildRound,
		Backoff:  carrier.Backoff{Base: 5 * time.Millisecond, Cap: 50 * time.Millisecond, Attempts: 8},
		Attempts: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	runExited := make(chan struct{})
	go func() { done <- rc.Run(ctx); close(runExited) }()
	defer joinSupervisor(t, cancel, runExited, 5*time.Second)

	lastEstablished := func() bool {
		return len(loops) > 0 && loops[len(loops)-1].Session().State() == session.StateEstablished
	}

	// readInner blocks for one datagram carrying marker, proving the seam that
	// leads to the host device is live. It loops because a live tunnel may emit
	// unrelated keepalive traffic between the two offers.
	readInner := func(within time.Duration, marker string) []byte {
		buf := make([]byte, 65535)
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			_ = host.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := host.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return nil
			}
			if n > 0 && bytes.Contains(buf[:n], []byte(marker)) {
				return append([]byte(nil), buf[:n]...)
			}
		}
		return nil
	}

	// Round 0 establishes over a real socket to the real gateway.
	waitFor(t, 20*time.Second, "round 0 to establish", func() bool {
		guard.Lock()
		defer guard.Unlock()
		return builds == 1 && lastEstablished()
	})
	guard.Lock()
	first := devices[0]
	guard.Unlock()

	// The seam carries before the kill.
	gw.dev.offer(t, dsInnerV4(gatewayAddr(), clientAddr(), []byte("winn3 reconnect seam pre")))
	if got := readInner(20*time.Second, "winn3 reconnect seam pre"); got == nil {
		t.Fatal("round 0 never delivered an inner packet to the host through its seam")
	}

	// Kill round 0's carrier socket. Stepping round 0's clock lets its session
	// give up, Run returns, and the supervisor rebuilds.
	guard.Lock()
	killed := conns[0]
	clk0 := clocks[0]
	guard.Unlock()
	if err := killed.Close(); err != nil {
		t.Fatalf("closing the client socket: %v", err)
	}
	stepRoundZeroUntilRebuilt(t, clk0, func() bool {
		guard.Lock()
		defer guard.Unlock()
		return builds >= 2
	})

	// Round 1 must re-establish against the same live responder AND carry.
	waitFor(t, 60*time.Second, "round 1 to re-establish after the kill", func() bool {
		guard.Lock()
		defer guard.Unlock()
		return builds == 2 && lastEstablished()
	})

	guard.Lock()
	if len(devices) != 2 || devices[1] == first {
		guard.Unlock()
		t.Fatal("the rebuilt round did not install a fresh datapath seam")
	}
	secondConn := conns[len(conns)-1]
	if secondConn == killed {
		guard.Unlock()
		t.Fatal("the rebuilt round reused the killed carrier connection")
	}
	if !sameUDPAddr(peers[len(peers)-1], gwAddr) {
		dialled := peers[len(peers)-1].String()
		guard.Unlock()
		t.Fatalf("the rebuilt round dialled peer %s, want the same %s", dialled, gwAddr)
	}
	guard.Unlock()

	// The re-seam: the rebuilt session must deliver through its OWN device.
	gw.dev.offer(t, dsInnerV4(gatewayAddr(), clientAddr(), []byte("winn3 reconnect seam post")))
	if got := readInner(45*time.Second, "winn3 reconnect seam post"); got == nil {
		t.Fatal("after the reconnect the re-seamed datapath delivered nothing to the host")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor did not stop after cancellation")
	}
	requireClientPortReleased(t, loopback, cliPort)
}
