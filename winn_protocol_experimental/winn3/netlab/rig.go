package netlab

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Keyring is one gateway's material plus one client's, exactly as the
// ML-DSA-65-signed descriptor would supply it to both ends.
type Keyring struct {
	GatewayStatic *core.StaticKey
	ClientStatic  *core.StaticKey
	GatewayPublic *core.PublicKey
	Params        core.GatewayParams
	// Secret is the gateway admission secret a stream carrier keys its length
	// layer from. The rigs here supply their own, as every loopback proof has
	// had to: whose control-plane object carries it on each platform is item 6
	// of the driver lane's §10 and is not this lane's to decide.
	Secret []byte
}

// NewKeyring generates a fresh keyring. Nothing here is any key this project
// deploys.
func NewKeyring() (*Keyring, error) {
	gw, err := core.GenerateStaticKey()
	if err != nil {
		return nil, err
	}
	cli, err := core.GenerateStaticKey()
	if err != nil {
		return nil, err
	}
	pub, err := core.NewPublicKey(gw.Public())
	if err != nil {
		return nil, err
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i*7 + 3)
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*11 + 5)
	}
	return &Keyring{
		GatewayStatic: gw,
		ClientStatic:  cli,
		GatewayPublic: pub,
		Params: core.GatewayParams{
			AdmissionKeys: [][]byte{admission},
			GatewayID:     []byte("winn3-netlab-fixture"),
		},
		Secret: secret,
	}, nil
}

// Endpoint is one half of a tunnel: a loop, its host device, and the goroutine
// running it.
type Endpoint struct {
	Loop   *driver.Loop
	Device *Device
	err    chan error

	mu     sync.Mutex
	exited bool
	result error
}

// Err returns the channel Run's result arrives on.
func (e *Endpoint) Err() <-chan error { return e.err }

// Exited reports whether this endpoint's Loop.Run has already returned, and
// with what.
//
// It is latched rather than a bare channel read because the answer has to be
// askable more than once: every wait in this rig polls it, and a plain receive
// would hand the error to whichever caller happened to ask first and report
// "still running" to every caller after that.
//
// This exists because of a measured failure mode, not for tidiness. A driver
// loop that has exited leaves its session frozen at whatever state it last
// held — and Session().State() keeps answering that frozen value forever. A
// rig that waited on a session condition without asking this question would
// wait out its whole budget and then report "the client is established", which
// is true, useless, and reads exactly like a protocol defect: the loop under it
// was dead. Reporting a dead loop as a live established session is the silent
// refusal shape one layer up from the one this package exists to catch, so no
// wait here is allowed to be blind to it.
func (e *Endpoint) Exited() (error, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.exited {
		select {
		case err := <-e.err:
			e.exited, e.result = true, err
		default:
		}
	}
	return e.result, e.exited
}

// PairConfig configures a two-endpoint rig.
type PairConfig struct {
	// PathMTU is the planning path MTU the plan floor is computed at. Zero
	// means carrier.DefaultPathMTU, the fleet default, which is where a host
	// that measured nothing lands — so the rig plans at what ships.
	//
	// It was a literal 1280 until 2026-08-10. That is the RFC 8200 minimum for
	// the INNER link and was never a planning value: over the shipping plan it
	// floors the inner interface at 1139, which the kernel refuses to put IPv6
	// on, so driver.NewSizing now rejects it outright. Note the consequence for
	// impairments: the planning MTU and the narrowed paths these tests arm are
	// no longer the same number, and tests that need them equal must say so by
	// naming Sizing.PathMTU rather than by repeating a literal.
	PathMTU int

	// Plan is the migration plan. Empty means the shipping plan,
	// [UDP, TCP, TLS], which is the one that produces the 84-byte gap.
	Plan []carrier.Class

	// Class is what the pipes stand in for. Zero means carrier.ClassUDP.
	Class carrier.Class

	// TokenWindow sizes the receive window, and therefore both the reordering
	// tolerance and the burst-loss cliff. Zero means core.DefaultTokenWindow
	// (1024); the reorder measurements here use 256 so the boundary is reached
	// in a few hundred messages rather than a few thousand.
	TokenWindow int

	// SendQueue bounds the session's inner-packet queue. Zero means the
	// session default.
	SendQueue int

	// Seed makes any random loss reproducible.
	Seed uint64

	// Tweak adjusts both endpoints' session configuration after the defaults
	// are applied.
	Tweak func(*session.Config)

	// GatewayNoTun builds the gateway half with no inner-IP layer, which is the
	// deployed shape: a gateway's inner side is its own forwarding table.
	GatewayNoTun bool
}

// Pair is two driver.Loops joined by two Links, one per direction.
type Pair struct {
	Client  *Endpoint
	Gateway *Endpoint

	// ToGateway carries client → gateway; ToClient carries the reverse. They
	// are separate because impairment is directional: a NAT rebind, a
	// constrained path and a burst outage all routinely affect one direction
	// and not the other, and the session lane's desync detector is explicitly a
	// per-direction property.
	ToGateway *Link
	ToClient  *Link

	ClientPipe  *carrier.Pipe
	GatewayPipe *carrier.Pipe

	Clock  *StepClock
	Sizing driver.Sizing

	ClientAddr  netip.Addr
	GatewayAddr netip.Addr

	cancel context.CancelFunc
}

// NewPair builds the rig. Nothing is started until Start.
func NewPair(kr *Keyring, cfg PairConfig) (*Pair, error) {
	if cfg.PathMTU == 0 {
		cfg.PathMTU = carrier.DefaultPathMTU
	}
	if len(cfg.Plan) == 0 {
		cfg.Plan = []carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS}
	}
	if cfg.Class == carrier.ClassUnknown {
		cfg.Class = carrier.ClassUDP
	}
	sz, err := driver.NewSizing(cfg.PathMTU, cfg.Plan...)
	if err != nil {
		return nil, err
	}
	clk := NewStepClock()

	var cp, gp *carrier.Pipe
	toGateway := NewLink(func(m []byte) error { return gp.Deliver(m) }, cfg.Seed)
	toClient := NewLink(func(m []byte) error { return cp.Deliver(m) }, cfg.Seed^0x5DEECE66D)

	pipeCfg := carrier.PipeConfig{
		Class:   cfg.Class,
		PathMTU: cfg.PathMTU,
		Depth:   4096,
		Clock:   SessionClockOf(clk),
	}
	pc := pipeCfg
	pc.Out = toGateway.Offer
	if cp, err = carrier.NewPipe(pc); err != nil {
		return nil, err
	}
	gc := pipeCfg
	gc.Out = toClient.Offer
	if gp, err = carrier.NewPipe(gc); err != nil {
		return nil, err
	}

	p := &Pair{
		ToGateway:   toGateway,
		ToClient:    toClient,
		ClientPipe:  cp,
		GatewayPipe: gp,
		Clock:       clk,
		Sizing:      sz,
		ClientAddr:  V4(10, 64, 0, 2),
		GatewayAddr: V4(10, 64, 0, 1),
	}

	// base sets NO timers, so every pair built without a PairConfig.Tweak
	// inherits session's production defaults: Silence {5s, 15s, 45s}, Probe
	// {3s, 8s, 20s}, RekeyTimeout 15s, RekeyInterval {5m, 15m, 45m}. That is
	// deliberate — a rig that quietly retuned the schedules would be measuring a
	// protocol nobody ships.
	//
	// It is also the number every wait in this file has to clear. See the
	// virtual-time budget invariant on Settle: a rig's injected budget must sit
	// strictly below the shortest of these that the test is not exercising, and
	// on this rig the injected budget is `real budget x step x 5000`, not the
	// real budget. A test that needs a long injected run must push the schedule
	// it is not exercising out through Tweak, the way
	// TestAMidSessionMTUDropIsInvisibleBelowTheSessionAndVisibleToIt pushes
	// RekeyInterval to 12h before spending many minutes of virtual time.
	base := func() session.Config {
		return session.Config{
			Core:      core.Config{Gateway: kr.Params, TokenWindow: cfg.TokenWindow},
			Padding:   core.PadBucket,
			SendQueue: cfg.SendQueue,
		}
	}

	ccfg := base()
	ccfg.Static = kr.ClientStatic
	ccfg.GatewayStatic = kr.GatewayPublic
	if cfg.Tweak != nil {
		cfg.Tweak(&ccfg)
	}
	if p.Client, err = p.endpoint(ccfg, cp, sz, p.ClientAddr, p.GatewayAddr, false, driver.NewClient); err != nil {
		return nil, err
	}

	gcfg := base()
	gcfg.Static = kr.GatewayStatic
	gcfg.Accept = func([]byte) error { return nil }
	if cfg.Tweak != nil {
		cfg.Tweak(&gcfg)
	}
	if p.Gateway, err = p.endpoint(gcfg, gp, sz, p.GatewayAddr, p.ClientAddr, cfg.GatewayNoTun, driver.NewGateway); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Pair) endpoint(
	sc session.Config, c carrier.Conn, sz driver.Sizing,
	local, router netip.Addr, noTun bool,
	build func(driver.Config) (*driver.Loop, error),
) (*Endpoint, error) {
	dcfg := driver.Config{Session: sc, Sizing: sz, Carrier: c, Clock: p.Clock}
	var dev *Device
	if !noTun {
		dev = NewDevice(sz.InnerMTU)
		dcfg.Tun = &tun.Config{
			Assign:    tun.Assignment{V4: local, RouterV4: router},
			Device:    dev,
			Clock:     SessionClockOf(p.Clock),
			ICMPBurst: 8,
		}
	}
	l, err := build(dcfg)
	if err != nil {
		return nil, err
	}
	return &Endpoint{Loop: l, Device: dev, err: make(chan error, 1)}, nil
}

// Start runs both loops. The returned context is cancelled by Stop.
func (p *Pair) Start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	go func() { p.Client.err <- p.Client.Loop.Run(ctx) }()
	go func() { p.Gateway.err <- p.Gateway.Loop.Run(ctx) }()
}

// Stop cancels both loops and closes both host devices, which is what ends the
// outbound device pump: tun.Device has no Close because that lifecycle belongs
// to the host, and the rig is the host here.
func (p *Pair) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.Client.Device != nil {
		p.Client.Device.Close()
	}
	if p.Gateway.Device != nil {
		p.Gateway.Device.Close()
	}
}

// MigrateTo moves BOTH live sessions onto a fresh carrier of another class,
// through a fresh pair of Links, with no re-handshake.
//
// It builds new Links as well as new pipes because the impairment on the new
// path is the whole point of the exercise: the 84-byte trap is a statement
// about what the DESTINATION carrier can carry, and a rig that migrated onto
// the old, unimpaired link would prove nothing about it.
//
// The two ends migrate one at a time, which is what a real failover looks like
// — the client dials the replacement and the gateway follows. Messages the
// client sends in between are buffered by the new gateway-side pipe, so the
// gap costs latency and not delivery.
func (p *Pair) MigrateTo(class carrier.Class, pathMTU int) error {
	if pathMTU == 0 {
		pathMTU = p.Sizing.PathMTU
	}
	var ncp, ngp *carrier.Pipe
	toGateway := NewLink(func(m []byte) error { return ngp.Deliver(m) }, 0x51ED)
	toClient := NewLink(func(m []byte) error { return ncp.Deliver(m) }, 0x51EE)

	cfg := carrier.PipeConfig{
		Class:   class,
		PathMTU: pathMTU,
		Depth:   4096,
		Clock:   SessionClockOf(p.Clock),
	}
	var err error
	cc := cfg
	cc.Out = toGateway.Offer
	if ncp, err = carrier.NewPipe(cc); err != nil {
		return err
	}
	gc := cfg
	gc.Out = toClient.Offer
	if ngp, err = carrier.NewPipe(gc); err != nil {
		return err
	}

	if _, err := p.Client.Loop.Migrate(ncp); err != nil {
		return fmt.Errorf("client migrate to %s: %w", class, err)
	}
	if _, err := p.Gateway.Loop.Migrate(ngp); err != nil {
		return fmt.Errorf("gateway migrate to %s: %w", class, err)
	}
	p.ClientPipe, p.GatewayPipe = ncp, ngp
	p.ToGateway, p.ToClient = toGateway, toClient
	return nil
}

// ProveCarrying pushes one small packet end to end and waits for it.
//
// It exists for one reason: a migration returns as soon as the carrier pointer
// has been swapped, but the reader goroutine only re-arms on the new carrier
// when it observes the generation change, and under `-race` on a loaded machine
// that is not instant. A test that armed an impairment and offered traffic in
// that window would be measuring the scheduler. This makes "the new path is
// live" an observed fact rather than an assumption.
//
// A refused Offer is ErrOfferRefused, not ErrTimeout. Only the Collect miss
// is a timeout.
func (p *Pair) ProveCarrying(budget time.Duration) error {
	if p.OfferInner(1, 64) != 1 {
		return fmt.Errorf("%w: the host device would not accept a probe packet", ErrOfferRefused)
	}
	if p.Collect(1, budget) != 1 {
		return fmt.Errorf("%w: no packet crossed the new carrier within %s", ErrTimeout, budget)
	}
	return nil
}

// ErrTimeout is what the wait helpers report rather than failing a test
// themselves, so that a caller decides whether a timeout is the expected result.
var ErrTimeout = errors.New("winn3/netlab: condition not reached")

// ErrOfferRefused is what ProveCarrying reports when the host device would not
// accept the probe packet. That is not a timeout: the device's input queue is
// full or the device is closed. Wrapping it as ErrTimeout made the two
// failures indistinguishable, and a closed device then read as "the new
// carrier is slow".
var ErrOfferRefused = errors.New("winn3/netlab: host device refused an offer")

// oddStep makes a clock step an ODD number of nanoseconds, which is not a
// micro-optimisation and is not cosmetic. It is the difference between this rig
// killing the loops it measures and not.
//
// session.Driver arms its next wake at `probe.at + Probe.Max` (NextDeadline),
// but expires that probe only once `now.Sub(probe.at) > Probe.Max` — strictly
// greater. The two disagree on exactly one instant: the boundary itself. Land
// on it and driver.Loop.waitForWork sees a deadline that is not in the future,
// returns at once WITHOUT building a timer ("already due; the next Poll
// consumes it" — except this Poll does not consume it), drains nothing, and
// comes straight back. On a real clock that is harmless: time moves during the
// spin and the next comparison passes. On an INJECTED clock `now` cannot move,
// because the only goroutine that moves it is the test goroutine, and it is
// asleep. So the loop spins against a frozen clock until maxSpins=4096 and
// exits with ErrConfig — both loops, deterministically, mid-test.
//
// The rig hits this constantly where production never would: a fake clock walks
// in round steps from a round start, so `at + 20s` is exactly reachable. A step
// of an odd number of nanoseconds cannot sum to Probe.Max (20e9 ns, whose only
// odd divisors are powers of five), so the boundary is stepped OVER rather than
// landed on, and the driver expires the probe on the same wake it is woken for.
//
// This is a rig-side accommodation of a real off-by-one in the session driver.
// It is worth stating plainly that the underlying inequality is the defect and
// this only makes it unreachable from here.
func oddStep(d time.Duration) time.Duration {
	if d%2 == 0 {
		return d + 1
	}
	return d
}

// ErrLoopExited is what SettleWithin reports when a driver loop it is waiting
// on has already returned. It is a distinct error from ErrTimeout because the
// two want opposite responses: a timeout means "not yet", and this means
// "never, and the thing that would have made it true is gone".
var ErrLoopExited = errors.New("winn3/netlab: a driver loop exited while the rig was waiting")

// SettleWithin is Settle bounded by INJECTED time, and it is the wait every
// deadline-driven property in this package should use.
//
// Settle's only bound is a REAL deadline, and on this rig those two quantities
// are three orders of magnitude apart: a step of 50 ms of injected time costs
// about 200 us of real time, so a 60-second Settle pours roughly THREE AND A
// HALF HOURS of virtual time into a session. The consequences were measured,
// not theorised — 18 of 30 runs of this package failed under six-way
// concurrency, across five different tests, and every one of them is this:
//
//   - Past about 45 minutes of injected time the session has been through a
//     dozen rekey intervals (DefaultRekeyIntervalMax is 45 minutes). On a path
//     that carries nothing every one of those rekeys times out. A test that
//     meant to measure a four-minute probe budget was measuring fourteen failed
//     rekeys instead, and its failure message still said "4m0s" because that
//     figure was a hardcoded constant rather than a measurement.
//   - The far end's goroutines get a fixed number of real scheduling turns no
//     matter how much virtual time is poured past them, so counters the
//     assertion depends on stop advancing while the clock runs away.
//
// So the budget that matters is the injected one, and it is also the one the
// tests actually document: "detection must happen within the probe budget" is a
// statement about virtual seconds. `real` remains only as a safety net against a
// wedged rig, and reaching it is reported as ErrTimeout just the same.
//
// The measured injected elapsed time is returned so a caller can PRINT what
// actually happened instead of restating its own budget back to the reader.
// The STEP COUNT is the thing that actually had to be fixed, and it is not
// obvious, so it is written down here rather than left in a commit message.
//
// driver.Loop.writeLoop counts consecutive wake-ups that move no message and
// gives up at maxSpins = 4096, returning "the write loop woke 4097 times
// without moving a message". That guard is right — on a real clock, 4096 empty
// wakes IS a hot spin — but a rig that advances a fake clock in fixed steps
// walks straight into it: 1920 seconds of injected time at 50 ms a step is
// 38 400 wakes, an order of magnitude past the limit. BOTH loops then exit,
// and from that moment the sessions are frozen. Session().State() keeps
// answering "established", Session().Err() keeps answering nil, and every
// assertion in the test is now reading a corpse. One of this package's tests
// was failing with exactly that: "the session does NOT report a narrowed path
// ... state established, err <nil>" with both write loops dead underneath it.
// Read without the loop's own error that sentence accuses the protocol of the
// silent-refusal defect this whole package exists to detect.
//
// So the step is DERIVED from the injected budget to keep the wake count near
// 1500, comfortably inside the guard, instead of being a constant the caller
// picked without knowing the limit existed. The clamp keeps it finer than the
// shortest thing worth not stepping over (Probe.Min is 3 s) and coarser than a
// millisecond.
//
// The two time budgets bound opposite failures and both are needed. Bounding
// injected time alone makes things worse, which was measured by getting it
// wrong: 240 s of injected time spent in 1 s of real time gives the far end's
// goroutines a thousandth of the turns Settle's 60-second real budget gave
// them, and 17 of 18 runs failed. `realFloor` is therefore the real time the
// injected budget must be SPREAD over, making the rig's time dilation an
// explicit dial rather than an accident of two constants. A run that satisfies
// cond early pays only its share.
func (p *Pair) SettleWithin(injected, realFloor, realCap time.Duration, cond func() bool) (time.Duration, error) {
	const targetSteps = 1500 // against driver's maxSpins of 4096

	step := injected / targetSteps
	if step < time.Millisecond {
		step = time.Millisecond
	}
	if step > time.Second {
		step = time.Second
	}
	step = oddStep(step)
	pace := 200 * time.Microsecond
	if steps := injected / step; steps > 0 {
		if derived := realFloor / time.Duration(steps); derived > pace {
			pace = derived
		}
	}
	start := p.Clock.Now()
	deadline := time.Now().Add(realCap)
	for {
		if cond() {
			return p.Clock.Now().Sub(start), nil
		}
		// A loop that has exited is NOTED, not acted on. It is deliberately not
		// a reason to stop waiting: on a dead path both ends run their own probe
		// budget and one of them reaches the end first, so the far loop
		// returning while the near one still has a probe to lose is the ordinary
		// case rather than the pathological one. Bounding the wait is the
		// injected budget's job now, and that costs about a second, so there is
		// nothing left to save by giving up early.
		//
		// What it IS for is the failure message. A frozen session keeps
		// answering State() with the value it stopped at, and a timeout that
		// printed only that state would read as "established while carrying
		// nothing" — the silent-refusal signature — when the truth was a loop
		// that had already returned an error nobody read.
		p.noteExits()
		if elapsed := p.Clock.Now().Sub(start); elapsed >= injected {
			return elapsed, p.timeoutErr(ErrTimeout)
		}
		if time.Now().After(deadline) {
			return p.Clock.Now().Sub(start), p.timeoutErr(fmt.Errorf(
				"%w: %s of real time passed after only %s of injected time, which means the rig "+
					"is not stepping, not the session", ErrTimeout, realCap, p.Clock.Now().Sub(start)))
		}
		p.Clock.Advance(step)
		time.Sleep(pace)
	}
}

// noteExits latches whether either loop has returned, so that a later failure
// message can say so.
func (p *Pair) noteExits() {
	_, _ = p.Client.Exited()
	_, _ = p.Gateway.Exited()
}

// timeoutErr decorates a timeout with any loop that has already exited.
func (p *Pair) timeoutErr(base error) error {
	p.noteExits()
	cErr, cDone := p.Client.Exited()
	gErr, gDone := p.Gateway.Exited()
	switch {
	case cDone && gDone:
		return fmt.Errorf("%w [%w: client returned %v, gateway returned %v]", base, ErrLoopExited, cErr, gErr)
	case cDone:
		return fmt.Errorf("%w [%w: client returned %v]", base, ErrLoopExited, cErr)
	case gDone:
		return fmt.Errorf("%w [%w: gateway returned %v]", base, ErrLoopExited, gErr)
	}
	return base
}

// pairExercise names a schedule the caller deliberately drives, so the budget
// check skips it. Same invariant as session/fingerprint_test.go:requireQuietBudget
// but for the netlab Pair, which has two live sessions.
type pairExercise string

const (
	exerciseProbe pairExercise = "Probe.Min"
	exerciseRekey pairExercise = "RekeyInterval.Min"
)

// requirePairBudget holds the virtual-time budget invariant for a Pair.
// It reads the live Probe.Min and RekeyInterval.Min off both drivers (via the
// exported getters added for this invariant) and refuses a budget that reaches
// any timer the caller has not declared it is exercising. The budget is virtual
// time, never real time or a step count.
func requirePairBudget(t *testing.T, p *Pair, budget time.Duration, exercised ...pairExercise) {
	t.Helper()
	cProbe := p.Client.Loop.Session().ProbeDraw().Min
	gProbe := p.Gateway.Loop.Session().ProbeDraw().Min
	probe := cProbe
	if gProbe < probe {
		probe = gProbe
	}
	cRekey := p.Client.Loop.Session().RekeyIntervalDraw().Min
	gRekey := p.Gateway.Loop.Session().RekeyIntervalDraw().Min
	rekey := cRekey
	if gRekey < rekey {
		rekey = gRekey
	}
	for _, tm := range []struct {
		name   pairExercise
		period time.Duration
	}{
		{exerciseProbe, probe},
		{exerciseRekey, rekey},
	} {
		skip := false
		for _, e := range exercised {
			if e == tm.name {
				skip = true
				break
			}
		}
		if skip || budget < tm.period {
			continue
		}
		t.Fatalf("this rig may inject %s of virtual time and %s is %s, so a timer the test has not "+
			"declared it is exercising can fire inside the measurement (over by %s). A rig's "+
			"virtual-time budget must sit strictly below the shortest period of every timer it is "+
			"not trying to exercise: lower the budget, raise the interval via PairConfig.Tweak, or declare exercised %q.",
			budget, tm.name, tm.period, budget-tm.period, tm.name)
	}
}

// Settle advances the injected clock in steps while polling cond.
//
// It does two things at once on purpose: real time passes so the loops'
// goroutines get to run, and the INJECTED clock advances so the session's
// silence, probe and rekey deadlines are reached in microseconds rather than in
// minutes. A rig that only slept would never reach a probe budget; one that only
// advanced the fake clock would deadlock against goroutines that never got
// scheduled.
//
// # THE VIRTUAL-TIME BUDGET INVARIANT
//
// State it once, here, because this is where rigs are configured:
//
//	A rig that advances an INJECTED clock must have a stated VIRTUAL-TIME
//	budget, and that budget must sit STRICTLY BELOW the shortest period of
//	every timer the test is not trying to exercise.
//
// `budget` below is NOT that. It is a REAL deadline, and on this rig the two are
// three orders of magnitude apart: at 200 us a step, a `budget` of B seconds and
// a step of S injects roughly `B x S x 5000` seconds of virtual time. Settle
// therefore satisfies the invariant only when the caller has done the arithmetic
// and knows the product lands under the shortest timer it is not exercising.
// **Prefer SettleWithin**, which is bounded by injected time and derives its step
// so the wake count stays inside driver's maxSpins guard.
//
// Three corollaries, each of them a measured failure rather than a caution:
//
//   - A step count is not a budget. session's soloEmissions bounded itself at
//     maxSteps=4,000,000 x 100 ms — 400,000 s — while its config parked Probe at
//     one hour, and a probe fired inside a window meant to measure the silence
//     timer in 14 of 200 runs.
//   - A real-time deadline is not a budget. This function's own `budget` poured
//     about 3.5 hours of virtual time into a session in 60 seconds of real time
//     and killed both write loops on driver's maxSpins=4096. One defect, five
//     failing test names, 18 of 30 runs under six-way concurrency.
//   - When the timer you are not exercising is armed with FULL JITTER its
//     shortest period is ZERO, so the only admissible budget is zero. That is
//     the handshake retry, and it is why Handshake below injects nothing.
//
// The timers a netlab rig inherits when PairConfig.Tweak does not say otherwise
// are session's defaults, and they are short: Silence {5s, 15s, 45s}, Probe
// {3s, 8s, 20s}, RekeyTimeout 15s, RekeyInterval {5m, 15m, 45m}. Those are the
// numbers any budget computed here has to clear.
func (p *Pair) Settle(budget, step time.Duration, cond func() bool) error {
	deadline := time.Now().Add(budget)
	for {
		if cond() {
			return nil
		}
		p.noteExits()
		if time.Now().After(deadline) {
			return p.timeoutErr(ErrTimeout)
		}
		p.Clock.Advance(step)
		time.Sleep(200 * time.Microsecond)
	}
}

// Handshake drives both halves to established AND waits for both tun gates to
// be carrying.
//
// The second wait is not tidiness. The driver lane records in its §9.1 that the
// gate opens ONE WAKE LATE: a state change made inside Deliver on the reader
// goroutine is applied to the gate by the writer on its next pass. The
// asymmetry is deliberate — closing is latched and must never be late, opening
// is harmless if it is — but it means a host that starts writing the instant the
// session reports "established" loses a burst of packets to TxDroppedClosed.
//
// This rig measured that under load on the first `-race -count=2` run: 64 of 64
// offered packets counted as TxDroppedClosed with the session established. It
// is not a defect and the staged-start posture already handles it (a host
// promotes on Stats().RxPackets > 0, which cannot be reached before the gate
// opens), but a rig that did not wait for it would attribute the loss to
// whatever impairment it had just armed.
// A handshake injects NO virtual time. That is not a tuning choice, it is the
// virtual-time budget invariant applied to a schedule armed with FULL JITTER.
//
// The client's handshake retransmission is `drawBackoff` on [0, Retry.Base] —
// uniform, so its shortest period is ZERO, and the only virtual-time budget that
// sits strictly below zero is zero. Any injected time at all carries a
// proportional chance of releasing a retransmission: at the old 1 ms step this
// wait spent 2–4 ms of virtual time against a 500 ms base, which is a ~0.6 %
// chance per run, and under load it spends far more because the loop keeps
// stepping until the real goroutines converge.
//
// What that retransmission costs is not the retransmission. The copy of the
// INITIATION arrives AFTER the gateway has installed its session, so it lands in
// session.Driver.Deliver's `d.sess.Open(msg)` rather than in deliverHandshake,
// fails, and is counted in Stats.Unopenable — correctly, since a replayed
// initiation is indistinguishable from noise. TestAPerfectLinkIsLoopback then
// reports "N messages failed to open on a perfect link" with no impairment armed
// anywhere in the run.
//
// Measured on this rig, 2026-08-09, six runs per row, by holding everything else
// fixed and varying ONLY the step this loop advances by:
//
//	step=0     injected 0s      HandshakeMessagesSent=1   gateway Unopenable=0   (6/6)
//	step=1ms   injected 2–4ms   HandshakeMessagesSent=1   gateway Unopenable=0   (6/6)
//	step=300ms injected 900ms   HandshakeMessagesSent=2–3 gateway Unopenable=1–3 (6/6)
//
// The middle row is the one that flaked: it is under the base only on an idle
// machine. The top row is this function now. A handshake is message-driven, not
// deadline-driven — nothing in it waits on a timer except the retry — so it
// completes on real scheduling turns alone, and injecting nothing removes the
// retransmission rather than baselining the count it produces.
//
// If a future test ever wants a handshake that DOES retry — one armed with loss
// before the handshake, say — it must ask for the injected time explicitly and
// expect the peer's Unopenable to move, because the two are the same event.
func (p *Pair) Handshake(budget time.Duration) error {
	carrying := func(e *Endpoint) bool {
		if e.Loop.Tunnel() == nil {
			return true
		}
		return e.Loop.Tunnel().Gate().State() == tun.StateCarrying
	}
	cond := func() bool {
		return p.Client.Loop.Session().State() == session.StateEstablished &&
			p.Gateway.Loop.Session().State() == session.StateEstablished &&
			carrying(p.Client) && carrying(p.Gateway)
	}

	start := p.Clock.Now()
	deadline := time.Now().Add(budget)
	real0 := time.Now()
	for !cond() {
		if time.Now().After(deadline) {
			p.noteExits()
			return p.timeoutErr(fmt.Errorf(
				"%w: handshake left client=%s gateway=%s after %s of real time and %s of injected "+
					"time (client err %v, gateway err %v). This wait injects no virtual time on "+
					"purpose, so a handshake that does not complete here is stalled on messages, "+
					"not waiting on a deadline",
				ErrTimeout, p.Client.Loop.Session().State(), p.Gateway.Loop.Session().State(),
				time.Since(real0), p.Clock.Now().Sub(start),
				p.Client.Loop.Session().Err(), p.Gateway.Loop.Session().Err()))
		}
		time.Sleep(200 * time.Microsecond)
	}
	return nil
}

// FullPayload is the payload size that makes one inner packet fill exactly one
// Winn3 message.
//
// It matters more than it looks. The session coalesces DATA frames until the
// message payload budget is spent, so 300 small packets cross the link as about
// 30 messages — and every impairment in this package acts on MESSAGES. A rig
// that offered small packets and then counted them would be measuring a tenth
// of the impairment it configured. Full-size packets are also the traffic class
// every failure here is actually about: the black hole a mis-sized session
// produces is invisible to small packets by construction.
func (p *Pair) FullPayload() int { return p.Sizing.InnerMTU - 20 }

// SendInner offers n inner packets of the given payload size from the client's
// host device to the gateway's, and reports how many arrived.
//
// It does not assert. Every property in this package is about how many packets
// arrive under an impairment, and a helper that failed on a missing packet
// could not express "this many were supposed to be lost".
func (p *Pair) SendInner(n, payload int, within time.Duration) (sent, got int) {
	sent = p.OfferInner(n, payload)
	return sent, p.Collect(sent, within)
}

// OfferInner hands n inner packets to the client's host device and reports how
// many the device accepted.
func (p *Pair) OfferInner(n, payload int) int {
	sent := 0
	for i := 0; i < n; i++ {
		buf := make([]byte, payload)
		for j := range buf {
			buf[j] = byte(i*31 + j)
		}
		if !p.Client.Device.Offer(IPv4Packet(p.ClientAddr, p.GatewayAddr, buf)) {
			break
		}
		sent++
	}
	return sent
}

// Collect waits for up to want packets to reach the gateway's host device and
// reports how many arrived. It advances the injected clock while it waits, so a
// stalled flow does not also stall the session's own schedule.
//
// The step is DERIVED from the virtual-time budget this Collect may inject,
// not a constant, to keep the wake count near 1500 and inside driver's
// maxSpins=4096 guard. Previously it hardcoded 1 ms, which for a 40-second
// real budget poured ~20 seconds of virtual time in 20 000 wakes — five times
// the guard — tripping it and killing both write loops with the session frozen
// at "established".
func (p *Pair) Collect(want int, within time.Duration) int {
	if p.Gateway.Device == nil {
		return 0
	}
	const targetSteps = 1500
	injectedEst := within / 2
	if injectedEst < time.Millisecond {
		injectedEst = time.Millisecond
	}
	step := injectedEst / targetSteps
	if step < time.Millisecond {
		step = time.Millisecond
	}
	if step > time.Second {
		step = time.Second
	}
	step = oddStep(step)
	got := 0
	deadline := time.Now().Add(within)
	for got < want && time.Now().Before(deadline) {
		if _, ok := p.Gateway.Device.Take(2 * time.Millisecond); ok {
			got++
			continue
		}
		p.Clock.Advance(step)
	}
	return got
}
