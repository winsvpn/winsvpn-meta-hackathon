package driver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// faultyCarrier is a Pipe that can be made to fail on demand, so that the loop's
// reaction to a carrier misbehaving is testable without a network.
type faultyCarrier struct {
	*carrier.Pipe
	sendErr atomic.Pointer[error]
	recvErr atomic.Pointer[error]
	sends   atomic.Uint64
	recvs   atomic.Uint64
}

func newFaulty(t *testing.T, class carrier.Class) *faultyCarrier {
	t.Helper()
	p, err := carrier.NewPipe(carrier.PipeConfig{Class: class})
	if err != nil {
		t.Fatal(err)
	}
	return &faultyCarrier{Pipe: p}
}

func (f *faultyCarrier) failSend(err error) { f.sendErr.Store(&err) }
func (f *faultyCarrier) failRecv(err error) { f.recvErr.Store(&err) }

func (f *faultyCarrier) Send(ctx context.Context, msg []byte) error {
	f.sends.Add(1)
	if e := f.sendErr.Load(); e != nil {
		return *e
	}
	return f.Pipe.Send(ctx, msg)
}

func (f *faultyCarrier) Recv(ctx context.Context) ([]byte, error) {
	if e := f.recvErr.Load(); e != nil {
		f.recvs.Add(1)
		return nil, *e
	}
	return f.Pipe.Recv(ctx)
}

func (f *faultyCarrier) SendBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if e := f.sendErr.Load(); e != nil {
		return 0, *e
	}
	sent, err := f.Pipe.SendBatch(ctx, msgs)
	f.sends.Add(uint64(sent))
	return sent, err
}

func (f *faultyCarrier) RecvBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if e := f.recvErr.Load(); e != nil {
		f.recvs.Add(1)
		return 0, *e
	}
	return f.Pipe.RecvBatch(ctx, msgs)
}

var _ carrier.Conn = (*faultyCarrier)(nil)
var _ carrier.BatchCarrier = (*faultyCarrier)(nil)

// TestWriterWaitsRatherThanSpinning is the battery guard, and it is a property
// no other layer can hold: winn3/session and winn3/tun have no timer at all, so
// nothing below this package can be wrong about the wait.
//
// A client whose carrier delivers nothing has exactly one thing to do — wait for
// its retransmission deadline — and it must do that by sleeping rather than by
// polling. The clock here never advances on its own, so a loop that spun would
// send its retransmissions immediately and the count would climb.
func TestWriterWaitsRatherThanSpinning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	clk := newStepClock()
	blocked, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	e := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: blocked, clock: clk, noTun: true,
		tweak: func(c *session.Config) {
			c.Retry = session.Retry{Base: 5 * time.Second, Cap: 20 * time.Second, Attempts: 6}
		},
	})
	e.start(ctx)

	// The initiation goes out at once; nothing else may.
	waitFor(t, 5*time.Second, "the handshake initiation", func() bool {
		return blocked.Stats().Sent >= 1
	})
	time.Sleep(200 * time.Millisecond)
	if got := blocked.Stats().Sent; got != 1 {
		t.Fatalf("the loop sent %d messages while its clock stood still; it is spinning, not waiting", got)
	}

	// Advancing past the backoff releases exactly one more attempt.
	clk.Advance(25 * time.Second)
	waitFor(t, 5*time.Second, "one retransmission", func() bool {
		return blocked.Stats().Sent >= 2
	})
	time.Sleep(200 * time.Millisecond)
	if got := blocked.Stats().Sent; got > 3 {
		t.Fatalf("one clock advance produced %d messages", got)
	}

	cancel()
	_ = e.waitRun(10 * time.Second)
}

// TestASendErrorIsNotADeadSession.
//
// The measured censorship failure produces NO error at all: the socket opens,
// every write succeeds, and the reads never return. A loop that treated a
// transient send error as fatal would therefore fail over for the wrong reason
// and still not fail over for the right one. The message is lost — Poll hands
// its output over and keeps no copy, and re-sealing it would be a nonce reuse —
// and the session carries on.
func TestASendErrorIsNotADeadSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	f := newFaulty(t, carrier.ClassUDP)
	f.failSend(errors.New("ENOBUFS"))

	e := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: f, noTun: true,
		tweak: func(c *session.Config) {
			c.Retry = session.Retry{Base: 5 * time.Millisecond, Cap: 10 * time.Millisecond, Attempts: 40}
		},
	})
	e.start(ctx)

	waitFor(t, 10*time.Second, "the loop to record failed sends", func() bool {
		return e.loop.Stats().SendFailed >= 3
	})
	if got := e.loop.Session().State(); got.Terminal() {
		t.Fatalf("the session is %s after a few send errors; a send error is not a dead session", got)
	}
	if got := e.loop.Stats().MessagesSent; got != 0 {
		t.Fatalf("the loop counted %d successful sends through a carrier that refuses everything", got)
	}

	cancel()
	_ = e.waitRun(10 * time.Second)
}

// TestACarrierThatDiesDoesNotKillTheSession is the property the whole design
// turns on: a session holds no socket, so the socket dying must be survivable.
//
// If a dead carrier tore the session down, migrating off a blocked transport
// would require a fresh handshake, and §5.4's free migration — the structural
// answer to a censor who blocks UDP wholesale — would not exist.
func TestACarrierThatDiesDoesNotKillTheSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	f := newFaulty(t, carrier.ClassUDP)
	f.failRecv(carrier.ErrStreamDesync)

	e := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: f, noTun: true,
	})
	e.start(ctx)

	waitFor(t, 10*time.Second, "the loop to notice the dead carrier", func() bool {
		return e.loop.CarrierErr() != nil
	})
	if !errors.Is(e.loop.CarrierErr(), carrier.ErrStreamDesync) {
		t.Fatalf("the loop recorded %v, want the carrier's own desync error", e.loop.CarrierErr())
	}
	if got := e.loop.Session().State(); got.Terminal() {
		t.Fatalf("the session is %s because its carrier died; the session must outlive the carrier", got)
	}
	// A dead carrier and a session that wants a different carrier are different
	// facts, and the policy layer treats them differently.
	if e.loop.Observe().NeedsChange {
		t.Fatal("a dead carrier raised the session's handshake-budget signal")
	}
	// Pipe has no fatal(). Before the overlay, Observe().CarrierErr was nil
	// here while CarrierErr() was set — a policy that reads only Observe
	// (which is what this package's docs tell a host to do) would miss it.
	if !errors.Is(e.loop.Observe().CarrierErr, carrier.ErrStreamDesync) {
		t.Fatalf("Observe().CarrierErr is %v, want ErrStreamDesync", e.loop.Observe().CarrierErr)
	}

	cancel()
	_ = e.waitRun(10 * time.Second)
}

// TestTransientReadErrorsDoNotSpinForever bounds the other busy-loop.
//
// A transient read error is ordinary on a datagram carrier and must not be
// fatal. A RUN of them is not ordinary, and continuing to retry one at full
// speed would burn a handset's battery in exactly the conditions the user is
// already struggling with.
func TestTransientReadErrorsDoNotSpinForever(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	f := newFaulty(t, carrier.ClassUDP)
	f.failRecv(errors.New("transient read error"))

	e := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: f, noTun: true})
	e.start(ctx)

	waitFor(t, 10*time.Second, "the reader to give up on a broken carrier", func() bool {
		return e.loop.CarrierErr() != nil
	})
	time.Sleep(200 * time.Millisecond)
	got := f.recvs.Load()
	if got > maxRecvErrors+2 {
		t.Fatalf("the reader retried %d times, more than the %d-error bound", got, maxRecvErrors)
	}
	if got < 2 {
		t.Fatalf("the reader gave up after %d errors; one transient error must not be fatal", got)
	}
	if e.loop.Stats().RecvFailed != got {
		t.Fatalf("the loop counted %d read failures and the carrier saw %d",
			e.loop.Stats().RecvFailed, got)
	}
	if e.loop.Observe().CarrierErr == nil {
		t.Fatal("Observe().CarrierErr is nil after the reader gave up; the loop recorded the error and a Pipe has no fatal()")
	}

	cancel()
	_ = e.waitRun(10 * time.Second)
}

// TestALoopWithNoTunCountsWhatItCannotDeliver covers the gateway-side shape: a
// session whose inner side is not a host device. The packets are counted rather
// than silently discarded, because a counter is the only evidence a host has that
// it wired the loop up wrong.
func TestALoopWithNoTunCountsWhatItCannotDeliver(t *testing.T) {
	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	e := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: pipe, noTun: true})
	if e.loop.Tunnel() != nil {
		t.Fatal("a loop configured with no tun built one anyway")
	}
	e.loop.deliverInner(ipv4Packet(gatewayAddr(), clientAddr(), []byte("nowhere to go")))
	if got := e.loop.Stats().InnerNoTun; got != 1 {
		t.Fatalf("InnerNoTun is %d, want 1", got)
	}
	// A loop with no tun still has a gate-free datapath, so the sync is a no-op
	// rather than a nil dereference.
	e.loop.syncGate()
	e.loop.latchDown()
}

// TestAnInnerPacketTheTunRefusesIsCounted keeps the two failure classes apart. A
// packet the tun layer refuses on its address rules is a very different event
// from one that could not be delivered at all, and merging the counters would
// hide a gateway sending traffic addressed to a third party — which is the leak
// the inbound rules exist to stop.
func TestAnInnerPacketTheTunRefusesIsCounted(t *testing.T) {
	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	e := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: pipe, local: clientAddr(), router: gatewayAddr(),
	})
	defer e.stop()

	e.loop.gateMu.Lock()
	e.loop.tn.Gate().Set(tunCarrying())
	e.loop.gateMu.Unlock()

	// Addressed to somebody else. A host with IP forwarding enabled would
	// oblige; this endpoint is structurally incapable of it.
	elsewhere := v4a(10, 64, 0, 9)
	e.loop.deliverInner(ipv4Packet(gatewayAddr(), elsewhere, []byte("not for us")))
	if got := e.loop.Stats().InnerRejected; got != 1 {
		t.Fatalf("InnerRejected is %d, want 1", got)
	}
	if got := e.loop.Stats().InnerDelivered; got != 0 {
		t.Fatalf("%d packets addressed elsewhere were delivered to the host", got)
	}

	// And the legitimate one is delivered, so the assertion above is about the
	// address rule rather than about a dead code path.
	e.loop.deliverInner(ipv4Packet(gatewayAddr(), clientAddr(), []byte("for us")))
	if got := e.loop.Stats().InnerDelivered; got != 1 {
		t.Fatalf("InnerDelivered is %d, want 1", got)
	}
}

// TestLifecycleRefusals covers the small refusals that keep a host honest.
func TestLifecycleRefusals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	e := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: pipe, noTun: true})

	if got := e.loop.Sizing().MessageSize; got != sz.MessageSize {
		t.Fatalf("the loop reports a %d-byte floor, want %d", got, sz.MessageSize)
	}
	if _, err := e.loop.Migrate(nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("Migrate accepted a nil destination (err %v)", err)
	}

	e.start(ctx)
	waitFor(t, 10*time.Second, "the first Run to take the loop", func() bool {
		return pipe.Stats().Sent >= 1
	})
	if err := e.loop.Run(ctx); !errors.Is(err, ErrConfig) {
		t.Fatalf("a second Run was accepted (err %v)", err)
	}
	// Close is idempotent.
	if err := e.loop.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.loop.Close(); err != nil {
		t.Fatal(err)
	}
	_ = e.waitRun(10 * time.Second)
}

// TestWaitForWorkHandlesEveryDeadlineShape covers the three shapes a session's
// next deadline can take, because getting any of them wrong produces a busy loop
// on a battery rather than a visible failure.
//
//   - a deadline in the future: build a timer and wait on it;
//   - a deadline already past: do NOT build a timer and do not sleep, because
//     the next Poll consumes it;
//   - no deadline at all: wait on the carrier and on cancellation alone.
func TestWaitForWorkHandlesEveryDeadlineShape(t *testing.T) {
	sz := planSizing(t)
	kr := newKeyring(t)
	clk := newStepClock()
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}

	// A gateway is INITIATING with a deadline one client budget away.
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: pipe, clock: clk, noTun: true,
	})
	if gw.loop.Session().NextDeadline().IsZero() {
		t.Fatal("a fresh gateway has no deadline")
	}

	// Past: waitForWork must return at once rather than build a timer for a
	// negative duration.
	//
	// A day is an enormous margin over a budget of about two minutes, and that
	// is deliberate HERE: this test's subject is the three structurally
	// different BRANCHES, and each row has to land unambiguously in one of them.
	// It is not this test's job to hold the boundary and it must not be
	// tightened to the deadline instant as a way of testing it — that instant is
	// owned, one tick either way, by
	// TestWaitForWorkTreatsTheDeadlineInstantItselfAsDue in
	// deadlineboundary_test.go, with the hot-spin it produces measured by
	// TestTheGatewayDeadlineDoesNotHotSpinOnItsOwnBoundary beside it.
	clk.Advance(24 * time.Hour)
	done := make(chan error, 1)
	go func() { done <- gw.loop.waitForWork(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForWork on a past deadline returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForWork slept on a deadline that had already passed")
	}

	// None: a terminal session schedules nothing, so only cancellation ends the
	// wait.
	if err := gw.loop.Session().Close(); err != nil {
		t.Fatal(err)
	}
	if !gw.loop.Session().State().Terminal() {
		t.Fatalf("a gateway with no session is %s after Close", gw.loop.Session().State())
	}
	if !gw.loop.Session().NextDeadline().IsZero() {
		t.Fatal("a terminal session still schedules a deadline")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- gw.loop.waitForWork(ctx) }()
	select {
	case <-done:
		t.Fatal("waitForWork returned while nothing had happened and nothing was scheduled")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waitForWork returned %v on cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForWork did not return on cancellation")
	}
}

// TestADeepSendQueueDrainsCompletely checks that one drain cannot starve the
// wait, the gate sync and cancellation, and that bounding it loses nothing.
//
// The bound exists because a drain is the one place the loop can run unboundedly
// long: a caller that filled the send queue would otherwise hold the writer
// inside a single pass, and a state change or a cancellation arriving during it
// would be applied only after the queue emptied.
func TestADeepSendQueueDrainsCompletely(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, Depth: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	deep := func(c *session.Config) { c.SendQueue = 4096 }
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, noTun: true, tweak: deep,
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(), tweak: deep,
	})
	defer gw.stop()
	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 20*time.Second)

	// One packet per message: large enough that coalescing cannot hide the depth.
	const deepCount = 600
	body := make([]byte, sz.InnerMTU-20)
	for i := 0; i < deepCount; i++ {
		body[0] = byte(i)
		body[1] = byte(i >> 8)
		if err := cli.loop.Session().Enqueue(ipv4Packet(clientAddr(), gatewayAddr(), body)); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	waitFor(t, 30*time.Second, "the whole queue to reach the peer", func() bool {
		return gw.loop.Stats().InnerDelivered >= deepCount
	})
	if got := gw.loop.Stats().InnerDelivered; got != deepCount {
		t.Fatalf("%d of %d packets arrived", got, deepCount)
	}
	if got := cli.loop.Stats().SendFailed; got != 0 {
		t.Fatalf("%d messages failed to send from a deep queue", got)
	}

	cancel()
	_ = cli.waitRun(15 * time.Second)
}

// TestTheLoopObeysItsNextDeadlineAtTheBoundaryAndDoesNotSpin drives the REAL
// Run goroutine against a clock it cannot move, and walks it across the instant
// its session's next-deadline reports.
//
// It complements TestWriterWaitsRatherThanSpinning, which proves a client waits
// rather than spinning by counting retransmissions, and
// TestTheGatewayDeadlineDoesNotHotSpinOnItsOwnBoundary in
// deadlineboundary_test.go, which reduces writeLoop to its three lines and
// counts wake-ups on a frozen clock. Neither runs through Run, so neither can
// cite the timer the loop actually built. This one can: the counting clock
// records the timer the loop builds, and the assertion is that the loop parked
// itself on its session's next-deadline — one timer of exactly the remaining
// budget and nothing else — and then crossed the boundary into a terminal
// session in a single wake.
//
// Both halves are asserted because both FAIL OPEN in different ways. A loop
// that does not wait at all (fires early) stops carrying while its session
// still reports itself healthy, and the caller sees silence. A loop that waits
// past the instant — `d < 0` instead of `d <= 0` on the boundary, the defect
// that flaked 18 of 30 concurrent runs on 2026-08-09 — has to be killed by the
// maxSpins battery guard and returns ErrConfig instead of timing the half-open
// session out cleanly. The injected clock is the control for both: it never
// moves on its own, so every wake the loop makes has to be visible in the timer
// count or the terminal state.
func TestTheLoopObeysItsNextDeadlineAtTheBoundaryAndDoesNotSpin(t *testing.T) {
	clk := newCountingClock()
	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}

	start := clk.Now()
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: pipe, clock: clk, noTun: true,
		tweak: func(c *session.Config) { c.Retry = boundaryRetry },
	})
	dl := gw.loop.Session().NextDeadline()
	if want := start.Add(boundaryBudget); !dl.Equal(want) {
		t.Fatalf("a fresh gateway's next-deadline is %s, want %s (built %s, one client budget %s); "+
			"this test is only about the instant they coincide",
			dl.UTC(), want.UTC(), start.UTC(), boundaryBudget)
	}

	// Measure only the run, not the fixture's construction.
	clk.reset()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.start(ctx)

	// The loop must park itself on its next-deadline: one timer of exactly the
	// remaining budget, and no second one while we hold the clock still. The
	// budget is its full value here because the clock has not moved, so the
	// timer the loop builds points exactly AT the deadline it was handed. Held
	// still a moment longer to give a spinning loop the chance to churn.
	waitFor(t, 2*time.Second, "the loop to build its deadline timer", func() bool {
		return len(clk.timersBuilt()) == 1
	})
	time.Sleep(150 * time.Millisecond)
	if built := clk.timersBuilt(); len(built) != 1 || built[0] != boundaryBudget {
		t.Fatalf("with the clock held still the loop built %v, want exactly [%s]: more than one "+
			"timer means each wake built another (that is the spin), and any timer but the whole "+
			"remaining budget means it is not parked on its session's next-deadline",
			showDurations(built), boundaryBudget)
	}
	if got := pipe.Stats().Sent; got != 0 {
		t.Fatalf("a gateway sent %d message(s) while parked; it emits nothing until a client "+
			"initiates, so this is a loop manufacturing work for itself", got)
	}

	// The boundary: advance to EXACTLY the reported next-deadline. The timer
	// fires, the next Poll consumes the deadline, and the half-open session
	// times itself out. One wake — no maxSpins error, no re-armed timer.
	clk.Advance(boundaryBudget)
	if !clk.Now().Equal(dl) {
		t.Fatalf("the clock is at %s and the deadline at %s, a difference of %s; the advance "+
			"must land on the instant this test is about",
			clk.Now().UTC(), dl.UTC(), clk.Now().Sub(dl))
	}

	err = gw.waitRun(5 * time.Second)
	if !errors.Is(err, ErrSessionFailed) {
		t.Fatalf("Run returned %v crossing its deadline, want ErrSessionFailed: a half-open "+
			"session must time out cleanly here, not be killed by the maxSpins battery guard",
			err)
	}
	if st := gw.loop.Session().State(); st != session.StateFailed {
		t.Fatalf("the session is %s after the timeout, want %s", st, session.StateFailed)
	}
	if got := gw.loop.Session().LocalCloseReason(); got != session.CloseProtocolError {
		t.Fatalf("the half-open session closed with reason %s, want %s",
			got, session.CloseProtocolError)
	}
	if e := gw.loop.Session().Err(); !errors.Is(e, session.ErrPeerUnreachable) {
		t.Fatalf("a gateway that timed out waiting for a client reports %v, want ErrPeerUnreachable",
			e)
	}
	if !gw.loop.Session().NextDeadline().IsZero() {
		t.Fatal("a terminal session still schedules a deadline; the caller would come straight back")
	}

	// The clock is the control: one advance and nothing else moved.
	if got := clk.Now().Sub(start); got != boundaryBudget {
		t.Fatalf("the injected clock advanced by %s, want exactly %s: this test's premise is that "+
			"the loop crossed one boundary and nothing else moved it",
			got, boundaryBudget)
	}
	// And the one timer is all the loop ever asked for: it did not re-arm to
	// wait again after going terminal.
	if built := clk.timersBuilt(); len(built) != 1 {
		t.Fatalf("the loop built %d timer(s) in total, want exactly 1 — the one for the deadline "+
			"it crossed; any more means it kept waiting after going terminal", len(built))
	}
}

// TestLoopDoesNotOverrunItsNextDeadline forces the loop's next-deadline path
// through the REAL Run goroutine and asserts the deadline is consumed in one
// wake rather than over-run.
//
// TestTheLoopObeysItsNextDeadlineAtTheBoundaryAndDoesNotSpin above pins the
// same instant, but its name does not match the `-run TestLoop` filter, and
// that filter is this package's release command. Run without a boundary case
// under the TestLoop prefix, `-run TestLoop` selects only TestLoopback* and
// TestLoopRefuses*, neither of which crosses a deadline — so the release gate
// could claim a green while the boundary it must hold is never exercised. This
// test exists to close exactly that false green.
//
// The failure it guards against is the over-run: a loop that fails to consume a
// deadline it has been woken for keeps waking and moving nothing, so the
// writeLoop spends its maxSpins battery budget and Run returns ErrConfig
// instead of ErrSessionFailed. At the boundary instant this is invisible on a
// real clock, which is why the clock below is injected and held still until the
// test crosses the instant itself.
func TestLoopDoesNotOverrunItsNextDeadline(t *testing.T) {
	clk := newCountingClock()
	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}

	start := clk.Now()
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: pipe, clock: clk, noTun: true,
		tweak: func(c *session.Config) { c.Retry = boundaryRetry },
	})
	dl := gw.loop.Session().NextDeadline()
	if want := start.Add(boundaryBudget); !dl.Equal(want) {
		t.Fatalf("a fresh gateway's next-deadline is %s, want %s (built %s); this test is "+
			"only about the instant they coincide", dl.UTC(), want.UTC(), start.UTC())
	}

	// Measure only the run, not the fixture's construction.
	clk.reset()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.start(ctx)

	// The loop must park itself on its next-deadline: one timer of exactly the
	// remaining budget, built while we hold the clock still. Any second timer is
	// a spin that a real clock would hide.
	waitFor(t, 2*time.Second, "the loop to build its deadline timer", func() bool {
		return len(clk.timersBuilt()) == 1
	})
	time.Sleep(150 * time.Millisecond)
	if built := clk.timersBuilt(); len(built) != 1 || built[0] != boundaryBudget {
		t.Fatalf("with the clock held still the loop built %v, want exactly [%s]: any other timer "+
			"means it is not parked on its next-deadline or it is spinning", showDurations(built),
			boundaryBudget)
	}

	// Cross the boundary to EXACTLY the reported deadline. The timer fires, the
	// next Poll consumes it, and the half-open session times itself out.
	clk.Advance(boundaryBudget)
	if !clk.Now().Equal(dl) {
		t.Fatalf("the clock is at %s and the deadline at %s, a difference of %s; the advance must "+
			"land on the instant this test is about", clk.Now().UTC(), dl.UTC(), clk.Now().Sub(dl))
	}

	// The over-run assertion. A loop that failed to consume the deadline would
	// keep waking and moving nothing, burning maxSpins and returning ErrConfig;
	// the loop under test must instead wait the half-open session out and
	// return ErrSessionFailed — the clean timeout, not the battery guard.
	err = gw.waitRun(5 * time.Second)
	if !errors.Is(err, ErrSessionFailed) {
		t.Fatalf("Run returned %v crossing its next-deadline, want ErrSessionFailed: an over-run "+
			"that fails to consume the deadline shows up here as the maxSpins ErrConfig instead",
			err)
	}
	if st := gw.loop.Session().State(); st != session.StateFailed {
		t.Fatalf("the session is %s after the timeout, want %s", st, session.StateFailed)
	}
	if got := gw.loop.Session().LocalCloseReason(); got != session.CloseProtocolError {
		t.Fatalf("the half-open session closed with reason %s, want %s",
			got, session.CloseProtocolError)
	}
	if e := gw.loop.Session().Err(); !errors.Is(e, session.ErrPeerUnreachable) {
		t.Fatalf("a gateway that timed out waiting for a client reports %v, want ErrPeerUnreachable",
			e)
	}
	if !gw.loop.Session().NextDeadline().IsZero() {
		t.Fatal("a terminal session still schedules a deadline; the caller would come straight back")
	}

	// The clock is the control: exactly one advance and nothing else moved it,
	// and the single deadline timer is all the loop ever asked for.
	if got := clk.Now().Sub(start); got != boundaryBudget {
		t.Fatalf("the injected clock advanced by %s, want exactly %s: this test's premise is that "+
			"the loop crossed one boundary and nothing else moved it", got, boundaryBudget)
	}
	if built := clk.timersBuilt(); len(built) != 1 {
		t.Fatalf("the loop built %d timer(s) in total, want exactly 1 — the one it crossed; any "+
			"more means it kept waiting after going terminal", len(built))
	}
}

// TestResequencerHoldTimerExpiryWakesWriteLoop. A message the resequencer held
// for a missing counter and then released on the hold timer must wake the
// write loop exactly as a batch delivery does: here the held message is the
// peer's authenticated CLOSE, and Run must return promptly instead of sleeping
// until the session's next scheduled timer.
func TestResequencerHoldTimerExpiryWakesWriteLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP, Depth: 64})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, noTun: true,
	})
	gwLoop, err := NewGateway(Config{
		Session: session.Config{
			Core:    coreConfigFor(kr),
			Static:  kr.gwStatic,
			Accept:  func([]byte) error { return nil },
			Padding: 1, // core.PadBucket
		},
		Sizing:  sz,
		Carrier: gwCar,
		Reseq:   ReseqConfig{Enabled: true, HoldTime: 10 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := &endpoint{t: t, loop: gwLoop, err: make(chan error, 1)}

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 5*time.Second)
	gw.waitState(session.StateEstablished, 5*time.Second)
	waitFor(t, 5*time.Second, "gateway carrying", func() bool {
		return gw.loop.Carrying()
	})

	// Two separate data batches so the gateway resequencer has a live
	// frontier in the data epoch.
	for i := 0; i < 2; i++ {
		pkt := ipv4Packet(clientAddr(), gatewayAddr(), []byte("first"))
		if err := cli.loop.SendInner(pkt); err != nil {
			t.Fatal(err)
		}
		want := uint64(i + 1)
		waitFor(t, 5*time.Second, "gateway to receive data packet", func() bool {
			return gw.loop.Stats().InnerNoTun >= want
		})
	}

	// Spend the next counter on the client without transmitting it (a lost
	// UDP datagram), then send an authenticated CLOSE at the following one.
	if err := cli.loop.Session().Enqueue(ipv4Packet(clientAddr(), gatewayAddr(), []byte("dropped"))); err != nil {
		t.Fatal(err)
	}
	discard := make([]byte, sz.MessageSize)
	if msg, err := cli.loop.Session().PollInto(discard); err != nil || len(msg) == 0 {
		t.Fatalf("PollInto dropped packet: len=%d err=%v", len(msg), err)
	}
	if err := cli.loop.Close(); err != nil {
		t.Fatal(err)
	}
	_ = cli.waitRun(5 * time.Second)

	select {
	case err := <-gw.err:
		if err != nil {
			t.Fatalf("gateway Run returned %v, want nil on peer CLOSE", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("gateway Run hung after the resequencer hold timer delivered CLOSE (session state=%s)",
			gw.loop.Session().State())
	}
}
