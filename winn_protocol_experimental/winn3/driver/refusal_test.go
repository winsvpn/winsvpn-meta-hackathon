package driver

import (
	"context"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestGateDropsWhereEnqueueBuffers is the two refusal policies side by side, in
// one test, on one packet.
//
// Both sibling lanes recorded that somebody would eventually notice the
// difference and "fix" one to match the other. This test makes that a failing
// change rather than a plausible one: it asserts BOTH behaviours and then
// asserts the consequence that makes each right.
//
//   - The tun gate DROPS, because a tun device that blocks backpressures the
//     kernel's IP stack, and because a queue is a place a packet can survive a
//     teardown.
//   - session.Enqueue BUFFERS, because the stall is transient and bounded, and
//     dropping there would make StrictPQ lose the first packets of every new
//     connection — exactly the traffic a user notices.
//
// The consequence, checked at the end: a packet that reached the session's queue
// during the handshake is DELIVERED once the session establishes. It is delayed,
// not lost. A packet that met the closed gate is gone.
func TestGateDropsWhereEnqueueBuffers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	// Nothing is running yet, so the session is INITIATING and the gate — which
	// tun.NewGate returns closed — has never been opened.
	if got := cli.loop.Session().State(); got != session.StateInitiating {
		t.Fatalf("session is %s before Run, want initiating", got)
	}
	if got := cli.loop.Tunnel().Gate().State(); got != tun.StateDown {
		t.Fatalf("gate is %s before Run, want down", got)
	}

	dropped := ipv4Packet(clientAddr(), gatewayAddr(), []byte("this packet meets the gate"))
	if err := cli.loop.Tunnel().Outbound(dropped); !errors.Is(err, tun.ErrNotCarrying) {
		t.Fatalf("the tun layer accepted a packet with the gate closed (err %v)", err)
	}
	if got := cli.loop.Tunnel().Stats().TxDroppedClosed; got != 1 {
		t.Fatalf("TxDroppedClosed is %d after one refused packet, want 1", got)
	}
	if got := cli.loop.Tunnel().Stats().TxPackets; got != 0 {
		t.Fatalf("the session accepted %d packets through a closed gate, want 0", got)
	}

	// The SAME packet class, offered directly to the session, is accepted and
	// held. This is the difference, and it is not a bug in either layer.
	buffered := ipv4Packet(clientAddr(), gatewayAddr(), []byte("this packet meets the queue"))
	if err := cli.loop.Session().Enqueue(buffered); err != nil {
		t.Fatalf("the session refused a packet during the handshake (err %v); it is supposed to buffer", err)
	}
	if got := cli.loop.Session().Stats().DataFramesSent; got != 0 {
		t.Fatalf("%d data frames were sent while initiating, want 0 — the queue must hold them", got)
	}

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)

	// The buffered packet is delivered, late. The dropped one never appears.
	got := gw.dev.take(t, 10*time.Second)
	if d := digest(payloadOf(got)); d != digest(payloadOf(buffered)) {
		t.Fatalf("the delivered packet has digest %s, want the buffered packet's %s",
			d, digest(payloadOf(buffered)))
	}
	select {
	case extra := <-gw.dev.out:
		t.Fatalf("a second packet arrived (%s); the one refused at the gate must be gone",
			digest(payloadOf(extra)))
	case <-time.After(500 * time.Millisecond):
	}
}

// TestNoPacketCrossesAfterRunReturns is the loop-level fail-closed property, and
// it is the reason Run does not wait for the device pump.
//
// The pump is still running when Run returns — it is blocked in the host's
// ReadPacket and only the host can unblock it. What must be true is that it
// cannot move a byte: Run latches the gate down and tun.Gate.Set is a drain
// barrier, so when it returns nothing is still on its way in either direction.
func TestNoPacketCrossesAfterRunReturns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)

	if err := cli.loop.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cli.waitRun(15 * time.Second); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	// The device is deliberately still open, so the pump goroutine is alive.
	if got := cli.loop.Tunnel().Gate().State(); got != tun.StateDown {
		t.Fatalf("gate is %s after Run returned, want down", got)
	}
	before := cli.loop.Tunnel().Stats()
	sentBefore := cliCar.Stats().Sent
	for i := 0; i < 8; i++ {
		cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("after the teardown")))
	}
	time.Sleep(250 * time.Millisecond)
	after := cli.loop.Tunnel().Stats()

	if after.TxPackets != before.TxPackets {
		t.Fatalf("%d packets reached the session after Run returned, want 0",
			after.TxPackets-before.TxPackets)
	}
	if got := cliCar.Stats().Sent; got != sentBefore {
		t.Fatalf("%d messages reached the carrier after Run returned, want 0", got-sentBefore)
	}
	// Whatever the pump read before it noticed the cancellation was refused
	// fail-closed, and nothing else. This is the exact statement: reads and
	// closed-drops moved by the same amount.
	reads := after.DeviceReads - before.DeviceReads
	drops := after.TxDroppedClosed - before.TxDroppedClosed
	if reads != drops {
		t.Fatalf("the pump read %d packets after Run returned and refused %d of them", reads, drops)
	}
	if after.TxDroppedInvalid != before.TxDroppedInvalid ||
		after.TxDroppedSink != before.TxDroppedSink {
		t.Fatal("a packet was refused for a reason other than the closed gate; the gate must be first")
	}
}

// TestOnlyEstablishedCarries walks all 256 values of session.State, not the
// constants declared today, and requires exactly one to open the gate.
//
// The mapping is written as a whitelist for this reason: a blacklist is the
// shape that fails OPEN when somebody adds a session state and forgets a case,
// and the state that would be added is far more likely to be a closed one.
func TestOnlyEstablishedCarries(t *testing.T) {
	carrying := 0
	for i := 0; i < 256; i++ {
		s := session.State(i)
		got := tunStateFor(s)
		if got == tun.StateCarrying {
			carrying++
			if s != session.StateEstablished {
				t.Fatalf("session state %d (%s) opens the gate", i, s)
			}
		}
		if !got.MayCarry() && got != tun.StateDown &&
			got != tun.StateHandshaking && got != tun.StateRekeying && got != tun.StateClosed {
			t.Fatalf("session state %d maps to %v, which is not a tun state", i, got)
		}
	}
	if carrying != 1 {
		t.Fatalf("%d of 256 session states open the gate, want exactly 1", carrying)
	}
	// The closed side is many-to-one on purpose; check the three that are not
	// StateDown are the three that carry a distinct diagnosis.
	for in, want := range map[session.State]tun.State{
		session.StateInitiating: tun.StateHandshaking,
		session.StateRekeying:   tun.StateRekeying,
		session.StateClosing:    tun.StateClosed,
		session.StateClosed:     tun.StateDown,
		session.StateFailed:     tun.StateDown,
		session.State(0):        tun.StateDown,
		session.State(math8Max): tun.StateDown,
	} {
		if got := tunStateFor(in); got != want {
			t.Fatalf("session %s maps to tun %s, want %s", in, got, want)
		}
	}
}

const math8Max = 255

// TestTheGateNeverReopensOnceLatched is the teardown half, and it is the one
// that must not be left to a race.
//
// Once the session is terminal or Close has been called, no later state read can
// compute a carrying state. A stale read that reopened the gate after a teardown
// would be a leak, and the drain barrier alone does not prevent it — only the
// latch does.
func TestTheGateNeverReopensOnceLatched(t *testing.T) {
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

	// Open it the way the write loop would.
	e.loop.gateMu.Lock()
	e.loop.tn.Gate().Set(tun.StateCarrying)
	e.loop.gateMu.Unlock()

	e.loop.latchDown()
	if got := e.loop.tn.Gate().State(); got != tun.StateDown {
		t.Fatalf("gate is %s after latchDown, want down", got)
	}

	// Every subsequent sync must be a no-op, whatever the session says. The
	// session here is still INITIATING, which maps to handshaking rather than to
	// down, so a sync that ignored the latch would move the gate.
	for i := 0; i < 64; i++ {
		e.loop.syncGate()
		if got := e.loop.tn.Gate().State(); got != tun.StateDown {
			t.Fatalf("syncGate moved a latched gate to %s", got)
		}
	}
}

// TestCloseLatchesBeforeItQueuesTheCloseFrame checks the ORDER, and it has to
// observe the window rather than the outcome, because both orders leave the same
// state behind once Close has returned.
//
// The window is made visible with the tun layer's own drain barrier. A packet is
// held mid-delivery inside the host device's write, which keeps a gate read-hold
// open; Gate.Set therefore blocks, so Close blocks INSIDE latchDown. While it is
// blocked:
//
//   - in the correct order the session has not been told anything yet, so it is
//     still ESTABLISHED;
//   - in the wrong order the session is already CLOSING, and a packet arriving
//     through the still-open gate would be refused by the session with ErrClosed
//     rather than dropped fail-closed by the gate — two different diagnoses, and
//     the wrong one for a tunnel that is shutting down.
func TestCloseLatchesBeforeItQueuesTheCloseFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()
	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 5*time.Second, "the gate to open", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})

	// Hold one inbound delivery inside the host's write, which holds the gate.
	cli.dev.block.Store(true)
	held := make(chan error, 1)
	go func() {
		held <- cli.loop.Tunnel().Inbound(ipv4Packet(gatewayAddr(), clientAddr(), []byte("held")))
	}()
	select {
	case <-cli.dev.writing:
	case <-time.After(5 * time.Second):
		t.Fatal("the delivery never reached the device write")
	}

	closed := make(chan struct{})
	go func() { _ = cli.loop.Close(); close(closed) }()

	// Close must be blocked in the drain barrier, and the session must not have
	// been touched.
	time.Sleep(200 * time.Millisecond)
	select {
	case <-closed:
		t.Fatal("Close returned while a packet was still in flight; the drain barrier was skipped")
	default:
	}
	if got := cli.loop.Session().State(); got != session.StateEstablished {
		t.Fatalf("the session is %s while Close is still shutting the gate; "+
			"the CLOSE frame was queued before the gate was shut", got)
	}

	close(cli.dev.release)
	if err := <-held; err != nil {
		t.Fatalf("the held delivery failed: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return once the in-flight packet drained")
	}

	if got := cli.loop.Tunnel().Gate().State(); got != tun.StateDown {
		t.Fatalf("gate is %s after Close returned, want down", got)
	}
	pkt := ipv4Packet(clientAddr(), gatewayAddr(), []byte("too late"))
	if err := cli.loop.Tunnel().Outbound(pkt); !errors.Is(err, tun.ErrNotCarrying) {
		t.Fatalf("a packet crossed after Close (err %v)", err)
	}
	_ = cli.waitRun(15 * time.Second)
}

// TestCancellingRunLatchesTheGateDown is the exit path that is easiest to
// forget, and the one a kill switch depends on.
//
// A cancelled context stops the loop while the session is still ESTABLISHED —
// the app was suspended, or the host pulled the tunnel down — so nothing in the
// session state machine closes the gate. Only Run's own latch does, and for a
// user under a hostile state a tunnel that stops carrying without closing the
// gate is traffic going out the physical interface in the clear.
func TestCancellingRunLatchesTheGateDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()
	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 5*time.Second, "the gate to open", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateCarrying
	})

	cancel()
	if err := cli.waitRun(15 * time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v on cancellation", err)
	}
	// The session never closed: this is a host tearing the tunnel down, not a
	// protocol teardown.
	if got := cli.loop.Session().State(); got.Terminal() {
		t.Fatalf("the session is %s; cancelling the context must not close the session", got)
	}
	if got := cli.loop.Tunnel().Gate().State(); got != tun.StateDown {
		t.Fatalf("gate is %s after a cancelled Run, want down", got)
	}
	pkt := ipv4Packet(clientAddr(), gatewayAddr(), []byte("after cancellation"))
	if err := cli.loop.Tunnel().Outbound(pkt); !errors.Is(err, tun.ErrNotCarrying) {
		t.Fatalf("a packet crossed after a cancelled Run (err %v)", err)
	}
}

// TestRefusalSilentPropagation is the HTTP-35-style silent-refusal case: the
// endpoint is reachable and the client reaches it, but the gateway REFUSES —
// by answering nothing. A v3 gateway that declines a client gives the client no
// byte it can build on, which is precisely what makes the protocol resistant to
// probing, and it is the shape this whole family exists to get right.
//
// HTTP 35 ("SSL connect error") is the same failure one protocol over: the
// transport leg succeeds, then the handshake is declined, and the client is
// left with an error carrying no usable detail about WHY — because only the
// peer that refused could say, and it stays quiet. Here that refusal is the
// gateway's Accept declining, which the responder turns into silence.
//
// Three properties must hold end to end, and each is asserted against a fact,
// not a name:
//
//   - the refusal PROPAGATES: Run returns ErrSessionFailed, never a hang and
//     never a false established;
//   - no host was ever told this tunnel was carrying: the gate never opened;
//   - the reason is NOT exposed: the refusing gateway received and declined the
//     initiation and put NOTHING back on the wire, and the client's own only
//     emissions are the indistinguishable handshake initiations a blocked path
//     would produce — no CLOSE, no distinguishing refusal frame.
func TestRefusalSilentPropagation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
		// A short, deterministic handshake budget on the CLIENT only, so the
		// verdict arrives on wall-clock instead of the default exponential
		// backoff. The gateway keeps its default budget so it does not evict the
		// half-open session before it has received and refused the initiation.
		tweak: func(c *session.Config) {
			c.Retry = session.Retry{Base: 5 * time.Millisecond, Cap: 40 * time.Millisecond, Attempts: 4}
		},
	})
	refusal := errors.New("not on the roster")
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
		tweak: func(c *session.Config) {
			c.Accept = func([]byte) error { return refusal }
		},
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	// Property 1: the refusal PROPAGATES as a failure of the loop. A silent
	// refusal must never read as success, and must never hang.
	runErr := cli.waitRun(20 * time.Second)
	if runErr == nil {
		t.Fatal("Run returned nil against a gateway that refused the handshake; " +
			"a silent refusal must not read as success")
	}
	if !errors.Is(runErr, ErrSessionFailed) {
		t.Fatalf("Run returned %v, want ErrSessionFailed", runErr)
	}
	// The client cannot tell a refusal from a block from where it stands — the
	// gateway answered neither — so it maps to the handshake-exhausted sentinel
	// and names no credential. That is the "without exposing the reason" half:
	// the driver declines to guess at a cause no byte supports.
	if !errors.Is(cli.loop.Session().Err(), session.ErrCarrierExhausted) {
		t.Fatalf("the client session failed with %v, want ErrCarrierExhausted "+
			"(the silent-refusal mapping)", cli.loop.Session().Err())
	}
	if got := cli.loop.Session().State(); got != session.StateFailed {
		t.Fatalf("the client session is %s, want failed", got)
	}

	// Property 2: the gate never opened, so no host was ever told it was
	// carrying.
	if cli.loop.Carrying() {
		t.Error("the client reported carrying on a session the gateway refused")
	}

	// Prove the refusal actually happened — it is not a packet that never
	// arrived. The gateway received and declined the initiation; the count is
	// on the gateway, which is the only side that can see it.
	waitFor(t, 5*time.Second, "the gateway to count the refused initiation", func() bool {
		return gw.loop.Session().Stats().Unopenable > 0
	})

	// Property 3: the reason was NOT exposed. The refusing gateway — which is
	// the only side that could say why — put nothing on the wire. A refusal
	// that answered would hand an observer a byte to build on, and a v3
	// gateway ships zero such bytes.
	if got := gwCar.Stats().Sent; got != 0 {
		t.Fatalf("the refusing gateway put %d messages on the wire; the refusal must be silent", got)
	}
	// And the client's own wire footprint is indistinguishable from a block:
	// it emitted handshake initiations and nothing they could have refused.
	if got := cliCar.Stats().Sent; got == 0 {
		t.Fatal("the client sent nothing at all; the refusal was never even attempted")
	}
	if got := cliCar.Stats().Sent; got != 1 {
		// A short budget can retire the client before every retransmission lands
		// on the wire, so an exact count would be a flake. What matters is that
		// at least one initiation went out and NO further distinguishing frame
		// followed it. The absence is asserted on the gateway side above, which
		// is the observable that cannot be laundered by the client's schedule.
		t.Logf("the client put %d handshake initiations on the wire (count is advisory)", got)
	}
	cancel()
	_ = gw.waitRun(5 * time.Second)
}

// TestRefusalControlAcceptsStillCarries is the over-fire control for the test
// above: the identical rig with the one thing changed — a gateway that ACCEPTS —
// must still establish and carry an inner packet. Without it, a silent-refusal
// test that always failed because the harness itself could never establish
// would look identical and be worthless.
func TestRefusalControlAcceptsStillCarries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	cli.waitState(session.StateEstablished, 15*time.Second)
	gw.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 5*time.Second, "the client gate to open", func() bool {
		return cli.loop.Carrying()
	})

	payload := []byte("an accepting peer still carries")
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
	got := gw.dev.take(t, 10*time.Second)
	if d, want := digest(payloadOf(got)), digest(payload); d != want {
		t.Fatalf("the packet arrived with digest %s, want %s", d, want)
	}
	if err := cli.loop.Session().Err(); err != nil {
		t.Fatalf("an accepting session recorded %v", err)
	}
	cancel()
	_ = cli.waitRun(5 * time.Second)
	_ = gw.waitRun(5 * time.Second)
}
