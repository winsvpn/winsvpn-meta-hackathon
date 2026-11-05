package driver

import (
	"context"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// TestTheMeasuredBlockRaisesTheCarrierSignalRatherThanRetryingForever is the
// defect this whole layer exists to answer, driven through the real loop.
//
// The measured failure is 24 handshake initiations leaving, none answered, 100 %
// loss, and a datapath that sat in that state indefinitely and reported nothing
// an orchestrator could act on. The shape is reproduced exactly — a carrier
// whose Send always succeeds and whose Recv never returns anything, which is
// what a wholesale UDP drop looks like from userspace — and what must happen is
// that the loop STOPS and raises §4.2's normative signal.
//
// Note what is asserted and what is not. The loop does not pick a successor and
// does not dial one: that is datapath/escalation.go's and failover.go's, and
// duplicating it here would give the fleet two opinions.
func TestTheMeasuredBlockRaisesTheCarrierSignalRatherThanRetryingForever(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)

	// Out is nil: every Send succeeds and nothing is ever delivered.
	blocked, err := carrier.NewPipe(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: blocked, local: clientAddr(), router: gatewayAddr(),
		tweak: func(c *session.Config) {
			c.Retry = session.Retry{
				Base: time.Millisecond, Cap: 2 * time.Millisecond, Attempts: 4,
			}
		},
	})
	defer cli.stop()
	cli.start(ctx)

	err = cli.waitRun(20 * time.Second)
	if err == nil {
		t.Fatal("Run returned nil on a carrier that never delivered anything")
	}

	sig := cli.loop.Observe()
	if !sig.NeedsChange {
		t.Fatal("the session did not raise NeedsCarrierChange after spending its budget; " +
			"this is the 24-retry failure")
	}
	if sig.Class != carrier.ClassUDP {
		t.Fatalf("the signal names class %s, want udp", sig.Class)
	}
	if sig.Stats.Sent == 0 {
		t.Fatal("no message was ever sent; the reproduction is not the measured shape")
	}
	if sig.Stats.Delivered != 0 {
		t.Fatalf("%d messages were delivered on a carrier with no sink", sig.Stats.Delivered)
	}
	if !sig.State.Terminal() {
		t.Fatalf("session is %s; a spent budget must stop rather than retry", sig.State)
	}
	// The loop stopped. That is the whole point: the retry schedule does not
	// abandon a dead transport by itself, and a schedule that never abandons one
	// is a beacon with a recognisable cadence.
	if got := cli.loop.Stats().MessagesSent; got > 8 {
		t.Fatalf("the loop sent %d messages into a black hole; the budget is 4 attempts", got)
	}
	t.Logf("blocked carrier: %d sent, %d delivered, state %s", sig.Stats.Sent, sig.Stats.Delivered, sig.State)
}

// TestObserveCarriesTheCarriersOwnFailureSeparately checks that a dead carrier
// and a session that wants a different carrier stay distinguishable. The policy
// layer treats them differently, and a loop that merged them would make a socket
// error look like censorship.
func TestObserveCarriesTheCarriersOwnFailureSeparately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)

	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	fresh := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: pipe, local: clientAddr(), router: gatewayAddr(),
	})
	defer fresh.stop()
	sig := fresh.loop.Observe()
	if sig.NeedsChange || sig.NeedsNewSession {
		t.Fatal("a fresh session already wants a different carrier")
	}
	if sig.State != session.StateInitiating {
		t.Fatalf("state is %s, want initiating", sig.State)
	}
	if fresh.loop.CarrierErr() != nil || sig.CarrierErr != nil {
		t.Fatalf("a fresh loop reports a carrier error: CarrierErr=%v Observe=%v",
			fresh.loop.CarrierErr(), sig.CarrierErr)
	}

	// Dead Pipe: the loop records carErr; Pipe has no fatal(), so Observe
	// only sees it if the loop overlays carErr onto the signal.
	f := newFaulty(t, carrier.ClassUDP)
	f.failRecv(carrier.ErrStreamDesync)
	e := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: f, noTun: true})
	e.start(ctx)
	waitFor(t, 10*time.Second, "the loop to notice the dead carrier", func() bool {
		return e.loop.CarrierErr() != nil
	})
	dead := e.loop.Observe()
	if !errors.Is(dead.CarrierErr, carrier.ErrStreamDesync) {
		t.Fatalf("Observe().CarrierErr is %v, want ErrStreamDesync", dead.CarrierErr)
	}
	if dead.NeedsChange {
		t.Fatal("a dead carrier was reported as the session's carrier-change signal")
	}
	if e.loop.Session().State().Terminal() {
		t.Fatalf("the session is %s because its carrier died; they must stay distinguishable",
			e.loop.Session().State())
	}
	cancel()
	_ = e.waitRun(10 * time.Second)
}

// TestMigrationResetsTheCarrierBudget checks the input the escalation policy
// reasons over. Elapsed time is measured from when the CARRIER was installed,
// not from when the session started: a freshly dialled carrier that has not had
// its budget yet must not inherit its predecessor's verdict.
func TestMigrationResetsTheCarrierBudget(t *testing.T) {
	sz := planSizing(t)
	kr := newKeyring(t)
	udp, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	tls, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassTLS})
	if err != nil {
		t.Fatal(err)
	}
	clk := newStepClock()
	e := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: udp, clock: clk, local: clientAddr(), router: gatewayAddr(),
	})
	defer e.stop()

	first := e.loop.CarrierOpenedAt()
	clk.Advance(90 * time.Second)
	if _, err := e.loop.Migrate(tls); err != nil {
		t.Fatal(err)
	}
	second := e.loop.CarrierOpenedAt()
	if !second.After(first) {
		t.Fatal("the carrier budget was not reset by a migration")
	}
	if got := second.Sub(first); got != 90*time.Second {
		t.Fatalf("the new carrier's clock reads %s after the old one, want 90s", got)
	}
	if e.loop.CarrierErr() != nil {
		t.Fatal("a migration carried the old carrier's error across")
	}
	if got := e.loop.Carrier().Class(); got != carrier.ClassTLS {
		t.Fatalf("the carrier is %s after migrating to tls", got)
	}
}
