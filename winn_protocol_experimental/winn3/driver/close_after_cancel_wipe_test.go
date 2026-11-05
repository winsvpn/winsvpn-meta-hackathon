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

// TestCloseAfterCancelledRunWipesSessionKeys is the key-lifecycle half of
// TestCancellingRunLatchesTheGateDown.
//
// Cancelling Run leaves the session ESTABLISHED on purpose: the kill switch
// must latch the tun gate without waiting for a CLOSE to be sealed. Session.Wipe
// lives on that CLOSE's after-hook (Driver.terminate). If the host then calls
// Loop.Close after Run has already returned, nobody is Polling, so without
// drainQueuedClose the session stays StateClosing with traffic keys still in
// the Session fields until GC.
//
// Client-visible before the drain: silence until the peer's probe budget
// expires (CloseDesynchronised), indistinguishable from a censor. This test
// does not require the CLOSE to have been delivered — it requires the local
// session to become terminal, which is what terminate/Wipe is.
func TestCloseAfterCancelledRunWipesSessionKeys(t *testing.T) {
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
	if got := cli.loop.Session().State(); got.Terminal() {
		t.Fatalf("the session is %s; cancelling the context must not close the session", got)
	}

	if err := cli.loop.Close(); err != nil {
		t.Fatalf("Close after cancelled Run: %v", err)
	}
	waitFor(t, 2*time.Second, "the session to become terminal after Close", func() bool {
		return cli.loop.Session().State().Terminal()
	})
	if _, err := cli.loop.Session().Deliver([]byte("after-wipe")); !errors.Is(err, session.ErrClosed) {
		t.Fatalf("Deliver after Close returned %v, want ErrClosed (keys must no longer open)", err)
	}
}
