package driver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// dropOnce vanishes exactly one Send after it is armed, then delivers.
//
// That is a single lost datagram on a live 5-tuple: the write still returns
// nil. A Close or a send error would be a different failure (carrier dead).
type dropOnce struct {
	carrier.Conn
	armed   atomic.Bool
	dropped atomic.Bool
}

func (d *dropOnce) Send(ctx context.Context, msg []byte) error {
	if d.armed.Load() && d.dropped.CompareAndSwap(false, true) {
		return nil
	}
	return d.Conn.Send(ctx, msg)
}

// TestDroppedRekeyAckFromGatewayClosesTheClientGateLoudlyInsteadOfCarrying is
// the session-layer
// TestDroppedRekeyAckWhenGatewayInitiatesClosesTheClientWithRekeyUnconfirmed
// driven through the real Loop and tun gate, which is the path a client host
// actually observes (Loop.Carrying, Gate.MayCarry, inner packets).
//
// The gateway's jittered rekey timer fires. The client is the rekey responder:
// it seals FrameRekeyAck, completeRekey runs inside Poll, and the ACK is then
// vanished. The control state returns to Established, but DataPlaneState keeps
// the tun gate in StateRekeying until a new-epoch message confirms convergence.
// For the RekeyTimeout window the client refuses packets while confirmation is
// pending. If nothing the gateway sealed under the new epoch arrives before
// rekeyConfirmAt, F-03 closes the
// client LOUDLY: Run returns ErrSessionFailed wrapping
// ErrRekeyUnconfirmed, LocalCloseReason is CloseRekeyUnconfirmed, the tun
// gate drops and Loop.Carrying goes false, so the app layer tears down and
// reconnects instead of carrying a tunnel that delivers nothing.
func TestDroppedRekeyAckFromGatewayClosesTheClientGateLoudlyInsteadOfCarrying(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	clk := newStepClock()

	cliPipe, gwPipe, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassUDP,
		PathMTU: carrier.DefaultPathMTU,
		Clock:   clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	cliCar := &dropOnce{Conn: cliPipe}

	const rekeyWait = 2 * time.Second
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, clock: clk,
		local: clientAddr(), router: gatewayAddr(),
		tweak: func(c *session.Config) {
			c.RekeyTimeout = rekeyWait
			c.RekeyInterval = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.Silence = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.Probe = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.RekeyAfterMessages = core.RejectAfterMessages
			c.RekeyAfterBytes = 1 << 60
		},
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwPipe, clock: clk,
		local: gatewayAddr(), router: clientAddr(),
		tweak: func(c *session.Config) {
			c.RekeyTimeout = rekeyWait
			c.RekeyInterval = session.Draw{
				Min: 50 * time.Millisecond, Mean: 100 * time.Millisecond, Max: 200 * time.Millisecond,
			}
			c.Silence = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.Probe = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.RekeyAfterMessages = core.RejectAfterMessages
			c.RekeyAfterBytes = 1 << 60
		},
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

	unopenableBefore := gw.loop.Session().Stats().Unopenable
	closedBefore := cli.loop.Tunnel().Stats().TxDroppedClosed

	cliCar.armed.Store(true)
	clk.Advance(time.Second)

	waitFor(t, 5*time.Second, "the client to complete the rekey as responder", func() bool {
		return cli.loop.Session().Stats().Rekeys >= 1 &&
			cli.loop.Session().State() == session.StateEstablished
	})
	waitFor(t, 5*time.Second, "the client gate to reflect the unconfirmed rekey", func() bool {
		return cli.loop.Tunnel().Gate().State() == tun.StateRekeying
	})
	if cli.loop.Carrying() {
		t.Fatal("Loop.Carrying is true after an unconfirmed REKEY_ACK; the host would advertise a black-holed path")
	}
	if st := cli.loop.Tunnel().Gate().State(); st.MayCarry() {
		t.Fatalf("tun gate is %s after an unconfirmed REKEY_ACK; MayCarry must stay false", st)
	}
	if gw.loop.Session().State() != session.StateRekeying {
		t.Fatalf("gateway state is %s, want rekeying (ACK vanished)", gw.loop.Session().State())
	}
	if cli.loop.Session().Err() != nil {
		t.Fatalf("client Session().Err() is %v inside the confirmation bound; the fail-loud verdict must wait for rekeyConfirmAt", cli.loop.Session().Err())
	}

	// Inside the bound the gate refuses host DATA rather than knowingly sending
	// it into the divergent epoch.
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("must-blackhole-after-lost-ack")))
	select {
	case p := <-gw.dev.out:
		t.Fatalf("an inner packet reached the gateway after a lost REKEY_ACK (%d bytes); the new epoch is unopenable there", len(p))
	case <-time.After(time.Second):
	}
	if got := gw.loop.Session().Stats().Unopenable; got != unopenableBefore {
		t.Fatalf("gateway Unopenable moved %d → %d; closed-gate DATA must not reach the carrier", unopenableBefore, got)
	}
	waitFor(t, 3*time.Second, "the closed client gate to count the refused packet", func() bool {
		return cli.loop.Tunnel().Stats().TxDroppedClosed > closedBefore
	})
	if got := cli.loop.Tunnel().Stats().TxDroppedClosed; got != closedBefore+1 {
		t.Fatalf("client TxDroppedClosed moved %d → %d, want exactly one fail-closed refusal", closedBefore, got)
	}

	// Cross the bound. The gateway fails at its own rekeyEnd with
	// CloseRekeyFailed; the client, which committed without the peer's
	// confirmation, must now fail LOUDLY with CloseRekeyUnconfirmed and stop
	// carrying — the F-03 close that replaces the old quiet carry.
	clk.Advance(rekeyWait)

	runErr := cli.waitRun(10 * time.Second)
	if !errors.Is(runErr, ErrSessionFailed) {
		t.Fatalf("Run returned %v, want ErrSessionFailed", runErr)
	}
	if !errors.Is(runErr, session.ErrRekeyUnconfirmed) {
		t.Fatalf("Run returned %v, which does not unwrap to ErrRekeyUnconfirmed; Session().Err() is %v",
			runErr, cli.loop.Session().Err())
	}
	if err := cli.loop.Session().Err(); !errors.Is(err, session.ErrRekeyUnconfirmed) {
		t.Fatalf("Session().Err() is %v, want ErrRekeyUnconfirmed", err)
	}
	if got := cli.loop.Session().LocalCloseReason(); got != session.CloseRekeyUnconfirmed {
		t.Fatalf("LocalCloseReason is %s, want %s", got, session.CloseRekeyUnconfirmed)
	}
	if !cli.loop.Session().NeedsNewSession() {
		t.Fatal("an unconfirmed rekey commit did not ask the client for a new session")
	}
	if cli.loop.Session().NeedsCarrierChange() {
		t.Fatal("a lost REKEY_ACK is not a dead carrier; NeedsCarrierChange must stay false")
	}
	if cli.loop.Carrying() {
		t.Fatal("Loop.Carrying is still true after the F-03 close; the app layer would keep carrying a tunnel that delivers nothing")
	}
	if st := cli.loop.Tunnel().Gate().State(); st.MayCarry() {
		t.Fatalf("tun gate is %s after the F-03 close; MayCarry must be false", st)
	}

	gw.waitState(session.StateFailed, 5*time.Second)
	if got := gw.loop.Session().LocalCloseReason(); got != session.CloseRekeyFailed {
		t.Fatalf("gateway LocalCloseReason is %s, want %s (responder-side verdict unchanged)",
			got, session.CloseRekeyFailed)
	}
}
