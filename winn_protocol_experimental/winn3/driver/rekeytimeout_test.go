package driver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// vanishSend is a carrier whose Send can be made to succeed without delivering.
//
// That is what a censor dropping a live 5-tuple looks like from this end: every
// write returns nil, nothing arrives. A Close or a send error would be a
// different failure (carrier dead), and this test is about the session timer,
// not the carrier.
type vanishSend struct {
	carrier.Conn
	vanish *atomic.Bool
}

func (v *vanishSend) Send(ctx context.Context, msg []byte) error {
	if v.vanish.Load() {
		return nil
	}
	return v.Conn.Send(ctx, msg)
}

// TestRekeyTimeoutClosesTheGateThenFailsTheLoop is the session-layer
// TestRekeyTimeoutTearsTheSessionDown driven through the real Loop and tun
// gate, which is the path a client actually observes.
//
// An established tunnel starts an in-band rekey. The REKEY_INIT is dropped
// (writes still succeed). For Config.RekeyTimeout:
//
//   - the session is StateRekeying
//   - tunStateFor maps that to tun.StateRekeying, so Gate.MayCarry is false
//     and Loop.Carrying is false — inner packets stop while the session is
//     not yet Failed
//   - when the clock crosses rekeyEnd, tick calls beginClose(CloseRekeyFailed,
//     ErrRekeyFailed)
//   - Loop.Run returns ErrSessionFailed wrapping that cause
//   - NeedsCarrierChange stays false, so a Reconnect supervisor retries the
//     same class
//
// The session-layer test already covers Driver.Err and LocalCloseReason. This
// one covers the gate and the Run error, which that test never touches.
func TestRekeyTimeoutClosesTheGateThenFailsTheLoop(t *testing.T) {
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
	drop := new(atomic.Bool)
	cliCar := &vanishSend{Conn: cliPipe, vanish: drop}
	gwCar := &vanishSend{Conn: gwPipe, vanish: drop}

	const rekeyWait = 2 * time.Second
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, clock: clk,
		local: clientAddr(), router: gatewayAddr(),
		tweak: func(c *session.Config) {
			c.RekeyTimeout = rekeyWait
			// Fire the time trigger on the first Advance past 200ms, well
			// below Silence.Min / Probe.Min so those timers are not the thing
			// that wakes the loop.
			c.RekeyInterval = session.Draw{
				Min: 50 * time.Millisecond, Mean: 100 * time.Millisecond, Max: 200 * time.Millisecond,
			}
		},
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, clock: clk,
		local: gatewayAddr(), router: clientAddr(),
		tweak: func(c *session.Config) {
			// Keep the gateway from starting its own rekey on the same Advance.
			c.RekeyInterval = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
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

	drop.Store(true)
	clk.Advance(time.Second)
	// Advancing a duration-based fake clock can race with waitForWork between
	// computing the duration and registering its timer. Wake the loop as well
	// so it must re-read the now-past absolute session deadline.
	cli.loop.signalWake()

	cli.waitState(session.StateRekeying, 5*time.Second)
	if cli.loop.Carrying() {
		t.Fatal("Loop.Carrying is true during StateRekeying; inner packets would still be admitted while the rekey cannot complete")
	}
	if st := cli.loop.Tunnel().Gate().State(); st.MayCarry() {
		t.Fatalf("tun gate is %s during rekey; MayCarry must be false", st)
	}

	// Exercise the adapter directly, bypassing the already-closed tun gate, so
	// session.ErrState cannot leak through as a different public refusal.
	woke := 0
	sink := frameSink{sess: cli.loop.Session(), wake: func() { woke++ }}
	err = sink.SendData(ipv4Packet(clientAddr(), gatewayAddr(), []byte("direct-adapter-refusal")))
	if err != tun.ErrNotCarrying {
		t.Fatalf("frameSink.SendData during rekey returned %v, want tun.ErrNotCarrying", err)
	}
	if woke != 0 {
		t.Fatalf("frameSink woke the writer after a refused packet; woke=%d", woke)
	}

	// An inner packet offered now must not reach the peer. The gate is the
	// fail-closed authority; a timeout test that never checks it would pass
	// with the gate left open.
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("must-not-cross-during-rekey")))
	select {
	case p := <-gw.dev.out:
		t.Fatalf("an inner packet reached the gateway during rekey (%d bytes); the gate did not hold", len(p))
	case <-time.After(time.Second):
	}

	clk.Advance(rekeyWait)
	cli.loop.signalWake()

	runErr := cli.waitRun(10 * time.Second)
	if !errors.Is(runErr, ErrSessionFailed) {
		t.Fatalf("Run returned %v, want ErrSessionFailed", runErr)
	}
	if !errors.Is(runErr, session.ErrRekeyFailed) {
		t.Fatalf("Run returned %v, which does not unwrap to ErrRekeyFailed; "+
			"a host that only inspects Run's error cannot tell a rekey timeout from a handshake failure. "+
			"Session().Err() is %v", runErr, cli.loop.Session().Err())
	}
	if err := cli.loop.Session().Err(); !errors.Is(err, session.ErrRekeyFailed) {
		t.Fatalf("Session().Err() is %v, want ErrRekeyFailed", err)
	}
	if got := cli.loop.Session().LocalCloseReason(); got != session.CloseRekeyFailed {
		t.Fatalf("LocalCloseReason is %s, want %s", got, session.CloseRekeyFailed)
	}
	if !cli.loop.Session().NeedsNewSession() {
		t.Fatal("a failed rekey did not ask for a new session")
	}
	if cli.loop.Session().NeedsCarrierChange() {
		t.Fatal("a rekey timeout set NeedsCarrierChange; that flag is the handshake-budget signal, and a Reconnect supervisor that honours it would change class for a timer that is not about the carrier")
	}
}

// TestDroppedRekeyAckFailsBothEndsLoudlyWithoutFalseCarrying is the
// session-layer TestDroppedRekeyAckAdvancesOnlyTheResponderThenInitiatorTimesOut
// driven through the real Loop and tun gate.
//
// TestRekeyTimeoutClosesTheGateThenFailsTheLoop vanishes BOTH directions, so
// REKEY_INIT never arrives, the gateway never ratchets, and a CLOSE sealed
// under the old epoch would be openable if it were delivered. This vanishes
// only the gateway's Send: REKEY_INIT arrives, onRekeyInit queues
// completeRekey as the assemble hook (it runs inside Poll before Send), the
// gateway is Established at epoch N+1, REKEY_ACK is dropped, and the CLOSE
// the client then emits is sealed under epoch N so the gateway cannot open it.
//
// tick in StateRekeying watches only rekeyEnd. There is no retransmission of
// either rekey frame. DefaultRekeyTimeout is 15s; DefaultRekeyInterval is a
// 5–45 minute draw. A single lost ACK on a lossy mobile path therefore:
//
//   - fails the client: Run returns ErrSessionFailed wrapping ErrRekeyFailed,
//     NeedsCarrierChange stays false, the tun gate is down
//   - keeps the ACK-sending gateway's data plane held until confirmation, then
//     fails it loudly with ErrRekeyUnconfirmed when the ACK never lands
//
// cmd/winn3-gateway indexes server.peers by netip.AddrPort, so a reconnect
// from the same 5-tuple is Delivered into this still-live session until the
// gateway's own probe budget (DefaultMaxLostProbes × DefaultProbeMax = 80s)
// fires. The new handshake is unopenable. The client sees silence.
func TestDroppedRekeyAckFailsBothEndsLoudlyWithoutFalseCarrying(t *testing.T) {
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
	dropAck := new(atomic.Bool)
	cliCar := cliPipe
	gwCar := &vanishSend{Conn: gwPipe, vanish: dropAck}

	const rekeyWait = 2 * time.Second
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, clock: clk,
		local: clientAddr(), router: gatewayAddr(),
		tweak: func(c *session.Config) {
			c.RekeyTimeout = rekeyWait
			c.RekeyInterval = session.Draw{
				Min: 50 * time.Millisecond, Mean: 100 * time.Millisecond, Max: 200 * time.Millisecond,
			}
		},
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, clock: clk,
		local: gatewayAddr(), router: clientAddr(),
		tweak: func(c *session.Config) {
			c.RekeyTimeout = rekeyWait
			c.RekeyInterval = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.Probe = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.Silence = session.Draw{
				Min: time.Hour, Mean: 2 * time.Hour, Max: 3 * time.Hour,
			}
			c.MaxLostProbes = 1 << 20
		},
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	cli.waitState(session.StateEstablished, 15*time.Second)
	gw.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 5*time.Second, "both gates to carry", func() bool {
		return cli.loop.Carrying() && gw.loop.Carrying()
	})

	cliEpoch := cli.loop.Session().Epoch()
	gwEpoch := gw.loop.Session().Epoch()
	if cliEpoch != gwEpoch {
		t.Fatalf("precondition: epochs already diverged: client %d gateway %d", cliEpoch, gwEpoch)
	}
	dropAck.Store(true)
	clk.Advance(time.Second)
	cli.loop.signalWake()

	cli.waitState(session.StateRekeying, 5*time.Second)
	waitFor(t, 5*time.Second, "the gateway to install the ratchet after a vanished ACK", func() bool {
		return gw.loop.Session().State() == session.StateEstablished &&
			gw.loop.Session().Epoch() == gwEpoch+1
	})
	if got := cli.loop.Session().Epoch(); got != cliEpoch {
		t.Fatalf("client epoch is %d, want still %d (ACK never arrived)", got, cliEpoch)
	}
	if cli.loop.Carrying() {
		t.Fatal("Loop.Carrying is true on the client during StateRekeying")
	}
	if gw.loop.Carrying() {
		t.Fatal("the gateway gate opened after an unconfirmed ACK; it would advertise a black-holed path")
	}
	if st := gw.loop.Tunnel().Gate().State(); st != tun.StateRekeying {
		t.Fatalf("gateway tun gate is %s after an unconfirmed ACK, want rekeying", st)
	}

	clk.Advance(rekeyWait)
	cli.loop.signalWake()
	gw.loop.signalWake()

	runErr := cli.waitRun(10 * time.Second)
	if !errors.Is(runErr, ErrSessionFailed) {
		t.Fatalf("Run returned %v, want ErrSessionFailed", runErr)
	}
	if !errors.Is(runErr, session.ErrRekeyFailed) {
		t.Fatalf("Run returned %v, which does not unwrap to ErrRekeyFailed; Session().Err() is %v",
			runErr, cli.loop.Session().Err())
	}
	if !cli.loop.Session().NeedsNewSession() {
		t.Fatal("a failed rekey did not ask for a new session")
	}
	if cli.loop.Session().NeedsCarrierChange() {
		t.Fatal("a lost REKEY_ACK is not a dead carrier; NeedsCarrierChange must stay false")
	}

	gwRunErr := gw.waitRun(10 * time.Second)
	if !errors.Is(gwRunErr, ErrSessionFailed) || !errors.Is(gwRunErr, session.ErrRekeyUnconfirmed) {
		t.Fatalf("gateway Run returned %v, want ErrSessionFailed wrapping ErrRekeyUnconfirmed", gwRunErr)
	}
	if gw.loop.Carrying() {
		t.Fatal("gateway Loop.Carrying is true after its unconfirmed-rekey close")
	}
	if st := gw.loop.Tunnel().Gate().State(); st.MayCarry() {
		t.Fatalf("gateway tun gate is %s after close; MayCarry must be false", st)
	}
	if got := gw.loop.Session().PeerCloseReason(); got != 0 {
		t.Fatalf("gateway opened a CLOSE reason %s; the CLOSE is under the old epoch and must be unopenable", got)
	}
	if cli.loop.Carrying() {
		t.Fatal("client Loop.Carrying is still true after Run returned")
	}
}
