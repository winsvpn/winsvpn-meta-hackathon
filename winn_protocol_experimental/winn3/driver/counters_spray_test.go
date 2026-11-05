package driver

import (
	"context"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// TestASprayMovesUnopenableOnLoopStatsAndNotInnerDelivered is the worst
// realistic counter failure on the standalone v3 stack:
//
//	readLoop increments MessagesReceived for every carrier message whose
//	Deliver did not abort the loop. session.Driver.Deliver returns (nil, nil)
//	for an unopenable message — noise, a scan, a replay — and only
//	session.Stats.Unopenable names it. Until Loop.Stats copied Unopenable,
//	the published status documents (cmd/winn-datapath winn3Status,
//	cmd/winn3-gateway serveStatus) showed messages_received climbing on a
//	promoted tunnel while the diagnosis stayed local. Measured in
//	session.Driver.tickEstablished: a sprayed end absorbed 28,818 unopenable
//	messages, lost zero probes, and stayed established.
//
// From the client side that is indistinguishable from a healthy receiving
// tunnel. The far end then dies on probe budget (ErrPeerUnreachable).
//
// This test drives the REAL call path: Pipe.Deliver → readLoop →
// session.Deliver → Loop.Stats. It does not call Session().Deliver itself,
// because that would skip the seam counter the lie is made of.
func TestASprayMovesUnopenableOnLoopStatsAndNotInnerDelivered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	clk := newStepClock()

	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassUDP,
		PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, clock: clk,
		local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, clock: clk,
		local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)
	cli.waitState(session.StateEstablished, 15*time.Second)
	gw.waitState(session.StateEstablished, 15*time.Second)
	waitFor(t, 5*time.Second, "both gates carrying", func() bool {
		return cli.loop.Carrying() && gw.loop.Carrying()
	})

	// Prove the gateway device by reading one host packet from it. RxPackets is
	// intentionally withheld until the same device has produced traffic; merely
	// writing into a device is not proof that a host received the write.
	gw.dev.offer(t, ipv4Packet(gatewayAddr(), clientAddr(), []byte("device-proof")))
	_ = cli.dev.take(t, 10*time.Second)

	// One real inner packet so InnerDelivered and RxPackets are a known
	// baseline, and so PromotionReady would be true on a status document.
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), []byte("baseline")))
	_ = gw.dev.take(t, 10*time.Second)

	beforeSess := gw.loop.Session().Stats()
	beforeLoop := gw.loop.Stats()
	beforeTun := gw.loop.Tunnel().Stats()
	if beforeTun.RxPackets == 0 {
		t.Fatal("the baseline packet did not credit RxPackets; the spray would be scored against a tunnel that never carried")
	}
	if beforeLoop.Unopenable != beforeSess.Unopenable {
		t.Fatalf("Loop.Stats.Unopenable=%d session.Stats.Unopenable=%d before the spray; the copy already disagrees",
			beforeLoop.Unopenable, beforeSess.Unopenable)
	}

	const n = 8
	junk := make([]byte, session.MessageFloor())
	for i := range junk {
		junk[i] = 0xA5
	}
	for i := 0; i < n; i++ {
		if err := gwCar.Deliver(junk); err != nil {
			t.Fatalf("Pipe.Deliver(%d): %v", i, err)
		}
	}

	waitFor(t, 5*time.Second, "gateway Unopenable to move by the spray", func() bool {
		return gw.loop.Session().Stats().Unopenable >= beforeSess.Unopenable+n
	})

	afterSess := gw.loop.Session().Stats()
	afterLoop := gw.loop.Stats()
	afterTun := gw.loop.Tunnel().Stats()

	gotUnopenable := afterSess.Unopenable - beforeSess.Unopenable
	if gotUnopenable != n {
		t.Fatalf("session Unopenable delta=%d, want %d (before=%d after=%d)",
			gotUnopenable, n, beforeSess.Unopenable, afterSess.Unopenable)
	}
	if afterLoop.Unopenable != afterSess.Unopenable {
		t.Fatalf("Loop.Stats.Unopenable=%d, session.Stats.Unopenable=%d; the published snapshot does not carry the diagnosis",
			afterLoop.Unopenable, afterSess.Unopenable)
	}

	gotRecv := afterLoop.MessagesReceived - beforeLoop.MessagesReceived
	if gotRecv < n {
		t.Fatalf("Loop.MessagesReceived delta=%d, want at least %d: the seam must count the spray so messages_received climbs while Unopenable names it (received=%d→%d unopenable=%d→%d)",
			gotRecv, n, beforeLoop.MessagesReceived, afterLoop.MessagesReceived, beforeSess.Unopenable, afterSess.Unopenable)
	}

	if afterLoop.InnerDelivered != beforeLoop.InnerDelivered {
		t.Fatalf("InnerDelivered moved %d→%d on a spray that carried no inner packet",
			beforeLoop.InnerDelivered, afterLoop.InnerDelivered)
	}
	if afterTun.RxPackets != beforeTun.RxPackets {
		t.Fatalf("RxPackets moved %d→%d on a spray; noise was counted as a delivery",
			beforeTun.RxPackets, afterTun.RxPackets)
	}
	if afterTun.RxOffered != beforeTun.RxOffered {
		t.Fatalf("RxOffered moved %d→%d on a spray; unopenable messages must not reach tun.Inbound",
			beforeTun.RxOffered, afterTun.RxOffered)
	}

	if gw.loop.Session().State() != session.StateEstablished {
		t.Fatalf("gateway state is %s after the spray; teardown on unopenable is the off-path kill switch",
			gw.loop.Session().State())
	}
	if !gw.loop.Carrying() {
		t.Fatal("the gate closed on a spray; the session stayed established so the gate must stay carrying")
	}

	t.Logf("MEASURED spray n=%d session.Unopenable %d→%d loop.Unopenable=%d messages_received %d→%d inner_delivered %d rx_packets %d state=%s carrying=%v",
		n, beforeSess.Unopenable, afterSess.Unopenable, afterLoop.Unopenable,
		beforeLoop.MessagesReceived, afterLoop.MessagesReceived,
		afterLoop.InnerDelivered, afterTun.RxPackets,
		gw.loop.Session().State(), gw.loop.Carrying())
}
