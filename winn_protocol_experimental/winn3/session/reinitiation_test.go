package session

import (
	"bytes"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// runResponder sends everything Driver a wants to say to Driver b and back,
// until nothing moves, up to a bound. A local, synchronous link pump: no sockets
// and no goroutines, so a handshake can be driven exactly.
func runResponder(t *testing.T, a, b *Driver) {
	t.Helper()
	for i := 0; i < 64; i++ {
		aMoved := 0
		for {
			msg, err := a.Poll()
			if err != nil {
				return
			}
			if msg == nil {
				break
			}
			_, _ = b.Deliver(msg)
			aMoved++
		}
		bMoved := 0
		for {
			msg, err := b.Poll()
			if err != nil {
				return
			}
			if msg == nil {
				break
			}
			_, _ = a.Deliver(msg)
			bMoved++
		}
		if aMoved == 0 && bMoved == 0 {
			return
		}
	}
	t.Fatal("the handshake link did not quiesce")
}

// TestResponderAdmitsAFreshReinitiationAndSupersedesTheDeadSession pins the
// responder half of the reconnect contract: a client whose carrier socket dies
// mid-session re-initialises on its next reconnect round (same static keys, a
// fresh ephemeral) and sends a brand-new initiation to the SAME responder that
// still holds the dead session. The responder must admit the fresh handshake
// and supersede the old session, or the reconnecting client is permanently
// refused — on a censored network, indistinguishable from a censor.
//
// The teeth: before the fix, an established responder treated the fresh
// initiation as an unopenable message (it does not share keying material with
// the old session), counted it, and returned silence — so the second client
// never established. This test requires the SAME responder to complete a fresh
// handshake with a second client after it has already established with a first.
func TestResponderAdmitsAFreshReinitiationAndSupersedesTheDeadSession(t *testing.T) {
	clk := newClock()

	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	gp := gatewayParams(t)

	gwCfg := Config{
		Core:    core.Config{Gateway: gp},
		Static:  gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
	}
	cliCfg := Config{
		Core:          core.Config{Gateway: gp},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
	}

	gw, err := NewGateway(gwCfg)
	if err != nil {
		t.Fatal(err)
	}
	cli1, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}

	// Round 1: client 1 establishes against the gateway.
	runResponder(t, cli1, gw)
	if got := cli1.State(); got != StateEstablished {
		t.Fatalf("round 1 client state is %s, want established (err %v)", got, cli1.Err())
	}
	if got := gw.State(); got != StateEstablished {
		t.Fatalf("gateway state is %s after round 1, want established (err %v)", got, gw.Err())
	}

	// Round 2: the same client identity re-initialises with a fresh ephemeral,
	// exactly as a reconnect supervisor does after its carrier socket is killed.
	// The same gw driver still holds round 1's established session.
	cli2, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	runResponder(t, cli2, gw)

	if got := cli2.State(); got != StateEstablished {
		t.Fatalf("round 2 client state is %s, want established (err %v)", got, cli2.Err())
	}
	if got := gw.State(); got != StateEstablished {
		t.Fatalf("gateway state after reinitiation is %s, want established (err %v)", got, gw.Err())
	}
}

func TestResponderRejectsReinitiationFromDifferentPeerIdentity(t *testing.T) {
	clk := newClock()

	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cli1Static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	attackerStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	gp := gatewayParams(t)

	gwCfg := Config{
		Core:    core.Config{Gateway: gp},
		Static:  gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
	}
	cli1Cfg := Config{
		Core:          core.Config{Gateway: gp},
		Static:        cli1Static,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
	}
	attackerCfg := Config{
		Core:          core.Config{Gateway: gp},
		Static:        attackerStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
	}

	gw, err := NewGateway(gwCfg)
	if err != nil {
		t.Fatal(err)
	}
	cli1, err := NewClient(cli1Cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Client 1 establishes against the gateway.
	runResponder(t, cli1, gw)
	if got := cli1.State(); got != StateEstablished {
		t.Fatalf("client 1 state is %s, want established (err %v)", got, cli1.Err())
	}
	if got := gw.State(); got != StateEstablished {
		t.Fatalf("gateway state is %s, want established (err %v)", got, gw.Err())
	}

	// An attacker with a distinct valid static key attempts to re-initiate against the same gateway driver.
	attacker, err := NewClient(attackerCfg)
	if err != nil {
		t.Fatal(err)
	}
	attackerInitMsg, err := attacker.Poll()
	if err != nil || attackerInitMsg == nil {
		t.Fatalf("attacker Poll: msg=%v err=%v", attackerInitMsg, err)
	}

	// Deliver attacker's initiation to gw.
	_, err = gw.Deliver(attackerInitMsg)
	if err != nil {
		t.Fatalf("gw.Deliver unexpected err: %v", err)
	}

	// Gateway must remain established with client 1, and peer static must not be replaced.
	if got := gw.State(); got != StateEstablished {
		t.Fatalf("gateway state after spoofed initiation is %s, want established", got)
	}
	if !bytes.Equal(gw.PeerStatic(), cli1Static.Public()) {
		t.Fatalf("gateway PeerStatic was replaced: got %x, want %x", gw.PeerStatic(), cli1Static.Public())
	}

	// Gateway should emit no response to the attacker.
	gwResp, err := gw.Poll()
	if err != nil {
		t.Fatalf("gw.Poll unexpected err: %v", err)
	}
	if gwResp != nil {
		t.Fatalf("gateway emitted handshake response to spoofed peer: %v", gwResp)
	}
}
