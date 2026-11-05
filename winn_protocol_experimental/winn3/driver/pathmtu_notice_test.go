package driver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Silent-refusal instance #3: the path MTU the two ends planned at.
//
// These tests live in package driver rather than in package session because
// this is where the number is WIRED — Sizing.PathMTU is the input the plan
// floor was derived from, and newLoop is the single site that hands it to the
// session. A test in session could only check that a field it was handed comes
// back out again.
//
// The order below is the order the proof has to be read in:
//
//  1. an old peer that sends no payload still connects — the compatibility
//     floor, and if this one is red nothing else matters;
//  2. an agreeing pair still establishes and still carries a packet, at every
//     path MTU an operator might reasonably choose — the over-fire control,
//     because a refusal that fires on a legitimate configuration is a worse
//     outage than the defect it closes;
//  3. only then, that a genuine mismatch is refused, loudly, naming both
//     values and both ends.

// pathMTUFixtureConfigs builds a client and a gateway session configuration by
// hand, so that a test can leave Config.PathMTU ZERO on either side and model a
// peer built before this check existed. Going through newLoop cannot express
// that: newLoop always sets the field, which is the point of it.
func pathMTUFixtureConfigs(kr *keyring, cliMTU, gwMTU int) (cli, gw session.Config) {
	sizeFor := func(mtu int) int {
		if mtu == 0 {
			// The peer that makes no claim is also the peer that predates
			// Sizing being threaded down here; give it the package default,
			// which is what such a caller would have had.
			return session.DefaultMaxMessageSize
		}
		return session.MaxMessageSizeForPath(mtu, session.CarrierOverheadUDPIPv6)
	}
	cli = session.Config{
		Core:           core.Config{Gateway: kr.params},
		Static:         kr.cliStatic,
		GatewayStatic:  kr.gwPublic,
		Padding:        core.PadBucket,
		PathMTU:        cliMTU,
		MaxMessageSize: sizeFor(cliMTU),
	}
	gw = session.Config{
		Core:           core.Config{Gateway: kr.params},
		Static:         kr.gwStatic,
		Accept:         func([]byte) error { return nil },
		Padding:        core.PadBucket,
		PathMTU:        gwMTU,
		MaxMessageSize: sizeFor(gwMTU),
	}
	return cli, gw
}

// pumpSessions drives two drivers against each other by hand until both are
// established or one of them refuses, and returns the CLIENT's refusal.
//
// It returns the error rather than failing, because "the client refused" is the
// assertion in one test here and the thing that must not happen in two others.
// A gateway-side error is always a test fault and does fail.
func pumpSessions(t *testing.T, cli, gw *session.Driver) error {
	t.Helper()
	for round := 0; round < 64; round++ {
		moved := false
		for {
			msg, err := cli.Poll()
			if err != nil {
				return err
			}
			if msg == nil {
				break
			}
			moved = true
			if _, err := gw.Deliver(msg); err != nil {
				t.Fatalf("round %d: the gateway refused a client message: %v", round, err)
			}
		}
		for {
			msg, err := gw.Poll()
			if err != nil {
				t.Fatalf("round %d: the gateway could not poll: %v", round, err)
			}
			if msg == nil {
				break
			}
			moved = true
			if _, err := cli.Deliver(msg); err != nil {
				return err
			}
		}
		if cli.State() == session.StateEstablished && gw.State() == session.StateEstablished {
			return nil
		}
		if !moved {
			t.Fatalf("round %d: neither end had anything to send and neither is established "+
				"(client %s, gateway %s)", round, cli.State(), gw.State())
		}
	}
	t.Fatalf("64 rounds without establishing (client %s, gateway %s)", cli.State(), gw.State())
	return nil
}

// TestAnOldPeerThatSendsNoHandshakePayloadStillConnects is the compatibility
// floor, and it is the first thing anyone reviewing this change should read.
//
// Before 2026-08-09 every caller of core.WriteResponse in this tree passed nil,
// so the response payload was empty. winn3/gateway passed nil until 2026-08-10
// and now states Config.PathMTU; a gateway that leaves it zero still sends
// nothing, which is the case this test is about. A
// peer that sends no payload must behave EXACTLY as it did, in both directions:
// an old gateway against a new client, and a new gateway against an old client.
// If either of those refuses, this change is an outage rather than a fix.
func TestAnOldPeerThatSendsNoHandshakePayloadStillConnects(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cliMTU, gwMTU  int
		wantNoticeSent bool
	}{
		{"an old gateway answers a new client", 1500, 0, false},
		{"a new gateway answers an old client", 0, 1280, true},
		{"neither end makes a claim", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kr := newKeyring(t)
			cliCfg, gwCfg := pathMTUFixtureConfigs(kr, tc.cliMTU, tc.gwMTU)

			// Measured, not assumed: what does a responder on this
			// configuration actually put in the payload?
			notice := session.EncodePathMTUNotice(gwCfg.PathMTU)
			if got := len(notice) > 0; got != tc.wantNoticeSent {
				t.Fatalf("the gateway sends a notice: %v, want %v (its PathMTU is %d)",
					got, tc.wantNoticeSent, gwCfg.PathMTU)
			}

			cli, err := session.NewClient(cliCfg)
			if err != nil {
				t.Fatal(err)
			}
			gw, err := session.NewGateway(gwCfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := pumpSessions(t, cli, gw); err != nil {
				t.Fatalf("a peer that makes no path-MTU claim was refused: %v", err)
			}
			if cli.State() != session.StateEstablished {
				t.Fatalf("client is %s, want established (err %v)", cli.State(), cli.Err())
			}
			if cli.Err() != nil {
				t.Fatalf("the client established and still recorded %v", cli.Err())
			}
		})
	}
}

// TestAForeignHandshakePayloadIsNotReadAsAPathMTUClaim.
//
// The payload is a shared channel. A later hint that is not a path-MTU notice
// must not be read as one — reading a foreign payload as an MTU would
// manufacture a refusal out of an unrelated extension, which is the over-fire
// this family cannot afford.
func TestAForeignHandshakePayloadIsNotReadAsAPathMTUClaim(t *testing.T) {
	for _, payload := range [][]byte{
		nil,
		{},
		[]byte("ok"),                        // what core's own vectors send
		[]byte("W3PM"),                      // the magic and nothing else
		{'W', '3', 'P', 'M', 2, 0x05, 0xDC}, // a version this build has never seen
		{'X', '3', 'P', 'M', 1, 0x05, 0xDC}, // one byte off the magic
		{'W', '3', 'P', 'M', 1, 0x00, 0x00}, // a claim of zero
		[]byte("a longer hint that is not a notice ...."),
	} {
		if mtu, ok := session.DecodePathMTUNotice(payload); ok {
			t.Errorf("payload %q was read as a path-MTU claim of %d", payload, mtu)
		}
	}
	// And the positive half, so the decoder is not merely returning false for
	// everything: a real notice round-trips.
	for _, mtu := range []int{1280, 1360, 1400, 1450, 1500, 9000} {
		got, ok := session.DecodePathMTUNotice(session.EncodePathMTUNotice(mtu))
		if !ok || got != mtu {
			t.Errorf("a notice for %d decoded as (%d, %v)", mtu, got, ok)
		}
	}
	// A notice that cannot be represented is no notice at all, rather than a
	// wrapped one: a claim the responder did not make is worse than none.
	for _, mtu := range []int{0, -1, 0x10000} {
		if n := session.EncodePathMTUNotice(mtu); n != nil {
			t.Errorf("EncodePathMTUNotice(%d) produced %x; want no notice", mtu, n)
		}
	}
}

// TestEveryAgreeingPathMTUStillEstablishes is the OVER-FIRE CONTROL.
//
// Seven legitimate configurations that must start and establish cleanly. A
// refusal that fires on any of these is a fleet-wide outage caused by the fix,
// which is strictly worse than the black hole it was meant to close.
func TestEveryAgreeingPathMTUStillEstablishes(t *testing.T) {
	for _, mtu := range []int{1280, 1360, 1400, 1420, 1450, 1500, 9000} {
		t.Run(strconv.Itoa(mtu), func(t *testing.T) {
			kr := newKeyring(t)
			cliCfg, gwCfg := pathMTUFixtureConfigs(kr, mtu, mtu)
			cli, err := session.NewClient(cliCfg)
			if err != nil {
				t.Fatal(err)
			}
			gw, err := session.NewGateway(gwCfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := pumpSessions(t, cli, gw); err != nil {
				t.Fatalf("two ends agreeing at %d were refused: %v", mtu, err)
			}
			if cli.State() != session.StateEstablished || gw.State() != session.StateEstablished {
				t.Fatalf("client %s, gateway %s at an agreed %d", cli.State(), gw.State(), mtu)
			}
		})
	}
}

// TestAPathMTUMismatchRefusesTheSessionLoudly is the defect, in the two regimes
// that were measured against live processes on 2026-08-09.
//
// The narrow regime is the dangerous one: before this change it ESTABLISHED,
// carried small packets, and black-holed full-size ones while both ends went on
// reporting the gate carrying. The refusal must name both numbers and both
// ends, because the whole cost of this defect was that neither end could see
// the other's.
func TestAPathMTUMismatchRefusesTheSessionLoudly(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cliMTU, gwMTU int
	}{
		{"narrow: the black hole", 1500, 1400},
		{"wide: no session at all", 1500, 1280},
		{"the client is the narrow end", 1280, 1500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kr := newKeyring(t)
			cliCfg, gwCfg := pathMTUFixtureConfigs(kr, tc.cliMTU, tc.gwMTU)
			cli, err := session.NewClient(cliCfg)
			if err != nil {
				t.Fatal(err)
			}
			gw, err := session.NewGateway(gwCfg)
			if err != nil {
				t.Fatal(err)
			}
			refusal := pumpSessions(t, cli, gw)
			if refusal == nil {
				t.Fatalf("a client at %d accepted a gateway at %d: the black hole is open",
					tc.cliMTU, tc.gwMTU)
			}
			if !errors.Is(refusal, session.ErrPathMTUMismatch) {
				t.Fatalf("refusal is %v, want ErrPathMTUMismatch", refusal)
			}
			if cli.State() != session.StateFailed {
				t.Errorf("client is %s after refusing, want failed", cli.State())
			}
			if !errors.Is(cli.Err(), session.ErrPathMTUMismatch) {
				t.Errorf("Err() is %v, want ErrPathMTUMismatch", cli.Err())
			}
			// Both values, and which end each belongs to. A refusal that says
			// only "path MTU mismatch" sends the operator back to the same two
			// files this defect has always hidden between.
			text := refusal.Error()
			for _, want := range []string{
				strconv.Itoa(tc.cliMTU), strconv.Itoa(tc.gwMTU), "responder", "initiator",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("the refusal does not contain %q:\n%s", want, text)
				}
			}
		})
	}
}

// TestALoopStatesThePathMTUItsSizingWasBuiltAt.
//
// The number carried across the handshake has to be the number this end's plan
// floor was DERIVED from. A notice built from a constant would agree with
// itself while the loop planned on something else, which is the shape of every
// defect in this family.
func TestALoopStatesThePathMTUItsSizingWasBuiltAt(t *testing.T) {
	// 1280 and 1400 are gone from this list: since 2026-08-10 NewSizing refuses
	// the dead zone, and for a udp-only plan that band ends at 1357. These are
	// three path MTUs a loop can actually be built at.
	for _, mtu := range []int{1357, 1450, 1500} {
		sz, err := NewSizing(mtu, carrier.ClassUDP)
		if err != nil {
			t.Fatal(err)
		}
		if sz.PathMTU != mtu {
			t.Fatalf("Sizing.PathMTU is %d, want %d", sz.PathMTU, mtu)
		}
		got, ok := session.DecodePathMTUNotice(session.EncodePathMTUNotice(sz.PathMTU))
		if !ok || got != mtu {
			t.Fatalf("a loop sized at %d would state (%d, %v)", mtu, got, ok)
		}
	}
}

// TestALoopRefusesAPathMTUSetByHand.
//
// Same argument newLoop already makes about MaxMessageSize, one input earlier.
// A host that could set the compared number separately from the number it sized
// itself at would make the comparison meaningless in exactly the direction that
// looks fine.
func TestALoopRefusesAPathMTUSetByHand(t *testing.T) {
	kr := newKeyring(t)
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(Config{
		Session: session.Config{
			Core:          core.Config{Gateway: kr.params},
			Static:        kr.cliStatic,
			GatewayStatic: kr.gwPublic,
			Padding:       core.PadBucket,
			PathMTU:       1500,
		},
		Sizing: sz, Carrier: conn, Tun: nil,
	})
	if !errors.Is(err, ErrSizeNotPinned) {
		t.Fatalf("newLoop accepted a hand-set Session.PathMTU: %v", err)
	}
}

// TestTwoLoopsAtDifferentPathMTUsRefuseInsteadOfBlackHoling is the same defect
// one layer up, through the real loops, the real carriers and the real tun
// layer — the composition cmd/winn-datapath and cmd/winn3-gateway actually run.
//
// It also pins the ROUTE the refusal takes to the operator: Run returns, and it
// returns text naming both numbers, which is what cmd/winn-datapath writes into
// the status document's `refusal` field.
func TestTwoLoopsAtDifferentPathMTUsRefuseInsteadOfBlackHoling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	kr := newKeyring(t)
	cliSizing, err := NewSizing(1500, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	// 1357 rather than 1280: still a genuine mismatch against the client's
	// 1500, but on the legal side of the dead-zone refusal, so this test goes
	// on measuring the mismatch refusal and not the sizing one.
	gwSizing, err := NewSizing(1357, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	// The pipe is built at the WIDER of the two so that both loops can be
	// constructed at all. A pipe at the narrow number would refuse the wide
	// client in newLoop with ErrSizeMismatch, which is a different refusal and
	// would make this test pass for the wrong reason.
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: cliSizing, carrier: cliCar,
		local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: gwSizing, carrier: gwCar,
		local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	runErr := cli.waitRun(20 * time.Second)
	if runErr == nil {
		t.Fatal("the client loop ran to completion against a gateway planning at a " +
			"different path MTU; that session is the black hole")
	}
	if !errors.Is(runErr, ErrSessionFailed) {
		t.Fatalf("Run returned %v, want ErrSessionFailed", runErr)
	}
	if !errors.Is(cli.loop.Session().Err(), session.ErrPathMTUMismatch) {
		t.Fatalf("the session failed with %v, want ErrPathMTUMismatch", cli.loop.Session().Err())
	}
	// Derived from the two sizings rather than written out, so the pair cannot
	// drift from the numbers the loops were actually built at.
	for _, want := range []string{
		strconv.Itoa(cliSizing.PathMTU), strconv.Itoa(gwSizing.PathMTU),
	} {
		if !strings.Contains(runErr.Error(), want) {
			t.Errorf("Run's error does not name %s:\n%s", want, runErr)
		}
	}
	// And the safety property the whole family is about: the gate never opened,
	// so no host was ever told this tunnel was carrying.
	if cli.loop.Carrying() {
		t.Error("the client reported carrying on a session it refused")
	}
	cancel()
	_ = gw.waitRun(20 * time.Second)
}

// TestTwoLoopsAgreeingOnThePathMTUStillCarryBytes is the over-fire control at
// the same layer: the identical fixture, with the one number brought into
// agreement, must still establish, open its gate and move an inner packet.
func TestTwoLoopsAgreeingOnThePathMTUStillCarryBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	kr := newKeyring(t)
	sz, err := NewSizing(1500, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar,
		local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar,
		local: gatewayAddr(), router: clientAddr(),
	})
	defer cli.stop()
	defer gw.stop()

	cli.start(ctx)
	gw.start(ctx)

	cli.waitState(session.StateEstablished, 20*time.Second)
	gw.waitState(session.StateEstablished, 20*time.Second)
	waitFor(t, 5*time.Second, "the client gate to open", func() bool {
		return cli.loop.Carrying()
	})

	payload := []byte(fmt.Sprintf("an agreeing pair at %d still carries", sz.PathMTU))
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
	got := gw.dev.take(t, 15*time.Second)
	if d, want := digest(payloadOf(got)), digest(payload); d != want {
		t.Fatalf("the packet arrived with digest %s, want %s", d, want)
	}
	if err := cli.loop.Session().Err(); err != nil {
		t.Fatalf("an agreeing session recorded %v", err)
	}
}
