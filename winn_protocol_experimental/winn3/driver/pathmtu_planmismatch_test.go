package driver

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// TestTwoLoopsAtTheSamePathMTUWithDifferentPlansRefuseInsteadOfBlackHoling
// is the worst remaining realistic MTU failure: PathMTUs match, plan floors
// do not.
//
// Shipping pair, inferred from the flags and constructors (not a live
// process): cmd/winn3-gateway defaults -plan udp; cmd/winn-datapath sizes
// whatever carrier_classes the served profile named, which the reference
// operator sets to udp,tcp,tls. Both resolve a missing path_mtu to
// carrier.DefaultPathMTU (1450). refusePathMTUMismatch used to return nil
// the moment PathMTUs agreed, so the session established, small packets
// carried, and a full-size inner packet from the wider tun vanished on the
// narrower one while both gates reported carrying.
//
// The notice suffix EncodePathMTUFloorNotice is what makes this loud. A
// 7-byte PathMTU-only notice still proceeds (old-peer compatibility), which
// is pinned beside this in session.TestRefusePathMTUMismatchIgnoresPlanFloorWhenThePeerSentOnlyPathMTU.
func TestTwoLoopsAtTheSamePathMTUWithDifferentPlansRefuseInsteadOfBlackHoling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	kr := newKeyring(t)
	cliSizing, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if err != nil {
		t.Fatal(err)
	}
	gwSizing, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	if cliSizing.PathMTU != gwSizing.PathMTU {
		t.Fatalf("harness: PathMTUs differ (%d vs %d); this test is about the same PathMTU",
			cliSizing.PathMTU, gwSizing.PathMTU)
	}
	if cliSizing.MessageSize >= gwSizing.MessageSize {
		t.Fatalf("harness: client floor %d is not below gateway udp-only floor %d",
			cliSizing.MessageSize, gwSizing.MessageSize)
	}

	// Pipe at the WIDER floor so both loops construct. A pipe at the client
	// floor would refuse the gateway in newLoop with ErrSizeMismatch, which
	// is a different refusal and would make this pass for the wrong reason.
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU,
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
		t.Fatal("the client loop ran to completion against a gateway with a wider plan floor " +
			"at the same path MTU; that session is the black hole")
	}
	if !errors.Is(runErr, ErrSessionFailed) {
		t.Fatalf("Run returned %v, want ErrSessionFailed", runErr)
	}
	if !errors.Is(cli.loop.Session().Err(), session.ErrPathMTUMismatch) {
		t.Fatalf("the session failed with %v, want ErrPathMTUMismatch", cli.loop.Session().Err())
	}
	for _, want := range []string{
		strconv.Itoa(cliSizing.MessageSize), strconv.Itoa(gwSizing.MessageSize),
	} {
		if !strings.Contains(runErr.Error(), want) {
			t.Errorf("Run's error does not name floor %s:\n%s", want, runErr)
		}
	}
	if cli.loop.Carrying() {
		t.Error("the client reported carrying on a session it refused")
	}
	cancel()
	_ = gw.waitRun(20 * time.Second)
}

// TestTwoLoopsAtTheSamePathMTUAndTheSamePlanStillCarryBytes is the over-fire
// control: identical PathMTU AND identical plan must still establish and
// move an inner packet. If the floor check refused agreeing floors, every
// healthy session would die at handshake.
func TestTwoLoopsAtTheSamePathMTUAndTheSamePlanStillCarryBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	kr := newKeyring(t)
	sz, err := NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS)
	if err != nil {
		t.Fatal(err)
	}
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: carrier.DefaultPathMTU,
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

	payload := []byte("same path MTU and same plan still carry")
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
	got := gw.dev.take(t, 15*time.Second)
	if d, want := digest(payloadOf(got)), digest(payload); d != want {
		t.Fatalf("the packet arrived with digest %s, want %s", d, want)
	}
	if err := cli.loop.Session().Err(); err != nil {
		t.Fatalf("an agreeing session recorded %v", err)
	}
}
