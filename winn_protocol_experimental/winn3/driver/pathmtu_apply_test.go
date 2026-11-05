package driver

// Loop-level APPLY for silent-refusal instance #3.
//
// A client at 1500 against a gateway at 1357, with a device that implements
// tun.MTUSetter, must establish, clamp the device, open the gate, and carry
// an inner packet. The same pair against fakeDevice (no SetMTU) is already
// pinned by TestTwoLoopsAtDifferentPathMTUsRefuseInsteadOfBlackHoling.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// clampingDevice is the APPLY test's host device. It is a wrapper, not a
// method on fakeDevice, so the rest of this package's tests keep modelling
// production hosts that cannot SetMTU.
type clampingDevice struct {
	*fakeDevice
}

func (d *clampingDevice) SetMTU(n int) error {
	if n > d.mtu {
		return fmt.Errorf("clampingDevice: cannot raise MTU from %d to %d", d.mtu, n)
	}
	if n < 1 {
		return fmt.Errorf("clampingDevice: MTU %d is not positive", n)
	}
	d.mtu = n
	return nil
}

func TestTwoLoopsAtDifferentPathMTUsCarryWhenTheDeviceCanSetMTU(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	kr := newKeyring(t)
	cliSizing, err := NewSizing(1500, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	gwSizing, err := NewSizing(1357, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	if cliSizing.InnerMTU <= gwSizing.InnerMTU {
		t.Fatalf("harness: client inner %d is not above gateway inner %d",
			cliSizing.InnerMTU, gwSizing.InnerMTU)
	}

	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}

	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: cliSizing, carrier: cliCar,
		local: clientAddr(), router: gatewayAddr(),
		clamping: true,
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: gwSizing, carrier: gwCar,
		local: gatewayAddr(), router: clientAddr(),
		clamping: true,
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

	if got, want := cli.loop.Tunnel().InnerMTU(), gwSizing.InnerMTU; got != want {
		t.Fatalf("client InnerMTU is %d after apply, want the gateway's %d", got, want)
	}
	if got, want := cli.dev.MTU(), gwSizing.InnerMTU; got != want {
		t.Fatalf("client device MTU is %d after apply, want %d — applyNegotiatedMTU did not clamp",
			got, want)
	}
	if got := cli.loop.Session().PathMTUAgreed(); got != gwSizing.PathMTU {
		t.Fatalf("PathMTUAgreed is %d, want %d", got, gwSizing.PathMTU)
	}
	if got := cli.loop.Session().MaxMessageSize(); got != gwSizing.MessageSize {
		t.Fatalf("client MaxMessageSize is %d after apply, want %d", got, gwSizing.MessageSize)
	}

	payload := []byte("a 1500 client carries at the 1357 peer's floor")
	cli.dev.offer(t, ipv4Packet(clientAddr(), gatewayAddr(), payload))
	got := gw.dev.take(t, 15*time.Second)
	if d, want := digest(payloadOf(got)), digest(payload); d != want {
		t.Fatalf("the packet arrived with digest %s, want %s", d, want)
	}
	if err := cli.loop.Session().Err(); err != nil {
		t.Fatalf("an applied session recorded %v", err)
	}
}

func TestALoopWithoutSetMTUStillRefusesTheSamePair(t *testing.T) {
	// Negative control for the test above: identical numbers, production-like
	// device, must still be ErrPathMTUMismatch. If APPLY became unconditional
	// this would go green on a black hole.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	kr := newKeyring(t)
	cliSizing, err := NewSizing(1500, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	gwSizing, err := NewSizing(1357, carrier.ClassUDP)
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
		t.Fatal("a client whose device cannot SetMTU established against a narrower gateway")
	}
	if cli.loop.Carrying() {
		t.Error("the client reported carrying on a session it should have refused")
	}
	if got := cli.dev.MTU(); got != cliSizing.InnerMTU {
		t.Fatalf("a refused session clamped the device to %d", got)
	}
}
