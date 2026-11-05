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

// TestSendInnerRefusesUnlessEstablished is the fail-closed half of the gateway
// return path. A no-tun loop has no physical gate, so Carrying must project the
// session's data-plane state and SendInner must enforce the same predicate.
func TestSendInnerRefusesUnlessEstablished(t *testing.T) {
	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	e := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: pipe, noTun: true})
	if e.loop.Carrying() {
		t.Fatal("a no-tun loop reports Carrying() true before establishment")
	}
	if e.loop.Session().State() == session.StateEstablished {
		t.Fatal("fixture was already established")
	}
	err = e.loop.SendInner(ipv4Packet(gatewayAddr(), clientAddr(), []byte("too early")))
	if !errors.Is(err, tun.ErrNotCarrying) {
		t.Fatalf("SendInner before Established returned %v, want tun.ErrNotCarrying", err)
	}
}

// TestSendInnerAfterCloseIsNotCarrying pins the reserved ErrClosed sentinel.
// Close always returns nil. After Close the session is no longer Established,
// so SendInner returns tun.ErrNotCarrying — not ErrClosed, which nothing in
// this package currently returns.
func TestSendInnerAfterCloseIsNotCarrying(t *testing.T) {
	sz := planSizing(t)
	kr := newKeyring(t)
	pipe, _, err := carrier.NewPipePair(carrier.PipeConfig{Class: carrier.ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	e := newClientEndpoint(t, kr, endpointOpts{sizing: sz, carrier: pipe, noTun: true})
	if err := e.loop.Close(); err != nil {
		t.Fatalf("Close returned %v, want nil", err)
	}
	if err := e.loop.Close(); err != nil {
		t.Fatalf("second Close returned %v, want nil (idempotent)", err)
	}
	err = e.loop.SendInner(ipv4Packet(gatewayAddr(), clientAddr(), []byte("after close")))
	if !errors.Is(err, tun.ErrNotCarrying) {
		t.Fatalf("SendInner after Close returned %v, want tun.ErrNotCarrying", err)
	}
	if errors.Is(err, ErrClosed) {
		t.Fatal("SendInner returned ErrClosed; callers must not errors.Is that sentinel")
	}
	if e.loop.Carrying() {
		t.Fatal("a closed no-tun loop reports Carrying() true")
	}
}

// TestSendInnerCarriesAReplyOnANoTunGateway is the production shape of
// cmd/winn3-gateway -forward: the gateway has no tun.Tunnel on the return
// path and hands internet replies to SendInner. If this is wrong, replies
// vanish while the session still reads established.
func TestSendInnerCarriesAReplyOnANoTunGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassUDP,
		PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, local: clientAddr(), router: gatewayAddr(),
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, local: gatewayAddr(), router: clientAddr(), noTun: true,
	})
	defer cli.stop()
	defer gw.stop()
	cli.start(ctx)
	gw.start(ctx)

	waitFor(t, 20*time.Second, "both sessions established", func() bool {
		return cli.loop.Session().State() == session.StateEstablished &&
			gw.loop.Session().State() == session.StateEstablished
	})
	waitFor(t, 10*time.Second, "client gate open", cli.loop.Carrying)
	if !gw.loop.Carrying() {
		t.Fatal("an established no-tun gateway reports Carrying() false")
	}

	payload := []byte("gateway-reply")
	if err := gw.loop.SendInner(ipv4Packet(gatewayAddr(), clientAddr(), payload)); err != nil {
		t.Fatalf("SendInner on an established no-tun gateway: %v", err)
	}
	got := cli.dev.take(t, 10*time.Second)
	if string(payloadOf(got)) != string(payload) {
		t.Fatalf("client received %q, want %q", payloadOf(got), payload)
	}
}

// TestCloseAndRunDoNotReturnErrClosed is the negative half of the reserved
// sentinel. A caller that errors.Is(err, ErrClosed) on Close or Run is
// matching a value this package never produces.
func TestCloseAndRunDoNotReturnErrClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	cliCar, gwCar, err := carrier.NewPipePair(carrier.PipeConfig{
		Class:   carrier.ClassUDP,
		PathMTU: carrier.DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	cli := newClientEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: cliCar, noTun: true,
	})
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar, noTun: true,
	})
	cli.start(ctx)
	gw.start(ctx)
	waitFor(t, 20*time.Second, "client established", func() bool {
		return cli.loop.Session().State() == session.StateEstablished
	})
	if err := cli.loop.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	runErr := cli.waitRun(10 * time.Second)
	if errors.Is(runErr, ErrClosed) {
		t.Fatalf("Run returned ErrClosed (%v); Close is a request and Run returns nil on a graceful close", runErr)
	}
	cancel()
	_ = gw.waitRun(10 * time.Second)
}
