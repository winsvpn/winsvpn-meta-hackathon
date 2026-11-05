package driver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

// heldReplyCarrier returns one successful read after the caller has moved to
// another carrier. It deliberately ignores cancellation after reading bytes.
type heldReplyCarrier struct {
	carrier.Conn
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (h *heldReplyCarrier) Recv(ctx context.Context) ([]byte, error) {
	msg, err := h.Conn.Recv(ctx)
	if err == nil && h.armed.CompareAndSwap(true, false) {
		h.once.Do(func() { close(h.entered) })
		<-h.release
	}
	return msg, err
}

func TestSuccessfulReadFromOldCarrierIsDiscarded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sizing := planSizing(t)
	keys := newKeyring(t)
	oldClient, oldGateway, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassUDP, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	held := &heldReplyCarrier{
		Conn: oldClient, entered: make(chan struct{}), release: make(chan struct{}),
	}
	client := newClientEndpoint(t, keys, endpointOpts{
		sizing: sizing, carrier: held, local: clientAddr(), router: gatewayAddr(),
	})
	gateway := newGatewayEndpoint(t, keys, endpointOpts{
		sizing: sizing, carrier: oldGateway, local: gatewayAddr(), router: clientAddr(),
	})
	defer client.stop()
	defer gateway.stop()
	client.start(ctx)
	gateway.start(ctx)
	client.waitState(session.StateEstablished, 5*time.Second)
	gateway.waitState(session.StateEstablished, 5*time.Second)

	held.armed.Store(true)
	gateway.dev.offer(t, ipv4Packet(gatewayAddr(), clientAddr(), []byte("stale")))
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal("old carrier did not hold a successful receive")
	}

	newClient, newGateway, err := carrier.NewPipePair(carrier.PipeConfig{
		Class: carrier.ClassTCP, PathMTU: sizing.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.loop.Migrate(newClient); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.loop.Migrate(newGateway); err != nil {
		t.Fatal(err)
	}
	close(held.release)
	gateway.dev.offer(t, ipv4Packet(gatewayAddr(), clientAddr(), []byte("fresh")))
	got := client.dev.take(t, 5*time.Second)
	if string(got[20:]) != "fresh" {
		t.Fatalf("read from old carrier crossed migration: %q", got[20:])
	}
}
