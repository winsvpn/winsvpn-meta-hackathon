package datapath

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
)

// syntheticAddr is what a real carrier PacketConn reports as its peer:
// carrier.fixedAddr, which is NOT a *net.UDPAddr. Any code that tries to match
// it against the configured gateway will reject every datagram, which is why
// OpenWithCarrier turns the gateway sender filter off.
type syntheticAddr string

func (a syntheticAddr) Network() string { return "winn-carrier" }
func (a syntheticAddr) String() string  { return string(a) }

// fakeCarrierConn stands in for what internal/carrier.Dialer returns: a
// PacketConn that ignores the address on WriteTo, reports a synthetic peer on
// ReadFrom, and carries opaque payloads.
type fakeCarrierConn struct {
	toGateway   chan []byte
	fromGateway chan []byte
	closed      chan struct{}
	closeOnce   sync.Once
}

func newFakeCarrierConn() *fakeCarrierConn {
	return &fakeCarrierConn{
		toGateway:   make(chan []byte, 16),
		fromGateway: make(chan []byte, 16),
		closed:      make(chan struct{}),
	}
}

func (c *fakeCarrierConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.fromGateway:
		return copy(buffer, packet), syntheticAddr("winn-carrier-peer"), nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakeCarrierConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	copied := append([]byte(nil), packet...)
	select {
	case c.toGateway <- copied:
		return len(packet), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeCarrierConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeCarrierConn) LocalAddr() net.Addr {
	return syntheticAddr("winn-carrier-local")
}
func (c *fakeCarrierConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeCarrierConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeCarrierConn) SetWriteDeadline(time.Time) error { return nil }

// stubPacketCarrierDialer is a carrier.PacketSocketDialer double. Like the real
// H3 dialer it REFUSES to dial without a socket unless explicitly told it may
// open its own, so a wiring bug that forgot to install the descriptor shows up
// as a failed dial rather than as a silently unprotected socket.
type stubPacketCarrierDialer struct {
	supplied     net.PacketConn
	allowOwn     bool
	dials        atomic.Int32
	ownedSockets atomic.Int32
	carrierConn  *fakeCarrierConn
}

func (d *stubPacketCarrierDialer) SuppliedSocketKind() carrier.SocketKind {
	return carrier.SocketKindPacket
}
func (d *stubPacketCarrierDialer) HasSuppliedSocket() bool { return d.supplied != nil }

func (d *stubPacketCarrierDialer) UseSuppliedSocket(conn net.PacketConn) error {
	if conn == nil {
		return carrier.ErrSuppliedSocketRequired
	}
	if d.supplied != nil {
		return carrier.ErrSuppliedSocketConsumed
	}
	d.supplied = conn
	return nil
}

func (d *stubPacketCarrierDialer) Dial(context.Context) (net.PacketConn, error) {
	d.dials.Add(1)
	if d.supplied == nil {
		if !d.allowOwn {
			return nil, errors.New(
				"stub carrier was asked to dial with no supplied socket",
			)
		}
		d.ownedSockets.Add(1)
	}
	if d.carrierConn == nil {
		d.carrierConn = newFakeCarrierConn()
	}
	return d.carrierConn, nil
}

// stubStreamCarrierDialer is the HTTP/2-shaped double: it takes a net.Conn.
type stubStreamCarrierDialer struct {
	supplied net.Conn
}

func (d *stubStreamCarrierDialer) SuppliedSocketKind() carrier.SocketKind {
	return carrier.SocketKindStream
}
func (d *stubStreamCarrierDialer) HasSuppliedSocket() bool { return d.supplied != nil }
func (d *stubStreamCarrierDialer) UseSuppliedSocket(conn net.Conn) error {
	d.supplied = conn
	return nil
}
func (d *stubStreamCarrierDialer) Dial(context.Context) (net.PacketConn, error) {
	return newFakeCarrierConn(), nil
}

func carrierConfigBlob(name, gateway string) []byte {
	return []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + name +
		`","gateway_endpoint":"` + gateway +
		`","session_id":"carrier-wiring"}`)
}

// TestOpenRefusesACarrierItCannotBuild is the honest half of lifting the
// refusal. Open still constructs only direct-awg, so a configuration naming a
// carrier is refused — but for the true reason (no dialer was supplied), not
// for the false one it used to give (that the carriers cannot be protected).
func TestOpenRefusesACarrierItCannotBuild(t *testing.T) {
	attempts := withSocketOpenerGuard(t)
	for _, name := range []string{CarrierHTTP3, CarrierHTTP2} {
		engine, err := Open(carrierConfigBlob(name, "203.0.113.9:51820"), -1)
		if engine != nil {
			_ = engine.Close()
			t.Fatalf("carrier %q produced an engine from Open", name)
		}
		if !errors.Is(err, ErrCarrierNoDialer) {
			t.Fatalf("carrier %q error = %v, want ErrCarrierNoDialer", name, err)
		}
		if errors.Is(err, ErrCarrierUnimplemented) {
			t.Fatalf(
				"carrier %q is still reported as unimplemented; it is "+
					"implemented and rides a supplied socket", name,
			)
		}
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("a refused carrier opened %d sockets; want 0", got)
	}
}

func TestOpenWithCarrierRefusesWhatItCannotProve(t *testing.T) {
	ctx := context.Background()
	const gateway = "203.0.113.9:51820"

	t.Run("nil dialer", func(t *testing.T) {
		_, err := OpenWithCarrier(
			ctx, carrierConfigBlob(CarrierHTTP3, gateway), -1, nil,
		)
		if !errors.Is(err, ErrCarrierDialerRequired) {
			t.Fatalf("error = %v, want ErrCarrierDialerRequired", err)
		}
	})

	t.Run("direct-awg has no carrier dialer", func(t *testing.T) {
		_, err := OpenWithCarrier(
			ctx, carrierConfigBlob(CarrierDirectAWG, gateway), -1,
			&stubPacketCarrierDialer{},
		)
		if !errors.Is(err, ErrCarrierDialerMismatch) {
			t.Fatalf("error = %v, want ErrCarrierDialerMismatch", err)
		}
	})

	t.Run("socket kind must match the carrier", func(t *testing.T) {
		// http2-stream needs a TCP connection; a packet dialer cannot serve it.
		_, err := OpenWithCarrier(
			ctx, carrierConfigBlob(CarrierHTTP2, gateway), -1,
			&stubPacketCarrierDialer{},
		)
		if !errors.Is(err, ErrCarrierDialerMismatch) {
			t.Fatalf("error = %v, want ErrCarrierDialerMismatch", err)
		}
		// ...and the reverse.
		_, err = OpenWithCarrier(
			ctx, carrierConfigBlob(CarrierHTTP3, gateway), -1,
			&stubStreamCarrierDialer{},
		)
		if !errors.Is(err, ErrCarrierDialerMismatch) {
			t.Fatalf("reverse error = %v, want ErrCarrierDialerMismatch", err)
		}
	})

	t.Run("a pre-loaded dialer is refused", func(t *testing.T) {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		_, err = OpenWithCarrier(
			ctx, carrierConfigBlob(CarrierHTTP3, gateway), -1,
			&stubPacketCarrierDialer{supplied: socket},
		)
		if !errors.Is(err, ErrCarrierSocketReused) {
			t.Fatalf("error = %v, want ErrCarrierSocketReused", err)
		}
	})

	t.Run("no descriptor without allow_own_socket", func(t *testing.T) {
		attempts := withSocketOpenerGuard(t)
		dialer := &stubPacketCarrierDialer{allowOwn: true}
		_, err := OpenWithCarrier(
			ctx, carrierConfigBlob(CarrierHTTP3, gateway), -1, dialer,
		)
		if !errors.Is(err, ErrOwnSocketRefused) {
			t.Fatalf("error = %v, want ErrOwnSocketRefused", err)
		}
		if dialer.dials.Load() != 0 {
			t.Fatal("a refused configuration still dialled the carrier")
		}
		if got := attempts.Load(); got != 0 {
			t.Fatalf("refusal opened %d sockets; want 0", got)
		}
	})
}

// TestOpenWithCarrierAcceptsSyntheticCarrierPeers proves the gateway sender
// filter is off on a carrier. A real carrier PacketConn reports a synthetic
// peer; with the filter left on, every datagram below would be counted as
// foreign and dropped, and the tunnel would look alive while carrying nothing.
func TestOpenWithCarrierAcceptsSyntheticCarrierPeers(t *testing.T) {
	attempts := withSocketOpenerGuard(t)
	config := Config{
		Contract:        ContractVersion,
		Payload:         PayloadAWGDatagram,
		Carrier:         CarrierHTTP3,
		GatewayEndpoint: "203.0.113.9:51820",
		SessionID:       "synthetic-peer",
		AllowOwnSocket:  true,
	}
	dialer := &stubPacketCarrierDialer{allowOwn: true}
	engine, err := OpenConfigWithCarrier(context.Background(), config, -1, dialer)
	if err != nil {
		t.Fatalf("OpenConfigWithCarrier: %v", err)
	}
	defer func() { _ = engine.Close() }()

	status := engine.Status()
	if status.GatewaySenderFilter {
		t.Fatal("gateway_sender_filter is on for a carrier transport")
	}
	if status.Carrier != CarrierHTTP3 {
		t.Fatalf("status carrier = %q, want %q", status.Carrier, CarrierHTTP3)
	}
	if !status.SocketOwnedByEngine {
		t.Fatal("socket_owned_by_engine should be true on the allow_own_socket path")
	}

	outbound := []byte("host-to-gateway-over-a-carrier")
	if _, err := engine.WriteInbound(outbound); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	select {
	case relayed := <-dialer.carrierConn.toGateway:
		if string(relayed) != string(outbound) {
			t.Fatalf("carrier got %q, want %q", relayed, outbound)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("carrier never received the outbound datagram")
	}

	inbound := []byte("gateway-to-host-over-a-carrier")
	dialer.carrierConn.fromGateway <- inbound
	buffer := make([]byte, 2048)
	count, err := engine.ReadOutboundTimeout(buffer, 5*time.Second)
	if err != nil {
		t.Fatalf("ReadOutbound: %v", err)
	}
	if string(buffer[:count]) != string(inbound) {
		t.Fatalf("host got %q, want %q", buffer[:count], inbound)
	}
	if got := engine.Status().RxForeign; got != 0 {
		t.Fatalf("%d carrier datagrams were rejected as foreign senders", got)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("carrier engine opened %d sockets of its own; want 0", got)
	}
}
