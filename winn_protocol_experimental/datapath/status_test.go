package datapath

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// These tests own TransportObservedBothWays — the single field a
// route-promotion gate may read. The contract, in the shape the hosts enforce:
//
//   - It must stay false for a socket that merely exists.
//   - A keepalive-sized transport datagram (exactly awgKeepaliveBytes == 32
//     bytes) must NEVER move the underlying payload counters, in either
//     direction. Only a datagram LARGER than the bare keepalive counts as
//     transfer.
//   - It must stay false until and unless a qualifying transport datagram has
//     crossed in BOTH directions.
//   - An off-path sender must never move it: a datagram not from the configured
//     gateway endpoint is dropped before classification.
//
// A green here means a gate built on this field cannot promote a route on
// empty-socket liveness, on handshakes, on keepalives, or on an injected
// foreign datagram. It is evidence the carrier delivered payload-carrying
// transport data from the configured endpoint and the host sent it back — never
// proof the cryptography succeeded (the Winn layer cannot verify that; see the
// Status type comment).

// freshStatusEngine builds a quiet direct-awg engine over the obfuscated
// shipping-style header profile and a real loopback socket, plus a real gateway
// socket to talk to. The engine never owns the socket and the gateway filter is
// on, which is the production posture.
func freshStatusEngine(t *testing.T) (*Engine, *net.UDPConn, Config) {
	t.Helper()
	gateway := newLoopbackGateway(t)
	config := obfuscatedConfig(gateway.LocalAddr())
	engine, err := OpenWithPacketConn(config, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine, gateway, config
}

func requireGatewayRead(
	t *testing.T,
	gateway *net.UDPConn,
	count int,
) *net.UDPAddr {
	t.Helper()
	buffer := make([]byte, 2048)
	var from *net.UDPAddr
	for i := 0; i < count; i++ {
		_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, sender, err := gateway.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("gateway read %d/%d: %v", i+1, count, err)
		}
		from = sender
	}
	return from
}

// TestStatusTransportObservedBothWaysStaysFalseOnKeepalivesOnly pins the
// keepalive boundary. A bare 32-byte transport keepalive is ClassTransportData
// but must not be counted as payload — otherwise a gate would promote a route
// on a tunnel that has carried no user data at all. It must stay false even
// when keepalives cross in both directions.
func TestStatusTransportObservedBothWaysStaysFalseOnKeepalivesOnly(t *testing.T) {
	engine, gateway, config := freshStatusEngine(t)
	headers := *config.AWGHeaders

	if got := engine.Status().TransportObservedBothWays; got {
		t.Fatal("transport_observed_both_ways is true before any traffic on a " +
			"fresh engine")
	}

	// A keepalive SIZED transport datagram out, and one larger than a keepalive
	// that is still a transport message. Only the larger one is payload.
	if _, err := engine.WriteInbound(awgDatagram(headers.H4.Start, awgKeepaliveBytes)); err != nil {
		t.Fatalf("WriteInbound keepalive: %v", err)
	}
	if _, err := engine.WriteInbound(awgDatagram(headers.H4.Start, 200)); err != nil {
		t.Fatalf("WriteInbound transport: %v", err)
	}
	status := engine.Status()
	if status.TxTransportDatagrams != 2 {
		t.Fatalf("tx_transport_datagrams = %d, want 2", status.TxTransportDatagrams)
	}
	if status.TxTransportPayloadDatagram != 1 {
		t.Fatalf("tx_transport_payload_datagrams = %d, want 1 (the larger "+
			"datagram, never the keepalive)", status.TxTransportPayloadDatagram)
	}

	// Drain the two datagrams the gateway saw, then answer with a keepalive only.
	from := requireGatewayRead(t, gateway, 2)
	if _, err := gateway.WriteToUDP(
		awgDatagram(headers.H4.Start, awgKeepaliveBytes), from,
	); err != nil {
		t.Fatalf("gateway keepalive write: %v", err)
	}
	buffer := make([]byte, 2048)
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound keepalive: %v", err)
	}
	status = engine.Status()
	if status.RxTransportDatagrams != 1 {
		t.Fatalf("rx_transport_datagrams = %d, want 1 (the inbound keepalive "+
			"is still transport data)", status.RxTransportDatagrams)
	}
	if status.RxTransportPayloadDatagram != 0 {
		t.Fatalf("rx_transport_payload_datagrams = %d, want 0 (a bare "+
			"keepalive is not payload)", status.RxTransportPayloadDatagram)
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways became true with only keepalives " +
			"crossing in both directions; a route-promotion gate on it would " +
			"fire on a tunnel carrying no user data")
	}
}

// TestStatusTransportObservedBothWaysRequiresPayloadInBothDirections is the
// core of the gate: outbound payload alone must stay false, and the field flips
// true only once a qualifying transport datagram has ALSO arrived inbound from
// the configured gateway endpoint.
func TestStatusTransportObservedBothWaysRequiresPayloadInBothDirections(t *testing.T) {
	engine, gateway, config := freshStatusEngine(t)
	headers := *config.AWGHeaders

	if _, err := engine.WriteInbound(awgDatagram(headers.H4.Start, 200)); err != nil {
		t.Fatalf("WriteInbound transport: %v", err)
	}
	status := engine.Status()
	if status.TxTransportPayloadDatagram != 1 {
		t.Fatalf("tx_transport_payload_datagrams = %d, want 1", status.TxTransportPayloadDatagram)
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is true with outbound payload only")
	}

	from := requireGatewayRead(t, gateway, 1)
	if _, err := gateway.WriteToUDP(awgDatagram(headers.H4.Start, 300), from); err != nil {
		t.Fatalf("gateway transport write: %v", err)
	}
	buffer := make([]byte, 2048)
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound transport: %v", err)
	}
	status = engine.Status()
	if status.RxTransportPayloadDatagram != 1 {
		t.Fatalf("rx_transport_payload_datagrams = %d, want 1", status.RxTransportPayloadDatagram)
	}
	if !status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is still false after payload " +
			"crossed in both directions")
	}
}

// TestStatusTransportObservedBothWaysUnaffectedByOffPathSender closes the
// injection hole: a datagram that did not come from the configured gateway
// endpoint must be dropped before classification. It may increment the foreign
// counter, but it must never move the transfer-proven counters or the field
// built on them.
func TestStatusTransportObservedBothWaysUnaffectedByOffPathSender(t *testing.T) {
	engine, gateway, config := freshStatusEngine(t)

	// Give the engine a genuine outbound payload first, so the ONLY thing that
	// could flip the field is the foreign datagram.
	if _, err := engine.WriteInbound(
		awgDatagram(config.AWGHeaders.H4.Start, 200),
	); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	_ = requireGatewayRead(t, gateway, 1)

	local, ok := engine.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("engine socket has no UDP address")
	}
	foreign := newLoopbackGateway(t)
	// A LARGE transport-looking datagram from an unconfigured sender. If the
	// gateway-sender filter were not applied, this would be classified inbound
	// as a payload datagram and would flip the gate.
	if _, err := foreign.WriteToUDP(
		awgDatagram(config.AWGHeaders.H4.Start, 400), local,
	); err != nil {
		t.Fatalf("foreign write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for engine.Status().RxForeign == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	status := engine.Status()
	if status.RxForeign != 1 {
		t.Fatalf("rx_foreign_sender = %d, want 1 (the foreign datagram was "+
			"rejected, and the rejection was counted)", status.RxForeign)
	}
	if status.RxTransportPayloadDatagram != 0 {
		t.Fatal("a datagram from an unconfigured sender was counted as inbound " +
			"payload")
	}
	if status.TransportObservedBothWays {
		t.Fatal("an off-path sender flipped transport_observed_both_ways; the " +
			"gate would promote routes on an injected datagram")
	}
}

// TestStatusTransportObservedBothWaysIgnoresHandshakeAlone pins that a
// handshake response from the gateway — evidence the gateway is answering, not
// evidence of transfer — never moves the field.
func TestStatusTransportObservedBothWaysIgnoresHandshakeAlone(t *testing.T) {
	engine, gateway, config := freshStatusEngine(t)
	headers := *config.AWGHeaders

	buffer := make([]byte, 2048)
	if _, err := engine.WriteInbound(awgDatagram(headers.H1.Start, 148)); err != nil {
		t.Fatalf("WriteInbound initiation: %v", err)
	}
	from := requireGatewayRead(t, gateway, 1)
	if _, err := gateway.WriteToUDP(awgDatagram(headers.H2.Start, 92), from); err != nil {
		t.Fatalf("gateway handshake response: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound response: %v", err)
	}
	status := engine.Status()
	if !status.HandshakeResponseObserved {
		t.Fatal("handshake_response_observed is false after a handshake response")
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is true on a handshake alone")
	}
}

// TestStatusJSONNamesTransportObservedBothWaysAndItsCounters pins the field
// names a route gate reads, so a rename on the wire cannot silently break a
// host with no compiler to notice.
func TestStatusJSONNamesTransportObservedBothWaysAndItsCounters(t *testing.T) {
	engine, _, _ := freshStatusEngine(t)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(engine.StatusJSON()), &decoded); err != nil {
		t.Fatalf("StatusJSON is not valid JSON: %v", err)
	}
	for _, key := range []string{
		"up",
		"tx_transport_datagrams",
		"tx_transport_payload_datagrams",
		"rx_transport_datagrams",
		"rx_transport_payload_datagrams",
		"handshake_response_observed",
		"transport_observed_both_ways",
	} {
		if _, present := decoded[key]; !present {
			t.Errorf("status JSON is missing %q", key)
		}
	}
}
