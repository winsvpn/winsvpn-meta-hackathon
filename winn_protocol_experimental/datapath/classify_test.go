package datapath

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// awgDatagram builds an outer datagram whose leading little-endian word is the
// given header type, padded to size. It is not a real AmneziaWG frame and does
// not need to be: the engine classifies by header type and never decrypts, so
// the header type and the length are the only inputs that matter.
func awgDatagram(headerType uint32, size int) []byte {
	if size < 4 {
		size = 4
	}
	datagram := make([]byte, size)
	binary.LittleEndian.PutUint32(datagram[:4], headerType)
	return datagram
}

func obfuscatedConfig(gateway net.Addr) Config {
	config := testConfig(gateway)
	// Values in the shape a signed AmneziaWG deployment produces: large,
	// arbitrary, and nothing like 1..4.
	config.AWGHeaders = &AWGHeaderTypes{
		H1: AwgHeaderSpec{Start: 0x51F3A2C4, End: 0x51F3A2C4},
		H2: AwgHeaderSpec{Start: 0x1B77E90D, End: 0x1B77E90D},
		H3: AwgHeaderSpec{Start: 0x9C40B215, End: 0x9C40B215},
		H4: AwgHeaderSpec{Start: 0x2E8D6F31, End: 0x2E8D6F31},
	}
	return config
}

// TestTransferProvenSignalRequiresPayloadInBothDirections is the field the
// Windows lane must gate route promotion on. It must stay false for a socket
// that merely exists, for handshakes alone, and for keepalives alone.
func TestTransferProvenSignalRequiresPayloadInBothDirections(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := obfuscatedConfig(gateway.LocalAddr())
	engine, err := OpenWithPacketConn(config, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()
	headers := *config.AWGHeaders

	status := engine.Status()
	if !status.Up {
		t.Fatal("a freshly opened engine should report up")
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is true before any traffic; a " +
			"route-promotion gate on it would fire on an empty socket")
	}
	if status.AWGClassification != "configured-h1h4" {
		t.Fatalf("awg_classification = %q, want configured-h1h4",
			status.AWGClassification)
	}

	// A handshake initiation out is not transfer.
	if _, err := engine.WriteInbound(awgDatagram(headers.H1.Start, 148)); err != nil {
		t.Fatalf("WriteInbound handshake: %v", err)
	}
	// A keepalive-sized transport datagram out is not transfer either.
	if _, err := engine.WriteInbound(awgDatagram(headers.H4.Start, 32)); err != nil {
		t.Fatalf("WriteInbound keepalive: %v", err)
	}
	if engine.Status().TxTransportPayloadDatagram != 0 {
		t.Fatal("a keepalive-sized datagram was counted as payload")
	}
	// A real payload-carrying transport datagram out.
	if _, err := engine.WriteInbound(awgDatagram(headers.H4.Start, 200)); err != nil {
		t.Fatalf("WriteInbound transport: %v", err)
	}

	status = engine.Status()
	if status.TxHandshakeInitiations != 1 {
		t.Fatalf("tx_handshake_initiations = %d, want 1", status.TxHandshakeInitiations)
	}
	if status.TxTransportDatagrams != 2 {
		t.Fatalf("tx_transport_datagrams = %d, want 2", status.TxTransportDatagrams)
	}
	if status.TxTransportPayloadDatagram != 1 {
		t.Fatalf("tx_transport_payload_datagrams = %d, want 1",
			status.TxTransportPayloadDatagram)
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is true with outbound traffic only")
	}

	// Drain the gateway side and answer.
	buffer := make([]byte, 2048)
	var from *net.UDPAddr
	for range 3 {
		_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, sender, err := gateway.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("gateway read: %v", err)
		}
		from = sender
	}

	// A handshake response in: evidence the gateway answered, not transfer.
	if _, err := gateway.WriteToUDP(awgDatagram(headers.H2.Start, 92), from); err != nil {
		t.Fatalf("gateway handshake response: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound handshake response: %v", err)
	}
	status = engine.Status()
	if !status.HandshakeResponseObserved {
		t.Fatal("handshake_response_observed is false after a handshake response")
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is true on a handshake response alone")
	}
	if status.FirstRxAt == "" {
		t.Fatal("first_rx_at is empty after the gateway answered")
	}

	// Finally, a payload-carrying transport datagram in.
	if _, err := gateway.WriteToUDP(awgDatagram(headers.H4.Start, 300), from); err != nil {
		t.Fatalf("gateway transport: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound transport: %v", err)
	}
	status = engine.Status()
	if status.RxTransportPayloadDatagram != 1 {
		t.Fatalf("rx_transport_payload_datagrams = %d, want 1",
			status.RxTransportPayloadDatagram)
	}
	if !status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is still false after " +
			"payload-carrying transport datagrams in both directions")
	}
}

// TestForeignSenderCannotMoveTheTransferProvenCounters closes the obvious hole
// in a gate built on these numbers: an off-path sender must not be able to make
// the host promote routes.
func TestForeignSenderCannotMoveTheTransferProvenCounters(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := obfuscatedConfig(gateway.LocalAddr())
	engine, err := OpenWithPacketConn(config, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if _, err := engine.WriteInbound(
		awgDatagram(config.AWGHeaders.H4.Start, 200),
	); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	local, ok := engine.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("engine socket has no UDP address")
	}
	foreign := newLoopbackGateway(t)
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
		t.Fatalf("rx_foreign_sender = %d, want 1", status.RxForeign)
	}
	if status.RxTransportPayloadDatagram != 0 {
		t.Fatal("a datagram from an unconfigured sender moved the " +
			"transport counters")
	}
	if status.TransportObservedBothWays {
		t.Fatal("an off-path sender made transport_observed_both_ways true")
	}
}

func TestClassificationFallsBackToWireGuardDefaultsAndSaysSo(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if got := engine.Status().AWGClassification; got != "wireguard-default-1234" {
		t.Fatalf("awg_classification = %q, want wireguard-default-1234", got)
	}
	// Plain WireGuard type 4 is transport data under the default table.
	if _, err := engine.WriteInbound(awgDatagram(4, 200)); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	if got := engine.Status().TxTransportPayloadDatagram; got != 1 {
		t.Fatalf("tx_transport_payload_datagrams = %d, want 1", got)
	}
}

func TestCarrierFailureClearsUp(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if engine.Status().Up {
		t.Fatal("up is still true after Close")
	}
}

func TestParseConfigRejectsAmbiguousHeaderTypes(t *testing.T) {
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":7,"h2":7,"h3":33,"h4":44}}`)
	_, err := ParseConfig(blob)
	if err == nil {
		t.Fatal("duplicate header type values were accepted")
	}
	if !strings.Contains(err.Error(), "pairwise distinct") {
		t.Fatalf("error %q does not explain the constraint", err)
	}
}

func TestStatusJSONCarriesTheTransferProvenFields(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		obfuscatedConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	var decoded map[string]any
	if err := json.Unmarshal([]byte(engine.StatusJSON()), &decoded); err != nil {
		t.Fatalf("StatusJSON is not valid JSON: %v", err)
	}
	// These are the names the Windows and Android hosts read. Renaming one is
	// a contract change, so the names are pinned here rather than left to the
	// struct tags alone.
	for _, key := range []string{
		"up", "socket_owned_by_engine", "awg_classification",
		"tx_datagrams", "tx_bytes", "rx_datagrams", "rx_bytes",
		"tx_handshake_initiations", "tx_transport_datagrams",
		"tx_transport_payload_datagrams", "rx_handshake_responses",
		"rx_transport_datagrams", "rx_transport_payload_datagrams",
		"handshake_response_observed", "transport_observed_both_ways",
	} {
		if _, present := decoded[key]; !present {
			t.Errorf("status JSON is missing %q", key)
		}
	}
}
