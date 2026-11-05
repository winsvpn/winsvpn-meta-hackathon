package datapath

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// newLoopbackGateway stands in for the Winn gateway: a real UDP socket on
// loopback that the engine's carrier writes to and reads from. Nothing is
// faked here — these are kernel sockets carrying real datagrams.
func newLoopbackGateway(t *testing.T) *net.UDPConn {
	t.Helper()
	gateway, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen loopback gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	return gateway
}

func newCarrierSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen carrier socket: %v", err)
	}
	return conn
}

func testConfig(gateway net.Addr) Config {
	return Config{
		Contract:        ContractVersion,
		Payload:         PayloadAWGDatagram,
		Carrier:         CarrierDirectAWG,
		GatewayEndpoint: gateway.String(),
		SessionID:       "loopback-test",
	}
}

// TestLoopbackDatagramTraversesEngineInBothDirections pushes datagrams in one
// end and observes them come out the other, in both directions, through a real
// socket. This is the test that would fail if the engine moved nothing.
func TestLoopbackDatagramTraversesEngineInBothDirections(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// host tun side -> Winn -> gateway
	outbound := []byte("winn-outer-datagram-host-to-gateway")
	written, err := engine.WriteInbound(outbound)
	if err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	if written != len(outbound) {
		t.Fatalf("WriteInbound wrote %d bytes, want %d", written, len(outbound))
	}

	received := make([]byte, 2048)
	if err := gateway.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set gateway read deadline: %v", err)
	}
	count, from, err := gateway.ReadFromUDP(received)
	if err != nil {
		t.Fatalf("gateway did not receive the datagram the engine sent: %v", err)
	}
	if !bytes.Equal(received[:count], outbound) {
		t.Fatalf("gateway received %q, want %q", received[:count], outbound)
	}

	// gateway -> Winn -> host tun side
	inbound := []byte("winn-outer-datagram-gateway-to-host")
	if _, err := gateway.WriteToUDP(inbound, from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	delivered := make([]byte, 2048)
	count, err = engine.ReadOutboundTimeout(delivered, 5*time.Second)
	if err != nil {
		t.Fatalf("ReadOutbound: %v", err)
	}
	if !bytes.Equal(delivered[:count], inbound) {
		t.Fatalf("ReadOutbound returned %q, want %q", delivered[:count], inbound)
	}

	status := engine.Status()
	if status.TxDatagrams != 1 || status.RxDatagrams != 1 {
		t.Fatalf("counters tx=%d rx=%d, want 1/1", status.TxDatagrams, status.RxDatagrams)
	}
	if status.TxBytes != uint64(len(outbound)) ||
		status.RxBytes != uint64(len(inbound)) {
		t.Fatalf("byte counters tx=%d rx=%d, want %d/%d",
			status.TxBytes, status.RxBytes, len(outbound), len(inbound))
	}
}

// TestLoopbackSustainedBurstPreservesEveryDatagram sends a burst larger than a
// single scheduling quantum and requires all of it back, in order. A datapath
// that dropped or reordered under load would fail here.
func TestLoopbackSustainedBurstPreservesEveryDatagram(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	const burst = 64
	// Echo every datagram straight back so one loop exercises both directions.
	go func() {
		buffer := make([]byte, 2048)
		for range burst {
			_ = gateway.SetReadDeadline(time.Now().Add(10 * time.Second))
			count, from, err := gateway.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if _, err := gateway.WriteToUDP(buffer[:count], from); err != nil {
				return
			}
		}
	}()

	for index := range burst {
		payload := []byte(strings.Repeat("W", 40) + string(rune('A'+index%26)))
		payload = append(payload, byte(index))
		if _, err := engine.WriteInbound(payload); err != nil {
			t.Fatalf("WriteInbound %d: %v", index, err)
		}
		echoed := make([]byte, 2048)
		count, err := engine.ReadOutboundTimeout(echoed, 10*time.Second)
		if err != nil {
			t.Fatalf("ReadOutbound %d: %v", index, err)
		}
		if !bytes.Equal(echoed[:count], payload) {
			t.Fatalf("echo %d mismatch: got %q want %q", index, echoed[:count], payload)
		}
	}

	status := engine.Status()
	if status.TxDatagrams != burst || status.RxDatagrams != burst {
		t.Fatalf("counters tx=%d rx=%d, want %d/%d",
			status.TxDatagrams, status.RxDatagrams, burst, burst)
	}
	if status.RxDropped != 0 {
		t.Fatalf("dropped %d datagrams in a synchronous echo loop", status.RxDropped)
	}
}

func TestReadOutboundTruncationReportsFullLength(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if _, err := engine.WriteInbound([]byte("prime the peer")); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	payload := bytes.Repeat([]byte("x"), 300)
	if _, err := gateway.WriteToUDP(payload, from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}

	small := make([]byte, 100)
	count, err := engine.ReadOutboundTimeout(small, 5*time.Second)
	if count != 100 {
		t.Fatalf("truncated read returned %d bytes, want 100", count)
	}
	if !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("truncated read error = %v, want ErrDatagramTooLarge", err)
	}
	if !strings.Contains(err.Error(), "300") {
		t.Fatalf("truncation error %q does not report the full length 300", err)
	}
}

// TestEngineRejectsDatagramFromForeignSender proves the engine will not hand
// the host bytes from anyone but the configured gateway. Without this an
// off-path sender could inject frames into the host's AWG engine.
func TestEngineRejectsDatagramFromForeignSender(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	local := engine.conn.LocalAddr().(*net.UDPAddr)
	foreign := newLoopbackGateway(t)
	if _, err := foreign.WriteToUDP([]byte("injected"), local); err != nil {
		t.Fatalf("foreign write: %v", err)
	}
	buffer := make([]byte, 2048)
	if _, err := engine.ReadOutboundTimeout(buffer, 300*time.Millisecond); !errors.Is(
		err, os.ErrDeadlineExceeded,
	) {
		t.Fatalf("foreign datagram was delivered to the host (err=%v)", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for engine.Status().RxForeign == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if engine.Status().RxForeign != 1 {
		t.Fatalf("rx_foreign_sender = %d, want 1", engine.Status().RxForeign)
	}
}

func TestWriteInboundRejectsOversizeAndEmpty(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := testConfig(gateway.LocalAddr())
	config.MaxDatagram = 200
	engine, err := OpenWithPacketConn(config, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if _, err := engine.WriteInbound(bytes.Repeat([]byte("z"), 201)); !errors.Is(
		err, ErrDatagramTooLarge,
	) {
		t.Fatalf("oversize WriteInbound error = %v, want ErrDatagramTooLarge", err)
	}
	if _, err := engine.WriteInbound(nil); err == nil {
		t.Fatal("empty WriteInbound was accepted")
	}
	if got := engine.Status().TxRejected; got != 2 {
		t.Fatalf("tx_rejected = %d, want 2", got)
	}
	if got := engine.Status().TxDatagrams; got != 0 {
		t.Fatalf("tx_datagrams = %d, want 0", got)
	}
}

func TestCloseIsIdempotentAndSynchronous(t *testing.T) {
	gateway := newLoopbackGateway(t)
	socket := newCarrierSocket(t)
	engine, err := OpenWithPacketConn(testConfig(gateway.LocalAddr()), socket)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Synchronous: the pump has already exited when Close returns.
	select {
	case <-engine.pumpDone:
	default:
		t.Fatal("Close returned before the carrier pump exited")
	}
	// The socket really is closed, not merely marked closed.
	if _, err := socket.WriteTo([]byte("after close"), gateway.LocalAddr()); !errors.Is(
		err, net.ErrClosed,
	) {
		t.Fatalf("carrier socket still writable after Close (err=%v)", err)
	}
	for range 3 {
		if err := engine.Close(); err != nil {
			t.Fatalf("repeat Close: %v", err)
		}
	}
	if _, err := engine.WriteInbound([]byte("after close")); !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteInbound after Close = %v, want ErrClosed", err)
	}
	if _, err := engine.ReadOutbound(make([]byte, 64)); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadOutbound after Close = %v, want ErrClosed", err)
	}
	if !engine.Status().Closed {
		t.Fatal("status does not report closed")
	}
}

func TestStatusJSONIsWellFormedAndHonest(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	var decoded Status
	decoder := json.NewDecoder(strings.NewReader(engine.StatusJSON()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("StatusJSON is not decodable into Status: %v", err)
	}
	if decoded.Contract != ContractVersion {
		t.Fatalf("contract = %q, want %q", decoded.Contract, ContractVersion)
	}
	if decoded.ProtocolVersion != "winn/3" {
		t.Fatalf("protocol_version = %q, want winn/3", decoded.ProtocolVersion)
	}
	if decoded.Payload != PayloadAWGDatagram || decoded.Carrier != CarrierDirectAWG {
		t.Fatalf("status payload/carrier = %q/%q", decoded.Payload, decoded.Carrier)
	}
	if decoded.GatewayEndpoint != gateway.LocalAddr().String() {
		t.Fatalf("gateway_endpoint = %q", decoded.GatewayEndpoint)
	}
	if decoded.LocalEndpoint == "" {
		t.Fatal("local_endpoint is empty")
	}
	// OpenWithPacketConn never creates a socket, so it must not claim to own one.
	if decoded.SocketOwnedByEngine {
		t.Fatal("socket_owned_by_engine is true for a caller-supplied connection")
	}
}

func TestReadOutboundTimeoutExpires(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	started := time.Now()
	if _, err := engine.ReadOutboundTimeout(
		make([]byte, 64), 120*time.Millisecond,
	); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("timeout error = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("ReadOutboundTimeout returned after %s, before its deadline", elapsed)
	}
}

// TestReadOutboundUnblocksOnClose is the property a host thread parked in a
// blocking read depends on. Without it, Close would deadlock the host.
func TestReadOutboundUnblocksOnClose(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, readErr := engine.ReadOutbound(make([]byte, 2048))
		result <- readErr
	}()
	time.Sleep(50 * time.Millisecond)
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case readErr := <-result:
		if !errors.Is(readErr, ErrClosed) {
			t.Fatalf("blocked ReadOutbound returned %v, want ErrClosed", readErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadOutbound did not unblock when the engine was closed")
	}
}

func TestNilEngineIsSafe(t *testing.T) {
	var engine *Engine
	if _, err := engine.WriteInbound([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil WriteInbound = %v", err)
	}
	if _, err := engine.ReadOutbound(make([]byte, 8)); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil ReadOutbound = %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("nil Close = %v", err)
	}
	if !engine.Status().Closed {
		t.Fatal("nil Status does not report closed")
	}
}
