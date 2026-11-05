package datapath

import (
	"errors"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
)

func configJSON(overrides string) []byte {
	// WINN_MANDATORY_HEADERS 2026-08-08: h1..h4 are REQUIRED; every valid config
	// must carry them, otherwise ParseConfig refuses (the gate would be blind).
	// This helper therefore includes a header table by default, matching the
	// hub's DEFAULT_OBFUSCATION, so tests that are not about headers do not have
	// to repeat it. Tests that need to exercise the missing-header refusal must
	// construct a blob without this field explicitly.
	base := `{"contract":"` + ContractVersion + `",` +
		`"payload":"` + PayloadAWGDatagram + `",` +
		`"carrier":"` + CarrierDirectAWG + `",` +
		`"gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,"s1":16,"s2":80,"s3":16,"s4":0}`
	if overrides != "" {
		base += "," + overrides
	}
	return []byte(base + "}")
}

func TestParseConfigDefaults(t *testing.T) {
	config, err := ParseConfig(configJSON(""))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if config.MaxDatagram != carrier.DefaultMaxDatagram {
		t.Fatalf("max_datagram default = %d, want %d",
			config.MaxDatagram, carrier.DefaultMaxDatagram)
	}
	if config.QueueDepth != DefaultQueueDepth {
		t.Fatalf("queue_depth default = %d, want %d",
			config.QueueDepth, DefaultQueueDepth)
	}
	if config.AllowOwnSocket {
		t.Fatal("allow_own_socket defaulted to true; it must fail closed")
	}
}

// TestParseConfigRefusesIPPacketPayload is the honesty test for the boundary
// this package draws. If someone later makes "ip-packet" parse without adding a
// real AmneziaWG encapsulator, this fails.
func TestParseConfigRefusesIPPacketPayload(t *testing.T) {
	// WINN_MANDATORY_HEADERS 2026-08-08: headers are required, so include them
	// to isolate the payload check.
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadIPPacket +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
	_, err := ParseConfig(blob)
	if !errors.Is(err, ErrPayloadUnimplemented) {
		t.Fatalf("ip-packet payload error = %v, want ErrPayloadUnimplemented", err)
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("refusal %q does not say why raw tun packets are refused", err)
	}
}

// TestParseConfigRefusesUnimplementedCarriers covers the carriers that
// internal/connectivity names but internal/carrier has no dialer for at all.
// They are refused at the configuration layer and stay refused.
//
// http3-connect-udp and http2-stream are deliberately NOT in this list any
// more: both dialers were converted to ride a caller-supplied, already-
// protected socket, so refusing them here would be refusing something that
// works. What they still need is a dialer, which is Open's refusal — see
// TestOpenRefusesACarrierItCannotBuild.
func TestParseConfigRefusesUnimplementedCarriers(t *testing.T) {
	for _, name := range []string{
		"reality-xhttp", "websocket-tls", "native-two-hop", "privacy-two-hop",
	} {
		// WINN_MANDATORY_HEADERS 2026-08-08: headers required, include them.
		blob := []byte(`{"contract":"` + ContractVersion +
			`","payload":"` + PayloadAWGDatagram +
			`","carrier":"` + name +
			`","gateway_endpoint":"203.0.113.9:51820",` +
			`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
		_, err := ParseConfig(blob)
		if !errors.Is(err, ErrCarrierUnimplemented) {
			t.Fatalf("carrier %q error = %v, want ErrCarrierUnimplemented", name, err)
		}
	}
}

// TestParseConfigAcceptsSuppliedSocketCarriers is the other half: the two
// converted carriers now pass validation.
func TestParseConfigAcceptsSuppliedSocketCarriers(t *testing.T) {
	for _, name := range []string{CarrierHTTP3, CarrierHTTP2} {
		// WINN_MANDATORY_HEADERS 2026-08-08: headers required.
		blob := []byte(`{"contract":"` + ContractVersion +
			`","payload":"` + PayloadAWGDatagram +
			`","carrier":"` + name +
			`","gateway_endpoint":"203.0.113.9:51820",` +
			`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
		config, err := ParseConfig(blob)
		if err != nil {
			t.Fatalf("carrier %q was refused: %v", name, err)
		}
		if config.Carrier != name {
			t.Fatalf("carrier = %q, want %q", config.Carrier, name)
		}
	}
}

func TestParseConfigRefusesHostnameGateway(t *testing.T) {
	for _, endpoint := range []string{
		"gateway.example.com:51820", "203.0.113.9", "0.0.0.0:51820",
		"203.0.113.9:0", "224.0.0.1:51820", "",
	} {
		// WINN_MANDATORY_HEADERS 2026-08-08: headers required, include them.
		blob := []byte(`{"contract":"` + ContractVersion +
			`","payload":"` + PayloadAWGDatagram +
			`","carrier":"` + CarrierDirectAWG +
			`","gateway_endpoint":"` + endpoint + `",` +
			`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
		if _, err := ParseConfig(blob); err == nil {
			t.Fatalf("gateway_endpoint %q was accepted", endpoint)
		}
	}
}

func TestParseConfigRejectsUnknownFieldsAndTrailingObjects(t *testing.T) {
	if _, err := ParseConfig(configJSON(`"max_datagrams":1300`)); err == nil {
		t.Fatal("a misspelled key was silently accepted")
	}
	doubled := append(configJSON(""), configJSON("")...)
	if _, err := ParseConfig(doubled); err == nil {
		t.Fatal("two concatenated JSON objects were accepted")
	}
}

func TestParseConfigBoundsDatagramAndQueue(t *testing.T) {
	cases := []string{
		`"max_datagram":31`,
		`"max_datagram":1501`,
		`"queue_depth":-1`,
		`"queue_depth":8193`,
	}
	for _, override := range cases {
		if _, err := ParseConfig(configJSON(override)); err == nil {
			t.Fatalf("%s was accepted", override)
		}
	}
	config, err := ParseConfig(configJSON(`"max_datagram":1500,"queue_depth":8192`))
	if err != nil {
		t.Fatalf("upper bounds rejected: %v", err)
	}
	if config.MaxDatagram != carrier.AbsoluteMaxDatagram {
		t.Fatalf("max_datagram = %d", config.MaxDatagram)
	}
}

func TestParseConfigRequiresMatchingContract(t *testing.T) {
	// WINN_MANDATORY_HEADERS 2026-08-08: headers required.
	blob := []byte(`{"contract":"winn-datapath/0","payload":"` +
		PayloadAWGDatagram + `","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
	if _, err := ParseConfig(blob); err == nil {
		t.Fatal("a mismatched contract version was accepted")
	}
}

// TestOpenRefusesToCreateItsOwnSocketByDefault is the Android loop guard. If
// this ever passes silently, an Android build without a protected descriptor
// would route its own carrier traffic back into the tunnel.
func TestOpenRefusesToCreateItsOwnSocketByDefault(t *testing.T) {
	engine, err := Open(configJSON(""), -1)
	if engine != nil {
		_ = engine.Close()
		t.Fatal("Open returned an engine with no descriptor and no permission")
	}
	if !errors.Is(err, ErrOwnSocketRefused) {
		t.Fatalf("Open error = %v, want ErrOwnSocketRefused", err)
	}
	if !strings.Contains(err.Error(), "VpnService.protect") {
		t.Fatalf("refusal %q does not name the Android requirement", err)
	}
}

func TestOpenWithAllowOwnSocketCreatesOne(t *testing.T) {
	gateway := newLoopbackGateway(t)
	// WINN_MANDATORY_HEADERS 2026-08-08: headers required.
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() +
		`","allow_own_socket":true,` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
	engine, err := Open(blob, -1)
	if err != nil {
		t.Fatalf("Open with allow_own_socket: %v", err)
	}
	defer func() { _ = engine.Close() }()
	if !engine.Status().SocketOwnedByEngine {
		t.Fatal("socket_owned_by_engine is false after the engine opened one")
	}
	if _, err := engine.WriteInbound([]byte("self-opened socket carries data")); err != nil {
		t.Fatalf("WriteInbound over a self-opened socket: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := gateway.ReadFromUDP(buffer); err != nil {
		t.Fatalf("gateway did not receive from the self-opened socket: %v", err)
	}
}

func TestOpenRejectsMalformedConfiguration(t *testing.T) {
	if _, err := Open([]byte("not json"), -1); err == nil {
		t.Fatal("malformed configuration was accepted")
	}
	if _, err := OpenWithPacketConn(Config{}, nil); err == nil {
		t.Fatal("a nil packet connection was accepted")
	}
}
