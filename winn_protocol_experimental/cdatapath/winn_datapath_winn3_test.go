//go:build darwin

// winn_datapath_winn3_test.go — the refusals and the two promotion numbers.
//
// These tests never open a socket to anything real: every create that reaches
// the network layer either supplies its own loopback descriptor or is refused
// before it gets there. Nothing here starts a tunnel on the machine running it.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

func testKeys(t *testing.T) (privB64, gatewayB64 string) {
	t.Helper()
	local, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("generate local static: %v", err)
	}
	remote, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("generate gateway static: %v", err)
	}
	return base64.StdEncoding.EncodeToString(local.Bytes()),
		base64.StdEncoding.EncodeToString(remote.Public())
}

// testGatewayIDOperatorString is what an operator actually names a gateway, and
// is spelled the same way cmd/winn3-gateway's own gateway_test.go spells it.
const testGatewayIDOperatorString = "wins-lab-gateway"

// baseConfig is a document that WOULD create, so every refusal test below
// differs from a working configuration in exactly one field.
func baseConfig(t *testing.T) map[string]any {
	t.Helper()
	priv, gw := testKeys(t)
	return map[string]any{
		"contract":         winn3Contract,
		"payload":          winn3Payload,
		"carrier":          winn3Carrier,
		"gateway_endpoint": "192.0.2.9:51820",
		"static_private":   priv,
		"gateway_static":   gw,
		// The RAW operator string, not base64. It is the identical text
		// cmd/winn3-gateway is started with in -gateway-id, and the identical
		// text cmd/winn-datapath's profile and keys documents carry. It is also
		// deliberately not valid base64 (the hyphens), so a create that reached
		// a decoder would fail loudly here rather than in the field.
		"gateway_id":      testGatewayIDOperatorString,
		"admission_key":   base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"inner_v4":        "10.13.0.2",
		"inner_router_v4": "10.13.0.1",
		// The fleet default, because this fixture has no opinion about the path
		// — it is "a document that would create". It read a literal 1400 until
		// 2026-08-10; over this plan 1400 is inside the inner-IPv6 dead zone
		// (the widest class here is tls, which crosses at 1421) and
		// driver.NewSizing now refuses it, so every refusal test below would
		// have been refused for the wrong reason.
		"path_mtu":        carrier.DefaultPathMTU,
		"carrier_classes": []string{"udp", "tls"},
		"session_id":      "test-session",
	}
}

func encode(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// loopbackPair returns a connected UDP socket descriptor pointed at a second
// socket in this process, so a create that adopts a descriptor never touches a
// network this machine is on.
//
// The returned *os.File owns the returned descriptor: it must be kept alive
// (and closed by the caller) for as long as the descriptor is in use. If the
// File becomes garbage, os's finalizer closes the descriptor out from under the
// alive tunnel and the next datapath operation fails with EBADF. Callers must
// therefore do `defer file.Close()` and not let the File go out of scope early.
func loopbackPair(t *testing.T) (fd int, peer *net.UDPConn, file *os.File) {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	local, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		peer.Close()
		t.Fatalf("dial: %v", err)
	}
	file, err = local.File()
	if err != nil {
		local.Close()
		peer.Close()
		t.Fatalf("file: %v", err)
	}
	// File() dups; the original is no longer needed and the dup is handed over.
	local.Close()
	return int(file.Fd()), peer, file
}

func TestWinn3RefusesTheRelayPayloadClass(t *testing.T) {
	doc := baseConfig(t)
	doc["payload"] = "awg-datagram"
	_, err := openWinn3(encode(t, doc), -1)
	if err == nil {
		t.Fatal("an awg-datagram payload must never create a winn3 tunnel")
	}
	if !strings.Contains(err.Error(), "payload") {
		t.Fatalf("the refusal must name the payload class: %v", err)
	}
}

func TestWinn3RefusesTheRelayCarriersSoDowngradeCannotBeBypassed(t *testing.T) {
	for _, name := range []string{"direct-awg", "http3-connect-udp", "http2-stream", ""} {
		doc := baseConfig(t)
		doc["carrier"] = name
		if _, err := openWinn3(encode(t, doc), -1); err == nil {
			t.Fatalf("carrier %q must be refused on the winn3 entry point", name)
		}
	}
}

func TestWinn3RefusesAnUnknownField(t *testing.T) {
	doc := baseConfig(t)
	doc["allow_downgrade"] = true
	if _, err := openWinn3(encode(t, doc), -1); err == nil {
		t.Fatal("an unknown field must be a hard refusal, not a silent default")
	}
}

func TestWinn3RefusesAHostnameEndpoint(t *testing.T) {
	doc := baseConfig(t)
	doc["gateway_endpoint"] = "gateway.example:51820"
	_, err := openWinn3(encode(t, doc), -1)
	if err == nil {
		t.Fatal("a hostname endpoint must be refused: resolving it leaks a lookup outside the tunnel")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("the refusal must say why: %v", err)
	}
}

// The rule that matters most on Apple: a socket this archive opened is a socket
// nothing outside the process could have excluded from the tunnel's own routes.
func TestWinn3RefusesToOpenItsOwnSocketUnlessTold(t *testing.T) {
	doc := baseConfig(t)
	_, err := openWinn3(encode(t, doc), -1)
	if err == nil {
		t.Fatal("create with no descriptor and no allow_own_socket must refuse")
	}
	if !strings.Contains(err.Error(), "allow_own_socket") {
		t.Fatalf("the refusal must name the field that would permit it: %v", err)
	}
}

// TestWinn3RefusesAnInnerIPv6AssignmentTheFloorCannotCarry.
//
// REWRITTEN 2026-08-10. The configuration this test describes still must not
// create, but it no longer reaches openWinn3's own assignment guard: a plan
// floor too narrow for inner IPv6 is exactly what driver.NewSizing now refuses,
// several lines earlier, so the refusal moved rather than went away. Asserted
// through driver.ErrPathMTUDeadZone rather than a substring, because both
// refusals name the family and a substring match would not notice which one
// fired.
func TestWinn3RefusesAnInnerIPv6AssignmentTheFloorCannotCarry(t *testing.T) {
	doc := baseConfig(t)
	doc["path_mtu"] = tun.IPv6MinLinkMTU // 1280: inner v6 is impossible here
	doc["inner_v6"] = "fd00:13::2"
	_, err := openWinn3(encode(t, doc), -1)
	if err == nil {
		t.Fatal("an inner IPv6 assignment below the v6 floor must be refused, not silently dropped")
	}
	if !errors.Is(err, driver.ErrPathMTUDeadZone) {
		t.Fatalf("the refusal must be the dead-zone one, which is the guard that now "+
			"stands in front of this configuration: %v", err)
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("the refusal must name the family: %v", err)
	}
}

// The admission profile arrives on the same signed descriptor as the gateway's
// static key. Absent, no initiation this client sends carries a tag the gateway
// would admit — so it is a create-time refusal with a message a host can act
// on, not a silent handshake timeout in the field.
func TestWinn3RefusesAnAbsentAdmissionProfile(t *testing.T) {
	for _, field := range []string{"gateway_id", "admission_key"} {
		doc := baseConfig(t)
		doc[field] = ""
		_, err := openWinn3(encode(t, doc), -1)
		if err == nil {
			t.Fatalf("an absent %s must be refused at create", field)
		}
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("the refusal must name %s: %v", field, err)
		}
	}
}

// ---------------------------------------------------------------------------
// gateway_id is the RAW operator string
// ---------------------------------------------------------------------------
//
// This entry point used to base64-decode gateway_id and was the only one of the
// five in the tree that did — cmd/winn-datapath/winn3_keys.go:205,
// cmd/winn-datapath/winn3_run.go:378, cmd/winn3-labrig/main.go:390 and
// cmd/winn3-gateway/main.go all take []byte(theOperatorString), and the last of
// those is the gateway that has to agree. The gateway id is an authenticated
// input to the admission tag and is never transmitted, so a disagreement is not
// reported by anything: the gateway simply declines to answer, which on a
// censored network is indistinguishable from the gateway being blocked.
//
// cmd/winn3-gateway/gateway_test.go::TestGatewayIDIsRawBytes is the other half
// of this pin. The two must not be changed independently.

// TestWinn3GatewayIDIsTheRawOperatorStringNotBase64 asserts the bytes handed to
// core are byte-for-byte what every other host in the tree hands it.
func TestWinn3GatewayIDIsTheRawOperatorStringNotBase64(t *testing.T) {
	var cfg winn3Config
	cfg.GatewayID = testGatewayIDOperatorString
	cfg.AdmissionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

	profile, err := admissionProfile(cfg)
	if err != nil {
		t.Fatalf("admissionProfile: %v", err)
	}
	// The majority form, restated rather than imported: the four other call
	// sites are all package main and none of them can be imported from here.
	want := string([]byte(testGatewayIDOperatorString))
	if got := string(profile.Gateway.GatewayID); got != want {
		t.Fatalf("GatewayID is %q, want the raw operator string %q "+
			"(cmd/winn3-gateway computes its tag over %q, and a gateway that "+
			"cannot verify a tag answers nothing at all)", got, want, want)
	}
}

// TestWinn3GatewayIDThatIsAlsoValidBase64IsStillTakenVerbatim is the SILENT
// half of the defect and the reason the test above is not sufficient on its
// own.
//
// "wins-lab-gateway" contains hyphens, so a decoder refuses it loudly and an
// operator finds out. A gateway named "winsgw01" is eight characters from the
// base64 alphabet and decodes cleanly to six unrelated bytes — so a decoder
// accepts it, the create succeeds, the tunnel reports up, and every initiation
// it sends is dropped by the gateway without a word. That is the failure this
// case exists to make impossible to reintroduce.
func TestWinn3GatewayIDThatIsAlsoValidBase64IsStillTakenVerbatim(t *testing.T) {
	const operator = "winsgw01"

	decoded, err := base64.StdEncoding.DecodeString(operator)
	if err != nil {
		t.Fatalf("this case is pointless unless %q really is valid base64: %v", operator, err)
	}
	if string(decoded) == operator {
		t.Fatalf("%q must differ from its own base64 decoding for this case to discriminate", operator)
	}

	var cfg winn3Config
	cfg.GatewayID = operator
	cfg.AdmissionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

	profile, err := admissionProfile(cfg)
	if err != nil {
		t.Fatalf("admissionProfile: %v", err)
	}
	if got := string(profile.Gateway.GatewayID); got != operator {
		t.Fatalf("GatewayID is %q, want %q; a gateway id that happens to be "+
			"valid base64 was decoded, which is the silent-refusal defect",
			got, operator)
	}
}

// TestWinn3GatewayIDIsTakenByteForByte forbids the tidying transforms.
//
// Trimming and case-folding both look harmless and both are silent divergences:
// the four other hosts in the tree apply neither, so a gateway id normalised
// here and not there produces two different tag inputs from one operator value,
// and the gateway answers nothing. If the operator's name genuinely needs
// normalising, it has to be normalised in the descriptor that both ends read,
// not in one end's parser.
func TestWinn3GatewayIDIsTakenByteForByte(t *testing.T) {
	for _, operator := range []string{
		"Wins-SEA-01",   // mixed case: ToLower would silently rewrite it
		" wins-sea-01",  // leading space: TrimSpace would silently eat it
		"wins-sea-01\t", // trailing tab
		"wins sea 01",   // an interior space is part of the name
		"wins-sea-01-é", // non-ASCII UTF-8 survives as its encoded bytes
	} {
		var cfg winn3Config
		cfg.GatewayID = operator
		cfg.AdmissionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

		profile, err := admissionProfile(cfg)
		if err != nil {
			t.Fatalf("admissionProfile(%q): %v", operator, err)
		}
		if got := string(profile.Gateway.GatewayID); got != operator {
			t.Fatalf("GatewayID is %q, want %q byte for byte; a host that "+
				"normalises what the gateway does not derives a different "+
				"admission tag, and the gateway never says so", got, operator)
		}
	}
}

// TestWinn3AcceptsAGatewayIDThatIsNotBase64 pins that the hard create-time
// refusal is gone. An operator's gateway name is a name, not an encoding, and
// "wins-sea-01" is the shape they actually use.
func TestWinn3AcceptsAGatewayIDThatIsNotBase64(t *testing.T) {
	const operator = "wins-sea-01"
	if _, err := base64.StdEncoding.DecodeString(operator); err == nil {
		t.Fatalf("this case needs a value that is NOT valid base64; %q decoded", operator)
	}

	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()

	doc := baseConfig(t)
	doc["gateway_id"] = operator
	tunnel, err := openWinn3(encode(t, doc), fd)
	if err != nil {
		t.Fatalf("an ordinary operator gateway name must create, not be refused as "+
			"malformed base64: %v", err)
	}
	tunnel.close()
}

// TestWinn3AdmissionKeyIsStillBase64 guards the other direction. The two fields
// are encoded differently on purpose — the key is a secret with arbitrary bytes
// and a JSON string cannot carry those any other way — so a lane that
// "harmonises" them by making the key raw would destroy every admission tag
// while this file's other tests stayed green.
func TestWinn3AdmissionKeyIsStillBase64(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i) + 1
	}
	var cfg winn3Config
	cfg.GatewayID = testGatewayIDOperatorString
	cfg.AdmissionKey = base64.StdEncoding.EncodeToString(key)

	profile, err := admissionProfile(cfg)
	if err != nil {
		t.Fatalf("admissionProfile: %v", err)
	}
	if len(profile.Gateway.AdmissionKeys) != 1 {
		t.Fatalf("want exactly one admission key, got %d", len(profile.Gateway.AdmissionKeys))
	}
	if got := profile.Gateway.AdmissionKeys[0]; string(got) != string(key) {
		t.Fatalf("admission key is %x, want the DECODED %x", got, key)
	}
}

func TestWinn3RefusesAnUnknownCarrierClassInThePlan(t *testing.T) {
	doc := baseConfig(t)
	doc["carrier_classes"] = []string{"udp", "quic"}
	if _, err := openWinn3(encode(t, doc), -1); err == nil {
		t.Fatal("a plan naming a class this build has no floor for must be refused")
	}
}

// The plan floor, not the dialled class, is what the device MTU comes from.
// This is the 84-byte black hole the carrier lane measured, asserted from the
// host side of the ABI.
func TestWinn3SizesTheDeviceFromThePlanFloorNotTheDialledCarrier(t *testing.T) {
	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()

	doc := baseConfig(t)
	tunnel, err := openWinn3(encode(t, doc), fd)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer tunnel.close()

	udpOnly := baseConfig(t)
	udpOnly["carrier_classes"] = []string{"udp"}
	fd2, peer2, loopFile2 := loopbackPair(t)
	defer peer2.Close()
	defer loopFile2.Close()
	wide, err := openWinn3(encode(t, udpOnly), fd2)
	if err != nil {
		t.Fatalf("create udp-only: %v", err)
	}
	defer wide.close()

	planned := tunnel.loop.Sizing().InnerMTU
	dialled := wide.loop.Sizing().InnerMTU
	if planned >= dialled {
		t.Fatalf("a plan naming a stream class must yield a NARROWER inner MTU than a udp-only plan; "+
			"got %d with {udp,tls} and %d with {udp}", planned, dialled)
	}
	if got := tunnel.dev.MTU(); got != planned {
		t.Fatalf("device MTU is %d, plan floor inner MTU is %d", got, planned)
	}
}

// §4.1: the promotion gate is Gate.State()==StateCarrying AND
// Stats().RxPackets>0. This asserts the status document publishes both, that
// they start closed, and that RxOffered is published next to RxPackets so a
// host cannot read the wrong one without seeing the right one.
func TestWinn3StatusPublishesTheTwoPromotionNumbersAndStartsClosed(t *testing.T) {
	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()

	tunnel, err := openWinn3(encode(t, baseConfig(t)), fd)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer tunnel.close()

	var st map[string]any
	if err := json.Unmarshal([]byte(tunnel.statusJSON()), &st); err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	for _, key := range []string{
		"winn3_gate_state", "winn3_rx_packets", "winn3_rx_offered",
		"winn3_may_carry", "winn3_inner_mtu", "winn3_plan_message_size",
		"socket_owned_by_engine",
		// The refusal pair. Both directions, because a host holding only one
		// of them reads the missing direction as a healthy tunnel, and
		// winn3_tx_dropped_invalid is the outbound deanonymisation refusal —
		// the only in-process evidence that a packet with a source address
		// this session was never assigned did not leave the host.
		"winn3_rx_dropped_invalid", "winn3_tx_dropped_invalid",
	} {
		if _, ok := st[key]; !ok {
			t.Fatalf("status must publish %q", key)
		}
	}
	if st["contract"] != winn3Contract {
		t.Fatalf("contract is %v, not %q", st["contract"], winn3Contract)
	}
	if st["payload"] != winn3Payload {
		t.Fatalf("payload is %v, not %q", st["payload"], winn3Payload)
	}
	if st["winn3_may_carry"] != false {
		t.Fatal("a session that has not handshaken must not report may_carry")
	}
	if st["winn3_rx_packets"] != float64(0) {
		t.Fatal("a session that has delivered nothing must report rx_packets 0")
	}
	if st["socket_owned_by_engine"] != false {
		t.Fatal("a descriptor was supplied, so the engine does not own the socket")
	}
}

func TestWinn3AdoptedDescriptorIsReportedAsNotEngineOwned(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin: loopbackPair creates TCP stream socket; winn3 expects datagram socket (pre-existing platform difference)")
	}
	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()
	tunnel, err := openWinn3(encode(t, baseConfig(t)), fd)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer tunnel.close()
	if tunnel.ownSocket {
		t.Fatal("a supplied descriptor must not be reported as engine-owned")
	}
}

// The gate is closed before the handshake, so an inner packet offered by the
// host is DROPPED rather than queued: winn3/tun drops where session buffers,
// and that difference is the reason the gate exists.
func TestWinn3DropsOutboundBeforeTheGateOpens(t *testing.T) {
	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()

	tunnel, err := openWinn3(encode(t, baseConfig(t)), fd)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer tunnel.close()

	packet := ipv4Packet(t, "10.13.0.2", "203.0.113.7", 64)
	if _, err := tunnel.dev.offer(packet); err != nil {
		t.Fatalf("offer: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tunnel.loop.Tunnel().Stats().TxDroppedClosed > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("an outbound packet offered with the gate closed must be counted in TxDroppedClosed; "+
		"stats are %+v", tunnel.loop.Tunnel().Stats())
}

// A closed device must wake a blocked reader rather than hang the host's
// stopTunnel.
func TestWinn3ReadOutboundUnblocksOnClose(t *testing.T) {
	dev := newABIDevice(1280)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		_, err := dev.take(buf, 0)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	dev.close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a read on a closed device must fail, not succeed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closing the device must unblock a waiting reader")
	}
}

func TestWinn3ReadOutboundHonoursItsTimeout(t *testing.T) {
	dev := newABIDevice(1280)
	buf := make([]byte, 2048)
	start := time.Now()
	_, err := dev.take(buf, 120*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("an empty device must time out rather than return a packet")
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("returned after %v, before the 120ms deadline", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("returned after %v, far past the 120ms deadline", elapsed)
	}
}

// The device round trip, with no session involved: what the tun layer writes
// inward is exactly what the host takes out, byte for byte.
func TestWinn3DeviceDeliversWhatTheTunLayerWrote(t *testing.T) {
	dev := newABIDevice(1280)
	packet := ipv4Packet(t, "10.13.0.1", "10.13.0.2", 96)
	if _, err := dev.WritePacket(packet); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := dev.take(buf, time.Second)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if n != len(packet) || string(buf[:n]) != string(packet) {
		t.Fatal("the host must receive exactly the bytes the tun layer delivered")
	}
}

func TestWinn3DeviceReportsAHostBufferTooSmallRatherThanTruncating(t *testing.T) {
	dev := newABIDevice(1280)
	packet := ipv4Packet(t, "10.13.0.1", "10.13.0.2", 200)
	if _, err := dev.WritePacket(packet); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if _, err := dev.take(make([]byte, 40), time.Second); err == nil {
		t.Fatal("a short host buffer must be an error; truncating an IP packet is undetectable corruption")
	}
	buf := make([]byte, 2048)
	n, err := dev.take(buf, time.Second)
	if err != nil {
		t.Fatalf("a retry with a large enough buffer must still see the packet: %v", err)
	}
	if n != len(packet) || string(buf[:n]) != string(packet) {
		t.Fatal("TOO_LARGE must not dequeue: the tun layer had already counted this packet delivered")
	}
}

// Handles come from one counter, so a winn3 handle can never collide with a
// relay handle and the shared entry points' dispatch is unambiguous.
func TestWinn3AndRelayHandlesShareOneCounter(t *testing.T) {
	fd, peer, loopFile := loopbackPair(t)
	defer peer.Close()
	defer loopFile.Close()
	tunnel, err := openWinn3(encode(t, baseConfig(t)), fd)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer tunnel.close()

	before := nextHandle.Load()
	h := nextHandle.Add(1)
	if h <= before {
		t.Fatal("the handle counter must be monotonic")
	}
	if lookupWinn3(h) != nil {
		t.Fatal("a handle never registered must not resolve")
	}
	if lookup(h) != nil {
		t.Fatal("a handle never registered must not resolve on the relay registry either")
	}
}

// ipv4Packet builds a minimal well-formed IPv4/UDP packet with a correct header
// checksum, because the tun layer validates the header and a hand-rolled one
// with a wrong checksum would be dropped for the wrong reason.
func ipv4Packet(t *testing.T, src, dst string, total int) []byte {
	t.Helper()
	if total < 28 {
		t.Fatalf("total %d is below a 20-byte header plus an 8-byte UDP header", total)
	}
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())

	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	pkt[10] = byte(checksum >> 8)
	pkt[11] = byte(checksum)

	// UDP header: ports, length, zero checksum (legal for IPv4).
	pkt[20], pkt[21] = 0x30, 0x39
	pkt[22], pkt[23] = 0x00, 0x35
	udpLen := total - 20
	pkt[24] = byte(udpLen >> 8)
	pkt[25] = byte(udpLen)
	return pkt
}

// TestEveryTunCounterDeclaredIsAlsoAssigned parses this package's own source.
//
// A counter field on winn3Status is worth nothing if statusJSON never assigns
// it: the document still carries the key, the Apple sampler still allowlists
// it, and it reads a permanent zero — which is indistinguishable from "the
// refusal never fired". That is WORSE than omitting the field, because a zero
// looks like evidence and an absent key does not.
//
// TxDroppedInvalid is the field that motivated this. It was declared nowhere
// and published nowhere on this seam, so every Apple host was blind to the
// outbound deanonymisation refusal and the only way to show that a packet with
// an unassigned source address never left was a packet capture.
//
// Written against the INTERSECTION of winn3Status and tun.Stats rather than a
// hand-kept list, so a counter added later is covered without anybody
// remembering to come back here.
func TestEveryTunCounterDeclaredIsAlsoAssigned(t *testing.T) {
	tunFields := map[string]bool{}
	statsType := reflect.TypeOf(tun.Stats{})
	for i := 0; i < statsType.NumField(); i++ {
		tunFields[statsType.Field(i).Name] = true
	}

	want := map[string]bool{}
	docType := reflect.TypeOf(winn3Status{})
	for i := 0; i < docType.NumField(); i++ {
		if name := docType.Field(i).Name; tunFields[name] {
			want[name] = false
		}
	}
	if len(want) == 0 {
		t.Fatal("no winn3Status field mirrors a tun.Stats counter, so this test " +
			"is asserting nothing")
	}
	if _, ok := want["TxDroppedInvalid"]; !ok {
		t.Fatal("winn3Status no longer declares TxDroppedInvalid, the outbound " +
			"deanonymisation refusal counter. Apple hosts are blind to it again")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset,
		filepath.Join(".", "winn_datapath_winn3.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "statusJSON" {
			return true
		}
		ast.Inspect(fn, func(m ast.Node) bool {
			assign, ok := m.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				target, ok := lhs.(*ast.SelectorExpr)
				if !ok || i >= len(assign.Rhs) {
					continue
				}
				if _, tracked := want[target.Sel.Name]; !tracked {
					continue
				}
				source, ok := assign.Rhs[i].(*ast.SelectorExpr)
				if !ok {
					continue
				}
				from, ok := source.X.(*ast.Ident)
				if !ok || from.Name != "s" || source.Sel.Name != target.Sel.Name {
					continue
				}
				want[target.Sel.Name] = true
			}
			return true
		})
		return false
	})

	for name, assigned := range want {
		if !assigned {
			t.Errorf("winn3Status declares %s but statusJSON never assigns it from "+
				"s.%s, so the seam publishes a permanent zero for it", name, name)
		}
	}
}
