package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The frame mode's refusals, attacked one at a time.
//
// Every test below asserts a REFUSAL and names the sentence it must contain,
// because the failure mode this mode exists to prevent is not a crash: it is a
// tunnel that starts and works and is the wrong protocol, or the right protocol
// at the wrong size. A guard that fires with an unrecognisable message is a
// guard the next lane deletes.

// validCreate is the Android host's own document, with the ONE number corrected.
//
// WinnV3EngineConfig's test fixture sends inner_mtu 1443 at path_mtu 1500 over
// carrier_classes [udp,tcp,tls]. 1443 is InnerMTUForPath(1500, 28) — the OVERHEAD
// OF A DIALLED UDP-OVER-IPV4 CARRIER — and the plan floor over those three
// classes at that path MTU is 1359. The 84-byte difference is exactly the black
// hole this seam refuses; see TestTheAndroidFixtureIsRefused.
func validCreate() map[string]any {
	return map[string]any{
		"payload":          "ip-packet",
		"gateway_endpoint": "127.0.0.1:51820",
		"inner_address":    "10.8.1.3",
		"inner_next_hop":   "10.8.1.1",
		"inner_mtu":        1359,
		"path_mtu":         1500,
		"carrier_classes":  []string{"udp", "tcp", "tls"},
		"session_id":       "session-1",
		"allow_own_socket": false,
		"owns_tun":         false,
	}
}

func createBytes(t *testing.T, document map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestTheFloorIsTheOnlyAcceptableInnerMTU is the 84-byte guard.
func TestTheFloorIsTheOnlyAcceptableInnerMTU(t *testing.T) {
	plan, err := decodeWinn3Create(createBytes(t, validCreate()), true, false)
	if err != nil {
		t.Fatalf("the corrected document was refused: %v", err)
	}
	if plan.sizing.InnerMTU != 1359 {
		t.Fatalf("plan floor inner MTU = %d, want 1359", plan.sizing.InnerMTU)
	}
	if plan.sizing.MessageSize != 1388 {
		t.Fatalf("plan floor message size = %d, want 1388", plan.sizing.MessageSize)
	}

	for _, mtu := range []int{1443, 1360, 1358, 576} {
		document := validCreate()
		document["inner_mtu"] = mtu
		_, err := decodeWinn3Create(createBytes(t, document), true, false)
		if err == nil {
			t.Fatalf("inner_mtu %d was accepted; only the floor may be", mtu)
		}
		if !strings.Contains(err.Error(), "plan floor") {
			t.Fatalf("inner_mtu %d refusal does not name the floor: %v", mtu, err)
		}
	}
}

// TestTheAndroidFixtureIsRefused runs the exact bytes WinnV3EngineConfig.toJson
// produces for its own test fixture.
//
// It is refused, and that is the finding: the number in the shipping host's
// fixture is the dialled carrier's inner MTU, not the plan's. A seam that
// accepted it would carry small packets perfectly and black-hole every full-size
// flow the moment the session migrated off UDP — while the tunnel still read
// "up" at both ends.
func TestTheAndroidFixtureIsRefused(t *testing.T) {
	fixture := []byte(`{"payload":"ip-packet",` +
		`"gateway_endpoint":"203.0.113.9:51820","inner_address":"10.8.1.3",` +
		`"inner_next_hop":"10.8.1.1","inner_mtu":1443,"path_mtu":1500,` +
		`"carrier_classes":["udp","tcp","tls"],"session_id":"session-1",` +
		`"allow_own_socket":false,"owns_tun":false}`)
	_, err := decodeWinn3Create(fixture, true, false)
	if err == nil {
		t.Fatal("the Android fixture was accepted; the 84-byte gap is unguarded")
	}
	for _, want := range []string{"1443", "1359", "black-hole"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

// TestThePayloadClassIsCheckedFirst pins the ordering.
//
// It matters because the other refusals are about correctness and this one is
// about cleartext: a document that is wrong about the payload AND wrong about
// everything else must still be refused for the payload, so the message a host
// logs is the one that explains the risk.
func TestThePayloadClassIsCheckedFirst(t *testing.T) {
	document := validCreate()
	document["payload"] = "awg-datagram"
	document["inner_mtu"] = 1443
	document["carrier_classes"] = []string{}
	document["gateway_endpoint"] = "not-an-endpoint"

	_, err := decodeWinn3Create(createBytes(t, document), true, false)
	if err == nil {
		t.Fatal("an awg-datagram document was accepted by the v3 frame mode")
	}
	if !strings.Contains(err.Error(), "winn/1 relay class") {
		t.Fatalf("refusal is not the payload one: %v", err)
	}
	if !strings.Contains(err.Error(), "double-encrypt") {
		t.Fatalf("refusal does not say what would happen: %v", err)
	}

	document["payload"] = ""
	if _, err := decodeWinn3Create(createBytes(t, document), true, false); err == nil ||
		!strings.Contains(err.Error(), "ip-packet") {
		t.Fatalf("an empty payload was not refused by class: %v", err)
	}
}

// TestTheSocketRuleHasNoPermissiveBranch walks all four combinations of
// allow_own_socket and a supplied descriptor, plus the exclusion.
func TestTheSocketRuleHasNoPermissiveBranch(t *testing.T) {
	cases := []struct {
		name              string
		allowOwn          bool
		hasDescriptor     bool
		exclusionDeclared bool
		wantErr           string
	}{
		{"mobile: descriptor handed over", false, true, false, ""},
		{"desktop: own socket with an exclusion", true, false, true, ""},
		{"neither", false, false, false, "no descriptor was handed over"},
		{"both", true, true, true, "one of the two documents is wrong"},
		{"own socket, no exclusion", true, false, false, "declares no"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := validCreate()
			document["allow_own_socket"] = tc.allowOwn
			_, err := decodeWinn3Create(
				createBytes(t, document), tc.hasDescriptor, tc.exclusionDeclared)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("refused a legitimate combination: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatal("accepted a combination that leaves the socket unprotected")
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("refusal %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestTheCreateRefusalsHaveTeeth is the flat sweep: one broken field each,
// every one refused, and the refusal names the field.
func TestTheCreateRefusalsHaveTeeth(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{"owns_tun", func(d map[string]any) { d["owns_tun"] = true }, "owns_tun"},
		{"no classes", func(d map[string]any) {
			d["carrier_classes"] = []string{}
		}, "carrier_classes is empty"},
		{"unknown class", func(d map[string]any) {
			d["carrier_classes"] = []string{"udp", "quic"}
		}, "unknown carrier class"},
		{"no udp in the plan", func(d map[string]any) {
			d["carrier_classes"] = []string{"tcp", "tls"}
			d["inner_mtu"] = 1359
		}, "only class this build can dial"},
		{"hostname endpoint", func(d map[string]any) {
			d["gateway_endpoint"] = "gateway.example:51820"
		}, "DNS lookup on the censored path"},
		{"port zero", func(d map[string]any) {
			d["gateway_endpoint"] = "127.0.0.1:0"
		}, "port 0"},
		{"no inner address", func(d map[string]any) {
			d["inner_address"] = ""
		}, "inner_address is empty"},
		{"next hop of the wrong family", func(d map[string]any) {
			d["inner_next_hop"] = "fd00::1"
		}, "not the same family"},
		{"misspelled key", func(d map[string]any) {
			d["inner_mtus"] = 1359
		}, "unknown field"},
		{"negative path mtu", func(d map[string]any) {
			d["path_mtu"] = -1
		}, "negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := validCreate()
			tc.mutate(document)
			_, err := decodeWinn3Create(createBytes(t, document), true, false)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("refusal %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestInnerIPv6NeedsAFloorThatCanCarryIt.
//
// An inner IPv6 assignment under a floor below RFC 8200's 1280-byte link MTU is
// a tunnel that drops all of its own v6 traffic. The refusal names the path MTU
// that would be needed, because a host cannot act on "refused".
//
// REWRITTEN 2026-08-10. The document below is now refused EARLIER than it was:
// a plan floor too narrow for inner IPv6 is precisely the dead zone
// driver.NewSizing refuses, and the create seam calls it before it ever looks
// at the assignment — so winn3_create.go's own "inner_address is IPv6 and this
// plan needs…" guard cannot be reached by lowering the path MTU any more. The
// property under test is unchanged (this configuration must not build) and so
// is the requirement that the refusal name the number to change; what moved is
// which guard says it, and the assertions follow it rather than pretending
// otherwise.
func TestInnerIPv6NeedsAFloorThatCanCarryIt(t *testing.T) {
	document := validCreate()
	document["inner_address"] = "fd00:d951:1::3"
	document["inner_next_hop"] = "fd00:d951:1::1"
	document["path_mtu"] = 1280
	document["inner_mtu"] = 1139 // the floor at 1280 over udp+tcp+tls

	_, err := decodeWinn3Create(createBytes(t, document), true, false)
	if err == nil {
		t.Fatal("an inner IPv6 tunnel was built at a floor that cannot carry it")
	}
	if !errors.Is(err, driver.ErrPathMTUDeadZone) {
		t.Fatalf("the refusal is not the dead-zone one, which is the guard that now stands "+
			"in front of this document: %v", err)
	}
	if !strings.Contains(err.Error(), "carrying IPv6") {
		t.Fatalf("refusal does not name the family: %v", err)
	}
	// The number the operator has to type, which is the whole reason this
	// refusal is worth having: 1421 for udp+tcp+tls, set by tls over IPv6.
	if !strings.Contains(err.Error(), "1421") {
		t.Fatalf("refusal does not name the path MTU this plan needs, so a host cannot act "+
			"on it: %v", err)
	}

	// And it is allowed once the path MTU can carry it, so the guard is about
	// the number and not about IPv6.
	sizing, err := driver.NewSizing(1500, mustClasses(t, "udp", "tcp", "tls")...)
	if err != nil {
		t.Fatal(err)
	}
	if !sizing.InnerIPv6 {
		t.Skip("the floor at 1500 cannot carry inner IPv6 on this build")
	}
	document["path_mtu"] = 1500
	document["inner_mtu"] = sizing.InnerMTU
	if _, err := decodeWinn3Create(createBytes(t, document), true, false); err != nil {
		t.Fatalf("a legitimate inner IPv6 tunnel was refused: %v", err)
	}
}

// --- the key document ---------------------------------------------------------

func validKeys(t *testing.T, dir string) map[string]any {
	t.Helper()
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"version":             winn3KeysVersion,
		"role":                "client",
		"gateway_id":          "lab-gateway",
		"static_path":         write("static.key", static.Bytes()),
		"gateway_static_path": write("gateway.pub", gateway.Public()),
		"admission_path":      write("admission.key", []byte("lab-admission-secret-padded-to-32-bytes")),
	}
}

// mustClasses resolves plan names through the shipping parser.
func mustClasses(t *testing.T, names ...string) []carrier.Class {
	t.Helper()
	out := make([]carrier.Class, 0, len(names))
	for _, name := range names {
		class, err := winn3ClassNamed(name)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, class)
	}
	return out
}

func writeKeys(t *testing.T, dir string, document map[string]any) string {
	t.Helper()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheKeyDocumentLoadsAndCarriesNoSecret(t *testing.T) {
	dir := t.TempDir()
	document := validKeys(t, dir)
	keys, err := loadWinn3Keys(writeKeys(t, dir, document))
	if err != nil {
		t.Fatalf("a valid key document was refused: %v", err)
	}
	if _, _, err := keys.sessionConfig(); err != nil {
		t.Fatalf("the session configuration would not build: %v", err)
	}

	// The log line is what a support ticket carries out of the country. It must
	// name no path, no key and no address.
	line := keys.describeForLog()
	for _, forbidden := range []string{
		dir, "static.key", "gateway.pub", "admission.key", "lab-admission-secret-padded-to-32-bytes",
	} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("the log line leaks %q: %q", forbidden, line)
		}
	}
}

func TestTheRekeyKnobOnlyTightens(t *testing.T) {
	dir := t.TempDir()
	document := validKeys(t, dir)

	document["rekey_after_messages"] = 8
	keys, err := loadWinn3Keys(writeKeys(t, dir, document))
	if err != nil {
		t.Fatalf("a lowered rekey volume was refused: %v", err)
	}
	cfg, _, err := keys.sessionConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RekeyAfterMessages != 8 {
		t.Fatalf("rekey volume = %d, want 8", cfg.RekeyAfterMessages)
	}

	// One past the protocol default. This is the direction that would weaken
	// forward secrecy from a configuration file, so it is the direction that is
	// refused.
	document["rekey_after_messages"] = uint64(core.RekeyAfterMessages) + 1
	if _, err := loadWinn3Keys(writeKeys(t, dir, document)); err == nil {
		t.Fatal("a rekey volume above the protocol default was accepted")
	} else if !strings.Contains(err.Error(), "MORE often") {
		t.Fatalf("refusal does not say which direction is allowed: %v", err)
	}

	// Exactly the default is not "raising" it and stays legal.
	document["rekey_after_messages"] = uint64(core.RekeyAfterMessages)
	if _, err := loadWinn3Keys(writeKeys(t, dir, document)); err != nil {
		t.Fatalf("the protocol default itself was refused: %v", err)
	}
}

func TestTheKeyDocumentRefusalsHaveTeeth(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{"version", func(d map[string]any) { d["version"] = "winn3-keys/2" }, "this build speaks"},
		{"role", func(d map[string]any) { d["role"] = "relay" }, "role is"},
		{"gateway id", func(d map[string]any) { d["gateway_id"] = "" }, "replays at another"},
		{"static", func(d map[string]any) { d["static_path"] = "" }, "static_path is empty"},
		{"admission", func(d map[string]any) { d["admission_path"] = "" }, "admission_path is empty"},
		{"client without a gateway key", func(d map[string]any) {
			d["gateway_static_path"] = ""
		}, "no anonymous mode"},
		{"gateway with a gateway key", func(d map[string]any) {
			d["role"] = "gateway"
		}, "the client's field"},
		{"one dual-auth path", func(d map[string]any) {
			d["dual_auth_ed25519_pub_path"] = "only-ed.pub"
		}, "must be set together"},
		{"misspelled key", func(d map[string]any) { d["fastpq"] = true }, "unknown field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			document := validKeys(t, dir)
			tc.mutate(document)
			_, err := loadWinn3Keys(writeKeys(t, dir, document))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("refusal %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// --- the flag rules -----------------------------------------------------------

// TestTheTwoV3ModesCannotBeMixed, and neither can be mixed with winn/1.
func TestTheTwoV3ModesCannotBeMixed(t *testing.T) {
	cases := []struct {
		name    string
		opts    options
		v3      winn3Options
		wantErr string
	}{
		{"both v3 modes", options{}, winn3Options{
			frame: true, keys: "k.json", profile: "p.json", tunFD: -1,
		}, "two v3 modes"},
		{"frame without keys", options{}, winn3Options{
			frame: true, tunFD: -1,
		}, "-winn3 needs -winn3-keys"},
		{"frame with a winn/1 carrier", options{carrierProfile: "c.json"},
			winn3Options{frame: true, keys: "k.json", tunFD: -1},
			"different protocols"},
		{"frame with a winn/1 fallback", options{carrierFallback: profilePaths{"c.json"}},
			winn3Options{frame: true, keys: "k.json", tunFD: -1},
			"winn/1 only"},
		{"frame with a tun descriptor", options{},
			winn3Options{frame: true, keys: "k.json", tunFD: 7},
			"the HOST owns the tun device"},
		{"frame with print-sizing", options{},
			winn3Options{frame: true, keys: "k.json", tunFD: -1, printSizing: true},
			"there is no floor to compute"},
		{"frame with both descriptors", options{udpFD: 5, receiveFD: true},
			winn3Options{frame: true, keys: "k.json", tunFD: -1},
			"mutually exclusive"},
		{"keys without -winn3", options{udpFD: -1},
			winn3Options{keys: "k.json", tunFD: -1},
			"-winn3-keys needs -winn3"},
		{"keys with the desktop profile", options{udpFD: -1},
			winn3Options{profile: "p.json", keys: "k.json", tunFD: -1},
			"applies to -winn3 only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := winn3RefuseMixedModes(tc.opts, tc.v3)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("refusal %v does not contain %q", err, tc.wantErr)
			}
		})
	}

	// And the combination Android actually builds is accepted, which is the
	// point of all of the above.
	android := options{transport: "unix", control: "@winn-abc", receiveFD: true, udpFD: -1}
	if err := winn3RefuseMixedModes(android, winn3Options{
		frame: true, keys: "/data/keys.json", tunFD: -1,
	}); err != nil {
		t.Fatalf("the Android argv was refused: %v", err)
	}
}

// --- the device ---------------------------------------------------------------

// TestTheFrameDeviceDropsTheOldestAndCountsIt.
//
// A datapath that drops the newest under pressure delivers a stale burst when
// the slow side wakes up. This asserts the queue stays CURRENT, because the
// alternative is a tunnel that looks alive and is replaying the past.
func TestTheFrameDeviceDropsTheOldestAndCountsIt(t *testing.T) {
	device, err := newWinn3FrameDevice(1200)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = device.Close() }()

	total := winn3FrameQueueDepth + 16
	for i := range total {
		if _, err := device.WritePacket([]byte{byte(i), byte(i >> 8)}); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := device.droppedToHost.Load(); dropped != 16 {
		t.Fatalf("dropped %d, want 16", dropped)
	}
	first, err := device.take()
	if err != nil {
		t.Fatal(err)
	}
	// The oldest 16 are gone, so the head is packet 16 and not packet 0.
	if first[0] != 16 {
		t.Fatalf("head of the queue is packet %d, want 16: the device dropped the newest", first[0])
	}
}

// TestTheUplinkQueueTailDropsAndKeepsItsHead.
//
// The opposite policy from the test above, on the opposite queue, and the
// difference is deliberate. toEngine carries an in-order inner TCP uplink:
// deleting its head deletes the lowest unacknowledged sequence number, the
// receiver cannot SACK a hole it never saw the start of, and the sender waits
// out an RTO. That is the mechanism behind the measured 21.5 Mbps uplink floor
// on a handset that does 1652.9 Mbps up with no VPN. This asserts the head
// survives and the NEW packet is the one counted.
func TestTheUplinkQueueTailDropsAndKeepsItsHead(t *testing.T) {
	device, err := newWinn3FrameDevice(1200)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = device.Close() }()

	total := winn3FrameQueueDepth + 16
	for i := range total {
		if err := device.offer([]byte{byte(i), byte(i >> 8)}); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := device.droppedToEngine.Load(); dropped != 16 {
		t.Fatalf("dropped %d, want 16", dropped)
	}
	buf := make([]byte, 64)
	n, err := device.ReadPacket(buf)
	if err != nil || n != 2 {
		t.Fatalf("ReadPacket = %d, %v", n, err)
	}
	// Packet 0 is still the head: the 16 that did not fit were the newest.
	if buf[0] != 0 {
		t.Fatalf("head of the uplink queue is packet %d, want 0: the device dropped the oldest", buf[0])
	}
}

func TestTheFrameDeviceRefusesAnOversizePacketWithoutDropTheTunnel(t *testing.T) {
	device, err := newWinn3FrameDevice(100)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = device.Close() }()

	if err := device.offer(make([]byte, 101)); err != nil {
		t.Fatalf("an oversize packet tore the session down: %v", err)
	}
	if device.oversize.Load() != 1 {
		t.Fatal("the oversize packet was not counted")
	}
	if err := device.offer(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 200)
	n, err := device.ReadPacket(buf)
	if err != nil || n != 100 {
		t.Fatalf("ReadPacket = %d, %v; the oversize packet was not skipped", n, err)
	}
}

// TestAClosedFrameDeviceUnblocksBothEnds. A device that did not would leave
// tun.PumpOutbound spinning and the host's pump hanging on a dead tunnel.
func TestAClosedFrameDeviceUnblocksBothEnds(t *testing.T) {
	device, err := newWinn3FrameDevice(1200)
	if err != nil {
		t.Fatal(err)
	}
	// Queue one in each direction first: a close must DRAIN what the tunnel
	// already validated rather than discard it.
	if _, err := device.WritePacket([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := device.offer([]byte{2}); err != nil {
		t.Fatal(err)
	}
	_ = device.Close()
	_ = device.Close() // idempotent

	if pkt, err := device.take(); err != nil || pkt[0] != 1 {
		t.Fatalf("a queued delivery was discarded by close: %v", err)
	}
	if _, err := device.take(); err == nil {
		t.Fatal("take did not report closure once drained")
	}
	buf := make([]byte, 8)
	if n, err := device.ReadPacket(buf); err != nil || n != 1 || buf[0] != 2 {
		t.Fatalf("a queued outbound packet was discarded by close: %d %v", n, err)
	}
	if _, err := device.ReadPacket(buf); err == nil {
		t.Fatal("ReadPacket did not report closure once drained")
	}
	if _, err := device.WritePacket([]byte{3}); err == nil {
		t.Fatal("a closed device accepted a delivery")
	}
	if err := device.offer([]byte{4}); err == nil {
		t.Fatal("a closed device accepted an offer")
	}
}

// TestTheDeviceMTUIsTheHostsObligation. tun.Attach refuses a device MTU above
// the tunnel's inner MTU, and this asserts the device reports what the create
// document declared rather than inventing one.
func TestTheDeviceMTUIsTheHostsObligation(t *testing.T) {
	if _, err := newWinn3FrameDevice(0); err == nil {
		t.Fatal("a zero MTU device was built")
	}
	device, err := newWinn3FrameDevice(tun.MinInnerMTUv4)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = device.Close() }()
	if device.MTU() != tun.MinInnerMTUv4 {
		t.Fatalf("MTU = %d, want %d", device.MTU(), tun.MinInnerMTUv4)
	}
}

// --- the transport wiring ------------------------------------------------------

// TestTheFrameTransportRefusalsHaveTeeth covers the argv combinations that
// reach runWinn3Frames rather than being caught by the flag rules.
//
// Each one is a way for a host to start a v3 process that cannot serve, and the
// consequence of accepting any of them is a tunnel that never carries and never
// says why.
func TestTheFrameTransportRefusalsHaveTeeth(t *testing.T) {
	dir := t.TempDir()
	keysPath := writeKeys(t, dir, validKeys(t, dir))

	cases := []struct {
		name    string
		opts    options
		wantErr string
	}{
		{"receive-fd over a pipe",
			options{transport: "stdio", receiveFD: true, udpFD: -1},
			"cannot be passed over a pipe"},
		{"control over a pipe",
			options{transport: "stdio", control: "/tmp/x", udpFD: -1},
			"applies only to -transport unix"},
		{"unix without a control path",
			options{transport: "unix", udpFD: -1},
			"requires -control PATH"},
		{"an unknown transport",
			options{transport: "quic", udpFD: -1},
			"unknown -transport"},
		{"a control socket nothing is listening on",
			options{transport: "unix", control: "/nonexistent-winn3-control", udpFD: -1},
			"connect control socket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runWinn3Frames(t.Context(), tc.opts, winn3Options{
				frame: true, keys: keysPath, tunFD: -1,
			})
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("refusal %v does not contain %q", err, tc.wantErr)
			}
		})
	}

	// A key document that does not exist is refused BEFORE any transport is
	// established, so a host that mis-staged the file learns it from a dead
	// process on stderr rather than from a tunnel that hangs.
	err := runWinn3Frames(t.Context(), options{transport: "stdio", udpFD: -1},
		winn3Options{frame: true, keys: filepath.Join(dir, "absent.json"), tunFD: -1})
	if err == nil || !strings.Contains(err.Error(), "read winn3 key document") {
		t.Fatalf("a missing key document was not refused first: %v", err)
	}
}

// TestServeRefusesWithoutBothStreams. A nil stream would panic in the reader,
// which on a host looks identical to an engine that crashed on the wire.
func TestServeRefusesWithoutBothStreams(t *testing.T) {
	dir := t.TempDir()
	keys, err := loadWinn3Keys(writeKeys(t, dir, validKeys(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if err := serveWinn3Frames(t.Context(), nil, nil, keys, -1); err == nil {
		t.Fatal("serve accepted nil streams")
	}
}
