package main

import (
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// --- the promotion gate ------------------------------------------------------

// TestPromotionNeedsBothHalves walks every one of the 256 byte values a
// tun.State can take, against a zero and a nonzero delivery count.
//
// Exhaustive rather than exemplary for the same reason the tun layer walks all
// 256 values of its own state: this predicate is written as a WHITELIST of one
// carrying state, and the failure mode of the alternative is that somebody adds
// a state, forgets a case, and the tunnel widens on it.
func TestPromotionNeedsBothHalves(t *testing.T) {
	for value := 0; value < 256; value++ {
		state := tun.State(value) //nolint:gosec // the loop bound is the range
		carrying := state == tun.StateCarrying
		if got := winn3PromotionReady(state, 0); got {
			t.Fatalf("state %s with zero delivered packets promoted", state)
		}
		if got := winn3PromotionReady(state, 1); got != carrying {
			t.Fatalf("state %s with one delivered packet: promoted=%v, want %v",
				state, got, carrying)
		}
	}
}

// TestPostureFollowsThePredicate pins the posture name to the boolean, so the
// two cannot disagree.
func TestPostureFollowsThePredicate(t *testing.T) {
	if got := winn3Posture(false); got != winn3PostureBootstrap {
		t.Fatalf("not ready maps to %q, want %q", got, winn3PostureBootstrap)
	}
	if got := winn3Posture(true); got != winn3PostureFull {
		t.Fatalf("ready maps to %q, want %q", got, winn3PostureFull)
	}
}

// TestTheStatusZeroValueIsTheBootstrapPosture is the fail-closed property of
// the wire format itself.
//
// A host that cannot parse a status line, or that parses one written by an
// older engine with no promotion_ready field, must hold the narrow posture. In
// JSON an absent bool decodes to false, and false is bootstrap. This test
// exists so that nobody ever "fixes" the field into a string, or inverts it
// into `hold_bootstrap`, either of which would make the absent case widen.
func TestTheStatusZeroValueIsTheBootstrapPosture(t *testing.T) {
	var status winn3Status
	if err := json.Unmarshal([]byte(`{"event":"posture"}`), &status); err != nil {
		t.Fatal(err)
	}
	if status.PromotionReady {
		t.Fatal("a status document with no promotion_ready field promoted")
	}
	if winn3Posture(status.PromotionReady) != winn3PostureBootstrap {
		t.Fatal("the zero value is not the bootstrap posture")
	}

	encoded, err := json.Marshal(winn3Status{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"promotion_ready":false`) {
		t.Fatalf("promotion_ready is not emitted explicitly: %s", encoded)
	}
}

// TestOnlyOnePlaceDecidesPromotion parses this package's own source.
//
// Two desktop hosts read this boolean and neither computes it. The guarantee
// that buys is worth nothing if a second site in this package can set the field
// to something other than a constant false, so the assignments are counted.
// Exactly one may come from winn3PromotionReady, and every other assignment
// must be the literal false — which is the teardown line in winn3Serve, and is
// safe by inspection because it can only narrow.
func TestOnlyOnePlaceDecidesPromotion(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fromPredicate, fromFalse, other := 0, 0, 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				selector, ok := lhs.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "PromotionReady" {
					continue
				}
				if i >= len(assign.Rhs) {
					other++
					continue
				}
				switch rhs := assign.Rhs[i].(type) {
				case *ast.CallExpr:
					if fn, ok := rhs.Fun.(*ast.Ident); ok &&
						fn.Name == "winn3PromotionReady" {
						fromPredicate++
						continue
					}
					other++
				case *ast.Ident:
					if rhs.Name == "false" {
						fromFalse++
						continue
					}
					other++
				default:
					other++
				}
			}
			return true
		})
	}
	if fromPredicate != 1 {
		t.Fatalf("%d sites set PromotionReady from winn3PromotionReady, want 1",
			fromPredicate)
	}
	if other != 0 {
		t.Fatalf("%d sites set PromotionReady from something that is neither "+
			"the predicate nor a constant false", other)
	}
	if fromFalse == 0 {
		t.Fatal("the teardown no longer forces PromotionReady false")
	}
}

// --- the profile -------------------------------------------------------------

// validProfile is the smallest document this build accepts.
func validProfile() map[string]any {
	return map[string]any{
		"version": winn3ProfileVersion,
		"role":    winn3RoleClient,
		"plan":    []string{"udp", "tcp", "tls"},
		// The fleet default. It was a literal 1280 until 2026-08-10, which over
		// this plan is inside the inner-IPv6 dead zone — driver.NewSizing
		// refuses it, so every consumer of this fixture that reaches the
		// preflight was refused for a reason none of them is about. The
		// document has no opinion about the path; the cases that do set
		// path_mtu themselves.
		"path_mtu":   carrier.DefaultPathMTU,
		"gateway_id": "winn3-desktop-fixture",
		"carrier": map[string]any{
			"class":    "udp",
			"endpoint": "198.51.100.7:51820",
		},
		"inner": map[string]any{
			"v4":        "10.64.0.2",
			"router_v4": "10.64.0.1",
		},
		"keys": map[string]any{
			"static_path":         "/nonexistent/static.key",
			"gateway_static_path": "/nonexistent/gateway.key",
			"admission_path":      "/nonexistent/admission.key",
		},
		"device": map[string]any{
			"kind":      winn3DeviceLoopbackUDP,
			"host_port": 51999,
		},
		"allow_own_socket":       true,
		"outer_socket_exclusion": "fwmark 0x1f4 lookup 51820",
	}
}

func writeProfile(t *testing.T, document map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "winn3.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAValidProfileLoads(t *testing.T) {
	profile, err := loadWinn3Profile(writeProfile(t, validProfile()))
	if err != nil {
		t.Fatalf("valid profile refused: %v", err)
	}
	if profile.Carrier.Class != "udp" {
		t.Fatalf("carrier class is %q", profile.Carrier.Class)
	}
	classes, err := profile.classes()
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 3 {
		t.Fatalf("plan resolved to %d classes", len(classes))
	}
}

func validTLSProfile() map[string]any {
	document := validProfile()
	document["carrier"] = map[string]any{
		"class":                "tls",
		"endpoint":             "198.51.100.7:443",
		"trust_anchor":         "private-ca",
		"root_ca_path":         "/nonexistent/ca.pem",
		"ech_config_list_path": "/nonexistent/ech.bin",
		"client_cert_path":     "/nonexistent/client.pem",
		"client_key_path":      "/nonexistent/client.key",
		"server_name":          "winn.example",
		"suite":                "x25519-mlkem768",
	}
	return document
}

func TestAValidTLSProfileLoads(t *testing.T) {
	profile, err := loadWinn3Profile(writeProfile(t, validTLSProfile()))
	if err != nil {
		t.Fatalf("valid tls profile refused: %v", err)
	}
	if profile.Carrier.Class != "tls" {
		t.Fatalf("carrier class is %q", profile.Carrier.Class)
	}
	if profile.Carrier.TrustAnchor != "private-ca" {
		t.Fatalf("trust_anchor is %q", profile.Carrier.TrustAnchor)
	}
	if profile.Carrier.tlsALPN() != winn3TLSDefaultALPN {
		t.Fatalf("default alpn is %q, want %q", profile.Carrier.tlsALPN(), winn3TLSDefaultALPN)
	}
}

func TestAValidWebPKITLSProfileLoads(t *testing.T) {
	document := validTLSProfile()
	carrier := document["carrier"].(map[string]any)
	carrier["trust_anchor"] = "webpki"
	delete(carrier, "root_ca_path")
	delete(carrier, "client_cert_path")
	delete(carrier, "client_key_path")
	carrier["server_name"] = "cdn.example"
	profile, err := loadWinn3Profile(writeProfile(t, document))
	if err != nil {
		t.Fatalf("valid webpki tls profile refused: %v", err)
	}
	if profile.Carrier.TrustAnchor != "webpki" {
		t.Fatalf("trust_anchor is %q", profile.Carrier.TrustAnchor)
	}
	if strings.TrimSpace(profile.Carrier.ClientCertPath) != "" {
		t.Fatal("webpki profile kept a client certificate path")
	}
}

// TestTheProfileRefusalsHaveTeeth is the table of things that must not start.
//
// Every entry is a configuration that would otherwise fail late, silently, or
// not at all. The socket-rule entries are the ones that matter most: a host
// that has not installed the route exclusion and starts this engine anyway
// produces a tunnel whose own carrier datagrams re-enter it and loop.
func TestTheProfileRefusalsHaveTeeth(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		expect string
	}{
		{"no socket rule", func(d map[string]any) {
			d["allow_own_socket"] = false
		}, "allow_own_socket is false"},
		{"exclusion not named", func(d map[string]any) {
			d["outer_socket_exclusion"] = "   "
		}, "outer_socket_exclusion is empty"},
		{"empty plan", func(d map[string]any) {
			d["plan"] = []string{}
		}, "plan is empty"},
		{"dialled class outside the plan", func(d map[string]any) {
			d["plan"] = []string{"tcp", "tls"}
		}, "is not named in the plan"},
		{"unknown class", func(d map[string]any) {
			d["plan"] = []string{"quic"}
		}, "unknown carrier class"},
		{"hostname endpoint", func(d map[string]any) {
			d["carrier"].(map[string]any)["endpoint"] = "gateway.example:51820"
		}, "not an IP literal"},
		{"port zero", func(d map[string]any) {
			d["carrier"].(map[string]any)["endpoint"] = "198.51.100.7:0"
		}, "port 0"},
		{"no gateway id", func(d map[string]any) {
			d["gateway_id"] = ""
		}, "gateway_id is empty"},
		{"no admission secret", func(d map[string]any) {
			d["keys"].(map[string]any)["admission_path"] = ""
		}, "admission_path is empty"},
		{"client with no gateway key", func(d map[string]any) {
			d["keys"].(map[string]any)["gateway_static_path"] = ""
		}, "gateway_static_path is empty"},
		{"no inner address", func(d map[string]any) {
			d["inner"] = map[string]any{}
		}, "neither an IPv4 nor an IPv6"},
		{"family mismatch", func(d map[string]any) {
			d["inner"].(map[string]any)["v4"] = "2001:db8::2"
		}, "not the expected family"},
		{"unknown device", func(d map[string]any) {
			d["device"].(map[string]any)["kind"] = "wintun"
		}, "device.kind"},
		{"seam with no port", func(d map[string]any) {
			d["device"].(map[string]any)["host_port"] = 0
		}, "not a usable port"},
		{"wrong version", func(d map[string]any) {
			d["version"] = "winn3-host/0"
		}, "this build speaks"},
		{"unknown role", func(d map[string]any) {
			d["role"] = "relay"
		}, "role is"},
		{"tls without trust material", func(d map[string]any) {
			d["carrier"].(map[string]any)["class"] = "tls"
		}, "trust_anchor"},
		{"tls fields on udp", func(d map[string]any) {
			d["carrier"].(map[string]any)["ech_config_list_path"] = "/nonexistent/ech.bin"
		}, "applies to class tls only"},
		{"tls private-ca without client cert", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "private-ca"
			carrier["root_ca_path"] = "/nonexistent/ca.pem"
			carrier["ech_config_list_path"] = "/nonexistent/ech.bin"
			carrier["server_name"] = "winn.example"
			carrier["suite"] = "x25519-mlkem768"
		}, "client_cert_path"},
		{"tls webpki with client cert", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "webpki"
			carrier["ech_config_list_path"] = "/nonexistent/ech.bin"
			carrier["client_cert_path"] = "/nonexistent/client.pem"
			carrier["client_key_path"] = "/nonexistent/client.key"
			carrier["server_name"] = "cdn.example"
			carrier["suite"] = "x25519-mlkem768"
		}, "must not present a stable device certificate"},
		{"tls without ech list", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "private-ca"
			carrier["root_ca_path"] = "/nonexistent/ca.pem"
			carrier["client_cert_path"] = "/nonexistent/client.pem"
			carrier["client_key_path"] = "/nonexistent/client.key"
			carrier["server_name"] = "winn.example"
			carrier["suite"] = "x25519-mlkem768"
		}, "ech_config_list_path"},
		{"tls without server_name", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "private-ca"
			carrier["root_ca_path"] = "/nonexistent/ca.pem"
			carrier["ech_config_list_path"] = "/nonexistent/ech.bin"
			carrier["client_cert_path"] = "/nonexistent/client.pem"
			carrier["client_key_path"] = "/nonexistent/client.key"
			carrier["suite"] = "x25519-mlkem768"
		}, "server_name"},
		{"tls without suite", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "private-ca"
			carrier["root_ca_path"] = "/nonexistent/ca.pem"
			carrier["ech_config_list_path"] = "/nonexistent/ech.bin"
			carrier["client_cert_path"] = "/nonexistent/client.pem"
			carrier["client_key_path"] = "/nonexistent/client.key"
			carrier["server_name"] = "winn.example"
		}, "suite"},
		{"tls private-ca without root_ca", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "private-ca"
			carrier["ech_config_list_path"] = "/nonexistent/ech.bin"
			carrier["client_cert_path"] = "/nonexistent/client.pem"
			carrier["client_key_path"] = "/nonexistent/client.key"
			carrier["server_name"] = "winn.example"
			carrier["suite"] = "x25519-mlkem768"
		}, "root_ca_path"},
		{"tls unknown trust_anchor", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "system"
			carrier["ech_config_list_path"] = "/nonexistent/ech.bin"
			carrier["server_name"] = "winn.example"
			carrier["suite"] = "x25519-mlkem768"
		}, "unknown"},
		{"tls webpki with IP server_name", func(d map[string]any) {
			carrier := d["carrier"].(map[string]any)
			carrier["class"] = "tls"
			carrier["trust_anchor"] = "webpki"
			carrier["ech_config_list_path"] = "/nonexistent/ech.bin"
			carrier["server_name"] = "198.51.100.7"
			carrier["suite"] = "x25519-mlkem768"
		}, "fronting DOMAIN"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			document := validProfile()
			testCase.mutate(document)
			_, err := loadWinn3Profile(writeProfile(t, document))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), testCase.expect) {
				t.Fatalf("refused with %q, expected it to mention %q",
					err, testCase.expect)
			}
		})
	}
}

// TestAMisspelledKeyIsRefused. A dropped key is a setting the operator believes
// took effect, and on this document the settings that could silently not take
// effect are the migration plan and the socket rule.
func TestAMisspelledKeyIsRefused(t *testing.T) {
	document := validProfile()
	document["allow_own_sockets"] = true
	_, err := loadWinn3Profile(writeProfile(t, document))
	if err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if !strings.Contains(err.Error(), "allow_own_sockets") {
		t.Fatalf("the refusal does not name the field: %v", err)
	}
}

// TestTheLogLineCarriesNoSecretAndNoAddress. The profile names every private
// file this device holds and the gateway it talks to; a support ticket carries
// logs out of the country.
func TestTheLogLineCarriesNoSecretAndNoAddress(t *testing.T) {
	profile, err := loadWinn3Profile(writeProfile(t, validProfile()))
	if err != nil {
		t.Fatal(err)
	}
	line := profile.describeForLog()
	for _, forbidden := range []string{
		"198.51.100.7", "10.64.0.2", "10.64.0.1", "/nonexistent",
		"static.key", "admission.key", "winn3-desktop-fixture",
	} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("the log line leaks %q: %s", forbidden, line)
		}
	}
	for _, required := range []string{"role=client", "carrier=udp",
		"plan=udp+tcp+tls", "allow_own_socket=true", "exclusion_declared=true"} {
		if !strings.Contains(line, required) {
			t.Fatalf("the log line omits %q: %s", required, line)
		}
	}
}

// --- mode separation ---------------------------------------------------------

// TestTheTwoProtocolsCannotBeMixed. winn/1 relays AmneziaWG datagrams and v3
// replaces AmneziaWG. A process configured for both has two opinions about what
// its payloads are, and the cost of guessing wrong is cleartext on the wire.
func TestTheTwoProtocolsCannotBeMixed(t *testing.T) {
	v3 := winn3Options{profile: "/tmp/winn3.json", tunFD: -1}
	cases := []struct {
		name string
		opts options
	}{
		{"carrier profile", options{carrierProfile: "/tmp/c.json", udpFD: -1}},
		{"carrier fallback", options{carrierFallback: profilePaths{"/tmp/f.json"}, udpFD: -1}},
		{"inherited socket", options{udpFD: 7}},
		{"socket hand-off", options{udpFD: -1, receiveFD: true}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := winn3RefuseMixedModes(testCase.opts, v3); err == nil {
				t.Fatal("accepted a mixed configuration")
			}
		})
	}
	if err := winn3RefuseMixedModes(options{udpFD: -1}, v3); err != nil {
		t.Fatalf("a clean v3 configuration was refused: %v", err)
	}
	if err := winn3RefuseMixedModes(
		options{udpFD: -1}, winn3Options{tunFD: 9}); err == nil {
		t.Fatal("-winn3-tun-fd was accepted without -winn3-profile")
	}
}

// --- key files ---------------------------------------------------------------

func TestKeyFilesAreAcceptedInBothEncodings(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	rawPath := filepath.Join(dir, "raw.key")
	hexPath := filepath.Join(dir, "hex.key")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hexPath,
		[]byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{rawPath, hexPath} {
		got, err := winn3ReadKeyFile(path, "keys.static_path")
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if string(got) != string(raw) {
			t.Fatalf("%s decoded to different bytes", path)
		}
	}
	shortPath := filepath.Join(dir, "short.key")
	if err := os.WriteFile(shortPath, raw[:16], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := winn3ReadKeyFile(shortPath, "keys.static_path"); err == nil {
		t.Fatal("a 16-byte key was accepted")
	}
}

// --- the tun counters the document carries -----------------------------------

// TestTheRefusalCountersReachTheWire pins the JSON keys of the two outbound
// refusal counters, which say DIFFERENT things and are read together.
//
// tx_dropped_closed is the gate refusing while shut. tx_dropped_invalid is the
// gate open and the packet refused anyway — most importantly a source address
// this session was never assigned. A host that saw only the first would read a
// deanonymisation refusal as a healthy tunnel.
func TestTheRefusalCountersReachTheWire(t *testing.T) {
	encoded, err := winn3EncodeStatus(winn3Status{
		Event:            "posture",
		TxDroppedClosed:  3,
		TxDroppedInvalid: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back["tx_dropped_invalid"] != float64(7) {
		t.Fatalf("tx_dropped_invalid is %v, want 7: %s", back["tx_dropped_invalid"], encoded)
	}
	if back["tx_dropped_closed"] != float64(3) {
		t.Fatalf("tx_dropped_closed is %v, want 3: %s", back["tx_dropped_closed"], encoded)
	}
}

// TestUnopenableAndPathNarrowedReachTheWire pins the two session counters that
// name "the tunnel looks healthy while it is not". messages_received includes
// unopenable datagrams; without unopenable on the document a spray reads as
// traffic. PromotionReady can stay true on small packets after the path has
// narrowed; path_narrowed_for is the counter that names that stall.
func TestUnopenableAndPathNarrowedReachTheWire(t *testing.T) {
	encoded, err := winn3EncodeStatus(winn3Status{
		Event:           "posture",
		Unopenable:      11,
		PathNarrowedFor: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back["unopenable"] != float64(11) {
		t.Fatalf("unopenable is %v, want 11: %s", back["unopenable"], encoded)
	}
	if back["path_narrowed_for"] != float64(2) {
		t.Fatalf("path_narrowed_for is %v, want 2: %s", back["path_narrowed_for"], encoded)
	}

	zero, err := winn3EncodeStatus(winn3Status{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zero), `"unopenable":0`) {
		t.Fatalf("unopenable is omitted at zero, so a never-sprayed tunnel is indistinguishable from a document that lacks the field: %s", zero)
	}
	if !strings.Contains(string(zero), `"path_narrowed_for":0`) {
		t.Fatalf("path_narrowed_for is omitted at zero: %s", zero)
	}
}

// TestSessionCountersAreCopiedFromLoopStats parses winn3StatusFrom so a later
// edit that declares the JSON keys and forgets the copy goes red — a permanent
// zero looks like evidence.
func TestSessionCountersAreCopiedFromLoopStats(t *testing.T) {
	src, err := os.ReadFile("winn3_status.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, n := range []string{
		"status.Unopenable = loopStats.Unopenable",
		"status.PathNarrowedFor = loopStats.PathNarrowedFor",
	} {
		if !strings.Contains(body, n) {
			t.Fatalf("winn3StatusFrom no longer copies %q; the JSON key would be a permanent zero", n)
		}
	}
}

// TestEveryTunCounterDeclaredIsAlsoAssigned parses this package's own source.
//
// A counter field on winn3Status is worth nothing if winn3StatusFrom never
// assigns it. The document still carries the key, the host still parses it, and
// it reads a permanent zero — which is indistinguishable from "the refusal
// never fired". That is WORSE than omitting the field, because a zero looks
// like evidence and an absent key does not.
//
// TxDroppedInvalid is the field that motivated this: until it was published,
// the only way to show that a packet with an unassigned source address never
// left the host was a packet capture, which is not a thing that can be done on
// a user's phone in Yangon.
//
// It is written against the INTERSECTION of winn3Status and tun.Stats rather
// than a hand-kept list, so a counter added later is covered without anybody
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
			"deanonymisation refusal counter. Hosts are blind to the refusal again")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "winn3_status.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "winn3StatusFrom" {
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
				if !ok || from.Name != "tunStats" || source.Sel.Name != target.Sel.Name {
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
			t.Errorf("winn3Status declares %s but winn3StatusFrom never assigns it "+
				"from tunStats.%s, so the document publishes a permanent zero for it",
				name, name)
		}
	}
}
