package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/datapath/carrierhost"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

func writeProfileBytes(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "winn3.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustMarshalProfile(t *testing.T, document map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestWinn3ProfileJSONAdversarialInputs is the hostile-document table for
// loadWinn3Profile. Every row is a claim about what a malformed or hostile
// file can do: over-read (not possible — the decoder reads a bounded slice),
// under-read (trailing values after the first object), unbounded allocation
// (file size, plan length, nesting), integer overflow (JSON numbers that do
// not fit in int), panic (garbage and nesting bombs), or silent acceptance
// of something invalid.
//
// wantErr empty means the document must load. A non-empty wantErr is a
// substring the refusal must contain, so deleting the guard that produces
// that substring turns the row red.
func TestWinn3ProfileJSONAdversarialInputs(t *testing.T) {
	type row struct {
		name    string
		raw     func(*testing.T) []byte
		wantErr string
	}

	valid := func(t *testing.T) []byte {
		t.Helper()
		return mustMarshalProfile(t, validProfile())
	}

	cases := []row{
		// --- already-correct refusals, pinned so they stay that way ---
		{
			name: "empty file",
			raw: func(*testing.T) []byte {
				return nil
			},
			wantErr: "decode",
		},
		{
			name: "whitespace only",
			raw: func(*testing.T) []byte {
				return []byte("   \n\t")
			},
			wantErr: "decode",
		},
		{
			name: "JSON array root",
			raw: func(*testing.T) []byte {
				return []byte(`[]`)
			},
			wantErr: "decode",
		},
		{
			name: "JSON string root",
			raw: func(*testing.T) []byte {
				return []byte(`"winn3-host/1"`)
			},
			wantErr: "decode",
		},
		{
			name: "JSON true root",
			raw: func(*testing.T) []byte {
				return []byte(`true`)
			},
			wantErr: "decode",
		},
		{
			name: "truncated object",
			raw: func(*testing.T) []byte {
				return []byte(`{"version":`)
			},
			wantErr: "decode",
		},
		{
			name: "UTF-8 BOM",
			raw: func(t *testing.T) []byte {
				return append([]byte{0xEF, 0xBB, 0xBF}, valid(t)...)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu as string",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["path_mtu"] = "1450"
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu as boolean",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["path_mtu"] = true
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu fractional",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["path_mtu"] = 1450.5
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu overflows int64",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"path_mtu":` + jsonNumber(t, validProfile()["path_mtu"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"path_mtu":9223372036854775808`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "plan is a string",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = "udp"
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "inner IPv6 zone",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = map[string]any{
					"v6": "fe80::1%lo0", "router_v6": "fe80::2%lo0",
				}
				return mustMarshalProfile(t, document)
			},
			wantErr: "carries a zone",
		},
		{
			name: "negative path_mtu",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["path_mtu"] = -1
				return mustMarshalProfile(t, document)
			},
			wantErr: "negative",
		},
		{
			name: "host_port above 65535",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"].(map[string]any)["host_port"] = 65536
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a usable port",
		},
		{
			name: "tun-fd without a name",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"] = map[string]any{"kind": winn3DeviceTunFD}
				return mustMarshalProfile(t, document)
			},
			wantErr: "device.name is empty",
		},
		{
			name: "loopback-udp with a tun name",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"].(map[string]any)["name"] = "winn0"
				return mustMarshalProfile(t, document)
			},
			wantErr: "device.name applies",
		},
		{
			name: "gateway carrying the client key field",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["role"] = winn3RoleGateway
				return mustMarshalProfile(t, document)
			},
			wantErr: "gateway_static_path is set on a gateway",
		},

		// --- guards added 2026-08-12: trailing values, size, depth, plan, path, unicast ---
		{
			name: "concatenated second object",
			raw: func(t *testing.T) []byte {
				first := valid(t)
				return append(append(first, '\n'), first...)
			},
			wantErr: "single JSON object",
		},
		{
			name: "trailing JSON null",
			raw: func(t *testing.T) []byte {
				return append(valid(t), []byte(" null")...)
			},
			wantErr: "single JSON object",
		},
		{
			name: "trailing JSON number",
			raw: func(t *testing.T) []byte {
				return append(valid(t), []byte(" 0")...)
			},
			wantErr: "single JSON object",
		},
		{
			name: "file larger than maxWinn3ProfileBytes",
			raw: func(*testing.T) []byte {
				return bytes.Repeat([]byte{' '}, maxWinn3ProfileBytes+1)
			},
			wantErr: "exceeds",
		},
		{
			name: "JSON nesting deeper than maxWinn3ProfileJSONDepth",
			raw: func(*testing.T) []byte {
				var b strings.Builder
				b.WriteByte('{')
				for i := 0; i < maxWinn3ProfileJSONDepth; i++ {
					b.WriteString(`"x":{`)
				}
				b.WriteString(`"y":1`)
				for i := 0; i < maxWinn3ProfileJSONDepth+1; i++ {
					b.WriteByte('}')
				}
				return []byte(b.String())
			},
			wantErr: "nesting depth",
		},
		{
			name: "unknown field with nested bomb as its value",
			raw: func(*testing.T) []byte {
				var b strings.Builder
				b.WriteString(`{"not_a_profile_field":`)
				for i := 0; i < maxWinn3ProfileJSONDepth+1; i++ {
					b.WriteByte('[')
				}
				b.WriteByte('1')
				for i := 0; i < maxWinn3ProfileJSONDepth+1; i++ {
					b.WriteByte(']')
				}
				b.WriteByte('}')
				return []byte(b.String())
			},
			wantErr: "nesting depth",
		},
		{
			name: "duplicate plan class",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = []string{"udp", "udp"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "plan names udp twice",
		},
		{
			name: "plan longer than the known classes",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = []string{"udp", "tcp", "tls", "udp"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "plan has 4 entries",
		},
		{
			name: "path_mtu above the IPv4 datagram ceiling",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["path_mtu"] = maxWinn3PathMTU + 1
				return mustMarshalProfile(t, document)
			},
			wantErr: "largest IP datagram",
		},
		{
			name: "unspecified IPv4 endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "0.0.0.0:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a unicast IP literal",
		},
		{
			name: "unspecified IPv6 endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "[::]:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a unicast IP literal",
		},
		{
			name: "multicast IPv4 endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "224.0.0.1:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a unicast IP literal",
		},
		{
			name: "multicast IPv6 endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "[ff02::1]:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a unicast IP literal",
		},
		{
			name: "limited-broadcast IPv4 endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "255.255.255.255:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a unicast IP literal",
		},
		{
			name: "unknown top-level field",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["allow_own_sockets"] = true
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "unknown nested field on carrier",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["hostname"] = "gateway.example"
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "empty object",
			raw: func(*testing.T) []byte {
				return []byte(`{}`)
			},
			wantErr: "this build speaks",
		},
		{
			name: "trailing comma",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				if encoded[len(encoded)-1] != '}' {
					t.Fatalf("fixture did not end with }: %s", encoded)
				}
				return append(encoded[:len(encoded)-1], []byte(`,}`)...)
			},
			wantErr: "decode",
		},
		{
			name: "JSON line comment",
			raw: func(t *testing.T) []byte {
				return append([]byte("// hostile\n"), valid(t)...)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu scientific notation",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"path_mtu":` + jsonNumber(t, validProfile()["path_mtu"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"path_mtu":1e3`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu JSON Infinity",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"path_mtu":` + jsonNumber(t, validProfile()["path_mtu"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"path_mtu":Infinity`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "host_port overflows int64",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"host_port":` + jsonNumber(t, validProfile()["device"].(map[string]any)["host_port"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"host_port":9223372036854775808`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "negative host_port",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"].(map[string]any)["host_port"] = -1
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a usable port",
		},
		{
			name: "allow_own_socket as string",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["allow_own_socket"] = "true"
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "carrier as array",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"] = []any{"udp"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "keys as string",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["keys"] = "/nonexistent/static.key"
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "plan JSON null is an empty plan",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = nil
				return mustMarshalProfile(t, document)
			},
			wantErr: "plan is empty",
		},
		{
			name: "plan entry is JSON null",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"plan":["udp","tcp","tls"]`)
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"plan":[null]`), 1)
			},
			wantErr: "unknown carrier class",
		},
		{
			name: "plan entry is empty string",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = []string{""}
				return mustMarshalProfile(t, document)
			},
			wantErr: "unknown carrier class",
		},
		{
			name: "plan with 64 dummy entries is refused by the cap not by panic",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				plan := make([]string, 64)
				for i := range plan {
					plan[i] = "x"
				}
				document["plan"] = plan
				return mustMarshalProfile(t, document)
			},
			wantErr: "plan has 64 entries",
		},
		{
			name: "empty static_path",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["keys"].(map[string]any)["static_path"] = ""
				return mustMarshalProfile(t, document)
			},
			wantErr: "static_path is empty",
		},
		{
			name: "hostname endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "gateway.example:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not an IP literal",
		},
		{
			name: "IPv6 endpoint without brackets",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "2001:db8::7:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not an IP literal",
		},
		{
			name: "endpoint port zero",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "198.51.100.7:0"
				return mustMarshalProfile(t, document)
			},
			wantErr: "port 0",
		},
		{
			name: "empty plan",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = []string{}
				return mustMarshalProfile(t, document)
			},
			wantErr: "plan is empty",
		},
		{
			name: "JSON nesting at exactly maxWinn3ProfileJSONDepth is not a depth refusal",
			raw: func(*testing.T) []byte {
				var b strings.Builder
				b.WriteByte('{')
				for i := 0; i < maxWinn3ProfileJSONDepth-1; i++ {
					b.WriteString(`"x":{`)
				}
				b.WriteString(`"y":1`)
				for i := 0; i < maxWinn3ProfileJSONDepth; i++ {
					b.WriteByte('}')
				}
				return []byte(b.String())
			},
			wantErr: "decode",
		},
		{
			name: "allow_own_socket JSON null is false and is refused",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"allow_own_socket":true`)
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"allow_own_socket":null`), 1)
			},
			wantErr: "allow_own_socket is false",
		},

		// --- legitimate documents that must keep loading ---
		{
			name:    "reference profile",
			raw:     valid,
			wantErr: "",
		},
		{
			name: "trailing whitespace after the object",
			raw: func(t *testing.T) []byte {
				return append(valid(t), []byte("  \n\n")...)
			},
			wantErr: "",
		},
		{
			name: "path_mtu omitted is zero which means the fleet default",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				delete(document, "path_mtu")
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "path_mtu at the IPv4 datagram ceiling",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["path_mtu"] = maxWinn3PathMTU
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "IPv6 gateway endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "[2001:db8::7]:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "loopback gateway endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "127.0.0.1:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "inner IPv6 only",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = map[string]any{
					"v6": "fd00:d951:1::2", "router_v6": "fd00:d951:1::1",
				}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "tun-fd device",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"] = map[string]any{
					"kind": winn3DeviceTunFD, "name": "winn0",
				}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "gateway role without the client key field",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["role"] = winn3RoleGateway
				delete(document["keys"].(map[string]any), "gateway_static_path")
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "udp-only plan",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = []string{"udp"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "braces inside a string are not nesting",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["outer_socket_exclusion"] = `fwmark {0x1f4} lookup [51820]`
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "host_port at 65535 still loads",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"].(map[string]any)["host_port"] = 65535
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "TrimSpace on a plan class still names udp",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = []string{" udp ", "tcp", "tls"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "path_mtu JSON null is the zero value which means the fleet default",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"path_mtu":` + jsonNumber(t, validProfile()["path_mtu"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"path_mtu":null`), 1)
			},
			wantErr: "",
		},
		{
			name: "relative key path is accepted at load; existence is not checked here",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["keys"].(map[string]any)["static_path"] = "static.key"
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "IPv4-mapped IPv6 endpoint currently loads (residual, not a unicast-form guard)",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "[::ffff:198.51.100.7]:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "inner unspecified IPv4 is accepted at load (martian check is tun.New, not this parser)",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = map[string]any{"v4": "0.0.0.0", "router_v4": "10.64.0.1"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "inner router equal to the assigned address is accepted at load (tun.New refuses it later)",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = map[string]any{"v4": "10.64.0.2", "router_v4": "10.64.0.2"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := loadWinn3Profile(writeProfileBytes(t, testCase.raw(t)))
			if testCase.wantErr == "" {
				if err != nil {
					t.Fatalf("refused a legitimate document: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("refused with %q, expected it to mention %q",
					err, testCase.wantErr)
			}
		})
	}
}

func jsonNumber(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// TestWinn3ProfileSizeCeilingMatchesCarrierhost pins the two profile loaders
// to the same byte budget so a hostile file cannot be oversized on one path
// and bounded on the other.
func TestWinn3ProfileSizeCeilingMatchesCarrierhost(t *testing.T) {
	if maxWinn3ProfileBytes != carrierhost.MaxProfileBytes {
		t.Fatalf("maxWinn3ProfileBytes is %d, carrierhost.MaxProfileBytes is %d",
			maxWinn3ProfileBytes, carrierhost.MaxProfileBytes)
	}
}

// TestWinn3ProfilePlanCapIsTheKnownClassCount fails if a fourth carrier
// class is added without raising maxWinn3PlanEntries — otherwise a legitimate
// four-class plan would be refused as hostile.
func TestWinn3ProfilePlanCapIsTheKnownClassCount(t *testing.T) {
	known := []carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS}
	if maxWinn3PlanEntries != len(known) {
		t.Fatalf("maxWinn3PlanEntries is %d, this build names %d classes %v",
			maxWinn3PlanEntries, len(known), known)
	}
}

// TestWinn3JSONNestingDepthIgnoresBracesInStrings is the scanner's own
// control: a depth bomb inside a JSON string must not count, or a legitimate
// exclusion description that mentions braces would be refused.
func TestWinn3JSONNestingDepthIgnoresBracesInStrings(t *testing.T) {
	raw := []byte(`{"a":"{{{{","b":[1]}`)
	if got := winn3JSONNestingDepth(raw); got != 2 {
		t.Fatalf("depth %d, want 2 (root object + one array)", got)
	}
	encoded, err := json.Marshal(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	if got := winn3JSONNestingDepth(encoded); got != 2 {
		t.Fatalf("a valid profile nests to %d, want 2", got)
	}
}

// TestWinn3ProfileGarbageDoesNotPanic is the DoS control. encoding/json is
// not supposed to panic on malformed input; if it starts to, a profile file
// becomes a way to kill the datapath.
func TestWinn3ProfileGarbageDoesNotPanic(t *testing.T) {
	junk := [][]byte{
		{0x00},
		{0xff, 0xfe},
		[]byte("{"),
		[]byte("{]"),
		[]byte("[[[[[[[["),
		bytes.Repeat([]byte{'['}, 32),
		[]byte("1e309"),
		[]byte(`{"version":` + strings.Repeat(`{"a":`, 4) + "1"),
	}
	for i, raw := range junk {
		t.Run(strings.ReplaceAll(string(raw), "\x00", "NUL"), func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("case %d panicked: %v", i, rec)
				}
			}()
			_, err := loadWinn3Profile(writeProfileBytes(t, raw))
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestWinn3ProfileDuplicateJSONKeysAreRefused. encoding/json last-wins;
// this loader must not. A document that states the socket rule twice is
// how a setting the operator believes took effect can be the other value.
// The status parser in this package already refuses duplicate members;
// the profile used to last-win and that was a silent-acceptance hole.
func TestWinn3ProfileDuplicateJSONKeysAreRefused(t *testing.T) {
	encoded := mustMarshalProfile(t, validProfile())
	if encoded[len(encoded)-1] != '}' {
		t.Fatalf("fixture did not end with }: %s", encoded)
	}
	withFalse := append(encoded[:len(encoded)-1], []byte(`,"allow_own_socket":false}`)...)
	_, err := loadWinn3Profile(writeProfileBytes(t, withFalse))
	if err == nil {
		t.Fatal("a duplicate allow_own_socket member was accepted")
	}
	if !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("refused with %q, want duplicate JSON member", err)
	}
	if !errors.Is(err, errWinn3Profile) {
		t.Fatalf("refusal is not errWinn3Profile: %v", err)
	}
}

// TestWinn3ProfilePaddedToTheByteCeilingStillLoads is the over-fire control
// for the size bound: a legitimate object padded with spaces to exactly
// maxWinn3ProfileBytes must still load, or the bound is refusing documents
// it claimed only to cap.
func TestWinn3ProfilePaddedToTheByteCeilingStillLoads(t *testing.T) {
	encoded := mustMarshalProfile(t, validProfile())
	if len(encoded) >= maxWinn3ProfileBytes {
		t.Fatalf("fixture is %d bytes, at or above the %d-byte ceiling",
			len(encoded), maxWinn3ProfileBytes)
	}
	padded := make([]byte, maxWinn3ProfileBytes)
	copy(padded, encoded)
	for i := len(encoded); i < len(padded); i++ {
		padded[i] = ' '
	}
	if _, err := loadWinn3Profile(writeProfileBytes(t, padded)); err != nil {
		t.Fatalf("a legitimate profile padded to the ceiling was refused: %v", err)
	}
}

func TestWinn3ValidateEndpointRefusesNonUnicast(t *testing.T) {
	for _, endpoint := range []string{
		"0.0.0.0:51820", "[::]:51820", "224.0.0.1:51820", "[ff02::1]:51820",
		"255.255.255.255:51820",
	} {
		if err := winn3ValidateEndpoint(endpoint); err == nil {
			t.Errorf("%s was accepted", endpoint)
		} else if !strings.Contains(err.Error(), "unicast") {
			t.Errorf("%s refused with %v, want unicast", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"127.0.0.1:51820", "[::1]:51820", "198.51.100.7:51820", "[2001:db8::7]:51820",
	} {
		if err := winn3ValidateEndpoint(endpoint); err != nil {
			t.Errorf("%s was refused: %v", endpoint, err)
		}
	}
}

// TestWinn3CreateAlsoRefusesANonUnicastEndpoint is the shared-function
// control: winn3ValidateEndpoint is also the Create-frame endpoint rule, so
// a profile-only table would not prove the frame path moved with it.
func TestWinn3CreateAlsoRefusesANonUnicastEndpoint(t *testing.T) {
	document := validCreate()
	document["gateway_endpoint"] = "0.0.0.0:51820"
	_, err := decodeWinn3Create(createBytes(t, document), true, false)
	if err == nil {
		t.Fatal("a Create document with an unspecified endpoint was accepted")
	}
	if !strings.Contains(err.Error(), "unicast") {
		t.Fatalf("refused, but not for unicast: %v", err)
	}
}

func TestWinn3CreateAlsoRefusesLimitedBroadcast(t *testing.T) {
	document := validCreate()
	document["gateway_endpoint"] = "255.255.255.255:51820"
	_, err := decodeWinn3Create(createBytes(t, document), true, false)
	if err == nil {
		t.Fatal("a Create document with a limited-broadcast endpoint was accepted")
	}
	if !strings.Contains(err.Error(), "unicast") {
		t.Fatalf("refused, but not for unicast: %v", err)
	}
}

func TestWinn3ProfileDirectoryIsRefused(t *testing.T) {
	_, err := loadWinn3Profile(t.TempDir())
	if err == nil {
		t.Fatal("a directory was accepted as a profile")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("refused with %q, want regular file", err)
	}
}

func TestWinn3ProfileMissingFileIsRefused(t *testing.T) {
	_, err := loadWinn3Profile(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("a missing file was accepted")
	}
}

func TestWinn3JSONNestingDepthAtCeilingIsAllowed(t *testing.T) {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < maxWinn3ProfileJSONDepth-1; i++ {
		b.WriteString(`"x":{`)
	}
	b.WriteString(`"y":1`)
	for i := 0; i < maxWinn3ProfileJSONDepth; i++ {
		b.WriteByte('}')
	}
	if got := winn3JSONNestingDepth([]byte(b.String())); got != maxWinn3ProfileJSONDepth {
		t.Fatalf("depth %d, want %d", got, maxWinn3ProfileJSONDepth)
	}
}

// TestWinn3ProfileDuplicateJSONKeysEndingInTrueAreRefused is the other
// last-wins polarity: the last value would have made the document load.
// Refusing only the polarity that validate() already rejects is not a
// duplicate-key guard.
func TestWinn3ProfileDuplicateJSONKeysEndingInTrueAreRefused(t *testing.T) {
	encoded := mustMarshalProfile(t, validProfile())
	if encoded[len(encoded)-1] != '}' {
		t.Fatalf("fixture did not end with }: %s", encoded)
	}
	withTrue := append(encoded[:len(encoded)-1], []byte(`,"allow_own_socket":false,"allow_own_socket":true}`)...)
	_, err := loadWinn3Profile(writeProfileBytes(t, withTrue))
	if err == nil {
		t.Fatal("duplicate allow_own_socket ending in true was accepted (last-wins would have loaded)")
	}
	if !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("refused with %q, want duplicate JSON member", err)
	}
}

func TestWinn3LimitedBroadcastIsOnlyTheAllOnesAddress(t *testing.T) {
	if !winn3LimitedBroadcast(netip.MustParseAddr("255.255.255.255")) {
		t.Fatal("255.255.255.255 was not classified as limited broadcast")
	}
	for _, ip := range []string{"198.51.100.7", "127.0.0.1", "224.0.0.1", "::", "2001:db8::7"} {
		if winn3LimitedBroadcast(netip.MustParseAddr(ip)) {
			t.Fatalf("%s was classified as limited broadcast", ip)
		}
	}
}
