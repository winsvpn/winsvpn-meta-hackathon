package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWinn3ProfileJSONAdversarialRemaining is the second hostile-document
// table for loadWinn3Profile. The first table in
// winn3_profile_adversarial_test.go pins the 2026-08-12 size/depth/unicast
// guards. This one pins holes that table did not name: duplicate JSON
// members (now refused), type confusion, whitespace-only strings, and
// residuals that still load so they are not mistaken for detection.
func TestWinn3ProfileJSONAdversarialRemaining(t *testing.T) {
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
		{
			name: "duplicate top-level allow_own_socket",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				if encoded[len(encoded)-1] != '}' {
					t.Fatalf("fixture did not end with }: %s", encoded)
				}
				return append(encoded[:len(encoded)-1], []byte(`,"allow_own_socket":false}`)...)
			},
			wantErr: "duplicate JSON member",
		},
		{
			name: "duplicate nested carrier.endpoint",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"endpoint":"198.51.100.7:51820"`)
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old,
					[]byte(`"endpoint":"198.51.100.7:51820","endpoint":"203.0.113.7:51820"`), 1)
			},
			wantErr: "duplicate JSON member",
		},
		{
			name: "duplicate nested keys.static_path",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"static_path":"/nonexistent/static.key"`)
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old,
					[]byte(`"static_path":"/nonexistent/static.key","static_path":"/other/static.key"`), 1)
			},
			wantErr: "duplicate JSON member",
		},
		{
			name: "version as number",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["version"] = 1
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "role as boolean",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["role"] = true
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "device.kind as number",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"].(map[string]any)["kind"] = 1
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "fast_pq as string",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["fast_pq"] = "true"
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu as array",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["path_mtu"] = []int{1450}
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu with a trailing .0 is still a JSON number that is not an int",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"path_mtu":` + jsonNumber(t, validProfile()["path_mtu"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"path_mtu":1450.0`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "path_mtu with a leading plus is not JSON",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"path_mtu":` + jsonNumber(t, validProfile()["path_mtu"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"path_mtu":+1450`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "inner JSON null zeros the assignment",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = nil
				return mustMarshalProfile(t, document)
			},
			wantErr: "neither an IPv4 nor an IPv6",
		},
		{
			name: "keys JSON null empties every path",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["keys"] = nil
				return mustMarshalProfile(t, document)
			},
			wantErr: "static_path is empty",
		},
		{
			name: "device JSON null leaves kind empty",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"] = nil
				return mustMarshalProfile(t, document)
			},
			wantErr: "device.kind",
		},
		{
			name: "carrier JSON null leaves class empty",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"] = nil
				return mustMarshalProfile(t, document)
			},
			wantErr: "unknown carrier class",
		},
		{
			name: "plan mixed types cannot decode into []string",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"plan":["udp","tcp","tls"]`)
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"plan":["udp",1]`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "plan as object",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = map[string]any{"udp": true}
				return mustMarshalProfile(t, document)
			},
			wantErr: "decode",
		},
		{
			name: "empty carrier.class",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["class"] = ""
				return mustMarshalProfile(t, document)
			},
			wantErr: "unknown carrier class",
		},
		{
			name: "carrier.class UDP is not udp",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["class"] = "UDP"
				return mustMarshalProfile(t, document)
			},
			wantErr: "unknown carrier class",
		},
		{
			name: "carrier.class is not named in the plan",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["plan"] = []string{"tcp", "tls"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "is not named in the plan",
		},
		{
			name: "whitespace-only gateway_id",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["gateway_id"] = "   "
				return mustMarshalProfile(t, document)
			},
			wantErr: "gateway_id is empty",
		},
		{
			name: "whitespace-only static_path",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["keys"].(map[string]any)["static_path"] = "   "
				return mustMarshalProfile(t, document)
			},
			wantErr: "static_path is empty",
		},
		{
			name: "whitespace-only admission_path",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["keys"].(map[string]any)["admission_path"] = "\t\n"
				return mustMarshalProfile(t, document)
			},
			wantErr: "admission_path is empty",
		},
		{
			name: "host_port 0 is not a usable port",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"].(map[string]any)["host_port"] = 0
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a usable port",
		},
		{
			name: "host_port omitted is zero and is not a usable port",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				delete(document["device"].(map[string]any), "host_port")
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a usable port",
		},
		{
			name: "host_port JSON null is zero and is not a usable port",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"host_port":` + jsonNumber(t, validProfile()["device"].(map[string]any)["host_port"]))
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"host_port":null`), 1)
			},
			wantErr: "not a usable port",
		},
		{
			name: "empty endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = ""
				return mustMarshalProfile(t, document)
			},
			wantErr: "empty",
		},
		{
			name: "whitespace-only endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "   "
				return mustMarshalProfile(t, document)
			},
			wantErr: "empty",
		},
		{
			name: "inner.v4 CIDR is not an address",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = map[string]any{"v4": "10.64.0.2/32", "router_v4": "10.64.0.1"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "inner.v4",
		},
		{
			name: "inner.v4 as a JSON number",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"v4":"10.64.0.2"`)
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"v4":10`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "JSON block comment",
			raw: func(t *testing.T) []byte {
				return append([]byte("/* hostile */"), valid(t)...)
			},
			wantErr: "decode",
		},
		{
			name: "single-quoted JSON",
			raw: func(*testing.T) []byte {
				return []byte(`{'version':'winn3-host/1'}`)
			},
			wantErr: "decode",
		},
		{
			name: "unquoted object key",
			raw: func(*testing.T) []byte {
				return []byte(`{version:"winn3-host/1"}`)
			},
			wantErr: "decode",
		},
		{
			name: "JSON undefined is not a value",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"fast_pq":false`)
				if bytes.Contains(encoded, old) {
					return bytes.Replace(encoded, old, []byte(`"fast_pq":undefined`), 1)
				}
				if encoded[len(encoded)-1] != '}' {
					t.Fatalf("fixture did not end with }: %s", encoded)
				}
				return append(encoded[:len(encoded)-1], []byte(`,"fast_pq":undefined}`)...)
			},
			wantErr: "decode",
		},
		{
			name: "trailing comma in the plan array",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				old := []byte(`"plan":["udp","tcp","tls"]`)
				if !bytes.Contains(encoded, old) {
					t.Fatalf("fixture does not contain %s: %s", old, encoded)
				}
				return bytes.Replace(encoded, old, []byte(`"plan":["udp","tcp","tls",]`), 1)
			},
			wantErr: "decode",
		},
		{
			name: "NUL inside the object",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				return append([]byte{'{', 0x00}, encoded[1:]...)
			},
			wantErr: "decode",
		},
		{
			name: "UTF-16 LE BOM",
			raw: func(t *testing.T) []byte {
				return append([]byte{0xFF, 0xFE}, valid(t)...)
			},
			wantErr: "decode",
		},
		{
			name: "allow_own_socket omitted is false and is refused",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				delete(document, "allow_own_socket")
				return mustMarshalProfile(t, document)
			},
			wantErr: "allow_own_socket is false",
		},
		{
			name: "role with trailing space is not client",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["role"] = "client "
				return mustMarshalProfile(t, document)
			},
			wantErr: "role is",
		},
		{
			name: "device.kind with trailing space is not a kind",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["device"].(map[string]any)["kind"] = winn3DeviceLoopbackUDP + " "
				return mustMarshalProfile(t, document)
			},
			wantErr: "device.kind",
		},
		{
			name: "administratively scoped multicast IPv4 endpoint",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "239.255.255.250:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "not a unicast IP literal",
		},

		// --- residuals: accepted at load, so a later reader cannot claim they are detected ---
		{
			name: "directed-broadcast IPv4 endpoint currently loads (only 255.255.255.255 is refused)",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "198.51.100.255:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "link-local IPv6 endpoint currently loads",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "[fe80::1]:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "zoned IPv6 endpoint currently loads",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["carrier"].(map[string]any)["endpoint"] = "[fe80::1%lo0]:51820"
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "inner multicast IPv4 is accepted at load (martian check is tun.New, not this parser)",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = map[string]any{"v4": "224.0.0.1", "router_v4": "10.64.0.1"}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "inner IPv4-mapped IPv6 in the v6 field is accepted at load (tun.New refuses Is4In6)",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["inner"] = map[string]any{
					"v6": "::ffff:10.64.0.2", "router_v6": "fd00:d951:1::1",
				}
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "CRLF between tokens still loads",
			raw: func(t *testing.T) []byte {
				encoded := valid(t)
				replaced := bytes.Replace(encoded, []byte(`{`), []byte("{\r\n"), 1)
				if bytes.Equal(replaced, encoded) {
					t.Fatal("fixture did not start with {")
				}
				return replaced
			},
			wantErr: "",
		},
		{
			name: "fast_pq true still loads",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				document["fast_pq"] = true
				return mustMarshalProfile(t, document)
			},
			wantErr: "",
		},
		{
			name: "fast_pq omitted is StrictPQ and still loads",
			raw: func(t *testing.T) []byte {
				document := validProfile()
				delete(document, "fast_pq")
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
					t.Fatalf("refused a document this row claims still loads: %v", err)
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

func TestWinn3DuplicateJSONMemberFindsNestedAndIgnoresMalformed(t *testing.T) {
	if got := winn3DuplicateJSONMember([]byte(`{"a":1,"a":2}`)); got != "a" {
		t.Fatalf("top-level duplicate: got %q", got)
	}
	if got := winn3DuplicateJSONMember([]byte(`{"a":{"b":1,"b":2}}`)); got != "b" {
		t.Fatalf("nested duplicate: got %q", got)
	}
	if got := winn3DuplicateJSONMember([]byte(`{"a":1,"b":1}`)); got != "" {
		t.Fatalf("no duplicate: got %q", got)
	}
	encoded, err := json.Marshal(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	if got := winn3DuplicateJSONMember(encoded); got != "" {
		t.Fatalf("valid profile reported duplicate %q", got)
	}
	if got := winn3DuplicateJSONMember([]byte(`{"version":`)); got != "" {
		t.Fatalf("malformed JSON reported duplicate %q; Decode must own that error", got)
	}
}

func TestWinn3ProfileSymlinkToRegularFileLoads(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, mustMarshalProfile(t, validProfile()), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWinn3Profile(link); err != nil {
		t.Fatalf("a symlink to a regular profile was refused: %v", err)
	}
}

func TestWinn3ProfileSymlinkToDirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	_, err := loadWinn3Profile(link)
	if err == nil {
		t.Fatal("a symlink to a directory was accepted")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("refused with %q, want regular file", err)
	}
}
