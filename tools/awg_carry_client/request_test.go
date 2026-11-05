package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A throwaway key: never a real one, never written anywhere.
func testKey(fill byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func testQuery(name string) []byte {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

// fullProfile is a non-default served profile with every base parameter.
func fullProfile() map[string]any {
	return map[string]any{
		"Jc": 3, "Jmin": 40, "Jmax": 70, "S1": 21, "S2": 37, "S3": 16, "S4": 0,
		"H1": 1234567, "H2": 2345678, "H3": 3456789, "H4": 4567890,
	}
}

func validRequest() map[string]any {
	return map[string]any{
		"version":         1,
		"id":              7,
		"slug":            "lab-1",
		"transport":       "udp",
		"private_key":     testKey(0x11),
		"peer_public_key": testKey(0x22),
		"local_address":   "10.8.255.1/32",
		"endpoint":        "127.0.0.1:51820",
		"obfuscation":     fullProfile(),
		"dns_server":      "10.8.1.1",
		"dns_port":        53,
		"dns_query_hex":   hex.EncodeToString(testQuery("hub.example.test")),
		"timeout_seconds": 20,
	}
}

func encode(t *testing.T, value any) []byte {
	t.Helper()
	line, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestAValidRequestIsAcceptedAndRenderedDeterministically(t *testing.T) {
	req, echo, err := parseRequest(encode(t, validRequest()), "udp")
	if err != nil {
		t.Fatalf("refused a valid request: %v", err)
	}
	if req.ID != 7 || req.Slug != "lab-1" || req.Transport != "udp" || *echo.ID != 7 {
		t.Fatalf("identification not read: %+v %+v", req, echo)
	}
	if req.EndpointHost != "127.0.0.1" || req.EndpointPort != 51820 || req.Timeout != 20*time.Second {
		t.Fatalf("endpoint or timeout not read: %+v", req)
	}
	if req.LocalAddress.String() != "10.8.255.1" || req.DNSServer.String() != "10.8.1.1" || req.DNSPort != 53 {
		t.Fatalf("addresses not read: %+v", req)
	}
	want := []string{"jc=3", "jmin=40", "jmax=70", "s1=21", "s2=37", "s3=16", "s4=0",
		"h1=1234567", "h2=2345678", "h3=3456789", "h4=4567890"}
	if strings.Join(req.ProfileLines, " ") != strings.Join(want, " ") {
		t.Fatalf("profile lines %v, want %v", req.ProfileLines, want)
	}
	if req.privateKeyHex != strings.Repeat("11", 32) || req.peerPublicHex != strings.Repeat("22", 32) {
		t.Fatal("keys were not decoded to their UAPI hex form")
	}
}

func TestNewerProfileParametersAreAppliedInAFixedOrder(t *testing.T) {
	request := validRequest()
	profile := fullProfile()
	profile["H1"] = "100-200"
	profile["I1"] = "<b 0xf6ab3267fa><r 32>"
	profile["i3"] = "<r 8>"
	profile["random_trailers"] = true
	profile["rekey_timeout"] = 5
	profile["content_padding_addition"] = "0-16"
	request["obfuscation"] = profile
	req, _, err := parseRequest(encode(t, request), "udp")
	if err != nil {
		t.Fatalf("refused newer parameters: %v", err)
	}
	joined := strings.Join(req.ProfileLines, "\n")
	for _, line := range []string{"h1=100-200", "i1=<b 0xf6ab3267fa><r 32>", "i3=<r 8>", "random_trailers=true",
		"rekey_timeout=5", "content_padding_addition=0-16"} {
		if !strings.Contains(joined, line) {
			t.Fatalf("missing %q in %q", line, joined)
		}
	}
	if strings.Index(joined, "i1=") < strings.Index(joined, "h4=") || strings.Index(joined, "i3=") < strings.Index(joined, "i1=") {
		t.Fatalf("order not fixed: %q", joined)
	}
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong version":           func(r map[string]any) { r["version"] = 2 },
		"missing version":         func(r map[string]any) { delete(r, "version") },
		"float id":                func(r map[string]any) { r["id"] = 1.5 },
		"string id":               func(r map[string]any) { r["id"] = "7" },
		"negative id":             func(r map[string]any) { r["id"] = -1 },
		"bool id":                 func(r map[string]any) { r["id"] = true },
		"missing slug":            func(r map[string]any) { delete(r, "slug") },
		"slug with a newline":     func(r map[string]any) { r["slug"] = "lab\n1" },
		"slug with a space":       func(r map[string]any) { r["slug"] = "lab 1" },
		"other transport":         func(r map[string]any) { r["transport"] = "stealth" },
		"unknown transport":       func(r map[string]any) { r["transport"] = "tcp" },
		"short private key":       func(r map[string]any) { r["private_key"] = base64.StdEncoding.EncodeToString([]byte("short")) },
		"hex private key":         func(r map[string]any) { r["private_key"] = strings.Repeat("11", 32) },
		"missing private key":     func(r map[string]any) { delete(r, "private_key") },
		"short peer key":          func(r map[string]any) { r["peer_public_key"] = "AAAA" },
		"local address not /32":   func(r map[string]any) { r["local_address"] = "10.8.255.1/24" },
		"local address v6":        func(r map[string]any) { r["local_address"] = "fd00::1/128" },
		"local address bare":      func(r map[string]any) { r["local_address"] = "10.8.255.1" },
		"endpoint without port":   func(r map[string]any) { r["endpoint"] = "127.0.0.1" },
		"endpoint port zero":      func(r map[string]any) { r["endpoint"] = "127.0.0.1:0" },
		"endpoint port too big":   func(r map[string]any) { r["endpoint"] = "127.0.0.1:70000" },
		"endpoint shell text":     func(r map[string]any) { r["endpoint"] = "$(id):53" },
		"endpoint unbracketed v6": func(r map[string]any) { r["endpoint"] = "::1:51820" },
		"endpoint multicast":      func(r map[string]any) { r["endpoint"] = "224.0.0.1:51820" },
		"profile missing":         func(r map[string]any) { delete(r, "obfuscation") },
		"profile not an object":   func(r map[string]any) { r["obfuscation"] = []int{1} },
		"profile missing S3":      func(r map[string]any) { p := fullProfile(); delete(p, "S3"); r["obfuscation"] = p },
		"profile missing H4":      func(r map[string]any) { p := fullProfile(); delete(p, "H4"); r["obfuscation"] = p },
		"profile unknown key":     func(r map[string]any) { p := fullProfile(); p["J1"] = 1; r["obfuscation"] = p },
		"profile negative":        func(r map[string]any) { p := fullProfile(); p["Jc"] = -1; r["obfuscation"] = p },
		"profile float":           func(r map[string]any) { p := fullProfile(); p["Jc"] = 1.5; r["obfuscation"] = p },
		"profile string count":    func(r map[string]any) { p := fullProfile(); p["Jc"] = "4"; r["obfuscation"] = p },
		"profile H over uint32":   func(r map[string]any) { p := fullProfile(); p["H1"] = 4294967296; r["obfuscation"] = p },
		"profile S over uint16":   func(r map[string]any) { p := fullProfile(); p["S1"] = 65536; r["obfuscation"] = p },
		"profile bad range":       func(r map[string]any) { p := fullProfile(); p["H2"] = "200-100"; r["obfuscation"] = p },
		"profile range text":      func(r map[string]any) { p := fullProfile(); p["H2"] = "a-b"; r["obfuscation"] = p },
		"profile duplicate case":  func(r map[string]any) { p := fullProfile(); p["jc"] = 3; r["obfuscation"] = p },
		"profile empty chain":     func(r map[string]any) { p := fullProfile(); p["I1"] = ""; r["obfuscation"] = p },
		"profile chain newline":   func(r map[string]any) { p := fullProfile(); p["I1"] = "<r 8>\npublic_key=00"; r["obfuscation"] = p },
		"profile bad bool":        func(r map[string]any) { p := fullProfile(); p["random_trailers"] = "yes"; r["obfuscation"] = p },
		"profile bad hex key":     func(r map[string]any) { p := fullProfile(); p["header_protection_key"] = "zz"; r["obfuscation"] = p },
		"dns server v6":           func(r map[string]any) { r["dns_server"] = "fd00::1" },
		"dns server name":         func(r map[string]any) { r["dns_server"] = "dns.example" },
		"dns port zero":           func(r map[string]any) { r["dns_port"] = 0 },
		"dns query not hex":       func(r map[string]any) { r["dns_query_hex"] = "zz" },
		"dns query short":         func(r map[string]any) { r["dns_query_hex"] = "1234" },
		"dns query is a response": func(r map[string]any) {
			q := testQuery("a.b")
			q[2] |= 0x80
			r["dns_query_hex"] = hex.EncodeToString(q)
		},
		"dns query two questions":  func(r map[string]any) { q := testQuery("a.b"); q[5] = 2; r["dns_query_hex"] = hex.EncodeToString(q) },
		"dns query with an answer": func(r map[string]any) { q := testQuery("a.b"); q[7] = 1; r["dns_query_hex"] = hex.EncodeToString(q) },
		"timeout zero":             func(r map[string]any) { r["timeout_seconds"] = 0 },
		"timeout too long":         func(r map[string]any) { r["timeout_seconds"] = 301 },
		"timeout float":            func(r map[string]any) { r["timeout_seconds"] = 2.5 },
		"timeout missing":          func(r map[string]any) { delete(r, "timeout_seconds") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			mutate(request)
			if _, _, err := parseRequest(encode(t, request), "udp"); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
	for name, line := range map[string]string{
		"not json":          "not json",
		"array":             "[1,2]",
		"two values":        `{"version":1} {"version":1}`,
		"string":            `"request"`,
		"empty object":      "{}",
		"null":              "null",
		"key with the key":  `{"version":1,"id":1,"slug":"x","transport":"udp","private_key":"` + testKey(1) + `"}`,
		"number":            "1",
		"ok but trailing":   string(encode(t, validRequest())) + "x",
		"utf8 control slug": `{"version":1,"id":1,"slug":"a\u0007b","transport":"udp"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRequest([]byte(line), "udp"); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestARefusalStillEchoesWhatItCouldRead(t *testing.T) {
	request := validRequest()
	request["private_key"] = "bad"
	_, echo, err := parseRequest(encode(t, request), "udp")
	if err == nil || echo.ID == nil || *echo.ID != 7 || echo.Slug != "lab-1" || echo.Transport != "udp" {
		t.Fatalf("echo %+v err %v", echo, err)
	}
	request = validRequest()
	request["id"] = "x"
	request["slug"] = "bad slug"
	_, echo, err = parseRequest(encode(t, request), "udp")
	if err == nil || echo.ID != nil || echo.Slug != "" || echo.Transport != "udp" {
		t.Fatalf("echo %+v err %v", echo, err)
	}
}

func TestARefusalNeverCarriesTheKey(t *testing.T) {
	request := validRequest()
	request["obfuscation"] = map[string]any{"Jc": testKey(0x11)}
	_, _, err := parseRequest(encode(t, request), "udp")
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), testKey(0x11)) || strings.Contains(err.Error(), strings.Repeat("11", 32)) {
		t.Fatalf("the refusal quotes request material: %v", err)
	}
}

func TestHostNamesAndBracketedV6EndpointsParse(t *testing.T) {
	for value, host := range map[string]string{
		"node.example.org:51820":  "node.example.org",
		"[2001:db8::1]:51820":     "2001:db8::1",
		"203.0.113.9:1":           "203.0.113.9",
		"node.example.org.:65535": "node.example.org.",
	} {
		got, _, err := parseEndpoint(value)
		if err != nil || got != host {
			t.Fatalf("%s: %q %v", value, got, err)
		}
	}
	for _, value := range []string{"[2001:db8::1]51820", "-bad.example:1", "a..b:1", "host name:1", ":1", "x:"} {
		if _, _, err := parseEndpoint(value); err == nil {
			t.Fatalf("%s accepted", value)
		}
	}
}

func TestIsResponseToIsStrictAboutIdAndQR(t *testing.T) {
	query := testQuery("hub.example.test")
	response := append([]byte{}, query...)
	response[2] |= 0x80
	if !isResponseTo(response, query) {
		t.Fatal("a response with the id and QR was not recognised")
	}
	other := append([]byte{}, response...)
	other[1] ^= 1
	if isResponseTo(other, query) {
		t.Fatal("another id was recognised")
	}
	if isResponseTo(query, query) {
		t.Fatal("the query itself (QR clear) was recognised")
	}
	if isResponseTo(response[:11], query) {
		t.Fatal("a truncated header was recognised")
	}
}

// The second review round's parser findings (Astra): every one of these is
// refused before anything is probed.
func TestParserEdgeCasesAreRefused(t *testing.T) {
	cases := map[string]func(map[string]any){
		// A JSON null is not a boolean: it must not read as false.
		"profile null random_trailers": func(r map[string]any) { p := fullProfile(); p["random_trailers"] = nil; r["obfuscation"] = p },
		"profile null disable_cookies": func(r map[string]any) { p := fullProfile(); p["disable_cookies"] = nil; r["obfuscation"] = p },
		// Jmin above Jmax underflows the engine's unsigned junk size.
		"profile Jmin above Jmax": func(r map[string]any) { p := fullProfile(); p["Jmin"] = 71; r["obfuscation"] = p },
		// Ordered but unbounded junk parameters: a resource budget, not a shape.
		"profile Jc above 128":     func(r map[string]any) { p := fullProfile(); p["Jc"] = 129; r["obfuscation"] = p },
		"profile Jmax above 65527": func(r map[string]any) { p := fullProfile(); p["Jmax"] = 65528; r["obfuscation"] = p },
		"dns query name of 256 bytes": func(r map[string]any) {
			r["dns_query_hex"] = hex.EncodeToString(testQuery(strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 62)}, ".")))
		},
		// The question itself is parsed: a label that overruns the message,
		// bytes after the question, a compression pointer, no type and class.
		"dns query label overruns": func(r map[string]any) { r["dns_query_hex"] = "1234010000010000000000003f00010001" },
		"dns query trailing bytes": func(r map[string]any) {
			r["dns_query_hex"] = hex.EncodeToString(append(testQuery("a.b"), 0, 0))
		},
		"dns query compressed name": func(r map[string]any) {
			q := append(testQuery("a.b")[:12], 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0)
			r["dns_query_hex"] = hex.EncodeToString(q)
		},
		"dns query without type and class": func(r map[string]any) {
			q := append(testQuery("a.b")[:12], 3, 'a', 'b', 'c', 0)
			r["dns_query_hex"] = hex.EncodeToString(q)
		},
		"dns query label over 63 bytes": func(r map[string]any) {
			r["dns_query_hex"] = hex.EncodeToString(testQuery(strings.Repeat("a", 64) + ".test"))
		},
		"dns query name over 255 bytes": func(r map[string]any) {
			label := strings.Repeat("a", 60)
			r["dns_query_hex"] = hex.EncodeToString(testQuery(strings.Join([]string{label, label, label, label, label}, ".")))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			mutate(request)
			if _, _, err := parseRequest(encode(t, request), "udp"); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
	// Data after the one JSON object, including a bare closer that
	// json.Decoder.More reports as no further value.
	for name, tail := range map[string]string{"trailing ]": "]", "trailing }": "}", "trailing object": "{}"} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRequest(append(encode(t, validRequest()), tail...), "udp"); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestEqualJunkBoundsExplicitBooleansAndLongNamesAreAccepted(t *testing.T) {
	request := validRequest()
	profile := fullProfile()
	profile["Jmin"], profile["Jmax"] = 50, 50
	profile["random_trailers"] = false
	profile["disable_cookies"] = true
	request["obfuscation"] = profile
	request["dns_query_hex"] = hex.EncodeToString(testQuery(strings.Repeat("a", 63) + ".example.test"))
	req, _, err := parseRequest(encode(t, request), "udp")
	if err != nil {
		t.Fatalf("refused a valid request: %v", err)
	}
	joined := strings.Join(req.ProfileLines, " ")
	for _, line := range []string{"jmin=50", "jmax=50", "random_trailers=false", "disable_cookies=true"} {
		if !strings.Contains(joined, line) {
			t.Fatalf("missing %q in %q", line, joined)
		}
	}
	// The largest junk budget and the longest name (255 bytes on the wire) pass.
	edge := validRequest()
	big := fullProfile()
	big["Jc"], big["Jmin"], big["Jmax"] = 128, 65527, 65527
	edge["obfuscation"] = big
	edge["dns_query_hex"] = hex.EncodeToString(testQuery(strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")))
	if _, _, err := parseRequest(encode(t, edge), "udp"); err != nil {
		t.Fatalf("refused the largest valid junk budget or name: %v", err)
	}
	// Surrounding whitespace is not trailing data.
	line := append(append([]byte(" "), encode(t, validRequest())...), ' ', '\t')
	if _, _, err := parseRequest(line, "udp"); err != nil {
		t.Fatalf("refused a request with surrounding whitespace: %v", err)
	}
}
