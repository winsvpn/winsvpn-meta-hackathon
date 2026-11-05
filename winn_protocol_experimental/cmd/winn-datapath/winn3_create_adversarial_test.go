package main

import (
	"strings"
	"testing"
)

// Table-driven adversarial cases for decodeWinn3Create, the JSON parser on
// the Android/Linux standalone create path. Same under-read rule as
// datapath.ParseConfig and decodeWinn3Config.
func TestDecodeWinn3CreateAdversarialTable(t *testing.T) {
	valid := string(createBytes(t, validCreate()))

	type row struct {
		name    string
		input   string
		wantErr string
	}
	rows := []row{
		{name: "valid create document", input: valid},
		{name: "trailing whitespace after one object", input: valid + " \n"},
		{
			name:    "concatenated second object is an under-read and must be refused",
			input:   valid + `{"payload":"awg-datagram"}`,
			wantErr: "single JSON object",
		},
		{
			name:    "concatenated number after the object",
			input:   valid + " 1",
			wantErr: "single JSON object",
		},
		{
			name:    "empty document",
			input:   "",
			wantErr: "decode:",
		},
		{
			name:    "JSON array",
			input:   `[]`,
			wantErr: "decode:",
		},
		{
			name:    "JSON null",
			input:   "null",
			wantErr: "decode:",
		},
		{
			name:    "unknown field",
			input:   `{"payload":"ip-packet","extra":1}`,
			wantErr: "decode:",
		},
		{
			name:    "relay payload class",
			input:   mustReplacePayload(valid, "awg-datagram"),
			wantErr: "winn/1 relay class",
		},
		{
			name:    "path_mtu overflowing int64 is a decode error, not a wrap",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":9223372036854775808,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "decode:",
		},
		{
			name:    "inner_mtu as a JSON string is a decode error",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":"1359","path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "decode:",
		},
		{
			name:    "owns_tun as 1 is a decode error, not a truthy accept",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":1}`,
			wantErr: "decode:",
		},
		{
			name:    "hostname endpoint is refused",
			input:   `{"payload":"ip-packet","gateway_endpoint":"gateway.example:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "gateway_endpoint",
		},
		{
			name:    "owns_tun true is refused, not a second tun",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":true}`,
			wantErr: "owns_tun",
		},
		{
			name:    "inner_address hostname is refused (would DNS-leak)",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"host.example","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "inner_address",
		},
		{
			name:    "empty inner_address is refused, not defaulted",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "inner_address is empty",
		},
		{
			name:    "negative path_mtu is refused, not wrapped",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":-1,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "negative",
		},
		{
			name:    "JSON string root is a decode error",
			input:   `"winn3"`,
			wantErr: "decode:",
		},
		{
			name:    "truncated object is a decode error",
			input:   `{"payload":"ip-packet"`,
			wantErr: "decode:",
		},
		{
			name:    "trailing comma is a decode error, not silently accepted",
			input:   `{"payload":"ip-packet",}`,
			wantErr: "decode:",
		},
		{
			name:    "JSON comments are a decode error, not stripped",
			input:   strings.TrimSuffix(valid, "}") + "/*x*/}",
			wantErr: "decode:",
		},
		{
			name:    "UTF-8 BOM is a decode error, not stripped",
			input:   "\xef\xbb\xbf" + valid,
			wantErr: "decode:",
		},
		{
			name:    "JSON true root is a decode error",
			input:   "true",
			wantErr: "decode:",
		},
		{
			name:    "JSON number root is a decode error",
			input:   "1",
			wantErr: "decode:",
		},
		{name: "leading whitespace before one object is not a second value", input: "  \n" + valid},
		{
			name:    "concatenated second object after a newline is an under-read",
			input:   valid + "\n" + `{"payload":"awg-datagram"}`,
			wantErr: "single JSON object",
		},
		{
			name:    "empty carrier_classes is refused, not defaulted",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":[],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "carrier_classes is empty",
		},
		{
			name:    "allow_own_socket as 1 is a decode error, not a truthy accept",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":1,"owns_tun":false}`,
			wantErr: "decode:",
		},
		{
			name:    "inner_next_hop hostname is refused (would DNS-leak)",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"host.example","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "inner_next_hop",
		},
		{
			name:    "IPv6 zone on inner_address is refused",
			input:   `{"payload":"ip-packet","gateway_endpoint":"127.0.0.1:51820","inner_address":"fe80::1%lo0","inner_next_hop":"","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "zone",
		},
		{
			name:    "newline in gateway_endpoint is refused (would forge an INI line)",
			input:   "{\"payload\":\"ip-packet\",\"gateway_endpoint\":\"127.0.0.1:51820\\ncarrier=direct-awg\",\"inner_address\":\"10.8.1.3\",\"inner_next_hop\":\"10.8.1.1\",\"inner_mtu\":1359,\"path_mtu\":1500,\"carrier_classes\":[\"udp\",\"tcp\",\"tls\"],\"session_id\":\"s\",\"allow_own_socket\":false,\"owns_tun\":false}",
			wantErr: "gateway_endpoint",
		},
		{
			name:    "missing payload field is not silently ip-packet",
			input:   `{"gateway_endpoint":"127.0.0.1:51820","inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1","inner_mtu":1359,"path_mtu":1500,"carrier_classes":["udp","tcp","tls"],"session_id":"s","allow_own_socket":false,"owns_tun":false}`,
			wantErr: "payload is",
		},
		{
			name:    "JSON NaN is a decode error, not a wrap",
			input:   `{"payload":"ip-packet","path_mtu":NaN}`,
			wantErr: "decode:",
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := decodeWinn3Create([]byte(r.input), true, false)
			if r.wantErr == "" {
				if err != nil {
					t.Fatalf("accepted row refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("hostile input was accepted")
			}
			if !strings.Contains(err.Error(), r.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), r.wantErr)
			}
		})
	}
}

func mustReplacePayload(valid, payload string) string {
	return strings.Replace(valid, `"payload":"ip-packet"`, `"payload":"`+payload+`"`, 1)
}

// TestDecodeWinn3CreateGarbageDoesNotPanic is the DoS control for the
// Android/Linux create parser. encoding/json returns an error past its own
// nesting ceiling; a panic here would still be a denial of service of the
// engine process.
func TestDecodeWinn3CreateGarbageDoesNotPanic(t *testing.T) {
	inputs := []string{
		"",
		"\x00\x01\x02",
		`{"payload":` + strings.Repeat("[", 64) + strings.Repeat("]", 64) + `}`,
		strings.Repeat("{", 32) + strings.Repeat("}", 32),
		`{"payload":"ip-packet"` + strings.Repeat(" ", 4096),
		strings.Repeat("A", 65536),
		strings.Repeat("{", 100) + strings.Repeat("}", 100),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("decodeWinn3Create panicked on %q: %v", in, rec)
				}
			}()
			_, _ = decodeWinn3Create([]byte(in), true, false)
		}()
	}
}
