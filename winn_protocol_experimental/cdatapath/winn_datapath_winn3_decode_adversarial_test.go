//go:build darwin

package main

import (
	"strings"
	"testing"
)

// Table-driven adversarial cases for decodeWinn3Config, the JSON parser on
// the Apple standalone create path. A panic here is a denial of service of
// the tunnel process. An under-read (trailing second object accepted) is a
// document the host did not mean to send.
func TestDecodeWinn3ConfigAdversarialTable(t *testing.T) {
	const valid = `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3"}`

	type row struct {
		name    string
		input   string
		wantErr string // substring; empty means accept
	}
	rows := []row{
		{name: "valid minimal object", input: valid},
		{name: "trailing whitespace after one object is not a second value", input: valid + "  \n\t"},
		{name: "leading whitespace", input: "  \n" + valid},
		{
			name:    "concatenated second object is an under-read and must be refused",
			input:   valid + `{"payload":"awg-datagram"}`,
			wantErr: "single JSON object",
		},
		{
			name:    "concatenated array after the object",
			input:   valid + `[1]`,
			wantErr: "single JSON object",
		},
		{
			name:    "trailing JSON true",
			input:   valid + ` true`,
			wantErr: "single JSON object",
		},
		{
			name:    "empty document",
			input:   "",
			wantErr: "empty document",
		},
		{
			name:    "JSON null",
			input:   "null",
			wantErr: "JSON object",
		},
		{
			name:    "JSON array",
			input:   `[]`,
			wantErr: "JSON object",
		},
		{
			name:    "JSON string",
			input:   `"winn3"`,
			wantErr: "JSON object",
		},
		{
			name:    "JSON number",
			input:   "1",
			wantErr: "JSON object",
		},
		{
			name:    "truncated object",
			input:   `{"contract":"winn-datapath/1+winn3"`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "unknown field is a hard refusal",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","allow_downgrade":true}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "relay payload class",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"awg-datagram","carrier":"winn3"}`,
			wantErr: "payload",
		},
		{
			name:    "relay carrier",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"direct-awg"}`,
			wantErr: "carrier",
		},
		{
			name:    "wrong contract",
			input:   `{"contract":"winn-datapath/1","payload":"ip-packet","carrier":"winn3"}`,
			wantErr: "contract",
		},
		{
			name:    "path_mtu overflowing int64 is a decode error, not a wrap",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","path_mtu":9223372036854775808}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "path_mtu as a JSON string is a decode error",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","path_mtu":"1500"}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "allow_own_socket as a JSON string is a decode error",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","allow_own_socket":"true"}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "carrier_classes as a string is a decode error",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","carrier_classes":"udp"}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "trailing comma is a decode error, not silently accepted",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3",}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "JSON comments are a decode error, not stripped",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3"/*x*/}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:  "hostname gateway_endpoint is accepted at decode (openWinn3 refuses later)",
			input: `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","gateway_endpoint":"gateway.example:51820"}`,
		},
		{
			name:    "UTF-8 BOM is a decode error, not stripped",
			input:   "\xef\xbb\xbf" + valid,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:    "empty object is a contract refusal, not a default",
			input:   `{}`,
			wantErr: "contract",
		},
		{
			name:    "JSON NaN is a decode error, not a wrap",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","path_mtu":NaN}`,
			wantErr: "winn3: invalid configuration",
		},
		{
			name:  "negative path_mtu is accepted at decode (openWinn3 / NewSizing refuse later)",
			input: `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","path_mtu":-1}`,
		},
		{
			name:  "hostname inner_v4 is accepted at decode (assignment refuses later)",
			input: `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","inner_v4":"host.example"}`,
		},
		{
			name:    "concatenated second object after a newline is an under-read",
			input:   valid + "\n" + `{"payload":"awg-datagram"}`,
			wantErr: "single JSON object",
		},
		{
			name:  "duplicate contract last-wins: trailing good contract is accepted",
			input: `{"contract":"wrong","contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3"}`,
		},
		{
			name:    "duplicate contract last-wins: trailing bad contract is refused",
			input:   `{"contract":"winn-datapath/1+winn3","payload":"ip-packet","carrier":"winn3","contract":"nope"}`,
			wantErr: "contract",
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := decodeWinn3Config([]byte(r.input))
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

// TestDecodeWinn3ConfigGarbageDoesNotPanic is the DoS control for the Apple
// create parser. A panic here is a denial of service of the tunnel process.
func TestDecodeWinn3ConfigGarbageDoesNotPanic(t *testing.T) {
	inputs := []string{
		"",
		"\x00\x01\x02",
		strings.Repeat("[", 64) + strings.Repeat("]", 64),
		strings.Repeat("{", 32) + strings.Repeat("}", 32),
		`{"contract":"winn-datapath/1+winn3"` + strings.Repeat(" ", 4096),
		strings.Repeat("A", 65536),
		strings.Repeat("{", 100) + strings.Repeat("}", 100),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("decodeWinn3Config panicked on %q: %v", in, rec)
				}
			}()
			_, _ = decodeWinn3Config([]byte(in))
		}()
	}
}
