package observability

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactAddressesRemovesPeerAddresses(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		absent  []string
		present []string
	}{
		{
			name:    "net/http TLS handshake error with IPv4 and port",
			line:    "http: TLS handshake error from 203.0.113.7:44100: unexpected EOF\n",
			absent:  []string{"203.0.113.7", "44100"},
			present: []string{"TLS handshake error", "unexpected EOF", RedactedAddress},
		},
		{
			name:    "ECH rejection carries the same peer address",
			line:    "http: TLS handshake error from 198.51.100.22:9931: winn requires accepted Encrypted Client Hello\n",
			absent:  []string{"198.51.100.22", "9931"},
			present: []string{"winn requires accepted Encrypted Client Hello"},
		},
		{
			name:    "bracketed IPv6 with port",
			line:    "http: TLS handshake error from [2001:db8::dead:beef]:44100: remote error\n",
			absent:  []string{"2001:db8", "dead:beef", "44100"},
			present: []string{"remote error", RedactedAddress},
		},
		{
			name:    "bare IPv6 loopback",
			line:    "http2: server: error reading preface from client ::1 timeout\n",
			absent:  []string{"::1"},
			present: []string{"error reading preface", RedactedAddress},
		},
		{
			name:    "bare IPv4 without a port",
			line:    "http: proxy error for 192.0.2.9 while dialing\n",
			absent:  []string{"192.0.2.9"},
			present: []string{"proxy error", "while dialing"},
		},
		{
			name:    "non-address tokens survive untouched",
			line:    "carrier_auth_rejected suite=x25519-mlkem768 generation=7\n",
			absent:  []string{RedactedAddress},
			present: []string{"carrier_auth_rejected", "x25519-mlkem768", "generation=7"},
		},
		{
			name: "net.OpError glues local->remote with no spaces",
			line: "http: TLS handshake error from 198.51.100.9:54321: read tcp 192.0.2.1:443->198.51.100.9:54321: i/o timeout\n",
			absent: []string{
				"198.51.100.9", "192.0.2.1", "54321",
			},
			present: []string{"TLS handshake error", "i/o timeout", "->", RedactedAddress},
		},
		{
			name: "net.OpError IPv6 local->remote",
			line: "http: TLS handshake error from [2001:db8::2]:59999: read tcp [2001:db8::1]:443->[2001:db8::2]:59999: i/o timeout\n",
			absent: []string{
				"2001:db8", "59999",
			},
			present: []string{"i/o timeout", "->", RedactedAddress},
		},
		{
			name:    "non-address arrow is preserved, not treated as an address",
			line:    "carrier_path foo->bar generation=7\n",
			absent:  []string{RedactedAddress},
			present: []string{"foo->bar", "generation=7"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := RedactAddresses(testCase.line)
			for _, forbidden := range testCase.absent {
				if strings.Contains(got, forbidden) {
					t.Fatalf("redacted line still contains %q: %q", forbidden, got)
				}
			}
			for _, required := range testCase.present {
				if !strings.Contains(got, required) {
					t.Fatalf("redacted line lost %q: %q", required, got)
				}
			}
			if !strings.HasSuffix(got, "\n") {
				t.Fatalf("redaction dropped the line terminator: %q", got)
			}
		})
	}
}

func TestErrorLoggerRedactsThroughLogPackage(t *testing.T) {
	var sink bytes.Buffer
	logger := ErrorLogger(&sink, "tls: ")
	logger.Printf("http: TLS handshake error from 203.0.113.7:44100: unexpected EOF")
	output := sink.String()
	if strings.Contains(output, "203.0.113.7") {
		t.Fatalf("logger leaked the peer address: %q", output)
	}
	if !strings.Contains(output, "tls: ") {
		t.Fatalf("logger dropped its prefix: %q", output)
	}
	if !strings.Contains(output, "unexpected EOF") {
		t.Fatalf("logger dropped the error class: %q", output)
	}
}

func TestErrorLoggerRedactsOpErrorThroughLogPackage(t *testing.T) {
	var sink bytes.Buffer
	logger := ErrorLogger(&sink, "winn3-gateway cover: ")
	logger.Printf("http: TLS handshake error from 198.51.100.9:54321: read tcp 192.0.2.1:443->198.51.100.9:54321: i/o timeout")
	output := sink.String()
	for _, forbidden := range []string{"198.51.100.9", "192.0.2.1"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("logger leaked %q: %q", forbidden, output)
		}
	}
	if !strings.Contains(output, "i/o timeout") {
		t.Fatalf("logger dropped the error class: %q", output)
	}
	if !strings.Contains(output, "winn3-gateway cover: ") {
		t.Fatalf("logger dropped its prefix: %q", output)
	}
}

func TestRedactAddressesOpErrorExactLine(t *testing.T) {
	got := RedactAddresses("http: TLS handshake error from 198.51.100.9:54321: read tcp 192.0.2.1:443->198.51.100.9:54321: i/o timeout\n")
	want := "http: TLS handshake error from [redacted-peer]: read tcp [redacted-peer]->[redacted-peer]: i/o timeout\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// A short write must not surface as an error to log.Logger, which would make
// the standard library report a logging failure on every redacted line.
func TestPeerRedactingWriterReportsCallerLength(t *testing.T) {
	var sink bytes.Buffer
	writer := NewPeerRedactingWriter(&sink)
	line := []byte("http: TLS handshake error from 203.0.113.7:44100: EOF\n")
	written, err := writer.Write(line)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if written != len(line) {
		t.Fatalf("Write reported %d bytes, want the caller's %d", written, len(line))
	}
}

func TestPeerRedactingWriterToleratesNilSink(t *testing.T) {
	writer := NewPeerRedactingWriter(nil)
	if _, err := writer.Write([]byte("anything\n")); err != nil {
		t.Fatalf("nil sink must not fail: %v", err)
	}
}
