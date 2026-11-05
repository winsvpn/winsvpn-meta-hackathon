package wirefmt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These bodies are the real helpers the engine instrument uses to assemble its
// DNS probes and to rewrite relayed answers into IPv4/UDP packets. Each test
// answers a pointed question rather than asserting a sentence-level verdict;
// the byte-for-byte expectations were computed from the RFC 1071 algorithm
// independently of this code (see .spark_lanes/scratch/gen_android_devicecheck).

func TestDNSQueryExactBytes(t *testing.T) {
	for _, tc := range []struct {
		id   uint16
		name string
		want []byte
	}{
		{0x1234, "example.com", []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
			0x00, 0x01, 0x00, 0x01,
		}},
		{0x5741, "dns.google", []byte{
			0x57, 0x41, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x03, 'd', 'n', 's', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x00,
			0x00, 0x01, 0x00, 0x01,
		}},
		{0x0001, "localhost", []byte{
			0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00,
			0x00, 0x01, 0x00, 0x01,
		}},
	} {
		got := DNSQuery(tc.id, tc.name)
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("DNSQuery(0x%04x, %q) = %x, want %x (len %d, want %d)",
				tc.id, tc.name, got, tc.want, len(got), len(tc.want))
		}
	}
}

func TestDNSQueryHeaderFields(t *testing.T) {
	got := DNSQuery(0xAAAA, "dns.google")
	if got[0] != 0xAA || got[1] != 0xAA {
		t.Fatalf("transaction id = %x, want 0xaaaa", got[0:2])
	}
	if binary.BigEndian.Uint16(got[2:4]) != 0x0100 {
		t.Fatalf("flags = %x, want 0x0100", got[2:4])
	}
	if binary.BigEndian.Uint16(got[4:6]) != 1 {
		t.Fatalf("question count = %d, want 1", binary.BigEndian.Uint16(got[4:6]))
	}
	if got[len(got)-5] != 0 {
		t.Fatalf("label terminator at %d = %x, want 0", len(got)-5, got[len(got)-5])
	}
	if binary.BigEndian.Uint16(got[len(got)-4:len(got)-2]) != 1 {
		t.Fatalf("qtype = %x, want A(1)", got[len(got)-4:len(got)-2])
	}
	if binary.BigEndian.Uint16(got[len(got)-2:]) != 1 {
		t.Fatalf("qclass = %x, want IN(1)", got[len(got)-2:])
	}
}

func TestDNSQueryDropsEmptyLabels(t *testing.T) {
	// "example..com" must not emit a zero-length label -- the empty label is
	// skipped, unlike a malformed encoder that would write a bare 0x00 mid-name.
	got := DNSQuery(0x9999, "example..com")
	want := DNSQuery(0x9999, "example.com")
	if !bytes.Equal(got, want) {
		t.Fatalf("empty-label name produced different bytes: %x, want %x", got, want)
	}
}

func TestChecksumRFC1071(t *testing.T) {
	// The canonical RFC 1071 IPv4 header example: a zeroed checksum field over
	// this header must fold to 0xb861.
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
		0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
	}
	if got := Checksum(hdr); got != 0xb861 {
		t.Fatalf("checksum(header) = 0x%04x, want 0xb861", got)
	}
	if got := Checksum(nil); got != 0xffff {
		t.Fatalf("checksum(nil) = 0x%04x, want 0xffff", got)
	}
	if got := Checksum([]byte{0x01}); got != 0xfeff {
		t.Fatalf("checksum({0x01}) = 0x%04x, want 0xfeff (odd-length fold)", got)
	}
}

func TestBuildUDPv4ExactBytes(t *testing.T) {
	// Fixed vector: src 203.0.113.1:4242 -> dst 8.8.8.8:53, payload "ABC".
	// Expected bytes include both computed checksums (header 0x1c89, UDP 0x1ebd).
	want := []byte{
		0x45, 0x00, 0x00, 0x1f, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11, 0x1c, 0x89,
		0xcb, 0x00, 0x71, 0x01, 0x08, 0x08, 0x08, 0x08,
		0x10, 0x92, 0x00, 0x35, 0x00, 0x0b, 0x1e, 0xbd, 'A', 'B', 'C',
	}
	src := []byte{203, 0, 113, 1}
	dst := []byte{8, 8, 8, 8}
	got := BuildUDPv4(src, dst, 4242, 53, []byte("ABC"))
	if !bytes.Equal(got, want) {
		t.Fatalf("BuildUDPv4 = %x, want %x", got, want)
	}
}

func TestBuildUDPv4Structure(t *testing.T) {
	src := []byte{10, 1, 2, 3}
	dst := []byte{192, 168, 0, 1}
	payload := []byte("hello")
	got := BuildUDPv4(src, dst, 1111, 53, payload)

	if len(got) != 20+8+len(payload) {
		t.Fatalf("packet length = %d, want %d", len(got), 20+8+len(payload))
	}
	if got[0] != 0x45 {
		t.Fatalf("version/IHL byte = 0x%02x, want 0x45", got[0])
	}
	if got[9] != 17 {
		t.Fatalf("protocol = %d, want 17 (UDP)", got[9])
	}
	if binary.BigEndian.Uint16(got[2:4]) != uint16(len(got)) {
		t.Fatalf("total length field = %d, want %d", binary.BigEndian.Uint16(got[2:4]), len(got))
	}
	if !bytes.Equal(got[12:16], src) || !bytes.Equal(got[16:20], dst) {
		t.Fatalf("IP addresses swapped or wrong: src=%x dst=%x", got[12:16], got[16:20])
	}
	if binary.BigEndian.Uint16(got[20:22]) != 1111 || binary.BigEndian.Uint16(got[22:24]) != 53 {
		t.Fatalf("ports = %d:%d, want 1111:53",
			binary.BigEndian.Uint16(got[20:22]), binary.BigEndian.Uint16(got[22:24]))
	}
	if binary.BigEndian.Uint16(got[24:26]) != uint16(8+len(payload)) {
		t.Fatalf("UDP length field = %d, want %d", binary.BigEndian.Uint16(got[24:26]), 8+len(payload))
	}
	if !bytes.Equal(got[28:], payload) {
		t.Fatalf("payload = %q, want %q", got[28:], payload)
	}
	// The real self-consistency check: with the computed checksum field in
	// place, re-summing the IP header must fold to zero.
	if got := Checksum(got[0:20]); got != 0 {
		t.Fatalf("IP header re-checksum = 0x%04x, want 0x0000 (self-consistent)", got)
	}
}

func TestSplitHostPort(t *testing.T) {
	for _, tc := range []struct {
		in      string
		host    string
		port    int
		wantErr bool
	}{
		{"8.8.8.8:53", "8.8.8.8", 53, false},
		{"127.0.0.1:8080", "127.0.0.1", 8080, false},
		{"example.com:80", "example.com", 80, false},
		{"2001:db8::53", "", 0, true}, // raw v6 without brackets is not a host:port split
		{"notanumber:abc", "", 0, true},
		{"8.8.8.8", "", 0, true},
	} {
		host, port, err := SplitHostPort(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("SplitHostPort(%q) returned %q:%d, want error", tc.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Fatalf("SplitHostPort(%q) unexpected error: %v", tc.in, err)
		}
		if host != tc.host || port != tc.port {
			t.Fatalf("SplitHostPort(%q) = %q:%d, want %q:%d", tc.in, host, port, tc.host, tc.port)
		}
	}
}
