package tun

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestParsePacketAdversarialInputs calls parsePacket directly, not through
// Outbound, so a structural refusal cannot be mistaken for a martian or
// source-address drop. FrameData payloads are inner IP packets; a panic
// here is a DoS on every delivered data frame.
func TestParsePacketAdversarialInputs(t *testing.T) {
	goodV4pkt := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8}.build()
	goodV6pkt := v6cfg{src: fixtureAssign().V6, dst: peerV6(), payload: 8}.build()

	cases := []struct {
		name   string
		in     []byte
		want   error
		accept bool
		v6     bool
	}{
		{"empty", nil, ErrShortPacket, false, false},
		{"one byte", []byte{0x45}, ErrShortPacket, false, false},
		{"19-byte IPv4 prefix", goodV4pkt[:19], ErrShortPacket, false, false},
		{"39-byte IPv6 prefix", goodV6pkt[:39], ErrShortPacket, false, false},
		{"version 0", make([]byte, 40), ErrBadVersion, false, false},
		{"version 5", []byte{0x50, 0, 0, 20}, ErrBadVersion, false, false},
		{"version 7 nibble on a one-byte buffer", []byte{0x70}, ErrBadVersion, false, false},
		{"IPv4 total length 0", func() []byte {
			b := append([]byte(nil), goodV4pkt...)
			binary.BigEndian.PutUint16(b[2:4], 0)
			return b
		}(), ErrBadHeader, false, false},
		{"IPv4 IHL 15 with only 20 bytes present", func() []byte {
			b := make([]byte, IPv4HeaderMin)
			b[0] = 0x4f // version 4, IHL 15 → 60-byte header
			binary.BigEndian.PutUint16(b[2:4], 60)
			b[8] = 64
			return b
		}(), ErrBadHeader, false, false},
		{"IPv6 payload length 65535 on a 40-byte packet", func() []byte {
			b := make([]byte, IPv6HeaderLen)
			b[0] = 0x60
			binary.BigEndian.PutUint16(b[4:6], 0xFFFF)
			b[7] = 64
			return b
		}(), ErrBadHeader, false, false},
		{"IPv6 payload length 0", func() []byte {
			b := append([]byte(nil), goodV6pkt...)
			binary.BigEndian.PutUint16(b[4:6], 0)
			return b
		}(), ErrBadHeader, false, false},
		{"well-formed IPv4", goodV4pkt, nil, true, false},
		{"well-formed IPv6", goodV6pkt, nil, true, true},
		{"IPv4 exact fill (no trailer)", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8}.build(), nil, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parsePacket(tc.in)
			if tc.accept {
				if err != nil {
					t.Fatalf("accepted case returned %v", err)
				}
				if p.v6 != tc.v6 {
					t.Fatalf("v6=%v, want %v", p.v6, tc.v6)
				}
				if len(p.body) > len(tc.in) {
					t.Fatalf("body %d bytes from a %d-byte input (over-read)", len(p.body), len(tc.in))
				}
				return
			}
			if err == nil {
				t.Fatalf("malformed packet was accepted (src=%s dst=%s)", p.src, p.dst)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestParsePacketIPv4BodyIsTruncatedToDeclaredLength pins the trailer rule:
// bytes past the IPv4 total-length field are the previous packet's tail and
// must not appear in body.
func TestParsePacketIPv4BodyIsTruncatedToDeclaredLength(t *testing.T) {
	pkt := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, trailer: 40}.build()
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	declared := int(binary.BigEndian.Uint16(pkt[2:4]))
	if len(p.body) != declared {
		t.Fatalf("body is %d bytes, declared total is %d", len(p.body), declared)
	}
	if p.tail != 40 {
		t.Fatalf("tail = %d, want 40", p.tail)
	}
}
