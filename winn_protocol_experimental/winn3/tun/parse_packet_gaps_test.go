package tun

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestParsePacketGapsAdversarialInputs calls parsePacket directly for the
// structural cases TestParsePacketAdversarialInputs left to Outbound.
// FrameData payloads are inner IP packets; a panic or an over-read here is
// a DoS / cross-flow leak on every delivered data frame.
func TestParsePacketGapsAdversarialInputs(t *testing.T) {
	goodV4 := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8}.build()
	goodV6 := v6cfg{src: fixtureAssign().V6, dst: peerV6(), payload: 8}.build()

	ihlZero := make([]byte, IPv4HeaderMin)
	ihlZero[0] = 0x40 // version 4, IHL 0 → 0-byte header
	binary.BigEndian.PutUint16(ihlZero[2:4], uint16(IPv4HeaderMin))
	ihlZero[8] = 64

	cases := []struct {
		name   string
		in     []byte
		want   error
		accept bool
		v6     bool
	}{
		{"IPv4 IHL 0 on a 20-byte buffer", ihlZero, ErrBadHeader, false, false},
		{"IPv4 IHL 4 (16-byte header claim)", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, ihlWords: 4}.build(), ErrBadHeader, false, false},
		{"IPv4 TTL 0", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, zeroTTL: true}.build(), ErrBadHeader, false, false},
		{"IPv4 reserved flag bit", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, reserved: true}.build(), ErrBadHeader, false, false},
		{"IPv4 bad checksum", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, badChecksum: true}.build(), ErrBadChecksum, false, false},
		{"IPv4 total length below header", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, useTotal: true, total: 12}.build(), ErrBadHeader, false, false},
		{"IPv6 hop limit 0", v6cfg{src: fixtureAssign().V6, dst: peerV6(), payload: 8, zeroHop: true}.build(), ErrBadHeader, false, false},
		{"IPv4 zero payload (total == header)", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 0}.build(), nil, true, false},
		{"IPv4 with 4 bytes of options (IHL 6)", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, ihlWords: 6}.build(), nil, true, false},
		{"IPv4 More Fragments still parses", v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 8, mf: true}.build(), nil, true, false},
		{"IPv6 exact fill, 8-byte payload", goodV6, nil, true, true},
		{"well-formed IPv4 control", goodV4, nil, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("parsePacket panicked: %v", rec)
				}
			}()
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
				t.Fatalf("malformed packet was accepted (src=%s dst=%s body=%d)", p.src, p.dst, len(p.body))
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestParsePacketIPv6BodyIsTruncatedToDeclaredLength is the IPv6 half of
// TestParsePacketIPv4BodyIsTruncatedToDeclaredLength. Bytes past the payload
// length field are the previous packet's tail.
func TestParsePacketIPv6BodyIsTruncatedToDeclaredLength(t *testing.T) {
	pkt := v6cfg{src: fixtureAssign().V6, dst: peerV6(), payload: 8, trailer: 40}.build()
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	declared := IPv6HeaderLen + int(binary.BigEndian.Uint16(pkt[4:6]))
	if len(p.body) != declared {
		t.Fatalf("body is %d bytes, declared total is %d", len(p.body), declared)
	}
	if p.tail != 40 {
		t.Fatalf("tail = %d, want 40", p.tail)
	}
}

// TestParsePacketIPv6PayloadLengthDoesNotOverflowTotal pins
// `total := IPv6HeaderLen + payload` against a 0xFFFF payload length on a
// buffer that is actually large enough. The addition cannot wrap an int on
// this architecture; the risk is a decoder that treats 0xFFFF as "too big"
// without checking the buffer, or that slices past it.
func TestParsePacketIPv6PayloadLengthDoesNotOverflowTotal(t *testing.T) {
	const payload = 0xFFFF
	b := make([]byte, IPv6HeaderLen+payload)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], payload)
	b[7] = 64
	srcV6 := fixtureAssign().V6.As16()
	dstV6 := peerV6().As16()
	copy(b[8:24], srcV6[:])
	copy(b[24:40], dstV6[:])
	p, err := parsePacket(b)
	if err != nil {
		t.Fatalf("max IPv6 payload length was rejected: %v", err)
	}
	if len(p.body) != IPv6HeaderLen+payload {
		t.Fatalf("body is %d, want %d", len(p.body), IPv6HeaderLen+payload)
	}
	if p.tail != 0 {
		t.Fatalf("tail = %d, want 0", p.tail)
	}
}
