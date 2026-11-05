package main

import (
	"encoding/binary"
	"errors"
	"testing"
)

// ipv4 builds a minimal IPv4 packet of total length `total` whose header
// declares `declared`.
func ipv4(total, declared int) []byte {
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(declared))
	return pkt
}

// ipv6 builds a minimal IPv6 packet of total length `total` whose header
// declares a payload length of `payload`.
func ipv6(total, payload int) []byte {
	pkt := make([]byte, total)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payload))
	return pkt
}

// Plan-correct published MTUs remain valid even when they equal a former trap.
func TestPublishedPlanMTUsAreAccepted(t *testing.T) {
	for _, plan := range []struct{ path, overhead, header, inner int }{
		{1364, 112, 29, 1223},
		{1470, 48, 29, 1393},
	} {
		if plan.path-plan.overhead-plan.header != plan.inner {
			t.Fatal("invalid plan sizing fixture")
		}
		if err := validateInnerMTU(plan.inner); err != nil {
			t.Fatalf("refused published plan MTU %d: %v", plan.inner, err)
		}
	}
}

// TestTheFloorMTUIsAccepted pins the other half: the correct value must not be
// caught by the tripwire that catches the wrong one.
func TestTheFloorMTUIsAccepted(t *testing.T) {
	if err := validateInnerMTU(winn3ShippingFloorInnerMTU); err != nil {
		t.Fatalf("refused the plan floor inner MTU %d: %v",
			winn3ShippingFloorInnerMTU, err)
	}
}

// TestTheFloorMTUCannotCarryInnerIPv6 records, as an executable fact, why the
// bootstrap posture has no IPv6 in it. 1139 is below RFC 8200's 1280-byte
// minimum link MTU, so an inner IPv6 assignment at the shipping floor is not a
// policy choice this lane made -- it is arithmetically impossible.
func TestTheFloorMTUCannotCarryInnerIPv6(t *testing.T) {
	if winn3ShippingFloorInnerMTU >= winn3IPv6MinLinkMTU {
		t.Fatalf("floor inner MTU %d is no longer below the %d-byte IPv6 "+
			"minimum; the no-IPv6 bootstrap rule needs rereading",
			winn3ShippingFloorInnerMTU, winn3IPv6MinLinkMTU)
	}
}

func TestValidateInnerMTU(t *testing.T) {
	cases := []struct {
		name   string
		mtu    int
		accept bool
	}{
		{"zero", 0, false},
		{"negative", -1, false},
		{"below the IPv4 minimum", 575, false},
		{"exactly the IPv4 minimum", 576, true},
		{"the plan floor", 1139, true},
		{"published 1364-byte path plan", 1223, true},
		{"published 1470-byte path plan", 1393, true},
		{"a wider measured path", 1443, true},
		{"above the maximum", 65536, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateInnerMTU(testCase.mtu)
			if testCase.accept && err != nil {
				t.Fatalf("refused %d: %v", testCase.mtu, err)
			}
			if !testCase.accept && err == nil {
				t.Fatalf("accepted %d", testCase.mtu)
			}
		})
	}
}

func TestClassifyInnerPacket(t *testing.T) {
	const mtu = 1139
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, errPacketEmpty},
		{"one byte over the MTU", ipv4(mtu+1, mtu+1), errPacketOversize},
		{"exactly the MTU", ipv4(mtu, mtu), nil},
		{"a normal IPv4 packet", ipv4(64, 64), nil},
		{"a normal IPv6 packet", ipv6(64, 24), nil},
		{"not an IP version at all", []byte{0x00, 0x01, 0x02, 0x03}, errPacketNotIP},
		{"an ethernet frame by mistake", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			errPacketNotIP},
		{"IPv4 shorter than its header", ipv4(19, 19)[:19], errPacketShort},
		{"IPv6 shorter than its header", ipv6(39, 0)[:39], errPacketShort},
		{"IPv4 declaring more than arrived", ipv4(40, 120), errPacketDeclared},
		{"IPv6 declaring more than arrived", ipv6(48, 120), errPacketDeclared},
		{"IPv4 declaring less than arrived is allowed", ipv4(80, 40), nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := classifyInnerPacket(testCase.pkt, mtu)
			if !errors.Is(got, testCase.want) {
				t.Fatalf("classify(%d bytes) = %v, want %v",
					len(testCase.pkt), got, testCase.want)
			}
		})
	}
}

// TestAVersion4NibbleIsNotEnough guards the specific confusion that would mean
// the relay had been wired to the wrong side of the seam: an AmneziaWG outer
// datagram arriving where an inner IP packet belongs. Such a datagram begins
// with a WireGuard message type in its first byte -- 0x01..0x04 -- whose high
// nibble is 0, so it is refused as "not an IP packet" rather than forwarded.
// If this ever passes, cleartext is reaching a gateway.
func TestAVersion4NibbleIsNotEnough(t *testing.T) {
	for _, messageType := range []byte{0x01, 0x02, 0x03, 0x04} {
		datagram := make([]byte, 148)
		datagram[0] = messageType
		if err := classifyInnerPacket(datagram, 1139); !errors.Is(err, errPacketNotIP) {
			t.Fatalf("an AmneziaWG type-%d datagram classified as %v, "+
				"expected it to be refused as not an IP packet",
				messageType, err)
		}
	}
}

func TestParseStartCommandIsStrict(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		accept bool
	}{
		{"the good case", "start mtu=1139 engine-port=54321", true},
		{"trailing whitespace", "  start mtu=1139 engine-port=54321  ", true},
		{"no verb", "mtu=1139 engine-port=54321", false},
		{"wrong verb", "begin mtu=1139 engine-port=54321", false},
		{"missing mtu", "start engine-port=54321", false},
		{"missing port", "start mtu=1139", false},
		{"unknown field", "start mtu=1139 engine-port=54321 turbo=1", false},
		{"misspelled field", "start mtu=1139 engineport=54321", false},
		{"duplicate field", "start mtu=1139 mtu=1223 engine-port=54321", false},
		{"not key=value", "start 1139 54321", false},
		{"non-numeric", "start mtu=big engine-port=54321", false},
		{"port zero", "start mtu=1139 engine-port=0", false},
		{"port too large", "start mtu=1139 engine-port=70000", false},
		{"published plan MTU", "start mtu=1223 engine-port=54321", true},
		{"empty", "", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cmd, err := parseStartCommand(testCase.line)
			if testCase.accept {
				if err != nil {
					t.Fatalf("refused %q: %v", testCase.line, err)
				}
				expectedMTU := 1139
				if testCase.name == "published plan MTU" {
					expectedMTU = 1223
				}
				if cmd.mtu != expectedMTU || cmd.enginePort != 54321 {
					t.Fatalf("parsed %q as %+v", testCase.line, cmd)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %q as %+v", testCase.line, cmd)
			}
		})
	}
}
