package tun

import (
	"errors"
	"strings"
	"testing"
)

// TestNewRefusesIPv6WhenCarrierFloorCannotCarryTheIPv6LinkMinimum pins the
// construction check that TestConfigRefusesWhatWouldSilentlyBreak does not
// reach: a carrier floor above the IPv4 floor (576+overhead) but below
// MinCarrierMessageForIPv6 (1309). That is the IPv6 black-hole config —
// the tunnel would start, small packets would work, and the first 1280-byte
// inner packet would vanish.
//
// The error text must name "carrier floor" so a device-MTU refusal cannot
// masquerade as this check. The same floor is accepted for v4-only, which is
// the positive control that the refusal is the v6 floor and not a broken New.
func TestNewRefusesIPv6WhenCarrierFloorCannotCarryTheIPv6LinkMinimum(t *testing.T) {
	floor := MinCarrierMessageForIPv6() - 1
	inner := InnerMTU(floor)
	if inner >= IPv6MinLinkMTU {
		t.Fatalf("harness: floor %d yields inner MTU %d, not below %d", floor, inner, IPv6MinLinkMTU)
	}
	if inner < MinInnerMTUv4 {
		t.Fatalf("harness: floor %d yields inner MTU %d, below the IPv4 floor — a different New check would fire", floor, inner)
	}

	_, err := New(Config{
		Assign:                  fixtureAssign(),
		Device:                  &fakeDevice{mtu: IPv6MinLinkMTU},
		Sink:                    &fakeSink{},
		Clock:                   newFakeClock(),
		CarrierFloorMessageSize: floor,
	})
	if err == nil {
		t.Fatal("New accepted inner IPv6 on a carrier floor that cannot carry a 1280-byte packet")
	}
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("New: %v, want ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "carrier floor") {
		t.Fatalf("error %q does not name the carrier floor; a different construction check may have fired", err)
	}

	v4, err := New(Config{
		Assign:                  Assignment{V4: fixtureAssign().V4, RouterV4: fixtureAssign().RouterV4},
		Device:                  &fakeDevice{mtu: inner},
		Sink:                    &fakeSink{},
		Clock:                   newFakeClock(),
		CarrierFloorMessageSize: floor,
	})
	if err != nil {
		t.Fatalf("v4-only New with the same floor was refused: %v", err)
	}
	if v4.InnerMTU() != inner {
		t.Fatalf("v4-only InnerMTU=%d, want %d", v4.InnerMTU(), inner)
	}
}
