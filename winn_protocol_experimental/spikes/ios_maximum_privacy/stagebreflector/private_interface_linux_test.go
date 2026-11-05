//go:build linux

package stagebreflector

import (
	"errors"
	"math"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxFileDescriptorRejectsOutOfRangeValue(t *testing.T) {
	if descriptor, ok := linuxFileDescriptor(0); !ok || descriptor != 0 {
		t.Fatalf("zero descriptor = %d, %t", descriptor, ok)
	}
	if _, ok := linuxFileDescriptor(^uintptr(0)); ok {
		t.Fatal("out-of-range descriptor was accepted")
	}
}

func TestLinuxPrivateInterfaceRejectsNegativeEncodedIPv4Index(t *testing.T) {
	control := unix.PktInfo4(&unix.Inet4Pktinfo{Ifindex: -1})
	controller := linuxPrivateInterfaceController{}
	if _, err := controller.InboundInterfaceIndex("udp4", control); !errors.Is(err, ErrPrivateInterface) {
		t.Fatalf("negative encoded interface index error = %v", err)
	}
}

func TestLinuxPrivateInterfaceRejectsOutOfRangeResponseIndex(t *testing.T) {
	controller := linuxPrivateInterfaceController{}
	connection := &privateTestConnection{}
	destination := netip.MustParseAddrPort("10.0.0.2:443")

	if _, err := controller.WriteResponse(
		connection,
		"udp4",
		[]byte("response"),
		destination,
		netip.MustParseAddr("10.0.0.1"),
		math.MaxInt32+1,
	); !errors.Is(err, ErrPrivateInterface) {
		t.Fatalf("out-of-range IPv4 interface index error = %v", err)
	}
	if len(connection.writes) != 0 {
		t.Fatal("out-of-range interface index reached the socket write")
	}
}
