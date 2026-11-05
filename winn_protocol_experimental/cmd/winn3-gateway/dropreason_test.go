package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// TestDropReasonCountersDistinguishNotForUsFromDelivered pins WHICH reason the
// gateway's per-reason counters report for the two shapes of inner traffic an
// iOS full-tunnel client produces against a userspace reflector.
//
// Background (measured 2026-08-11, winn3_ios_20260811T044620Z): the iPhone
// carried 54 v3 datagrams, the gateway gate opened to StateCarrying, but
// rx_offered 50 / rx_packets 0 / rx_dropped_invalid 50 — every inner packet
// rejected, with no way to tell which of the five rejections was firing. The
// root cause is the reflector's inbound rule (winn3/tun/ip.go, `p.dst !=
// v.ours(p)`): a reflector accepts only packets addressed to its OWN inner
// address, while AllowedIPs = 0.0.0.0/0, ::/0 sends every inner packet to a
// real destination. On top of that the gateway had no inner IPv6 assignment,
// so whatever IPv6 iOS routed into the tunnel failed familyAllowed first.
//
// This test drives the REAL gateway components — tun.Tunnel over reflect.go's
// reflector device, with a pump goroutine standing in for the driver loop —
// and reads the same tun.Stats fields serveStatus sums. Three controls:
//
//   - v4 to an internet destination -> ErrNotForUs, RxDropNotForUs (never
//     RxDropFamilyOff).
//   - v6 to an internet destination, inner IPv6 ASSIGNED -> ErrNotForUs, and
//     RxDropFamilyOff stays ZERO (the "give the gateway an inner IPv6
//     assignment" part of the fix).
//   - v4 at the gateway's own inner address 10.64.0.1 -> delivered and
//     reflected, rx_packets > 0 (the "drive traffic AT the gateway" part).
func TestDropReasonCountersDistinguishNotForUsFromDelivered(t *testing.T) {
	sizing, _, err := buildServeSizing(serveOptions{pathMTU: 1450, plan: "udp"})
	if err != nil {
		t.Fatal(err)
	}

	// Built through parseAssignment, the real seam runServe uses, so a mutation
	// that drops the -inner-v6 handling is caught by this test and not just by
	// the parse unit test.
	assign, err := parseAssignment("10.64.0.1", "10.64.0.2", "2001:db8::1", "")
	if err != nil {
		t.Fatal(err)
	}

	dev := newReflector(sizing.InnerMTU, assign.V4)
	defer dev.Close()

	sink := &recordingSink{}
	tunnel, err := tun.New(tun.Config{
		Assign: assign,
		Device: dev,
		Sink:   sink,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
		// Carrier floor exactly as the gateway serves it, so the inner MTU is
		// large enough for inner IPv6 (>= 1280).
		CarrierFloorMessageSize: sizing.MessageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.SetState(tun.StateCarrying)

	// The pump goroutine plays the driver's device loop: it is the ONLY path
	// that increments deviceReads, which is the ONLY thing that makes
	// DeviceProven true, which is the ONLY thing that lets Stats report a
	// delivery instead of a bare write. A manual ReadPacket loop would not do
	// it — the count lives in PumpOutbound, not in the device.
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- tunnel.PumpOutbound(ctx) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()

	const gwV4 = "10.64.0.1"
	const clientV4 = "10.64.0.2"
	const clientV6 = "2001:db8::2"
	const gwV6 = "2001:db8::1"

	// --- control 1: v4 traffic THROUGH the gateway (dst is an internet address)

	err = tunnel.Inbound(buildIPv4ICMP(clientV4, "8.8.8.8"))
	if !errors.Is(err, tun.ErrNotForUs) {
		t.Fatalf("v4 through-traffic returned %v, want ErrNotForUs", err)
	}
	st := tunnel.Stats()
	if st.RxDropNotForUs == 0 {
		t.Fatal("v4 through-traffic did not increment RxDropNotForUs")
	}
	if st.RxDropFamilyOff != 0 {
		t.Fatalf("v4 through-traffic incremented RxDropFamilyOff (%d); it is a v4 packet", st.RxDropFamilyOff)
	}
	if st.RxPackets != 0 {
		t.Fatalf("a rejected packet was counted as delivered: rx_packets=%d", st.RxPackets)
	}

	// --- control 2: v6 traffic THROUGH the gateway, with v6 now ASSIGNED.
	// Before -inner-v6 existed this was a familyAllowed failure; now it is
	// correctly a NotForUs failure and familyOff stays zero.

	err = tunnel.Inbound(buildIPv6ICMP(clientV6, "2001:db8::feed"))
	if !errors.Is(err, tun.ErrNotForUs) {
		t.Fatalf("v6 through-traffic returned %v, want ErrNotForUs", err)
	}
	st = tunnel.Stats()
	if st.RxDropFamilyOff != 0 {
		t.Fatalf("inner IPv6 is assigned but v6 through-traffic still increments "+
			"RxDropFamilyOff (%d); -inner-v6 did not take effect", st.RxDropFamilyOff)
	}
	if st.RxDropNotForUs < 2 {
		t.Fatalf("v6 through-traffic was not counted as NotForUs: RxDropNotForUs=%d", st.RxDropNotForUs)
	}

	// --- control 3: v4 traffic AT the gateway's own inner address.

	err = tunnel.Inbound(buildIPv4ICMP(clientV4, gwV4))
	if err != nil {
		t.Fatalf("v4 traffic at the gateway's own inner address was refused: %v", err)
	}
	waitFor(t, 5*time.Second, "the reflection read back so DeviceProven becomes true and rx_packets is reported",
		func() bool { return tunnel.Stats().RxPackets > 0 })
	st = tunnel.Stats()
	if st.RxPackets == 0 {
		t.Fatal("rx_packets is still 0 after a packet addressed to this endpoint's inner address")
	}
	if st.RxDropNotForUs != 2 {
		t.Fatalf("the counted NotForUs total changed when it should not: %d", st.RxDropNotForUs)
	}

	// The sum invariant: RxDroppedInvalid == the per-reason reasons.
	if got := st.RxDropFamilyOff + st.RxDropMartian + st.RxDropNotForUs +
		st.RxDropReflected + st.RxDropMalformed; got != st.RxDroppedInvalid {
		t.Fatalf("per-reason counters sum to %d but RxDroppedInvalid=%d", got, st.RxDroppedInvalid)
	}
}

// --- the v6 reflector question, stated as evidence ---------------------------

// TestReflectorAnswersIPv4Only guards the boundary serveStatus reports on:
// an inner IPv6 packet addressed AT the gateway passes inbound (with v6
// assigned) and is written to the device, but reflect.go answers IPv4-only, so
// it is written and ignored, not raised. This test keeps that behaviour
// deliberate rather than discovered.
func TestReflectorAnswersIPv4Only(t *testing.T) {
	dev := newReflector(1400, netip.MustParseAddr("10.64.0.1"))
	defer dev.Close()

	got, _ := dev.WritePacket(buildIPv6ICMP("2001:db8::2", "2001:db8::1"))
	if got == 0 {
		t.Fatal("the reflector must accept separately from answer")
	}
	if dev.Reflected() != 0 {
		t.Fatalf("an IPv6 packet was reflected (%d), but reflect.go is IPv4-only", dev.Reflected())
	}
	if dev.Ignored() == 0 {
		t.Fatal("an unanswerable IPv6 packet was not counted as ignored")
	}
}

// --- helpers -----------------------------------------------------------------

type recordingSink struct{}

func (s *recordingSink) SendData(pkt []byte) error { return nil }

var _ tun.FrameSink = (*recordingSink)(nil)

// buildIPv4ICMP synthesises a structurally valid IPv4 ICMP echo packet, the
// shape a host actually emits. Checksums are real: the tun layer verifies the
// IPv4 header checksum and rejects a bad one.
func buildIPv4ICMP(src, dst string) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 28)
	b[8] = 64
	b[9] = 1 // ICMP
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	b[20] = 8 // echo request
	putIPv4Checksum(b)
	return b
}

// buildIPv6ICMP synthesises a structurally valid IPv6 ICMPv6 echo packet,
// correct enough that parseIPv6 accepts it and neither family nor martian
// rules fire.
func buildIPv6ICMP(src, dst string) []byte {
	s := netip.MustParseAddr(src).As16()
	d := netip.MustParseAddr(dst).As16()
	b := make([]byte, 48)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], 8) // 40-byte header + 8-byte ICMPv6
	b[6] = 58                             // ICMPv6
	b[7] = 64                             // hop limit
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	b[40] = 128 // echo request
	return b
}

func putIPv4Checksum(b []byte) {
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
}
