package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// The edges. Each of these is a branch that only fires when something upstream
// is already wrong — a lying device, a header that claims more than it has, a
// misconfigured router address. They are exactly the branches that never run in
// a lab and always run in the field, so they are tested rather than left to be
// discovered by a user in Yangon.

// TestHeaderLongerThanTheBuffer. An IHL that claims sixty bytes of header in a
// twenty-byte read is the classic over-read: a parser that trusts it reads
// forty bytes of whatever was next in memory and puts them on the wire as
// addresses.
func TestHeaderLongerThanTheBuffer(t *testing.T) {
	buf := make([]byte, IPv4HeaderMin)
	buf[0] = 0x4f // version 4, IHL 15 => a 60-byte header
	binary.BigEndian.PutUint16(buf[2:4], IPv4HeaderMin)
	buf[8] = 64
	if _, err := parsePacket(buf); !errors.Is(err, ErrBadHeader) {
		t.Fatalf("%v, want ErrBadHeader", err)
	}

	f := newFixture(t).carrying()
	if err := f.tun.Outbound(buf); !errors.Is(err, ErrBadHeader) {
		t.Fatalf("Outbound: %v, want ErrBadHeader", err)
	}
	f.quiet("over-long IHL")
}

// TestInboundRejectsMalformedPackets. The tunnel is authenticated, so a
// malformed inbound packet means the gateway is broken or compromised. Either
// way it does not get written into the host's stack.
func TestInboundRejectsMalformedPackets(t *testing.T) {
	f := newFixture(t).carrying()
	for _, pkt := range [][]byte{
		nil,
		{0x45},
		{0x35, 0, 0, 0},
		arrivingV4(100)[:15],
	} {
		if err := f.tun.Inbound(pkt); err == nil {
			t.Fatalf("Inbound accepted %d malformed bytes", len(pkt))
		}
	}
	if f.dev.writeCount() != 0 {
		t.Fatal("a malformed inbound packet reached the host device")
	}
	if st := f.tun.Stats(); st.RxDroppedInvalid != 4 {
		t.Fatalf("RxDroppedInvalid=%d, want 4", st.RxDroppedInvalid)
	}
}

// TestMartianReasonRejectsTheZeroAddress. netip's zero value is not an address
// at all, and every predicate on it is false — so a validator that asks "is it
// loopback? is it multicast?" and stops there would let it through.
func TestMartianReasonRejectsTheZeroAddress(t *testing.T) {
	if martianReason(netip.Addr{}) == "" {
		t.Fatal("the zero Addr was accepted as usable")
	}
}

// TestChecksumHandlesOddLengths. The one's complement sum pads a trailing odd
// byte into the high half of the final word. Getting that wrong produces
// checksums that are right for even-length messages and wrong for odd ones,
// which is a bug that hides for a long time.
func TestChecksumHandlesOddLengths(t *testing.T) {
	even := []byte{0x12, 0x34, 0x56, 0x78}
	odd := []byte{0x12, 0x34, 0x56, 0x78, 0x9a}
	if checksum(even) == checksum(odd) {
		t.Fatal("a trailing odd byte did not change the checksum")
	}
	// The padding is into the HIGH half, so appending a zero byte must be a
	// no-op and appending it as a low byte must not be.
	if checksum(append(append([]byte(nil), even...), 0x00)) != checksum(even) {
		t.Fatal("a trailing zero byte changed the checksum; the odd byte is being padded into the wrong half")
	}

	var src, dst [16]byte
	src[0], dst[0] = 0xfd, 0xfd
	msgEven := []byte{0x02, 0x00, 0x00, 0x00, 0, 0, 0x05, 0x00}
	msgOdd := append(append([]byte(nil), msgEven...), 0x7f)
	if icmpv6Checksum(src, dst, msgEven) == icmpv6Checksum(src, dst, msgOdd) {
		t.Fatal("the ICMPv6 checksum ignores a trailing odd byte")
	}
}

// TestNoIPv6RouterMeansNoIPv6Signal is the v6 half of
// TestNoRouterAddressMeansNoSignal. The two families have separate router
// addresses and a tunnel can easily be configured with one and not the other.
func TestNoIPv6RouterMeansNoIPv6Signal(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		a := fixtureAssign()
		a.RouterV6 = netip.Addr{}
		c.Assign = a
	}).carrying()

	if err := f.tun.Outbound(goodV6(4000)); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	if f.dev.writeCount() != 0 {
		t.Fatal("an IPv6 signal was synthesised with no IPv6 router address")
	}

	// The IPv4 side is unaffected, which is the point of keeping them separate.
	if err := f.tun.Outbound(goodV4(4000)); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	if f.dev.writeCount() != 1 {
		t.Fatalf("device saw %d writes, want the IPv4 signal", f.dev.writeCount())
	}
}

// TestRouterAddressValidation covers the router checks New makes on top of the
// assignment's own. A router address that the inbound rules would reject means
// every synthesised signal is silently discarded by deliver — the tunnel would
// count signals it never actually delivered.
func TestRouterAddressValidation(t *testing.T) {
	cases := []struct {
		name string
		a    Assignment
	}{
		{"multicast v4 router", Assignment{V4: v4a(10, 64, 0, 2), RouterV4: v4a(224, 0, 0, 1)}},
		{"multicast v6 router", Assignment{V6: ulaV6(2), RouterV6: docV6M()}},
		{"v6 router equals the assignment", Assignment{V6: ulaV6(2), RouterV6: ulaV6(2)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{
				Assign:                  tc.a,
				Device:                  &fakeDevice{mtu: fixtureInnerMTU},
				Sink:                    &fakeSink{},
				Clock:                   newFakeClock(),
				CarrierFloorMessageSize: fixtureCarrierFloor,
			})
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("New accepted an unusable router address: %v", err)
			}
		})
	}
}

// TestSignalDeliveryFailureIsCountedAsSuppressed. If the device write fails,
// the host was not told. Counting it as a delivered signal would make a host
// problem read as a healthy tunnel doing its job.
func TestSignalDeliveryFailureIsCountedAsSuppressed(t *testing.T) {
	f := newFixture(t).carrying()
	f.dev.mu.Lock()
	f.dev.writeErr = errors.New("device gone")
	f.dev.mu.Unlock()

	if err := f.tun.Outbound(goodV4(4000)); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	st := f.tun.Stats()
	if st.PMTUSignals != 0 || st.PMTUSuppressed != 1 {
		t.Fatalf("signals=%d suppressed=%d, want 0 and 1", st.PMTUSignals, st.PMTUSuppressed)
	}
}

// TestPumpRefusesADeviceThatOverreports. A device implementation that returns
// more than it copied is a bug — or, on a platform where the device is a shared
// file descriptor, a way to make the tunnel read past its own buffer and send
// whatever is next in memory.
//
// Two defences, and the test exercises both. A report past the end of the
// buffer is refused outright, because slicing on it would panic or over-read.
// A report merely past the end of the PACKET is absorbed by the declared-length
// truncation, which is the same mechanism that stops the reused buffer from
// leaking one flow's tail into another's packet.
func TestPumpRefusesADeviceThatOverreports(t *testing.T) {
	f := newFixture(t).carrying()
	f.dev.mu.Lock()
	f.dev.overreport = MaxIPPacket
	f.dev.mu.Unlock()
	f.dev.queue(goodV4(64))

	_ = f.tun.PumpOutbound(context.Background())
	if f.sink.count() != 0 {
		t.Fatal("the pump trusted a device that reported past the end of its own buffer")
	}
	if st := f.tun.Stats(); st.DeviceReads != 1 || st.TxDroppedInvalid != 1 {
		t.Fatalf("counters: %+v", st)
	}

	g := newFixture(t).carrying()
	g.dev.mu.Lock()
	g.dev.overreport = 40
	g.dev.mu.Unlock()
	g.dev.queue(goodV4(64))

	_ = g.tun.PumpOutbound(context.Background())
	if g.sink.count() != 1 {
		t.Fatalf("session saw %d packets, want 1", g.sink.count())
	}
	if n := len(g.sink.last()); n != 64+IPv4HeaderMin {
		t.Fatalf("session received %d bytes; the header declared %d, so %d over-reported bytes travelled",
			n, 64+IPv4HeaderMin, n-64-IPv4HeaderMin)
	}
	if st := g.tun.Stats(); st.TxTruncatedTail != 1 {
		t.Fatalf("TxTruncatedTail=%d, want 1", st.TxTruncatedTail)
	}
}

// TestWrappedErrorsCarryTheirSentinel. Every caller of this package classifies
// failures with errors.Is; a wrapper that loses its sentinel turns "the source
// was not ours" into "some error happened", and the host's fail-closed logic
// keys on the difference.
func TestWrappedErrorsCarryTheirSentinel(t *testing.T) {
	err := errWrap(ErrConfig, "detail %d", 7)
	if !errors.Is(err, ErrConfig) {
		t.Fatal("the wrapper lost its sentinel")
	}
	if got := err.Error(); got != ErrConfig.Error()+": detail 7" {
		t.Fatalf("Error() = %q", got)
	}
	if errors.Unwrap(err) != ErrConfig {
		t.Fatal("Unwrap did not return the sentinel")
	}
}
