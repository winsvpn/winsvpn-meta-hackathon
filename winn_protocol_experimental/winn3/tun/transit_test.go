package tun

import (
	"errors"
	"testing"
)

// A tunnel endpoint accepts only packets addressed to itself. A LAB RESPONDER
// terminating a client's full-tunnel traffic must accept packets addressed to
// the internet, because that is all such a client ever sends.
//
// This pair exists because the distinction cost a working measurement. On
// 2026-08-11 the first standalone winn/3 carriage on a physical iPhone reached
// gate state carrying with 54 authenticated datagrams, and then reported
// rx_offered 50 / rx_packets 0 / rx_dropped_invalid 50. Every inner packet was
// rejected, so the promotion predicate (carrying AND RxPackets > 0) could never
// converge and the provider correctly failed closed. The cause was not the
// crypto, the carrier, or the control plane: the client's AllowedIPs is
// mandatorily 0.0.0.0/0, so it addressed every packet to an internet
// destination, and the responder rejected all of them with ErrNotForUs.
//
// The first test pins the security property. The second pins the escape hatch.
// Deleting either one is how this regresses.

// TestAForeignDestinationIsRefusedByDefault is the property that must never
// weaken: without AcceptTransit, a packet addressed to somebody else is refused
// and counted as such. Relaxing this by default would let a peer inject packets
// addressed to third parties into the host.
func TestAForeignDestinationIsRefusedByDefault(t *testing.T) {
	f := newFixture(t).carrying()

	// Addressed to a public address, not to this tunnel's assigned address.
	pkt := v4cfg{src: peerV4(), dst: v4a(1, 1, 1, 1), payload: 64}.build()

	err := f.tun.Inbound(pkt)
	if err == nil {
		t.Fatal("a packet addressed elsewhere was accepted; the destination check is gone")
	}
	if !errors.Is(err, ErrNotForUs) {
		t.Fatalf("want ErrNotForUs, got %v", err)
	}

	s := f.tun.Stats()
	if s.RxPackets != 0 {
		t.Fatalf("RxPackets = %d, want 0: nothing should have been delivered", s.RxPackets)
	}
	if s.RxDroppedInvalid != 1 {
		t.Fatalf("RxDroppedInvalid = %d, want 1", s.RxDroppedInvalid)
	}
	// The per-reason counter is the whole point: a bare RxDroppedInvalid tells
	// an operator that something was rejected, not which of five checks fired.
	if s.RxDropNotForUs != 1 {
		t.Fatalf("RxDropNotForUs = %d, want 1 — the reason must be attributable", s.RxDropNotForUs)
	}
	if s.RxDropFamilyOff != 0 || s.RxDropMartian != 0 || s.RxDropReflected != 0 {
		t.Fatalf("a foreign destination was miscategorised: familyOff=%d martian=%d reflected=%d",
			s.RxDropFamilyOff, s.RxDropMartian, s.RxDropReflected)
	}
}

// TestAcceptTransitDeliversAForeignDestination is the fix. The same packet that
// the test above refuses must now be delivered, so RxPackets can leave zero and
// the promotion predicate can converge.
func TestAcceptTransitDeliversAForeignDestination(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()

	pkt := v4cfg{src: peerV4(), dst: v4a(1, 1, 1, 1), payload: 64}.build()

	if err := f.tun.Inbound(pkt); err != nil {
		t.Fatalf("AcceptTransit did not accept a foreign destination: %v", err)
	}

	s := f.tun.Stats()
	if s.RxDroppedInvalid != 0 {
		t.Fatalf("RxDroppedInvalid = %d, want 0", s.RxDroppedInvalid)
	}
	if s.RxDropNotForUs != 0 {
		t.Fatalf("RxDropNotForUs = %d, want 0", s.RxDropNotForUs)
	}
	if s.RxDeviceWrites != 1 {
		t.Fatalf("RxDeviceWrites = %d, want 1: the packet should have reached the device", s.RxDeviceWrites)
	}
}

// TestAcceptTransitStillRefusesMartiansAndReflections proves AcceptTransit is a
// narrow relaxation and not a bypass. It relaxes exactly one test, "is this
// addressed to me". Every other guard still stands, and each is attributed to
// its own counter.
func TestAcceptTransitStillRefusesMartiansAndReflections(t *testing.T) {
	t.Run("reflected source is still refused", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()
		// Our own address as the source, arriving from the tunnel.
		pkt := v4cfg{src: fixtureAssign().V4, dst: v4a(1, 1, 1, 1), payload: 64}.build()
		err := f.tun.Inbound(pkt)
		if !errors.Is(err, ErrReflected) {
			t.Fatalf("want ErrReflected, got %v", err)
		}
		if got := f.tun.Stats().RxDropReflected; got != 1 {
			t.Fatalf("RxDropReflected = %d, want 1", got)
		}
	})

	t.Run("martian source is still refused", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()
		// Loopback must never cross a tunnel.
		pkt := v4cfg{src: v4a(127, 0, 0, 1), dst: v4a(1, 1, 1, 1), payload: 64}.build()
		err := f.tun.Inbound(pkt)
		if !errors.Is(err, ErrMartian) {
			t.Fatalf("want ErrMartian, got %v", err)
		}
		if got := f.tun.Stats().RxDropMartian; got != 1 {
			t.Fatalf("RxDropMartian = %d, want 1", got)
		}
	})

	// PQ OI-5 (gateway client isolation): the gateway's own destination rule
	// (cmd/winn3-gateway forward_isolation.go) does not repeat the link-local
	// block, because this rule refuses it first, with AcceptTransit set, before
	// the gateway's device ever sees the packet. The cloud metadata address is
	// the one that matters.
	t.Run("martian destination is still refused", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()
		pkt := v4cfg{src: peerV4(), dst: v4a(169, 254, 169, 254), payload: 64}.build()
		err := f.tun.Inbound(pkt)
		if !errors.Is(err, ErrMartian) {
			t.Fatalf("want ErrMartian, got %v", err)
		}
		if got := f.tun.Stats().RxDropMartian; got != 1 {
			t.Fatalf("RxDropMartian = %d, want 1", got)
		}
		if f.dev.writeCount() != 0 {
			t.Fatal("a link-local destination reached the host device under AcceptTransit")
		}
	})
}

// TestTransitOffPathSenderCannotMoveTransportCounters pins the transport-counters
// property of the full-tunnel responder posture.
//
// The transport counters are TxPackets and TxBytes — the only counters in this
// package that move because bytes were handed to the session (sink.SendData),
// i.e. pushed toward the carrier. An OFF-PATH sender is an inner source that is
// not this endpoint's own address. Under AcceptTransit the responder happily
// ADMITS foreign-destination traffic inbound and writes it to the host device
// because that is the whole job of a full-tunnel reflector. The security line is
// the return path: that same foreign-sourced inner packet, which the host now
// HOLDS, must never turn into transport-bound traffic. If the reflector tried to
// re-insert it outbound with its original source, the source check has to refuse
// it and the transport counters have to stay exactly where they were.
func TestTransitOffPathSenderCannotMoveTransportCounters(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()

	// A full-tunnel transit packet addressed to the internet, the exact traffic
	// the responder exists to admit. Its source (peerV4) is off-path: it is
	// neither this endpoint's inner address nor anything the tunnel owns.
	transit := v4cfg{src: peerV4(), dst: v4a(1, 1, 1, 1), payload: 64}.build()

	// The inbound leg admits it — the responder's job. It must reach the device.
	if err := f.tun.Inbound(transit); err != nil {
		t.Fatalf("the responder refused a full-tunnel transit packet: %v", err)
	}
	if got := f.tun.Stats().RxDeviceWrites; got != 1 {
		t.Fatalf("RxDeviceWrites = %d, want 1: the transit packet should reach the device", got)
	}
	if got := f.sink.count(); got != 0 {
		t.Fatalf("%d packet(s) reached the session from Inbound; the transport must never see an arrival", got)
	}

	// Now the host is holding that packet. It tries to send it back out the
	// tunnel with its ORIGINAL off-path source — a reflector echoing transit
	// traffic, or a spoofed host. Outbound must refuse it AND the transport
	// counters must not have moved.
	err := f.tun.Outbound(transit)
	if !errors.Is(err, ErrSourceNotOurs) {
		t.Fatalf("off-path outbound after transit admission: %v, want ErrSourceNotOurs", err)
	}
	st := f.tun.Stats()
	if st.TxPackets != 0 || st.TxBytes != 0 {
		t.Fatalf("transport counters moved for an off-path sender: TxPackets=%d TxBytes=%d, want 0/0",
			st.TxPackets, st.TxBytes)
	}
	if n := f.sink.count(); n != 0 {
		t.Fatalf("%d packet(s) reached the transport from an off-path sender; expected none", n)
	}
	if st.TxDroppedInvalid != 1 {
		t.Fatalf("TxDroppedInvalid = %d, want 1: the off-path sender was not even counted as a refusal", st.TxDroppedInvalid)
	}

	// Positive control: a packet from THIS endpoint's own address still crosses
	// the SAME gate and DOES move the transport counters. Without this, "nothing
	// moved" could be true because the tunnel is broken rather than because an
	// off-path source is refused.
	if err := f.tun.Outbound(goodV4(64)); err != nil {
		t.Fatalf("a valid own-source packet after the off-path refusal was dropped: %v", err)
	}
	st = f.tun.Stats()
	if st.TxPackets != 1 || st.TxBytes != uint64(len(goodV4(64))) {
		t.Fatalf("transport counters after a valid own-source packet: TxPackets=%d TxBytes=%d, want 1/%d",
			st.TxPackets, st.TxBytes, len(goodV4(64)))
	}
	if n := f.sink.count(); n != 1 {
		t.Fatalf("%d packet(s) reached the transport, want exactly the one own-source packet", n)
	}
}

// TestTransitClassificationIsByteGated pins that "transit" is decided by a
// byte-for-byte comparison of the parsed destination address against the
// assigned address — p.dst == ours — and by nothing else.
//
// The resident danger is a classifier that thinks in subnets or prefixes rather
// than exact addresses. This tunnel's assigned inner address is 10.64.0.2; its
// on-link router is 10.64.0.1, in the SAME /24. If classification were subnet-
// based, a packet to 10.64.0.1 would be read as addressed-to-us and admitted
// WITHOUT AcceptTransit — silently forwarding traffic for a neighbour while
// claiming it was local. Byte-gating refuses it: a destination that differs by
// one byte is foreign, needs the escape, and without it is counted ErrNotForUs.
func TestTransitClassificationIsByteGated(t *testing.T) {
	// foreign is a normal public destination a full-tunnel client would send.
	foreignDst := v4a(1, 1, 1, 1)
	// subnetNeighbour shares every byte of our /24 except the last: 10.64.0.1 vs
	// the assigned 10.64.0.2. It is NOT ours, but a prefix classifier would say
	// it is.
	subnetNeighbour := v4a(10, 64, 0, 1)
	ours := fixtureAssign().V4

	t.Run("a one-byte-off subnet neighbour is not ours without the escape", func(t *testing.T) {
		f := newFixture(t).carrying()
		pkt := v4cfg{src: peerV4(), dst: subnetNeighbour, payload: 64}.build()
		err := f.tun.Inbound(pkt)
		if !errors.Is(err, ErrNotForUs) {
			t.Fatalf("a packet to 10.64.0.1 (one byte off ours) was %v; a byte-gated classifier must not read it as ours", err)
		}
		s := f.tun.Stats()
		if s.RxDropNotForUs != 1 {
			t.Fatalf("RxDropNotForUs = %d, want 1", s.RxDropNotForUs)
		}
		if s.RxDeviceWrites != 0 {
			t.Fatalf("RxDeviceWrites = %d, want 0: a subnet neighbour must not be delivered as local", s.RxDeviceWrites)
		}
	})

	t.Run("the same one-byte-off neighbour is transit once the escape is on", func(t *testing.T) {
		g := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()
		pkt := v4cfg{src: peerV4(), dst: subnetNeighbour, payload: 64}.build()
		if err := g.tun.Inbound(pkt); err != nil {
			t.Fatalf("AcceptTransit did not admit a subnet neighbour as transit: %v", err)
		}
		if got := g.tun.Stats().RxDeviceWrites; got != 1 {
			t.Fatalf("RxDeviceWrites = %d, want 1", got)
		}
	})

	t.Run("foreign destination bytes demand the escape", func(t *testing.T) {
		f := newFixture(t).carrying()
		pkt := v4cfg{src: peerV4(), dst: foreignDst, payload: 64}.build()
		if err := f.tun.Inbound(pkt); !errors.Is(err, ErrNotForUs) {
			t.Fatalf("a public destination without AcceptTransit was %v, want ErrNotForUs", err)
		}

		g := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()
		if err := g.tun.Inbound(pkt); err != nil {
			t.Fatalf("the same public destination with AcceptTransit was refused: %v", err)
		}
		if got := g.tun.Stats().RxDeviceWrites; got != 1 {
			t.Fatalf("RxDeviceWrites = %d, want 1", got)
		}
	})

	t.Run("our own address bytes are terminal and never need the escape", func(t *testing.T) {
		f := newFixture(t).carrying()
		pkt := v4cfg{src: peerV4(), dst: ours, payload: 64}.build()
		if err := f.tun.Inbound(pkt); err != nil {
			t.Fatalf("a packet to our own address was refused even without the escape: %v", err)
		}
		s := f.tun.Stats()
		if s.RxDropNotForUs != 0 {
			t.Fatalf("RxDropNotForUs = %d, want 0: our own destination is never transit", s.RxDropNotForUs)
		}
		if s.RxDeviceWrites != 1 {
			t.Fatalf("RxDeviceWrites = %d, want 1", s.RxDeviceWrites)
		}
	})
}
