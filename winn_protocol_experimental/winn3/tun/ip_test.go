package tun

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// TestOutboundEnforcesExactlyOneSource sweeps the whole last octet of the
// source address and requires that precisely one value crosses.
//
// The failure it catches is the tempting one: validating against the inner
// PREFIX instead of the inner ADDRESS. A /24 check passes all 256 of these,
// and every one of the other 255 is a packet this endpoint forwarded on behalf
// of somebody it is not — which is how a shared inner subnet turns one
// compromised client into a source of traffic attributed to another.
func TestOutboundEnforcesExactlyOneSource(t *testing.T) {
	accepted := 0
	for i := 0; i < 256; i++ {
		f := newFixture(t).carrying()
		pkt := v4cfg{src: v4a(10, 64, 0, byte(i)), dst: peerV4(), payload: 64}.build()
		err := f.tun.Outbound(pkt)
		if err == nil {
			accepted++
			if byte(i) != 2 {
				t.Errorf("source ending .%d was accepted; only the assigned address may be", i)
			}
			continue
		}
		if byte(i) == 2 {
			t.Fatalf("the assigned source was rejected: %v", err)
		}
		if !errors.Is(err, ErrSourceNotOurs) && !errors.Is(err, ErrMartian) {
			t.Errorf("source ending .%d: %v, want ErrSourceNotOurs or ErrMartian", i, err)
		}
		f.quiet("foreign source")
	}
	if accepted != 1 {
		t.Fatalf("%d of 256 source addresses crossed; exactly one may", accepted)
	}
}

// TestForeignSourceIsDroppedWhileCarrying pins the drop itself, not just the
// sweep that counts it.
//
// The sweep above proves that exactly one source crosses; this test asserts
// what a foreign source does to a tunnel that is otherwise carrying: it is
// refused with ErrSourceNotOurs, it is counted in TxDroppedInvalid, and no byte
// of it reaches the session — while a valid packet through the SAME gate still
// crosses afterward. The second half is the positive control: without it, "the
// foreign packet was dropped" could be true because the tunnel is broken, and
// the drop proves nothing about the source check.
func TestForeignSourceIsDroppedWhileCarrying(t *testing.T) {
	f := newFixture(t).carrying()

	foreign := v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()
	if err := f.tun.Outbound(foreign); !errors.Is(err, ErrSourceNotOurs) {
		t.Fatalf("foreign source while carrying: %v, want ErrSourceNotOurs", err)
	}
	if n := f.sink.count(); n != 0 {
		t.Fatalf("%d packet(s) reached the session carrying a foreign source; expected none", n)
	}
	if st := f.tun.Stats(); st.TxDroppedInvalid != 1 || st.TxPackets != 0 {
		t.Fatalf("counters after a foreign-source drop: %+v, want TxDroppedInvalid=1 TxPackets=0", st)
	}

	if err := f.tun.Outbound(goodV4(64)); err != nil {
		t.Fatalf("a valid packet after the drop was refused: %v", err)
	}
	if n := f.sink.count(); n != 1 {
		t.Fatalf("session saw %d packets, want exactly the one valid one", n)
	}
}

// TestForeignSourceIsDroppedOnTheCarryPath pins the source-address drop where
// it actually has to happen: on the packet the host device hands the pump.
//
// The tests above call Outbound directly, which is the right unit-level proof
// that a foreign source is refused. This one drives the REAL PumpOutbound path
// a host would — a device emitting a foreign-source packet into a carrying
// tunnel. It must be dropped before it reaches the session, counted in
// TxDroppedInvalid, and no byte attributed to it. A valid packet through the
// SAME device and pump must still cross afterwards: that is what makes the drop
// attributable to the source check and not to a tunnel that carries nothing.
func TestForeignSourceIsDroppedOnTheCarryPath(t *testing.T) {
	f := newFixture(t).carrying()

	foreign := v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()
	valid := goodV4(64)

	f.dev.queue(foreign, valid)
	if err := f.tun.PumpOutbound(context.Background()); !errors.Is(err, errNoMoreReads) {
		t.Fatalf("PumpOutbound: %v (want the end-of-queue sentinel after the queued packets)", err)
	}

	st := f.tun.Stats()
	if st.TxDroppedInvalid != 1 {
		t.Fatalf("TxDroppedInvalid=%d, want 1: the foreign source was not counted as a dropped packet", st.TxDroppedInvalid)
	}
	if st.TxPackets != 1 {
		t.Fatalf("TxPackets=%d, want 1", st.TxPackets)
	}
	if n := f.sink.count(); n != 1 {
		t.Fatalf("%d packet(s) reached the session, want exactly the one valid one", n)
	}
	got := f.sink.last()
	p, err := parsePacket(got)
	if err != nil {
		t.Fatalf("the carried packet does not parse: %v", err)
	}
	if p.src != fixtureAssign().V4 {
		t.Fatalf("a packet bearing a foreign source reached the session on the carry path")
	}
}

// TestInboundNeverForwards is the same sweep on the other side, and it is the
// property that makes this endpoint structurally incapable of routing.
//
// A gateway that sends a packet destined elsewhere is asking this host to
// forward it. A host with IP forwarding on would do exactly that, out its real
// interface, sourced from a third party — the leak in its purest form, and one
// equality test away from happening.
func TestInboundNeverForwards(t *testing.T) {
	accepted := 0
	for i := 0; i < 256; i++ {
		f := newFixture(t).carrying()
		pkt := v4cfg{src: peerV4(), dst: v4a(10, 64, 0, byte(i)), payload: 64}.build()
		err := f.tun.Inbound(pkt)
		if err == nil {
			accepted++
			if byte(i) != 2 {
				t.Errorf("destination ending .%d was written to the host; only the assigned address may be", i)
			}
			continue
		}
		if byte(i) == 2 {
			t.Fatalf("the assigned destination was rejected: %v", err)
		}
		if !errors.Is(err, ErrNotForUs) && !errors.Is(err, ErrMartian) {
			t.Errorf("destination ending .%d: %v, want ErrNotForUs or ErrMartian", i, err)
		}
		if f.dev.writeCount() != 0 {
			t.Fatalf("destination ending .%d reached the host device", i)
		}
	}
	if accepted != 1 {
		t.Fatalf("%d of 256 destinations were delivered; exactly one may", accepted)
	}
}

// TestInboundRefusesOurOwnSource catches a packet arriving from the tunnel that
// claims to have come from this host. Either it is a loop, or it is something
// trying to make the local stack treat remote traffic as locally originated —
// which, for anything that trusts its own address, is an authentication bypass.
func TestInboundRefusesOurOwnSource(t *testing.T) {
	f := newFixture(t).carrying()
	a := fixtureAssign()
	pkt := v4cfg{src: a.V4, dst: a.V4, payload: 32}.build()
	if err := f.tun.Inbound(pkt); !errors.Is(err, ErrReflected) {
		t.Fatalf("%v, want ErrReflected", err)
	}
	if f.dev.writeCount() != 0 {
		t.Fatal("a reflected packet reached the host device")
	}
}

// TestOutboundRefusesOurOwnDestination: a packet addressed to our own inner
// address belongs on the host's loopback path. Putting it on the wire makes the
// gateway send it straight back, which is a reflector built out of the tunnel.
func TestOutboundRefusesOurOwnDestination(t *testing.T) {
	f := newFixture(t).carrying()
	a := fixtureAssign()
	pkt := v4cfg{src: a.V4, dst: a.V4, payload: 32}.build()
	if err := f.tun.Outbound(pkt); !errors.Is(err, ErrMartian) {
		t.Fatalf("%v, want ErrMartian", err)
	}
	f.quiet("self-addressed packet")
}

func TestStructuralRejections(t *testing.T) {
	a := fixtureAssign()
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, ErrShortPacket},
		{"version 5", []byte{0x50, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, ErrBadVersion},
		{"version 0", make([]byte, 40), ErrBadVersion},
		{"ipv4 header truncated", goodV4(64)[:19], ErrShortPacket},
		{"ipv6 header truncated", goodV6(64)[:39], ErrShortPacket},
		{"ihl below five", v4cfg{src: a.V4, dst: peerV4(), payload: 8, ihlWords: 4}.build(), ErrBadHeader},
		{"total length below header", v4cfg{src: a.V4, dst: peerV4(), payload: 8, useTotal: true, total: 12}.build(), ErrBadHeader},
		{"total length past the buffer", v4cfg{src: a.V4, dst: peerV4(), payload: 8, useTotal: true, total: 900}.build()[:28], ErrBadHeader},
		{"bad ipv4 checksum", v4cfg{src: a.V4, dst: peerV4(), payload: 8, badChecksum: true}.build(), ErrBadChecksum},
		{"reserved flag set", v4cfg{src: a.V4, dst: peerV4(), payload: 8, reserved: true}.build(), ErrBadHeader},
		{"ttl zero", v4cfg{src: a.V4, dst: peerV4(), payload: 8, zeroTTL: true}.build(), ErrBadHeader},
		{"hop limit zero", v6cfg{src: a.V6, dst: peerV6(), payload: 8, zeroHop: true}.build(), ErrBadHeader},
		{"ipv6 payload length zero", v6cfg{src: a.V6, dst: peerV6(), payload: 8, useLen: true, plen: 0}.build(), ErrBadHeader},
		{"ipv6 payload length past the buffer", v6cfg{src: a.V6, dst: peerV6(), payload: 8, useLen: true, plen: 900}.build()[:48], ErrBadHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t).carrying()
			if err := f.tun.Outbound(tc.pkt); !errors.Is(err, tc.want) {
				t.Fatalf("Outbound: %v, want %v", err, tc.want)
			}
			f.quiet(tc.name)
		})
	}
}

// TestMartianAddresses covers the addresses that must never cross in either
// direction whatever else is true of the packet.
//
// The multicast rows are the ones worth reading twice. They exclude mDNS,
// LLMNR and NetBIOS name advertisement, and those packets carry the device's
// hostname in cleartext inside the tunnel. A VPN that forwards them has told
// the gateway what the user calls their laptop.
func TestMartianAddresses(t *testing.T) {
	a := fixtureAssign()
	cases := []struct {
		name     string
		src, dst netip.Addr
		v6       bool
	}{
		{"multicast destination", a.V4, v4a(224, 0, 0, 251), false},
		{"broadcast destination", a.V4, v4a(255, 255, 255, 255), false},
		{"loopback destination", a.V4, v4a(127, 0, 0, 1), false},
		{"link-local destination", a.V4, v4a(169, 254, 1, 1), false},
		{"unspecified destination", a.V4, v4a(0, 0, 0, 0), false},
		{"reserved high destination", a.V4, v4a(250, 1, 2, 3), false},
		{"leading-zero source", v4a(0, 1, 2, 3), peerV4(), false},
		{"ipv6 multicast destination", a.V6, docV6M(), true},
		{"ipv6 link-local source", linkLocalV6(), peerV6(), true},
		{"ipv6 loopback destination", a.V6, loopbackV6(), true},
		{"ipv4-mapped ipv6 destination", a.V6, mappedV6(198, 51, 100, 9), true},
		{"ipv4-compatible ipv6 destination", a.V6, compatV6(9), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t).carrying()
			var pkt []byte
			if tc.v6 {
				pkt = v6cfg{src: tc.src, dst: tc.dst, payload: 32}.build()
			} else {
				pkt = v4cfg{src: tc.src, dst: tc.dst, payload: 32}.build()
			}
			if err := f.tun.Outbound(pkt); err == nil {
				t.Fatal("Outbound accepted a martian address")
			}
			f.quiet(tc.name + " outbound")

			g := newFixture(t).carrying()
			if err := g.tun.Inbound(pkt); err == nil {
				t.Fatal("Inbound accepted a martian address")
			}
			if g.dev.writeCount() != 0 {
				t.Fatal("a martian packet reached the host device")
			}
		})
	}
}

// TestIPv6SinkClassification is the IPv6 half of the transit fail-closed rule,
// pinned on the promoted-posture sink address.
//
// A promoted posture that communicates no inner IPv6 installs an IPv6 sink
// address (`fd00:d951:1::2`, drawn in by the `::/1` + `8000::/1` halves) so the
// host's IPv6 goes INTO the tunnel, where this package must refuse it rather
// than let it re-egress the physical NIC. The sink address shares this tunnel's
// `fd00::/8` prefix with the assigned inner address (`fd00::2`) but is NOT that
// address. A classifier that tests the prefix instead of the bytes reads a sink
// destination as "ours" and admits it without AcceptTransit — forwarding a
// neighbour's v6 while claiming it was local, the IPv6 twin of the 10.64.0.1
// byte-gate already pinned for IPv4 in transit_test.go. The rules must fail
// closed the same way, and this is what they cover; until this test the IPv6
// AcceptTransit path had no coverage at all.
func TestIPv6SinkClassification(t *testing.T) {
	ours := fixtureAssign().V6
	sink := sinkV6()
	if ours == sink {
		t.Fatal("fixture: the sink address must differ from the assigned inner address; this is not a guard")
	}
	oursB, sinkB := ours.As16(), sink.As16()
	if oursB[0] != sinkB[0] || oursB[1] != sinkB[1] || oursB[0] != 0xfd {
		t.Fatal("fixture: sink and assigned address must share the fd00:: ULA prefix or this is not a prefix-classifier guard")
	}

	t.Run("sink destination is foreign without the escape", func(t *testing.T) {
		f := newFixture(t).carrying()
		pkt := v6cfg{src: peerV6(), dst: sink, payload: 64}.build()
		err := f.tun.Inbound(pkt)
		if !errors.Is(err, ErrNotForUs) {
			t.Fatalf("a packet to the sink address (fd00::, not ours) was %v; a byte-gated classifier must not read it as ours", err)
		}
		s := f.tun.Stats()
		if s.RxDropNotForUs != 1 {
			t.Fatalf("RxDropNotForUs = %d, want 1", s.RxDropNotForUs)
		}
		if s.RxDropFamilyOff != 0 || s.RxDropMartian != 0 {
			t.Fatalf("the sink destination was miscategorised: familyOff=%d martian=%d, want 0/0", s.RxDropFamilyOff, s.RxDropMartian)
		}
		if s.RxDeviceWrites != 0 {
			t.Fatalf("RxDeviceWrites = %d, want 0: the sink destination must not be delivered as local", s.RxDeviceWrites)
		}
	})

	t.Run("the same sink destination is transit once the escape is on", func(t *testing.T) {
		g := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()
		pkt := v6cfg{src: peerV6(), dst: sink, payload: 64}.build()
		if err := g.tun.Inbound(pkt); err != nil {
			t.Fatalf("AcceptTransit did not admit the sink destination as transit: %v", err)
		}
		s := g.tun.Stats()
		if s.RxDeviceWrites != 1 {
			t.Fatalf("RxDeviceWrites = %d, want 1", s.RxDeviceWrites)
		}
		if s.RxDropNotForUs != 0 {
			t.Fatalf("RxDropNotForUs = %d, want 0 under AcceptTransit", s.RxDropNotForUs)
		}
	})

	t.Run("a global v6 foreign destination is refused by default", func(t *testing.T) {
		f := newFixture(t).carrying()
		global := docV6(0x4d) // 2001:db8::4d, a documentation-range global, not ours
		pkt := v6cfg{src: peerV6(), dst: global, payload: 64}.build()
		err := f.tun.Inbound(pkt)
		if !errors.Is(err, ErrNotForUs) {
			t.Fatalf("a packet to a global v6 destination was %v, want ErrNotForUs", err)
		}
		s := f.tun.Stats()
		if s.RxDropNotForUs != 1 || s.RxDeviceWrites != 0 {
			t.Fatalf("global v6 default: RxDropNotForUs=%d RxDeviceWrites=%d, want 1/0", s.RxDropNotForUs, s.RxDeviceWrites)
		}
	})

	t.Run("the same global v6 destination is admitted under transit", func(t *testing.T) {
		g := newFixture(t, func(c *Config) { c.AcceptTransit = true }).carrying()
		global := docV6(0x4d)
		pkt := v6cfg{src: peerV6(), dst: global, payload: 64}.build()
		if err := g.tun.Inbound(pkt); err != nil {
			t.Fatalf("AcceptTransit did not admit a global v6 destination: %v", err)
		}
		if got := g.tun.Stats().RxDeviceWrites; got != 1 {
			t.Fatalf("RxDeviceWrites = %d, want 1", got)
		}
	})

	t.Run("outbound v6 sink into a v4-only tunnel fails closed", func(t *testing.T) {
		// A promoted tunnel that communicates no inner IPv6 is exactly where
		// the sink is installed: the host draws v6 into the tunnel and this
		// layer is the last thing that can refuse it. The refusal is
		// ErrFamilyOff — a blackout this side can observe, not a silent forward
		// back to the NIC, which is the "leak closed" claim in the Windows sink
		// handoffs.
		v4only := func(c *Config) {
			c.Assign = Assignment{V4: fixtureAssign().V4, RouterV4: fixtureAssign().RouterV4}
		}
		f := newFixture(t, v4only).carrying()
		pkt := v6cfg{src: docV6(0x4d), dst: docV6(0x4e), payload: 64}.build()
		if err := f.tun.Outbound(pkt); !errors.Is(err, ErrFamilyOff) {
			t.Fatalf("outbound v6 on a v4-only tunnel: %v, want ErrFamilyOff", err)
		}
		f.quiet("v6 sink on a v4-only tunnel")
	})
}

func docV6M() netip.Addr {
	var x [16]byte
	x[0], x[1] = 0xff, 0x02
	x[15] = 0xfb
	return netip.AddrFrom16(x)
}

func linkLocalV6() netip.Addr {
	var x [16]byte
	x[0], x[1] = 0xfe, 0x80
	x[15] = 0x11
	return netip.AddrFrom16(x)
}

func loopbackV6() netip.Addr {
	var x [16]byte
	x[15] = 1
	return netip.AddrFrom16(x)
}

// sinkV6 is the IPv6 sink address a promoted posture installs on the tunnel
// (`fd00:d951:1::2`) so that a host with global IPv6 draws its v6 flows into
// the tunnel instead of letting them leak out the physical NIC. It shares this
// fixture's assigned `fd00::/8` ULA prefix with `fixtureAssign().V6` but is a
// different address — exactly the discriminant a prefix-based classifier would
// wrongly collapse.
func sinkV6() netip.Addr {
	var x [16]byte
	x[0], x[1] = 0xfd, 0x00
	x[2], x[3] = 0xd9, 0x51
	x[4], x[5] = 0x00, 0x01
	x[15] = 0x02
	return netip.AddrFrom16(x)
}

// TestUnassignedFamilyIsRefused. If the gateway assigned no inner IPv6, the tun
// layer is the last thing standing between a host that somehow routed IPv6 at
// the interface and an IPv6 flow leaving in the clear. It says no.
func TestUnassignedFamilyIsRefused(t *testing.T) {
	v4only := func(c *Config) {
		c.Assign = Assignment{V4: fixtureAssign().V4, RouterV4: fixtureAssign().RouterV4}
	}
	f := newFixture(t, v4only).carrying()
	if err := f.tun.Outbound(goodV6(64)); !errors.Is(err, ErrFamilyOff) {
		t.Fatalf("Outbound IPv6 on a v4-only tunnel: %v, want ErrFamilyOff", err)
	}
	if err := f.tun.Inbound(arrivingV6(64)); !errors.Is(err, ErrFamilyOff) {
		t.Fatalf("Inbound IPv6 on a v4-only tunnel: %v, want ErrFamilyOff", err)
	}
	f.quiet("ipv6 on a v4-only tunnel")

	v6only := func(c *Config) {
		c.Assign = Assignment{V6: fixtureAssign().V6, RouterV6: fixtureAssign().RouterV6}
	}
	g := newFixture(t, v6only).carrying()
	if err := g.tun.Outbound(goodV4(64)); !errors.Is(err, ErrFamilyOff) {
		t.Fatalf("Outbound IPv4 on a v6-only tunnel: %v, want ErrFamilyOff", err)
	}
	g.quiet("ipv4 on a v6-only tunnel")
}

// TestTruncationDoesNotLeakTheBufferTail is the reused-buffer bug, made
// concrete.
//
// The pump reads into one buffer for the life of the tunnel. A 1400-byte
// packet lands, then a 60-byte one. If the layer forwards what the device
// returned rather than what the header declares, the second DATA frame carries
// 60 bytes of the new flow followed by 1340 bytes of the previous one — one
// application's traffic inside another's packet, encrypted, delivered, and
// invisible to everything downstream.
func TestTruncationDoesNotLeakTheBufferTail(t *testing.T) {
	f := newFixture(t).carrying()

	const declared = 100
	pkt := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: declared - IPv4HeaderMin, trailer: 900}.build()
	if len(pkt) != declared+900 {
		t.Fatalf("builder produced %d bytes, want %d", len(pkt), declared+900)
	}
	if err := f.tun.Outbound(pkt); err != nil {
		t.Fatalf("Outbound: %v", err)
	}
	got := f.sink.last()
	if len(got) != declared {
		t.Fatalf("session received %d bytes; the header declared %d, so %d bytes of somebody else's data travelled",
			len(got), declared, len(got)-declared)
	}
	if st := f.tun.Stats(); st.TxTruncatedTail != 1 {
		t.Fatalf("TxTruncatedTail=%d, want 1", st.TxTruncatedTail)
	}

	// Same rule on the way in, where the trailing bytes would be written into
	// the host's stack instead.
	in := v4cfg{src: peerV4(), dst: fixtureAssign().V4, payload: declared - IPv4HeaderMin, trailer: 400}.build()
	if err := f.tun.Inbound(in); err != nil {
		t.Fatalf("Inbound: %v", err)
	}
	if n := len(f.dev.lastWrite()); n != declared {
		t.Fatalf("host device received %d bytes, want %d", n, declared)
	}
	if st := f.tun.Stats(); st.RxTruncatedTail != 1 {
		t.Fatalf("RxTruncatedTail=%d, want 1", st.RxTruncatedTail)
	}
}

// TestSingleByteMutationsNeverProduceAForeignSource walks a valid packet byte
// by byte, corrupts each one several ways, and requires the invariant to hold
// over everything the session ended up accepting.
//
// It is a property test rather than a list of cases on purpose: it covers
// header fields nobody thought to write a case for, including ones a later
// change might add.
func TestSingleByteMutationsNeverProduceAForeignSource(t *testing.T) {
	f := newFixture(t).carrying()
	base := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 200, df: true}.build()

	masks := []byte{0x01, 0x0f, 0x55, 0x80, 0xff}
	for i := range base {
		for _, m := range masks {
			mutated := append([]byte(nil), base...)
			mutated[i] ^= m
			_ = f.tun.Outbound(mutated)
		}
	}
	// The IPv6 half of the same sweep.
	base6 := v6cfg{src: fixtureAssign().V6, dst: peerV6(), payload: 200}.build()
	for i := range base6 {
		for _, m := range masks {
			mutated := append([]byte(nil), base6...)
			mutated[i] ^= m
			_ = f.tun.Outbound(mutated)
		}
	}

	sent := f.sink.all()
	if len(sent) == 0 {
		t.Fatal("no mutation was accepted at all; the sweep proves nothing")
	}
	a := fixtureAssign()
	for _, pkt := range sent {
		p, err := parsePacket(pkt)
		if err != nil {
			t.Fatalf("the session was handed something that does not parse: %v", err)
		}
		want := a.V4
		if p.v6 {
			want = a.V6
		}
		if p.src != want {
			t.Fatalf("a packet with a foreign source reached the session after a single-byte mutation")
		}
		if len(pkt) > f.tun.InnerMTU() {
			t.Fatalf("a %d-byte packet reached the session; the inner MTU is %d", len(pkt), f.tun.InnerMTU())
		}
		if len(pkt) != len(p.body) {
			t.Fatalf("the session was handed %d bytes for a packet that declares %d", len(pkt), len(p.body))
		}
	}
	t.Logf("mutation sweep: %d of %d mutated packets were accepted, all with the assigned source",
		len(sent), (len(base)+len(base6))*len(masks))
}

// TestFragmentsAreCarried. Inner fragments are ordinary traffic and are
// forwarded; what this package refuses to do is CREATE them. A non-first
// fragment carries no transport header but still carries a source address, and
// that is the field the rules turn on.
func TestFragmentsAreCarried(t *testing.T) {
	f := newFixture(t).carrying()
	first := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 200, mf: true}.build()
	later := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 200, fragOff: 25}.build()
	if err := f.tun.Outbound(first); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if err := f.tun.Outbound(later); err != nil {
		t.Fatalf("later fragment: %v", err)
	}
	if f.sink.count() != 2 {
		t.Fatalf("session saw %d fragments, want 2", f.sink.count())
	}

	// A later fragment with a foreign source is still refused: the fragment
	// offset does not buy an exemption from the address rule.
	foreign := v4cfg{src: peerV4(), dst: peerV4(), payload: 200, fragOff: 25}.build()
	if err := f.tun.Outbound(foreign); !errors.Is(err, ErrSourceNotOurs) {
		t.Fatalf("foreign later fragment: %v, want ErrSourceNotOurs", err)
	}
}

// TestIPv4OptionsAreParsed makes sure a header with options is measured by its
// IHL and not by the 20-byte minimum — otherwise the option bytes would be
// read as the start of the payload and the addresses would be read from the
// wrong offsets.
func TestIPv4OptionsAreParsed(t *testing.T) {
	f := newFixture(t).carrying()
	pkt := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 64, ihlWords: 8}.build()
	if err := f.tun.Outbound(pkt); err != nil {
		t.Fatalf("Outbound with IPv4 options: %v", err)
	}
	p, err := parsePacket(f.sink.last())
	if err != nil {
		t.Fatal(err)
	}
	if p.hdrLen != 32 {
		t.Fatalf("header length %d, want 32", p.hdrLen)
	}
	if p.src != fixtureAssign().V4 {
		t.Fatal("addresses were read from the wrong offsets")
	}
}

// TestErrorsDoNotNameTheHostAddress. These errors are logged by hosts. A log
// line naming the handset's real carrier-assigned source address records
// exactly the fact the tunnel exists to keep off the record — and on a seized
// device the log is the first thing read.
func TestErrorsDoNotNameTheHostAddress(t *testing.T) {
	f := newFixture(t).carrying()
	real := v4a(203, 0, 113, 45)
	pkt := v4cfg{src: real, dst: peerV4(), payload: 64}.build()
	err := f.tun.Outbound(pkt)
	if err == nil {
		t.Fatal("a foreign source was accepted")
	}
	if got := err.Error(); containsAddr(got, real) {
		t.Fatalf("the error text names the host's real source address: %q", got)
	}
}

func containsAddr(s string, a netip.Addr) bool {
	txt := a.String()
	for i := 0; i+len(txt) <= len(s); i++ {
		if s[i:i+len(txt)] == txt {
			return true
		}
	}
	return false
}
