package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// OI-5 gateway client isolation (PQ-ATTEST round, unanimous 2026-10-10; exact
// code 2026-10-11). Each test below is one refusal class or one item of the
// agreed acceptance list: A-to-B, spoofed source, return-flow misdelivery,
// management and metadata access, NAT hairpin, address reuse after reconnect.
// Every test that asserts a refusal fails on the tree before the fix, where
// WritePacket discarded the destination and wrote a non-IPv4 packet through.
//
// The addresses are used by no other test in this package, so a stray stderr
// line from another goroutine cannot satisfy or defeat the absence checks.

const (
	isoPool    = "10.64.80.0/24"
	isoInner   = "10.64.80.1"
	isoClientA = "10.64.80.2"
	isoClientB = "10.64.80.3"
	isoWAN     = "203.0.113.80"
	isoSecond  = "203.0.113.81" // a second public address on a local interface
	isoPublic  = "198.51.100.80"
)

// fakeLister stands in for net.InterfaceAddrs: it reports the given addresses
// as /32 and /128 interface addresses.
func fakeLister(addrs ...string) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		out := make([]net.Addr, 0, len(addrs))
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				return nil, errors.New("fakeLister: bad address")
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
		return out, nil
	}
}

// isolatedTable is a forwardTable carrying the OI-5 rule for isoPool, with
// the inner address and the given local addresses, and no registry.
func isolatedTable(t *testing.T, local ...string) *forwardTable {
	t.Helper()
	tbl := newForwardTable()
	iso, err := newForwardIsolationWith(netip.MustParsePrefix(isoPool), netip.MustParseAddr(isoInner),
		fakeLister(append([]string{isoInner, "127.0.0.1", "fe80::1"}, local...)...))
	if err != nil {
		t.Fatalf("newForwardIsolationWith: %v", err)
	}
	tbl.isolation = iso
	return tbl
}

// boundDevice is a device on tbl with a fresh fake writer and a bound loop.
func boundDevice(t *testing.T, tbl *forwardTable) (*gatewayForwardDevice, *fakeInnerWriter) {
	t.Helper()
	writer := &fakeInnerWriter{}
	dev := newGatewayForwardDevice(writer, tbl, 1400)
	dev.bind(fakeLoop())
	t.Cleanup(func() { _ = dev.Close() })
	return dev, writer
}

// expectRefused asserts one destination refusal: the error, no write, and
// the counter moved by one.
func expectRefused(t *testing.T, dev *gatewayForwardDevice, writer *fakeInnerWriter, src, dst string) {
	t.Helper()
	before := dev.table.Stats().IntraSubnet
	writes := len(writer.written)
	n, err := dev.WritePacket(ipv4Packet(t, src, dst))
	if !errors.Is(err, errGatewayDestinationRefused) || n != 0 {
		t.Fatalf("%s -> %s: n=%d err=%v, want 0 and %v", src, dst, n, err, errGatewayDestinationRefused)
	}
	if len(writer.written) != writes {
		t.Fatalf("%s -> %s reached the kernel writer", src, dst)
	}
	if got := dev.table.Stats().IntraSubnet; got != before+1 {
		t.Fatalf("%s -> %s: intra_subnet = %d, want %d", src, dst, got, before+1)
	}
}

// expectForwarded asserts the packet was written through unchanged.
func expectForwarded(t *testing.T, dev *gatewayForwardDevice, writer *fakeInnerWriter, src, dst string) {
	t.Helper()
	writes := len(writer.written)
	pkt := ipv4Packet(t, src, dst)
	n, err := dev.WritePacket(pkt)
	if err != nil || n != len(pkt) {
		t.Fatalf("%s -> %s: n=%d err=%v, want written", src, dst, n, err)
	}
	if len(writer.written) != writes+1 {
		t.Fatalf("%s -> %s: writer received %d packets, want %d", src, dst, len(writer.written), writes+1)
	}
}

// Refusal class: not IPv4. Before the fix the packet was logged and WRITTEN.
func TestForwardIsolationRefusesNonIPv4(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t))
	pkt := ipv4Packet(t, isoClientA, isoPublic)
	pkt[0] = 0x60 // version 6
	n, err := dev.WritePacket(pkt)
	if !errors.Is(err, errGatewayForwardNotIPv4) || n != 0 {
		t.Fatalf("non-IPv4 write: n=%d err=%v, want 0 and %v", n, err, errGatewayForwardNotIPv4)
	}
	if len(writer.written) != 0 {
		t.Fatal("a non-IPv4 packet reached the kernel writer")
	}
	if got := dev.table.Stats().IntraSubnet; got != 1 {
		t.Fatalf("intra_subnet = %d, want 1", got)
	}
	// The same refusal with no isolation rule attached (a bare table): the
	// family check does not depend on the rule being configured.
	bare, bareWriter := boundDevice(t, newForwardTable())
	if _, err := bare.WritePacket(pkt); !errors.Is(err, errGatewayForwardNotIPv4) || len(bareWriter.written) != 0 {
		t.Fatalf("bare table: err=%v writes=%d, want %v and 0", err, len(bareWriter.written), errGatewayForwardNotIPv4)
	}
}

// Acceptance: A-to-B. A client packet addressed to another pool address is
// refused; the same session's internet traffic still flows.
func TestForwardIsolationRefusesAToB(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t))
	expectForwarded(t, dev, writer, isoClientA, isoPublic)
	expectRefused(t, dev, writer, isoClientA, isoClientB)
	expectRefused(t, dev, writer, isoClientA, "10.64.80.254")
	expectForwarded(t, dev, writer, isoClientA, "1.1.1.1")
}

// Refusal class: the pool's network and directed-broadcast addresses. The
// registry refuses to bind them; this refuses to send to them.
func TestForwardIsolationRefusesPoolNetworkAndBroadcast(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t))
	expectRefused(t, dev, writer, isoClientA, "10.64.80.0")
	expectRefused(t, dev, writer, isoClientA, "10.64.80.255")
}

// The one pool address a client may reach: the gateway's own inner address,
// where the resolver, the echo responder and the speedtest ingest live. Also
// pins that an inner address listed by the interface lister is not put in the
// local set by mistake.
func TestForwardIsolationAllowsTheGatewayInnerAddress(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t, isoWAN))
	expectForwarded(t, dev, writer, isoClientA, isoInner)
	if got := dev.table.Stats().IntraSubnet; got != 0 {
		t.Fatalf("intra_subnet = %d after a packet to the inner address, want 0", got)
	}
	for _, a := range dev.table.isolation.localAddrs() {
		if a == netip.MustParseAddr(isoInner) {
			t.Fatal("the inner address is in the local refusal set")
		}
	}
}

// Refusal class: RFC 1918 and RFC 6598 destinations, including the block
// edges, and the public neighbours of those edges that must still pass.
func TestForwardIsolationRefusesPrivateAndSharedSpace(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t))
	for _, dst := range []string{
		"10.0.0.0", "10.8.0.1", "10.255.255.255", // 10/8 (awg0's VPN_CIDR lives here)
		"172.16.0.0", "172.17.0.1", "172.31.255.255", // 172.16/12 (docker0 lives here)
		"192.168.0.0", "192.168.4.36", "192.168.255.255", // 192.168/16
		"100.64.0.0", "100.100.100.100", "100.127.255.255", // 100.64/10
	} {
		expectRefused(t, dev, writer, isoClientA, dst)
	}
	for _, dst := range []string{
		"9.255.255.255", "11.0.0.0",
		"172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0",
		"100.63.255.255", "100.128.0.0",
		"8.8.8.8", "1.1.1.1", "198.51.100.1",
	} {
		expectForwarded(t, dev, writer, isoClientA, dst)
	}
}

// Acceptance: management access. A tunnel packet to any address configured
// on a local interface, including a public secondary address, is refused in
// process; a public address that is not local still passes. Metadata access
// (169.254/16) is refused before this layer by the tun validator: see
// winn3/tun/transit_test.go, "martian destination is still refused".
func TestForwardIsolationRefusesLocalInterfaceAddresses(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t, isoWAN, isoSecond))
	expectRefused(t, dev, writer, isoClientA, isoWAN)
	expectRefused(t, dev, writer, isoClientA, isoSecond)
	expectForwarded(t, dev, writer, isoClientA, "203.0.113.82")
	// Loopback was listed by the lister and sits in the set; the tun
	// validator refuses it upstream, and it is harmless here.
	expectRefused(t, dev, writer, isoClientA, "127.0.0.1")
}

// Acceptance: NAT hairpin. The WAN address is the one every client already
// holds (it is the outer endpoint); addressed from inside the tunnel it is
// refused before the kernel could deliver it to the gateway's own sockets.
func TestForwardIsolationRefusesNATHairpinToTheWANAddress(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t, isoWAN))
	expectRefused(t, dev, writer, isoClientA, isoWAN)
	if got := dev.table.Stats().IntraSubnet; got != 1 {
		t.Fatalf("intra_subnet = %d, want 1", got)
	}
}

// Refusal class: dst == src. Without a registry the source is unconstrained,
// so a source outside the pool addressed to itself is refused by this rule
// alone, and a source outside the pool addressed elsewhere passes.
func TestForwardIsolationRefusesDestinationEqualToSource(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t))
	expectRefused(t, dev, writer, "198.51.100.90", "198.51.100.90")
	expectForwarded(t, dev, writer, "198.51.100.90", "198.51.100.91")
}

// Acceptance: spoofed source. Through a real authenticated session and
// registry, a packet whose inner source is not the one the registry binds is
// refused as source_mismatch, with the destination rule attached and never
// consulted: the source checks run first, so intra_subnet stays 0.
func TestForwardIsolationSpoofedSourceIsRefusedAsSourceFirst(t *testing.T) {
	const spoofed = "10.10.0.80"
	f := newAuthorityFixture(t, 0)
	iso, err := newForwardIsolationWith(netip.MustParsePrefix("10.10.0.0/24"), netip.MustParseAddr("10.10.0.1"),
		fakeLister("10.10.0.1", isoWAN))
	if err != nil {
		t.Fatal(err)
	}
	f.table.isolation = iso
	// Spoofed source to a pool destination: source_mismatch, not intra_subnet.
	if _, err := f.device.WritePacket(ipv4Packet(t, spoofed, "10.10.0.3")); !errors.Is(err, errGatewayInnerSourceMismatch) {
		t.Fatalf("spoofed source error = %v, want %v", err, errGatewayInnerSourceMismatch)
	}
	// The authorized source to a pool destination: intra_subnet.
	if _, err := f.device.WritePacket(ipv4Packet(t, f.addr.String(), "10.10.0.3")); !errors.Is(err, errGatewayDestinationRefused) {
		t.Fatalf("A-to-B through the fixture: err = %v, want %v", err, errGatewayDestinationRefused)
	}
	// The authorized source to the WAN address: intra_subnet.
	if _, err := f.device.WritePacket(ipv4Packet(t, f.addr.String(), isoWAN)); !errors.Is(err, errGatewayDestinationRefused) {
		t.Fatalf("hairpin through the fixture: err = %v, want %v", err, errGatewayDestinationRefused)
	}
	got := f.table.Stats()
	if got.SourceMismatch != 1 || got.IntraSubnet != 2 || got.PeerUnauthorized != 0 {
		t.Fatalf("counters = %+v, want source_mismatch 1, intra_subnet 2", got)
	}
	// Internet traffic from the authorized source still flows.
	f.checkForwarding(t, true)
}

// Acceptance: return-flow misdelivery. A refused A-to-B packet changes
// nothing in the forwarding table: B's address still returns to B's session
// only, and A's session is not learned for B's address.
func TestForwardIsolationAToBLeavesTheReturnPathPinned(t *testing.T) {
	tbl := isolatedTable(t)
	a, aWriter := boundDevice(t, tbl)
	b, bWriter := boundDevice(t, tbl)
	expectForwarded(t, a, aWriter, isoClientA, isoPublic)
	expectForwarded(t, b, bWriter, isoClientB, isoPublic)
	expectRefused(t, a, aWriter, isoClientA, isoClientB)
	expectRefused(t, b, bWriter, isoClientB, isoClientA)
	ownerB, ok := tbl.lookup(netip.MustParseAddr(isoClientB))
	if !ok || ownerB != b.loop {
		t.Fatalf("B's return path: got=%v ok=%v, want B's session", ownerB, ok)
	}
	ownerA, ok := tbl.lookup(netip.MustParseAddr(isoClientA))
	if !ok || ownerA != a.loop {
		t.Fatalf("A's return path: got=%v ok=%v, want A's session", ownerA, ok)
	}
	if stats := tbl.Stats(); stats.Size != 2 || stats.Collisions != 0 {
		t.Fatalf("table after A-to-B attempts: %+v, want size 2, collisions 0", stats)
	}
}

// The local set follows the WAN address: after the host's address changes,
// one refresh makes the new address refused and the old one a plain public
// destination again. runLocalRefresh does the same on its tick and stops
// with its context.
func TestForwardIsolationLocalSetFollowsAWANAddressChange(t *testing.T) {
	const moved = "203.0.113.83"
	var current atomic.Pointer[[]string]
	initial := []string{isoInner, isoWAN}
	current.Store(&initial)
	lister := func() ([]net.Addr, error) { return fakeLister((*current.Load())...)() }
	tbl := newForwardTable()
	iso, err := newForwardIsolationWith(netip.MustParsePrefix(isoPool), netip.MustParseAddr(isoInner), lister)
	if err != nil {
		t.Fatal(err)
	}
	tbl.isolation = iso
	dev, writer := boundDevice(t, tbl)
	expectRefused(t, dev, writer, isoClientA, isoWAN)
	expectForwarded(t, dev, writer, isoClientA, moved)

	movedSet := []string{isoInner, moved}
	current.Store(&movedSet)
	if err := iso.refreshLocal(); err != nil {
		t.Fatal(err)
	}
	expectForwarded(t, dev, writer, isoClientA, isoWAN)
	expectRefused(t, dev, writer, isoClientA, moved)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		iso.runLocalRefresh(ctx, 2*time.Millisecond)
	}()
	current.Store(&initial)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if local := iso.localAddrs(); len(local) == 1 && local[0] == netip.MustParseAddr(isoWAN) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("runLocalRefresh did not pick up the new address within 2s: %v", iso.localAddrs())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLocalRefresh did not stop with its context")
	}
	expectRefused(t, dev, writer, isoClientA, isoWAN)
}

// A refresh that fails keeps the last good set in force and reports once.
func TestForwardIsolationRefreshFailureKeepsTheLastGoodSet(t *testing.T) {
	fail := false
	lister := func() ([]net.Addr, error) {
		if fail {
			return nil, errors.New("netlink: operation not permitted")
		}
		return fakeLister(isoInner, isoWAN)()
	}
	iso, err := newForwardIsolationWith(netip.MustParsePrefix(isoPool), netip.MustParseAddr(isoInner), lister)
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := iso.refreshLocal(); err == nil {
		t.Fatal("refreshLocal reported success on a failing lister")
	}
	if local := iso.localAddrs(); len(local) != 1 || local[0] != netip.MustParseAddr(isoWAN) {
		t.Fatalf("local set after a failed refresh = %v, want the last good set", local)
	}
	out := captureStderr(t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); iso.runLocalRefresh(ctx, time.Millisecond) }()
		deadline := time.Now().Add(2 * time.Second)
		for !iso.warned.Load() {
			if time.Now().After(deadline) {
				cancel()
				<-done
				t.Fatal("refresh loop did not report failure within 2s")
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(10 * time.Millisecond)
		cancel()
		<-done
	})
	if c := strings.Count(out, "refreshing this host's interface addresses failed"); c != 1 {
		t.Fatalf("refresh failure lines = %d, want exactly 1; captured:\n%s", c, out)
	}
	// Construction itself fails closed on a failing lister.
	if _, err := newForwardIsolationWith(netip.MustParsePrefix(isoPool), netip.MustParseAddr(isoInner), lister); err == nil {
		t.Fatal("newForwardIsolationWith succeeded with a lister that fails")
	}
}

// Acceptance: address reuse after reconnect. Session A closes; a new session
// claims the same inner address; the rule applies to it unchanged, its first
// refusal is described again (the once-per-session bound is per session),
// and the counter keeps running process-wide.
func TestForwardIsolationSurvivesAddressReuseAfterReconnect(t *testing.T) {
	tbl := isolatedTable(t, isoWAN)
	out := captureStderr(t, func() {
		first, firstWriter := boundDevice(t, tbl)
		expectForwarded(t, first, firstWriter, isoClientA, isoPublic)
		expectRefused(t, first, firstWriter, isoClientA, isoClientB)
		expectRefused(t, first, firstWriter, isoClientA, isoClientB)
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		if _, ok := tbl.lookup(netip.MustParseAddr(isoClientA)); ok {
			t.Fatal("the closed session still owns its address")
		}
		second, secondWriter := boundDevice(t, tbl)
		expectForwarded(t, second, secondWriter, isoClientA, isoPublic)
		expectRefused(t, second, secondWriter, isoClientA, isoClientB)
		expectRefused(t, second, secondWriter, isoClientA, isoWAN)
		owner, ok := tbl.lookup(netip.MustParseAddr(isoClientA))
		if !ok || owner != second.loop {
			t.Fatalf("after reconnect the address returns to got=%v ok=%v, want the new session", owner, ok)
		}
	})
	if got := tbl.Stats().IntraSubnet; got != 4 {
		t.Fatalf("intra_subnet = %d, want 4 across both sessions", got)
	}
	if c := strings.Count(out, "forward destination refused"); c != 2 {
		t.Fatalf("destination-refused lines = %d, want 2 (one per session); captured:\n%s", c, out)
	}
}

// The diagnostic is bounded and carries no address: counted per packet,
// described once per session, and the stderr line names neither the inner
// source nor the refused destination (forwardRefusal's privacy rule).
func TestForwardIsolationRefusalIsCountedPerPacketDescribedOnceAndCarriesNoAddresses(t *testing.T) {
	tbl := isolatedTable(t, isoWAN)
	out := captureStderr(t, func() {
		dev, writer := boundDevice(t, tbl)
		for i := 0; i < 5; i++ {
			expectRefused(t, dev, writer, isoClientA, isoClientB)
		}
		expectRefused(t, dev, writer, isoClientA, isoWAN)
		pkt := ipv4Packet(t, isoClientA, isoPublic)
		pkt[0] = 0x60
		if _, err := dev.WritePacket(pkt); !errors.Is(err, errGatewayForwardNotIPv4) {
			t.Fatalf("non-IPv4 after a described refusal: %v", err)
		}
	})
	if got := tbl.Stats().IntraSubnet; got != 7 {
		t.Fatalf("intra_subnet = %d, want 7", got)
	}
	if c := strings.Count(out, "forward destination refused"); c != 1 {
		t.Fatalf("destination-refused lines = %d, want 1; captured:\n%s", c, out)
	}
	if strings.Contains(out, "non-IPv4") {
		t.Fatalf("the non-IPv4 refusal was described a second time for the same class; captured:\n%s", out)
	}
	if !strings.Contains(out, "see forward.table.intra_subnet") {
		t.Fatalf("the line does not point at its counter; captured:\n%s", out)
	}
	for _, addr := range []string{isoClientA, isoClientB, isoWAN, isoPublic, isoInner} {
		if strings.Contains(out, addr) {
			t.Errorf("forward diagnostic leaked %s:\n%s", addr, out)
		}
	}
}

// The counter is published under forward.table as intra_subnet, beside the
// existing classes, so the rate is visible in status as the agreed text says.
func TestForwardIsolationPublishesTheIntraSubnetCounter(t *testing.T) {
	tbl := isolatedTable(t)
	dev, writer := boundDevice(t, tbl)
	expectRefused(t, dev, writer, isoClientA, isoClientB)
	blob, err := json.Marshal(gatewayForwardStatus{Table: tbl.Stats()})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Table map[string]any `json:"table"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}
	if got, ok := doc.Table["intra_subnet"]; !ok || got != float64(1) {
		t.Fatalf("forward.table.intra_subnet = %v (present=%v), want 1: %s", got, ok, blob)
	}
	for _, key := range []string{"peer_unauthorized", "source_mismatch", "source_changed", "source_owned", "write_failed"} {
		if _, ok := doc.Table[key]; !ok {
			t.Fatalf("forward.table lost %s: %s", key, blob)
		}
	}
}

// The rule is IPv4 only, like -forward itself.
func TestNewForwardIsolationRefusesNonIPv4Inputs(t *testing.T) {
	if _, err := newForwardIsolationWith(netip.MustParsePrefix("fd00::/64"), netip.MustParseAddr(isoInner), fakeLister()); err == nil {
		t.Fatal("an IPv6 pool was accepted")
	}
	if _, err := newForwardIsolationWith(netip.MustParsePrefix(isoPool), netip.MustParseAddr("fd00::1"), fakeLister()); err == nil {
		t.Fatal("an IPv6 inner address was accepted")
	}
	if _, err := newForwardIsolationWith(netip.Prefix{}, netip.MustParseAddr(isoInner), fakeLister()); err == nil {
		t.Fatal("an invalid pool was accepted")
	}
}

// The pool mask is computed for every prefix length -forward accepts. The
// "out" address is outside the pool's mask and outside every other refused
// range, so the allowed verdict comes from the mask alone; the production
// pool (10.64/24) sits inside 10/8 and the /22 inside the CGNAT block, so
// their out addresses leave those blocks entirely. /0 is not refused by
// parseForwardCIDR (only /31 and above are) and must not panic here.
func TestForwardIsolationPoolMaskArithmetic(t *testing.T) {
	cases := []struct{ pool, inner, in, out string }{
		{"10.64.0.0/24", "10.64.0.1", "10.64.0.200", "11.64.0.1"},
		{"203.0.113.0/24", "203.0.113.1", "203.0.113.200", "203.0.114.1"},
		{"192.0.2.0/25", "192.0.2.1", "192.0.2.126", "192.0.2.129"},
		{"100.100.0.0/22", "100.100.0.1", "100.100.3.254", "100.128.0.1"},
		{"198.18.0.0/15", "198.18.0.1", "198.19.255.254", "198.20.0.1"},
	}
	for _, c := range cases {
		iso, err := newForwardIsolationWith(netip.MustParsePrefix(c.pool), netip.MustParseAddr(c.inner), fakeLister())
		if err != nil {
			t.Fatalf("%s: %v", c.pool, err)
		}
		src := isoWord(t, netip.MustParseAddr(c.inner).Next().String())
		if !iso.refuses(src, isoWord(t, c.in)) {
			t.Errorf("%s: %s inside the pool was allowed", c.pool, c.in)
		}
		if iso.refuses(src, isoWord(t, c.out)) {
			t.Errorf("%s: %s outside the pool was refused", c.pool, c.out)
		}
		if iso.refuses(src, isoWord(t, c.inner)) {
			t.Errorf("%s: the inner address was refused", c.pool)
		}
	}
	iso, err := newForwardIsolationWith(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr(isoInner), fakeLister())
	if err != nil {
		t.Fatal(err)
	}
	if !iso.refuses(isoWord(t, isoClientA), isoWord(t, "8.8.8.8")) {
		t.Fatal("a /0 pool must contain everything")
	}
}

// isoWord is an address as the word refuses compares, the form
// ipv4SourceDestinationUint32 reads out of a packet.
func isoWord(t *testing.T, s string) uint32 {
	t.Helper()
	a := netip.MustParseAddr(s).As4()
	return binary.BigEndian.Uint32(a[:])
}

// The words refuses reads are the packet's own address fields, byte for
// byte, so the rule and ipv4SourceDestination can never disagree about which
// addresses a packet carries.
func TestIPv4SourceDestinationUint32ReadsThePacketsOwnFields(t *testing.T) {
	pkt := ipv4Packet(t, isoClientA, isoPublic)
	src, dst, ok := ipv4SourceDestination(pkt)
	if !ok {
		t.Fatal("the test packet does not parse")
	}
	s, d := ipv4SourceDestinationUint32(pkt)
	if s != isoWord(t, src.String()) || d != isoWord(t, dst.String()) {
		t.Fatalf("words = %#x %#x, want %#x %#x", s, d, isoWord(t, src.String()), isoWord(t, dst.String()))
	}
}

// A pool carved out of the private or shared space it is refused inside of
// (the production default 10.64/24 sits in 10/8; a 100.100/24 pool sits in
// 100.64/10) keeps exactly one exception: the inner address. Every other
// pool address, the network and broadcast included, stays refused, and so
// does the rest of the enclosing block. The exception runs first in refuses,
// which is what makes both sentences of the agreed text true at once.
func TestForwardIsolationPoolInsidePrivateSpaceKeepsOnlyTheInnerException(t *testing.T) {
	for _, c := range []struct{ pool, inner string }{
		{"10.64.0.0/24", "10.64.0.1"},
		{"100.100.0.0/24", "100.100.0.1"},
		{"192.168.50.0/24", "192.168.50.1"},
		{"172.20.0.0/24", "172.20.0.1"},
	} {
		tbl := newForwardTable()
		iso, err := newForwardIsolationWith(netip.MustParsePrefix(c.pool), netip.MustParseAddr(c.inner),
			fakeLister(c.inner, "127.0.0.1", isoWAN))
		if err != nil {
			t.Fatalf("%s: %v", c.pool, err)
		}
		tbl.isolation = iso
		dev, writer := boundDevice(t, tbl)
		network := netip.MustParsePrefix(c.pool).Masked().Addr()
		var last [4]byte
		binary.BigEndian.PutUint32(last[:], isoWord(t, network.String())|0xff)
		client := netip.MustParseAddr(c.inner).Next()
		expectForwarded(t, dev, writer, client.String(), c.inner)
		expectForwarded(t, dev, writer, client.String(), isoPublic)
		for _, dst := range []string{
			network.String(),               // the pool's network address
			netip.AddrFrom4(last).String(), // the pool's broadcast address
			client.Next().String(),         // another client
			network.Prev().String(),        // just below the pool, inside the enclosing block
		} {
			expectRefused(t, dev, writer, client.String(), dst)
		}
		if got := tbl.Stats().IntraSubnet; got != 4 {
			t.Fatalf("%s: intra_subnet = %d, want 4", c.pool, got)
		}
	}
}

// dst == src has priority even when both name the inner service exception.
func TestForwardIsolationSelfInnerIsRefused(t *testing.T) {
	dev, writer := boundDevice(t, isolatedTable(t))
	expectRefused(t, dev, writer, isoInner, isoInner)
}

// Every local address must be screened, including hosts with more than 16.
func TestForwardIsolationKeepsAllLocalAddresses(t *testing.T) {
	locals := make([]string, 40)
	for i := range locals {
		locals[i] = netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 100)}).String()
	}
	dev, writer := boundDevice(t, isolatedTable(t, locals...))
	for _, dst := range locals {
		expectRefused(t, dev, writer, isoClientA, dst)
	}
}
