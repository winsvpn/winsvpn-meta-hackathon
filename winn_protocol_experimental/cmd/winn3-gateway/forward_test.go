package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// These tests exercise forward.go's portable half only: forwardTable,
// gatewayForwardDevice and ipv4SourceDestination need no kernel interface and
// run on every OS this repo builds on, including this one. sharedGatewayTun
// itself (forward_linux.go) needs a real Linux host with CAP_NET_ADMIN and is
// NOT exercised here -- see the handoff document for what that leaves
// unverified.
//
// *driver.Loop is used below only as an opaque identity: forwardTable and
// gatewayForwardDevice never call a method on it, only compare and store the
// pointer, so a bare &driver.Loop{} (legal from outside the package because
// the zero-value composite literal names no field) is a safe stand-in for
// "some session" without constructing a real handshake, carrier and session
// driver.

func fakeLoop() *driver.Loop { return &driver.Loop{} }

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestForwardTableLearnLookupForget(t *testing.T) {
	tbl := newForwardTable()
	loop := fakeLoop()
	addr := mustAddr(t, "10.64.0.2")

	if _, ok := tbl.lookup(addr); ok {
		t.Fatal("lookup on an empty table found something")
	}

	tbl.learn(addr, loop)
	got, ok := tbl.lookup(addr)
	if !ok || got != loop {
		t.Fatalf("lookup after learn: got=%v ok=%v, want %v true", got, ok, loop)
	}
	if stats := tbl.Stats(); stats.Size != 1 || stats.Learned != 1 || stats.Collisions != 0 {
		t.Fatalf("stats after one learn: %+v", stats)
	}

	tbl.forget(addr, loop)
	if _, ok := tbl.lookup(addr); ok {
		t.Fatal("lookup after forget still found the address")
	}
	if stats := tbl.Stats(); stats.Size != 0 || stats.Forgotten != 1 {
		t.Fatalf("stats after forget: %+v", stats)
	}
}

// TestForwardTableCollisionKeepsTheLiveOwner pins the exact race forget's doc
// describes: session B cannot take A's address before A's cleanup runs. Once A
// forgets it, no stale mapping remains and B may claim it normally.
func TestForwardTableCollisionKeepsTheLiveOwner(t *testing.T) {
	tbl := newForwardTable()
	addr := mustAddr(t, "10.64.0.9")
	sessionA := fakeLoop()
	sessionB := fakeLoop()

	tbl.learn(addr, sessionA)
	if tbl.learn(addr, sessionB) { // B collides before A's cleanup runs
		t.Fatal("a second live session stole A's mapping")
	}

	tbl.forget(addr, sessionA) // A's stale cleanup

	got, ok := tbl.lookup(addr)
	if ok {
		t.Fatalf("A's forget left a mapping behind: got=%v", got)
	}
}

func TestForwardTableCountsCollisions(t *testing.T) {
	tbl := newForwardTable()
	addr := mustAddr(t, "10.64.0.5")
	first := fakeLoop()
	second := fakeLoop()
	tbl.learn(addr, first)
	if tbl.learn(addr, second) { // a different session claims the same address
		t.Fatal("a colliding session was allowed to steal the mapping")
	}
	if stats := tbl.Stats(); stats.Collisions != 1 {
		t.Fatalf("Collisions = %d, want 1", stats.Collisions)
	}
	got, ok := tbl.lookup(addr)
	if !ok || got != first {
		t.Fatalf("collision replaced the owner: got=%v ok=%v, want the first session", got, ok)
	}
	if stats := tbl.Stats(); stats.Size != 1 {
		t.Fatalf("a collision grew the table to %d entries; one address is one slot", stats.Size)
	}
}

func TestForwardTableIgnoresAnInvalidAddress(t *testing.T) {
	tbl := newForwardTable()
	tbl.learn(netip.Addr{}, fakeLoop())
	if stats := tbl.Stats(); stats.Size != 0 || stats.Learned != 0 {
		t.Fatalf("an invalid address was recorded: %+v", stats)
	}
}

func TestForwardTableIgnoresANilLoop(t *testing.T) {
	tbl := newForwardTable()
	tbl.learn(mustAddr(t, "10.64.0.2"), nil)
	if stats := tbl.Stats(); stats.Size != 0 || stats.Learned != 0 {
		t.Fatalf("a nil session was recorded: %+v", stats)
	}
}

func TestForwardTableSameSessionRelearnIsNotACollision(t *testing.T) {
	tbl := newForwardTable()
	loop := fakeLoop()
	addr := mustAddr(t, "10.64.0.2")
	tbl.learn(addr, loop)
	tbl.learn(addr, loop)
	if stats := tbl.Stats(); stats.Collisions != 0 || stats.Learned != 2 || stats.Size != 1 {
		t.Fatalf("same-loop relearn: %+v (want collisions=0 learned=2 size=1)", stats)
	}
}

func TestForwardTableForgetOfAMissingOrForeignLoopDoesNotCountAsForgotten(t *testing.T) {
	tbl := newForwardTable()
	owner := fakeLoop()
	stranger := fakeLoop()
	addr := mustAddr(t, "10.64.0.2")
	tbl.learn(addr, owner)
	tbl.forget(mustAddr(t, "10.64.0.9"), owner) // never learned
	tbl.forget(addr, stranger)                  // not the owner
	if stats := tbl.Stats(); stats.Forgotten != 0 {
		t.Fatalf("Forgotten = %d, want 0", stats.Forgotten)
	}
	got, ok := tbl.lookup(addr)
	if !ok || got != owner {
		t.Fatalf("a foreign forget evicted the owner: got=%v ok=%v", got, ok)
	}
}

// TestForwardTableKeepsAMappingUntilTheOwningLoopForgetsIt pins the eviction
// policy and the 2026-08-12 measured failure mode in one place: there is no
// TTL, a dead session that has not called forget still owns 10.64.0.2, and a
// new session that claims the same address is refused and counts a collision.
// forgotten stays 0 until the owner actually forgets.
func TestForwardTableKeepsAMappingUntilTheOwningLoopForgetsIt(t *testing.T) {
	tbl := newForwardTable()
	dead := fakeLoop()
	live := fakeLoop()
	addr := mustAddr(t, "10.64.0.2")
	tbl.learn(addr, dead)

	time.Sleep(20 * time.Millisecond)
	got, ok := tbl.lookup(addr)
	if !ok || got != dead {
		t.Fatal("forwardTable dropped a mapping without forget; eviction is Close-driven, not a TTL")
	}

	if tbl.learn(addr, live) {
		t.Fatal("a live session stole an address before its owner closed")
	}
	got, ok = tbl.lookup(addr)
	if !ok || got != dead {
		t.Fatalf("the collision replaced 10.64.0.2's owner: got=%v ok=%v", got, ok)
	}
	if stats := tbl.Stats(); stats.Collisions != 1 || stats.Forgotten != 0 || stats.Size != 1 {
		t.Fatalf("want collisions=1 forgotten=0 size=1 (the measured 2026-08-12 shape), got %+v", stats)
	}

	tbl.forget(addr, dead)
	if _, ok := tbl.lookup(addr); ok {
		t.Fatal("the dead session's close did not release its mapping")
	}
	if !tbl.learn(addr, live) {
		t.Fatal("a new session could not claim the address after the owner closed")
	}
	tbl.forget(addr, live)
	if _, ok := tbl.lookup(addr); ok {
		t.Fatal("the live session's forget did not release 10.64.0.2")
	}
}

// fakeInnerWriter is a test double for innerWriter: it records every packet
// handed to write and never touches a real device.
type fakeInnerWriter struct {
	written [][]byte
	err     error
}

func (f *fakeInnerWriter) write(pkt []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	cp := append([]byte(nil), pkt...)
	f.written = append(f.written, cp)
	return len(pkt), nil
}

// ipv4Packet builds the minimum legal-looking IPv4 header (no options, no
// payload) with the given source and destination, which is all
// ipv4SourceDestination and gatewayForwardDevice.WritePacket look at.
func ipv4Packet(t *testing.T, src, dst string) []byte {
	t.Helper()
	s := mustAddr(t, src).As4()
	d := mustAddr(t, dst).As4()
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // version 4, IHL 5 (20 bytes)
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	return pkt
}

func TestGatewayForwardDeviceWritePacketLearnsTheSourceAndWritesThrough(t *testing.T) {
	tbl := newForwardTable()
	writer := &fakeInnerWriter{}
	dev := newGatewayForwardDevice(writer, tbl, 1400)
	loop := fakeLoop()
	dev.bind(loop)

	pkt := ipv4Packet(t, "10.64.0.2", "8.8.8.8")
	n, err := dev.WritePacket(pkt)
	if err != nil || n != len(pkt) {
		t.Fatalf("WritePacket: n=%d err=%v", n, err)
	}
	if len(writer.written) != 1 {
		t.Fatalf("shared writer received %d packets, want 1", len(writer.written))
	}

	got, ok := tbl.lookup(mustAddr(t, "10.64.0.2"))
	if !ok || got != loop {
		t.Fatalf("forwarding table did not learn the client's source: got=%v ok=%v", got, ok)
	}
}

// TestGatewayForwardDeviceWritePacketBeforeBindFailsClosed covers the ordering
// note on bind: if WritePacket were ever reachable before bind (it should not
// be, in newSession's actual sequencing), it must fail closed.
func TestGatewayForwardDeviceWritePacketBeforeBindFailsClosed(t *testing.T) {
	tbl := newForwardTable()
	writer := &fakeInnerWriter{}
	dev := newGatewayForwardDevice(writer, tbl, 1400)

	pkt := ipv4Packet(t, "10.64.0.3", "1.1.1.1")
	if _, err := dev.WritePacket(pkt); !errors.Is(err, errGatewayForwardDeviceUnbound) {
		t.Fatalf("WritePacket before bind error = %v, want %v", err, errGatewayForwardDeviceUnbound)
	}
	if len(writer.written) != 0 {
		t.Fatalf("shared writer received %d packets, want 0", len(writer.written))
	}
	if stats := tbl.Stats(); stats.Size != 0 {
		t.Fatalf("table learned an address with no bound session: %+v", stats)
	}
}

func TestGatewayForwardDeviceBindsOneSourcePerSession(t *testing.T) {
	tbl := newForwardTable()
	writer := &fakeInnerWriter{}
	dev := newGatewayForwardDevice(writer, tbl, 1400)
	dev.bind(fakeLoop())

	if _, err := dev.WritePacket(ipv4Packet(t, "10.64.0.2", "8.8.8.8")); err != nil {
		t.Fatalf("first source: %v", err)
	}
	if _, err := dev.WritePacket(ipv4Packet(t, "10.64.0.3", "8.8.4.4")); !errors.Is(err, errGatewayInnerSourceChanged) {
		t.Fatalf("changed source error = %v, want %v", err, errGatewayInnerSourceChanged)
	}
	if len(writer.written) != 1 {
		t.Fatalf("shared writer received %d packets, want only the first", len(writer.written))
	}
	stats := tbl.Stats()
	if stats.Size != 1 || stats.Learned != 1 {
		t.Fatalf("one session grew more than one table entry: %+v", stats)
	}
}

func TestGatewayForwardDeviceRefusesCrossSessionAddressTheft(t *testing.T) {
	tbl := newForwardTable()
	firstWriter := &fakeInnerWriter{}
	secondWriter := &fakeInnerWriter{}
	first := newGatewayForwardDevice(firstWriter, tbl, 1400)
	second := newGatewayForwardDevice(secondWriter, tbl, 1400)
	firstLoop := fakeLoop()
	secondLoop := fakeLoop()
	first.bind(firstLoop)
	second.bind(secondLoop)
	pkt := ipv4Packet(t, "10.64.0.2", "8.8.8.8")

	if _, err := first.WritePacket(pkt); err != nil {
		t.Fatalf("owner write: %v", err)
	}
	if _, err := second.WritePacket(pkt); !errors.Is(err, errGatewayInnerSourceOwned) {
		t.Fatalf("colliding write error = %v, want %v", err, errGatewayInnerSourceOwned)
	}
	owner, ok := tbl.lookup(mustAddr(t, "10.64.0.2"))
	if !ok || owner != firstLoop {
		t.Fatalf("collision changed owner: got=%v ok=%v", owner, ok)
	}
	if len(secondWriter.written) != 0 {
		t.Fatalf("colliding session wrote %d packets to the kernel, want 0", len(secondWriter.written))
	}
}

func TestGatewayForwardDeviceClosePropagatesToTheSharedWriteError(t *testing.T) {
	tbl := newForwardTable()
	writer := &fakeInnerWriter{err: errGatewayForwardDeviceClosed}
	dev := newGatewayForwardDevice(writer, tbl, 1400)
	dev.bind(fakeLoop())

	if _, err := dev.WritePacket(ipv4Packet(t, "10.64.0.4", "9.9.9.9")); err == nil {
		t.Fatal("WritePacket over a failing shared writer returned nil error")
	}
}

func TestGatewayForwardDeviceCloseForgetsLearnedAddresses(t *testing.T) {
	tbl := newForwardTable()
	writer := &fakeInnerWriter{}
	dev := newGatewayForwardDevice(writer, tbl, 1400)
	loop := fakeLoop()
	dev.bind(loop)

	if _, err := dev.WritePacket(ipv4Packet(t, "10.64.0.6", "192.0.2.2")); err != nil {
		t.Fatal(err)
	}
	if _, ok := tbl.lookup(mustAddr(t, "10.64.0.6")); !ok {
		t.Fatal("setup: address was not learned")
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := tbl.lookup(mustAddr(t, "10.64.0.6")); ok {
		t.Fatal("Close did not forget the address this session learned")
	}
}

func TestGatewayForwardDeviceCloseReleasesItsSoleAddress(t *testing.T) {
	tbl := newForwardTable()
	writer := &fakeInnerWriter{}
	dev := newGatewayForwardDevice(writer, tbl, 1400)
	oldSession := fakeLoop()
	dev.bind(oldSession)
	if _, err := dev.WritePacket(ipv4Packet(t, "10.64.0.7", "3.3.3.3")); err != nil {
		t.Fatal(err)
	}

	// A newer session cannot claim the same address until the old session's
	// device closes.
	newSession := fakeLoop()
	if tbl.learn(mustAddr(t, "10.64.0.7"), newSession) {
		t.Fatal("new session stole the old session's live mapping")
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := tbl.lookup(mustAddr(t, "10.64.0.7")); ok {
		t.Fatal("old session's Close did not release its mapping")
	}
}

func TestGatewayForwardDeviceReadPacketUnblocksOnClose(t *testing.T) {
	dev := newGatewayForwardDevice(&fakeInnerWriter{}, newForwardTable(), 1400)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		if _, err := dev.ReadPacket(buf); err == nil {
			t.Error("ReadPacket returned nil error after Close")
		}
	}()

	select {
	case <-done:
		t.Fatal("ReadPacket returned before Close was called")
	case <-time.After(20 * time.Millisecond):
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket did not unblock within 2s of Close")
	}
}

func TestGatewayForwardDeviceMTUReportsWhatItWasBuiltWith(t *testing.T) {
	dev := newGatewayForwardDevice(&fakeInnerWriter{}, newForwardTable(), 1370)
	if got := dev.MTU(); got != 1370 {
		t.Fatalf("MTU() = %d, want 1370", got)
	}
}

func TestIPv4SourceDestination(t *testing.T) {
	pkt := ipv4Packet(t, "10.64.0.2", "8.8.8.8")
	src, dst, ok := ipv4SourceDestination(pkt)
	if !ok {
		t.Fatal("a well-formed 20-byte IPv4 header was rejected")
	}
	if src != mustAddr(t, "10.64.0.2") || dst != mustAddr(t, "8.8.8.8") {
		t.Fatalf("src=%v dst=%v, want 10.64.0.2 / 8.8.8.8", src, dst)
	}
}

func TestIPv4SourceDestinationRejectsShortInput(t *testing.T) {
	for _, n := range []int{0, 1, 19} {
		if _, _, ok := ipv4SourceDestination(make([]byte, n)); ok {
			t.Fatalf("a %d-byte packet was accepted as a valid IPv4 header", n)
		}
	}
}

func TestIPv4SourceDestinationRejectsNonIPv4(t *testing.T) {
	pkt := ipv4Packet(t, "10.64.0.2", "8.8.8.8")
	pkt[0] = 0x60 // version 6
	if _, _, ok := ipv4SourceDestination(pkt); ok {
		t.Fatal("a version-6 packet was accepted by the IPv4 parser")
	}
}

// --- -forward-cidr and -forward's startup validation -----------------------
//
// These are the checks standing between an operator's flags and a subnet
// that either cannot work (host bits set, too narrow) or that collides with
// awg0's own VPN_CIDR -- the one constraint this whole feature is not
// allowed to regress. They need no network and no TUN device, so they run
// here rather than only being provable on a real host.

func TestParseForwardCIDRAcceptsTheDocumentedDefault(t *testing.T) {
	bits, err := parseForwardCIDR("10.64.0.0/24", mustAddr(t, "10.64.0.1"))
	if err != nil {
		t.Fatalf("parseForwardCIDR: %v", err)
	}
	if bits != 24 {
		t.Fatalf("bits = %d, want 24", bits)
	}
}

func TestParseForwardCIDRRejectsHostBitsInTheNetworkPortion(t *testing.T) {
	_, err := parseForwardCIDR("10.64.0.5/24", mustAddr(t, "10.64.0.5"))
	if err == nil {
		t.Fatal("a CIDR with host bits set in its network portion was accepted")
	}
}

func TestParseForwardCIDRRejectsAnAddressOutsideTheSubnet(t *testing.T) {
	_, err := parseForwardCIDR("10.64.0.0/24", mustAddr(t, "10.65.0.1"))
	if err == nil {
		t.Fatal("-inner-v4 outside -forward-cidr was accepted")
	}
}

func TestParseForwardCIDRRejectsTheNetworkAddressItself(t *testing.T) {
	_, err := parseForwardCIDR("10.64.0.0/24", mustAddr(t, "10.64.0.0"))
	if err == nil {
		t.Fatal("-inner-v4 equal to the network address was accepted")
	}
}

func TestParseForwardCIDRRejectsTheBroadcastAddress(t *testing.T) {
	_, err := parseForwardCIDR("10.64.0.0/24", mustAddr(t, "10.64.0.255"))
	if err == nil {
		t.Fatal("-inner-v4 equal to the broadcast address was accepted")
	}
	_, err = parseForwardCIDR("10.64.0.0/30", mustAddr(t, "10.64.0.3"))
	if err == nil {
		t.Fatal("-inner-v4 equal to a /30's broadcast address was accepted")
	}
}

func TestParseForwardCIDRRejectsTooNarrowAPrefix(t *testing.T) {
	for _, cidr := range []string{"10.64.0.0/31", "10.64.0.1/32"} {
		if _, err := parseForwardCIDR(cidr, mustAddr(t, "10.64.0.1")); err == nil {
			t.Fatalf("%s was accepted despite leaving no room for a distinct client address", cidr)
		}
	}
}

func TestParseForwardCIDRRejectsIPv6(t *testing.T) {
	_, err := parseForwardCIDR("fd00::/64", mustAddr(t, "10.64.0.1"))
	if err == nil {
		t.Fatal("an IPv6 -forward-cidr was accepted")
	}
}

func TestParseForwardCIDRRejectsGarbage(t *testing.T) {
	_, err := parseForwardCIDR("not a cidr", mustAddr(t, "10.64.0.1"))
	if err == nil {
		t.Fatal("a syntactically invalid -forward-cidr was accepted")
	}
}

// TestLastAddrInPrefix pins the broadcast-address arithmetic independently of
// parseForwardCIDR, against hand-computed values including the two edge
// prefixes (/0 and /32) where the shift-by-32 UB trap lives in C and is worth
// checking explicitly in Go too.
func TestLastAddrInPrefix(t *testing.T) {
	cases := []struct{ cidr, want string }{
		{"10.64.0.0/24", "10.64.0.255"},
		{"10.64.0.0/30", "10.64.0.3"},
		{"192.168.1.0/25", "192.168.1.127"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"10.64.0.1/32", "10.64.0.1"},
		{"0.0.0.0/0", "255.255.255.255"},
	}
	for _, c := range cases {
		prefix, err := netip.ParsePrefix(c.cidr)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", c.cidr, err)
		}
		got := lastAddrInPrefix(prefix.Masked())
		if got.String() != c.want {
			t.Errorf("lastAddrInPrefix(%s) = %s, want %s", c.cidr, got, c.want)
		}
	}
}

func TestValidateForwardModeRequiresAcceptTransit(t *testing.T) {
	opts := serveOptions{
		acceptTransit: false,
		forwardIf:     "winn3gw0",
		forwardCIDR:   "10.64.0.0/24",
	}
	assign := tun.Assignment{V4: mustAddr(t, "10.64.0.1")}
	if _, err := validateForwardMode(opts, assign); err == nil {
		t.Fatal("-forward without -accept-transit was accepted")
	} else if !strings.Contains(err.Error(), "accept-transit") {
		t.Fatalf("error does not name -accept-transit: %v", err)
	}
}

func TestValidateForwardModeRejectsInnerIPv6(t *testing.T) {
	opts := serveOptions{
		acceptTransit: true,
		forwardIf:     "winn3gw0",
		forwardCIDR:   "10.64.0.0/24",
	}
	assign := tun.Assignment{V4: mustAddr(t, "10.64.0.1"), V6: mustAddr(t, "fd00::1")}
	if _, err := validateForwardMode(opts, assign); err == nil {
		t.Fatal("-forward with an inner IPv6 assignment was accepted")
	}
}

func TestValidateForwardModeRequiresACIDR(t *testing.T) {
	opts := serveOptions{acceptTransit: true, forwardIf: "winn3gw0", forwardCIDR: ""}
	assign := tun.Assignment{V4: mustAddr(t, "10.64.0.1")}
	if _, err := validateForwardMode(opts, assign); err == nil {
		t.Fatal("-forward with no -forward-cidr was accepted")
	}
}

func TestValidateForwardModeRequiresAnInterfaceName(t *testing.T) {
	opts := serveOptions{acceptTransit: true, forwardIf: "  ", forwardCIDR: "10.64.0.0/24"}
	assign := tun.Assignment{V4: mustAddr(t, "10.64.0.1")}
	if _, err := validateForwardMode(opts, assign); err == nil {
		t.Fatal("-forward with a blank -forward-if was accepted")
	}
}

func TestValidateForwardModeAcceptsTheDocumentedDefaults(t *testing.T) {
	opts := serveOptions{acceptTransit: true, forwardIf: "winn3gw0", forwardCIDR: "10.64.0.0/24", peerRegistry: "peers.json"}
	assign := tun.Assignment{V4: mustAddr(t, "10.64.0.1")}
	bits, err := validateForwardMode(opts, assign)
	if err != nil {
		t.Fatalf("validateForwardMode: %v", err)
	}
	if bits != 24 {
		t.Fatalf("bits = %d, want 24", bits)
	}
}

func TestValidateForwardModeRequiresPeerRegistry(t *testing.T) {
	opts := serveOptions{acceptTransit: true, forwardIf: "winn3gw0", forwardCIDR: "10.64.0.0/24"}
	assign := tun.Assignment{V4: mustAddr(t, "10.64.0.1")}
	if _, err := validateForwardMode(opts, assign); err == nil || !strings.Contains(err.Error(), "-peer-registry") {
		t.Fatalf("missing peer registry error = %v", err)
	}
}

func TestIPv4SourceDestinationRejectsABadIHL(t *testing.T) {
	pkt := ipv4Packet(t, "10.64.0.2", "8.8.8.8")
	pkt[0] = 0x44 // IHL 4 words = 16 bytes, below the 20-byte minimum
	if _, _, ok := ipv4SourceDestination(pkt); ok {
		t.Fatal("a packet declaring a 16-byte IHL was accepted")
	}
	pkt[0] = 0x4f // IHL 15 words = 60 bytes, longer than the buffer
	if _, _, ok := ipv4SourceDestination(pkt); ok {
		t.Fatal("a packet declaring an IHL past the end of the buffer was accepted")
	}
}

// --- the forward-mode health contract (D11) -----------------------------------
//
// These cover serveStatus.CarriageProven and serveStatus.InnerPacketsDelivered.
// They live here rather than in gateway_test.go because both fields exist only
// to describe -forward, and they run on every OS because the RULE about which
// counter is evidence in which mode is not platform-specific even though the
// forwarding itself is Linux-only.

func TestCarriageProvenIsModeAware(t *testing.T) {
	fwd := func(delivered uint64) *gatewayForwardStatus {
		return &gatewayForwardStatus{
			Device: sharedGatewayTunStats{Delivered: delivered},
		}
	}
	cases := []struct {
		name     string
		forward  bool
		carrying int
		promoted int
		fwd      *gatewayForwardStatus
		want     bool
		why      string
	}{
		{
			name: "reflect mode, nothing carrying", want: false,
			why: "no session, no claim",
		},
		{
			name:     "reflect mode, gate open but nothing delivered",
			carrying: 2, promoted: 0, want: false,
			why: "a gate that opened over an empty tunnel is the exact state " +
				"Promoted exists to refuse; CarriageProven must refuse it too",
		},
		{
			name: "reflect mode, promoted", carrying: 2, promoted: 1, want: true,
			why: "gate carrying AND RxPackets > 0 is the reflector's proof",
		},
		{
			name:    "forward mode, the measured healthy gateway",
			forward: true, carrying: 2, promoted: 0, fwd: fwd(8), want: true,
			why: "carrying 2 / promoted 0 with real deliveries is the 2026-08-12 " +
				"measurement that this whole field exists for; reporting it dead " +
				"is the bug",
		},
		{
			name:    "forward mode, interface up but no reply ever returned",
			forward: true, carrying: 2, promoted: 0, fwd: fwd(0), want: false,
			why: "a shared device that has delivered nothing is not carriage, " +
				"however many sessions think they are carrying",
		},
		{
			name:    "forward mode, deliveries but no live session",
			forward: true, carrying: 0, promoted: 0, fwd: fwd(8), want: false,
			why: "Delivered alone says a packet reached SOME session; the " +
				"conjunction is what says one is open",
		},
		{
			name:    "forward mode with the forward evidence missing",
			forward: true, carrying: 2, promoted: 1, fwd: nil, want: false,
			why: "fail closed: a forward-mode document that lost its forward " +
				"block must not fall through to the reflector predicate",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := carriageProven(tc.forward, tc.carrying, tc.promoted, tc.fwd)
			if got != tc.want {
				t.Fatalf("carriageProven(forward=%v, carrying=%d, promoted=%d, fwd=%v) = %v, want %v: %s",
					tc.forward, tc.carrying, tc.promoted, tc.fwd, got, tc.want, tc.why)
			}
		})
	}
}

// TestTheStatusDocumentPublishesForwardModeCarriageEvidence is the JSON-shape
// half: the promotion-evidence rulers scan flat counter KEYS by name, so the
// keys, not just the Go fields, are the contract.
func TestTheStatusDocumentPublishesForwardModeCarriageEvidence(t *testing.T) {
	// A FRESH map per document. json.Unmarshal merges into a non-empty map
	// rather than clearing it, so reusing one would let an earlier document's
	// keys satisfy a later document's absence check -- which is precisely the
	// assertion this test makes about reflector mode.
	marshalFlat := func(st serveStatus) (map[string]any, []byte) {
		t.Helper()
		blob, err := json.Marshal(st)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		flat := map[string]any{}
		if err := json.Unmarshal(blob, &flat); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		return flat, blob
	}

	delivered := uint64(8)
	forwardMode := serveStatus{
		Event:                 "posture",
		Carrying:              2,
		Promoted:              0,
		RxPackets:             0,
		RxDeviceWrites:        8,
		InnerPacketsDelivered: &delivered,
		CarriageProven:        true,
		Forward: &gatewayForwardStatus{
			Device: sharedGatewayTunStats{Reads: 8, Delivered: 8},
		},
	}
	flat, blob := marshalFlat(forwardMode)
	if got, ok := flat["inner_packets_delivered"]; !ok || got != float64(8) {
		t.Fatalf("inner_packets_delivered = %v (present=%v), want 8. A forward-mode "+
			"posture whose only delivered counter is rx_packets is structurally 0, "+
			"and step 5 of the cross-family verifier reads the gateway file ALONE: "+
			"document is %s", got, ok, blob)
	}
	if got, ok := flat["carriage_proven"]; !ok || got != true {
		t.Fatalf("carriage_proven = %v (present=%v), want true: %s", got, ok, blob)
	}
	if got := flat["promoted"]; got != float64(0) {
		t.Fatalf("promoted = %v, want 0 — this test's premise is that a healthy "+
			"forwarding gateway reports promoted 0", got)
	}

	// A forwarding gateway that has delivered NOTHING must publish an explicit
	// zero rather than dropping the key: delivered_counter_zero is a sharper
	// diagnosis than delivered_counter_absent, and a counter that vanishes when
	// it matters most is how the last several of these were missed.
	zero := uint64(0)
	forwardMode.InnerPacketsDelivered = &zero
	forwardMode.CarriageProven = false
	flat, blob = marshalFlat(forwardMode)
	if got, ok := flat["inner_packets_delivered"]; !ok || got != float64(0) {
		t.Fatalf("a forwarding gateway with zero deliveries dropped the key "+
			"(value=%v present=%v); it must stay visible as 0: %s", got, ok, blob)
	}
	if flat["carriage_proven"] != false {
		t.Fatalf("carriage_proven = %v, want false: %s", flat["carriage_proven"], blob)
	}

	// Reflector mode: the key is ABSENT, so nothing invites a reader to look
	// for a forwarding counter on a gateway that does not forward. rx_packets
	// is the delivered counter there and it is emitted unconditionally.
	reflectMode := serveStatus{Event: "posture", Carrying: 1, Promoted: 1, RxPackets: 50}
	flat, blob = marshalFlat(reflectMode)
	if _, ok := flat["inner_packets_delivered"]; ok {
		t.Fatalf("a reflector-mode posture published inner_packets_delivered: %s", blob)
	}
	if _, ok := flat["forward"]; ok {
		t.Fatalf("a reflector-mode posture published a forward block: %s", blob)
	}
	if got, ok := flat["carriage_proven"]; !ok || got != false {
		t.Fatalf("carriage_proven = %v (present=%v); it is emitted unconditionally "+
			"and is false here only because this literal sets no CarriageProven: %s",
			got, ok, blob)
	}
}
