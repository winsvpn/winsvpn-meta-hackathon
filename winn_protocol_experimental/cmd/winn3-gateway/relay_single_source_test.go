package main

import (
	"hash/maphash"
	"net/netip"
	"testing"
	"time"
)

// Ciphertext relay Double VPN (packet B). The Core forwards every phone's
// datagrams to one exit through a kernel DNAT plus MASQUERADE, so the exit sees
// ALL relayed phones as ONE source address (the Core's home address, after the
// home router's own NAT) with one distinct source port per phone flow. These
// tests pin the exit-side admission properties that arrangement relies on. They
// run against the real meter this binary installs in runServe and change
// nothing in it: the relay needs no exit code change, and these tests are the
// regression guard that keeps it that way.
//
// What they do NOT claim: they say nothing about the Core's own NAT, conntrack
// timeouts, the home router, or throughput. Those are kernel and network facts
// that no unit test in this package can reach (see scripts/core_relay_netns_e2e.sh).

// relayCoreAddr is a documentation address standing in for the Core's public
// address as the exit sees it.
func relaySource(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 77}), port)
}

// A theoretical 253-flow storm from ONE source address must pass the admission
// meter in one instant. This does not test the configured session ceiling or
// free addresses in the fleet-wide /24 inner pool. The per-source cell is keyed
// on address AND port (admission_meter.go), so one shared address is not one
// shared cell, and 253 screens are far inside the gateway-wide burst of 2000.
func TestRelaySingleSourceReconnectStormIsAdmitted(t *testing.T) {
	m := newAdmissionMeter()
	now := time.Unix(1700000000, 0)
	const phones = 253
	for i := 0; i < phones; i++ {
		if !m.allow(relaySource(uint16(20000+i)), now) {
			t.Fatalf("phone %d of %d behind one relay address was refused at its first handshake", i, phones)
		}
	}
	// The storm spent one global token per phone and no more.
	if want := float64(admissionBurst - phones); m.global.toks != want {
		t.Fatalf("global tokens after the storm = %.0f, want %.0f", m.global.toks, want)
	}
}

// Each phone's own retransmit budget (its source cell burst) is independent of
// every other phone behind the same address: one phone spending its whole burst
// leaves every other port of that address untouched.
func TestRelaySingleSourcePhonesDoNotShareACell(t *testing.T) {
	m := newAdmissionMeter()
	now := time.Unix(1700000000, 0)
	noisy := relaySource(30000)
	for i := 0; i < admissionSourceBurst; i++ {
		if !m.allow(noisy, now) {
			t.Fatalf("screen %d within one flow's burst refused", i)
		}
	}
	if m.allow(noisy, now) {
		t.Fatal("a flow past its own burst was allowed")
	}
	// Probe 64 neighbour ports. Cells are hashed with a per-process seed, so a
	// neighbour that lands in the noisy flow's own cell shares its budget by
	// construction (1 in 4096). Those are skipped by index, so the test never
	// depends on the seed; every other neighbour must pass.
	cellOf := func(src netip.AddrPort) uint64 {
		var key [18]byte
		addr := src.Addr().Unmap().As16()
		copy(key[:16], addr[:])
		key[16] = byte(src.Port() >> 8)
		key[17] = byte(src.Port())
		return maphash.Bytes(m.seed, key[:]) & m.mask
	}
	checked := 0
	for p := uint16(30001); p < 30065; p++ {
		if cellOf(relaySource(p)) == cellOf(noisy) {
			continue
		}
		checked++
		if !m.allow(relaySource(p), now) {
			t.Fatalf("flow port %d behind the same address was refused by another flow's spent cell", p)
		}
	}
	if checked < 60 {
		t.Fatalf("only %d of 64 neighbour flows were checked", checked)
	}
}

// Junk that reaches the exit through the relay is junk from relayed flows. One
// relayed flow flooding the exit is bounded by its own cell, and the screens its
// cell refused never spend the global budget (the astra-2 rule), so the flood
// cannot starve the next phone's handshake.
func TestRelaySingleSourceFloodDoesNotStarveANewPhone(t *testing.T) {
	m := newAdmissionMeter()
	now := time.Unix(1700000000, 0)
	flood := relaySource(40000)
	admitted := 0
	for i := 0; i < 10*admissionBurst; i++ {
		if m.allow(flood, now) {
			admitted++
		}
	}
	if admitted != admissionSourceBurst {
		t.Fatalf("one relayed flow admitted %d screens, want its burst %d", admitted, admissionSourceBurst)
	}
	if !m.allow(relaySource(40001), now) {
		t.Fatal("a new phone behind the same address was refused after one flow's flood")
	}
}

// The relay's own defence in front of the exit is the Core's per-port limit of
// NEW flows (CORE_RELAY_NEW_PER_PORT, default 400 per second, burst 800). That
// number is only sound if it stays well below the exit's gateway-wide screen
// rate: otherwise a flood of distinct junk sources against ONE relay port could
// spend the whole global budget and lock every other phone of that exit out.
// This pins the arithmetic against the constants the binary really uses, so a
// later change to admissionRate fails here and forces the relay default to be
// reviewed.
func TestRelayCorePerPortLimitStaysBelowTheGlobalScreenRate(t *testing.T) {
	const corePerPortRate = 400  // CORE_RELAY_NEW_PER_PORT, new flows per second
	const corePerPortBurst = 800 // CORE_RELAY_NEW_PER_PORT_BURST
	if corePerPortRate*2 > admissionRate {
		t.Fatalf("the Core per-port rate %d is more than half the exit's global screen rate %d",
			corePerPortRate, admissionRate)
	}
	if corePerPortBurst > admissionBurst {
		t.Fatalf("the Core per-port burst %d exceeds the exit's global burst %d", corePerPortBurst, admissionBurst)
	}
}
