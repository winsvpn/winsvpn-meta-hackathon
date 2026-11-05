package main

import (
	"net/netip"
	"testing"
	"time"
)

// The meter must spend the per-source burst, then refuse that source while
// other sources still pass, and refill with time. Times are injected, so
// the test never sleeps.
func TestAdmissionMeterPerSourceBurstAndRefill(t *testing.T) {
	m := newAdmissionMeter()
	src := netip.MustParseAddrPort("203.0.113.7:4000")
	now := time.Unix(1700000000, 0)
	for i := 0; i < admissionSourceBurst; i++ {
		if !m.allow(src, now) {
			t.Fatalf("screen %d within the source burst refused", i)
		}
	}
	if m.allow(src, now) {
		t.Fatal("screen past the source burst allowed")
	}
	other := netip.MustParseAddrPort("203.0.113.7:4001")
	if !m.allow(other, now) {
		t.Fatal("a second source port was refused by the first source's spent cell")
	}
	if !m.allow(src, now.Add(time.Second)) {
		t.Fatal("source cell did not refill after one second")
	}
}

// The global bucket is the CPU bound whatever the sources are: after the
// burst, fresh sources are refused too.
func TestAdmissionMeterGlobalBurstBoundsFreshSources(t *testing.T) {
	m := newAdmissionMeter()
	now := time.Unix(1700000000, 0)
	for i := 0; i < admissionBurst; i++ {
		src := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 5000)
		if !m.allow(src, now) {
			t.Fatalf("screen %d within the global burst refused", i)
		}
	}
	fresh := netip.MustParseAddrPort("192.0.2.1:5000")
	if m.allow(fresh, now) {
		t.Fatal("fresh source allowed past the global burst")
	}
	if !m.allow(fresh, now.Add(time.Second)) {
		t.Fatal("global bucket did not refill after one second")
	}
}

// A nil meter allows everything: servers assembled by tests keep the
// unmetered behaviour, and only runServe installs the budget.
func TestAdmissionMeterNilAllows(t *testing.T) {
	var m *admissionMeter
	if !m.allow(netip.MustParseAddrPort("192.0.2.1:5000"), time.Now()) {
		t.Fatal("nil meter refused")
	}
}

// One source that is over its own cell must not spend the global budget
// every other new client needs: only the screens its cell allowed may
// come out of the global bucket (audit R1 astra-2).
func TestAdmissionMeterSourceFloodPreservesGlobalBudget(t *testing.T) {
	m := newAdmissionMeter()
	now := time.Unix(1700000000, 0)
	flood := netip.MustParseAddrPort("203.0.113.7:4000")
	admitted := 0
	for i := 0; i < admissionBurst; i++ {
		if m.allow(flood, now) {
			admitted++
		}
	}
	if admitted != admissionSourceBurst {
		t.Fatalf("source admitted %d, want %d", admitted, admissionSourceBurst)
	}
	if want := float64(admissionBurst - admissionSourceBurst); m.global.toks != want {
		t.Fatalf("source-refused packets spent global tokens: got %.0f, want %.0f", m.global.toks, want)
	}
	// Another source port lands in another cell unless the per-process
	// hash collides with the flood's; one of these must be admitted.
	for port := uint16(4001); port < 5000; port++ {
		if m.allow(netip.AddrPortFrom(flood.Addr(), port), now) {
			return
		}
	}
	t.Fatal("no other source admitted after one source's refused flood")
}
