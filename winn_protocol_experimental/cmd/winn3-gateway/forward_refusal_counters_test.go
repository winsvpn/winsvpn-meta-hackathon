package main

import (
	"errors"
	"strings"
	"testing"
)

// The forward refusal diagnostics used to fire once per packet. With the
// identifiers gone they are bounded instead: every refusal is counted on the
// shared forwardTable, and each class is described once per session. These
// tests pin both halves, so the change cannot silently turn into "no error
// visibility" (the counter) or back into one journal line per packet (the
// bound).

func TestForwardRefusalsAreCountedAndDescribedOncePerSession(t *testing.T) {
	const inner1, inner2, dest = "10.64.78.2", "10.64.78.3", "198.51.100.80"
	const repeats = 5
	tbl := newForwardTable()
	out := captureStderr(t, func() {
		for session := 0; session < 2; session++ {
			// Each session owns a distinct inner address, so the second session
			// learns rather than colliding.
			own := inner1
			other := inner2
			if session == 1 {
				own, other = inner2, inner1
			}
			dev := newGatewayForwardDevice(&fakeInnerWriter{}, tbl, 1400)
			loop := fakeLoop()
			dev.bind(loop)
			if _, err := dev.WritePacket(ipv4Packet(t, own, dest)); err != nil {
				t.Fatalf("session %d first packet: %v", session, err)
			}
			for i := 0; i < repeats; i++ {
				if _, err := dev.WritePacket(ipv4Packet(t, other, dest)); !errors.Is(err, errGatewayInnerSourceChanged) {
					t.Fatalf("session %d repeat %d: err = %v, want %v", session, i, err, errGatewayInnerSourceChanged)
				}
			}
			tbl.forget(mustAddr(t, own), loop)
		}
	})
	if got := tbl.Stats().SourceChanged; got != 2*repeats {
		t.Fatalf("SourceChanged = %d, want %d: every refusal must stay counted", got, 2*repeats)
	}
	if got := strings.Count(out, "forward source changed"); got != 2 {
		t.Fatalf("source-changed lines = %d, want 2 (one per session); captured:\n%s", got, out)
	}
	// The second session's line carries the running total, so the rate is
	// visible in the journal as well as in status.
	if !strings.Contains(out, "6 since start") {
		t.Fatalf("second session's line does not carry the running total; captured:\n%s", out)
	}
}

func TestForwardRefusalCountersCoverEveryClass(t *testing.T) {
	const inner1, inner2, dest = "10.64.79.2", "10.64.79.3", "198.51.100.81"
	tbl := newForwardTable()
	out := captureStderr(t, func() {
		owner := newGatewayForwardDevice(&fakeInnerWriter{}, tbl, 1400)
		owner.bind(fakeLoop())
		if _, err := owner.WritePacket(ipv4Packet(t, inner1, dest)); err != nil {
			t.Fatalf("owner packet: %v", err)
		}
		claimant := newGatewayForwardDevice(&fakeInnerWriter{}, tbl, 1400)
		claimant.bind(fakeLoop())
		for i := 0; i < 3; i++ {
			if _, err := claimant.WritePacket(ipv4Packet(t, inner1, dest)); !errors.Is(err, errGatewayInnerSourceOwned) {
				t.Fatalf("collision %d: err = %v", i, err)
			}
		}
		failing := newGatewayForwardDevice(&fakeInnerWriter{err: errors.New("tun write refused")}, tbl, 1400)
		failing.bind(fakeLoop())
		for i := 0; i < 4; i++ {
			if _, err := failing.WritePacket(ipv4Packet(t, inner2, dest)); err == nil {
				t.Fatalf("failing write %d reported success", i)
			}
		}
	})
	got := tbl.Stats()
	if got.SourceOwned != 3 || got.WriteFailed != 4 || got.SourceChanged != 0 || got.PeerUnauthorized != 0 || got.SourceMismatch != 0 {
		t.Fatalf("refusal counters = %+v, want source_owned 3, write_failed 4", got)
	}
	if got.Collisions != 3 {
		t.Fatalf("Collisions = %d, want 3: SourceOwned is WritePacket's share of it", got.Collisions)
	}
	for want, n := range map[string]int{"forward table.learn failed": 1, "shared.write failed": 1} {
		if c := strings.Count(out, want); c != n {
			t.Fatalf("%q lines = %d, want %d; captured:\n%s", want, c, n, out)
		}
	}
	// OI-U2: the writer's error text is not logged (it is unrestricted and
	// may name addresses); the count and the first sighting are what remain.
	if strings.Contains(out, "tun write refused") {
		t.Fatalf("the writer's error text reached the log; captured:\n%s", out)
	}
}

func TestForwardPeerRefusalIsCountedAndDescribedOncePerSession(t *testing.T) {
	const spoofed, dest = "10.10.0.78", "198.51.100.82"
	f := newAuthorityFixture(t, 0)
	out := captureStderr(t, func() {
		for i := 0; i < 4; i++ {
			if _, err := f.device.WritePacket(ipv4Packet(t, spoofed, dest)); !errors.Is(err, errGatewayInnerSourceMismatch) {
				t.Fatalf("spoofed %d: err = %v", i, err)
			}
		}
	})
	if got := f.table.Stats(); got.SourceMismatch != 4 || got.PeerUnauthorized != 0 {
		t.Fatalf("SourceMismatch = %d, PeerUnauthorized = %d, want 4 and 0", got.SourceMismatch, got.PeerUnauthorized)
	}
	if c := strings.Count(out, "forward validatePeerSource failed"); c != 1 {
		t.Fatalf("validatePeerSource lines = %d, want 1; captured:\n%s", c, out)
	}
}
