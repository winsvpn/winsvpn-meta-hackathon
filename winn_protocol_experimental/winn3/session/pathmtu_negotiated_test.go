package session

// The min-of-both-ends half of silent-refusal instance #3.
//
// NegotiatedPathMTU is the arithmetic the tree's stated remedy — "have the
// client take the minimum" — names. These tests pin the arithmetic itself and
// the guarded return in refusePathMTUMismatch that consumes it, so that a
// change to either half cannot drift from the other without a test naming the
// number that got away.
//
// The requirement this whole file tests is: a session carries ONLY at the
// minimum of the two ends' planning path MTUs, and the driver with no
// interface-reapplication hook must refuse any two-sided difference loudly
// rather than establish the black hole.

import (
	"strings"
	"testing"
)

func TestNegotiatedPathMTUAgreesOnTheMinimum(t *testing.T) {
	// The positive cases. local is this end's planning path MTU, peer is what
	// the responder put on the wire; the negotiated number must be the smaller
	// of the two in every case where both made a claim.
	for _, tc := range []struct {
		name          string
		local, peer   int
		want          int
		wantBothClaim bool
	}{
		{"both claim and agree", 1500, 1500, 1500, true},
		{"the peer is the narrow end", 1500, 1400, 1400, true},
		{"this end is the narrow end", 1400, 1500, 1400, true},
		// These are from the measured regimes of 2026-08-09, so the arithmetic
		// is pinned on the actual defect, not on round numbers someone chose.
		{"narrow mismatch: the black hole", 1500, 1400, 1400, true},
		{"wide mismatch: no session at all", 1500, 1280, 1280, true},
		// And the boundary that a min-of-both-ends helper must get right: the
		// minimum is ≤ both, never strictly above either.
		{"one-byte narrowest", 1280, 1281, 1280, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, both := NegotiatedPathMTU(tc.local, tc.peer)
			if both != tc.wantBothClaim {
				t.Fatalf("bothClaimed = %v, want %v", both, tc.wantBothClaim)
			}
			if got != tc.want {
				t.Fatalf("NegotiatedPathMTU(%d, %d) = %d, want %d", tc.local, tc.peer, got, tc.want)
			}
			// The invariant that makes the number a MINIMUM and not a guess:
			// it never exceeds either end's claim.
			if tc.wantBothClaim && got > tc.local || tc.wantBothClaim && got > tc.peer {
				t.Fatalf("negotiated %d exceeds a claiming end (%d, %d)", got, tc.local, tc.peer)
			}
		})
	}
}

func TestNegotiatedPathMTURequiresBothClaims(t *testing.T) {
	// A peer that made no claim — an old build, or a caller whose PathMTU is
	// zero — is not a party to negotiation. The fallback is the pre-2026-08-09
	// behaviour: use this end's own number and neither refuse nor shrink.
	for _, tc := range []struct {
		name        string
		local, peer int
	}{
		{"this end makes no claim", 0, 1500},
		{"the peer makes no claim", 1500, 0},
		{"neither end makes a claim", 0, 0},
		{"a negative number is no claim", -5, 1500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, both := NegotiatedPathMTU(tc.local, tc.peer)
			if both {
				t.Fatalf("NegotiatedPathMTU(%d, %d) claimed to negotiate", tc.local, tc.peer)
			}
			if got != 0 {
				t.Fatalf("NegotiatedPathMTU(%d, %d) = %d, want 0 to mark no-claim", tc.local, tc.peer, got)
			}
		})
	}
}

// TestRefusePathMTUMismatchIsAGuardedReturnOnTheMinimum.
//
// refusePathMTUMismatch is the initiator's half of instance #3. The point of
// converting it into a guarded return was to make the contract explicit: the
// driver may proceed ONLY when the negotiated minimum differs from NEITHER end.
// Everything else — a two-sided difference in either direction — must refuse
// loudly, because there is no interface-reapplication hook behind it.
//
// We call the method directly on a hand-built Driver rather than driving a full
// session, precisely so a test in this package holds the guard and the
// arithmetic together; the full-session tests already live one layer up.
func TestRefusePathMTUMismatchIsAGuardedReturnOnTheMinimum(t *testing.T) {
	negotiated, both := NegotiatedPathMTU(1500, 1500)
	if negotiated != 1500 {
		t.Fatalf("harness bug: negotiated %d, want 1500", negotiated)
	}
	if !both {
		t.Fatal("harness bug: 1500/1500 should negotiate")
	}
	d := &Driver{cfg: Config{PathMTU: 1500, MaxMessageSize: 1452}}

	// The agreeing pair: the negotiated number equals BOTH ends, so the guard
	// lets the session proceed.
	if err := d.refusePathMTUMismatch(EncodePathMTUNotice(1500)); err != nil {
		t.Fatalf("an agreeing pair was refused: %v", err)
	}

	// The measured narrow regime: peer at 1400 against this end's 1500. This is
	// the BLACK HOLE: before the check, it established and killed full-size
	// packets silently. The guarded return must refuse it, and name the number
	// (the minimum) that a session would have needed.
	err := d.refusePathMTUMismatch(EncodePathMTUNotice(1400))
	if err == nil {
		t.Fatal("the narrow mismatch was not refused: the black hole is open")
	}
	if got, want := err.Error(), "1400"; !strings.Contains(got, want) {
		t.Errorf("the refusal does not name the peer's plan %s:\n%s", want, got)
	}
	if got, want := err.Error(), "1452"; !strings.Contains(got, want) {
		t.Errorf("the refusal does not name this end's message budget %s:\n%s", want, got)
	}

	// The measured wide regime: peer at 1280. Also refused, and the refusal must
	// be built on the minimum (1280).
	err = d.refusePathMTUMismatch(EncodePathMTUNotice(1280))
	if err == nil {
		t.Fatal("the wide mismatch was not refused")
	}
	if got, want := err.Error(), "1280"; !strings.Contains(got, want) {
		t.Errorf("the wide refusal does not name the minimum %s:\n%s", want, got)
	}

	// The reverse narrow case — this end is the NARROW one at a peer of 1500.
	// The negotiated minimum equals this end's own number, but the PEER - the
	// wide end - would still send full-size messages this end refuses. There is
	// no hook to make the peer shrink, so this must also refuse, or the black
	// hole re-appears one packet later in the opposite direction.
	d2 := &Driver{cfg: Config{PathMTU: 1280, MaxMessageSize: 1232}}
	if err := d2.refusePathMTUMismatch(EncodePathMTUNotice(1500)); err == nil {
		t.Fatal("the reverse narrow case was not refused - the wide peer can over-send")
	}

	// Compatibility floor: a peer that sends NO payload predates the notice and
	// must behave exactly as it always did.
	if err := d.refusePathMTUMismatch(nil); err != nil {
		t.Fatalf("a peer with no payload was refused: %v", err)
	}
	// And a peer that sends a payload that is not a notice at all.
	if err := d.refusePathMTUMismatch([]byte("W3PM")); err != nil {
		t.Fatalf("a foreign payload was refused: %v", err)
	}
}
