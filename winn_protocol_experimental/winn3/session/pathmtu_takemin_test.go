package session

// The take-the-minimum half of silent-refusal instance #3, pinned at the
// driver rather than at the helper.
//
// NegotiatedPathMTU has exactly two branches — the peer is the narrow end, or
// this end is — and Driver.refusePathMTUMismatch has to reason about the same
// number in both. These tests prove the minimum the driver TOOK
// (Driver.pathMTUAgreed) matches both branches: the peer's claim in the
// peer-narrow branch, this end's own claim in the local-narrow branch, and the
// common number when they agree — and that the guarded return proceeds exactly
// when both ends are already at that number.

import (
	"strings"
	"testing"
)

func newMTUCfg(local int) *Driver {
	return &Driver{cfg: Config{
		PathMTU:        local,
		MaxMessageSize: MaxMessageSizeForPath(local, CarrierOverheadUDPIPv6),
	}}
}

// TestTheDriverTakesTheMinimumBothEndsClaim proves min selection matches both
// branches of the helper in the driver that consumes it. For every pair of
// planning numbers, the number the driver records must be the smaller of the
// two, and the guarded return must proceed exactly when the two numbers are
// equal.
func TestTheDriverTakesTheMinimumBothEndsClaim(t *testing.T) {
	for _, tc := range []struct {
		name        string
		local, peer int
		wantTaken   int
		wantProceed bool
	}{
		{"agree at 1500", 1500, 1500, 1500, true},
		{"agree at 1280", 1280, 1280, 1280, true},
		{"peer is the narrow end", 1500, 1400, 1400, false},
		{"this end is the narrow end", 1280, 1500, 1280, false},
		{"peer is one byte narrower", 1500, 1499, 1499, false},
		{"this end is one byte narrower", 1499, 1500, 1499, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newMTUCfg(tc.local)
			err := d.refusePathMTUMismatch(EncodePathMTUNotice(tc.peer))
			if d.pathMTUAgreed != tc.wantTaken {
				t.Fatalf("the driver took %d; the minimum of %d and %d is %d",
					d.pathMTUAgreed, tc.local, tc.peer, tc.wantTaken)
			}
			if tc.wantProceed && err != nil {
				t.Fatalf("an agreeing pair at %d was refused: %v", tc.local, err)
			}
			if !tc.wantProceed && err == nil {
				t.Fatal("a two-sided difference proceeded: the black hole is open")
			}
		})
	}
}

// TestTheTakenMinimumNamesThisEndWhenItIsTheNarrowEnd is the local-narrow
// branch of the error text. The guarded-return test already asserts the PEER's
// number appears when the peer is narrow; this is the same assertion for the
// other branch, where the minimum taken is THIS end's claim — 1280 — not the
// peer's 1500.
func TestTheTakenMinimumNamesThisEndWhenItIsTheNarrowEnd(t *testing.T) {
	d := newMTUCfg(1280)
	err := d.refusePathMTUMismatch(EncodePathMTUNotice(1500))
	if err == nil {
		t.Fatal("a wide peer was not refused: it can over-send full-size messages")
	}
	if d.pathMTUAgreed != 1280 {
		t.Fatalf("the driver took %d, want 1280 (this end is the narrow end)", d.pathMTUAgreed)
	}
	if got, want := err.Error(), "1280"; !strings.Contains(got, want) {
		t.Errorf("the refusal does not name the taken minimum %s:\n%s", want, got)
	}
}

// TestNoClaimLeavesNoMinimumTaken is the negative shape for the same field. A
// peer that predates the notice, or a payload that is not a notice at all, is
// "no claim": there is nothing to take the minimum of, so the driver must
// proceed exactly as it always did and record no agreement.
func TestNoClaimLeavesNoMinimumTaken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"a peer that sends no payload", nil},
		{"a foreign payload", []byte("W3PM")},
		// Unknown version is no-claim by design (DecodePathMTUNotice): an
		// over-firing refusal is a worse outage than the original defect.
		// Named here so a later change from fail-open-to-no-claim cannot
		// happen without this test going red.
		{"an unknown version of the notice", func() []byte {
			p := EncodePathMTUNotice(1400)
			p[4] = pathMTUNoticeVersion + 1
			return p
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newMTUCfg(1500)
			if err := d.refusePathMTUMismatch(tc.payload); err != nil {
				t.Fatalf("%s was refused: %v", tc.name, err)
			}
			if d.pathMTUAgreed != 0 {
				t.Fatalf("%s left a minimum of %d recorded; want 0 for no claim",
					tc.name, d.pathMTUAgreed)
			}
		})
	}
}
