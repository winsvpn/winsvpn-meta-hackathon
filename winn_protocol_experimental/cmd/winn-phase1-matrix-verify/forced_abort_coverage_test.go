// Tests for the forced-abort coverage requirement that -carrier-conservation-report
// applies on top of the promotional conservation law.
//
// The distinction these lock in is the whole point of the check. A completed
// production matrix has no reason to abort at all, so "every closed abort
// reason appears exactly once per carrier" is not a property promotional
// evidence should be forced to have — verifyCarrierConservation therefore
// checks enum membership and nothing more, and must keep doing exactly that.
// A forced-abort smoke, on the other hand, exists solely to make that stronger
// claim, and until this check existed the claim rested only on the smoke
// binary's own exit status: MATRIX_VERIFY_CARRIER_CONSERVATION_OK asserted less
// than a reader would reasonably take it to mean.
//
// The padded fixture below is the proof. Its counts balance perfectly, its
// reasons are all inside the closed enum, its HMAC chain and evidence manifest
// are self-consistent — so the promotional verifier accepts it, exactly as it
// should — and yet four of the five abort reasons were never exercised.
package main

import (
	"fmt"
	"strings"
	"testing"
)

// forcedAbortFixture is one balanced sealed run in the shape the conservation
// smoke produces: an H3 auth-only request, one open/closed pair per carrier,
// and one abort per carrier per closed abort reason.
func forcedAbortFixture(h3Reasons, h2Reasons []string) conservationFixture {
	events := []carrierAuditEvent{
		authenticated("fa-h3-auth-only"), authOnly("fa-h3-auth-only"),
		authenticated("fa-h3-relay"), opened("fa-h3-relay"),
		h2Event(authenticated("fa-h2-relay")), h2Event(opened("fa-h2-relay")),
	}
	for index, reason := range h3Reasons {
		label := "fa-h3-abort-" + string(rune('a'+index))
		events = append(
			events, authenticated(label), aborted(label, reason),
		)
	}
	for index, reason := range h2Reasons {
		label := "fa-h2-abort-" + string(rune('a'+index))
		events = append(
			events,
			h2Event(authenticated(label)),
			h2Event(aborted(label, reason)),
		)
	}
	events = append(
		events, closed("fa-h3-relay"), h2Event(closed("fa-h2-relay")),
	)
	// Three clean requests plus one per abort, so every fixture below is an
	// honest ledger and the only thing that can reject it is the forced-abort
	// coverage requirement itself.
	return conservationFixture{
		events: events,
		redemptionCount: fmt.Sprintf(
			"%d\n", 3+len(h3Reasons)+len(h2Reasons),
		),
	}
}

func allAbortReasons() []string {
	return []string{
		abortReasonRateLimited,
		abortReasonBackendDown,
		abortReasonInvalidMTU,
		abortReasonResponseSigning,
		abortReasonAuditUnavailable,
	}
}

func auditTrail(directory string) string {
	return directory + "/" + carrierAuditFileName
}

func TestForcedAbortCoverageAcceptsOneOfEachPerCarrier(t *testing.T) {
	directory, pin := sealConservationEvidenceClosed(
		t, forcedAbortFixture(allAbortReasons(), allAbortReasons()),
	)
	if err := conservationVerdict(t, directory); err != nil {
		t.Fatalf("the positive-control fixture must verify cleanly: %v", err)
	}
	observed, err := requireForcedAbortCoverage(auditTrail(directory))
	if err != nil {
		t.Fatalf("a fully forced run was rejected: %v", err)
	}
	for _, family := range []carrierFamily{carrierFamilyH3, carrierFamilyH2} {
		for _, reason := range allAbortReasons() {
			if observed[family][reason] != 1 {
				t.Fatalf(
					"%s recomputed %s=%d, want exactly 1 (%s)",
					family, reason, observed[family][reason],
					formatAbortReasonMultiset(observed[family]),
				)
			}
		}
	}
	if err := reportCarrierConservation(directory, pin); err != nil {
		t.Fatalf("the report mode rejected a fully forced run: %v", err)
	}
}

// TestForcedAbortCoverageRejectsPaddedReasons is the regression Codex named:
// five aborts on H3, all carrying the same valid reason. Every count balances
// and every reason is a member of the closed enum, so the promotional path
// accepts it — which this test asserts, because that behaviour must not change
// — and only the report-mode requirement can see that four reasons were never
// exercised at all.
func TestForcedAbortCoverageRejectsPaddedReasons(t *testing.T) {
	padded := []string{
		abortReasonRateLimited,
		abortReasonRateLimited,
		abortReasonRateLimited,
		abortReasonRateLimited,
		abortReasonRateLimited,
	}
	directory, pin := sealConservationEvidenceClosed(
		t, forcedAbortFixture(padded, allAbortReasons()),
	)

	if err := conservationVerdict(t, directory); err != nil {
		t.Fatalf(
			"the promotional conservation law must still accept a balanced "+
				"ledger whose reasons are all inside the closed enum; this "+
				"check must not be tightened for real matrices, got: %v",
			err,
		)
	}

	_, err := requireForcedAbortCoverage(auditTrail(directory))
	if err == nil {
		t.Fatal(
			"five copies of one abort reason were accepted as full forced " +
				"coverage; the report mode's attestation means nothing",
		)
	}
	if !strings.Contains(err.Error(), "exactly once") ||
		!strings.Contains(err.Error(), "h3") {
		t.Fatalf("unhelpful rejection: %v", err)
	}
	if reportCarrierConservation(directory, pin) == nil {
		t.Fatal("the report mode accepted padded abort reasons")
	}
}

func TestForcedAbortCoverageRejectsAMissingCarrier(t *testing.T) {
	// H2 authenticated and terminalized every request honestly, but never
	// aborted at all: conservation holds, forced coverage does not.
	directory := sealConservationEvidence(
		t, forcedAbortFixture(allAbortReasons(), nil),
	)
	if err := conservationVerdict(t, directory); err != nil {
		t.Fatalf(
			"a carrier that simply never aborted is a perfectly conserving "+
				"ledger and the promotional path must accept it: %v", err,
		)
	}
	_, err := requireForcedAbortCoverage(auditTrail(directory))
	if err == nil {
		t.Fatal("a carrier that never aborted passed forced abort coverage")
	}
	if !strings.Contains(err.Error(), "h2") {
		t.Fatalf("rejection did not name the carrier at fault: %v", err)
	}
}

func TestForcedAbortCoverageRejectsADuplicatedReason(t *testing.T) {
	// Four distinct reasons plus a second copy of one of them: the aborted
	// count is still five, so nothing count-based can see the substitution.
	duplicated := []string{
		abortReasonRateLimited,
		abortReasonBackendDown,
		abortReasonInvalidMTU,
		abortReasonResponseSigning,
		abortReasonRateLimited,
	}
	directory := sealConservationEvidence(
		t, forcedAbortFixture(duplicated, allAbortReasons()),
	)
	if err := conservationVerdict(t, directory); err != nil {
		t.Fatalf("the promotional path must still accept this: %v", err)
	}
	_, err := requireForcedAbortCoverage(auditTrail(directory))
	if err == nil {
		t.Fatal("a duplicated abort reason passed forced abort coverage")
	}
	if !strings.Contains(err.Error(), "2 times") &&
		!strings.Contains(err.Error(), "0 times") {
		t.Fatalf("unhelpful rejection: %v", err)
	}
}
