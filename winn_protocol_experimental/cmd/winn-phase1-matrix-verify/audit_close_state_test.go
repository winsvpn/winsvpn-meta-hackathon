// The AUDIT-CLOSE state machine, asserted as a negative.
//
// Producer-side success is not evidence of a closed trail. A batch sealed on
// AICORE has a final audit log, a sealed base manifest, a PASS result, and a
// conservation law that reconciles exactly — and none of that can detect a tail
// truncation, because the HMAC chain cannot and the arithmetic is over whatever
// records survive. The terminal checkpoint is created later, on the controller,
// with a credential the producing host never held.
//
// These tests prove there is no path where producer-side success alone makes
// evidence look ready for promotion.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
)

// producerSideEvidence is the exact state AICORE hands over: everything the
// producer can legitimately produce, and nothing it cannot.
func producerSideEvidence(t *testing.T) string {
	t.Helper()
	directory := sealConservationEvidence(t, forcedAbortFixture(
		allAbortReasons(), allAbortReasons(),
	))
	if _, err := os.Lstat(
		filepath.Join(directory, auditcheckpoint.FileName),
	); err == nil {
		t.Fatal(
			"the producer-side fixture already carries a checkpoint; it is " +
				"then not the state under test",
		)
	}
	return directory
}

// TestProducerSideSuccessIsNotPromotable is the state-machine assertion.
//
// The fixture passes every check the producing host can run — the manifest
// verifies, the conservation law reconciles, the forced-abort coverage is
// complete — and is still refused, by name, for the one thing the producer
// cannot do.
func TestProducerSideSuccessIsNotPromotable(t *testing.T) {
	directory := producerSideEvidence(t)

	// Producer-side checks: all green.
	if err := verifyEvidenceManifest(directory); err != nil {
		t.Fatalf("the producer's own manifest must verify: %v", err)
	}
	if err := verifyCarrierConservation(directory); err != nil {
		t.Fatalf("the producer's own conservation law must reconcile: %v", err)
	}
	if _, err := requireForcedAbortCoverage(
		filepath.Join(directory, carrierAuditFileName),
	); err != nil {
		t.Fatalf("the producer's own abort coverage must be complete: %v", err)
	}

	// And acceptance still refuses, because none of the above can see a tail
	// that was cut off.
	closed := closeConservationEvidence(t, directory, conservationFixtureRunID)
	if err := os.Remove(
		filepath.Join(directory, auditcheckpoint.FileName),
	); err != nil {
		t.Fatal(err)
	}
	err := reportCarrierConservation(directory, closed)
	if err == nil {
		t.Fatal(
			"evidence that never went through the controller's checkpoint step " +
				"was accepted; producer-side success alone would then be enough " +
				"to promote a truncated trail",
		)
	}
	if !strings.Contains(err.Error(), auditCheckpointRequiredMessage) ||
		!strings.Contains(err.Error(), "audit checkpoint is missing") {
		t.Fatalf(
			"pre-checkpoint evidence was refused for the wrong reason: %v", err,
		)
	}
}

// TestUnpinnedAcceptanceIsRefused covers the other way producer-side evidence
// could slip through: an operator who runs the real verifier but supplies none
// of the external bindings. Every one of the three is a refusal naming the
// blocker, not a relaxation.
func TestUnpinnedAcceptanceIsRefused(t *testing.T) {
	directory, pin := sealConservationEvidenceClosed(t, forcedAbortFixture(
		allAbortReasons(), allAbortReasons(),
	))
	if err := reportCarrierConservation(directory, pin); err != nil {
		t.Fatalf("the positive control must pass: %v", err)
	}
	for name, degraded := range map[string]auditCheckpointPin{
		"no_finalizer_pin": {
			runID: pin.runID, producerDigest: pin.producerDigest,
		},
		"no_run_identity": {
			finalizerKeyID: pin.finalizerKeyID,
			producerDigest: pin.producerDigest,
		},
		"no_producer_digest": {
			finalizerKeyID: pin.finalizerKeyID, runID: pin.runID,
		},
		"nothing_pinned": {},
	} {
		t.Run(name, func(t *testing.T) {
			err := reportCarrierConservation(directory, degraded)
			if err == nil {
				t.Fatal("acceptance ran with an incomplete external binding")
			}
			if !strings.Contains(err.Error(), auditCheckpointRequiredMessage) {
				t.Fatalf("refusal did not name the blocker: %v", err)
			}
		})
	}
}

// TestBatchRunIdentityIsDerivedPerBatch pins the composition the verifier and
// the controller must agree on. A single matrix-wide identity would let one
// batch's checkpoint be transplanted onto another batch of the same matrix.
func TestBatchRunIdentityIsDerivedPerBatch(t *testing.T) {
	first := batchRunIdentity("phase1-auto-v1", "b0001-edge-warm")
	second := batchRunIdentity("phase1-auto-v1", "b0002-edge-cold")
	if first == "" || second == "" {
		t.Fatalf("safe identifiers produced no run identity: %q %q", first, second)
	}
	if first == second {
		t.Fatal(
			"two batches of one matrix share a run identity; a checkpoint " +
				"could be moved between them undetected",
		)
	}
	if first != "phase1-auto-v1-b0001-edge-warm" {
		t.Fatalf("unexpected run identity %q", first)
	}
	for _, unsafe := range [][2]string{
		{"", "b0001"},
		{"phase1/auto", "b0001"},
		{"phase1-auto-v1", "b 0001"},
		{"phase1-auto-v1", ""},
	} {
		if identity := batchRunIdentity(unsafe[0], unsafe[1]); identity != "" {
			t.Fatalf(
				"unsafe components %q/%q produced run identity %q",
				unsafe[0], unsafe[1], identity,
			)
		}
	}
}
