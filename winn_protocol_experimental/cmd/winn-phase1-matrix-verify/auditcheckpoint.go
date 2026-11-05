package main

import (
	"errors"
	"fmt"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
)

// AUDIT-CLOSE: the terminal checkpoint gate.
//
// The HMAC chain in carrier-audit.jsonl proves that no record was inserted,
// reordered, mutated, or deleted from the middle. It cannot prove that no
// record was deleted from the END, because a prefix of a valid hash chain is
// itself a valid hash chain. Everything downstream of the trail — the
// conservation law, the forced-abort coverage attestation, the sealed
// conservation snapshot — is arithmetic over however many records happen to be
// present, so a sophisticated truncation that also rewrites those files stays
// self-consistent all the way through.
//
// verifyAuditCheckpoint is what closes that. It requires exactly one
// finalizer-signed checkpoint committing to the trail's length and head, under
// a credential the carrier process that wrote the trail never held, and it
// recomputes every field the checkpoint binds from the files on disk.
//
// It runs BEFORE the conservation law at every acceptance site. That order is
// the point: conservation arithmetic over a truncated trail is arithmetic over
// a lie, and reporting "conservation holds" first would be reporting a true
// statement about the wrong evidence.
const auditCheckpointRequiredMessage = "AUDIT-CLOSE"

// auditCheckpointPin is the auditor-supplied verification input. Every field
// comes from outside the evidence, and that is the whole of its value: a
// checkpoint checked only against the key it carries, the run it names, and the
// producer it claims authenticates nothing but itself. Self-assertion is not
// provenance.
//
// On the formal and anchored paths these are derived from matrix.env's
// matrix_id and from the auditor's own -expected-source-digest, both of which
// the verifier has already bound independently. On the standalone conservation
// report they must be supplied explicitly on the command line, because there is
// no matrix root to derive them from — and a blank value there is a refusal,
// not a relaxation.
type auditCheckpointPin struct {
	finalizerKeyID string
	runID          string
	producerDigest string
}

// withBatchRun returns the pin bound to one batch's own run identity and to the
// auditor's pinned producer digest.
//
// Every batch seals its own evidence directory and therefore closes its own
// audit trail, so every batch has its own checkpoint. Pinning a single
// matrix-wide identity across all of them would let one batch's checkpoint be
// transplanted onto another batch of the same matrix and still pass — the
// transplant defence has to be per-batch to mean anything. The identity is
// composed from values the verifier has already bound independently: the
// matrix_id recorded in matrix.env and the batch key the signed anchor request
// commits to.
func (pin auditCheckpointPin) withBatchRun(
	matrixID, batchKey, producerDigest string,
) auditCheckpointPin {
	pin.runID = batchRunIdentity(matrixID, batchKey)
	pin.producerDigest = producerDigest
	return pin
}

// batchRunIdentity is the one derivation both the runner and the verifier use.
// It returns the empty string for an unusable component so the caller's
// mandatory non-empty check refuses rather than pinning "-".
func batchRunIdentity(matrixID, batchKey string) string {
	if !safeMatrixIdentifier.MatchString(matrixID) ||
		!safeMatrixIdentifier.MatchString(batchKey) {
		return ""
	}
	return matrixID + "-" + batchKey
}

// verifyAuditCheckpoint gates one sealed evidence directory on its terminal
// checkpoint.
//
// The pin is mandatory. An unpinned mode would be the "optional add-on" this
// gate exists to not be: evidence that simply omitted the checkpoint, or
// carried one signed by a key the adversary generated, would pass. So an empty
// pin is a refusal naming the blocker rather than a silent skip.
func verifyAuditCheckpoint(
	evidenceDirectory string,
	pin auditCheckpointPin,
) (auditcheckpoint.Checkpoint, error) {
	if evidenceDirectory == "" {
		return auditcheckpoint.Checkpoint{}, errors.New(
			"audit checkpoint verification requires an evidence directory",
		)
	}
	if pin.finalizerKeyID == "" {
		return auditcheckpoint.Checkpoint{}, fmt.Errorf(
			"%s: no audit checkpoint finalizer key is pinned. Pass "+
				"-audit-finalizer-key-id with the runner's published finalizer "+
				"identity; evidence whose close record is verified only against "+
				"the key it carries is not closed at all",
			auditCheckpointRequiredMessage,
		)
	}
	// A blank run identity or producer digest would mean accepting the
	// checkpoint's own claims about which run it closed and which source
	// produced it. That is circular, and it is exactly what makes a cross-run
	// transplant work: a genuine checkpoint from run A, attached to run B's
	// evidence, is only caught because the auditor already knows independently
	// which run this is.
	if pin.runID == "" {
		return auditcheckpoint.Checkpoint{}, fmt.Errorf(
			"%s: no run identity is pinned. Pass -audit-run-id (or verify a "+
				"matrix root, whose matrix.env supplies it); a checkpoint that "+
				"vouches for whatever run it names cannot detect a transplant",
			auditCheckpointRequiredMessage,
		)
	}
	if pin.producerDigest == "" {
		return auditcheckpoint.Checkpoint{}, fmt.Errorf(
			"%s: no producer digest is pinned. Pass -audit-producer-digest "+
				"(or verify a matrix root, whose expected source digest "+
				"supplies it); a checkpoint that vouches for whatever producer "+
				"it names binds no source tree at all",
			auditCheckpointRequiredMessage,
		)
	}
	checkpoint, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
		EvidenceDirectory:      evidenceDirectory,
		ExpectedFinalizerKeyID: pin.finalizerKeyID,
		ExpectedRunID:          pin.runID,
		ExpectedProducerDigest: pin.producerDigest,
		AuditLogName:           carrierAuditFileName,
	})
	if err != nil {
		return auditcheckpoint.Checkpoint{}, fmt.Errorf(
			"%s: %w", auditCheckpointRequiredMessage, err,
		)
	}
	return checkpoint, nil
}
