// Package auditcheckpoint implements winn-audit-checkpoint/v1: the terminal
// record that closes a sealed audit trail.
//
// WHY THIS EXISTS.
//
// internal/audit chains every record into the next through
// previous_mac = HMAC(key, previous record). That detects insertion,
// reordering, deletion from the middle, and mutation of any record — but it
// cannot detect truncation at the tail, because a prefix of a valid hash chain
// is itself a valid hash chain. An adversary who deletes the last k records
// leaves behind a trail that verifies perfectly and simply claims fewer things
// happened. The 2026-07-26 forced-abort conservation gate caught exactly that
// only because the separate conservation arithmetic happened to notice; nothing
// in the chain verification itself did.
//
// The checkpoint closes that hole by committing, once, to how long the chain
// is and what its head is, under a credential the chain's own writer does not
// hold.
//
// ROLE SEPARATION — the whole point of the design.
//
// The party that can write ordinary audit records is precisely the party the
// checkpoint exists to constrain. A close key derived from the audit writer's
// own HMAC key (for example HKDF(audit_key, "close")) therefore proves nothing:
// anyone able to forge chain records can derive the same subkey and forge the
// close record too. Domain separation is not custody separation.
//
// This package therefore uses a genuinely independent finalizer credential: an
// ML-DSA-65 keypair (internal/pqauth), generated separately from the audit
// HMAC key, held only by the runner/deployer role, and never handed to the
// process that writes audit records during a run. The signature is asymmetric,
// so verification needs no secret at all: an auditor needs only the pinned
// public key identity.
//
// This package deliberately does not import internal/audit. The record shape is
// restated here — the same rule cmd/winn-phase1-matrix-verify applies to the
// carrier trail — so that a change to the writer's encoding cannot silently
// become a change to the finalizer's expectation, and so that a binary that
// writes audit records does not link the finalizer code at all.
//
// WHY THE CHECKPOINT IS A SIDECAR FILE.
//
// The checkpoint binds the audit log's own SHA-256, so it cannot live inside
// the audit log. It binds the evidence manifest's own SHA-256, so the manifest
// must not cover it: a manifest that hashed the checkpoint that hashed the
// manifest is a digest cycle neither party could ever satisfy. It is therefore
// a separate file next to the evidence, excluded from the base manifest by
// construction and by an explicit check here. Its own signature is what
// protects it; an outer archive/anchor step (internal/phase1anchor) is what
// later commits to the manifest and the checkpoint together.
package auditcheckpoint

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	// Schema is the checkpoint's own schema token. Evidence carrying any other
	// value is rejected rather than interpreted.
	Schema = "winn-audit-checkpoint/v1"

	// FileName is the one name a checkpoint may have inside an evidence
	// directory. A fixed name is what makes "exactly one checkpoint" a
	// decidable question.
	FileName = "audit-checkpoint.json"

	// checkpointNameMarker is the substring every checkpoint-like filename must
	// contain. Duplicate detection scans for it rather than for FileName alone,
	// so a second checkpoint smuggled in under audit-checkpoint.json.bak or
	// audit-checkpoint-2.json is caught as an ambiguity instead of ignored.
	checkpointNameMarker = "audit-checkpoint"

	// FinalizerAlgorithm is the only accepted finalizer signature algorithm.
	// Pinning it here (rather than trusting the algorithm the checkpoint
	// declares) means a checkpoint cannot select a weaker scheme for itself.
	FinalizerAlgorithm = pqauth.MLDSA65

	// EnvironmentName is the sealed key/value file the producer digest is
	// independently recomputed from. It is manifest-covered evidence, so the
	// value read back here is not the checkpoint's own claim about itself.
	EnvironmentName = "environment.txt"

	// auditRecordFormat mirrors internal/audit's logFormat. Restated, not
	// imported: see the package comment.
	auditRecordFormat = "winn-audit-hmac-sha256/v1"

	zeroMAC = "0000000000000000000000000000000000000000000000000000000000000000"

	maximumAuditBytes   = 512 << 20
	maximumAuditLine    = 64 << 10
	maximumAuditRecords = 4_000_000
	maximumManifestSize = 4 << 20
	maximumCheckpoint   = 64 << 10
)

// safeIdentifier mirrors phase1anchor's safeID and the matrix verifier's
// safeMatrixIdentifier. Every signed component is forced through a charset that
// contains neither '=' nor '\n', so the canonical signing message below cannot
// be made ambiguous by a crafted field value.
var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// safeRunIdentifier is the same charset with a longer bound, because a run
// identity is composed (matrix id plus batch key) and would otherwise be
// length-limited by its shortest component's budget.
var safeRunIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}$`)

// producerDigestKeys are the environment.txt keys that may carry this run's
// producer/source digest, in no particular order. Every key that is present
// must agree with the checkpoint; at least one must be present.
var producerDigestKeys = []string{"source_digest", "smoke_source_digest"}

// Checkpoint is the on-disk winn-audit-checkpoint/v1 document.
//
// Every field except Signature is covered by Signature. AuditLogName and
// ManifestName are signed too, so a checkpoint cannot be relocated to vouch for
// a different pair of files inside the same directory.
type Checkpoint struct {
	Schema                string `json:"schema"`
	RunID                 string `json:"run_id"`
	AuditLogName          string `json:"audit_log_name"`
	FinalSequence         uint64 `json:"final_sequence"`
	RecordCount           uint64 `json:"record_count"`
	ChainHeadMAC          string `json:"chain_head_mac"`
	AuditLogSHA256        string `json:"audit_log_sha256"`
	ManifestName          string `json:"evidence_manifest_name"`
	ManifestSHA256        string `json:"evidence_manifest_sha256"`
	ProducerDigest        string `json:"producer_digest"`
	ClosedAtUTC           string `json:"closed_at_utc"`
	FinalizerAlgorithm    string `json:"finalizer_algorithm"`
	FinalizerKeyID        string `json:"finalizer_key_id"`
	FinalizerPublicKeyB64 string `json:"finalizer_public_key"`
	SignatureB64          string `json:"signature"`
}

// Chain is what an offline reader can recompute from an audit log without ever
// holding the audit HMAC key: how many records there are, where the sequence
// ended, what the head MAC is, and when the last record was written.
type Chain struct {
	RecordCount   uint64
	FinalSequence uint64
	HeadMAC       string
	FinalUTC      time.Time
}

// auditRecord is internal/audit's on-disk record, restated. Decoded with
// DisallowUnknownFields, so an added field is a rejection rather than a
// silently ignored annotation.
type auditRecord struct {
	Format         string `json:"format"`
	Sequence       uint64 `json:"sequence"`
	Timestamp      string `json:"timestamp"`
	Event          string `json:"event"`
	DeviceHash     string `json:"device_hash,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Detail         string `json:"detail,omitempty"`
	PreviousMAC    string `json:"previous_mac"`
	Authentication string `json:"authentication"`
}

// GenerateFinalizerSeed returns a fresh 32-byte finalizer seed. It is generated
// independently of any audit HMAC key and must stay under runner-only custody.
func GenerateFinalizerSeed() ([]byte, error) {
	return pqauth.GenerateSeed()
}

// LoadFinalizer loads the runner-held finalizer signer from a private seed file.
func LoadFinalizer(seedPath string) (*pqauth.Signer, error) {
	return pqauth.LoadSigner(FinalizerAlgorithm, seedPath)
}

// SealInput is everything the finalizer needs. Nothing here is read from the
// evidence's own claims about itself: RunID and ProducerDigest come from the
// runner, and every other bound value is recomputed from the files on disk.
type SealInput struct {
	EvidenceDirectory string
	// AuditLogName and ManifestName are basenames inside EvidenceDirectory.
	// Empty ManifestName means the conventional evidence-manifest.sha256.
	AuditLogName string
	ManifestName string
	RunID        string
	// ProducerDigest is REQUIRED and comes from the runner, not from the
	// evidence. There is deliberately no environment-derived fallback: a
	// checkpoint whose producer binding was read out of a file inside the same
	// directory it is closing would attest only that the directory agrees with
	// itself. Seal reads environment.txt as well and requires the two to
	// AGREE — neither defers to the other.
	ProducerDigest string
	// ClosedAt defaults to time.Now(). It is recorded in UTC at second
	// granularity and must not precede the final audit record.
	ClosedAt time.Time
	Signer   *pqauth.Signer
}

// Seal creates the checkpoint for an already-closed audit log and an
// already-sealed evidence manifest, and writes it to EvidenceDirectory.
//
// Ordering is a precondition, not a suggestion. The audit log must be closed
// and fsynced and the manifest must be sealed before this runs, because both
// digests are committed here. Seal re-reads the audit log's size after hashing
// it and refuses if it moved, so a checkpoint is never produced over a trail
// that was still being appended to; and even if that check were defeated, a
// record appended afterwards is caught by Verify as a post-close record.
func Seal(input SealInput) (Checkpoint, error) {
	if input.Signer == nil {
		return Checkpoint{}, errors.New("audit checkpoint requires a finalizer signer")
	}
	if input.Signer.Algorithm() != FinalizerAlgorithm {
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint finalizer algorithm is %q, want %q",
			input.Signer.Algorithm(), FinalizerAlgorithm,
		)
	}
	// Run identity and producer digest are hard preconditions, exactly like the
	// finalizer pin on the verifying side. Both must be supplied by the runner
	// from custody outside the evidence: a checkpoint that named whatever run
	// and whatever producer the audited directory claimed would be a document
	// vouching for itself.
	if input.RunID == "" {
		return Checkpoint{}, errors.New(
			"audit checkpoint requires a run identity supplied by the runner",
		)
	}
	if !safeRunIdentifier.MatchString(input.RunID) {
		return Checkpoint{}, errors.New("audit checkpoint run identity is not a safe identifier")
	}
	if input.ProducerDigest == "" {
		return Checkpoint{}, errors.New(
			"audit checkpoint requires a producer digest supplied by the " +
				"runner; it is never taken from the evidence being closed",
		)
	}
	if !lowerHex(input.ProducerDigest, 64) {
		return Checkpoint{}, errors.New(
			"audit checkpoint producer digest is not 64 lower-hex characters",
		)
	}
	logName := input.AuditLogName
	manifestName := input.ManifestName
	if manifestName == "" {
		manifestName = "evidence-manifest.sha256"
	}
	if !safeName(logName) || !safeName(manifestName) {
		return Checkpoint{}, errors.New("audit checkpoint file names must be safe basenames")
	}
	directory, err := realDirectory(input.EvidenceDirectory)
	if err != nil {
		return Checkpoint{}, err
	}
	logPath := filepath.Join(directory, logName)

	before, err := regularSize(logPath)
	if err != nil {
		return Checkpoint{}, err
	}
	chain, err := ScanChain(logPath)
	if err != nil {
		return Checkpoint{}, err
	}
	if chain.RecordCount == 0 {
		return Checkpoint{}, errors.New("refusing to seal an empty audit trail")
	}
	logDigest, err := sha256File(logPath)
	if err != nil {
		return Checkpoint{}, err
	}
	after, err := regularSize(logPath)
	if err != nil {
		return Checkpoint{}, err
	}
	if before != after {
		return Checkpoint{}, errors.New(
			"audit log changed while the checkpoint was being sealed; the log " +
				"must be closed and fsynced first",
		)
	}

	manifestDigest, err := sha256File(filepath.Join(directory, manifestName))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("evidence manifest must be sealed first: %w", err)
	}
	if err := requireManifestShape(
		directory, manifestName, logName, logDigest,
	); err != nil {
		return Checkpoint{}, err
	}

	producer, err := producerDigestFromEnvironment(directory)
	if err != nil {
		return Checkpoint{}, err
	}
	if input.ProducerDigest != producer {
		return Checkpoint{}, fmt.Errorf(
			"runner supplied producer digest %s, sealed environment records %s",
			input.ProducerDigest, producer,
		)
	}

	closedAt := input.ClosedAt
	if closedAt.IsZero() {
		closedAt = time.Now()
	}
	closedAt = closedAt.UTC().Truncate(time.Second)
	if closedAt.Before(chain.FinalUTC.Truncate(time.Second)) {
		return Checkpoint{}, errors.New(
			"audit checkpoint close time precedes the final audit record",
		)
	}

	publicKey := input.Signer.PublicBytes()
	checkpoint := Checkpoint{
		Schema:                Schema,
		RunID:                 input.RunID,
		AuditLogName:          logName,
		FinalSequence:         chain.FinalSequence,
		RecordCount:           chain.RecordCount,
		ChainHeadMAC:          chain.HeadMAC,
		AuditLogSHA256:        logDigest,
		ManifestName:          manifestName,
		ManifestSHA256:        manifestDigest,
		ProducerDigest:        producer,
		ClosedAtUTC:           closedAt.Format(time.RFC3339),
		FinalizerAlgorithm:    FinalizerAlgorithm,
		FinalizerKeyID:        input.Signer.KeyID(),
		FinalizerPublicKeyB64: base64.StdEncoding.EncodeToString(publicKey),
	}
	message, err := checkpoint.signingMessage()
	if err != nil {
		return Checkpoint{}, err
	}
	signature, err := pqauth.SignDomainMessage(
		pqauth.AuditCheckpointSignatureDomain, message, input.Signer,
	)
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	clear(signature)

	encoded, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return Checkpoint{}, err
	}
	// Create-once, never replace. A terminal record that a second run could
	// silently overwrite is not terminal: an adversary who can re-seal would
	// simply re-close the truncated trail under the same name. AtomicWriteNew
	// resolves the race in the kernel, so a concurrent second finalizer loses
	// with os.ErrExist and the incumbent's bytes are untouched.
	if err := securefile.AtomicWriteNew(
		filepath.Join(directory, FileName), append(encoded, '\n'), 0o600,
	); err != nil {
		return Checkpoint{}, fmt.Errorf("write audit checkpoint: %w", err)
	}
	return checkpoint, nil
}

// VerifyInput is what an offline auditor supplies. No secret appears here: the
// finalizer credential is asymmetric, so the pin is a public key identity.
type VerifyInput struct {
	EvidenceDirectory string
	// ExpectedFinalizerKeyID is mandatory. A signature that only verifies
	// against a key the checkpoint itself supplies proves nothing at all, so a
	// missing pin is a refusal rather than a relaxation.
	ExpectedFinalizerKeyID string
	// ExpectedRunID is mandatory, for the same reason the pin is: accepting
	// whatever run the checkpoint names is how a cross-run transplant succeeds.
	ExpectedRunID string
	// ExpectedProducerDigest is mandatory. It must equal both the checkpoint's
	// bound producer digest and the digest recomputed from environment.txt.
	ExpectedProducerDigest string
	// AuditLogName restricts which audit log the checkpoint may vouch for.
	// Empty accepts whatever the checkpoint names, provided it is a safe
	// basename that exists.
	AuditLogName string
}

// Verify recomputes, from the files on disk, every value the checkpoint binds,
// and requires exact equality with what the checkpoint claims.
//
// It rejects, with a distinct message for each: a missing checkpoint, more than
// one checkpoint, an in-log checkpoint record, an unknown schema, an unpinned
// or mismatched finalizer key, a bad signature, a truncated chain, a record
// appended after close, a wrong head MAC, a wrong final sequence, a changed
// audit log, a changed or stale evidence manifest, a manifest that covers the
// checkpoint (the digest cycle), a producer-digest mismatch, and a run identity
// mismatch.
//
// Cross-run transplant is covered by the combination, not by any single field:
// a checkpoint lifted from another run carries that run's chain head MAC, audit
// log digest, manifest digest and run_id, all four of which are signed, so it
// can only be attached to evidence that is byte-identical to the evidence it
// was made for — at which point it is not a transplant.
func Verify(input VerifyInput) (Checkpoint, error) {
	directory, err := realDirectory(input.EvidenceDirectory)
	if err != nil {
		return Checkpoint{}, err
	}
	if input.ExpectedFinalizerKeyID == "" {
		return Checkpoint{}, errors.New(
			"audit checkpoint finalizer key is not pinned; a checkpoint " +
				"verified only against the key it carries proves nothing",
		)
	}
	if !lowerHex(input.ExpectedFinalizerKeyID, 64) {
		return Checkpoint{}, errors.New(
			"pinned audit checkpoint finalizer key id is not 64 lower-hex characters",
		)
	}
	// The run identity and producer digest are preconditions of equal standing
	// with the pin, enforced here at the trust boundary rather than only in
	// whatever command happens to call this. A caller reaching the library or
	// the CLI directly gets the same refusal.
	if input.ExpectedRunID == "" {
		return Checkpoint{}, errors.New(
			"audit checkpoint verification requires an externally supplied run " +
				"identity; accepting the run the checkpoint names cannot detect " +
				"a cross-run transplant",
		)
	}
	if !safeRunIdentifier.MatchString(input.ExpectedRunID) {
		return Checkpoint{}, errors.New(
			"expected audit checkpoint run identity is not a safe identifier",
		)
	}
	if input.ExpectedProducerDigest == "" {
		return Checkpoint{}, errors.New(
			"audit checkpoint verification requires an externally supplied " +
				"producer digest; accepting the producer the checkpoint names " +
				"binds no source tree at all",
		)
	}
	if !lowerHex(input.ExpectedProducerDigest, 64) {
		return Checkpoint{}, errors.New(
			"expected audit checkpoint producer digest is not 64 lower-hex characters",
		)
	}

	found, err := checkpointFiles(directory)
	if err != nil {
		return Checkpoint{}, err
	}
	switch {
	case len(found) == 0:
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint is missing: evidence carries no %s, so the "+
				"audit trail was never closed and a truncated tail would be "+
				"indistinguishable from a short run", FileName,
		)
	case len(found) > 1:
		return Checkpoint{}, fmt.Errorf(
			"evidence carries %d audit checkpoints (%s); exactly one is "+
				"required, because two close records make the trail's length "+
				"ambiguous", len(found), strings.Join(found, ", "),
		)
	case found[0] != FileName:
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint must be named %s, found %s", FileName, found[0],
		)
	}

	checkpoint, err := load(filepath.Join(directory, FileName))
	if err != nil {
		return Checkpoint{}, err
	}
	if input.AuditLogName != "" && checkpoint.AuditLogName != input.AuditLogName {
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint vouches for %q, this evidence is verified over %q",
			checkpoint.AuditLogName, input.AuditLogName,
		)
	}
	if checkpoint.RunID != input.ExpectedRunID {
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint run identity mismatch: checkpoint declares %q, "+
				"this run is %q", checkpoint.RunID, input.ExpectedRunID,
		)
	}

	// The credential first: everything below is a comparison against values the
	// checkpoint asserts, and those assertions are worth reading only once they
	// are known to come from the pinned finalizer.
	verifier, err := pqauth.NewVerifier(
		FinalizerAlgorithm, mustDecodeBase64(checkpoint.FinalizerPublicKeyB64),
	)
	if err != nil {
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint finalizer public key is unusable: %w", err,
		)
	}
	if !pqauth.EqualKeyID(verifier.KeyID(), checkpoint.FinalizerKeyID) {
		return Checkpoint{}, errors.New(
			"audit checkpoint finalizer key id does not match its own public key",
		)
	}
	if !pqauth.EqualKeyID(verifier.KeyID(), input.ExpectedFinalizerKeyID) {
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint finalizer key mismatch: checkpoint is signed by "+
				"%s, the pinned finalizer is %s",
			checkpoint.FinalizerKeyID, input.ExpectedFinalizerKeyID,
		)
	}
	message, err := checkpoint.signingMessage()
	if err != nil {
		return Checkpoint{}, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(checkpoint.SignatureB64)
	if err != nil {
		return Checkpoint{}, errors.New("audit checkpoint signature is not valid base64")
	}
	defer clear(signature)
	if err := pqauth.VerifyDomainMessage(
		pqauth.AuditCheckpointSignatureDomain, message, signature, verifier,
	); err != nil {
		return Checkpoint{}, fmt.Errorf("audit checkpoint signature is invalid: %w", err)
	}

	// Now recompute every bound field from the real files.
	logPath := filepath.Join(directory, checkpoint.AuditLogName)
	chain, err := ScanChain(logPath)
	if err != nil {
		return Checkpoint{}, err
	}
	// Counts before digests, deliberately. "The audit log digest changed" is
	// true of a truncated trail too, and reporting it first would let the
	// specific defect this whole record exists to catch hide behind a generic
	// integrity failure.
	switch {
	case chain.RecordCount < checkpoint.RecordCount:
		return Checkpoint{}, fmt.Errorf(
			"audit log was truncated: the checkpoint closed the trail at %d "+
				"records, the trail on disk has %d",
			checkpoint.RecordCount, chain.RecordCount,
		)
	case chain.RecordCount > checkpoint.RecordCount:
		return Checkpoint{}, fmt.Errorf(
			"audit log grew after the checkpoint was sealed: %d post-close "+
				"record(s) follow the closed trail of %d",
			chain.RecordCount-checkpoint.RecordCount, checkpoint.RecordCount,
		)
	}
	if chain.FinalSequence != checkpoint.FinalSequence {
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint final sequence mismatch: checkpoint claims %d, "+
				"trail ends at %d", checkpoint.FinalSequence, chain.FinalSequence,
		)
	}
	if chain.HeadMAC != checkpoint.ChainHeadMAC {
		return Checkpoint{}, fmt.Errorf(
			"audit chain head MAC mismatch: checkpoint closed on %s, trail "+
				"ends on %s", checkpoint.ChainHeadMAC, chain.HeadMAC,
		)
	}
	closedAt, err := parseClosedAt(checkpoint.ClosedAtUTC)
	if err != nil {
		return Checkpoint{}, err
	}
	if closedAt.Before(chain.FinalUTC.Truncate(time.Second)) {
		return Checkpoint{}, errors.New(
			"audit checkpoint close time precedes the final audit record",
		)
	}

	logDigest, err := sha256File(logPath)
	if err != nil {
		return Checkpoint{}, err
	}
	if logDigest != checkpoint.AuditLogSHA256 {
		return Checkpoint{}, fmt.Errorf(
			"audit log digest mismatch: checkpoint binds %s, the log on disk "+
				"hashes to %s", checkpoint.AuditLogSHA256, logDigest,
		)
	}

	manifestDigest, err := sha256File(filepath.Join(directory, checkpoint.ManifestName))
	if err != nil {
		return Checkpoint{}, err
	}
	if manifestDigest != checkpoint.ManifestSHA256 {
		return Checkpoint{}, fmt.Errorf(
			"evidence manifest digest mismatch: checkpoint binds %s, the "+
				"manifest on disk hashes to %s",
			checkpoint.ManifestSHA256, manifestDigest,
		)
	}
	// A manifest sealed before the last records were written hashes correctly
	// as a file and still describes a shorter log. That partial-completion
	// state — the crash between fsync and seal — is caught here and nowhere
	// else, because both digests above are individually consistent.
	if err := requireManifestShape(
		directory, checkpoint.ManifestName, checkpoint.AuditLogName, logDigest,
	); err != nil {
		return Checkpoint{}, err
	}

	producer, err := producerDigestFromEnvironment(directory)
	if err != nil {
		return Checkpoint{}, err
	}
	if producer != checkpoint.ProducerDigest {
		return Checkpoint{}, fmt.Errorf(
			"producer digest mismatch: checkpoint binds %s, sealed environment "+
				"records %s", checkpoint.ProducerDigest, producer,
		)
	}
	if input.ExpectedProducerDigest != checkpoint.ProducerDigest {
		return Checkpoint{}, fmt.Errorf(
			"producer digest mismatch: auditor expects %s, checkpoint binds %s",
			input.ExpectedProducerDigest, checkpoint.ProducerDigest,
		)
	}
	return checkpoint, nil
}

// ScanChain recomputes an audit trail's length, final sequence, head MAC and
// final timestamp without the audit HMAC key.
//
// The key is deliberately not available to the finalizer or to an offline
// auditor, so this is structural verification only: format, sequence continuity
// from 1, and previous-MAC linkage. That is exactly the property the checkpoint
// needs — how long the chain is and what its head is — and it is why the
// finalizer role can exist without ever touching the writer's key.
func ScanChain(path string) (Chain, error) {
	file, atOpen, err := openRegular(path, maximumAuditBytes)
	if err != nil {
		return Chain{}, err
	}
	defer file.Close()

	// The limit is enforced on the read, not on a stat taken before it: the
	// trail can grow after it is opened, and a scanner that simply stopped at
	// the cap would report a truncated trail as a complete one.
	reader := boundedReader(file, maximumAuditBytes, atOpen)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), maximumAuditLine)
	var chain Chain
	var expectedSequence uint64 = 1
	previousMAC := zeroMAC
	lines := 0
	for scanner.Scan() {
		lines++
		if lines > maximumAuditRecords {
			return Chain{}, errors.New("audit log is implausibly long")
		}
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var entry auditRecord
		if err := decoder.Decode(&entry); err != nil {
			return Chain{}, fmt.Errorf("audit line %d: %w", lines, err)
		}
		if err := requireEOF(decoder); err != nil {
			return Chain{}, fmt.Errorf("audit line %d: %w", lines, err)
		}
		// An in-log record wearing the checkpoint schema is an attempt to make
		// the trail look closed from the inside, where no finalizer signature
		// is possible. It is an ambiguity, so it is a rejection.
		if strings.Contains(entry.Event, Schema) ||
			strings.Contains(entry.Detail, Schema) {
			return Chain{}, fmt.Errorf(
				"audit line %d carries an in-log %s record; the checkpoint is "+
					"a signed sidecar and is never a chain record", lines, Schema,
			)
		}
		if entry.Format != auditRecordFormat {
			return Chain{}, fmt.Errorf("audit line %d: unsupported record format", lines)
		}
		if entry.Sequence != expectedSequence {
			return Chain{}, fmt.Errorf("audit line %d: sequence discontinuity", lines)
		}
		if entry.PreviousMAC != previousMAC {
			return Chain{}, fmt.Errorf("audit line %d: previous MAC linkage broken", lines)
		}
		if !lowerHex(entry.Authentication, 64) {
			return Chain{}, fmt.Errorf("audit line %d: malformed authentication", lines)
		}
		stamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			return Chain{}, fmt.Errorf("audit line %d: invalid timestamp", lines)
		}
		previousMAC = entry.Authentication
		expectedSequence = entry.Sequence + 1
		chain.RecordCount++
		chain.FinalSequence = entry.Sequence
		chain.HeadMAC = entry.Authentication
		chain.FinalUTC = stamp.UTC()
	}
	if err := scanner.Err(); err != nil {
		return Chain{}, fmt.Errorf("read audit log: %w", err)
	}
	if err := reader.check(file, path); err != nil {
		return Chain{}, err
	}
	if chain.RecordCount == 0 {
		chain.HeadMAC = zeroMAC
	}
	return chain, nil
}

// KeyIDFromSeedFile returns the finalizer key identity a seed file produces,
// so a runner can print the pin an auditor will later be given without ever
// disclosing the seed.
func KeyIDFromSeedFile(seedPath string) (string, error) {
	signer, err := LoadFinalizer(seedPath)
	if err != nil {
		return "", err
	}
	defer signer.Destroy()
	return signer.KeyID(), nil
}

// signingMessage renders the canonical, order-fixed, newline-delimited message
// the finalizer signs.
//
// JSON is not used as the signing input on purpose: two different JSON
// encodings of the same document would produce two different signatures, and an
// encoder change would silently invalidate every existing checkpoint. Every
// component is validated against a charset that excludes '=' and '\n' first, so
// no field value can forge a field boundary.
func (c Checkpoint) signingMessage() ([]byte, error) {
	if c.Schema != Schema {
		return nil, fmt.Errorf(
			"audit checkpoint declares unknown schema %q, want %q", c.Schema, Schema,
		)
	}
	if !safeRunIdentifier.MatchString(c.RunID) {
		return nil, errors.New("audit checkpoint run identity is not a safe identifier")
	}
	if !safeName(c.AuditLogName) || !safeName(c.ManifestName) {
		return nil, errors.New("audit checkpoint file names must be safe basenames")
	}
	for label, digest := range map[string]string{
		"chain_head_mac":           c.ChainHeadMAC,
		"audit_log_sha256":         c.AuditLogSHA256,
		"evidence_manifest_sha256": c.ManifestSHA256,
		"producer_digest":          c.ProducerDigest,
		"finalizer_key_id":         c.FinalizerKeyID,
	} {
		if !lowerHex(digest, 64) {
			return nil, fmt.Errorf(
				"audit checkpoint %s is not 64 lower-hex characters", label,
			)
		}
	}
	if c.FinalizerAlgorithm != FinalizerAlgorithm {
		return nil, fmt.Errorf(
			"audit checkpoint finalizer algorithm is %q, want %q",
			c.FinalizerAlgorithm, FinalizerAlgorithm,
		)
	}
	if c.RecordCount == 0 || c.FinalSequence == 0 {
		return nil, errors.New("audit checkpoint closes an empty trail")
	}
	if _, err := parseClosedAt(c.ClosedAtUTC); err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString(Schema + "\n")
	for _, pair := range [][2]string{
		{"run_id", c.RunID},
		{"audit_log_name", c.AuditLogName},
		{"final_sequence", fmt.Sprintf("%d", c.FinalSequence)},
		{"record_count", fmt.Sprintf("%d", c.RecordCount)},
		{"chain_head_mac", c.ChainHeadMAC},
		{"audit_log_sha256", c.AuditLogSHA256},
		{"evidence_manifest_name", c.ManifestName},
		{"evidence_manifest_sha256", c.ManifestSHA256},
		{"producer_digest", c.ProducerDigest},
		{"closed_at_utc", c.ClosedAtUTC},
		{"finalizer_algorithm", c.FinalizerAlgorithm},
		{"finalizer_key_id", c.FinalizerKeyID},
	} {
		builder.WriteString(pair[0] + "=" + pair[1] + "\n")
	}
	return []byte(builder.String()), nil
}

func load(path string) (Checkpoint, error) {
	content, err := securefile.ReadPublicIntegrity(path, maximumCheckpoint)
	if err != nil {
		return Checkpoint{}, err
	}
	if err := requireUniqueJSONKeys(content); err != nil {
		return Checkpoint{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var checkpoint Checkpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return Checkpoint{}, fmt.Errorf("audit checkpoint is not decodable: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Checkpoint{}, fmt.Errorf("audit checkpoint carries extra JSON: %w", err)
	}
	if checkpoint.Schema != Schema {
		return Checkpoint{}, fmt.Errorf(
			"audit checkpoint declares unknown schema %q, want %q",
			checkpoint.Schema, Schema,
		)
	}
	return checkpoint, nil
}

// checkpointFiles returns every checkpoint-like basename in the directory, so
// "exactly one" can be enforced rather than assumed from a fixed-name lookup.
func checkpointFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Any non-directory dirent whose name contains the marker counts,
		// including a symlink. Skipping non-regular files let
		// audit-checkpoint.json.bak exist as a second close record that
		// Verify never saw, so "exactly one checkpoint" was not decidable
		// from the directory listing.
		if strings.Contains(strings.ToLower(entry.Name()), checkpointNameMarker) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// requireManifestShape enforces the structural rules the base manifest must
// satisfy for a checkpoint to mean anything.
//
//   - It must not cover the checkpoint. That is the digest cycle the sidecar
//     design exists to avoid.
//   - It must cover the audit log AND environment.txt. Coverage is what makes
//     those two files evidence rather than annotations: environment.txt is
//     where the producer digest is independently recomputed from, so a run that
//     simply left it out of the manifest could supply any producer it liked.
//   - Every digest it records for those files must be the digest the file
//     actually has right now. A manifest sealed before the trail finished is a
//     valid file describing a shorter log — a partial-completion state, and the
//     only thing that can see it is this cross-check, because the manifest's
//     own digest and the log's own digest are each individually consistent.
func requireManifestShape(
	directory, manifestName, logName, logDigest string,
) error {
	required := map[string]string{logName: logDigest}
	environmentDigest, err := sha256File(filepath.Join(directory, EnvironmentName))
	if err != nil {
		return fmt.Errorf(
			"audit checkpoint requires sealed %s: %w", EnvironmentName, err,
		)
	}
	required[EnvironmentName] = environmentDigest

	content, err := securefile.ReadPublicIntegrity(
		filepath.Join(directory, manifestName), maximumManifestSize,
	)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), maximumAuditLine)
	covered := make(map[string]string, len(required))
	for scanner.Scan() {
		digest, path, ok := strings.Cut(scanner.Text(), "  ")
		if !ok || !lowerHex(digest, 64) {
			return errors.New("evidence manifest line is invalid")
		}
		name := strings.TrimPrefix(path, "./")
		if strings.Contains(strings.ToLower(name), checkpointNameMarker) {
			return fmt.Errorf(
				"evidence manifest covers the audit checkpoint (%s); the base "+
					"manifest must exclude it, because a manifest that hashes "+
					"the checkpoint that hashes the manifest is a digest cycle",
				name,
			)
		}
		if _, wanted := required[name]; !wanted {
			continue
		}
		if _, duplicate := covered[name]; duplicate {
			return fmt.Errorf("evidence manifest covers %s twice", name)
		}
		covered[name] = digest
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, name := range sortedKeys(required) {
		recorded, present := covered[name]
		if !present {
			return fmt.Errorf("evidence manifest does not cover %s", name)
		}
		if recorded != required[name] {
			return fmt.Errorf(
				"evidence manifest is stale: it records %s for %s, the file "+
					"hashes to %s", recorded, name, required[name],
			)
		}
	}
	return nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// requireUniqueJSONKeys rejects a document containing a repeated object key.
//
// encoding/json silently keeps the last occurrence of a duplicated key, so a
// checkpoint could carry record_count twice — one value for a casual reader,
// another for the decoder — and DisallowUnknownFields would not notice, because
// neither occurrence is unknown. The token stream is walked here so the two
// occurrences are both seen.
func requireUniqueJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("audit checkpoint JSON is nested too deeply")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("audit checkpoint JSON has a non-string key")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf(
						"audit checkpoint JSON repeats the key %q; a document "+
							"that states one field twice states nothing", key,
					)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		}
		// Consume the matching closing delimiter.
		if _, err := decoder.Token(); err != nil {
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	return requireEOF(decoder)
}

// producerDigestFromEnvironment recomputes this run's producer/source digest
// from sealed, manifest-covered evidence rather than from the checkpoint's own
// claim. Every recognised key that is present must agree, so a second key
// carrying a different value is a refusal rather than a lucky pick.
func producerDigestFromEnvironment(directory string) (string, error) {
	content, err := securefile.ReadPublicIntegrity(
		filepath.Join(directory, EnvironmentName), 64<<10,
	)
	if err != nil {
		return "", fmt.Errorf(
			"audit checkpoint requires sealed %s to recompute the producer "+
				"digest: %w", EnvironmentName, err,
		)
	}
	values := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || key == "" {
			return "", fmt.Errorf("invalid key/value line in %s", EnvironmentName)
		}
		if _, duplicate := values[key]; duplicate {
			return "", fmt.Errorf("duplicate key %q in %s", key, EnvironmentName)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	digest := ""
	for _, key := range producerDigestKeys {
		value, present := values[key]
		if !present {
			continue
		}
		if !lowerHex(value, 64) {
			return "", fmt.Errorf(
				"%s records %s=%q, which is not a SHA-256 digest",
				EnvironmentName, key, value,
			)
		}
		if digest != "" && digest != value {
			return "", fmt.Errorf(
				"%s records two different producer digests", EnvironmentName,
			)
		}
		digest = value
	}
	if digest == "" {
		return "", fmt.Errorf(
			"%s records no producer digest under %s",
			EnvironmentName, strings.Join(producerDigestKeys, " or "),
		)
	}
	return digest, nil
}

// parseClosedAt accepts exactly one rendering of the close time: RFC3339,
// second granularity, literal "Z".
//
// "Any valid RFC3339 timestamp" would not do. 2026-07-26T16:13:57Z and
// 2026-07-26T21:13:57+05:00 are the same instant written two ways, so a
// checkpoint could be re-rendered into a different signed message that means
// the same thing — and, worse, a reader comparing timestamps as strings would
// see two different closes. One instant, one spelling.
func parseClosedAt(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf(
			"audit checkpoint close time %q is not canonical UTC; it must end "+
				"in Z, not carry a zone offset", value,
		)
	}
	closedAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.New(
			"audit checkpoint close time is not RFC3339 UTC",
		)
	}
	if closedAt.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf(
			"audit checkpoint close time %q is not canonical RFC3339 UTC", value,
		)
	}
	return closedAt, nil
}

func mustDecodeBase64(encoded string) []byte {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil
	}
	return decoded
}

func safeName(name string) bool {
	return safeIdentifier.MatchString(name) &&
		name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\\")
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func realDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("evidence directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("evidence directory must be a real directory")
	}
	return absolute, nil
}

// openRegular opens a file that must be a regular file no larger than
// maximum, and proves the handle it returns refers to the very file that was
// inspected.
//
// The size check here is a fast rejection, NOT the bound. A file that is within
// the limit at this instant can grow while it is being read, so a check made
// before the first byte cannot bound the read that follows: boundedReader is
// what actually enforces the limit, by reading through maximum+1 and refusing
// anything that reaches it. Callers must use boundedReader; a plain read of
// this descriptor is unbounded.
//
// The other failure mode closed here is the check/open race. Lstat inspects a
// path; open resolves the path again. Between the two, the name can be
// repointed at something else, so the opened descriptor is re-stat'd and
// compared with os.SameFile: if they are not the same file, the inspection
// proved nothing about what was opened.
func openRegular(path string, maximum int64) (*os.File, int64, error) {
	return openRegularWithHook(path, maximum, nil)
}

// openRegularWithHook is openRegular with an injection point for the one window
// that cannot otherwise be reproduced deterministically: between the descriptor
// being opened and sized, and the first byte being read.
//
// The hook is a parameter rather than a package variable on purpose. A mutable
// global would be shared by every concurrent Seal and Verify in a running
// process, so a test that set it could perturb unrelated work, and two parallel
// tests could overwrite each other. Production reaches this only through
// openRegular, which passes nil.
func openRegularWithHook(
	path string,
	maximum int64,
	afterOpen func(path string),
) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !before.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if before.Size() > maximum {
		return nil, 0, fmt.Errorf(
			"%s is %d bytes, over the %d-byte limit; refusing to read a prefix "+
				"of it", filepath.Base(path), before.Size(), maximum,
		)
	}
	// #nosec G304 -- the path is composed from a caller-supplied evidence
	// directory and a basename already forced through safeName, and the opened
	// descriptor is re-verified below against the file just inspected.
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, 0, fmt.Errorf(
			"%s changed between inspection and open", filepath.Base(path),
		)
	}
	if opened.Size() > maximum {
		_ = file.Close()
		return nil, 0, fmt.Errorf(
			"%s is %d bytes, over the %d-byte limit; refusing to read a prefix "+
				"of it", filepath.Base(path), opened.Size(), maximum,
		)
	}
	atOpen := opened.Size()
	if afterOpen != nil {
		afterOpen(path)
	}
	return file, atOpen, nil
}

func regularSize(path string) (int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	return info.Size(), nil
}

func sha256File(path string) (string, error) {
	file, atOpen, err := openRegular(path, maximumAuditBytes)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	reader := boundedReader(file, maximumAuditBytes, atOpen)
	if _, err := io.Copy(hash, reader); err != nil {
		return "", err
	}
	if err := reader.check(file, path); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// boundedRead enforces the size limit on the READ rather than on a stat taken
// before it.
//
// The distinction matters because a file can grow after it is opened. An
// upfront size check on a file that is within the limit at that instant says
// nothing about how much data an unbounded read will go on to consume, so the
// limit has to be enforced by the reader itself.
//
// It reads through maximum+1 bytes, never maximum. A file of exactly maximum
// bytes reaches EOF at maximum and never yields the extra byte; a file with
// more than maximum bytes yields it. Reading one byte past the limit is
// therefore what distinguishes "exactly at the limit" from "over it", and it is
// why this cannot be written as a plain LimitReader(maximum), which produces
// the same byte stream for a file at the limit and a file far beyond it.
//
// A prefix is never accepted as the whole. Exceeding the limit is an error, not
// a truncation.
type boundedRead struct {
	limited *io.LimitedReader
	maximum int64
	// atOpen is the descriptor's size at the moment it was opened, captured
	// before any byte was read. Growth is detected by comparing against it,
	// because a comparison against what was consumed would agree with itself:
	// a reader that swallowed the appended bytes and a file that now contains
	// them are consistent, and consistently wrong.
	atOpen int64
}

func boundedReader(reader io.Reader, maximum, atOpen int64) *boundedRead {
	return &boundedRead{
		limited: &io.LimitedReader{R: reader, N: maximum + 1},
		maximum: maximum,
		atOpen:  atOpen,
	}
}

func (b *boundedRead) Read(buffer []byte) (int, error) {
	return b.limited.Read(buffer)
}

// consumed is how many bytes the reader actually delivered.
func (b *boundedRead) consumed() int64 {
	return b.maximum + 1 - b.limited.N
}

// check is called after EOF. It rejects a file that delivered more than the
// limit, and re-stats the descriptor so a file that grew after it was opened is
// caught whether or not the growth pushed the read past the limit.
func (b *boundedRead) check(file *os.File, path string) error {
	if b.consumed() > b.maximum {
		return fmt.Errorf(
			"%s exceeds the %d-byte limit; refusing to accept a prefix of it "+
				"as the whole file", filepath.Base(path), b.maximum,
		)
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if after.Size() != b.atOpen || b.consumed() != b.atOpen {
		return fmt.Errorf(
			"%s changed while it was being read: it held %d bytes when it was "+
				"opened, %d were consumed, and it now holds %d",
			filepath.Base(path), b.atOpen, b.consumed(), after.Size(),
		)
	}
	if after.Size() > b.maximum {
		return fmt.Errorf(
			"%s exceeds the %d-byte limit; refusing to accept a prefix of it "+
				"as the whole file", filepath.Base(path), b.maximum,
		)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}
