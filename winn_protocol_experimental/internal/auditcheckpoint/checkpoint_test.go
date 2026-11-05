// Adversarial suite for winn-audit-checkpoint/v1.
//
// The checkpoint exists for exactly one reason: an HMAC chain cannot detect
// truncation at the tail, because a prefix of a valid chain is a valid chain.
// Every test below therefore builds a REAL chained audit log through
// internal/audit, seals a real manifest over it, and closes it with a real
// ML-DSA-65 finalizer — so every cryptographic and digest check the pipeline
// has passes, and the only defect present is the one the test names.
//
// Where a scenario could plausibly be caught "by accident" (a truncation that
// also happens to change the log's SHA-256), the test asserts on the specific
// error substring, so a rejection for an unrelated reason fails the test rather
// than passing it.
package auditcheckpoint

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/pqauth"
)

const (
	testLogName   = "carrier-audit.jsonl"
	testRunID     = "checkpoint-suite-run"
	testProducer  = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	testRecords   = 8
	otherProducer = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// evidence is one closed run: the directory, the finalizer's public identity
// (the auditor's pin), and the finalizer signer, which in production never
// leaves the runner.
type evidence struct {
	directory string
	pin       string
	signer    *pqauth.Signer
	auditKey  []byte
}

// newEvidence builds a sealed, closed evidence directory in the exact order a
// runner must use: write records, close and fsync the log, seal the base
// manifest (excluding the checkpoint), then sign the checkpoint.
func newEvidence(t *testing.T, records int) *evidence {
	t.Helper()
	run := newOpenEvidence(t, records, testProducer)
	run.seal(t)
	run.close(t, testRunID)
	return run
}

// newOpenEvidence writes the audit log and environment but stops short of
// sealing and closing, so the crash-simulation tests can stop at any stage.
func newOpenEvidence(t *testing.T, records int, producer string) *evidence {
	t.Helper()
	directory := t.TempDir()
	keyDirectory := t.TempDir()
	keyPath := filepath.Join(keyDirectory, "audit.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(directory, testLogName), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < records; index++ {
		if err := log.Record(
			fmt.Sprintf("carrier_event_%d", index), "device", "", "detail",
		); err != nil {
			_ = log.Close()
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, EnvironmentName),
		[]byte("carrier_authorization_mode=anonymous-token\nsource_digest="+
			producer+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	seed, err := GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(FinalizerAlgorithm, seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	return &evidence{
		directory: directory,
		pin:       signer.KeyID(),
		signer:    signer,
		auditKey:  key,
	}
}

// seal writes evidence-manifest.sha256 over every regular file except itself
// and except any checkpoint, mirroring the live sealer.
func (e *evidence) seal(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(e.directory)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() ||
			name == "evidence-manifest.sha256" ||
			strings.Contains(name, checkpointNameMarker) {
			continue
		}
		digest, err := sha256File(filepath.Join(e.directory, name))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, digest+"  ./"+name)
	}
	sort.Strings(lines)
	if err := os.WriteFile(
		filepath.Join(e.directory, "evidence-manifest.sha256"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func (e *evidence) close(t *testing.T, runID string) Checkpoint {
	t.Helper()
	checkpoint, err := Seal(SealInput{
		EvidenceDirectory: e.directory,
		AuditLogName:      testLogName,
		RunID:             runID,
		ProducerDigest:    testProducer,
		Signer:            e.signer,
	})
	if err != nil {
		t.Fatalf("seal checkpoint: %v", err)
	}
	return checkpoint
}

func (e *evidence) verify() error {
	_, err := Verify(VerifyInput{
		EvidenceDirectory:      e.directory,
		ExpectedFinalizerKeyID: e.pin,
		ExpectedRunID:          testRunID,
		ExpectedProducerDigest: testProducer,
		AuditLogName:           testLogName,
	})
	return err
}

func (e *evidence) logPath() string {
	return filepath.Join(e.directory, testLogName)
}

func (e *evidence) checkpointPath() string {
	return filepath.Join(e.directory, FileName)
}

func (e *evidence) readCheckpoint(t *testing.T) Checkpoint {
	t.Helper()
	checkpoint, err := load(e.checkpointPath())
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

// writeSigned re-signs an arbitrary checkpoint document with the legitimate
// finalizer key and installs it. This is the "the finalizer itself lies" case:
// the signature is genuine and the pin matches, so only independent
// recomputation of every bound field can reject it.
func (e *evidence) writeSigned(t *testing.T, checkpoint Checkpoint) {
	t.Helper()
	message, err := checkpoint.signingMessage()
	if err != nil {
		t.Fatalf("sign mutated checkpoint: %v", err)
	}
	signature, err := pqauth.SignDomainMessage(
		pqauth.AuditCheckpointSignatureDomain, message, e.signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	encoded, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		e.checkpointPath(), append(encoded, '\n'), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// writeRaw installs a checkpoint document without re-signing it, so the
// existing signature no longer covers the mutated field.
func (e *evidence) writeRaw(t *testing.T, checkpoint Checkpoint) {
	t.Helper()
	encoded, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		e.checkpointPath(), append(encoded, '\n'), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	content, err := os.ReadFile(path) // #nosec G304 -- test-local temp path
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSuffix(string(content), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireReject(t *testing.T, err error, want, scenario string) {
	t.Helper()
	if err == nil {
		t.Fatalf(
			"the checkpoint verifier ACCEPTED %s; every other check in the "+
				"pipeline passes on this fixture, so acceptance means the "+
				"checkpoint gate itself is missing or wrong", scenario,
		)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf(
			"%s was rejected, but not for the intended reason: wanted an error "+
				"containing %q, got: %v", scenario, want, err,
		)
	}
}

// --- positive control -----------------------------------------------------

func TestCheckpointAcceptsAProperlyClosedRun(t *testing.T) {
	run := newEvidence(t, testRecords)
	if err := run.verify(); err != nil {
		t.Fatalf("a correctly closed run must verify cleanly: %v", err)
	}
	checkpoint := run.readCheckpoint(t)
	if checkpoint.RecordCount != testRecords ||
		checkpoint.FinalSequence != testRecords {
		t.Fatalf(
			"checkpoint closed %d records at sequence %d, want %d/%d",
			checkpoint.RecordCount, checkpoint.FinalSequence,
			testRecords, testRecords,
		)
	}
	if checkpoint.Schema != Schema ||
		checkpoint.FinalizerAlgorithm != FinalizerAlgorithm {
		t.Fatalf("unexpected schema/algorithm: %+v", checkpoint)
	}
	// The base manifest must not cover the checkpoint: that is the digest
	// cycle the sidecar design exists to avoid.
	manifest, err := os.ReadFile(
		filepath.Join(run.directory, "evidence-manifest.sha256"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), checkpointNameMarker) {
		t.Fatalf("base manifest covers the checkpoint:\n%s", manifest)
	}
}

// --- truncation -----------------------------------------------------------

// TestCheckpointRejectsTruncationAtEveryBoundary is the finding this record was
// created for. A prefix of a valid HMAC chain is a valid HMAC chain, so every
// one of these truncated trails passes internal/audit's own verification.
func TestCheckpointRejectsTruncationAtEveryBoundary(t *testing.T) {
	for keep := 0; keep < testRecords; keep++ {
		t.Run(fmt.Sprintf("keep_%d_of_%d", keep, testRecords), func(t *testing.T) {
			run := newEvidence(t, testRecords)
			lines := readLines(t, run.logPath())
			writeLines(t, run.logPath(), lines[:keep])
			requireReject(
				t, run.verify(), "audit log was truncated",
				fmt.Sprintf(
					"a trail truncated from %d records to %d", testRecords, keep,
				),
			)
		})
	}
}

// TestCheckpointRejectsConsistentlyRewrittenTruncation is the sophisticated
// case: the adversary truncates the trail AND re-seals the evidence manifest so
// every digest in the pipeline agrees with the shortened log. Nothing except
// the checkpoint has any surviving record of how long the trail was.
func TestCheckpointRejectsConsistentlyRewrittenTruncation(t *testing.T) {
	run := newEvidence(t, testRecords)
	lines := readLines(t, run.logPath())
	writeLines(t, run.logPath(), lines[:testRecords-3])
	run.seal(t)

	// Prove the adversary's work was thorough: the manifest and the files now
	// agree, and the surviving chain is structurally perfect.
	chain, err := ScanChain(run.logPath())
	if err != nil {
		t.Fatalf("the truncated chain must still be structurally valid: %v", err)
	}
	if chain.RecordCount != testRecords-3 {
		t.Fatalf("truncated chain has %d records", chain.RecordCount)
	}
	requireReject(
		t, run.verify(), "audit log was truncated",
		"a truncated trail whose manifest was re-sealed to match",
	)
}

// TestCheckpointRejectsAppendAfterClose covers the other direction: records
// written after the trail was declared closed.
func TestCheckpointRejectsAppendAfterClose(t *testing.T) {
	run := newEvidence(t, testRecords)
	lines := readLines(t, run.logPath())
	// A genuine continuation of the chain would need the audit key; a
	// structurally valid extra line is enough to prove the count binding is
	// what catches this, and the count check runs before any digest check.
	last := lines[len(lines)-1]
	var tail map[string]any
	if err := json.Unmarshal([]byte(last), &tail); err != nil {
		t.Fatal(err)
	}
	extra := map[string]any{
		"format":         auditRecordFormat,
		"sequence":       float64(testRecords + 1),
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"event":          "carrier_event_after_close",
		"previous_mac":   tail["authentication"],
		"authentication": strings.Repeat("ab", 32),
	}
	encoded, err := json.Marshal(extra)
	if err != nil {
		t.Fatal(err)
	}
	writeLines(t, run.logPath(), append(lines, string(encoded)))
	run.seal(t)
	requireReject(
		t, run.verify(), "audit log grew after the checkpoint was sealed",
		"a record appended after the trail was closed",
	)
}

// --- presence and uniqueness ----------------------------------------------

func TestCheckpointRejectsAMissingCheckpoint(t *testing.T) {
	run := newEvidence(t, testRecords)
	if err := os.Remove(run.checkpointPath()); err != nil {
		t.Fatal(err)
	}
	requireReject(
		t, run.verify(), "audit checkpoint is missing",
		"evidence with no checkpoint at all",
	)
}

func TestCheckpointRejectsADuplicateCheckpoint(t *testing.T) {
	for _, name := range []string{
		// Case variants are deliberately not tested here: on a
		// case-insensitive filesystem writing AUDIT-CHECKPOINT.JSON would
		// simply overwrite the incumbent, so the scenario is not portable.
		// checkpointFiles lowercases before matching, so it is covered by
		// construction.
		"audit-checkpoint.json.bak",
		"audit-checkpoint-2.json",
		"audit-checkpoint.old",
	} {
		t.Run(name, func(t *testing.T) {
			run := newEvidence(t, testRecords)
			content, err := os.ReadFile(run.checkpointPath())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(run.directory, name), content, 0o600,
			); err != nil {
				t.Fatal(err)
			}
			requireReject(
				t, run.verify(), "audit checkpoints",
				"evidence carrying a second checkpoint named "+name,
			)
		})
	}
}

func TestCheckpointRejectsADuplicateCheckpointSymlink(t *testing.T) {
	run := newEvidence(t, testRecords)
	bak := filepath.Join(run.directory, "audit-checkpoint.json.bak")
	if err := os.Symlink(run.checkpointPath(), bak); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	requireReject(
		t, run.verify(), "audit checkpoints",
		"evidence carrying a second checkpoint as a symlink named audit-checkpoint.json.bak",
	)
}

// TestCheckpointRejectsAnInLogCheckpointRecord covers the attempt to make the
// trail look closed from inside the log, where no finalizer signature is
// possible.
func TestCheckpointRejectsAnInLogCheckpointRecord(t *testing.T) {
	run := newEvidence(t, testRecords)
	lines := readLines(t, run.logPath())
	var tail map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &tail); err != nil {
		t.Fatal(err)
	}
	forged := map[string]any{
		"format":         auditRecordFormat,
		"sequence":       float64(testRecords + 1),
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"event":          Schema,
		"detail":         Schema + " closed",
		"previous_mac":   tail["authentication"],
		"authentication": strings.Repeat("cd", 32),
	}
	encoded, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	writeLines(t, run.logPath(), append(lines, string(encoded)))
	run.seal(t)
	requireReject(
		t, run.verify(), "in-log winn-audit-checkpoint/v1 record",
		"a forged close record written inside the audit log",
	)
}

// TestCheckpointRejectsAManifestThatCoversIt proves the digest cycle is
// refused rather than silently tolerated.
func TestCheckpointRejectsAManifestThatCoversIt(t *testing.T) {
	run := newEvidence(t, testRecords)
	digest, err := sha256File(run.checkpointPath())
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(run.directory, "evidence-manifest.sha256")
	lines := readLines(t, manifestPath)
	writeLines(t, manifestPath, append(lines, digest+"  ./"+FileName))
	// Re-close so the checkpoint binds the new manifest; only the cycle rule
	// can reject this.
	if err := os.Remove(run.checkpointPath()); err != nil {
		t.Fatal(err)
	}
	_, err = Seal(SealInput{
		EvidenceDirectory: run.directory,
		AuditLogName:      testLogName,
		RunID:             testRunID,
		ProducerDigest:    testProducer,
		Signer:            run.signer,
	})
	requireReject(
		t, err, "digest cycle",
		"a base manifest that covers the checkpoint",
	)
}

// --- credential -----------------------------------------------------------

func TestCheckpointRejectsAnUnpinnedFinalizer(t *testing.T) {
	run := newEvidence(t, testRecords)
	_, err := Verify(VerifyInput{
		EvidenceDirectory: run.directory,
		AuditLogName:      testLogName,
	})
	requireReject(
		t, err, "finalizer key is not pinned",
		"verification with no pinned finalizer identity",
	)
}

func TestCheckpointRejectsASwappedFinalizerKey(t *testing.T) {
	run := newEvidence(t, testRecords)

	// The adversary generates their own finalizer key and re-closes the trail
	// with it. The document is internally perfect; only the pin rejects it.
	seed, err := GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := pqauth.NewSigner(FinalizerAlgorithm, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer rogue.Destroy()
	if err := os.Remove(run.checkpointPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(SealInput{
		EvidenceDirectory: run.directory,
		AuditLogName:      testLogName,
		RunID:             testRunID,
		ProducerDigest:    testProducer,
		Signer:            rogue,
	}); err != nil {
		t.Fatal(err)
	}
	requireReject(
		t, run.verify(), "finalizer key mismatch",
		"a checkpoint closed by a finalizer key the auditor did not pin",
	)
}

// TestCheckpointResistsTheAuditWriterKey is the cryptographic requirement
// itself, stated as a test.
//
// It implements the design that was explicitly REJECTED — a close credential
// derived from the ordinary audit-writer's HMAC key via
// HKDF(audit_key, "winn-audit-close/v1") — and proves that an adversary
// holding that key still cannot produce a checkpoint the auditor accepts. Under
// the rejected design this adversary would have succeeded completely, because
// the derivation is deterministic and public.
func TestCheckpointResistsTheAuditWriterKey(t *testing.T) {
	run := newEvidence(t, testRecords)

	derived := make([]byte, 32)
	reader := hkdf.New(
		sha256.New, run.auditKey, nil, []byte("winn-audit-close/v1"),
	)
	if _, err := reader.Read(derived); err != nil {
		t.Fatal(err)
	}
	adversary, err := pqauth.NewSigner(FinalizerAlgorithm, derived)
	if err != nil {
		t.Fatal(err)
	}
	defer adversary.Destroy()
	if adversary.KeyID() == run.pin {
		t.Fatal(
			"the audit writer's key derived the finalizer identity; the " +
				"finalizer credential is not independent of the audit key",
		)
	}

	// The adversary truncates the trail, re-seals the manifest, and closes it
	// with everything they hold.
	lines := readLines(t, run.logPath())
	writeLines(t, run.logPath(), lines[:testRecords-2])
	run.seal(t)
	if err := os.Remove(run.checkpointPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(SealInput{
		EvidenceDirectory: run.directory,
		AuditLogName:      testLogName,
		RunID:             testRunID,
		ProducerDigest:    testProducer,
		Signer:            adversary,
	}); err != nil {
		t.Fatal(err)
	}
	requireReject(
		t, run.verify(), "finalizer key mismatch",
		"a truncation closed with a credential derived from the audit HMAC key",
	)

	// And separately: an HMAC computed directly under the audit key is not a
	// signature at all, so it cannot even be parsed as one.
	checkpoint := run.readCheckpoint(t)
	message, err := checkpoint.signingMessage()
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, run.auditKey)
	mac.Write(message)
	checkpoint.SignatureB64 = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	checkpoint.FinalizerPublicKeyB64 = base64.StdEncoding.EncodeToString(
		run.signer.PublicBytes(),
	)
	checkpoint.FinalizerKeyID = run.pin
	run.writeRaw(t, checkpoint)
	requireReject(
		t, run.verify(), "audit checkpoint signature is invalid",
		"an HMAC under the audit key presented as a finalizer signature",
	)
}

// --- cross-run transplant -------------------------------------------------

// TestCheckpointRejectsCrossRunTransplant lifts a genuine, correctly signed
// checkpoint from one run and attaches it to another run's evidence — including
// the case where both runs share the same finalizer, so the pin alone cannot
// tell them apart.
func TestCheckpointRejectsCrossRunTransplant(t *testing.T) {
	donor := newEvidence(t, testRecords)
	target := newOpenEvidence(t, testRecords, testProducer)
	// Same finalizer for both, so only the bound run content can distinguish.
	target.signer = donor.signer
	target.pin = donor.pin
	target.seal(t)
	target.close(t, testRunID)

	transplanted, err := os.ReadFile(donor.checkpointPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		target.checkpointPath(), transplanted, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	// The two runs differ in their record timestamps, hence in their chain head
	// MACs and their log digests; the checkpoint binds all of them.
	requireReject(
		t, target.verify(), "audit chain head MAC mismatch",
		"a genuine checkpoint from a different run of the same finalizer",
	)

	// And with a distinct run identity pinned, the transplant is caught by name
	// before anything else is examined.
	donor2 := newOpenEvidence(t, testRecords, testProducer)
	donor2.seal(t)
	donor2.close(t, "some-other-run")
	_, err = Verify(VerifyInput{
		EvidenceDirectory:      donor2.directory,
		ExpectedFinalizerKeyID: donor2.pin,
		ExpectedRunID:          testRunID,
		ExpectedProducerDigest: testProducer,
		AuditLogName:           testLogName,
	})
	requireReject(
		t, err, "run identity mismatch",
		"a checkpoint naming a run other than the one being verified",
	)
}

// --- per-field mutation ---------------------------------------------------

// TestCheckpointRejectsEveryUnsignedFieldMutation mutates each bound field on
// its own, leaving the original signature in place. Every one must be caught by
// the signature, which is what proves the signing message really covers the
// whole document rather than a convenient subset.
func TestCheckpointRejectsEveryUnsignedFieldMutation(t *testing.T) {
	for name, mutate := range map[string]func(*Checkpoint){
		"run_id":                   func(c *Checkpoint) { c.RunID = "another-run" },
		"audit_log_name":           func(c *Checkpoint) { c.AuditLogName = "other.jsonl" },
		"final_sequence":           func(c *Checkpoint) { c.FinalSequence-- },
		"record_count":             func(c *Checkpoint) { c.RecordCount-- },
		"chain_head_mac":           func(c *Checkpoint) { c.ChainHeadMAC = strings.Repeat("11", 32) },
		"audit_log_sha256":         func(c *Checkpoint) { c.AuditLogSHA256 = strings.Repeat("22", 32) },
		"evidence_manifest_name":   func(c *Checkpoint) { c.ManifestName = "other.sha256" },
		"evidence_manifest_sha256": func(c *Checkpoint) { c.ManifestSHA256 = strings.Repeat("33", 32) },
		"producer_digest":          func(c *Checkpoint) { c.ProducerDigest = otherProducer },
		"closed_at_utc": func(c *Checkpoint) {
			c.ClosedAtUTC = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		},
	} {
		t.Run(name, func(t *testing.T) {
			run := newEvidence(t, testRecords)
			checkpoint := run.readCheckpoint(t)
			mutate(&checkpoint)
			run.writeRaw(t, checkpoint)
			err := run.verify()
			if err == nil {
				t.Fatalf("mutating %s was accepted", name)
			}
			// A mutated file name or run identity is rejected by the name/run
			// binding before the signature is even consulted; everything else
			// must fail the signature.
			if !strings.Contains(err.Error(), "signature is invalid") &&
				!strings.Contains(err.Error(), "vouches for") &&
				!strings.Contains(err.Error(), "run identity mismatch") {
				t.Fatalf(
					"mutating %s was rejected for an unexpected reason: %v",
					name, err,
				)
			}
		})
	}
}

// TestCheckpointRejectsAFinalizerThatLies re-signs each mutated field with the
// legitimate finalizer key, so the signature is genuine and the pin matches.
// Only independent recomputation from the real files can reject these, which is
// the "recompute every bound field" requirement stated as a test.
func TestCheckpointRejectsAFinalizerThatLies(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Checkpoint)
		want   string
	}{
		{
			name:   "understated_record_count",
			mutate: func(c *Checkpoint) { c.RecordCount-- },
			want:   "audit log grew after the checkpoint was sealed",
		},
		{
			name:   "overstated_record_count",
			mutate: func(c *Checkpoint) { c.RecordCount++ },
			want:   "audit log was truncated",
		},
		{
			name:   "wrong_final_sequence",
			mutate: func(c *Checkpoint) { c.FinalSequence++ },
			want:   "final sequence mismatch",
		},
		{
			name:   "wrong_chain_head_mac",
			mutate: func(c *Checkpoint) { c.ChainHeadMAC = strings.Repeat("44", 32) },
			want:   "audit chain head MAC mismatch",
		},
		{
			name:   "wrong_audit_log_digest",
			mutate: func(c *Checkpoint) { c.AuditLogSHA256 = strings.Repeat("55", 32) },
			want:   "audit log digest mismatch",
		},
		{
			name:   "wrong_manifest_digest",
			mutate: func(c *Checkpoint) { c.ManifestSHA256 = strings.Repeat("66", 32) },
			want:   "evidence manifest digest mismatch",
		},
		{
			name:   "wrong_producer_digest",
			mutate: func(c *Checkpoint) { c.ProducerDigest = otherProducer },
			want:   "producer digest mismatch",
		},
		{
			name: "close_time_before_the_final_record",
			mutate: func(c *Checkpoint) {
				c.ClosedAtUTC = time.Now().UTC().
					Add(-24 * time.Hour).Format(time.RFC3339)
			},
			want: "close time precedes the final audit record",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			run := newEvidence(t, testRecords)
			checkpoint := run.readCheckpoint(t)
			test.mutate(&checkpoint)
			run.writeSigned(t, checkpoint)
			requireReject(
				t, run.verify(), test.want,
				"a genuinely signed checkpoint whose "+test.name+
					" disagrees with the sealed files",
			)
		})
	}
}

// --- crash / partial completion -------------------------------------------

// TestCheckpointRejectsPartialCompletionStates walks the runner's required
// ordering and stops at each intermediate point. None of these states may be
// silently accepted as closed evidence.
func TestCheckpointRejectsPartialCompletionStates(t *testing.T) {
	t.Run("crash_after_log_close_before_manifest_seal", func(t *testing.T) {
		run := newOpenEvidence(t, testRecords, testProducer)
		_, err := Seal(SealInput{
			EvidenceDirectory: run.directory,
			AuditLogName:      testLogName,
			RunID:             testRunID,
			ProducerDigest:    testProducer,
			Signer:            run.signer,
		})
		if err == nil {
			t.Fatal("a checkpoint was sealed over evidence with no manifest")
		}
		if !strings.Contains(err.Error(), "manifest must be sealed first") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})

	t.Run("crash_after_manifest_seal_before_checkpoint", func(t *testing.T) {
		run := newOpenEvidence(t, testRecords, testProducer)
		run.seal(t)
		requireReject(
			t, run.verify(), "audit checkpoint is missing",
			"a run that sealed its manifest and then died before closing",
		)
	})

	t.Run("manifest_sealed_before_the_final_records", func(t *testing.T) {
		// The stale-manifest case: the manifest is a valid file whose own
		// digest the checkpoint binds correctly, but it describes a shorter
		// log. Both digest checks pass individually; only the cross-check
		// between them sees it.
		run := newOpenEvidence(t, testRecords, testProducer)
		full := readLines(t, run.logPath())
		writeLines(t, run.logPath(), full[:testRecords-2])
		run.seal(t)
		writeLines(t, run.logPath(), full)
		_, err := Seal(SealInput{
			EvidenceDirectory: run.directory,
			AuditLogName:      testLogName,
			RunID:             testRunID,
			ProducerDigest:    testProducer,
			Signer:            run.signer,
		})
		if err == nil {
			t.Fatal("a checkpoint was sealed over a stale manifest")
		}
		if !strings.Contains(err.Error(), "evidence manifest is stale") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})

	t.Run("manifest_does_not_cover_the_audit_log", func(t *testing.T) {
		run := newOpenEvidence(t, testRecords, testProducer)
		run.seal(t)
		manifestPath := filepath.Join(run.directory, "evidence-manifest.sha256")
		var kept []string
		for _, line := range readLines(t, manifestPath) {
			if !strings.HasSuffix(line, testLogName) {
				kept = append(kept, line)
			}
		}
		writeLines(t, manifestPath, kept)
		_, err := Seal(SealInput{
			EvidenceDirectory: run.directory,
			AuditLogName:      testLogName,
			RunID:             testRunID,
			ProducerDigest:    testProducer,
			Signer:            run.signer,
		})
		if err == nil ||
			!strings.Contains(err.Error(), "does not cover "+testLogName) {
			t.Fatalf("unexpected result: %v", err)
		}
	})

	t.Run("empty_trail", func(t *testing.T) {
		run := newOpenEvidence(t, 0, testProducer)
		run.seal(t)
		_, err := Seal(SealInput{
			EvidenceDirectory: run.directory,
			AuditLogName:      testLogName,
			RunID:             testRunID,
			ProducerDigest:    testProducer,
			Signer:            run.signer,
		})
		if err == nil ||
			!strings.Contains(err.Error(), "empty audit trail") {
			t.Fatalf("an empty trail was closed as evidence: %v", err)
		}
	})
}

// TestCheckpointRejectsAMutatedEnvironment covers the producer binding: the
// digest is recomputed from sealed evidence, not read back from the checkpoint.
func TestCheckpointRejectsAMutatedEnvironment(t *testing.T) {
	t.Run("rewritten_and_resealed", func(t *testing.T) {
		// The thorough version: the adversary rewrites environment.txt AND
		// re-seals the manifest, so nothing on disk is stale. Re-sealing the
		// manifest after the close is itself the detection, because the
		// checkpoint bound the manifest's digest.
		run := newEvidence(t, testRecords)
		if err := os.WriteFile(
			filepath.Join(run.directory, EnvironmentName),
			[]byte("carrier_authorization_mode=anonymous-token\nsource_digest="+
				otherProducer+"\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		run.seal(t)
		requireReject(
			t, run.verify(), "evidence manifest digest mismatch",
			"evidence whose sealed environment names a different producer",
		)
	})

	t.Run("rewritten_without_resealing", func(t *testing.T) {
		// The careless version is caught earlier, by the manifest freshness
		// cross-check, which is the correct and more specific answer.
		run := newEvidence(t, testRecords)
		if err := os.WriteFile(
			filepath.Join(run.directory, EnvironmentName),
			[]byte("source_digest="+otherProducer+"\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		requireReject(
			t, run.verify(), "evidence manifest is stale",
			"an environment rewritten without re-sealing the manifest",
		)
	})

	t.Run("environment_not_covered_by_the_manifest", func(t *testing.T) {
		run := newOpenEvidence(t, testRecords, testProducer)
		run.seal(t)
		manifestPath := filepath.Join(run.directory, "evidence-manifest.sha256")
		var kept []string
		for _, line := range readLines(t, manifestPath) {
			if !strings.HasSuffix(line, EnvironmentName) {
				kept = append(kept, line)
			}
		}
		writeLines(t, manifestPath, kept)
		_, err := Seal(SealInput{
			EvidenceDirectory: run.directory,
			AuditLogName:      testLogName,
			RunID:             testRunID,
			ProducerDigest:    testProducer,
			Signer:            run.signer,
		})
		if err == nil ||
			!strings.Contains(err.Error(), "does not cover "+EnvironmentName) {
			t.Fatalf(
				"an uncovered environment.txt would let a run name any "+
					"producer it liked; got: %v", err,
			)
		}
	})

	t.Run("auditor_expects_a_different_producer", func(t *testing.T) {
		run := newEvidence(t, testRecords)
		_, err := Verify(VerifyInput{
			EvidenceDirectory:      run.directory,
			ExpectedFinalizerKeyID: run.pin,
			ExpectedRunID:          testRunID,
			ExpectedProducerDigest: otherProducer,
			AuditLogName:           testLogName,
		})
		requireReject(
			t, err, "producer digest mismatch",
			"a checkpoint binding a producer the auditor did not expect",
		)
	})
}

// TestCheckpointIsCreateOnce proves the terminal record cannot be silently
// re-closed. Without this, an adversary who could truncate and re-seal would
// simply run the finalizer again over the shortened trail.
func TestCheckpointIsCreateOnce(t *testing.T) {
	run := newEvidence(t, testRecords)
	before, err := os.ReadFile(run.checkpointPath()) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	_, err = Seal(SealInput{
		EvidenceDirectory: run.directory,
		AuditLogName:      testLogName,
		RunID:             testRunID,
		ProducerDigest:    testProducer,
		Signer:            run.signer,
	})
	if err == nil {
		t.Fatal("a second checkpoint silently replaced the first")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("re-closing failed for an unexpected reason: %v", err)
	}
	after, err := os.ReadFile(run.checkpointPath()) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the incumbent checkpoint changed after a rejected re-close")
	}
	if err := run.verify(); err != nil {
		t.Fatalf("the original checkpoint stopped verifying: %v", err)
	}
}

// TestCheckpointRejectsADuplicateJSONKey covers a real encoding/json behaviour,
// not a hypothetical one: the standard decoder silently keeps the LAST
// occurrence of a repeated key, so a document could state record_count twice —
// one value for a human reader, another for the verifier — and
// DisallowUnknownFields would raise nothing, because neither occurrence is
// unknown.
func TestCheckpointRejectsADuplicateJSONKey(t *testing.T) {
	run := newEvidence(t, testRecords)
	content, err := os.ReadFile(run.checkpointPath()) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	doubled := strings.Replace(
		string(content),
		`"record_count":`,
		`"record_count": 1,`+"\n  "+`"record_count":`,
		1,
	)
	if doubled == string(content) {
		t.Fatal("failed to build the duplicate-key fixture")
	}
	if err := os.WriteFile(
		run.checkpointPath(), []byte(doubled), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	requireReject(
		t, run.verify(), "repeats the key",
		"a checkpoint stating record_count twice",
	)
}

// TestCheckpointRejectsANonZuluCloseTime pins the one accepted rendering of the
// close time. A zone offset would let the same instant be written two ways, so
// two byte-different signed messages would mean the same thing.
func TestCheckpointRejectsANonZuluCloseTime(t *testing.T) {
	for _, value := range []string{
		"2026-07-26T21:13:57+05:00",
		"2026-07-26T16:13:57-00:00",
		"2026-07-26T16:13:57.500Z",
		"2026-07-26 16:13:57Z",
	} {
		t.Run(value, func(t *testing.T) {
			run := newEvidence(t, testRecords)
			checkpoint := run.readCheckpoint(t)
			checkpoint.ClosedAtUTC = value
			if _, err := checkpoint.signingMessage(); err == nil {
				t.Fatalf("%q produced a signable message", value)
			}
			run.writeRaw(t, checkpoint)
			if err := run.verify(); err == nil {
				t.Fatalf("%q was accepted as a close time", value)
			}
		})
	}
}

// TestOversizedInputIsRejectedNotTruncated is the boundary+1 case. A reader
// that caps itself and never asks whether more followed would hash, and
// reconcile, a prefix of an oversized trail and report success.
func TestOversizedInputIsRejectedNotTruncated(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "oversized.bin")
	const limit = 1 << 16
	if err := os.WriteFile(
		path, make([]byte, limit+1), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRegular(path, limit); err == nil {
		t.Fatal(
			"a file one byte over the limit was opened; it would have been " +
				"silently processed as its own prefix",
		)
	} else if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("unexpected rejection: %v", err)
	}
	if err := os.WriteFile(path, make([]byte, limit), 0o600); err != nil {
		t.Fatal(err)
	}
	file, _, err := openRegular(path, limit)
	if err != nil {
		t.Fatalf("a file exactly at the limit must be accepted: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestOpenRegularRefusesASwappedTarget covers the check/open race: a name that
// is repointed between inspection and open must not be read as though the
// inspection applied to it.
func TestOpenRegularRefusesASwappedTarget(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "target")
	if err := os.WriteFile(path, []byte("real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := openRegular(link, 1<<20); err == nil {
		t.Fatal("a symlink was opened as a regular evidence file")
	}
}

// --- concurrency ----------------------------------------------------------

// TestCheckpointFinalizeRaceNeverAcceptsAnOpenTrail runs the finalizer against
// a log that is still being appended to, which is precisely the ordering
// violation the design forbids.
//
// The required property is not that Seal wins the race — it is that no outcome
// of the race produces evidence that verifies while records were still being
// written. Either Seal refuses (the log moved under it), or it closes a prefix
// and Verify then reports the post-close records.
func TestCheckpointFinalizeRaceNeverAcceptsAnOpenTrail(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, testLogName)
	log, err := audit.Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, EnvironmentName),
		[]byte("source_digest="+testProducer+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	// Seed the trail so there is something to seal, and seal a manifest over
	// it. Both will be stale by the time the writer is done, which is the
	// point.
	for index := 0; index < 4; index++ {
		if err := log.Record("carrier_seed", "device", "", "detail"); err != nil {
			t.Fatal(err)
		}
	}
	seed, err := GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(FinalizerAlgorithm, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	run := &evidence{directory: directory, pin: signer.KeyID(), signer: signer}
	run.seal(t)

	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := log.Record(
				"carrier_concurrent", "device", "", "detail",
			); err != nil {
				return
			}
		}
	}()

	sealErr := func() error {
		_, err := Seal(SealInput{
			EvidenceDirectory: directory,
			AuditLogName:      testLogName,
			RunID:             testRunID,
			ProducerDigest:    testProducer,
			Signer:            signer,
		})
		return err
	}()
	close(stop)
	writers.Wait()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	if sealErr != nil {
		// The finalizer noticed the trail moving and refused. Acceptable, and
		// it must say so specifically — by one of the three ways the movement
		// can show itself: the log grew between the scan and the hash, the log
		// grew during a single read, or the manifest no longer describes it.
		if !strings.Contains(sealErr.Error(), "changed while the checkpoint") &&
			!strings.Contains(sealErr.Error(), "changed while it was being read") &&
			!strings.Contains(sealErr.Error(), "evidence manifest is stale") {
			t.Fatalf("seal failed for an unexpected reason: %v", sealErr)
		}
		return
	}
	// The finalizer closed a prefix. Verification must now report that records
	// followed the close, and must never accept the directory.
	err = run.verify()
	if err == nil {
		t.Fatal(
			"a checkpoint sealed while records were still being written was " +
				"accepted; the trail was open when it was declared closed",
		)
	}
	if !strings.Contains(err.Error(), "grew after the checkpoint was sealed") &&
		!strings.Contains(err.Error(), "evidence manifest is stale") {
		t.Fatalf("unexpected rejection of a raced seal: %v", err)
	}
}

// --- signing message ------------------------------------------------------

// TestSigningMessageIsUnambiguous proves the canonical message cannot be forged
// by field content: every component is restricted to a charset containing
// neither the separator nor the terminator.
func TestSigningMessageIsUnambiguous(t *testing.T) {
	base := Checkpoint{
		Schema:             Schema,
		RunID:              testRunID,
		AuditLogName:       testLogName,
		FinalSequence:      3,
		RecordCount:        3,
		ChainHeadMAC:       strings.Repeat("77", 32),
		AuditLogSHA256:     strings.Repeat("88", 32),
		ManifestName:       "evidence-manifest.sha256",
		ManifestSHA256:     strings.Repeat("99", 32),
		ProducerDigest:     testProducer,
		ClosedAtUTC:        time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		FinalizerAlgorithm: FinalizerAlgorithm,
		FinalizerKeyID:     strings.Repeat("aa", 32),
	}
	if _, err := base.signingMessage(); err != nil {
		t.Fatalf("a well-formed checkpoint must render: %v", err)
	}
	for name, mutate := range map[string]func(*Checkpoint){
		"newline_in_run_id":   func(c *Checkpoint) { c.RunID = "a\nrecord_count=1" },
		"equals_in_run_id":    func(c *Checkpoint) { c.RunID = "a=b" },
		"slash_in_log_name":   func(c *Checkpoint) { c.AuditLogName = "../etc/passwd" },
		"short_digest":        func(c *Checkpoint) { c.ChainHeadMAC = "abc" },
		"uppercase_digest":    func(c *Checkpoint) { c.AuditLogSHA256 = strings.ToUpper(strings.Repeat("ab", 32)) },
		"unknown_schema":      func(c *Checkpoint) { c.Schema = "winn-audit-checkpoint/v2" },
		"unknown_algorithm":   func(c *Checkpoint) { c.FinalizerAlgorithm = "HMAC-SHA-256" },
		"zero_record_count":   func(c *Checkpoint) { c.RecordCount = 0 },
		"non_canonical_close": func(c *Checkpoint) { c.ClosedAtUTC = "2026-07-26 16:13:57" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := base
			mutate(&mutated)
			if _, err := mutated.signingMessage(); err == nil {
				t.Fatalf("%s produced a signable message", name)
			}
		})
	}
}

// TestScanChainIsKeyless proves the finalizer never needs the audit HMAC key:
// the structural facts the checkpoint binds are all readable without it.
func TestScanChainIsKeyless(t *testing.T) {
	run := newEvidence(t, testRecords)
	chain, err := ScanChain(run.logPath())
	if err != nil {
		t.Fatal(err)
	}
	if chain.RecordCount != testRecords || chain.FinalSequence != testRecords {
		t.Fatalf("scan produced %+v", chain)
	}
	if !lowerHex(chain.HeadMAC, 64) || chain.HeadMAC == zeroMAC {
		t.Fatalf("scan produced head MAC %q", chain.HeadMAC)
	}
	lines := readLines(t, run.logPath())
	var tail struct {
		Authentication string `json:"authentication"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &tail); err != nil {
		t.Fatal(err)
	}
	if chain.HeadMAC != tail.Authentication {
		t.Fatalf(
			"scan head MAC %s is not the final record's own MAC %s",
			chain.HeadMAC, tail.Authentication,
		)
	}
	// Sanity: the digest helper agrees with an independent hash.
	content, err := os.ReadFile(run.logPath()) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	got, err := sha256File(run.logPath())
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(sum[:]) {
		t.Fatal("sha256File disagrees with an independent hash")
	}
}

// TestGrowthDuringReadIsRejected covers the case an upfront size check cannot
// reach: a file that is within the limit when it is opened and grows while it
// is being read.
//
// The limit is therefore enforced on the read — through maximum+1 bytes, so
// that "exactly at the limit" and "over it" produce different observations —
// and the descriptor is re-stat'd at EOF so growth that landed beyond what was
// consumed is caught too. A prefix is never accepted as the whole file.
func TestGrowthDuringReadIsRejected(t *testing.T) {
	t.Run("consumed_more_than_the_limit", func(t *testing.T) {
		// A reader handed more bytes than the limit must refuse, not truncate.
		const limit = 64
		reader := boundedReader(bytes.NewReader(make([]byte, limit+1)), limit, limit+1)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			t.Fatal(err)
		}
		if reader.consumed() != limit+1 {
			t.Fatalf("consumed %d bytes, want %d", reader.consumed(), limit+1)
		}
		file, err := os.CreateTemp(t.TempDir(), "grown-*")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := reader.check(file, file.Name()); err == nil {
			t.Fatal("a read past the limit was accepted")
		} else if !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})

	t.Run("exactly_at_the_limit_is_accepted", func(t *testing.T) {
		// The boundary itself must still pass, or the +1 probe would have
		// turned a correct file into a rejection.
		const limit = 64
		directory := t.TempDir()
		path := filepath.Join(directory, "at-limit.bin")
		if err := os.WriteFile(path, make([]byte, limit), 0o600); err != nil {
			t.Fatal(err)
		}
		file, atOpen, err := openRegular(path, limit)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		reader := boundedReader(file, limit, atOpen)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			t.Fatal(err)
		}
		if err := reader.check(file, path); err != nil {
			t.Fatalf("a file exactly at the limit was rejected: %v", err)
		}
	})

	t.Run("a_file_that_grew_after_open_is_rejected", func(t *testing.T) {
		// The window an upfront size check cannot reach, reproduced exactly:
		// the descriptor is opened and sized, the file then grows, and the read
		// that follows is the one that would have exceeded the bound.
		path := growAfterOpenFixture(t)
		file, atOpen, err := openRegularWithHook(path, maximumAuditBytes, grow(t))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		reader := boundedReader(file, maximumAuditBytes, atOpen)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			t.Fatal(err)
		}
		err = reader.check(file, path)
		if err == nil {
			t.Fatal(
				"a file that grew after it was opened was accepted; the bytes " +
					"read were treated as the whole file",
			)
		}
		if !strings.Contains(err.Error(), "changed while it was being read") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})

	t.Run("ScanChain_and_sha256File_use_the_bounded_path", func(t *testing.T) {
		// Both readers must go through boundedRead.check, so a trail that grew
		// is rejected rather than scanned or hashed as a prefix. Asserted by
		// construction here: an oversized file is refused by both.
		directory := t.TempDir()
		path := filepath.Join(directory, "oversized.jsonl")
		file, err := os.Create(path) // #nosec G304 -- test temp path
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maximumAuditBytes + 1); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := sha256File(path); err == nil ||
			!strings.Contains(err.Error(), "over the") {
			t.Fatalf("sha256File accepted an oversized file: %v", err)
		}
		if _, err := ScanChain(path); err == nil ||
			!strings.Contains(err.Error(), "over the") {
			t.Fatalf("ScanChain accepted an oversized trail: %v", err)
		}
	})
}

// growAfterOpenFixture returns a file that is comfortably within the limit.
// grow returns the callback that enlarges it in the window between open and
// read — the window the whole bounded-read design exists to cover, and one that
// a plain filesystem test cannot reach without racing an appender against a
// reader and hoping.
func growAfterOpenFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "growing.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func grow(t *testing.T) func(string) {
	t.Helper()
	grown := false
	return func(path string) {
		if grown {
			return
		}
		grown = true
		appended, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := appended.Write(make([]byte, 4096)); err != nil {
			t.Error(err)
		}
		if err := appended.Close(); err != nil {
			t.Error(err)
		}
	}
}
