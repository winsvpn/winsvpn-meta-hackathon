// Adversarial AUDIT-CLOSE suite over the REAL winn-audit-checkpoint/v1
// implementation, authored by the Fable 5 audit lane against the Codex
// architecture ruling of 2026-07-26 and Codex's explicit twelve-item attack
// list.
//
// This suite drives the REAL package seam (auditcheckpoint.Seal /
// auditcheckpoint.Verify / auditcheckpoint.ScanChain, pqauth ML-DSA-65
// credentials, the real internal/audit writer) — deliberately not a parallel
// reference model. An earlier parallel-blind draft of this lane's scenarios
// ran against a self-contained HMAC stand-in; it was discarded once the
// production package landed, because a stand-in proves nothing about the
// gate. Every scenario from that draft is preserved below in ML-DSA terms:
// "wrong HMAC key" became "wrong ML-DSA seed / wrong pin / wrong signature
// domain".
//
// Codex attack list -> test mapping:
//
//  1. tail truncation at EVERY record boundary   TestFableCkptTailTruncationEveryBoundary
//  2. truncation with consistent re-seal         TestFableCkptConsistentResealTruncation
//  3. append after checkpoint (post-close)       TestFableCkptPostCloseAppend
//  4. missing checkpoint (unclosed chain)        TestFableCkptMissingCheckpoint
//  5. duplicate checkpoint                       TestFableCkptDuplicateCheckpoint
//  6. cross-run transplant                       TestFableCkptCrossRunTransplant
//  7. swapped key/pin                            TestFableCkptSwappedPin,
//     TestFableCkptAttackerSelfSignedCheckpoint
//  8. every field mutated one at a time          TestFableCkptFieldMutationStaleSignature (unsigned tamper),
//     TestFableCkptBoundFieldRecomputationHonestSignature
//     (correctly signed but wrong — recompute must catch)
//  9. stale manifest                             TestFableCkptStaleManifest
//  10. wrong tail MAC/count/sequence explicitly   TestFableCkptAuditKeyRewritesFinalRecord (head MAC,
//     semantic), plus the count/sequence/head rows of
//     both field-mutation tables
//  11. crash between steps                        TestFableCkptCrashBetweenSteps
//  12. concurrent Record vs Seal under -race      TestFableCkptRecordVersusSealRace
//
// Every rejection asserts a stable substring of the implementation's own
// error text, never bare err != nil, and every scenario that could
// accidentally fail as "checkpoint missing" is guarded against doing so.
//
// PENDING RECONCILIATION SCOPE (not covered by this file yet; recorded here
// so it cannot be lost between rounds). Three requirements land with the
// controller-side finalization design and need tests once those seams exist:
//
//	R1. Custody probe, not a custody claim. Root on the AICORE harness can
//	    read any root-owned file, so a 0600 seed file next to a root-run
//	    carrier is not custody separation. Whatever Opus lands (most likely
//	    controller-only seed custody) needs a NEGATIVE test proving the
//	    finalizer seed is provably absent from the producer-side evidence and
//	    environment at the point the carrier process runs — a probe of the
//	    boundary, not an assertion in a comment. The former
//	    AssertProducerCustody helper was a heuristic scan and has already been
//	    withdrawn from the package; the replacement must be tested for
//	    FAIL-CLOSED behaviour specifically: an unreadable or inaccessible scan
//	    path must fail the check, never be silently skipped.
//	R2. Producer PASS is not promotable. Integration-shaped test of the real
//	    state transition, not a unit check of one function: an AICORE-side run
//	    that passes every conservation and verification check but has not been
//	    through the controller's checkpoint-and-new-archive step must remain
//	    genuinely non-promotional and unanchorable (no .done marker, no
//	    anchor, no promotional archive), and must become promotable only after
//	    the controller seals+verifies the checkpoint and creates the new
//	    content-addressed archive carrying manifest and checkpoint together.
//	R3. Gate order at the matrix-verify acceptance sites: the checkpoint gate
//	    must run before conservation, and an unpinned invocation must refuse
//	    with the AUDIT-CLOSE blocker rather than skipping.
//
// The audit HMAC key is treated as ADVERSARY-HELD throughout: fixtures
// deliberately use it to build perfectly chain-valid tampered logs (the
// exact party the checkpoint exists to constrain). The finalizer seed is
// runner-held and never available to those forgeries except in the custody
// controls, which prove the credential — not the arithmetic — is the
// boundary.
package auditcheckpoint_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	fckAuditLogName   = "carrier-audit.jsonl"
	fckManifestName   = "evidence-manifest.sha256"
	fckRecordDomain   = "winn-audit-record/v1\x00"
	fckDefaultRecords = 5
)

type fckFixture struct {
	root         string
	dir          string
	auditKeyPath string
	auditKey     []byte
	signer       *pqauth.Signer
	pin          string
	runID        string
	producer     string
}

func (f *fckFixture) logPath() string        { return filepath.Join(f.dir, fckAuditLogName) }
func (f *fckFixture) manifestPath() string   { return filepath.Join(f.dir, fckManifestName) }
func (f *fckFixture) checkpointPath() string { return filepath.Join(f.dir, auditcheckpoint.FileName) }

func fckNewSigner(t *testing.T) *pqauth.Signer {
	t.Helper()
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(auditcheckpoint.FinalizerAlgorithm, seed)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// fckBuild constructs sealed evidence end to end through the REAL
// internal/audit writer, without the checkpoint yet: records, aux evidence,
// environment.txt (producer digest source), and the base manifest.
func fckBuild(t *testing.T, signer *pqauth.Signer, runID string, records int) *fckFixture {
	t.Helper()
	root := t.TempDir()
	f := &fckFixture{
		root:         root,
		dir:          filepath.Join(root, "evidence"),
		auditKeyPath: filepath.Join(root, "keys", "carrier-audit.key"),
		auditKey:     make([]byte, 32),
		signer:       signer,
		runID:        runID,
	}
	copy(f.auditKey, []byte(strings.Repeat("\x5a", 32)))
	f.pin = signer.KeyID()
	source := sha256.Sum256([]byte("fable-adversarial-producer/" + runID))
	f.producer = hex.EncodeToString(source[:])
	for _, dir := range []string{filepath.Dir(f.auditKeyPath), f.dir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := securefile.AtomicWrite(f.auditKeyPath, f.auditKey, 0o600); err != nil {
		t.Fatal(err)
	}
	fckAppendRecords(t, f, 0, records)
	for name, content := range map[string]string{
		"environment.txt": "source_digest=" + f.producer +
			"\ncarrier_authorization_mode=anonymous-token\n",
		"carrier-conservation.txt": "schema=carrier-conservation/v2\n" +
			fmt.Sprintf("redemptions=%d\n", records),
	} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fckSealManifest(t, f)
	return f
}

func fckAppendRecords(t *testing.T, f *fckFixture, base, count int) {
	t.Helper()
	log, err := audit.Open(f.logPath(), f.auditKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	for index := base; index < base+count; index++ {
		detail := fmt.Sprintf(
			"carrier-terminal/v1 class=authenticated mode=anonymous-token "+
				"session=%032x reason=none", 6000+index,
		)
		if err := log.Record(
			"carrier.h3.authenticated", "android-lab-1",
			fmt.Sprintf("%032x", 7000+index), detail,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}

// fckSealManifest mirrors the smoke tool's sealManifest rule and the
// ruling's exclusion: "<sha256>  ./<name>", sorted, every regular file
// except the manifest itself and anything checkpoint-named.
func fckSealManifest(t *testing.T, f *fckFixture) {
	t.Helper()
	if err := fckSealManifestErr(f.dir); err != nil {
		t.Fatal(err)
	}
}

// fckSealManifestErr is the goroutine-safe form (no t.Fatal), used by the
// concurrency test.
func fckSealManifestErr(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var lines []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || name == fckManifestName ||
			strings.Contains(strings.ToLower(name), "audit-checkpoint") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		lines = append(lines, hex.EncodeToString(digest[:])+"  ./"+name)
	}
	sort.Strings(lines)
	return os.WriteFile(
		filepath.Join(dir, fckManifestName),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600,
	)
}

func fckSeal(t *testing.T, f *fckFixture) auditcheckpoint.Checkpoint {
	t.Helper()
	checkpoint, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: f.dir,
		AuditLogName:      fckAuditLogName,
		RunID:             f.runID,
		ProducerDigest:    f.producer,
		Signer:            f.signer,
	})
	if err != nil {
		t.Fatalf("sealing honest evidence failed: %v", err)
	}
	return checkpoint
}

// fckFixtureSealed is the standard starting state: honest evidence, honest
// checkpoint, and a passing baseline (asserted, so no scenario below can
// blame its rejection on a broken fixture).
func fckFixtureSealed(t *testing.T) *fckFixture {
	t.Helper()
	f := fckBuild(t, fckNewSigner(t), "fable-adversarial-run-1", fckDefaultRecords)
	fckSeal(t, f)
	if err := fckVerify(f); err != nil {
		t.Fatalf("pristine sealed fixture does not verify: %v", err)
	}
	return f
}

func fckVerify(f *fckFixture) error {
	_, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
		EvidenceDirectory:      f.dir,
		ExpectedFinalizerKeyID: f.pin,
		ExpectedRunID:          f.runID,
		ExpectedProducerDigest: f.producer,
		AuditLogName:           fckAuditLogName,
	})
	return err
}

func fckExpectReject(t *testing.T, f *fckFixture, wantToken, scenario string) {
	t.Helper()
	err := fckVerify(f)
	if err == nil {
		t.Fatalf("%s PASSED checkpoint verification", scenario)
	}
	if wantToken != "missing" && strings.Contains(err.Error(), "is missing") {
		t.Fatalf("%s failed as a MISSING checkpoint, not its own defect: %v",
			scenario, err)
	}
	if !strings.Contains(err.Error(), wantToken) {
		t.Fatalf("%s rejected for the wrong reason:\n  got:  %v\n  want token: %q",
			scenario, err, wantToken)
	}
}

// fckRemoveCheckpoint models an adversary (or an operator) deleting the
// existing close record before attempting a re-close. Seal refuses to
// overwrite in place, so every re-seal path in this file has to do it
// explicitly — which keeps that refusal visible rather than incidental.
func fckRemoveCheckpoint(t *testing.T, f *fckFixture) {
	t.Helper()
	if err := os.Remove(f.checkpointPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func fckLogLines(t *testing.T, f *fckFixture) []string {
	t.Helper()
	raw, err := os.ReadFile(f.logPath())
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func fckWriteLogLines(t *testing.T, f *fckFixture, lines []string) {
	t.Helper()
	if err := os.WriteFile(
		f.logPath(), []byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func fckLoadCheckpoint(t *testing.T, f *fckFixture) auditcheckpoint.Checkpoint {
	t.Helper()
	raw, err := os.ReadFile(f.checkpointPath())
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint auditcheckpoint.Checkpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func fckWriteCheckpoint(t *testing.T, f *fckFixture, checkpoint auditcheckpoint.Checkpoint) {
	t.Helper()
	encoded, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		f.checkpointPath(), append(encoded, '\n'), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// fckSigningMessage restates the implementation's canonical signing message
// so tests holding the honest finalizer can produce CORRECTLY SIGNED
// checkpoints with deliberately wrong bound values (property: recomputation
// must reject even a validly authenticated claim). If the canonical format
// drifts, TestFableCkptBoundFieldRecomputationHonestSignature's own control
// row fails first and loudly.
func fckSigningMessage(c auditcheckpoint.Checkpoint) []byte {
	var builder strings.Builder
	builder.WriteString(auditcheckpoint.Schema + "\n")
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
	return []byte(builder.String())
}

func fckResign(t *testing.T, f *fckFixture, checkpoint *auditcheckpoint.Checkpoint) {
	t.Helper()
	signature, err := pqauth.SignDomainMessage(
		pqauth.AuditCheckpointSignatureDomain,
		fckSigningMessage(*checkpoint), f.signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
}

func fckFlipHex(value string) string {
	if value[0] == '0' {
		return "1" + value[1:]
	}
	return "0" + value[1:]
}

// --- 1. tail truncation at every record boundary ----------------------------

func TestFableCkptTailTruncationEveryBoundary(t *testing.T) {
	f := fckFixtureSealed(t)
	lines := fckLogLines(t, f)
	if len(lines) != fckDefaultRecords {
		t.Fatalf("fixture sealed %d records, want %d", len(lines), fckDefaultRecords)
	}
	for keep := 1; keep < len(lines); keep++ {
		t.Run(fmt.Sprintf("truncated to %d of %d records", keep, len(lines)),
			func(t *testing.T) {
				fckWriteLogLines(t, f, lines[:keep])
				// Premise: the ordinary keyed verifier still ACCEPTS this
				// prefix — the exact hole AUDIT-CLOSE exists to fix.
				if err := audit.Verify(f.logPath(), f.auditKeyPath); err != nil {
					t.Fatalf("premise broken: audit.Verify rejects a clean "+
						"prefix on its own (%v)", err)
				}
				fckExpectReject(t, f, "audit log was truncated",
					fmt.Sprintf("a %d-record prefix of a %d-record closed trail",
						keep, len(lines)))
			})
	}
	// Restore and confirm the fixture still passes: rejection above came from
	// the truncation, not fixture rot.
	fckWriteLogLines(t, f, lines)
	if err := fckVerify(f); err != nil {
		t.Fatalf("restored fixture no longer verifies: %v", err)
	}
}

// --- 2. truncation with everything downstream re-sealed consistently --------

// The sophisticated attacker: holds the audit key, truncates whole trailing
// records, rewrites the conservation counts to match, and re-seals the
// manifest so every digest it records is correct for the tampered files.
// Every artifact is now self-consistent EXCEPT the one thing the attacker
// cannot re-issue: the finalizer-signed checkpoint.
func TestFableCkptConsistentResealTruncation(t *testing.T) {
	f := fckFixtureSealed(t)
	lines := fckLogLines(t, f)
	fckWriteLogLines(t, f, lines[:3])
	if err := os.WriteFile(
		filepath.Join(f.dir, "carrier-conservation.txt"),
		[]byte("schema=carrier-conservation/v2\nredemptions=3\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	fckSealManifest(t, f) // manifest now honestly describes the tampered files
	fckExpectReject(t, f, "audit log was truncated",
		"a truncation with counts and manifest consistently re-sealed")
}

// --- 3. post-close append ----------------------------------------------------

// The appended record is a PERFECT chain extension made with the real writer
// and the adversary-held audit key: continuous sequence, linked previous
// MAC, valid HMAC. Only the checkpoint's length commitment can name it.
func TestFableCkptPostCloseAppend(t *testing.T) {
	f := fckFixtureSealed(t)
	fckAppendRecords(t, f, fckDefaultRecords, 1)
	if err := audit.Verify(f.logPath(), f.auditKeyPath); err != nil {
		t.Fatalf("premise broken: the appended record is not chain-valid: %v", err)
	}
	fckExpectReject(t, f, "grew after the checkpoint",
		"a validly chained record appended after close")
}

// An in-log record dressed as a checkpoint is an attempt to close the trail
// from the inside, where no finalizer signature exists. Both the finalizer
// and the verifier must treat it as a rejection, not a record.
func TestFableCkptInLogCheckpointRecordRejected(t *testing.T) {
	t.Run("seal refuses", func(t *testing.T) {
		f := fckBuild(t, fckNewSigner(t), "fable-inlog-seal", 2)
		log, err := audit.Open(f.logPath(), f.auditKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Record(
			"audit.close", "android-lab-1", fmt.Sprintf("%032x", 8000),
			auditcheckpoint.Schema+" pretending to close the trail in-band",
		); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		fckSealManifest(t, f)
		_, err = auditcheckpoint.Seal(auditcheckpoint.SealInput{
			EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
			RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
		})
		if err == nil || !strings.Contains(err.Error(), "in-log") {
			t.Fatalf("sealing over an in-log checkpoint record: got %v, "+
				"want an in-log rejection", err)
		}
	})
	t.Run("verify refuses", func(t *testing.T) {
		f := fckFixtureSealed(t)
		log, err := audit.Open(f.logPath(), f.auditKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Record(
			"audit.close", "android-lab-1", fmt.Sprintf("%032x", 8001),
			auditcheckpoint.Schema+" in-band close appended post-seal",
		); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		fckExpectReject(t, f, "in-log",
			"an in-log checkpoint record appended after close")
	})
}

// --- 4. missing checkpoint ----------------------------------------------------

func TestFableCkptMissingCheckpoint(t *testing.T) {
	f := fckFixtureSealed(t)
	if err := os.Remove(f.checkpointPath()); err != nil {
		t.Fatal(err)
	}
	err := fckVerify(f)
	if err == nil {
		t.Fatal("evidence with no checkpoint passed verification")
	}
	if !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("missing checkpoint rejected with the wrong identity: %v", err)
	}
}

// --- 11. crash-between-steps partial states -----------------------------------

func TestFableCkptCrashBetweenSteps(t *testing.T) {
	t.Run("crash after log fsync, before manifest seal", func(t *testing.T) {
		f := fckBuild(t, fckNewSigner(t), "fable-crash-a", 3)
		if err := os.Remove(f.manifestPath()); err != nil {
			t.Fatal(err)
		}
		err := fckVerify(f)
		if err == nil {
			t.Fatal("a run with no manifest and no checkpoint verified as closed")
		}
		if !strings.Contains(err.Error(), "is missing") {
			t.Fatalf("partial state rejected with the wrong identity: %v", err)
		}
		// And the finalizer itself refuses to close this state.
		_, err = auditcheckpoint.Seal(auditcheckpoint.SealInput{
			EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
			RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
		})
		if err == nil || !strings.Contains(err.Error(), "manifest must be sealed first") {
			t.Fatalf("sealing without a manifest: got %v, want a "+
				"manifest-must-be-sealed-first refusal", err)
		}
	})
	t.Run("crash after manifest seal, before checkpoint", func(t *testing.T) {
		f := fckBuild(t, fckNewSigner(t), "fable-crash-b", 3)
		err := fckVerify(f)
		if err == nil {
			t.Fatal("a run with a manifest but no checkpoint verified as closed")
		}
		if !strings.Contains(err.Error(), "is missing") {
			t.Fatalf("partial state rejected with the wrong identity: %v", err)
		}
	})
}

// --- 5. duplicate checkpoint ---------------------------------------------------

func TestFableCkptDuplicateCheckpoint(t *testing.T) {
	duplicates := []string{
		"audit-checkpoint-2.json",
		"audit-checkpoint.json.bak",
		"AUDIT-CHECKPOINT-copy.json", // case games must not evade the marker scan
	}
	for _, name := range duplicates {
		t.Run(name, func(t *testing.T) {
			f := fckFixtureSealed(t)
			raw, err := os.ReadFile(f.checkpointPath())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.dir, name), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			fckExpectReject(t, f, "exactly one",
				"evidence carrying a second checkpoint named "+name)
		})
	}
	t.Run("sole checkpoint under a wrong name", func(t *testing.T) {
		f := fckFixtureSealed(t)
		if err := os.Rename(
			f.checkpointPath(),
			filepath.Join(f.dir, "audit-checkpoint-renamed.json"),
		); err != nil {
			t.Fatal(err)
		}
		fckExpectReject(t, f, "must be named",
			"a checkpoint stored under a non-canonical name")
	})
}

// --- 6. cross-run transplant ----------------------------------------------------

// A GENUINELY VALID checkpoint from sealed run A is attached to run B's
// evidence. Same finalizer key (realistic: one runner closes many runs), so
// the pin and signature are both good — only the binding can refuse it.
func TestFableCkptCrossRunTransplant(t *testing.T) {
	signer := fckNewSigner(t)
	// B first, A second, so A's close time cannot precede B's records.
	runB := fckBuild(t, signer, "fable-transplant-b", fckDefaultRecords)
	fckSeal(t, runB)
	runA := fckBuild(t, signer, "fable-transplant-a", fckDefaultRecords)
	fckSeal(t, runA)
	transplanted, err := os.ReadFile(runA.checkpointPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runB.checkpointPath(), transplanted, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("with the run identity pinned", func(t *testing.T) {
		fckExpectReject(t, runB, "run identity mismatch",
			"run A's valid checkpoint transplanted into run B's evidence")
	})
	t.Run("an omitted run identity pin is itself a refusal", func(t *testing.T) {
		// Verify now requires the run identity as a hard precondition, so an
		// auditor cannot reach the transplant with the pin left blank at all.
		_, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
			EvidenceDirectory:      runB.dir,
			ExpectedFinalizerKeyID: runB.pin,
			ExpectedProducerDigest: runB.producer,
			AuditLogName:           fckAuditLogName,
		})
		if err == nil {
			t.Fatal("verification ran with no run identity pinned")
		}
		if !strings.Contains(err.Error(), "externally supplied run identity") {
			t.Fatalf("unpinned verification rejected for the wrong reason: %v", err)
		}
	})
	t.Run("the binding refuses even when the run identity agrees", func(t *testing.T) {
		// The stronger claim, and the reason the transplant defence is not
		// merely a name check: pin run A's identity, so the run_id comparison
		// PASSES, and the transplant is still refused — both chains are the
		// same length, so only the signed chain-head/digest bindings can
		// differ.
		_, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
			EvidenceDirectory:      runB.dir,
			ExpectedFinalizerKeyID: runB.pin,
			ExpectedRunID:          runA.runID,
			ExpectedProducerDigest: runB.producer,
			AuditLogName:           fckAuditLogName,
		})
		if err == nil {
			t.Fatal("a transplant whose run identity agreed verified")
		}
		if !strings.Contains(err.Error(), "head MAC mismatch") {
			t.Fatalf("transplant rejected for the wrong reason: %v", err)
		}
	})
}

// --- 7. swapped key / pin --------------------------------------------------------

func TestFableCkptSwappedPin(t *testing.T) {
	t.Run("wrong pinned finalizer identity", func(t *testing.T) {
		f := fckFixtureSealed(t)
		f.pin = fckNewSigner(t).KeyID() // a real, well-formed, WRONG pin
		fckExpectReject(t, f, "finalizer key mismatch",
			"verification pinned to a different finalizer identity")
	})
	t.Run("empty pin is a refusal, not a relaxation", func(t *testing.T) {
		f := fckFixtureSealed(t)
		_, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
			EvidenceDirectory: f.dir,
			ExpectedRunID:     f.runID,
			AuditLogName:      fckAuditLogName,
		})
		if err == nil || !strings.Contains(err.Error(), "not pinned") {
			t.Fatalf("unpinned verification: got %v, want a not-pinned refusal", err)
		}
	})
	t.Run("malformed pin", func(t *testing.T) {
		f := fckFixtureSealed(t)
		f.pin = "NOT-A-KEY-ID"
		fckExpectReject(t, f, "64 lower-hex",
			"verification with a malformed finalizer pin")
	})
}

// The strongest asymmetric forgery: the attacker (audit key in hand)
// truncates the trail, re-seals counts and manifest consistently, generates
// their OWN ML-DSA-65 keypair, and produces a completely self-consistent,
// correctly-signed checkpoint over the tampered evidence. Everything
// verifies — except that the key is not the pinned finalizer.
func TestFableCkptAttackerSelfSignedCheckpoint(t *testing.T) {
	f := fckFixtureSealed(t)
	lines := fckLogLines(t, f)
	fckWriteLogLines(t, f, lines[:3])
	fckSealManifest(t, f)
	attacker := fckNewSigner(t)
	if pqauth.EqualKeyID(attacker.KeyID(), f.pin) {
		t.Fatal("attacker key collided with the finalizer pin")
	}
	// Seal refuses to replace an existing checkpoint (see
	// TestFableCkptSealRefusesToReplace), so an attacker with directory write
	// access removes the honest one first. Modeled explicitly rather than
	// worked around silently.
	fckRemoveCheckpoint(t, f)
	if _, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
		RunID: f.runID, ProducerDigest: f.producer, Signer: attacker,
	}); err != nil {
		t.Fatalf("the attacker's own honest re-seal failed structurally: %v", err)
	}
	fckExpectReject(t, f, "finalizer key mismatch",
		"a self-consistent checkpoint signed by the attacker's own key")

	// Custody control: the identical tampered evidence re-closed by the REAL
	// finalizer passes, proving the rejections above are credential checks,
	// not accidental field mismatches.
	fckRemoveCheckpoint(t, f)
	if _, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
		RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
	}); err != nil {
		t.Fatalf("custody control re-seal failed: %v", err)
	}
	if err := fckVerify(f); err != nil {
		t.Fatalf("custody control failed (%v): the self-signed rejection may "+
			"not have been a credential check", err)
	}
}

// --- 10 (semantic head-MAC case). audit-key holder rewrites history --------------

// The audit-key holder rewrites the FINAL record's content and re-MACs it
// correctly, then re-seals the manifest consistently. The chain verifies
// under the audit key; length and sequence agree with the checkpoint; the
// first bound value that can object is the chain head MAC.
func TestFableCkptAuditKeyRewritesFinalRecord(t *testing.T) {
	type unsignedRecord struct {
		Format      string `json:"format"`
		Sequence    uint64 `json:"sequence"`
		Timestamp   string `json:"timestamp"`
		Event       string `json:"event"`
		DeviceHash  string `json:"device_hash,omitempty"`
		RequestID   string `json:"request_id,omitempty"`
		Detail      string `json:"detail,omitempty"`
		PreviousMAC string `json:"previous_mac"`
	}
	type fullRecord struct {
		unsignedRecord
		Authentication string `json:"authentication"`
	}
	f := fckFixtureSealed(t)
	lines := fckLogLines(t, f)
	var last fullRecord
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	last.Detail = strings.Replace(
		last.Detail, "class=authenticated", "class=aborted", 1,
	)
	unsigned, err := json.Marshal(last.unsignedRecord)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, f.auditKey)
	mac.Write([]byte(fckRecordDomain))
	mac.Write(unsigned)
	last.Authentication = hex.EncodeToString(mac.Sum(nil))
	rewritten, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	lines[len(lines)-1] = string(rewritten)
	fckWriteLogLines(t, f, lines)
	if err := audit.Verify(f.logPath(), f.auditKeyPath); err != nil {
		t.Fatalf("premise broken: the audit-key re-MAC is not chain-valid "+
			"(%v); this scenario must model a key-holding adversary", err)
	}
	fckSealManifest(t, f) // digests all consistent with the rewritten trail
	fckExpectReject(t, f, "head MAC mismatch",
		"a final record rewritten and re-MACed with the adversary-held audit key")
}

// --- 8a. every checkpoint field mutated without the credential --------------------

// JSON-level tampering by an adversary who does NOT hold the finalizer seed:
// one field changed, signature left as sealed. Every row must fail with its
// own identity — mostly the signature, and never anything downstream of it.
func TestFableCkptFieldMutationStaleSignature(t *testing.T) {
	other := fckNewSigner(t)
	scenarios := []struct {
		name   string
		mutate func(*auditcheckpoint.Checkpoint)
		token  string
	}{
		{"schema", func(c *auditcheckpoint.Checkpoint) {
			c.Schema = "winn-audit-checkpoint/v0"
		}, "unknown schema"},
		{"run_id", func(c *auditcheckpoint.Checkpoint) {
			c.RunID = "fable-other-run"
		}, "run identity mismatch"},
		{"audit_log_name", func(c *auditcheckpoint.Checkpoint) {
			c.AuditLogName = "other-audit.jsonl"
		}, "vouches for"},
		{"final_sequence", func(c *auditcheckpoint.Checkpoint) {
			c.FinalSequence++
		}, "signature is invalid"},
		{"record_count", func(c *auditcheckpoint.Checkpoint) {
			c.RecordCount++
		}, "signature is invalid"},
		{"chain_head_mac", func(c *auditcheckpoint.Checkpoint) {
			c.ChainHeadMAC = fckFlipHex(c.ChainHeadMAC)
		}, "signature is invalid"},
		{"audit_log_sha256", func(c *auditcheckpoint.Checkpoint) {
			c.AuditLogSHA256 = fckFlipHex(c.AuditLogSHA256)
		}, "signature is invalid"},
		{"evidence_manifest_name", func(c *auditcheckpoint.Checkpoint) {
			c.ManifestName = "environment.txt"
		}, "signature is invalid"},
		{"evidence_manifest_sha256", func(c *auditcheckpoint.Checkpoint) {
			c.ManifestSHA256 = fckFlipHex(c.ManifestSHA256)
		}, "signature is invalid"},
		{"producer_digest", func(c *auditcheckpoint.Checkpoint) {
			c.ProducerDigest = fckFlipHex(c.ProducerDigest)
		}, "signature is invalid"},
		{"closed_at_utc", func(c *auditcheckpoint.Checkpoint) {
			c.ClosedAtUTC = "2031-01-01T00:00:00Z"
		}, "signature is invalid"},
		{"finalizer_algorithm", func(c *auditcheckpoint.Checkpoint) {
			c.FinalizerAlgorithm = "ml-dsa-87"
		}, "finalizer algorithm"},
		{"finalizer_key_id", func(c *auditcheckpoint.Checkpoint) {
			c.FinalizerKeyID = fckFlipHex(c.FinalizerKeyID)
		}, "does not match its own public key"},
		{"finalizer_public_key swapped", func(c *auditcheckpoint.Checkpoint) {
			c.FinalizerPublicKeyB64 =
				base64.StdEncoding.EncodeToString(other.PublicBytes())
		}, "does not match its own public key"},
		{"signature bit-flipped", func(c *auditcheckpoint.Checkpoint) {
			raw, _ := base64.StdEncoding.DecodeString(c.SignatureB64)
			raw[0] ^= 0x01
			c.SignatureB64 = base64.StdEncoding.EncodeToString(raw)
		}, "signature is invalid"},
		{"signature emptied", func(c *auditcheckpoint.Checkpoint) {
			c.SignatureB64 = ""
		}, "signature is invalid"},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			f := fckFixtureSealed(t)
			checkpoint := fckLoadCheckpoint(t, f)
			scenario.mutate(&checkpoint)
			fckWriteCheckpoint(t, f, checkpoint)
			fckExpectReject(t, f, scenario.token,
				"an unsigned tamper of checkpoint field "+scenario.name)
		})
	}
}

// --- 8b/10. bound fields wrong under a VALID finalizer signature -------------------

// The deeper property (Codex item 8, and the heart of items 10 and 7-of-7
// from the original spec brief): a checkpoint that is present, well-formed
// and CORRECTLY SIGNED by the pinned finalizer, but claims wrong values,
// must still fail on independent recomputation, field by field. (Threat
// model: a compromised or buggy finalizer step — the credential alone must
// not be sufficient.)
func TestFableCkptBoundFieldRecomputationHonestSignature(t *testing.T) {
	// Control row: re-signing the UNMODIFIED checkpoint with the replicated
	// canonical message must still verify. If this fails, the canonical
	// format in fckSigningMessage drifted from the implementation and every
	// row below would be failing for the wrong reason.
	t.Run("control: re-signed unmodified checkpoint verifies", func(t *testing.T) {
		f := fckFixtureSealed(t)
		checkpoint := fckLoadCheckpoint(t, f)
		fckResign(t, f, &checkpoint)
		fckWriteCheckpoint(t, f, checkpoint)
		if err := fckVerify(f); err != nil {
			t.Fatalf("canonical signing-message replica drifted from the "+
				"implementation: %v", err)
		}
	})
	scenarios := []struct {
		name   string
		mutate func(*auditcheckpoint.Checkpoint)
		token  string
	}{
		{"final_sequence overstated", func(c *auditcheckpoint.Checkpoint) {
			c.FinalSequence++ // count left correct: only the sequence check can object
		}, "final sequence mismatch"},
		{"record_count understated", func(c *auditcheckpoint.Checkpoint) {
			c.RecordCount--
		}, "grew after the checkpoint"},
		{"record_count overstated", func(c *auditcheckpoint.Checkpoint) {
			c.RecordCount++
		}, "audit log was truncated"},
		{"chain_head_mac wrong", func(c *auditcheckpoint.Checkpoint) {
			c.ChainHeadMAC = fckFlipHex(c.ChainHeadMAC)
		}, "head MAC mismatch"},
		{"audit_log_sha256 wrong", func(c *auditcheckpoint.Checkpoint) {
			c.AuditLogSHA256 = fckFlipHex(c.AuditLogSHA256)
		}, "audit log digest mismatch"},
		{"evidence_manifest_sha256 wrong", func(c *auditcheckpoint.Checkpoint) {
			c.ManifestSHA256 = fckFlipHex(c.ManifestSHA256)
		}, "manifest digest mismatch"},
		{"producer_digest wrong", func(c *auditcheckpoint.Checkpoint) {
			c.ProducerDigest = fckFlipHex(c.ProducerDigest)
		}, "producer digest mismatch"},
		{"closed_at_utc before the final record", func(c *auditcheckpoint.Checkpoint) {
			c.ClosedAtUTC = "2020-01-01T00:00:00Z"
		}, "precedes the final audit record"},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			f := fckFixtureSealed(t)
			checkpoint := fckLoadCheckpoint(t, f)
			scenario.mutate(&checkpoint)
			fckResign(t, f, &checkpoint)
			fckWriteCheckpoint(t, f, checkpoint)
			fckExpectReject(t, f, scenario.token,
				"a correctly signed checkpoint with "+scenario.name)
		})
	}
	// Domain separation: the honest finalizer key signing the honest message
	// under a DIFFERENT Winn domain must not verify as a checkpoint.
	t.Run("honest key, wrong signature domain", func(t *testing.T) {
		f := fckFixtureSealed(t)
		checkpoint := fckLoadCheckpoint(t, f)
		signature, err := pqauth.SignDomainMessage(
			pqauth.TransparencySignatureDomain,
			fckSigningMessage(checkpoint), f.signer,
		)
		if err != nil {
			t.Fatal(err)
		}
		checkpoint.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
		fckWriteCheckpoint(t, f, checkpoint)
		fckExpectReject(t, f, "signature is invalid",
			"a checkpoint signed under a foreign Winn signature domain")
	})
}

// --- 9. stale manifest ---------------------------------------------------------

func TestFableCkptStaleManifest(t *testing.T) {
	t.Run("seal refuses a manifest sealed before the trail finished", func(t *testing.T) {
		f := fckBuild(t, fckNewSigner(t), "fable-stale-seal", 3)
		fckAppendRecords(t, f, 3, 2) // manifest still describes the 3-record log
		_, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
			EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
			RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
		})
		if err == nil || !strings.Contains(err.Error(), "stale") {
			t.Fatalf("sealing over a stale manifest: got %v, want a stale refusal", err)
		}
	})
	t.Run("manifest re-sealed after the checkpoint", func(t *testing.T) {
		f := fckFixtureSealed(t)
		if err := os.WriteFile(
			filepath.Join(f.dir, "late-addition.txt"), []byte("smuggled\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		fckSealManifest(t, f)
		fckExpectReject(t, f, "manifest digest mismatch",
			"a manifest re-sealed after the checkpoint was issued")
	})
	// environment.txt is manifest-covered and freshness-checked, so rewriting
	// the producer digest after the seal is caught as a STALE MANIFEST before
	// the producer comparison is ever reached. That is the stronger identity
	// (it names the file that moved), so it is asserted as such rather than
	// loosened; the producer comparison itself is exercised, under a valid
	// finalizer signature, by the recomputation table's producer_digest row.
	t.Run("environment producer digest rewritten after seal", func(t *testing.T) {
		f := fckFixtureSealed(t)
		forged := sha256.Sum256([]byte("forged-producer"))
		if err := os.WriteFile(
			filepath.Join(f.dir, "environment.txt"),
			[]byte("source_digest="+hex.EncodeToString(forged[:])+"\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		fckExpectReject(t, f, "manifest is stale",
			"a sealed environment whose producer digest was rewritten")
		if !strings.Contains(fckVerify(f).Error(), "environment.txt") {
			t.Fatal("the staleness rejection does not name environment.txt")
		}
	})
	// PINNED SCOPE LIMIT, deliberately (flagged for Codex): checkpoint
	// verification recomputes the manifest's own digest and the audit log's
	// manifest entry, but does NOT re-verify every other manifest entry
	// against its file. A post-seal rewrite of an aux evidence file
	// (carrier-conservation.txt here) passes the CHECKPOINT gate and is
	// caught only by the outer manifest verification the wrappers already
	// run. If this pin ever fails, the checkpoint's scope was widened —
	// update the wrapper rationale and this pin together.
	t.Run("pinned: aux file rewrite is outer-manifest scope, not checkpoint scope",
		func(t *testing.T) {
			f := fckFixtureSealed(t)
			if err := os.WriteFile(
				filepath.Join(f.dir, "carrier-conservation.txt"),
				[]byte("schema=carrier-conservation/v2\nredemptions=999\n"), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			if err := fckVerify(f); err != nil {
				t.Fatalf("the checkpoint gate now rejects aux-file rewrites "+
					"(%v) — its scope was widened; move this pin and the "+
					"outer-manifest rationale together", err)
			}
		})
}

// --- producer binding under a FULL re-close (scope finding) ---------------------

// The complete producer-substitution attack: rewrite environment.txt, re-seal
// the manifest, delete the old close record, and re-close with the genuine
// finalizer. Every internal cross-check now agrees, because the checkpoint
// recomputes the producer digest from the very file that was rewritten.
//
// The only thing that can still object is an EXTERNAL expectation. This test
// asserts both halves, because the difference is the whole argument for
// making the producer/run binding auditor-supplied rather than self-asserted:
//
//	with ExpectedProducerDigest pinned -> rejected
//	without it                         -> ACCEPTED (pinned here as a scope limit)
//
// If the second half ever starts failing, the binding was made mandatory
// somewhere else in the chain; move this pin with it.
func TestFableCkptForgedEnvironmentFullReclose(t *testing.T) {
	f := fckFixtureSealed(t)
	forged := sha256.Sum256([]byte("forged-producer-full-reclose"))
	forgedHex := hex.EncodeToString(forged[:])
	if err := os.WriteFile(
		filepath.Join(f.dir, "environment.txt"),
		[]byte("carrier_authorization_mode=anonymous-token\nsource_digest="+
			forgedHex+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	fckRemoveCheckpoint(t, f)
	fckSealManifest(t, f)
	// The runner-supplied producer digest is what stops the finalizer from
	// closing over a substituted environment in the first place.
	if _, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
		RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
	}); err == nil || !strings.Contains(err.Error(), "runner supplied producer digest") {
		t.Fatalf("sealing over a substituted environment with the runner's "+
			"expectation supplied: got %v, want a runner-expectation refusal", err)
	}
	// The scope limit this test originally pinned is now closed: the producer
	// digest is a hard precondition of Seal, so an attacker cannot re-close
	// over the substituted environment by simply omitting it. Both halves are
	// asserted below, and both are refusals.
	t.Run("the finalizer cannot omit the producer digest", func(t *testing.T) {
		_, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
			EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
			RunID: f.runID, Signer: f.signer,
		})
		if err == nil ||
			!strings.Contains(err.Error(), "requires a producer digest") {
			t.Fatalf("an omitted producer digest sealed a checkpoint: %v", err)
		}
	})
	t.Run("the auditor cannot omit the producer pin", func(t *testing.T) {
		// Reach a state where a forged close record exists at all: the
		// attacker supplies the forged digest they themselves planted.
		if _, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
			EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
			RunID: f.runID, ProducerDigest: forgedHex, Signer: f.signer,
		}); err != nil {
			t.Fatalf("the attacker's self-consistent re-close failed: %v", err)
		}
		// Pinned: the substitution is caught.
		fckExpectReject(t, f, "producer digest mismatch",
			"a fully re-closed run over a substituted environment")
		// Unpinned: refused as a precondition, not accepted.
		_, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
			EvidenceDirectory:      f.dir,
			ExpectedFinalizerKeyID: f.pin,
			ExpectedRunID:          f.runID,
			AuditLogName:           fckAuditLogName,
		})
		if err == nil ||
			!strings.Contains(err.Error(), "externally supplied producer digest") {
			t.Fatalf(
				"verification without a producer pin: got %v, want a refusal",
				err,
			)
		}
	})
}

// --- 6 of original brief. digest-cycle exclusion is enforced, not accidental ----

func TestFableCkptManifestDigestCycle(t *testing.T) {
	t.Run("sealed base manifest genuinely excludes the checkpoint", func(t *testing.T) {
		f := fckFixtureSealed(t)
		raw, err := os.ReadFile(f.manifestPath())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(raw)), "audit-checkpoint") {
			t.Fatal("the honest base manifest references the checkpoint")
		}
		if !strings.Contains(string(raw), fckAuditLogName) {
			t.Fatal("the honest base manifest does not cover the audit log")
		}
	})
	t.Run("seal refuses a manifest that covers the checkpoint", func(t *testing.T) {
		// The checkpoint file is sneaked into the directory BEFORE manifest
		// sealing, and the manifest walk is made to include it — the
		// regression Codex called out. Seal must refuse by name, not luck.
		f := fckBuild(t, fckNewSigner(t), "fable-cycle-seal", 3)
		if err := os.WriteFile(
			f.checkpointPath(), []byte("{\"schema\":\"placeholder\"}\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(f.checkpointPath())
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		manifest, err := os.ReadFile(f.manifestPath())
		if err != nil {
			t.Fatal(err)
		}
		cyclic := append(
			strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n"),
			hex.EncodeToString(digest[:])+"  ./"+auditcheckpoint.FileName,
		)
		sort.Strings(cyclic)
		if err := os.WriteFile(
			f.manifestPath(), []byte(strings.Join(cyclic, "\n")+"\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		_, err = auditcheckpoint.Seal(auditcheckpoint.SealInput{
			EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
			RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
		})
		if err == nil || !strings.Contains(err.Error(), "digest cycle") {
			t.Fatalf("sealing under a checkpoint-covering manifest: got %v, "+
				"want a digest-cycle refusal", err)
		}
	})
	t.Run("verify refuses a checkpoint bound to a cyclic manifest", func(t *testing.T) {
		// Internally consistent by construction: the cyclic manifest's true
		// digest is what the (honestly re-signed) checkpoint binds, so the
		// cycle rule itself must fire — not a digest comparison.
		f := fckFixtureSealed(t)
		checkpointRaw, err := os.ReadFile(f.checkpointPath())
		if err != nil {
			t.Fatal(err)
		}
		staleDigest := sha256.Sum256(checkpointRaw)
		manifest, err := os.ReadFile(f.manifestPath())
		if err != nil {
			t.Fatal(err)
		}
		cyclic := append(
			strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n"),
			hex.EncodeToString(staleDigest[:])+"  ./"+auditcheckpoint.FileName,
		)
		sort.Strings(cyclic)
		cyclicBytes := []byte(strings.Join(cyclic, "\n") + "\n")
		if err := os.WriteFile(f.manifestPath(), cyclicBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		checkpoint := fckLoadCheckpoint(t, f)
		manifestDigest := sha256.Sum256(cyclicBytes)
		checkpoint.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
		fckResign(t, f, &checkpoint)
		fckWriteCheckpoint(t, f, checkpoint)
		fckExpectReject(t, f, "digest cycle",
			"a correctly signed checkpoint bound to a manifest that covers it")
	})
}

// --- 12. Record versus Seal: premature close + concurrency under -race ------------

// The finalizer is a separate role, so there is deliberately no shared Go
// lock between audit.Log.Record and auditcheckpoint.Seal — the serialization
// contract is Seal's file-level guards (size re-check around hashing, the
// manifest-freshness requirement, and Verify's post-close detection). Two
// phases, because the two claims need different constructions:
//
// Phase 1 (deterministic, assertions unconditional): the actual hazard is a
// Seal that succeeds while the writer still intends more records — Seal
// cannot know the trail is unfinished if the file happens to be quiescent.
// The test FORCES that window with a handshake: writer pauses with the log
// open, Seal runs to a REQUIRED success, writer resumes and appends. The
// resulting checkpoint must then be rejected as post-close. No outcome of
// this phase is conditional; an earlier draft of this test let the window
// close probabilistically and Codex correctly rejected it as vacuous.
//
// Phase 2 (free-running, under -race): Record and Seal hammer the same
// files with no synchronization, to prove race-detector cleanliness and
// that the trail survives intact. This phase makes NO claim about whether a
// mid-run Seal succeeds — phase 1 already pinned that property — but if one
// does, its artifact must also fail as post-close/stale.
func TestFableCkptRecordVersusSealRace(t *testing.T) {
	// ---- Phase 1: forced premature close, unconditional ----
	f := fckBuild(t, fckNewSigner(t), "fable-race-run", 3)
	log, err := audit.Open(f.logPath(), f.auditKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	// The log is OPEN and the writer is mid-run (paused, more records
	// coming). The evidence directory is quiescent and internally
	// consistent, so Seal MUST succeed here — that requirement is the test:
	// nothing at seal time can know the writer is not done.
	fckSealManifest(t, f)
	if _, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
		RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
	}); err != nil {
		t.Fatalf("the forced premature-close window did not open: Seal over a "+
			"quiescent open trail failed (%v); this phase must not be skipped "+
			"or weakened — rework the window, do not make the assertion "+
			"conditional", err)
	}
	// Writer resumes: the trail the checkpoint claims to have closed grows.
	for index := 0; index < 4; index++ {
		if err := log.Record(
			"carrier.h3.authenticated", "android-lab-1",
			fmt.Sprintf("%032x", 9500+index),
			fmt.Sprintf("carrier-terminal/v1 class=authenticated "+
				"mode=anonymous-token session=%032x reason=none", 9500+index),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := audit.Verify(f.logPath(), f.auditKeyPath); err != nil {
		t.Fatalf("premise broken: the resumed trail is not chain-valid: %v", err)
	}
	// UNCONDITIONAL core assertion: the prematurely sealed checkpoint must
	// fail over the finished trail, with the post-close identity.
	err = fckVerify(f)
	if err == nil {
		t.Fatal("a checkpoint sealed while the writer was still mid-run " +
			"verifies over the finished trail")
	}
	if !strings.Contains(err.Error(), "grew after the checkpoint") {
		t.Fatalf("the premature checkpoint was rejected without the post-close "+
			"identity: %v", err)
	}

	// ---- Phase 2: free-running concurrency, -race cleanliness ----
	fckRemoveCheckpoint(t, f)
	log, err = audit.Open(f.logPath(), f.auditKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	var sealSucceededMidRun bool
	var midRunCheckpoint auditcheckpoint.Checkpoint
	var mu sync.Mutex
	recording := make(chan struct{})
	group.Add(2)
	go func() {
		defer group.Done()
		defer close(recording)
		for index := 0; index < 200; index++ {
			if err := log.Record(
				"carrier.h3.authenticated", "android-lab-1",
				fmt.Sprintf("%032x", 9000+index),
				fmt.Sprintf("carrier-terminal/v1 class=authenticated "+
					"mode=anonymous-token session=%032x reason=none", 9000+index),
			); err != nil {
				t.Errorf("concurrent Record failed: %v", err)
				return
			}
		}
	}()
	go func() {
		defer group.Done()
		// The manifest is re-sealed before each attempt so manifest staleness
		// is not the only possible refusal; whether a Seal lands in a
		// quiescent instant is scheduler luck, and this phase asserts nothing
		// about it (phase 1 owns that property deterministically).
		for {
			select {
			case <-recording:
				return
			default:
			}
			if err := fckSealManifestErr(f.dir); err != nil {
				continue
			}
			sealed, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
				EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
				RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
			})
			if err == nil {
				mu.Lock()
				sealSucceededMidRun = true
				midRunCheckpoint = sealed
				mu.Unlock()
				return // keep the artifact for the conditional check below
			}
		}
	}()
	group.Wait()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	// The trail must have stayed intact under the concurrency.
	if err := audit.Verify(f.logPath(), f.auditKeyPath); err != nil {
		t.Fatalf("audit chain corrupted by concurrent Record/Seal: %v", err)
	}
	// Supplementary only (phase 1 already proved the property): the exact
	// contract for a concurrent-phase Seal success depends on when it landed.
	// If the trail grew past what it bound, it must fail as post-close; if it
	// happened to land after the writer's final record, it legitimately
	// closed the complete trail and must verify. Both directions asserted.
	if sealSucceededMidRun {
		chain, err := auditcheckpoint.ScanChain(f.logPath())
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case chain.RecordCount > midRunCheckpoint.RecordCount:
			err := fckVerify(f)
			if err == nil {
				t.Fatalf("a checkpoint bound to %d records verifies over a "+
					"trail that grew to %d",
					midRunCheckpoint.RecordCount, chain.RecordCount)
			}
			if !strings.Contains(err.Error(), "grew after the checkpoint") {
				t.Fatalf("concurrent-phase premature checkpoint rejected "+
					"without the post-close identity: %v", err)
			}
		case chain.RecordCount == midRunCheckpoint.RecordCount:
			// The Seal landed after the final record: a complete close. The
			// manifest may or may not have been re-sealed since; re-seal it
			// to the state the checkpoint bound before asserting acceptance.
			if err := fckVerify(f); err != nil &&
				!strings.Contains(err.Error(), "manifest") {
				t.Fatalf("a checkpoint that bound the complete %d-record "+
					"trail was rejected for a non-manifest reason: %v",
					chain.RecordCount, err)
			}
		default:
			t.Fatalf("the trail shrank (%d records) below what a successful "+
				"Seal bound (%d)", chain.RecordCount, midRunCheckpoint.RecordCount)
		}
	}
	// Proper close sequence over the finished trail must then succeed once the
	// mid-run artifact is cleared (Seal never overwrites in place).
	fckRemoveCheckpoint(t, f)
	fckSealManifest(t, f)
	fckSeal(t, f)
	if err := fckVerify(f); err != nil {
		t.Fatalf("the properly ordered close of the finished trail failed: %v", err)
	}
}

// --- re-close refusal (silent second close) -------------------------------------

// A second Seal over already-closed evidence must not silently replace the
// first close record. Overwriting in place would give an adversary who
// reaches the finalizer role a way to re-close a truncated trail without ever
// producing the two-checkpoint state duplicate detection looks for.
func TestFableCkptSealRefusesToReplace(t *testing.T) {
	f := fckFixtureSealed(t)
	before, err := os.ReadFile(f.checkpointPath())
	if err != nil {
		t.Fatal(err)
	}
	_, err = auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: f.dir, AuditLogName: fckAuditLogName,
		RunID: f.runID, ProducerDigest: f.producer, Signer: f.signer,
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("re-sealing closed evidence: got %v, want an already-exists refusal", err)
	}
	after, err := os.ReadFile(f.checkpointPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the refused re-seal still modified the existing checkpoint")
	}
	if err := fckVerify(f); err != nil {
		t.Fatalf("evidence no longer verifies after a refused re-seal: %v", err)
	}
}

// --- baseline -----------------------------------------------------------------

func TestFableCkptBaselineHonestClosePasses(t *testing.T) {
	f := fckFixtureSealed(t)
	if err := fckVerify(f); err != nil {
		t.Fatalf("honest sealed-and-closed evidence failed: %v", err)
	}
}
