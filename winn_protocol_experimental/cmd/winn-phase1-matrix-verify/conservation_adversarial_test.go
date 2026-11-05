// Adversarial conservation-law suite for the sealed carrier-redemption
// evidence, authored independently by the Fable 5 audit lane against the
// Codex/Sol ruling of 2026-07-26 09:51 EDT
// (WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md lines 2638-2694), then
// reconciled by the orchestrating session against Opus 5's actual
// implementation (internal/carrier/terminal.go,
// cmd/winn-phase1-matrix-verify/carrieraudit.go) per Codex's follow-up
// review. The ruling requires:
//
//	DB redemptions == authenticated == auth_only + open + aborted
//	open == closed
//
// recomputed by this verifier from manifest-bound sealed evidence, with every
// durable redemption reaching exactly one mutually exclusive terminal class,
// a closed versioned abort-reason enum that fails closed on unknown reasons,
// and rejection of missing, duplicate, unknown, reclassified, or uncorrelated
// terminal events.
//
// DESIGN RULE (from the ruling): "Each mutation must fail for the intended
// semantic reason rather than merely by an unrelated digest check." Every
// fixture below is therefore built through the real internal/audit HMAC
// chain and sealed under a self-consistent evidence-manifest.sha256, so all
// cryptographic and digest checks pass and the ONLY defect present is the one
// semantic violation the test names. The single exception is the
// tamper-after-seal subtest, where the digest mismatch IS the intended
// detection.
//
// RECONCILIATION NOTES (what changed from the original blind draft, and why):
//
//  1. Detail encoding: the original draft guessed the abort reason travelled
//     alone in the detail field. Opus's actual encoding is the fixed
//     five-token form "carrier-terminal/v1 class=<c> mode=<m> session=<s>
//     reason=<r>", identical in every terminal class. Every event builder
//     below emits that exact shape via terminalDetail.
//  2. Correlation identity: the original draft used bare labels like "sess-A"
//     as both the JSONL request_id and a stand-in session value. Opus's real
//     correlation ID is 128 server-minted random bits, hex-encoded (32
//     lowercase hex characters); the session value inside detail is
//     separately checked for the same 32-hex shape. hexID derives a stable,
//     valid 32-hex value from a short label so the fixtures stay readable
//     ("sess-A" reads the same as before) while the bytes on disk are
//     interface-correct. Two calls with the same label still collide on
//     purpose, which is exactly what the correlation-ID-reuse scenario needs.
//  3. Reason enum: the original draft guessed four reasons. Opus's is five —
//     audit_unavailable (the audit sink itself refusing a write) is a fifth,
//     legitimate member, added below.
//  4. The audit HMAC key: the original draft assumed the verifier would need
//     carrier-audit.key sealed alongside the log to recheck the chain
//     offline. Codex's review ruled the opposite, explicitly: sealing the MAC
//     key would let anyone forge the log, so it must never be disclosed.
//     Opus's real verifier does not read a key at all — integrity is the
//     manifest/anchor binding plus a keyless structural chain check
//     (sequence continuity and previous-MAC linkage, which still catches
//     insertion/deletion, just not a full HMAC recompute). The fixture still
//     writes a throwaway key so internal/audit's real Open/Record path
//     (which does use a key locally, at write time, exactly like the real
//     carrier) produces a genuine chained log; the verifier under test simply
//     never looks at that key file, which matches production.
//  5. Evidence-file set: carrier-audit-convergence.txt is renamed
//     carrier-conservation.txt, with a wider, closed key set covering
//     per-carrier counts (schema, redemptions, anonymous_authenticated,
//     h3_*, h2_* — 13 keys exactly). environment.txt with
//     carrier_authorization_mode=anonymous-token is now required too, since
//     verifyCarrierConservation reads the recorded mode before anything else.
//  6. H2 has no auth_only class — it never did, and Opus's fix did not add
//     one (H2 has no "authenticate without allocating a backend" purpose in
//     the protocol; only H3 does). The mixed-carrier positive control below
//     no longer calls h2Event(authOnly(...)), which would have produced an
//     event name the verifier does not recognise and made that subtest fail
//     for the wrong reason.
//
// None of the six semantic scenarios were weakened, narrowed, or removed in
// reconciliation — only the encoding/fixture layer changed to match the real
// interface.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
)

func init() {
	verifyCarrierConservationSeam = verifyCarrierConservation
}

// verifyCarrierConservationSeam is the single reconciliation point between
// this adversarial suite and the conservation verifier implementation. Wired
// above to the real entry point; do not weaken either side to make a test
// pass without recording why.
var verifyCarrierConservationSeam func(evidenceDirectory string) error

// The closed abort-reason enum, matching internal/carrier/terminal.go's
// AbortReasons() exactly (duplicated on purpose, mirroring the verifier's own
// duplication of the schema token: a test suite that imported the production
// enum could not catch a case where the two drift apart).
const (
	abortReasonRateLimited      = "carrier_rate_limited"
	abortReasonBackendDown      = "awg_backend_unavailable"
	abortReasonInvalidMTU       = "invalid_carrier_mtu"
	abortReasonResponseSigning  = "response_auth_failed"
	abortReasonAuditUnavailable = "audit_unavailable"
)

const (
	carrierAuthorizationMode = "anonymous-token"
	terminalSchemaToken      = "carrier-terminal/v1"
)

// hexID derives a stable, valid 32-lowercase-hex-character identity from a
// short human-readable label, so fixtures stay readable while every
// correlation ID and session value on disk matches Opus's real 128-bit
// hex-encoded shape. Two calls with the same label always collide, which is
// exactly the property the correlation-ID-reuse scenario needs.
func hexID(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])[:32]
}

// terminalDetail renders the fixed five-token carrier terminal encoding
// exactly as parseCarrierTerminalDetail expects it.
func terminalDetail(class, session, reason string) string {
	return terminalSchemaToken +
		" class=" + class +
		" mode=" + carrierAuthorizationMode +
		" session=" + session +
		" reason=" + reason
}

type carrierAuditEvent struct {
	event     string
	device    string
	requestID string
	detail    string
}

func authenticated(label string) carrierAuditEvent {
	id := hexID(label)
	return carrierAuditEvent{
		event:     "carrier_h3_authenticated",
		device:    "device-" + label,
		requestID: id,
		detail:    terminalDetail("authenticated", id, "none"),
	}
}

func authOnly(label string) carrierAuditEvent {
	id := hexID(label)
	return carrierAuditEvent{
		event:     "carrier_h3_auth_only",
		device:    "device-" + label,
		requestID: id,
		detail:    terminalDetail("auth_only", id, "none"),
	}
}

func opened(label string) carrierAuditEvent {
	id := hexID(label)
	return carrierAuditEvent{
		event:     "carrier_h3_open",
		device:    "device-" + label,
		requestID: id,
		detail:    terminalDetail("open", id, "none"),
	}
}

func closed(label string) carrierAuditEvent {
	id := hexID(label)
	return carrierAuditEvent{
		event:     "carrier_h3_closed",
		device:    "device-" + label,
		requestID: id,
		detail:    terminalDetail("closed", id, "none"),
	}
}

func aborted(label, reason string) carrierAuditEvent {
	id := hexID(label)
	return carrierAuditEvent{
		event:     "carrier_h3_aborted",
		device:    "device-" + label,
		requestID: id,
		detail:    terminalDetail("aborted", id, reason),
	}
}

// h2Event converts an H3 fixture event to its H2 counterpart. H2 has no
// auth_only class (it never has: the protocol's "authenticate without
// allocating a backend" purpose only exists on H3) — callers must not build
// one via authOnly for H2.
func h2Event(event carrierAuditEvent) carrierAuditEvent {
	if strings.Contains(event.event, "auth_only") {
		panic("h2Event: H2 has no auth_only class, do not convert one")
	}
	event.event = strings.Replace(event.event, "carrier_h3_", "carrier_h2_", 1)
	return event
}

// familyCounts tallies one carrier's terminal-class events, mirroring the
// verifier's own bookkeeping closely enough to build an honest conservation
// snapshot for the positive-control and non-adversarial fixtures.
type familyCounts struct {
	authenticated, authOnly, open, closed, aborted int
}

func tallyByFamily(events []carrierAuditEvent) (h3, h2 familyCounts) {
	for _, event := range events {
		var target *familyCounts
		var suffix string
		switch {
		case strings.HasPrefix(event.event, "carrier_h3_"):
			target = &h3
			suffix = strings.TrimPrefix(event.event, "carrier_h3_")
		case strings.HasPrefix(event.event, "carrier_h2_"):
			target = &h2
			suffix = strings.TrimPrefix(event.event, "carrier_h2_")
		default:
			continue
		}
		switch suffix {
		case "authenticated":
			target.authenticated++
		case "auth_only":
			target.authOnly++
		case "open":
			target.open++
		case "closed":
			target.closed++
		case "aborted":
			target.aborted++
		}
	}
	return h3, h2
}

type conservationFixture struct {
	events []carrierAuditEvent
	// redemptionCount is the byte content of redemption-count.txt (the DB
	// snapshot). The live harness writes the psql count with surrounding
	// whitespace and reads it back with tr -d '[:space:]', so a trailing
	// newline is the realistic sealed shape.
	redemptionCount string
	// omitRedemptionCount seals evidence with NO redemption-count.txt at
	// all, which must never be treated as "zero" or as "check disabled".
	omitRedemptionCount bool
	// conservationSnapshot overrides the self-reported carrier-conservation.txt
	// content. Empty means derive an honest one from events. The verifier
	// must recompute from the JSONL and must never trust this file's claims.
	conservationSnapshot string
}

// sealConservationEvidence builds one sealed evidence directory: a REAL
// HMAC-chained carrier-audit.jsonl written through internal/audit (so the
// chain verifies end to end), a throwaway audit key (used locally by
// internal/audit's real Open/Record path, exactly as the live carrier uses
// its own key at write time — the verifier under test never reads this file
// back, matching production, where the key is deliberately not disclosed),
// the DB-count snapshot, environment.txt declaring the anonymous-token mode,
// the sealed conservation summary, and a self-consistent
// evidence-manifest.sha256 covering every file (mirroring the harness rule:
// every regular file except the manifest itself).
func sealConservationEvidence(
	t *testing.T,
	fixture conservationFixture,
) string {
	t.Helper()
	directory := t.TempDir()
	// The throwaway HMAC writer key lives in a SEPARATE directory, never
	// inside the sealed evidence directory. internal/audit's real Open/
	// Record path needs a key locally to produce a genuine chained log,
	// exactly like the live carrier does — but the live carrier's key stays
	// in $PKI_DIR, never inside the evidence it seals, because sealing the
	// MAC key alongside the log it authenticates would let anyone holding
	// the evidence forge arbitrary "valid" entries. Keeping the fixture's
	// key outside `directory` means sealEvidenceManifest (which walks every
	// regular file in `directory`) can never accidentally cover it.
	keyDirectory := t.TempDir()
	keyPath := filepath.Join(keyDirectory, "carrier-audit.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "carrier-audit.jsonl")
	log, err := audit.Open(logPath, keyPath)
	if err != nil {
		t.Fatalf("open fixture audit log: %v", err)
	}
	for _, event := range fixture.events {
		if err := log.Record(
			event.event, event.device, event.requestID, event.detail,
		); err != nil {
			_ = log.Close()
			t.Fatalf("record fixture event %s: %v", event.event, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if !fixture.omitRedemptionCount {
		if err := os.WriteFile(
			filepath.Join(directory, "redemption-count.txt"),
			[]byte(fixture.redemptionCount),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(directory, "environment.txt"),
		[]byte(
			"carrier_authorization_mode="+carrierAuthorizationMode+"\n"+
				"source_digest="+fixtureProducerDigest+"\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	snapshot := fixture.conservationSnapshot
	if snapshot == "" {
		snapshot = honestConservationSnapshot(fixture.events, fixture.redemptionCount)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "carrier-conservation.txt"),
		[]byte(snapshot),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	sealEvidenceManifest(t, directory)
	assertAuditKeyNotSealed(t, directory)
	return directory
}

// fixtureProducerDigest is the source digest every conservation fixture seals
// into environment.txt, so the checkpoint's producer binding has a real value
// to recompute against rather than an empty string that would compare equal to
// another empty string.
const fixtureProducerDigest = "" +
	"11111111111111111111111111111111" +
	"11111111111111111111111111111111"

// sealConservationEvidenceClosed builds a fixture and then closes it exactly
// the way a real runner does: the audit log is already closed, the base
// manifest is already sealed, and only then does a finalizer that never held
// the audit HMAC key sign the terminal checkpoint.
//
// It returns the auditor's pin separately from the evidence, because that
// separation is the property under test. A pin that travelled inside the
// evidence directory would let anyone who could rewrite the evidence rewrite
// the pin too.
func sealConservationEvidenceClosed(
	t *testing.T,
	fixture conservationFixture,
) (string, auditCheckpointPin) {
	t.Helper()
	directory := sealConservationEvidence(t, fixture)
	pin := closeConservationEvidence(t, directory, conservationFixtureRunID)
	return directory, pin
}

const conservationFixtureRunID = "conservation-fixture-run"

// closeConservationEvidence seals a checkpoint over an already-sealed evidence
// directory with a freshly generated, test-local finalizer key.
func closeConservationEvidence(
	t *testing.T,
	directory string,
	runID string,
) auditCheckpointPin {
	t.Helper()
	seed, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(t.TempDir(), "finalizer.seed")
	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := auditcheckpoint.LoadFinalizer(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	if _, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: directory,
		AuditLogName:      carrierAuditFileName,
		RunID:             runID,
		ProducerDigest:    fixtureProducerDigest,
		Signer:            signer,
	}); err != nil {
		t.Fatalf("seal fixture checkpoint: %v", err)
	}
	return auditCheckpointPin{
		finalizerKeyID: signer.KeyID(),
		runID:          runID,
		producerDigest: fixtureProducerDigest,
	}
}

// assertAuditKeyNotSealed proves the threat-boundary decision holds for
// every fixture this suite builds, not just by construction: the HMAC
// writer key must never appear inside the sealed evidence directory or its
// manifest. Disclosing it would let anyone holding the evidence forge
// arbitrary "valid" log entries, which defeats the point of authenticating
// the log at all.
func assertAuditKeyNotSealed(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "audit.key") ||
			strings.Contains(entry.Name(), "audit-key") {
			t.Fatalf(
				"sealed evidence directory contains %q; the HMAC writer "+
					"key must never be sealed alongside the evidence it "+
					"authenticates",
				entry.Name(),
			)
		}
	}
	manifest, err := os.ReadFile(
		filepath.Join(directory, "evidence-manifest.sha256"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), "key") {
		t.Fatalf(
			"evidence manifest references a key-named file: %s",
			manifest,
		)
	}
}

// honestConservationSnapshot derives the sealed carrier-conservation.txt
// content an honest harness would have written for the given events. Used
// only to build non-adversarial fixtures (the positive control and the
// scenarios whose defect lies elsewhere); every adversarial fixture that
// specifically targets this file supplies its own conservationSnapshot.
func honestConservationSnapshot(events []carrierAuditEvent, redemptionCount string) string {
	h3, h2 := tallyByFamily(events)
	redemptions := strings.TrimSpace(redemptionCount)
	anonymous := h3.authenticated + h2.authenticated
	return conservationSnapshotContent(
		redemptions, fmt.Sprintf("%d", anonymous), h3, h2,
	)
}

// conservationSnapshotContent renders the exact closed key set
// verifyCarrierConservationWithMode expects: schema plus 12 counts, nothing
// else.
func conservationSnapshotContent(
	redemptions, anonymousAuthenticated string,
	h3, h2 familyCounts,
) string {
	return fmt.Sprintf(
		"schema=%s\n"+
			"redemptions=%s\n"+
			"anonymous_authenticated=%s\n"+
			"h3_authenticated=%d\nh3_auth_only=%d\nh3_open=%d\nh3_closed=%d\nh3_aborted=%d\n"+
			"h2_authenticated=%d\nh2_auth_only=%d\nh2_open=%d\nh2_closed=%d\nh2_aborted=%d\n",
		terminalSchemaToken, redemptions, anonymousAuthenticated,
		h3.authenticated, h3.authOnly, h3.open, h3.closed, h3.aborted,
		h2.authenticated, h2.authOnly, h2.open, h2.closed, h2.aborted,
	)
}

// sealEvidenceManifest writes evidence-manifest.sha256 with real digests in
// the exact "<sha256>  ./<relative>" shape verifyEvidenceManifest accepts,
// covering every regular file except the manifest itself — the same rule the
// live sealer uses (scripts/aicore_auto_e2e.sh:499-506).
func sealEvidenceManifest(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() ||
			entry.Name() == "evidence-manifest.sha256" {
			continue
		}
		digest, err := sha256File(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, digest+"  ./"+entry.Name())
	}
	sort.Strings(lines)
	if err := os.WriteFile(
		filepath.Join(directory, "evidence-manifest.sha256"),
		[]byte(strings.Join(lines, "\n")+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func conservationVerdict(t *testing.T, directory string) error {
	t.Helper()
	if verifyCarrierConservationSeam == nil {
		t.Fatalf(
			"RECONCILE: verifyCarrierConservationSeam is not wired to the " +
				"conservation verifier entry point.",
		)
	}
	return verifyCarrierConservationSeam(directory)
}

// requireConservationReject asserts not merely that the verifier rejects,
// but that it rejects for the intended semantic reason: err's message must
// contain wantSubstring. Without this, an unrelated failure (a manifest
// digest mismatch, a parser error on some other field) could make the test
// pass while the specific check the scenario targets is silently missing or
// broken — exactly the "unrelated digest check" failure mode the ruling
// warns against.
func requireConservationReject(
	t *testing.T,
	directory string,
	wantSubstring string,
	scenario string,
) {
	t.Helper()
	err := conservationVerdict(t, directory)
	if err == nil {
		t.Fatalf(
			"conservation verifier ACCEPTED sealed evidence that violates "+
				"the conservation law: %s. The fixture's HMAC chain and "+
				"evidence manifest are self-consistent, so acceptance means "+
				"the semantic check itself is missing or wrong.",
			scenario,
		)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf(
			"conservation verifier rejected %s, but not for the intended "+
				"reason: wanted an error containing %q, got: %v",
			scenario, wantSubstring, err,
		)
	}
}

// TestConservationAcceptsBalancedSealedEvidence is the positive control.
// Every rejection test below is meaningful only if a fully balanced ledger —
// all three terminal classes present, every reason inside the closed enum,
// DB count equal to the authenticated count, open equal to closed — passes.
// A verifier that rejects this fixture is fail-closed to the point of being
// unusable, and (worse) would mask which adversarial fixture actually
// exercised the intended check.
func TestConservationAcceptsBalancedSealedEvidence(t *testing.T) {
	directory := sealConservationEvidence(t, conservationFixture{
		events: []carrierAuditEvent{
			authenticated("sess-A"), authOnly("sess-A"),
			authenticated("sess-B"), opened("sess-B"),
			authenticated("sess-C"), aborted("sess-C", abortReasonRateLimited),
			authenticated("sess-D"), aborted("sess-D", abortReasonBackendDown),
			authenticated("sess-E"), authOnly("sess-E"),
			authenticated("sess-F"), opened("sess-F"),
			closed("sess-B"), closed("sess-F"),
		},
		redemptionCount: "6\n",
	})
	if err := conservationVerdict(t, directory); err != nil {
		t.Fatalf(
			"balanced sealed evidence must verify cleanly, got: %v", err,
		)
	}
}

// Scenario 1 — dropping the abort event.
//
// Real-world failure mode: a request is rejected after single-use token
// redemption (rate limit, backend dial failure, MTU policy, response signing
// failure) and the reject path simply returns without terminalizing — which
// is exactly what internal/carrier/h2.go did before its fix, and what H3 did
// before its own partial fix. A durable redemption then vanishes from the
// sealed trail, and a censoring gateway (or a bug) can silently eat paid
// redemptions.
//
// Correct implementation: reject, because authenticated(3) !=
// auth_only(1)+open(1)+aborted(0) AND session sess-C has no terminal event.
// Both the aggregate equation and the per-correlation pairing are violated.
//
// Broken implementation: accepts because it only enforces the old
// upper/lower BOUNDS (terminals <= authenticated passes), or because it
// trusts the self-reported conservation summary — which this fixture
// deliberately makes lie (it claims aborted=1). The ruling requires the
// verifier to recompute from the JSONL, so the lying summary must not save
// the evidence.
func TestConservationRejectsDroppedAbortEvent(t *testing.T) {
	events := []carrierAuditEvent{
		authenticated("sess-A"), authOnly("sess-A"),
		authenticated("sess-B"), opened("sess-B"), closed("sess-B"),
		authenticated("sess-C"),
		// sess-C was rejected post-auth and nothing was recorded.
	}
	h3, h2 := tallyByFamily(events)
	h3.aborted = 1 // the lie: claims the abort was recorded.
	directory := sealConservationEvidence(t, conservationFixture{
		events:          events,
		redemptionCount: "3\n",
		conservationSnapshot: conservationSnapshotContent(
			"3", "3", h3, h2,
		),
	})
	requireConservationReject(
		t, directory, "reached no terminal class",
		"a durable redemption (sess-C) has no terminal event of any class",
	)
}

// Scenario 2 — duplicate terminalization.
//
// Real-world failure mode: a race between the relay-error path and stream
// teardown records two terminals for one request; or a replayed/duplicated
// abort record is used to make the AGGREGATE sums balance while a different
// redemption is quietly dropped. This is the classic double-entry attack on
// any counting audit: totals that add up while individual entries are wrong.
//
// Correct implementation: reject. Terminal classes are mutually exclusive
// per correlation ID and exactly one terminal is allowed per redemption, so
// the verifier must correlate per ID, not merely sum columns.
//
// Broken implementation: silently sums. In both subtests below
// authenticated == auth_only + open + aborted and open == closed hold at the
// aggregate level, so a column-summing verifier accepts evidence in which
// one session terminalized twice and another vanished entirely.
func TestConservationRejectsDuplicateTerminalization(t *testing.T) {
	t.Run("CrossClassDoubleTerminal", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), authOnly("sess-A"),
				authenticated("sess-B"), opened("sess-B"), closed("sess-B"),
				// sess-B reaches a SECOND terminal class (reclassified).
				aborted("sess-B", abortReasonBackendDown),
				authenticated("sess-C"),
				// sess-C has no terminal; sums still balance: 1+1+1 == 3.
			},
			redemptionCount: "3\n",
		})
		requireConservationReject(
			t, directory, "terminalized twice",
			"sess-B reached two terminal classes (open+closed AND aborted) "+
				"while sess-C reached none; aggregate sums balance",
		)
	})
	t.Run("RepeatedAbortForOneRedemption", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), authOnly("sess-A"),
				authenticated("sess-B"), opened("sess-B"), closed("sess-B"),
				authenticated("sess-C"),
				aborted("sess-C", abortReasonRateLimited),
				// The same terminalization is recorded twice (double-record
				// race or deliberate padding)...
				aborted("sess-C", abortReasonRateLimited),
				// ...which hides that sess-D's terminal is missing:
				// 1 + 1 + 2 == 4 authenticated.
				authenticated("sess-D"),
			},
			redemptionCount: "4\n",
		})
		requireConservationReject(
			t, directory, "terminalized twice",
			"sess-C is aborted twice, padding the aborted column to hide "+
				"sess-D's missing terminal",
		)
	})
}

// Scenario 3 — unknown abort reason.
//
// Real-world failure mode: a new reject path (or a compromised gateway) emits
// an abort with a reason string outside the frozen enum. If the verifier
// accepts-and-ignores, the "closed, versioned reason enum" of the ruling is
// fiction: arbitrary strings become a covert channel and future enum drift
// is never caught. If the verifier panics on an unexpected key, an attacker
// can crash audits at will.
//
// Correct implementation: reject (fail closed), without panicking or
// hanging, exactly as the ruling states: "Unknown reasons fail closed."
//
// Broken implementation: counts the event into the aborted column anyway
// (the aggregate here balances perfectly), crashes on the unknown token, or
// treats the empty reason as "no reason recorded, fine" — the same
// absent-vs-empty confusion the project's F1 finding required
// verifyExperimentKnobs to avoid for force_carrier.
func TestConservationRejectsUnknownAbortReason(t *testing.T) {
	t.Run("UnknownToken", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), authOnly("sess-A"),
				authenticated("sess-B"), opened("sess-B"), closed("sess-B"),
				authenticated("sess-C"),
				aborted("sess-C", "stream_reset_optimization_v9"),
			},
			redemptionCount: "3\n",
		})
		requireConservationReject(
			t, directory, "unrecognised reason",
			"aborted event carries a reason outside the closed enum",
		)
	})
	t.Run("EmptyReason", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), authOnly("sess-A"),
				authenticated("sess-B"), opened("sess-B"), closed("sess-B"),
				authenticated("sess-C"), aborted("sess-C", ""),
			},
			redemptionCount: "3\n",
		})
		requireConservationReject(
			// An empty reason= value is rejected one layer earlier than an
			// unrecognised one: the fixed five-token parser requires every
			// key to have a non-empty value, so this fails at "lacks a
			// reason token" rather than "unrecognised reason". Both are
			// fail-closed for the same underlying defect (empty is not a
			// valid enum member); this asserts the layer it actually hits.
			t, directory, "lacks a reason token",
			"aborted event carries an empty reason; empty must be rejected "+
				"exactly like any other out-of-enum value, not treated as "+
				"'absent, therefore unchecked'",
		)
	})
}

// Scenario 4 — correlation-ID reuse.
//
// Real-world failure mode: a correlation-ID collision (bad randomness, or a
// malicious client/gateway replaying one ID) lets events from two different
// redemptions be attributed to one another. With reuse, one redemption's
// terminal can "cover" for another's missing terminal, so the conservation
// equation can be made to balance while the per-redemption guarantee is
// broken. The ruling requires "a stable correlation identity" per durable
// redemption — identity, not just arithmetic.
//
// Correct implementation: reject, because two distinct
// carrier_h3_authenticated events share request_id sess-X, so terminal
// attribution is ambiguous. The verifier must detect the reuse itself (here,
// via the existing "authenticated more than once" check — a real collision
// of a 128-bit random ID is exactly this shape).
//
// Broken implementation: reconciles the counts (authenticated=3 ==
// auth_only 1 + open 1 + aborted 1; open == closed) and accepts, silently
// tolerating ambiguous attribution.
func TestConservationRejectsCorrelationIDReuse(t *testing.T) {
	directory := sealConservationEvidence(t, conservationFixture{
		events: []carrierAuditEvent{
			authenticated("sess-X"), authOnly("sess-X"),
			// A second, distinct redemption presents the SAME correlation ID.
			authenticated("sess-X"), opened("sess-X"), closed("sess-X"),
			authenticated("sess-Y"),
			aborted("sess-Y", abortReasonInvalidMTU),
		},
		redemptionCount: "3\n",
	})
	requireConservationReject(
		t, directory, "authenticated more than once",
		"two distinct redemptions share correlation ID sess-X, making "+
			"terminal attribution ambiguous while aggregate counts balance",
	)
}

// Scenario 5 — tampering with the DB-count snapshot.
//
// Real-world failure mode: redemption-count.txt is the only bridge between
// the PostgreSQL ground truth and the sealed evidence. An attacker who can
// edit one small text file after sealing (or who convinces the harness to
// omit it) controls the left-hand side of the conservation equation and can
// hide skimmed redemptions.
//
// The ruling is explicit: "Any DB-count snapshot used by the equation must
// itself be included in the evidence manifest and anchor commitment."
func TestConservationDBCountSnapshotIsTamperEvident(t *testing.T) {
	balanced := conservationFixture{
		events: []carrierAuditEvent{
			authenticated("sess-A"), authOnly("sess-A"),
			authenticated("sess-B"), opened("sess-B"), closed("sess-B"),
			authenticated("sess-C"),
			aborted("sess-C", abortReasonResponseSigning),
		},
		redemptionCount: "3\n",
	}

	// Correct implementation: the manifest walk hashes redemption-count.txt
	// and reports THIS file as changed. Broken implementation: leaves the
	// snapshot outside the manifest (nothing to mismatch), or only checks
	// files it already knew about in the pre-ruling schema.
	//
	// This subtest runs against the EXISTING verifyEvidenceManifest today
	// and doubles as proof that the fixture's manifest actually covers the
	// snapshot, so the seam-level subtests below cannot pass vacuously.
	t.Run("TamperAfterSealIsCaughtByManifest", func(t *testing.T) {
		directory := sealConservationEvidence(t, balanced)
		if err := verifyEvidenceManifest(directory); err != nil {
			t.Fatalf("pre-tamper manifest must verify, got: %v", err)
		}
		if err := os.WriteFile(
			filepath.Join(directory, "redemption-count.txt"),
			[]byte("2\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		err := verifyEvidenceManifest(directory)
		if err == nil {
			t.Fatal(
				"evidence manifest verification accepted a DB-count " +
					"snapshot edited after sealing; the snapshot is either " +
					"not manifest-covered or not being rehashed",
			)
		}
		if !strings.Contains(err.Error(), "redemption-count.txt") {
			t.Fatalf(
				"tamper must be attributed to redemption-count.txt "+
					"specifically, got: %v",
				err,
			)
		}
	})

	// An attacker who can rewrite BOTH the snapshot and the manifest line
	// keeps the digests self-consistent (the anchor commitment catches the
	// manifest rewrite in the full pipeline, but the conservation check must
	// not depend on that alone). The equation itself must then reject:
	// DB says 2, the sealed chain proves 3 authenticated redemptions.
	// Broken implementation: only compares the snapshot against the
	// conservation summary, or clamps with an inequality (2 <= 3 passes a
	// bounds check).
	t.Run("ConsistentRewriteBreaksTheEquation", func(t *testing.T) {
		fixture := balanced
		fixture.redemptionCount = "2\n"
		directory := sealConservationEvidence(t, fixture)
		requireConservationReject(
			t, directory, "does not equal anonymous authenticated",
			"DB-count snapshot (2) != authenticated events (3) in "+
				"otherwise self-consistent sealed evidence",
		)
	})

	// Absent snapshot: without the file there IS no left-hand side, so the
	// equation cannot be evaluated and the evidence must be rejected.
	// Broken implementation: "file missing, skip the DB check" — the exact
	// field-absent-vs-empty failure class the F1 finding fixed for
	// force_carrier (verifyExperimentKnobs requires the key to be PRESENT
	// and empty; absence is rejection).
	t.Run("MissingSnapshotIsRejected", func(t *testing.T) {
		fixture := balanced
		fixture.omitRedemptionCount = true
		directory := sealConservationEvidence(t, fixture)
		requireConservationReject(
			t, directory, "evidence manifest does not cover",
			"redemption-count.txt is absent; absence must fail closed, "+
				"never disable the DB side of the equation",
		)
	})

	// Empty snapshot: present-but-empty must also fail closed rather than
	// parse as zero (or worse, be skipped as "no value"). The live harness
	// would fail its numeric [ -ne ] comparison here; the offline verifier
	// must be at least as strict.
	t.Run("EmptySnapshotIsRejected", func(t *testing.T) {
		fixture := balanced
		fixture.redemptionCount = ""
		directory := sealConservationEvidence(t, fixture)
		requireConservationReject(
			t, directory, "durable redemption snapshot",
			"redemption-count.txt is empty; an unparseable count must be "+
				"rejected, not coerced to zero or skipped",
		)
	})
}

// Scenario 6 — post-auth failure concurrent with teardown (sealed-evidence
// shapes). The genuinely concurrent substrate test lives in
// internal/audit/terminal_conservation_race_test.go; these subtests pin the
// two evidence shapes a teardown race actually produces, so the verifier
// catches them no matter which side of the race won.
func TestConservationRejectsTeardownRaceEvidence(t *testing.T) {
	// Shape 1: the abort path lost the race with normal closure and BOTH
	// terminals were recorded, abort last. Distinct from the generic
	// duplicate-terminal test above in its ordering: a verifier that only
	// checks "no terminal after the first" in file order, or that keys its
	// per-ID state machine on "last event wins", can mis-accept one of the
	// two orderings. Sums balance (authenticated 2 == open 1 + aborted 1,
	// open == closed) so only per-ID exclusivity catches it.
	t.Run("AbortRecordedAfterClose", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), opened("sess-A"), closed("sess-A"),
				// Teardown already terminalized sess-A; the racing abort
				// path then appends its own terminal.
				aborted("sess-A", abortReasonBackendDown),
				authenticated("sess-B"),
				// sess-B's terminal is the one the race actually lost.
			},
			redemptionCount: "2\n",
		})
		requireConservationReject(
			t, directory, "terminalized twice",
			"sess-A carries both a closed and a later aborted terminal "+
				"(teardown race, abort path lost); sess-B has none",
		)
	})

	// Shape 2: the process (or candidate teardown) died between recording
	// carrier_h3_open and recording the terminal close/abort. CRITICAL
	// SUBSTRATE FACT, demonstrated runnably in
	// internal/audit/terminal_conservation_race_test.go: the audit HMAC
	// chain has no termination marker, so a log truncated at any record
	// boundary still verifies perfectly. Cryptography CANNOT catch this
	// shape — only the conservation law can. Correct implementation:
	// reject (open=1 != closed=0, and sess-B lacks a terminal). Broken
	// implementation: "chain verifies, counts are within bounds, pass" —
	// which is precisely the pre-ruling Gate 6 behavior of observing
	// equality when it happens to hold rather than enforcing it.
	t.Run("TeardownTruncationAfterOpen", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), authOnly("sess-A"),
				authenticated("sess-B"), opened("sess-B"),
				// Crash during teardown: no closed, no aborted, log ends on
				// a perfectly valid chained record.
			},
			redemptionCount: "2\n",
		})
		requireConservationReject(
			t, directory, "never closed",
			"open(1) != closed(0): teardown died after open and the chain "+
				"cannot reveal the truncation; only the equation can",
		)
	})
}

// TestConservationClosedRejectsIgnoredCloseRecordError proves Codex's
// requirement 5 directly rather than assuming it: an implementation that
// ignores a failed Record() call on the closed event is only safe because
// open != closed then makes the run fail closed. This fixture is exactly
// that shape — an open with no matching closed, standing in for "the closed
// record's write failed and the error was ignored" — and must be rejected on
// that basis regardless of whether the production code's own return value is
// checked.
func TestConservationClosedRejectsIgnoredCloseRecordError(t *testing.T) {
	directory := sealConservationEvidence(t, conservationFixture{
		events: []carrierAuditEvent{
			authenticated("sess-A"), opened("sess-A"),
			// The closed record's write is presumed to have failed and its
			// error ignored by the caller — exactly what would happen on
			// disk if internal/carrier's own ignored Record() error fires.
		},
		redemptionCount: "1\n",
	})
	requireConservationReject(
		t, directory, "never closed",
		"open(1) != closed(0) must reject even when nothing else in the "+
			"trail looks wrong, which is the only thing that makes ignoring "+
			"the closed-record's own write error a defensible choice",
	)
}

// The ownership declaration widened the ruling's scope to the H2 carrier,
// which before Opus's fix recorded NO authenticated-boundary or terminal
// events at all — every post-auth reject in internal/carrier/h2.go (rate
// limit, backend, MTU, response signing) made a durable redemption vanish.
// H2 events now participate in the same conservation law, sharing the single
// DB redemption count with H3. H2 has no auth_only class (see the file-level
// reconciliation note 6) — every H2 fixture below only ever uses
// authenticated/open/closed/aborted.
func TestConservationCoversH2CarrierEvents(t *testing.T) {
	t.Run("BalancedMixedCarriersPass", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), authOnly("sess-A"),
				h2Event(authenticated("sess-G")),
				h2Event(aborted("sess-G", abortReasonAuditUnavailable)),
				h2Event(authenticated("sess-H")),
				h2Event(opened("sess-H")),
				h2Event(closed("sess-H")),
			},
			redemptionCount: "3\n",
		})
		if err := conservationVerdict(t, directory); err != nil {
			t.Fatalf(
				"balanced mixed H2+H3 evidence must verify, got: %v", err,
			)
		}
	})
	t.Run("H2DroppedTerminalIsRejected", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				authenticated("sess-A"), authOnly("sess-A"),
				h2Event(authenticated("sess-G")),
				// H2 rejected post-auth with nothing recorded — the exact
				// pre-fix behavior of every h2.go post-auth reject path.
			},
			redemptionCount: "2\n",
		})
		requireConservationReject(
			t, directory, "reached no terminal class",
			"an H2 redemption (sess-G) has no terminal event; H2 is inside "+
				"the ruling's scope per the ownership declaration",
		)
	})
}

// rawEvent builds a carrierAuditEvent with fully explicit fields, bypassing
// the authenticated/opened/closed/aborted convenience builders, for fixtures
// that deliberately break the normal one-correlation-one-identity invariant:
// a real request can never legitimately change its own mode, session, or
// device between events, so these fixtures can only be built by hand.
func rawEvent(eventName, device, requestID, class, mode, session, reason string) carrierAuditEvent {
	return carrierAuditEvent{
		event:     eventName,
		device:    device,
		requestID: requestID,
		detail: terminalSchemaToken +
			" class=" + class + " mode=" + mode +
			" session=" + session + " reason=" + reason,
	}
}

// Codex's interim review, point 1: a unique, unforgeable correlation ID
// rules out one request's events being credited to another's tally by
// accident, but it does not by itself prove every event under that ID
// actually describes the same request. These three subtests each keep the
// SAME correlation ID across an authenticated event and a later event, but
// substitute one of mode/session/device_hash on the later event — the exact
// shape a bug or a forged event would take if it mislabeled which
// correlation an event belonged to while keeping the ID itself intact.
func TestConservationRejectsCorrelationMetadataSubstitution(t *testing.T) {
	id := hexID("sess-substitution")
	sessionA := hexID("session-A")
	sessionB := hexID("session-B")

	t.Run("SubstitutedMode", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				rawEvent(
					"carrier_h3_authenticated", "device-substitution-mode",
					id, "authenticated", "anonymous-token", sessionA, "none",
				),
				// Structurally valid mode ("identity" is a real enum
				// member), but different from what authenticated pinned.
				rawEvent(
					"carrier_h3_open", "device-substitution-mode",
					id, "open", "identity", sessionA, "none",
				),
				rawEvent(
					"carrier_h3_closed", "device-substitution-mode",
					id, "closed", "identity", sessionA, "none",
				),
			},
			redemptionCount: "1\n",
		})
		requireConservationReject(
			t, directory, "authenticated mode",
			"correlation authenticated as anonymous-token but a later event "+
				"under the same ID declares identity",
		)
	})

	t.Run("SubstitutedSession", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				rawEvent(
					"carrier_h3_authenticated", "device-substitution-session",
					id, "authenticated", "anonymous-token", sessionA, "none",
				),
				// Both values are validly-shaped 32-hex sessions; only
				// pinning-and-recheck distinguishes "valid" from "the same".
				rawEvent(
					"carrier_h3_open", "device-substitution-session",
					id, "open", "anonymous-token", sessionB, "none",
				),
				rawEvent(
					"carrier_h3_closed", "device-substitution-session",
					id, "closed", "anonymous-token", sessionB, "none",
				),
			},
			redemptionCount: "1\n",
		})
		requireConservationReject(
			t, directory, "authenticated session",
			"correlation authenticated under one session value but a later "+
				"event under the same ID declares a different one",
		)
	})

	t.Run("SubstitutedDeviceHash", func(t *testing.T) {
		directory := sealConservationEvidence(t, conservationFixture{
			events: []carrierAuditEvent{
				rawEvent(
					"carrier_h3_authenticated", "device-original",
					id, "authenticated", "anonymous-token", sessionA, "none",
				),
				// A different raw device string means internal/audit's own
				// HMAC(audit_key, deviceID) produces a different device_hash
				// automatically — no manual corruption needed to exercise
				// this path.
				rawEvent(
					"carrier_h3_open", "device-substituted",
					id, "open", "anonymous-token", sessionA, "none",
				),
				rawEvent(
					"carrier_h3_closed", "device-substituted",
					id, "closed", "anonymous-token", sessionA, "none",
				),
			},
			redemptionCount: "1\n",
		})
		requireConservationReject(
			t, directory, "authenticated device",
			"correlation authenticated under one device_hash but a later "+
				"event under the same ID hashes to a different one",
		)
	})
}

// mutateAuditRecord rewrites one field of the first matching event in a
// sealed carrier-audit.jsonl, then reseals the evidence manifest so the ONLY
// defect present is the field mutation itself — not an unrelated manifest
// digest mismatch. Breaks the record's own HMAC authentication, which is
// expected and irrelevant here: the semantic check under test runs on each
// record before the deferred structural-chain error would ever be returned,
// so the mutation's intended defect is what the verifier reports first.
func mutateAuditRecord(
	t *testing.T,
	directory string,
	eventName string,
	field string,
	value any,
) {
	t.Helper()
	path := filepath.Join(directory, "carrier-audit.jsonl")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	mutated := false
	for index, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("audit log line %d is not valid JSON: %v", index+1, err)
		}
		if !mutated && record["event"] == eventName {
			record[field] = value
			bytes, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			lines[index] = string(bytes)
			mutated = true
		}
	}
	if !mutated {
		t.Fatalf("event %q not found in %s", eventName, path)
	}
	if err := os.WriteFile(
		path, []byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	sealEvidenceManifest(t, directory)
}

// Codex's interim review, point 3: a tracked terminal record must carry a
// valid, non-empty 64-lower-hex device_hash before it is trusted for
// pinning. internal/audit always derives this field via
// HMAC(audit_key, deviceID) (audit.go:145-147) whenever a non-empty deviceID
// is supplied, so a malformed or empty value here can only be evidence
// tampering after the fact, not a normal carrier code path — which is
// exactly why the verifier must reject it rather than trust an
// opaque-but-wrong-shaped string.
func TestConservationRejectsMalformedDeviceHash(t *testing.T) {
	fixture := conservationFixture{
		events:          []carrierAuditEvent{authenticated("sess-A"), authOnly("sess-A")},
		redemptionCount: "1\n",
	}
	t.Run("NonHexValue", func(t *testing.T) {
		directory := sealConservationEvidence(t, fixture)
		mutateAuditRecord(
			t, directory, "carrier_h3_authenticated", "device_hash",
			"not-a-valid-hex-digest",
		)
		requireConservationReject(
			t, directory, "no usable device hash",
			"device_hash is present but not 64 lower-hex characters",
		)
	})
	t.Run("EmptyValue", func(t *testing.T) {
		directory := sealConservationEvidence(t, fixture)
		mutateAuditRecord(
			t, directory, "carrier_h3_authenticated", "device_hash", "",
		)
		requireConservationReject(
			t, directory, "no usable device hash",
			"device_hash is present but empty; empty must fail closed like "+
				"any other malformed shape, not be treated as absent-and-"+
				"therefore-unchecked",
		)
	})
}

// Codex's interim review, point 2 (closed schema): carrier-conservation.txt
// must reject any key beyond its declared 12 counts plus schema, not only
// missing or wrong-value ones. A field smuggled in under a look-alike name,
// or left over from a reverted schema version, must not ride along
// unexamined.
func TestConservationRejectsUnknownConservationKey(t *testing.T) {
	events := []carrierAuditEvent{authenticated("sess-A"), authOnly("sess-A")}
	h3, h2 := tallyByFamily(events)
	snapshot := conservationSnapshotContent("1", "1", h3, h2) +
		"unexpected_extra_field=1\n"
	directory := sealConservationEvidence(t, conservationFixture{
		events:               events,
		redemptionCount:      "1\n",
		conservationSnapshot: snapshot,
	})
	requireConservationReject(
		t, directory, "unknown key",
		"carrier-conservation.txt declares a key outside its closed schema",
	)
}
