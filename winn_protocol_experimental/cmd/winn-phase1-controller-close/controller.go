// Command winn-phase1-controller-close performs the matrix state transition
// that the producing host is not permitted to perform.
//
// WHAT THIS REPLACES.
//
// A per-evidence finalize script that closed one directory and published one
// archive. That was a stand-in, not the deliverable: closing evidence is one
// step of a matrix transition, and a step performed out of order, or performed
// on evidence that was never eligible, produces exactly the promotion-laundering
// this whole review cycle exists to prevent.
//
// THE ORDERED TRANSITION.
//
//	PRODUCER_CLOSED_PENDING + *.closed-pending
//	  1. verify producer state       full schedule, partial=0, deferred anchor
//	                                 mode committed up front, ZERO anchor
//	                                 artifacts on the producer
//	  2. close each batch            terminal checkpoint under the controller's
//	                                 finalizer, over the retrieved evidence
//	  3. publish each closed archive one atomic artifact per batch
//	  4. dual-provider anchors       over the CLOSED archives, never the
//	                                 producer's pre-checkpoint ones
//	  5. *.done                      the terminal batch records
//	  6. terminal seal               the aggregate anchor
//	  7. COMPLETE                    and only now
//
// Every phase refuses to run until its predecessor's outputs exist, and every
// phase is resumable, because each of its steps is idempotent or
// crash-recoverable on its own.
//
// WHAT CANNOT BE UPGRADED.
//
// Evidence produced with ANCHOR_MODE=disabled, or with ALLOW_PARTIAL_MATRIX=1,
// or without the committed deferred-anchor metadata, is not eligible and there
// is no flag here that makes it eligible. The commitment has to have been made
// before the first batch ran, in matrix.env, where it is part of the frozen
// compared parameters. A run that did not make it cannot make it afterwards:
// that is the difference between a deferred anchor and a retroactive one.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/closedarchive"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/producersnapshot"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	producerMarker      = "PRODUCER_CLOSED_PENDING"
	completeMarker      = "COMPLETE"
	deferredMode        = "controller-deferred-dual-provider-v1"
	intendedMode        = "dual-provider-v1"
	pendingSuffix       = ".closed-pending"
	doneSuffix          = ".done"
	auditLogName        = "carrier-audit.jsonl"
	manifestName        = "evidence-manifest.sha256"
	anchorSchema        = "winn-phase1-archive-pin/v1"
	batchSchemaV3       = "winn-phase1-auto-matrix-batch/v3"
	matrixSchemaV3      = "winn-phase1-auto-matrix-complete/v3"
	pendingSchema       = "winn-phase1-auto-matrix-batch-closed-pending/v3"
	producerSchema      = "winn-phase1-auto-matrix-closed-pending/v3"
	closedSuffix        = ".closed.tar.gz"
	pendingArchive      = ".closed-pending.tar.gz"
	maximumRecord       = 64 << 10
	maximumBatches      = 10_000
	genesisSlotName     = "000000-genesis"
	controllerEnvName   = "controller.env"
	controllerEnvSchema = "winn-phase1-controller-close/v1"
	// candidateCompleteName is deliberately dot-prefixed and not
	// completion-shaped: it exists only while the final verification runs, and
	// it must never be mistaken for a terminal marker if a crash leaves it.
	candidateCompleteName = ".controller-complete-candidate"
	// candidatePassMarker records that a candidate pass happened, under a name
	// and a schema that say plainly it is not a promotion.
	candidatePassMarker = "CONTROLLER_CANDIDATE_PASS_NON_PROMOTIONAL"
	// #nosec G101 -- a schema token, not a credential. It names a document
	// format; nothing here is secret and nothing authenticates with it.
	candidatePassSchema = "winn-phase1-controller-candidate-pass/v1"
)

var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Receipts are the two provider receipt digests one anchor produced.
type Receipts struct {
	RequestSHA256    string
	ProviderOneSHA25 string
	ProviderTwoSHA25 string
}

// AnchorRunner performs one dual-provider anchor. It is an interface so the
// ordering and eligibility logic above can be tested without two live SSH
// providers; production wires it to the real winn-phase1-anchor-pin binary.
type AnchorRunner interface {
	Anchor(slot string, request []byte, previousOne, previousTwo string) (Receipts, error)
}

// Controller is one transition.
type Controller struct {
	MatrixRoot           string
	FinalizerSeedPath    string
	ExpectedSourceDigest string
	Anchor               AnchorRunner
	Verifier             Verifier
	AnchorProviderOneID  string
	AnchorProviderOneKey string
	AnchorProviderTwoID  string
	AnchorProviderTwoKey string
	AnchorKnownHosts     string
	// Out receives progress lines.
	Out *os.File

	sealReceipts    Receipts
	aggregateDigest string
	// crashAfter aborts immediately after the named completion stage. Test-only
	// and unexported, so no production caller can reach it.
	crashAfter       completionStage
	finalizerKeyID   string
	signedSnapshot   string
	trust            *trustView
	started          *controllerStart
	usingFrozenTrust bool
	// mutateAfterParse and mutateBeforeAnchor are test-only injection points
	// for the two race windows this sandwich closes. Unexported, so no
	// production caller can reach them.
	mutateAfterParse   func()
	mutateBeforeAnchor func()
	// mutateAfterGate fires AFTER the last reversible gate and before the first
	// anchor — the window in which a trust swap must not be able to reach a
	// provider.
	mutateAfterGate func()
	// mutateBetweenTrustReads fires after loadTrustInputs and before the
	// signed-record comparison — the window a swap-then-restore would exploit.
	mutateBetweenTrustReads func()
}

func (c *Controller) log(format string, arguments ...any) {
	if c.Out == nil {
		return
	}
	fmt.Fprintf(c.Out, format+"\n", arguments...)
}

// readKeyValues parses the project's key=value record format, rejecting a
// duplicated key rather than silently keeping one of the two values.
func readKeyValues(path string) (map[string]string, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- controller-selected root
	if err != nil {
		return nil, err
	}
	if len(content) > maximumRecord {
		return nil, fmt.Errorf("%s is too large to be a record", path)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid key/value line in %s", path)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("duplicate key %q in %s", key, path)
		}
		values[key] = value
	}
	return values, nil
}

// writeCreateOnce publishes a terminal record that must never be silently
// replaced. A .done or a COMPLETE that a second run could overwrite would let a
// later, weaker transition quietly supersede an earlier one.
func writeCreateOnce(path string, content []byte) error {
	existing, err := os.ReadFile(path) // #nosec G304 -- controller-selected root
	if err == nil {
		if string(existing) == string(content) {
			// Idempotent resume: this run would have written exactly this.
			return nil
		}
		return fmt.Errorf(
			"%s already exists with different content; refusing to replace a "+
				"terminal record", path,
		)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return securefile.AtomicWriteNew(path, content, 0o600)
}

func sha256Of(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- controller-selected root
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func lowerHex(value string) bool {
	if len(value) != 64 {
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

// producerState is what the producing host committed to, read back and checked
// rather than assumed.
type producerState struct {
	matrixID          string
	sourceDigest      string
	anchorMode        string
	intendedMode      string
	partial           string
	scheduleDigest    string
	profileDigest     string
	artifactDigest    string
	producerAttempts  int
	executionInventor string
}

type batchRecord struct {
	key              string
	ordinal          int
	block            string
	orderDigest      string
	profile          string
	readiness        string
	attempts         string
	attemptCount     int
	startedAt        string
	finishedAt       string
	archiveRelative  string
	evidenceRelative string
	pendingSHA256    string
	inventory        string
	scheduleRowSHA   string
	closedArchive    string
	closedSHA256     string
	evidenceDir      string
	manifestSHA256   string
	attemptLogSHA    string
	attemptAnchorSHA string
	receipts         Receipts
}

// BatchVerification names one closed batch for the real verifier.
type BatchVerification struct {
	EvidenceDirectory string
	FinalizerKeyID    string
	RunID             string
	ProducerDigest    string
}

// Verifier runs the project's real verification logic. It is an interface only
// so the transition's ORDERING can be tested without two live anchor providers;
// production wires both methods to the actual winn-phase1-matrix-verify binary,
// never to a reimplementation of it.
type Verifier interface {
	// VerifyBatch runs the checkpoint and conservation verification over one
	// closed evidence directory.
	VerifyBatch(BatchVerification) error
	// VerifyMatrix runs the full matrix verification against a candidate
	// completion record that has not yet been promoted to COMPLETE.
	VerifyMatrix(completeRecordName string) error
}

// Run performs the whole ordered transition.
func (c *Controller) Run() error {
	if c.Verifier == nil {
		return errors.New("no verifier is configured")
	}
	// Seed custody first, then the credential, then ownership, then the trust
	// set, then anything the producer wrote. The signer has to exist and be
	// validated before the state transition, because the start record that
	// establishes ownership is signed with it: a controller that inspected the
	// matrix first would be deciding whether to trust existing state before it
	// knew whose state it was.
	//
	// Seed custody and trust-input SELECTION are deliberately separate steps.
	// They were one, and entangling them meant the trust inputs were always
	// read from the operator's original paths — so a resume could not use the
	// frozen copies at all, and the freeze protected nothing on the path that
	// actually runs.
	if err := c.verifySeedCustody(); err != nil {
		return err
	}
	signer, err := auditcheckpoint.LoadFinalizer(c.FinalizerSeedPath)
	if err != nil {
		return err
	}
	defer signer.Destroy()
	c.finalizerKeyID = signer.KeyID()

	// Ownership, verified against the signer this run actually loaded rather
	// than an identity derived from a separate read of the seed.
	// An unverifiable record is a refusal, never a fall-through to first-run.
	started, err := c.loadControllerStart(signer)
	if err != nil {
		return err
	}
	if err := c.selectTrustInputs(started); err != nil {
		return err
	}

	// The snapshot sandwich.
	//
	// A single measurement is not enough, in either direction. Measured only
	// before the parse, the signature can end up covering a state the parse
	// never saw; measured only at signing time, it can cover a state NEWER than
	// the one the anchors are built from — the signature and the anchored
	// content diverging silently, which is the worst possible outcome because
	// both look internally consistent.
	//
	// So the state is measured, parsed, and measured again, and the two
	// measurements must be identical. Only then do the parsed values and the
	// signed digest provably describe the same instant.
	before, err := producersnapshot.Digest(c.MatrixRoot)
	if err != nil {
		return err
	}
	// On a resume the signed digest is checked against that first measurement
	// immediately, before anything is interpreted: a later check would be
	// reading files whose drift is the thing under suspicion, and would report
	// it as whatever downstream inconsistency it happened to cause.
	if started != nil && started.ProducerSnapshot != before {
		return snapshotDriftError(started.ProducerSnapshot, before)
	}
	state, err := c.verifyProducerState(started != nil)
	if err != nil {
		return err
	}
	schedule, err := c.loadSchedule()
	if err != nil {
		return err
	}
	batches, err := c.loadPendingBatches(state, schedule)
	if err != nil {
		return err
	}
	if c.mutateAfterParse != nil {
		c.mutateAfterParse()
	}
	after, err := producersnapshot.Digest(c.MatrixRoot)
	if err != nil {
		return err
	}
	if after != before {
		return fmt.Errorf(
			"the producer state changed while it was being read: it hashed to "+
				"%s before the parse and %s after. The parsed values and the "+
				"signature would describe different states", before, after,
		)
	}

	if started != nil {
		if err := c.requireStartAgrees(started, state, batches); err != nil {
			return err
		}
		c.log("CONTROLLER_RESUME start_record=verified matrix=%s", state.matrixID)
	} else {
		// The freshly published record is RETAINED, not discarded, and held to
		// the same agreement check a resumed one gets. Discarding it left a
		// first run with nothing to re-check its own trust inputs against.
		published, err := c.publishControllerStart(
			state, batches, before, signer,
		)
		if err != nil {
			return err
		}
		if err := c.requireStartAgrees(published, state, batches); err != nil {
			return err
		}
		started = published
	}
	c.started = started
	c.signedSnapshot = before
	// Only now: the anchor root. Publishing ownership first means a crash here
	// leaves a verifiable claim and no anchors, which resumes; the reverse
	// order would leave anchors with no claim, and every retry would read that
	// as a producer violation and refuse forever.
	if err := c.freezeAnchorRoot(); err != nil {
		return err
	}
	// Anonymous snapshots taken once, here, before the last reversible gate.
	// From this point nothing downstream resolves a trust PATHNAME at all: the
	// anchor subprocess receives /dev/fd names backed by unnamed inodes, and
	// every in-process check reads the captured bytes directly.
	if err := c.snapshotFrozenTrust(); err != nil {
		return err
	}
	defer c.trust.close()
	c.adoptFrozenTrust(c.finalizerKeyID)
	if err := c.writeControllerState(state, len(batches)); err != nil {
		return err
	}

	for index := range batches {
		if err := c.closeBatch(state, &batches[index], signer); err != nil {
			return fmt.Errorf("batch %s: %w", batches[index].key, err)
		}
	}
	// Everything checkable, checked, before the first irreversible step. An
	// anchor is two independent providers durably signing a statement about
	// this matrix; there is no operation that retracts one. Any defect that can
	// be found by reading files has to be found here, while the only cost of
	// stopping is a failed run.
	if c.mutateBeforeAnchor != nil {
		c.mutateBeforeAnchor()
	}
	if err := c.verifyLastReversibleGate(state, schedule, batches); err != nil {
		return err
	}
	if c.mutateAfterGate != nil {
		c.mutateAfterGate()
	}
	if err := c.anchorAndRecord(state, batches); err != nil {
		return err
	}
	if err := c.writeComplete(state, batches); err != nil {
		return err
	}
	c.log("CONTROLLER_CLOSE_COMPLETE matrix=%s batches=%d",
		state.matrixID, len(batches))
	return nil
}

// --- phase 1: producer eligibility ----------------------------------------

// verifyProducerState decides whether this matrix root is even a candidate.
//
// The three refusals here are the ones that matter, and none of them has an
// override:
//
//   - partial=1. A partial run is a subset of the frozen schedule. There is no
//     operation that turns a subset into the whole, so there is no path from
//     partial evidence to a formal matrix.
//   - anchor_mode != the deferred mode. Anchoring has to have been INTENDED
//     before the first batch ran. A run that was configured as exploratory
//     cannot be reclassified afterwards, because the commitment is what the
//     controller is verifying — a commitment made after the fact verifies
//     nothing.
//   - any anchor artifact on the producer. The deferred mode's whole claim is
//     that no anchoring happened there.
func (c *Controller) verifyProducerState(resuming bool) (producerState, error) {
	root := c.MatrixRoot
	if root == "" {
		return producerState{}, errors.New("matrix root is required")
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() {
		return producerState{}, errors.New("matrix root must be a real directory")
	}
	// An existing COMPLETE is deliberately NOT refused here.
	//
	// Refusing early looks safe and is the opposite: a crash at or after
	// COMPLETE publication would leave a root that every later attempt bounces
	// off, so the last step of the transition would be the one that made the
	// transition unfinishable. It also makes re-entry into a finished state an
	// error, when the correct answer is "already done".
	//
	// Every step from here on is idempotent — checkpoints are create-once and
	// re-verified, archives recognise their own published artifact, anchors
	// re-verify committed slots against both providers' signatures, terminal
	// records are create-once with exact-match resume — so a re-run reconciles
	// rather than duplicates, and writeComplete makes the final judgement: a
	// COMPLETE this run agrees with is success, and one it does not agree with
	// is a refusal.
	marker, err := readKeyValues(filepath.Join(root, producerMarker))
	if err != nil {
		return producerState{}, fmt.Errorf(
			"this matrix carries no %s marker, so the producer never finished "+
				"a closed-pending run over it: %w", producerMarker, err,
		)
	}
	environment, err := readKeyValues(filepath.Join(root, "matrix.env"))
	if err != nil {
		return producerState{}, err
	}

	if marker["schema"] != producerSchema {
		return producerState{}, fmt.Errorf(
			"%s declares schema %q, want %q",
			producerMarker, marker["schema"], producerSchema,
		)
	}
	// Eligibility, in the order a reader should think about it.
	if marker["partial"] != "0" || environment["partial"] != "0" {
		return producerState{}, fmt.Errorf(
			"this matrix was produced with partial=%q (matrix.env %q). A "+
				"partial run is a subset of the frozen schedule, and no "+
				"controller operation turns a subset into the whole; it cannot "+
				"be promoted to a formal matrix by this or any other path",
			marker["partial"], environment["partial"],
		)
	}
	for source, values := range map[string]map[string]string{
		producerMarker: marker,
		"matrix.env":   environment,
	} {
		if values["anchor_mode"] != deferredMode {
			return producerState{}, fmt.Errorf(
				"%s records anchor_mode=%q, want %q. Deferred anchoring has to "+
					"be committed before the first batch runs; evidence produced "+
					"under any other mode cannot be reclassified afterwards, "+
					"because a commitment made after the fact commits to nothing",
				source, values["anchor_mode"], deferredMode,
			)
		}
		if values["intended_anchor_mode"] != intendedMode {
			return producerState{}, fmt.Errorf(
				"%s records intended_anchor_mode=%q, want %q; the producer never "+
					"committed to controller-side dual-provider anchoring",
				source, values["intended_anchor_mode"], intendedMode,
			)
		}
	}
	if environment["matrix_id"] == "" ||
		!safeIdentifier.MatchString(environment["matrix_id"]) {
		return producerState{}, errors.New("matrix.env has no usable matrix_id")
	}
	if marker["matrix_id"] != environment["matrix_id"] {
		return producerState{}, errors.New(
			"the producer marker and matrix.env disagree about matrix_id",
		)
	}
	if c.ExpectedSourceDigest == "" || !lowerHex(c.ExpectedSourceDigest) {
		return producerState{}, errors.New(
			"the controller requires an externally pinned source digest",
		)
	}
	if environment["source_digest"] != c.ExpectedSourceDigest {
		return producerState{}, fmt.Errorf(
			"matrix.env records source_digest=%s, the controller pinned %s",
			environment["source_digest"], c.ExpectedSourceDigest,
		)
	}

	// Zero anchor artifacts on the PRODUCER. This is the property the deferred
	// mode asserts and the one the controller must not take on trust.
	//
	// The check has to distinguish producer state from this controller's own
	// earlier state, because a resumed transition legitimately owns
	// <root>/anchors. What tells them apart is the SIGNED start record: the
	// producing host cannot have produced one, because it does not hold the
	// finalizer key. An unsigned marker could not do this — anything able to
	// write a file could forge it, and the resume path is precisely the path
	// that tolerates pre-existing anchors.
	//
	// The producer guarantee is untouched. On a first run there is no valid
	// start record, so anchors/ must be absent, full stop; on a resume every
	// committed slot is re-verified against both providers' signatures before
	// it is reused.
	if _, err := os.Lstat(filepath.Join(root, "anchors")); err == nil && !resuming {
		return producerState{}, errors.New(
			"the producer holds anchor artifacts under a deferred-anchor run; " +
				"the separation the mode claims did not hold",
		)
	}
	// A .done present here is NOT automatically a producer violation. This
	// controller writes .done records as it goes, so a run interrupted between
	// the first .done and the terminal seal leaves them behind, and refusing
	// them outright would make that ordinary crash unrecoverable. What
	// distinguishes the two cases is the controller's own state file: the
	// producer cannot have written that, so its presence means the records
	// belong to an earlier attempt of this transition. Each one is then
	// re-derived and compared exactly by writeDone's create-once rule.
	entries, err := os.ReadDir(filepath.Join(root, "batches"))
	if err != nil {
		return producerState{}, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), doneSuffix) {
			continue
		}
		if !resuming {
			return producerState{}, fmt.Errorf(
				"the producer wrote a terminal batch record %s; terminal "+
					"records are the controller's to write", entry.Name(),
			)
		}
	}

	producerAttempts, err := strconv.Atoi(marker["attempts"])
	if err != nil || producerAttempts <= 0 {
		return producerState{}, errors.New("producer marker has no usable attempt total")
	}
	// Syntax only, here. The digest the marker claims has to be a digest at
	// all before anything downstream carries it, and reporting that early gives
	// the operator the real reason instead of a confusing failure later.
	//
	// This is deliberately NOT where the inventory is decided. The claim is
	// cross-checked against matrix.env and against the file's actual bytes in
	// verifyLastReversibleGate, immediately before the first provider is
	// contacted — see the note there on why it belongs at that instant and not
	// at this one.
	if !lowerHex(marker["execution_inventory_sha256"]) {
		return producerState{}, fmt.Errorf(
			"producer marker records execution_inventory_sha256=%q, which is "+
				"not a lowercase 64-hex SHA-256 digest",
			marker["execution_inventory_sha256"],
		)
	}
	if marker["schedule_sha256"] != environment["schedule_sha256"] {
		return producerState{}, errors.New(
			"the producer marker and matrix.env disagree about the schedule",
		)
	}
	return producerState{
		matrixID:          environment["matrix_id"],
		sourceDigest:      c.ExpectedSourceDigest,
		anchorMode:        deferredMode,
		intendedMode:      intendedMode,
		partial:           "0",
		scheduleDigest:    marker["schedule_sha256"],
		producerAttempts:  producerAttempts,
		profileDigest:     environment["profile_sha256"],
		artifactDigest:    environment["auto_artifact_sha256"],
		executionInventor: marker["execution_inventory_sha256"],
	}, nil
}

// --- schedule ---------------------------------------------------------------

// scheduledBatch is one row of the frozen schedule, in the order the schedule
// states it.
type scheduledBatch struct {
	block       int
	orderDigest string
	key         string
	profile     string
	readiness   string
	attempts    int
}

// loadSchedule reads schedule.tsv, which is the source of truth for both the
// SET of batches and their ORDER.
//
// Ordering matters concretely, not aesthetically: the anchor chain is
// sequential, each request carries its ordinal, and each receipt commits to the
// previous one. A controller that anchored in sorted-key order would build a
// chain the verifier — which walks the schedule — cannot reproduce, and every
// ordinal after the first divergence would be wrong.
func (c *Controller) loadSchedule() ([]scheduledBatch, error) {
	path := filepath.Join(c.MatrixRoot, "schedule.tsv")
	content, err := os.ReadFile(path) // #nosec G304 -- controller-selected root
	if err != nil {
		return nil, err
	}
	var schedule []scheduledBatch
	for number, line := range strings.Split(
		strings.TrimSuffix(string(content), "\n"), "\n",
	) {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			return nil, fmt.Errorf(
				"schedule.tsv line %d is not the six-column frozen form",
				number+1,
			)
		}
		block, err := strconv.Atoi(fields[0])
		if err != nil || block < 1 {
			return nil, fmt.Errorf("schedule.tsv line %d has no block", number+1)
		}
		attempts, err := strconv.Atoi(fields[5])
		if err != nil || attempts < 1 {
			return nil, fmt.Errorf(
				"schedule.tsv line %d has no attempt count", number+1,
			)
		}
		if !safeIdentifier.MatchString(fields[2]) {
			return nil, fmt.Errorf(
				"schedule.tsv line %d has an unusable batch key", number+1,
			)
		}
		schedule = append(schedule, scheduledBatch{
			block:       block,
			orderDigest: fields[1],
			key:         fields[2],
			profile:     fields[3],
			readiness:   fields[4],
			attempts:    attempts,
		})
		if len(schedule) > maximumBatches {
			return nil, errors.New("schedule.tsv is implausibly long")
		}
	}
	if len(schedule) == 0 {
		return nil, errors.New("schedule.tsv is empty")
	}
	return schedule, nil
}

// scheduleRowDigest reproduces the exact row encoding the verifier hashes. The
// format string is duplicated from the verifier on purpose, mirroring how the
// verifier duplicates the carrier's schema token: the two have to be edited
// together, and a drift produces a loud anchor mismatch rather than a silent
// one.
func scheduleRowDigest(row scheduledBatch) string {
	encoded := fmt.Sprintf("%06d\t%s\t%s\t%s\t%s\t%d\n",
		row.block, row.orderDigest, row.key, row.profile,
		row.readiness, row.attempts,
	)
	sum := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(sum[:])
}

// loadPendingBatches pairs every scheduled row with its producer record, in
// schedule order, and requires the two sets to match exactly.
func (c *Controller) loadPendingBatches(
	state producerState,
	schedule []scheduledBatch,
) ([]batchRecord, error) {
	directory := filepath.Join(c.MatrixRoot, "batches")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	pending := make(map[string]map[string]string)
	for _, entry := range entries {
		if !entry.Type().IsRegular() ||
			!strings.HasSuffix(entry.Name(), pendingSuffix) {
			continue
		}
		values, err := readKeyValues(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		key := values["batch_key"]
		if !safeIdentifier.MatchString(key) ||
			key+pendingSuffix != entry.Name() {
			return nil, fmt.Errorf("%s has an inconsistent batch key", entry.Name())
		}
		if _, duplicate := pending[key]; duplicate {
			return nil, fmt.Errorf("batch %s has two producer records", key)
		}
		pending[key] = values
	}
	if len(pending) != len(schedule) {
		return nil, fmt.Errorf(
			"the producer sealed %d batches, the frozen schedule has %d; a "+
				"partial set cannot be completed into a formal matrix",
			len(pending), len(schedule),
		)
	}

	batches := make([]batchRecord, 0, len(schedule))
	for index, row := range schedule {
		values, present := pending[row.key]
		if !present {
			return nil, fmt.Errorf(
				"the frozen schedule requires batch %s and the producer sealed "+
					"no record for it", row.key,
			)
		}
		if values["schema"] != pendingSchema {
			return nil, fmt.Errorf(
				"batch %s declares schema %q, want %q",
				row.key, values["schema"], pendingSchema,
			)
		}
		if values["anchor_mode"] != deferredMode {
			return nil, fmt.Errorf(
				"batch %s records anchor_mode=%q; every batch of a deferred run "+
					"must declare the deferred mode", row.key, values["anchor_mode"],
			)
		}
		for _, forbidden := range []string{
			"anchor_request_sha256",
			"anchor_provider_one_receipt_sha256",
			"anchor_provider_two_receipt_sha256",
		} {
			if values[forbidden] != "" {
				return nil, fmt.Errorf(
					"batch %s already carries %s; the producer anchored something",
					row.key, forbidden,
				)
			}
		}
		if values["execution_inventory_sha256"] != state.executionInventor {
			return nil, fmt.Errorf(
				"batch %s is not bound to the matrix execution inventory", row.key,
			)
		}
		// The producer's row values must match the frozen schedule's, or the
		// anchor request this controller builds would describe a batch that was
		// never scheduled.
		if values["profile"] != row.profile ||
			values["readiness"] != row.readiness ||
			values["attempts"] != strconv.Itoa(row.attempts) ||
			values["order_digest"] != row.orderDigest ||
			values["randomized_block"] != strconv.Itoa(row.block) {
			return nil, fmt.Errorf(
				"batch %s does not match its frozen schedule row", row.key,
			)
		}
		relative := values["archive_relative"]
		if err := producersnapshot.RequireEvidenceRelative(relative); err != nil {
			return nil, fmt.Errorf(
				"batch %s names an unusable producer archive %q: %w",
				row.key, relative, err,
			)
		}
		// The evidence directory is the archive name minus the producer's
		// suffix, computed once, here, and then carried explicitly. Downstream
		// code and the verifier both read the mapping rather than re-deriving
		// it from whatever suffix an archive happens to have.
		evidenceRelative := strings.TrimSuffix(relative, pendingArchive)
		batches = append(batches, batchRecord{
			key:              row.key,
			ordinal:          index + 1,
			block:            strconv.Itoa(row.block),
			orderDigest:      row.orderDigest,
			profile:          row.profile,
			readiness:        row.readiness,
			attempts:         strconv.Itoa(row.attempts),
			attemptCount:     row.attempts,
			scheduleRowSHA:   scheduleRowDigest(row),
			startedAt:        values["started_at_utc"],
			finishedAt:       values["finished_at_utc"],
			archiveRelative:  relative,
			evidenceRelative: evidenceRelative,
			pendingSHA256:    values["archive_sha256"],
			inventory:        values["execution_inventory_sha256"],
			evidenceDir:      filepath.Join(c.MatrixRoot, evidenceRelative),
		})
	}
	return batches, nil
}

// --- phase 2/3: close, publish, then VERIFY each batch ----------------------

// closeBatch seals the terminal checkpoint, publishes the single closed
// artifact, and then runs the real verifier over the result.
//
// The verification is inside this step, before anything is anchored, because
// anchoring is externally witnessed and irreversible: two independent providers
// sign a durable statement about an artifact, and there is no operation that
// retracts it. Anchoring first and verifying afterwards would mean discovering
// a defect in evidence that has already been permanently attested.
func (c *Controller) closeBatch(
	state producerState,
	batch *batchRecord,
	signer *pqauth.Signer,
) error {
	runID := state.matrixID + "-" + batch.key
	checkpoint := filepath.Join(batch.evidenceDir, auditcheckpoint.FileName)
	if _, err := os.Lstat(checkpoint); err == nil {
		if _, err := auditcheckpoint.Verify(auditcheckpoint.VerifyInput{
			EvidenceDirectory:      batch.evidenceDir,
			ExpectedFinalizerKeyID: signer.KeyID(),
			ExpectedRunID:          runID,
			ExpectedProducerDigest: state.sourceDigest,
			AuditLogName:           auditLogName,
		}); err != nil {
			return fmt.Errorf(
				"an existing checkpoint does not match this run: %w", err,
			)
		}
		c.log("CONTROLLER_RESUME batch=%s checkpoint=verified", batch.key)
	} else if _, err := auditcheckpoint.Seal(auditcheckpoint.SealInput{
		EvidenceDirectory: batch.evidenceDir,
		AuditLogName:      auditLogName,
		ManifestName:      manifestName,
		RunID:             runID,
		ProducerDigest:    state.sourceDigest,
		Signer:            signer,
	}); err != nil {
		return err
	}

	published, err := closedarchive.Publish(closedarchive.Input{
		EvidenceDirectory: batch.evidenceDir,
		Destination:       batch.evidenceDir + closedSuffix,
	})
	if err != nil {
		return err
	}
	batch.closedArchive = published.Destination
	batch.closedSHA256 = published.SHA256

	// The real verifier, over the real closed evidence, before this batch is
	// eligible to be anchored.
	if err := c.Verifier.VerifyBatch(BatchVerification{
		EvidenceDirectory: batch.evidenceDir,
		FinalizerKeyID:    signer.KeyID(),
		RunID:             runID,
		ProducerDigest:    state.sourceDigest,
	}); err != nil {
		return fmt.Errorf("closed evidence failed verification: %w", err)
	}

	for name, target := range map[string]*string{
		manifestName:            &batch.manifestSHA256,
		"attempts.jsonl":        &batch.attemptLogSHA,
		"attempts.jsonl.anchor": &batch.attemptAnchorSHA,
	} {
		digest, err := sha256Of(filepath.Join(batch.evidenceDir, name))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		*target = digest
	}
	c.log("CONTROLLER_CLOSE batch=%s ordinal=%d closed_sha256=%s",
		batch.key, batch.ordinal, batch.closedSHA256)
	return nil
}

// --- phase 4/5/6: anchor, then .done, then the terminal seal ----------------

// anchorAndRecord walks the batches in schedule order. For each one it anchors,
// then writes the terminal .done record, then accumulates the aggregate row.
//
// That order is forced by the verifier's aggregate shape, which is
//
//	ordinal \t request digest \t receipt one \t receipt two \t .done digest
//
// The .done digest is in it. A controller that sealed the aggregate before
// writing the .done records could not compute the rows it needs, and any
// aggregate it did produce would be one the verifier cannot reproduce.
func (c *Controller) anchorAndRecord(
	state producerState,
	batches []batchRecord,
) error {
	if c.Anchor == nil {
		return errors.New("no anchor runner is configured")
	}
	for index := range batches {
		if batches[index].closedSHA256 == "" {
			return errors.New(
				"anchoring was reached before every batch was closed and verified",
			)
		}
	}
	identity := phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		MatrixID:           state.matrixID,
		SourceDigest:       state.sourceDigest,
		AutoArtifactDigest: state.artifactDigest,
		ProfileDigest:      state.profileDigest,
		ScheduleDigest:     state.scheduleDigest,
		ExpectedBatchCount: len(batches),
	}

	genesis := identity
	genesis.Kind = phase1anchor.KindGenesis
	genesis.Ordinal = 0
	// phase1anchor.ZeroDigest, never "". The empty string is not a canonical
	// digest, and phase1anchor rejects it — so this call would have travelled
	// all the way to two external providers and failed there, mid-chain, on a
	// sequence that cannot be retracted.
	receipts, err := c.anchorOne(
		genesisSlotName, genesis,
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	if err != nil {
		return fmt.Errorf("genesis anchor: %w", err)
	}
	previousOne, previousTwo := receipts.ProviderOneSHA25, receipts.ProviderTwoSHA25

	var aggregate strings.Builder
	for index := range batches {
		batch := &batches[index]
		request := identity
		request.Kind = phase1anchor.KindBatch
		request.Ordinal = batch.ordinal
		request.BatchKey = batch.key
		request.ScheduleRowDigest = batch.scheduleRowSHA
		request.Profile = batch.profile
		request.Readiness = batch.readiness
		request.AttemptCount = batch.attemptCount
		// The CLOSED archive, never the producer's pre-checkpoint one.
		request.ArchiveDigest = batch.closedSHA256
		request.EvidenceManifestDigest = batch.manifestSHA256
		request.AttemptLogDigest = batch.attemptLogSHA
		request.AttemptAnchorDigest = batch.attemptAnchorSHA

		slot := fmt.Sprintf("%06d-%s", batch.ordinal, batch.key)
		receipts, err := c.anchorOne(slot, request, previousOne, previousTwo)
		if err != nil {
			return fmt.Errorf("batch %s anchor: %w", batch.key, err)
		}
		batch.receipts = receipts
		previousOne, previousTwo = receipts.ProviderOneSHA25, receipts.ProviderTwoSHA25

		if err := c.writeDone(*batch); err != nil {
			return fmt.Errorf("batch %s: %w", batch.key, err)
		}
		doneDigest, err := sha256Of(
			filepath.Join(c.MatrixRoot, "batches", batch.key+doneSuffix),
		)
		if err != nil {
			return err
		}
		fmt.Fprintf(&aggregate, "%06d\t%s\t%s\t%s\t%s\n",
			batch.ordinal, receipts.RequestSHA256,
			receipts.ProviderOneSHA25, receipts.ProviderTwoSHA25, doneDigest,
		)
		c.log("CONTROLLER_ANCHOR batch=%s ordinal=%d done=written",
			batch.key, batch.ordinal)
	}
	return c.terminalSeal(identity, batches, aggregate.String(), previousOne, previousTwo)
}

// anchorOne validates the request before it leaves this process, so a malformed
// request is a local refusal rather than something two external providers are
// asked to sign.
func (c *Controller) anchorOne(
	slot string,
	request phase1anchor.Request,
	previousOne, previousTwo string,
) (Receipts, error) {
	if err := request.Validate(); err != nil {
		return Receipts{}, fmt.Errorf("anchor request %s: %w", slot, err)
	}
	// Both predecessors, checked here, before the runner is reached and long
	// before any provider is contacted. A malformed predecessor is a local
	// programming error; discovering it after two external providers have been
	// asked to sign wastes an irreversible step to learn something this process
	// already knew.
	for label, previous := range map[string]string{
		"first":  previousOne,
		"second": previousTwo,
	} {
		if !phase1anchor.ValidPreviousDigest(previous, request.Ordinal) {
			if request.Ordinal == 0 {
				return Receipts{}, fmt.Errorf(
					"anchor %s: the %s genesis predecessor is %q, want the "+
						"canonical zero digest", slot, label, previous,
				)
			}
			return Receipts{}, fmt.Errorf(
				"anchor %s: the %s predecessor %q is not a canonical "+
					"non-genesis receipt digest", slot, label, previous,
			)
		}
	}
	encoded, err := request.Canonical()
	if err != nil {
		return Receipts{}, err
	}
	return c.Anchor.Anchor(slot, encoded, previousOne, previousTwo)
}

func (c *Controller) terminalSeal(
	identity phase1anchor.Request,
	batches []batchRecord,
	aggregate string,
	previousOne, previousTwo string,
) error {
	aggregatePath := filepath.Join(c.MatrixRoot, "anchors", "terminal-aggregate.list")
	if err := writeCreateOnce(aggregatePath, []byte(aggregate)); err != nil {
		return err
	}
	aggregateDigest, err := sha256Of(aggregatePath)
	if err != nil {
		return err
	}
	seal := identity
	seal.Kind = phase1anchor.KindSeal
	seal.Ordinal = len(batches) + 1
	seal.AggregateDigest = aggregateDigest
	slot := fmt.Sprintf("%06d-terminal-seal", seal.Ordinal)
	receipts, err := c.anchorOne(slot, seal, previousOne, previousTwo)
	if err != nil {
		return fmt.Errorf("terminal seal anchor: %w", err)
	}
	c.sealReceipts = receipts
	c.aggregateDigest = aggregateDigest
	c.log("CONTROLLER_TERMINAL_SEAL aggregate_sha256=%s", aggregateDigest)
	return nil
}

// writeDone publishes one terminal batch record.
//
// Create-once with an exact-match resume: a controller that crashed after
// writing a .done and before the terminal seal must be able to run again, and a
// rule that refused any pre-existing .done would wedge exactly that state
// permanently. An incumbent whose bytes differ is still a refusal, because two
// different terminal records for one batch cannot both be true.
func (c *Controller) writeDone(batch batchRecord) error {
	if batch.receipts.ProviderOneSHA25 == "" ||
		batch.receipts.ProviderTwoSHA25 == "" {
		return errors.New(
			"a terminal batch record was reached before the batch was anchored",
		)
	}
	path := filepath.Join(c.MatrixRoot, "batches", batch.key+doneSuffix)
	record := strings.Join([]string{
		"schema=" + batchSchemaV3,
		"batch_key=" + batch.key,
		"randomized_block=" + batch.block,
		"order_digest=" + batch.orderDigest,
		"profile=" + batch.profile,
		"readiness=" + batch.readiness,
		"attempts=" + batch.attempts,
		"started_at_utc=" + batch.startedAt,
		"finished_at_utc=" + batch.finishedAt,
		"archive=" + batch.closedArchive,
		"archive_relative=" + batch.evidenceRelative + closedSuffix,
		"evidence_relative=" + batch.evidenceRelative,
		"archive_sha256=" + batch.closedSHA256,
		"execution_inventory_sha256=" + batch.inventory,
		"anchor_mode=" + intendedMode,
		"anchor_request_sha256=" + batch.receipts.RequestSHA256,
		"anchor_provider_one_receipt_sha256=" + batch.receipts.ProviderOneSHA25,
		"anchor_provider_two_receipt_sha256=" + batch.receipts.ProviderTwoSHA25,
	}, "\n") + "\n"
	return writeCreateOnce(path, []byte(record))
}

// --- phase 7: full verification, then COMPLETE ------------------------------

// completionStage names the crash boundaries of the completion sequence.
type completionStage string

const (
	stageAfterCandidate   completionStage = "after-candidate"
	stageAfterVerify      completionStage = "after-verify"
	stageAfterPassMarker  completionStage = "after-pass-marker"
	stageAfterComplete    completionStage = "after-complete"
	stageBeforeCandidateC completionStage = "before-candidate-cleanup"
)

// writeComplete runs a full verifier pass over a CANDIDATE record and only then
// publishes COMPLETE.
//
// Every step is idempotent and every piece of state is reconcilable against the
// others, because this sequence is interrupted in practice and a resume must be
// able to finish it.
//
// The subtlety that makes that hard is the timestamp. An earlier version
// regenerated completed_at_utc on each attempt, which changed the candidate's
// bytes, which changed its digest — so a pass marker published by attempt one
// (and bound to attempt one's digest) could never agree with attempt two's
// freshly minted candidate. The interruption produced a permanent conflict.
//
// So the FIRST candidate's bytes are durable state. A resume reads them, checks
// them against what this run would produce in every field except the timestamp,
// and then reuses them verbatim — timestamp included. Nothing regenerates, and
// nothing is silently replaced: a candidate that disagrees is a refusal, not
// something to clobber.
func (c *Controller) writeComplete(
	state producerState,
	batches []batchRecord,
) error {
	if c.sealReceipts.ProviderOneSHA25 == "" {
		return errors.New("COMPLETE was reached before the terminal seal")
	}
	total := 0
	for _, batch := range batches {
		if _, err := os.Lstat(filepath.Join(
			c.MatrixRoot, "batches", batch.key+doneSuffix,
		)); err != nil {
			return fmt.Errorf(
				"COMPLETE was reached before batch %s had a terminal record",
				batch.key,
			)
		}
		total += batch.attemptCount
	}

	candidate := filepath.Join(c.MatrixRoot, candidateCompleteName)
	final := filepath.Join(c.MatrixRoot, completeMarker)

	// Idempotent re-entry into an already-finished state. A root that already
	// carries a COMPLETE this run agrees with is done; saying so is the correct
	// answer, and re-verifying or rewriting it would be worse than useless.
	if published, err := os.ReadFile(final); err == nil { // #nosec G304
		if err := c.requireCompletionAgrees(published, state, total); err != nil {
			return fmt.Errorf(
				"this matrix already carries a COMPLETE that disagrees with "+
					"what this run would publish: %w", err,
			)
		}
		if err := c.removeCandidate(candidate, published); err != nil {
			return err
		}
		c.log("CONTROLLER_ALREADY_COMPLETE matrix=%s", state.matrixID)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	record, err := c.candidateRecord(candidate, state, total)
	if err != nil {
		return err
	}
	if c.crashAfter == stageAfterCandidate {
		return fmt.Errorf("injected crash at %s", stageAfterCandidate)
	}

	// Verification is safe to repeat, so it simply runs on every attempt.
	if err := c.Verifier.VerifyMatrix(candidateCompleteName); err != nil {
		// Fail closed: nothing that looks like completion survives a failed
		// final check. The candidate is removed only here, on a verdict this
		// run obtained itself.
		_ = os.Remove(candidate)
		return fmt.Errorf(
			"the final full verification of this matrix failed, and the "+
				"candidate completion record has been removed: %w", err,
		)
	}
	if c.crashAfter == stageAfterVerify {
		return fmt.Errorf("injected crash at %s", stageAfterVerify)
	}

	// Re-read after verification and require the exact bytes. This closes the
	// gap between "these bytes verified" and "this file is published": the
	// verifier read a file, and only bytes identical to the ones it read may be
	// promoted.
	verified, err := os.ReadFile(candidate) // #nosec G304 -- controller root
	if err != nil {
		return err
	}
	if !bytes.Equal(verified, record) {
		return errors.New(
			"the candidate completion record changed between verification and " +
				"publication; refusing to publish bytes that were not verified",
		)
	}

	// A distinct, explicitly non-promotional marker. Without it, a verifier
	// PASS transcript beside this matrix could not be told apart from a real
	// promotion. Bound to the candidate's digest, which is now stable across
	// resumes because the candidate's bytes are.
	if err := writeCreateOnce(
		filepath.Join(c.MatrixRoot, candidatePassMarker),
		[]byte(strings.Join([]string{
			"schema=" + candidatePassSchema,
			"matrix_id=" + state.matrixID,
			"promotional=0",
			"meaning=a full verifier pass over an unpublished candidate record",
			"candidate_record_sha256=" + sha256OfBytes(verified),
		}, "\n")+"\n"),
	); err != nil {
		return fmt.Errorf(
			"candidate pass marker: %w; a marker bound to different bytes than "+
				"this run's candidate means the two attempts disagree about "+
				"what was verified", err,
		)
	}
	if c.crashAfter == stageAfterPassMarker {
		return fmt.Errorf("injected crash at %s", stageAfterPassMarker)
	}

	if err := writeCreateOnce(final, verified); err != nil {
		return err
	}
	if c.crashAfter == stageAfterComplete {
		return fmt.Errorf("injected crash at %s", stageAfterComplete)
	}
	if c.crashAfter == stageBeforeCandidateC {
		return fmt.Errorf("injected crash at %s", stageBeforeCandidateC)
	}
	return c.removeCandidate(candidate, verified)
}

// candidateRecord returns the durable candidate bytes, creating them once.
//
// On the first attempt it mints the record, including its timestamp, and
// publishes it create-once. On every later attempt it reads the incumbent,
// proves it is the record this run would have produced in every field the run
// determines, and returns it unchanged — timestamp and all. That is what makes
// the digest stable across resumes.
func (c *Controller) candidateRecord(
	candidate string,
	state producerState,
	total int,
) ([]byte, error) {
	existing, err := os.ReadFile(candidate) // #nosec G304 -- controller root
	if err == nil {
		if err := c.requireCompletionAgrees(existing, state, total); err != nil {
			return nil, fmt.Errorf(
				"an existing candidate completion record disagrees with what "+
					"this run would publish, and is not something to overwrite: "+
					"%w", err,
			)
		}
		c.log("CONTROLLER_RESUME candidate=reused")
		return existing, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	record := []byte(strings.Join([]string{
		"schema=" + matrixSchemaV3,
		"matrix_id=" + state.matrixID,
		"completed_at_utc=" + time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"attempts=" + strconv.Itoa(total),
		"schedule_sha256=" + state.scheduleDigest,
		"execution_inventory_sha256=" + state.executionInventor,
		"anchor_mode=" + intendedMode,
		"partial=0",
		"terminal_aggregate_sha256=" + c.aggregateDigest,
		"anchor_provider_one_seal_sha256=" + c.sealReceipts.ProviderOneSHA25,
		"anchor_provider_two_seal_sha256=" + c.sealReceipts.ProviderTwoSHA25,
		"audit_close_state=closed",
	}, "\n") + "\n")
	if err := securefile.AtomicWriteNew(candidate, record, 0o600); err != nil {
		return nil, err
	}
	return record, nil
}

// requireCompletionAgrees compares an incumbent completion record against what
// this run determines.
//
// completed_at_utc is exempt from the comparison and required to be present and
// well formed instead. It is the one field the run does not determine — it
// records when the first attempt got here — and demanding it match would make
// every resume a conflict, which is exactly the wedge this design removes.
func (c *Controller) requireCompletionAgrees(
	incumbent []byte,
	state producerState,
	total int,
) error {
	values := make(map[string]string)
	for _, line := range strings.Split(
		strings.TrimSuffix(string(incumbent), "\n"), "\n",
	) {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return errors.New("the record has an invalid key/value line")
		}
		if _, duplicate := values[key]; duplicate {
			return fmt.Errorf("the record repeats the key %q", key)
		}
		values[key] = value
	}
	expected := map[string]string{
		"schema":                          matrixSchemaV3,
		"matrix_id":                       state.matrixID,
		"attempts":                        strconv.Itoa(total),
		"schedule_sha256":                 state.scheduleDigest,
		"execution_inventory_sha256":      state.executionInventor,
		"anchor_mode":                     intendedMode,
		"partial":                         "0",
		"terminal_aggregate_sha256":       c.aggregateDigest,
		"anchor_provider_one_seal_sha256": c.sealReceipts.ProviderOneSHA25,
		"anchor_provider_two_seal_sha256": c.sealReceipts.ProviderTwoSHA25,
		"audit_close_state":               "closed",
	}
	if len(values) != len(expected)+1 {
		return fmt.Errorf(
			"the record has %d fields, this run produces %d",
			len(values), len(expected)+1,
		)
	}
	for key, want := range expected {
		got, present := values[key]
		if !present {
			return fmt.Errorf("the record omits %s", key)
		}
		if got != want {
			return fmt.Errorf(
				"the record states %s=%q, this run produces %q", key, got, want,
			)
		}
	}
	stamp, present := values["completed_at_utc"]
	if !present {
		return errors.New("the record omits completed_at_utc")
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", stamp); err != nil {
		return fmt.Errorf("the record has an unusable completed_at_utc %q", stamp)
	}
	return nil
}

// removeCandidate clears the candidate only when it is the record that was
// promoted. A candidate holding anything else is left alone and reported: it is
// evidence of a state nobody has reconciled, and deleting it would destroy the
// only trace of that.
func (c *Controller) removeCandidate(candidate string, published []byte) error {
	existing, err := os.ReadFile(candidate) // #nosec G304 -- controller root
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, published) {
		return fmt.Errorf(
			"a candidate completion record remains that differs from the " +
				"published COMPLETE; refusing to delete it, because it is the " +
				"only evidence of an unreconciled state",
		)
	}
	return os.Remove(candidate)
}

// verifyLastReversibleGate is the single last-chance check before anything
// irreversible happens.
//
// It is deliberately ONE gate rather than several. An anchor is two independent
// providers durably signing a statement about this matrix, and there is no
// operation that retracts one; everything that can be checked by reading files
// must therefore be checked at the same instant, immediately before that step.
// Two gates separated by other work are two different instants, and the window
// between them is exactly where a mutation lands unnoticed.
//
// It covers three things:
//
//   - the signed producer snapshot, re-measured. This catches an internally
//     consistent manifest-and-members rewrite that landed after the earlier
//     measurement. Controller-added checkpoint and log files are excluded from
//     the measurement, so this run's own close work does not read as drift.
//   - every digest the anchor requests are about to carry, rehashed from the
//     files themselves: the published closed archive, the evidence manifest,
//     the attempt log and the attempt anchor. Without this, a mutation after
//     VerifyBatch and Publish but before anchoring produces provider receipts
//     over stale values, and only the post-anchor verifier notices — after the
//     receipts are already irreversible.
//   - the frozen schedule, the attempt totals, the producer cross-records and
//     each producer archive.
func (c *Controller) verifyLastReversibleGate(
	state producerState,
	schedule []scheduledBatch,
	batches []batchRecord,
) error {
	// The schedule this controller read must be the schedule the producer
	// committed to. Every anchor request carries schedule_digest, so anchoring
	// under a different schedule would have two providers attest to an ordering
	// nobody froze.
	scheduleDigest, err := sha256Of(filepath.Join(c.MatrixRoot, "schedule.tsv"))
	if err != nil {
		return err
	}
	if state.scheduleDigest == "" || scheduleDigest != state.scheduleDigest {
		return fmt.Errorf(
			"schedule.tsv hashes to %s, the producer committed to %s; the "+
				"frozen order changed after the run",
			scheduleDigest, state.scheduleDigest,
		)
	}
	if err := c.requireExecutionInventoryAgrees(state); err != nil {
		return err
	}

	// Attempt totals. The producer's marker states a total; the schedule states
	// per-batch counts; the batch records state their own. All three must agree,
	// or the completion record this transition eventually writes would claim an
	// attempt count no evidence supports.
	scheduledTotal := 0
	for _, row := range schedule {
		scheduledTotal += row.attempts
	}
	recordedTotal := 0
	for _, batch := range batches {
		recordedTotal += batch.attemptCount
	}
	if scheduledTotal != recordedTotal {
		return fmt.Errorf(
			"the frozen schedule totals %d attempts, the batch records total %d",
			scheduledTotal, recordedTotal,
		)
	}
	if state.producerAttempts != scheduledTotal {
		return fmt.Errorf(
			"the producer marker claims %d attempts, the frozen schedule "+
				"totals %d", state.producerAttempts, scheduledTotal,
		)
	}
	if len(schedule) != len(batches) {
		return fmt.Errorf(
			"the frozen schedule has %d batches, %d were loaded",
			len(schedule), len(batches),
		)
	}

	// Every batch artifact on disk must be one the schedule accounts for. A
	// stray record is either a batch that was never scheduled or a leftover
	// from a different run, and either way it means this root is not the thing
	// it claims to be.
	expected := make(map[string]struct{}, len(batches)*2)
	for _, batch := range batches {
		expected[batch.key+pendingSuffix] = struct{}{}
		expected[batch.key+doneSuffix] = struct{}{}
	}
	entries, err := os.ReadDir(filepath.Join(c.MatrixRoot, "batches"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf(
				"the matrix carries an unexpected batch artifact %s", entry.Name(),
			)
		}
	}

	// Each batch's producer archive: it must exist at the path the record
	// names, and hash to the digest the record claims. The closed archive this
	// controller publishes is derived from the same evidence directory, so a
	// producer archive that does not match its own record means the evidence
	// this transition is about to anchor is not the evidence that was sealed.
	for _, batch := range batches {
		if !lowerHex(batch.pendingSHA256) {
			return fmt.Errorf(
				"batch %s records no usable producer archive digest", batch.key,
			)
		}
		// Removed: a comparison between filepath.Join(root, archiveRelative)
		// and evidenceDir+pendingArchive. evidenceDir is itself derived from
		// archiveRelative by trimming that same suffix, so both sides reduced
		// to one value by construction and the check could never fire. A test
		// that cannot fail is worse than no test: it reads as a confinement
		// guarantee that nothing is providing.
		//
		// The real confinement is asserted below, against the recorded path
		// itself rather than against a value derived from it.
		archivePath := filepath.Join(c.MatrixRoot, batch.archiveRelative)
		digest, err := sha256Of(archivePath)
		if err != nil {
			return fmt.Errorf("batch %s producer archive: %w", batch.key, err)
		}
		if digest != batch.pendingSHA256 {
			return fmt.Errorf(
				"batch %s producer archive hashes to %s, its record claims %s",
				batch.key, digest, batch.pendingSHA256,
			)
		}
		info, err := os.Lstat(batch.evidenceDir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf(
				"batch %s evidence directory is absent or unsafe", batch.key,
			)
		}
	}
	// Every digest the provider requests are about to carry, rehashed from the
	// artifact itself. batch.closedSHA256 was computed when the archive was
	// published; this proves the file still hashes to it now, at the moment the
	// providers are asked to sign it.
	for _, batch := range batches {
		if batch.closedSHA256 == "" || batch.closedArchive == "" {
			return fmt.Errorf(
				"batch %s reached the anchor gate without a closed archive",
				batch.key,
			)
		}
		bound := []struct {
			label    string
			path     string
			expected string
		}{
			{"closed archive", batch.closedArchive, batch.closedSHA256},
			{
				"evidence manifest",
				filepath.Join(batch.evidenceDir, manifestName),
				batch.manifestSHA256,
			},
			{
				"attempt log",
				filepath.Join(batch.evidenceDir, "attempts.jsonl"),
				batch.attemptLogSHA,
			},
			{
				"attempt anchor",
				filepath.Join(batch.evidenceDir, "attempts.jsonl.anchor"),
				batch.attemptAnchorSHA,
			},
		}
		for _, item := range bound {
			if item.expected == "" {
				return fmt.Errorf(
					"batch %s has no %s digest to anchor", batch.key, item.label,
				)
			}
			_, digest, err := producersnapshot.ReadRegular(
				item.path, producersnapshot.MaximumSnapshotMember, nil,
			)
			if err != nil {
				return fmt.Errorf(
					"batch %s %s: %w", batch.key, item.label, err,
				)
			}
			if digest != item.expected {
				return fmt.Errorf(
					"batch %s %s hashes to %s, the anchor request would carry "+
						"%s; the file changed after it was verified and before "+
						"the providers were asked to sign it",
					batch.key, item.label, digest, item.expected,
				)
			}
		}
	}

	// The signed producer snapshot and the frozen trust set, both re-checked
	// inside this same gate. All three questions — is the evidence what was
	// authorised, are the digests still right, is the trust set still the one
	// the signature covers — have to be answered at the same instant, because
	// the next step cannot be undone.
	if err := c.requireSnapshotStill(c.signedSnapshot); err != nil {
		return err
	}
	if c.started == nil {
		return errors.New("no signed controller start record is held")
	}
	// Both checks, for two different questions.
	//
	// (A) the in-memory view this run will actually snapshot and use, against
	// the signature — catching a swap-before-load/restore-before-check race.
	if err := c.requireFrozenTrustUnchanged(c.started); err != nil {
		return err
	}
	// (B) the persisted evidence on disk, against the same signature —
	// catching corruption that was already there, where nothing adversarial
	// happened and the in-memory view is perfectly self-consistent. The
	// anonymous snapshots make later CONSUMPTION safe; they do not make
	// corrupted on-disk evidence something to anchor over.
	if err := c.requirePersistedTrustUnchanged(c.started); err != nil {
		return err
	}
	c.log("CONTROLLER_LAST_REVERSIBLE_GATE_OK batches=%d attempts=%d",
		len(batches), scheduledTotal)
	return nil
}

// requireExecutionInventoryAgrees proves the execution inventory BEFORE the
// first provider is contacted.
//
// WHAT WAS WRONG. verifyProducerState accepted any non-empty marker value and
// copied it forward. Nothing hashed <root>/execution-inventory.sha256, and
// nothing compared the marker's claim with matrix.env's. Both records are
// written by the producer and both are read by the FORMAL verifier — which
// requires matrix.env's value, COMPLETE's value and the file's actual digest to
// be the same number. So a root whose two records disagree, or whose inventory
// file does not hash to what its records claim, was:
//
//	closed -> ANCHORED by two independent providers -> then rejected
//
// by the final verification. The rejection is correct and far too late: an
// anchor is a durable external attestation and there is no operation that
// retracts one. The run would leave permanent provider signatures over a matrix
// that can never be completed, and the operator's only remaining choice is to
// abandon the matrix ID.
//
// WHY IT LIVES IN THE LAST REVERSIBLE GATE. Three properties are checked
// together at one instant, because they are one question with three parts:
//
//   - SYNTAX. Both records' claims are lowercase 64-hex digests. (Also checked
//     early on the marker, for a clearer message; repeated here so this gate is
//     self-sufficient rather than depending on an earlier instant.)
//   - CROSS-RECORD. The producer marker and matrix.env agree with each other,
//     and therefore with the value this run is about to seal into every anchor
//     request's lineage and into COMPLETE.
//   - CONTENT. <root>/execution-inventory.sha256 actually hashes to it, read
//     now rather than trusted from a record.
//
// Splitting these across phases would put a window between them, which is the
// defect this gate exists to remove — and would reintroduce exactly the
// two-different-instants problem the single-gate design was adopted to fix.
func (c *Controller) requireExecutionInventoryAgrees(
	state producerState,
) error {
	if !lowerHex(state.executionInventor) {
		return fmt.Errorf(
			"the execution inventory digest this run would anchor is %q, which "+
				"is not a lowercase 64-hex SHA-256 digest",
			state.executionInventor,
		)
	}
	marker, err := readKeyValues(filepath.Join(c.MatrixRoot, producerMarker))
	if err != nil {
		return err
	}
	environment, err := readKeyValues(filepath.Join(c.MatrixRoot, "matrix.env"))
	if err != nil {
		return err
	}
	for source, values := range map[string]map[string]string{
		producerMarker: marker,
		"matrix.env":   environment,
	} {
		recorded := values["execution_inventory_sha256"]
		if !lowerHex(recorded) {
			return fmt.Errorf(
				"%s records execution_inventory_sha256=%q, which is not a "+
					"lowercase 64-hex SHA-256 digest", source, recorded,
			)
		}
		if recorded != state.executionInventor {
			return fmt.Errorf(
				"%s records execution_inventory_sha256=%s and this run would "+
					"anchor %s; the producer's own records disagree about which "+
					"execution inventory this matrix ran under, and the formal "+
					"verifier requires them to be the same value — anchoring "+
					"first would make that disagreement permanent",
				source, recorded, state.executionInventor,
			)
		}
	}
	inventory := filepath.Join(c.MatrixRoot, "execution-inventory.sha256")
	digest, err := sha256Of(inventory)
	if err != nil {
		return fmt.Errorf("execution-inventory.sha256: %w", err)
	}
	if digest != state.executionInventor {
		return fmt.Errorf(
			"execution-inventory.sha256 hashes to %s and every record of this "+
				"matrix claims %s; the inventory the providers are about to "+
				"attest is not the inventory this matrix ran under",
			digest, state.executionInventor,
		)
	}
	return nil
}

// verifySeedCustody validates the finalizer credential's own custody before it
// is loaded.
//
// The finalizer seed is the credential the whole audit-close design rests on:
// it must be a real, private, regular file, and it must live outside the matrix
// root. A seed inside the root would be archived with the evidence it closes,
// and anyone holding that archive could then re-close a truncated copy of it —
// which is precisely the property the checkpoint exists to deny.
//
// The anchor trust inputs are NOT handled here: which copies of them this run
// reads depends on whether it is a resume, which is not known until the signed
// start record has been loaded — with this seed. See selectTrustInputs.
func (c *Controller) verifySeedCustody() error {
	root, err := filepath.Abs(c.MatrixRoot)
	if err != nil {
		return err
	}
	seed, err := filepath.Abs(c.FinalizerSeedPath)
	if err != nil {
		return err
	}
	info, err := os.Lstat(seed)
	if err != nil {
		return fmt.Errorf("finalizer seed: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("the finalizer seed is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"the finalizer seed has permissions %04o; it must not be readable "+
				"by group or other", info.Mode().Perm(),
		)
	}
	if seed == root || strings.HasPrefix(seed, root+string(os.PathSeparator)) {
		return errors.New(
			"the finalizer seed lives inside the matrix root; it would be " +
				"archived with the evidence it closes, and anyone holding that " +
				"archive could re-close a truncated copy of it",
		)
	}

	return nil
}

func sha256OfBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// writeControllerState records the key/value projection the verifier reads.
//
// It is a separate file from matrix.env on purpose. matrix.env is frozen before
// the producer's first batch and compared byte-for-byte on every resume, and it
// necessarily carries EMPTY anchor identities, because a deferred run refuses to
// start if the producing host holds any anchor credential at all. Rewriting it
// afterwards to carry the identities would destroy the very commitment the
// verifier checks. So the producer's record stays exactly as sealed, and the
// controller's own state carries what only the controller could know.
//
// The authoritative, signed statement of ownership is CONTROLLER_START; this is
// the unsigned projection of it that the verifier's key/value contract consumes.
func (c *Controller) writeControllerState(
	state producerState,
	batchCount int,
) error {
	record := strings.Join([]string{
		"schema=" + controllerEnvSchema,
		"matrix_id=" + state.matrixID,
		"source_digest=" + state.sourceDigest,
		"anchor_mode=" + intendedMode,
		"anchor_schema=" + phase1anchor.RequestSchema,
		"anchor_provider_one_id=" + c.AnchorProviderOneID,
		"anchor_provider_one_key_id=" + c.trust.providerOneKeyID,
		"anchor_provider_two_id=" + c.AnchorProviderTwoID,
		"anchor_provider_two_key_id=" + c.trust.providerTwoKeyID,
		"anchor_known_hosts_sha256=" + c.trust.knownHostsSHA,
		"expected_batch_count=" + strconv.Itoa(batchCount),
		// The finalizer identity, recorded so the verifier can cross-check that
		// CONTROLLER_START, this projection, and every checkpoint bind the same
		// credential. Three artifacts naming three different signers would mean
		// nobody owns this transition.
		"finalizer_key_id=" + c.finalizerKeyID,
	}, "\n") + "\n"
	return writeCreateOnce(
		filepath.Join(c.MatrixRoot, controllerEnvName), []byte(record),
	)
}

func anchorPublicKeyID(path string) (string, error) {
	if path == "" {
		return "", errors.New("an anchor provider public key is required")
	}
	content, err := os.ReadFile(path) // #nosec G304 -- operator input
	if err != nil {
		return "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(string(content)),
	)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return "", errors.New("invalid Ed25519 public key")
	}
	return phase1anchor.PublicKeyID(ed25519.PublicKey(decoded)), nil
}
