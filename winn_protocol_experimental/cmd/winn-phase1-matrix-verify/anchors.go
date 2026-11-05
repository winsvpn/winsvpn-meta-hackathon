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
	"strconv"
	"strings"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

// anchorZeroDigest is the canonical genesis predecessor, taken from
// internal/phase1anchor rather than restated. A local 64-zero literal here
// agreed with the ledger's only by coincidence of copying.
const anchorZeroDigest = phase1anchor.ZeroDigest

func verifyAnchoredSmoke(
	matrixRoot string,
	profilePath string,
	expectedSource string,
	expectedAWGEngine string,
	trust anchorTrust,
	checkpoint auditCheckpointPin,
) error {
	if matrixRoot == "" || profilePath == "" ||
		!lowerHex(expectedSource, sha256.Size*2) ||
		!lowerHex(expectedAWGEngine, sha256.Size*2) {
		return errors.New("anchored smoke inputs are incomplete")
	}
	root, err := filepath.Abs(matrixRoot)
	if err != nil {
		return err
	}
	profiles, profileDigest, err := loadProfiles(profilePath)
	if err != nil {
		return err
	}
	environment, err := parseKeyValueFile(filepath.Join(root, "matrix.env"))
	if err != nil {
		return err
	}
	if environment["source_digest"] != expectedSource ||
		environment["awg_engine_sha256"] != expectedAWGEngine ||
		environment["profile_sha256"] != profileDigest ||
		environment["partial"] != "1" ||
		environment["anchor_mode"] != "dual-provider-v1" ||
		environment["batch_size"] != "100" ||
		environment["attempts_per_readiness_per_profile"] != "100" ||
		environment["profile_filter"] == "" {
		return errors.New("anchored smoke environment is not the exact partial design")
	}
	var selected networkProfile
	found := false
	for _, profile := range profiles.Profiles {
		if profile.ID == environment["profile_filter"] {
			selected = profile
			found = true
			break
		}
	}
	if !found || len(profiles.ReadinessClasses) != 2 {
		return errors.New("anchored smoke profile filter is invalid")
	}
	profiles.Profiles = []networkProfile{selected}
	profiles.AttemptsPerReadinessPerProfile = 100
	profiles.BatchSize = 100
	complete, err := parseKeyValueFile(filepath.Join(root, "COMPLETE"))
	if err != nil {
		return err
	}
	batches, err := loadBatches(root)
	if err != nil {
		return err
	}
	if err := verifyExecutionInventory(root, environment, complete); err != nil {
		return err
	}
	if err := verifyV2Schedule(
		root, profiles, environment, complete, batches,
	); err != nil {
		return err
	}
	if err := verifyDualProviderAnchors(
		root,
		profiles,
		environment,
		complete,
		batches,
		false,
		trust,
		true,
		checkpoint,
	); err != nil {
		return err
	}
	total := 0
	for _, batch := range batches {
		attempts, err := verifyBatch(
			root,
			environment["matrix_id"],
			batch,
			selected,
			3000,
			expectedSource,
			expectedAWGEngine,
			true,
			environment["execution_inventory_sha256"],
			checkpoint,
		)
		if err != nil {
			return fmt.Errorf("anchored smoke batch %s: %w", batch.key, err)
		}
		total += len(attempts)
	}
	if total != 200 || complete["attempts"] != "200" {
		return fmt.Errorf("anchored smoke has %d attempts, want 200", total)
	}
	fmt.Printf(
		"ANCHORED_SMOKE_VERIFY_PASS attempts=%d batches=%d "+
			"source_digest=%s non_promotional=1 formal_matrix_required=1\n",
		total,
		len(batches),
		expectedSource,
	)
	return nil
}

// anchorSlotProfile names which set of artifacts an anchor slot must contain.
//
// The two profiles exist because two different tools created these slots, and
// they created different files.
//
// The legacy producer-side path wrote a batch-meta.env alongside each batch
// slot, and the verifier's count assumed it. The controller-side path does not:
// winn-phase1-anchor-pin creates exactly seven artifacts and never wrote that
// file at all, so every batch slot the real pin tool produces would have failed
// the eight-file rule — after the providers had already signed it.
//
// The fix is a schema-aware expectation, not a relaxed one. Loosening the rule
// globally to "at least these seven" would have made the verifier blind to a
// stray file in EVERY slot, including the historical ones, to accommodate a
// difference that only exists in one path. Instead each profile states exactly
// what its own tool produces, and evidence declaring neither is refused.
type anchorSlotProfile string

const (
	// anchorSlotLegacyV2 is the producer-anchored layout, whose batch slots
	// carry batch-meta.env. Historical sealed evidence uses it and must remain
	// verifiable.
	anchorSlotLegacyV2 anchorSlotProfile = "legacy-producer-anchored/v2"
	// anchorSlotControllerV3 is the controller-anchored layout: exactly the
	// seven artifacts winn-phase1-anchor-pin writes, for every kind.
	anchorSlotControllerV3 anchorSlotProfile = "controller-deferred/v3"
)

// selectAnchorSlotProfile decides which anchoring layout this evidence declares.
//
// It binds the matrix SCHEMA and the anchor MODE as a pair, and accepts only
// the two pairs that any real tool has ever produced. Neither field alone is
// sufficient, and this is not a stylistic preference:
//
// Choosing on mode alone leaves every mixed combination silently accepted. A
// schema-v3 root declaring the legacy mode would be routed to the legacy
// profile — which skips controller.env entirely, and with it the controller's
// anchor identities, its finalizer binding, and the whole deferred-anchor
// commitment. The root would verify as "anchored" while none of the checks that
// make controller-side anchoring trustworthy had run. Choosing on schema alone
// has the mirror problem.
//
// So the pairs are enumerated, and anything else is refused rather than guessed
// at. A future layout adds a case here; it does not fall through to whichever
// existing profile happens to match one of its fields.
func selectAnchorSlotProfile(
	environment map[string]string,
) (anchorSlotProfile, error) {
	schema := environment["schema"]
	mode := environment["anchor_mode"]
	switch {
	case schema == matrixSchemaV2 && mode == anchorModeDualProvider:
		// Historical, producer-anchored. Its batch slots carry batch-meta.env,
		// and its anchor identities live in matrix.env because the producer
		// held them.
		return anchorSlotLegacyV2, nil

	case schema == matrixSchemaV3 && mode == deferredAnchorMode:
		// Controller-anchored. The producer committed to deferred anchoring
		// before its first batch; that commitment is part of the pair.
		if environment["intended_anchor_mode"] != anchorModeDualProvider {
			return "", errors.New(
				"matrix.env does not carry the producer's committed " +
					"controller-deferred dual-provider anchor intent",
			)
		}
		return anchorSlotControllerV3, nil

	default:
		return "", fmt.Errorf(
			"matrix.env declares schema=%q with anchor_mode=%q, which is not a "+
				"recognised anchoring layout. The only accepted pairs are "+
				"%s with %s (legacy producer-anchored) and %s with %s "+
				"(controller-deferred); a mismatched pair is refused rather "+
				"than verified under whichever profile happens to match one of "+
				"its fields",
			schema, mode,
			matrixSchemaV2, anchorModeDualProvider,
			matrixSchemaV3, deferredAnchorMode,
		)
	}
}

// anchorSlotFileSet returns the exact artifact set one slot must contain.
func anchorSlotFileSet(
	profile anchorSlotProfile,
	kind string,
) (map[string]struct{}, error) {
	// The set the pin tool actually writes, in both profiles — taken from the
	// pin tool's own definition rather than restated here. A second enumeration
	// is what produced the batch-meta.env P0: this side required a file the
	// writer never produced, and each side's tests agreed with itself.
	names := phase1anchor.SlotArtifactSet()
	switch profile {
	case anchorSlotControllerV3:
		return names, nil
	case anchorSlotLegacyV2:
		if kind == phase1anchor.KindBatch {
			names["batch-meta.env"] = struct{}{}
		}
		return names, nil
	default:
		return nil, fmt.Errorf(
			"anchor slot profile %q is not recognised; evidence must declare a "+
				"known anchoring layout rather than being verified under a "+
				"guessed one", profile,
		)
	}
}

const (
	// deferredAnchorMode is what the producing host records in matrix.env: the
	// schedule ran there, the anchoring is the controller's to perform.
	deferredAnchorMode = "controller-deferred-dual-provider-v1"
	// anchorModeDualProvider is the mode actually performed, recorded by the
	// controller in its own state and in the completion record.
	anchorModeDualProvider = "dual-provider-v1"
	// controllerEnvName is the controller's state file. It exists because the
	// producer's matrix.env is frozen before the first batch and cannot carry
	// identities the producer was forbidden to hold.
	controllerEnvName   = "controller.env"
	controllerEnvSchema = "winn-phase1-controller-close/v1"
)

// mergedAnchorIdentity overlays the controller's anchor identities onto the
// producer's frozen environment for the identity checks below.
//
// The producer's record is not modified, on disk or in place: a deferred run's
// matrix.env is part of the frozen compared parameters, and rewriting it to
// satisfy a later check would destroy the very commitment being verified. This
// returns a copy.
func mergedAnchorIdentity(
	environment, controller map[string]string,
) map[string]string {
	merged := make(map[string]string, len(environment)+8)
	for key, value := range environment {
		merged[key] = value
	}
	for _, key := range []string{
		"anchor_provider_one_id",
		"anchor_provider_one_key_id",
		"anchor_provider_two_id",
		"anchor_provider_two_key_id",
		"anchor_known_hosts_sha256",
		"anchor_schema",
		"expected_batch_count",
	} {
		if value, present := controller[key]; present && value != "" {
			merged[key] = value
		}
	}
	return merged
}

func verifyDualProviderAnchors(
	root string,
	profiles profileDocument,
	environment map[string]string,
	complete map[string]string,
	batches []matrixBatch,
	staging bool,
	trust anchorTrust,
	allowPartialSmoke bool,
	checkpoint auditCheckpointPin,
) error {
	mode := environment["anchor_mode"]
	if staging {
		if mode != "" && mode != "disabled" {
			return errors.New("staging report unexpectedly claims formal anchoring")
		}
		return nil
	}
	expectedPartial := "0"
	if allowPartialSmoke {
		expectedPartial = "1"
	}
	// AUDIT-CLOSE changed what "anchored" means, and the contract now has two
	// halves that must BOTH hold.
	//
	// The producing host is forbidden to anchor, so matrix.env — frozen before
	// the first batch and never rewritten — records the DEFERRED mode and the
	// dual-provider mode it commits the controller to performing. The
	// controller then performs it and records the real thing in its own state
	// and in the completion record.
	//
	// Checking only the completion record would let a run that never committed
	// to deferred anchoring be anchored afterwards and called formal; checking
	// only matrix.env would accept a committed intent that was never carried
	// out. Neither half is sufficient, so both are required.
	if environment["partial"] != expectedPartial {
		return errors.New("full matrix lacks mandatory dual-provider anchoring")
	}
	profile, err := selectAnchorSlotProfile(environment)
	if err != nil {
		return err
	}
	if complete["anchor_mode"] != anchorModeDualProvider {
		return errors.New(
			"the completion record does not record performed dual-provider " +
				"anchoring",
		)
	}
	if trust.providerOneID == "" || trust.providerTwoID == "" ||
		trust.providerOneID == trust.providerTwoID ||
		trust.providerOnePublicKey == "" ||
		trust.providerTwoPublicKey == "" {
		return errors.New("independent external anchor trust roots are required")
	}
	publicOne, err := loadAnchorPublicKey(trust.providerOnePublicKey)
	if err != nil {
		return fmt.Errorf("first anchor trust root: %w", err)
	}
	publicTwo, err := loadAnchorPublicKey(trust.providerTwoPublicKey)
	if err != nil {
		return fmt.Errorf("second anchor trust root: %w", err)
	}
	if bytes.Equal(publicOne, publicTwo) {
		return errors.New("anchor trust roots use the same signing key")
	}
	// The controller's own state carries the anchor identities, because the
	// producer had none: a deferred run is refused if any anchor credential is
	// present on the producing host, so matrix.env's anchor identity fields are
	// necessarily empty and must not be consulted for them.
	if profile == anchorSlotLegacyV2 {
		// The legacy lineage carries its anchor identities in matrix.env,
		// because the producer held them. Nothing further to merge.
		return verifyAnchorChain(
			root, profiles, environment, complete, batches, trust,
			publicOne, publicTwo, profile,
		)
	}
	controller, err := readControllerEnv(filepath.Join(root, controllerEnvName))
	if err != nil {
		return fmt.Errorf(
			"anchored evidence requires the controller's %s: %w",
			controllerEnvName, err,
		)
	}
	// The signed ownership record, verified against the same externally pinned
	// finalizer identity the checkpoints are verified against.
	//
	// Without this the record did no work for an auditor at all: it was
	// produced, signed, and then never consulted by the thing that decides
	// whether evidence is acceptable. A signature nobody checks is a comment.
	if err := verifyControllerStartRecord(
		root, environment, complete, controller, checkpoint.finalizerKeyID,
	); err != nil {
		return err
	}
	if controller["schema"] != controllerEnvSchema ||
		controller["anchor_mode"] != anchorModeDualProvider ||
		controller["anchor_schema"] != phase1anchor.RequestSchema ||
		controller["matrix_id"] != environment["matrix_id"] ||
		controller["source_digest"] != environment["source_digest"] {
		return errors.New(
			"the controller anchor state does not match this matrix",
		)
	}
	// One finalizer identity across the whole transition. The controller's
	// recorded identity, and the identity every batch checkpoint was verified
	// against, must be the same externally pinned key; three artifacts naming
	// different signers would mean nobody owns this state.
	if checkpoint.finalizerKeyID == "" {
		return errors.New(
			"anchored evidence requires an externally pinned audit finalizer " +
				"identity (-audit-finalizer-key-id)",
		)
	}
	if controller["finalizer_key_id"] != checkpoint.finalizerKeyID {
		return fmt.Errorf(
			"the controller state records finalizer %s, the auditor pinned %s",
			controller["finalizer_key_id"], checkpoint.finalizerKeyID,
		)
	}
	environment = mergedAnchorIdentity(environment, controller)
	return verifyAnchorChain(
		root, profiles, environment, complete, batches, trust,
		publicOne, publicTwo, profile,
	)
}

// verifyAnchorChain walks the committed anchor slots for either lineage.
func verifyAnchorChain(
	root string,
	profiles profileDocument,
	environment map[string]string,
	complete map[string]string,
	batches []matrixBatch,
	trust anchorTrust,
	publicOne ed25519.PublicKey,
	publicTwo ed25519.PublicKey,
	profile anchorSlotProfile,
) error {
	if environment["anchor_provider_one_id"] != trust.providerOneID ||
		environment["anchor_provider_two_id"] != trust.providerTwoID ||
		environment["anchor_provider_one_key_id"] !=
			phase1anchor.PublicKeyID(publicOne) ||
		environment["anchor_provider_two_key_id"] !=
			phase1anchor.PublicKeyID(publicTwo) {
		return errors.New("matrix anchor identities differ from external trust roots")
	}

	// The audited matrix root is opened ONCE, and the whole anchor subtree is
	// reached by descending confined handles from it.
	//
	// This used to compose ambient pathnames — filepath.Join(root, "anchors"),
	// then "pending", "committed" and each slot under that — and hand them to
	// os.ReadDir, loadAnchorPublicKey and sha256File. Every one of those follows
	// symbolic links on the intermediate components, and only the FINAL slot
	// directory was ever type-checked. So a link at anchors, at anchors/pending
	// or at anchors/committed was FOLLOWED: the committed slots, the archived
	// provider keys and the known-hosts file could all live entirely outside the
	// root the auditor believes it is verifying, and the run still reported PASS.
	//
	// The rule now is the same one verifyAnchorSlot already applies to slot
	// members: every directory component is Lstat'ed and REFUSED if it is not a
	// real directory. filepath.EvalSymlinks is deliberately not used anywhere in
	// this path — resolving a link is not rejecting one, and for sealed evidence
	// reading whatever a substituted component points at is precisely the
	// behaviour that must not occur.
	//
	// Holding descriptors also removes the swap window: once anchors/committed is
	// open, renaming a different directory over that name cannot change which
	// inode the slot reads reach.
	matrixRoot, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open matrix root: %w", err)
	}
	defer matrixRoot.Close()
	anchorRoot, err := openConfinedSubdirectory(matrixRoot, "anchors")
	if err != nil {
		return fmt.Errorf("anchor root: %w", err)
	}
	defer anchorRoot.Close()
	pendingRoot, err := openConfinedSubdirectory(anchorRoot, "pending")
	if err != nil {
		return fmt.Errorf("read anchor pending directory: %w", err)
	}
	defer pendingRoot.Close()
	entries, err := readConfinedDirectory(pendingRoot)
	if err != nil {
		return fmt.Errorf("read anchor pending directory: %w", err)
	}
	if len(entries) != 0 {
		return errors.New("matrix retains uncommitted anchor pending state")
	}
	inRootOne, err := loadRootAnchorPublicKey(
		anchorRoot, "provider-one.ed25519.pub",
	)
	if err != nil || !bytes.Equal(inRootOne, publicOne) {
		return errors.New("archived first provider key differs from trust root")
	}
	inRootTwo, err := loadRootAnchorPublicKey(
		anchorRoot, "provider-two.ed25519.pub",
	)
	if err != nil || !bytes.Equal(inRootTwo, publicTwo) {
		return errors.New("archived second provider key differs from trust root")
	}
	// The authenticated known-hosts identity, for BOTH lineages.
	//
	// The archived file is required to hash to the value the matrix's own
	// signed state binds. That single value is then threaded into every slot
	// check below, so a provider-config claiming a different — but perfectly
	// well-formed — digest is refused. Requiring only canonical shape there
	// meant the verifier declined to use an answer it already held.
	authenticatedKnownHosts := environment["anchor_known_hosts_sha256"]
	knownHostsDigest, err := sha256RootRegular(anchorRoot, "known_hosts")
	if err != nil || !lowerHex(authenticatedKnownHosts, sha256.Size*2) ||
		knownHostsDigest != authenticatedKnownHosts {
		return errors.New("archived anchor host keys differ from frozen identity")
	}

	schedule, err := loadV2Schedule(
		filepath.Join(root, "schedule.tsv"), profiles,
	)
	if err != nil {
		return err
	}
	if len(schedule) != len(batches) ||
		environment["expected_batch_count"] != strconv.Itoa(len(schedule)) {
		return errors.New("anchored batch count differs from frozen schedule")
	}
	batchByKey := make(map[string]matrixBatch, len(batches))
	for _, batch := range batches {
		batchByKey[batch.key] = batch
	}
	identity := phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		MatrixID:           environment["matrix_id"],
		SourceDigest:       environment["source_digest"],
		AutoArtifactDigest: environment["auto_artifact_sha256"],
		ProfileDigest:      environment["profile_sha256"],
		ScheduleDigest:     environment["schedule_sha256"],
		ExpectedBatchCount: len(schedule),
	}
	if !lowerHex(identity.AutoArtifactDigest, sha256.Size*2) {
		return errors.New("matrix lacks exact anchored Auto artifact digest")
	}

	committedRoot, err := openConfinedSubdirectory(anchorRoot, "committed")
	if err != nil {
		return fmt.Errorf("read committed anchors: %w", err)
	}
	defer committedRoot.Close()
	committedEntries, err := readConfinedDirectory(committedRoot)
	if err != nil {
		return fmt.Errorf("read committed anchors: %w", err)
	}
	if len(committedEntries) != len(schedule)+2 {
		return fmt.Errorf(
			"matrix has %d committed anchor slots, want %d",
			len(committedEntries), len(schedule)+2,
		)
	}
	genesis := identity
	genesis.Kind = phase1anchor.KindGenesis
	genesis.Ordinal = 0
	previousOne, previousTwo, _, err := verifyAnchorSlot(
		committedRoot,
		"000000-genesis",
		genesis,
		trust,
		publicOne,
		publicTwo,
		anchorZeroDigest,
		anchorZeroDigest,
		profile,
		authenticatedKnownHosts,
	)
	if err != nil {
		return fmt.Errorf("anchor genesis: %w", err)
	}

	var aggregate bytes.Buffer
	for index, scheduled := range schedule {
		ordinal := index + 1
		batch, ok := batchByKey[scheduled.key]
		if !ok {
			return fmt.Errorf("anchor schedule lacks batch %s", scheduled.key)
		}
		if batch.anchorMode != "dual-provider-v1" ||
			!lowerHex(batch.requestHash, sha256.Size*2) ||
			!lowerHex(batch.receiptOne, sha256.Size*2) ||
			!lowerHex(batch.receiptTwo, sha256.Size*2) {
			return fmt.Errorf("batch %s lacks anchor bindings", batch.key)
		}
		archive, archiveDigest, err := resolveBatchArchive(
			root, identity.MatrixID, batch,
		)
		if err != nil {
			return fmt.Errorf("batch %s archive: %w", batch.key, err)
		}
		// First of the two required bindings: the bytes that were opened are
		// the bytes the .done record claims. The second binding, against the
		// signed request, is asserted below once verifyAnchorSlot has proved
		// what the providers actually put their signatures on.
		if archiveDigest != batch.digest {
			return fmt.Errorf("batch %s archive digest mismatch", batch.key)
		}
		evidenceDirectory, err := resolveEvidenceDirectory(root, batch, archive)
		if err != nil {
			return fmt.Errorf("batch %s evidence: %w", batch.key, err)
		}
		evidenceManifest, err := sha256File(
			filepath.Join(evidenceDirectory, "evidence-manifest.sha256"),
		)
		if err != nil {
			return fmt.Errorf("batch %s evidence manifest: %w", batch.key, err)
		}
		attemptLog, err := sha256File(
			filepath.Join(evidenceDirectory, "attempts.jsonl"),
		)
		if err != nil {
			return fmt.Errorf("batch %s attempt log: %w", batch.key, err)
		}
		attemptAnchor, err := sha256File(
			filepath.Join(evidenceDirectory, "attempts.jsonl.anchor"),
		)
		if err != nil {
			return fmt.Errorf("batch %s attempt anchor: %w", batch.key, err)
		}
		row := fmt.Sprintf(
			"%06d\t%s\t%s\t%s\t%s\t%d\n",
			scheduled.block,
			scheduled.orderDigest,
			scheduled.key,
			scheduled.profile,
			scheduled.readiness,
			scheduled.attempts,
		)
		rowSum := sha256.Sum256([]byte(row))
		request := identity
		request.Kind = phase1anchor.KindBatch
		request.Ordinal = ordinal
		request.BatchKey = scheduled.key
		request.ScheduleRowDigest = hex.EncodeToString(rowSum[:])
		request.Profile = scheduled.profile
		request.Readiness = string(scheduled.readiness)
		request.AttemptCount = scheduled.attempts
		request.ArchiveDigest = batch.digest
		request.EvidenceManifestDigest = evidenceManifest
		request.AttemptLogDigest = attemptLog
		request.AttemptAnchorDigest = attemptAnchor
		slot := fmt.Sprintf("%06d-%s", ordinal, scheduled.key)
		nextOne, nextTwo, requestDigest, err := verifyAnchorSlot(
			committedRoot,
			slot,
			request,
			trust,
			publicOne,
			publicTwo,
			previousOne,
			previousTwo,
			profile,
			authenticatedKnownHosts,
		)
		if err != nil {
			return fmt.Errorf("anchor batch %s: %w", batch.key, err)
		}
		// Second required binding. verifyAnchorSlot has just proved that both
		// providers signed exactly this request, so request.ArchiveDigest is
		// now authenticated rather than merely asserted by the .done file, and
		// the archive that was opened has to equal it as well. Stated
		// explicitly so that the two bindings cannot be collapsed into one by
		// a later change to how request is assembled.
		if archiveDigest != request.ArchiveDigest {
			return fmt.Errorf(
				"batch %s archive differs from the signed archive digest",
				batch.key,
			)
		}
		if requestDigest != batch.requestHash ||
			nextOne != batch.receiptOne ||
			nextTwo != batch.receiptTwo {
			return fmt.Errorf(
				"batch %s metadata differs from signed receipts", batch.key,
			)
		}
		doneDigest, err := sha256File(
			filepath.Join(root, "batches", batch.key+".done"),
		)
		if err != nil {
			return err
		}
		fmt.Fprintf(
			&aggregate,
			"%06d\t%s\t%s\t%s\t%s\n",
			ordinal,
			requestDigest,
			nextOne,
			nextTwo,
			doneDigest,
		)
		previousOne, previousTwo = nextOne, nextTwo
	}
	aggregateData, err := readRootRegular(
		anchorRoot, "terminal-aggregate.list", 16<<20,
	)
	if err != nil {
		return fmt.Errorf("terminal aggregate: %w", err)
	}
	if !bytes.Equal(aggregate.Bytes(), aggregateData) {
		return errors.New("terminal aggregate list differs from signed batch chain")
	}
	aggregateSum := sha256.Sum256(aggregateData)
	aggregateDigest := hex.EncodeToString(aggregateSum[:])
	if complete["terminal_aggregate_sha256"] != aggregateDigest {
		return errors.New("COMPLETE terminal aggregate digest mismatch")
	}
	seal := identity
	seal.Kind = phase1anchor.KindSeal
	seal.Ordinal = len(schedule) + 1
	seal.AggregateDigest = aggregateDigest
	sealOne, sealTwo, _, err := verifyAnchorSlot(
		committedRoot,
		fmt.Sprintf("%06d-terminal-seal", len(schedule)+1),
		seal,
		trust,
		publicOne,
		publicTwo,
		previousOne,
		previousTwo,
		profile,
		authenticatedKnownHosts,
	)
	if err != nil {
		return fmt.Errorf("terminal anchor seal: %w", err)
	}
	if complete["anchor_provider_one_seal_sha256"] != sealOne ||
		complete["anchor_provider_two_seal_sha256"] != sealTwo {
		return errors.New("COMPLETE differs from terminal provider seals")
	}
	return nil
}

func verifyAnchorSlot(
	committed *os.Root,
	name string,
	expected phase1anchor.Request,
	trust anchorTrust,
	publicOne ed25519.PublicKey,
	publicTwo ed25519.PublicKey,
	previousOne string,
	previousTwo string,
	profile anchorSlotProfile,
	knownHostsDigest string,
) (string, string, string, error) {
	// The slot is opened ONCE, through the caller's already-open committed
	// handle, and every read below goes through the slot handle that produces.
	//
	// This used to enumerate the ambient pathname and then reopen each member
	// by path through readSecureRegular — which calls filepath.EvalSymlinks and
	// therefore RESOLVED a substituted member instead of REFUSING it. Resolving
	// a symbolic link and hashing whatever it points at is precisely what must
	// not happen to sealed evidence: the manifest would describe a file that is
	// not the one in the slot, and every signature would still check out.
	//
	// Reopening by path also left a swap window between the exact-set
	// enumeration and the per-member reads, so the set check could describe one
	// directory while the bytes came from another. os.Root closes both: it is a
	// descriptor, so nothing can be renamed out from under it, and it refuses
	// any component that would leave the slot.
	//
	// Taking the parent as a descriptor rather than a pathname is what extends
	// that guarantee upwards: confining only the final component still let a
	// symbolic link at anchors, anchors/pending or anchors/committed place the
	// whole slot set outside the audited matrix root.
	root, err := openConfinedSubdirectory(committed, name)
	if err != nil {
		return "", "", "", errors.New("anchor slot is absent or unsafe")
	}
	defer root.Close()
	expectedNames, err := anchorSlotFileSet(profile, expected.Kind)
	if err != nil {
		return "", "", "", err
	}
	if err := requireExactSlotMembers(root, expectedNames, profile); err != nil {
		return "", "", "", err
	}
	configData, err := readRootRegular(
		root, phase1anchor.SlotProviderConfigName, 64<<10,
	)
	if err != nil {
		return "", "", "", err
	}
	// Decoded and checked through the shared contract, so this side cannot
	// drift from what the pin tool writes or from what the controller demands
	// when it adopts an interrupted run's slot. The byte check is part of it:
	// a configuration whose duplicate object keys or whitespace differ decodes
	// to the same values, and it is the bytes that were sealed.
	configuration, err := phase1anchor.RequireCanonicalSlotConfig(configData)
	if err != nil {
		return "", "", "", err
	}
	if err := configuration.Verify(phase1anchor.SlotConfigExpectation{
		ProviderOneID:    trust.providerOneID,
		ProviderTwoID:    trust.providerTwoID,
		ProviderOneKeyID: phase1anchor.PublicKeyID(publicOne),
		ProviderTwoKeyID: phase1anchor.PublicKeyID(publicTwo),
		PreviousOne:      previousOne,
		PreviousTwo:      previousTwo,
		// The known-hosts digest the matrix's own signed state binds, already
		// checked against the archived anchors/known_hosts file by
		// verifyAnchorChain. The verifier HAS this value, so requiring each
		// slot to name it exactly costs nothing; leaving it unset meant a
		// provider-config tampered to claim any well-formed 64-hex digest
		// passed, while the correct answer was sitting one function away.
		KnownHostsDigest: knownHostsDigest,
		// ProviderOneHost and ProviderTwoHost are deliberately left unset. An
		// auditor reading sealed evidence holds no host pin to compare against:
		// nothing signed binds the addresses, and the receipts authenticate the
		// providers' possession of the request, not where they were reached. So
		// from this side those fields are UNVERIFIED provenance metadata, and
		// remain so unless a future signed schema binds them. See
		// SlotConfigExpectation.
	}); err != nil {
		return "", "", "", fmt.Errorf(
			"anchor slot provider configuration: %w", err,
		)
	}
	requestData, err := readRootRegular(
		root, phase1anchor.SlotRequestName, 64<<10,
	)
	if err != nil {
		return "", "", "", err
	}
	request, err := phase1anchor.DecodeRequest(bytes.NewReader(requestData))
	if err != nil {
		return "", "", "", err
	}
	expectedCanonical, err := expected.Canonical()
	if err != nil {
		return "", "", "", err
	}
	requestCanonical, err := request.Canonical()
	if err != nil || !bytes.Equal(requestCanonical, expectedCanonical) {
		return "", "", "", errors.New("anchor request differs from expected evidence")
	}
	// Pin the sealed bytes, not just the parsed value. Digest and Canonical
	// both hash a re-marshal, so without this an auditor's parser could read
	// different content out of this exact file while every digest still
	// matched: encoding/json takes the last of duplicate object keys and
	// ignores insignificant whitespace. The writer emits canonical JSON plus
	// one newline; anything else is not the sealed artifact.
	if !bytes.Equal(requestData, append(requestCanonical, '\n')) {
		return "", "", "", errors.New(
			"anchor request bytes are not the canonical sealed encoding",
		)
	}
	requestDigest, err := request.Digest()
	if err != nil {
		return "", "", "", err
	}
	storedRequestDigest, err := readRootDigestFile(
		root, phase1anchor.SlotRequestName+phase1anchor.SlotDigestSuffix,
	)
	if err != nil || storedRequestDigest != requestDigest {
		return "", "", "", errors.New("stored anchor request digest mismatch")
	}
	one, err := verifyAnchorReceipt(
		root, phase1anchor.SlotProviderOneReceiptName,
		request,
		trust.providerOneID,
		publicOne,
		previousOne,
	)
	if err != nil {
		return "", "", "", err
	}
	two, err := verifyAnchorReceipt(
		root, phase1anchor.SlotProviderTwoReceiptName,
		request,
		trust.providerTwoID,
		publicTwo,
		previousTwo,
	)
	if err != nil {
		return "", "", "", err
	}
	storedOne, err := readRootDigestFile(
		root,
		phase1anchor.SlotProviderOneReceiptName+phase1anchor.SlotDigestSuffix,
	)
	if err != nil || storedOne != one {
		return "", "", "", errors.New("first provider receipt digest mismatch")
	}
	storedTwo, err := readRootDigestFile(
		root,
		phase1anchor.SlotProviderTwoReceiptName+phase1anchor.SlotDigestSuffix,
	)
	if err != nil || storedTwo != two {
		return "", "", "", errors.New("second provider receipt digest mismatch")
	}
	return one, two, requestDigest, nil
}

func verifyAnchorReceipt(
	root *os.Root,
	name string,
	request phase1anchor.Request,
	providerID string,
	public ed25519.PublicKey,
	previous string,
) (string, error) {
	data, err := readRootRegular(root, name, 64<<10)
	if err != nil {
		return "", err
	}
	receipt, err := phase1anchor.DecodeReceipt(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if err := receipt.Verify(request, providerID, public, previous); err != nil {
		return "", err
	}
	// Pin the sealed bytes, not just the parsed value — see the equivalent
	// check on request.json. A receipt whose duplicate keys or whitespace
	// differ still verifies and still digests identically, which would let two
	// auditors read different provider_id or request_sha256 values out of one
	// sealed receipt while this verifier reported PASS.
	canonical, err := receipt.Canonical()
	if err != nil {
		return "", err
	}
	if !bytes.Equal(data, append(canonical, '\n')) {
		return "", errors.New(
			"anchor receipt bytes are not the canonical sealed encoding",
		)
	}
	return receipt.Digest()
}

// readDigestFile reads a slot digest sidecar and requires its EXACT bytes.
//
// This used to TrimSpace, so a sidecar padded with leading spaces, tabs or
// blank lines carried the right digest and was accepted here — while the pin
// tool that wrote it compares exact bytes and would refuse the same file. A
// byte-canonical evidence guarantee has to be byte-canonical on the side whose
// job is to check it, or it is not a guarantee.
func readDigestFile(path string) (string, error) {
	data, err := readSecureRegular(path, 4<<10)
	if err != nil {
		return "", err
	}
	value, err := phase1anchor.ParseSidecarDigest(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return value, nil
}

// loadAnchorPublicKey reads one of the AUDITOR'S OWN pinned trust roots.
//
// These are the two public keys the person running the verifier supplies on the
// command line. They are deliberately still read by pathname: they are not
// matrix content, they live wherever the auditor keeps them, and confining them
// to the evidence root would be wrong. The copies archived INSIDE the matrix go
// through loadRootAnchorPublicKey instead, and are compared against these.
func loadAnchorPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readSecureRegular(path, 4<<10)
	if err != nil {
		return nil, err
	}
	return decodeAnchorPublicKey(data)
}

// loadRootAnchorPublicKey reads an archived provider key through a confined
// handle on the directory that is supposed to contain it.
func loadRootAnchorPublicKey(
	root *os.Root, name string,
) (ed25519.PublicKey, error) {
	data, err := readRootRegular(root, name, 4<<10)
	if err != nil {
		return nil, err
	}
	return decodeAnchorPublicKey(data)
}

func decodeAnchorPublicKey(data []byte) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(string(data)),
	)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

// openConfinedSubdirectory descends exactly ONE directory component through an
// already-open root, refusing anything that is not a real directory.
//
// The Lstat is a REJECTION, not a resolution, and that distinction is the whole
// point. os.Root on its own would still traverse a symbolic link whose target
// stays inside the root, so the containment property alone does not say "the
// committed anchor slots are in the directory the evidence names" — only
// refusing the link does.
//
// The opened handle is then compared with os.SameFile against the inspection,
// so a rename landing between the two is refused rather than descended into.
// After this returns, the caller holds a descriptor: nothing renamed over the
// name afterwards can change which inode its reads reach.
//
// WHAT MUTATION TESTING ACTUALLY SHOWS ABOUT THESE TWO CHECKS. Neither one is
// independently detectable, and the comment says so rather than implying a
// coverage claim that does not hold. Removing only the mode refusal leaves the
// symlink case green, because the Lstat describes the LINK and the opened
// handle describes its TARGET, so os.SameFile already disagrees. Removing only
// the SameFile comparison leaves it green too, because the mode refusal fires
// first. Removing BOTH flips it: os.Root follows a relative symbolic link whose
// target stays inside the root, so with neither check present the verifier
// certifies a matrix whose anchors, pending or committed component is a link.
// The two together are the control; each alone is defence in depth.
//
// A link that points OUTSIDE the root, or any absolute link, is separately
// refused by os.Root itself — so a test built only on those would be satisfied
// by containment and would prove nothing about this function.
func openConfinedSubdirectory(
	parent *os.Root, name string,
) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsDir() {
		return nil, fmt.Errorf(
			"%s is not a real directory; a symbolic link, file or special node "+
				"in this position is refused rather than resolved", name,
		)
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	handle, err := child.Open(".")
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	defer handle.Close()
	opened, err := handle.Stat()
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	if !opened.IsDir() || !os.SameFile(info, opened) {
		_ = child.Close()
		return nil, fmt.Errorf(
			"%s changed between inspection and open", name,
		)
	}
	return child, nil
}

// readConfinedDirectory enumerates a directory through its own descriptor.
func readConfinedDirectory(root *os.Root) ([]os.DirEntry, error) {
	handle, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	return handle.ReadDir(-1)
}

// sha256RootRegular streams the digest of one regular file through a confined
// handle on its directory.
//
// sha256RootFile is not enough here: it opens by name and type-checks the
// DESCRIPTOR, so a symbolic link inside the root pointing at a regular file
// would be followed and hashed. This Lstat-refuses the link first and then
// proves the descriptor reaches the inode that was classified.
func sha256RootRegular(root *os.Root, name string) (string, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return "", fmt.Errorf("%s changed between inspection and open", name)
	}
	return sha256Reader(file)
}

// requireExactSlotMembers proves a slot holds precisely the profile's artifact
// set, enumerated through the OPEN ROOT rather than the pathname.
//
// Listing the pathname and then reading through the root would let a rename
// between the two describe one directory and read another, so the exact-set
// result would say nothing about the bytes that were actually verified. Both
// operations have to name the same inode, and only a descriptor guarantees
// that.
//
// Every member is additionally required to be a REGULAR file via Lstat, which
// is a rejection rather than a resolution: a symbolic link here — even one
// pointing at a byte-identical copy — means the slot does not contain the
// artifact it claims to contain.
func requireExactSlotMembers(
	root *os.Root,
	expectedNames map[string]struct{},
	profile anchorSlotProfile,
) error {
	directoryFile, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	entries, err := directoryFile.ReadDir(-1)
	if err != nil {
		return err
	}
	if len(entries) != len(expectedNames) {
		return fmt.Errorf(
			"anchor slot has %d files, the %s profile requires exactly %d",
			len(entries), profile, len(expectedNames),
		)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, ok := expectedNames[entry.Name()]; !ok {
			return fmt.Errorf(
				"anchor slot file %q is not part of the %s profile",
				entry.Name(), profile,
			)
		}
		seen[entry.Name()] = struct{}{}
	}
	for name := range expectedNames {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf(
				"anchor slot is missing %q, which the %s profile requires",
				name, profile,
			)
		}
		// Re-checked through the root, so the member that will actually be
		// opened is the one that was classified. A directory entry's cached
		// type and the inode a later lookup reaches are two different facts.
		info, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("anchor slot member %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf(
				"anchor slot member %q is not a regular file; a symbolic "+
					"link, directory or special file in a sealed slot is "+
					"refused rather than resolved", name,
			)
		}
	}
	return nil
}

// readRootRegular reads one slot member through the already-open root.
//
// The previous readSecureRegular path resolved the member with
// filepath.EvalSymlinks, which FOLLOWS a substituted member. Resolving is not
// rejecting: a link pointing at a byte-identical file elsewhere would have been
// read and verified, and the sealed slot would have been certified on the
// strength of a file it does not contain.
func readRootRegular(
	root *os.Root, name string, maximum int64,
) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"anchor slot member %s is not a regular file", name,
		)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf(
			"anchor slot member %s changed between inspection and open", name,
		)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf(
			"anchor slot member %s exceeds the %d-byte limit", name, maximum,
		)
	}
	return content, nil
}

// readRootDigestFile is readDigestFile through the confined root, with the same
// exact-bytes requirement.
func readRootDigestFile(root *os.Root, name string) (string, error) {
	data, err := readRootRegular(root, name, 4<<10)
	if err != nil {
		return "", err
	}
	value, err := phase1anchor.ParseSidecarDigest(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}
