// Command winn-phase1-matrix-verify independently verifies a completed
// production-Auto Phase 1 matrix and calculates every frozen score cell.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/measurement"
)

const (
	profileSchemaV1 = "winn-phase1-auto-impairment-profiles/v1"
	profileSchemaV2 = "winn-phase1-auto-impairment-profiles/v2"

	stagingEdgeProfileID = "envelope-edge-250ms-3pct-10mbps"
	stagingAttempts      = 1000
	stagingBatchSize     = 100
	stagingBatches       = 10
	stagingTCritical95   = 1.833113

	// evidenceDirectoryName is the single directory, directly beneath the
	// matrix root, that holds every batch archive. The sealer hard-codes it
	// (scripts/aicore_phase1_auto_matrix.sh:657) and it is the only directory
	// this verifier will open an archive from.
	evidenceDirectoryName = "evidence"
	archiveSuffix         = ".tar.gz"
	archiveNamePrefix     = "auto-e2e-"

	matrixSchemaV2   = "winn-phase1-auto-matrix/v2"
	batchSchemaV2    = "winn-phase1-auto-matrix-batch/v2"
	completeSchemaV2 = "winn-phase1-auto-matrix-complete/v2"

	matrixSchemaV3   = "winn-phase1-auto-matrix/v3"
	batchSchemaV3    = "winn-phase1-auto-matrix-batch/v3"
	completeSchemaV3 = "winn-phase1-auto-matrix-complete/v3"
)

// safeMatrixIdentifier mirrors phase1anchor's safeID
// (internal/phase1anchor/anchor.go:32) exactly. Every matrix_id and batch_key
// carried by a signed anchor request has already been forced through that shape
// by Request.Validate, so re-applying it here means a derived archive filename
// can never contain a path separator, a NUL, or anything else that could be
// read as structure rather than as a name.
var safeMatrixIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

type profileDocument struct {
	Schema                         string           `json:"schema"`
	ProtocolVersion                string           `json:"protocol_version"`
	AttemptsPerReadinessPerProfile int              `json:"attempts_per_readiness_per_profile"`
	BatchSize                      int              `json:"batch_size,omitempty"`
	ScheduleSeed                   string           `json:"schedule_seed,omitempty"`
	ScheduleSeedProvenance         string           `json:"schedule_seed_provenance,omitempty"`
	ReadinessClasses               []string         `json:"readiness_classes"`
	Profiles                       []networkProfile `json:"profiles"`
	ScoreGate                      scoreGate        `json:"score_gate"`
	FailureTaxonomy                failureTaxonomy  `json:"failure_taxonomy,omitempty"`
	FrozenAtUTC                    string           `json:"frozen_at_utc"`
	MeasurementRule                json.RawMessage  `json:"measurement_rule"`
	TrafficControlRule             json.RawMessage  `json:"traffic_control_rule"`
}

type failureTaxonomy struct {
	Availability []connectivity.FailureCode `json:"availability,omitempty"`
	Security     []connectivity.FailureCode `json:"security,omitempty"`
}

type networkProfile struct {
	ID           string  `json:"id"`
	RTTMillis    float64 `json:"rtt_millis"`
	LossFraction float64 `json:"loss_fraction"`
	CapacityMbps float64 `json:"capacity_mbps"`
	Purpose      string  `json:"purpose"`
}

type scoreGate struct {
	Failures                    *int    `json:"failures,omitempty"`
	AvailabilityFailuresMax     *int    `json:"availability_failures_max,omitempty"`
	SecurityFailuresMax         *int    `json:"security_failures_max,omitempty"`
	P50MillisMax                float64 `json:"p50_millis_max"`
	P95MillisMax                float64 `json:"p95_millis_max"`
	P99MillisMax                float64 `json:"p99_millis_max"`
	IndividualAttemptMillisMax  float64 `json:"individual_attempt_millis_max"`
	LatencyThresholdMillis      float64 `json:"latency_threshold_millis,omitempty"`
	LatencyExceedanceUpper95Max float64 `json:"latency_exceedance_upper_95_max,omitempty"`
	ClusterBatchSize            int     `json:"cluster_batch_size,omitempty"`
	ClusterBatchesPerCell       int     `json:"cluster_batches_per_cell,omitempty"`
	ClusterTCritical95          float64 `json:"cluster_t_critical_95,omitempty"`
	StagingDesignTargetMillis   float64 `json:"staging_design_target_millis,omitempty"`
}

type matrixBatch struct {
	schema string
	key    string
	block  int
	// orderDigest, profile, readiness and attempts are pinned to the frozen
	// schedule row and to the signed anchor request.
	orderDigest string
	profile     string
	readiness   measurement.ReadinessClass
	attempts    int
	// archive is the absolute path of the machine that sealed this batch. It
	// is provenance only: it is recorded, cross-checked for shape, and never
	// opened, because a byte-exact copy of a sealed root does not live there.
	archive string
	// archiveRelative is the schema-v3 archive path relative to the matrix
	// root. Empty for legacy v2 roots, whose archive name is derived instead.
	archiveRelative string
	// evidenceRelative names the evidence directory EXPLICITLY, relative to the
	// matrix root.
	//
	// It exists because deriving the directory by trimming ".tar.gz" off the
	// archive name is a guess that happens to be right only while the two
	// names differ by exactly that suffix. A closed archive is
	// "<name>.closed.tar.gz" and its evidence directory is "<name>", so the
	// trim yields "<name>.closed" — a directory that does not exist. Rather
	// than teach the trim about every suffix that will ever be introduced, the
	// record states the mapping and the verifier reads it.
	evidenceRelative string
	digest           string
	inventory        string
	anchorMode       string
	requestHash      string
	receiptOne       string
	receiptTwo       string
}

type anchorTrust struct {
	providerOneID        string
	providerOnePublicKey string
	providerTwoID        string
	providerTwoPublicKey string
}

type scheduledBatch struct {
	key         string
	block       int
	orderDigest string
	profile     string
	readiness   measurement.ReadinessClass
	attempts    int
}

type qdiscRecord struct {
	Kind    string `json:"kind"`
	Root    bool   `json:"root"`
	Packets uint64 `json:"packets"`
	Options struct {
		Delay struct {
			Delay float64 `json:"delay"`
		} `json:"delay"`
		LossRandom struct {
			Loss float64 `json:"loss"`
		} `json:"loss-random"`
		Rate struct {
			Rate float64 `json:"rate"`
		} `json:"rate"`
	} `json:"options"`
}

func main() {
	matrixRoot := flag.String(
		"matrix-root", "", "completed private matrix root",
	)
	profilePath := flag.String(
		"profiles", "", "frozen impairment profile JSON",
	)
	expectedSource := flag.String(
		"expected-source-digest", "", "required Auto source digest",
	)
	expectedAWGEngine := flag.String(
		"expected-awg-engine-digest", "", "required Winn AWG engine digest",
	)
	stagingEdgeReport := flag.Bool(
		"staging-edge-report",
		false,
		"verify the exact 2,000-attempt edge staging screen; never promotes",
	)
	anchoredSmokeReport := flag.Bool(
		"anchored-smoke-report",
		false,
		"verify a partial dual-provider integration smoke; never promotes",
	)
	carrierConservationReport := flag.String(
		"carrier-conservation-report",
		"",
		"recompute the carrier conservation law of one sealed evidence "+
			"directory; never promotes",
	)
	providerOneID := flag.String(
		"anchor-provider-one-id", "", "trusted first anchor provider ID",
	)
	providerOnePublicKey := flag.String(
		"anchor-provider-one-public-key", "",
		"trusted first anchor Ed25519 public key",
	)
	providerTwoID := flag.String(
		"anchor-provider-two-id", "", "trusted second anchor provider ID",
	)
	providerTwoPublicKey := flag.String(
		"anchor-provider-two-public-key", "",
		"trusted second anchor Ed25519 public key",
	)
	// AUDIT-CLOSE. The finalizer identity is the auditor's own pin, published
	// by the runner separately from the evidence. It is a public ML-DSA-65 key
	// identity, so supplying it discloses nothing and grants nothing; what it
	// does is make the checkpoint's signature mean something other than "this
	// document vouches for itself".
	auditFinalizerKeyID := flag.String(
		"audit-finalizer-key-id", "",
		"pinned winn-audit-checkpoint/v1 finalizer key identity (64 lower-hex)",
	)
	auditRunID := flag.String(
		"audit-run-id", "",
		"run identity the audit checkpoint must name; required by the "+
			"standalone conservation report, derived from matrix.env otherwise",
	)
	// AUDIT-CLOSE. The controller has to run a full verification pass over the
	// state it is ABOUT to complete, because a pass that ran only after
	// COMPLETE was written could not prevent a failed check from leaving a
	// completion-looking artifact behind. This names the record to read
	// instead of COMPLETE, so the candidate can be verified under a name no
	// consumer treats as terminal, and COMPLETE is written only afterwards.
	completeRecordName := flag.String(
		"complete-record-name", "COMPLETE",
		"completion record to read; a controller verifies its candidate under "+
			"a non-terminal name before publishing COMPLETE",
	)
	auditProducerDigest := flag.String(
		"audit-producer-digest", "",
		"producer/source digest the audit checkpoint must bind; required by "+
			"the standalone conservation report, derived from "+
			"-expected-source-digest otherwise",
	)
	flag.Parse()
	trust := anchorTrust{
		providerOneID:        *providerOneID,
		providerOnePublicKey: *providerOnePublicKey,
		providerTwoID:        *providerTwoID,
		providerTwoPublicKey: *providerTwoPublicKey,
	}
	checkpoint := auditCheckpointPin{
		finalizerKeyID: *auditFinalizerKeyID,
		runID:          *auditRunID,
		producerDigest: *auditProducerDigest,
	}
	if *carrierConservationReport != "" {
		if *stagingEdgeReport || *anchoredSmokeReport {
			fmt.Fprintln(
				os.Stderr,
				"MATRIX_VERIFY_FAIL: report modes are mutually exclusive",
			)
			os.Exit(1)
		}
		if err := reportCarrierConservation(
			*carrierConservationReport, checkpoint,
		); err != nil {
			fmt.Fprintln(os.Stderr, "MATRIX_VERIFY_FAIL:", err)
			os.Exit(1)
		}
		return
	}
	if *anchoredSmokeReport {
		if *stagingEdgeReport {
			fmt.Fprintln(
				os.Stderr,
				"MATRIX_VERIFY_FAIL: report modes are mutually exclusive",
			)
			os.Exit(1)
		}
		if err := verifyAnchoredSmoke(
			*matrixRoot,
			*profilePath,
			*expectedSource,
			*expectedAWGEngine,
			trust,
			checkpoint,
		); err != nil {
			fmt.Fprintln(os.Stderr, "MATRIX_VERIFY_FAIL:", err)
			os.Exit(1)
		}
		return
	}
	if err := verifyMatrixWithAnchorTrust(
		*matrixRoot, *profilePath, *expectedSource, *expectedAWGEngine,
		*stagingEdgeReport,
		trust,
		checkpoint,
		*completeRecordName,
	); err != nil {
		fmt.Fprintln(os.Stderr, "MATRIX_VERIFY_FAIL:", err)
		os.Exit(1)
	}
}

// reportCarrierConservation runs exactly the two checks a promotional batch
// runs over its carrier evidence — the evidence manifest, then the carrier
// conservation law recomputed from the sealed trail — against a single sealed
// evidence directory that is not part of a completed matrix.
//
// It exists so a synthetic conservation smoke can be judged by the real
// verifier rather than by a bespoke copy of its logic. It is additive and
// read-only: it calls verifyEvidenceManifest and verifyCarrierConservation
// unchanged, relaxes nothing, and cannot promote anything. Everything it
// prints is recomputed here from the sealed trail, never read from the
// harness's own claim, which the conservation check has already required to
// match.
//
// It then applies one check the promotional path deliberately does not: the
// forced-abort attestation itself, that every member of the closed abort-reason
// enum appears exactly once per carrier. A real matrix has no reason to abort
// at all, let alone exactly once for each reason, so this requirement belongs
// only to the report mode — but without it MATRIX_VERIFY_CARRIER_CONSERVATION_OK
// would claim less than it appears to, leaving the "each reason exactly once"
// attestation resting solely on the smoke binary's own exit status.
func reportCarrierConservation(
	evidenceDirectory string,
	checkpoint auditCheckpointPin,
) error {
	if evidenceDirectory == "" {
		return errors.New("carrier-conservation-report requires a directory")
	}
	if err := verifyEvidenceManifest(evidenceDirectory); err != nil {
		return err
	}
	// AUDIT-CLOSE before conservation, for the reason spelled out in
	// auditcheckpoint.go: the manifest proves the files are the files that were
	// sealed, and the conservation law proves the records that are present
	// reconcile, but only the terminal checkpoint proves the records that are
	// present are all the records there were.
	closed, err := verifyAuditCheckpoint(evidenceDirectory, checkpoint)
	if err != nil {
		return err
	}
	if err := verifyCarrierConservation(evidenceDirectory); err != nil {
		return err
	}
	abortReasons, err := requireForcedAbortCoverage(
		filepath.Join(evidenceDirectory, carrierAuditFileName),
	)
	if err != nil {
		return err
	}
	counts, err := recomputeCarrierAudit(
		filepath.Join(evidenceDirectory, carrierAuditFileName),
	)
	if err != nil {
		return err
	}
	redemptions, err := readCarrierCount(
		filepath.Join(evidenceDirectory, redemptionCountFileName),
	)
	if err != nil {
		return err
	}
	h3 := counts[carrierFamilyH3]
	h2 := counts[carrierFamilyH2]
	fmt.Println("MATRIX_VERIFY_CARRIER_CONSERVATION_OK")
	fmt.Printf("evidence_dir=%s\n", evidenceDirectory)
	// What the checkpoint actually closed, printed from the verified record so
	// the report states the trail length it reconciled rather than leaving a
	// reader to assume the trail was complete.
	fmt.Printf(
		"audit_close_run_id=%s audit_close_records=%d "+
			"audit_close_chain_head=%s audit_close_finalizer=%s\n",
		closed.RunID, closed.RecordCount, closed.ChainHeadMAC,
		closed.FinalizerKeyID,
	)
	fmt.Printf("redemptions=%d\n", redemptions)
	fmt.Printf(
		"anonymous_authenticated=%d\n",
		h3.anonymousAuthenticated+h2.anonymousAuthenticated,
	)
	fmt.Printf(
		"h3_authenticated=%d h3_auth_only=%d h3_open=%d h3_closed=%d "+
			"h3_aborted=%d\n",
		h3.authenticated, h3.authOnly, h3.open, h3.closed, h3.aborted,
	)
	fmt.Printf(
		"h2_authenticated=%d h2_auth_only=%d h2_open=%d h2_closed=%d "+
			"h2_aborted=%d\n",
		h2.authenticated, h2.authOnly, h2.open, h2.closed, h2.aborted,
	)
	fmt.Printf(
		"h3_abort_reasons=%s\n",
		formatAbortReasonMultiset(abortReasons[carrierFamilyH3]),
	)
	fmt.Printf(
		"h2_abort_reasons=%s\n",
		formatAbortReasonMultiset(abortReasons[carrierFamilyH2]),
	)
	return nil
}

// requireForcedAbortCoverage recomputes, from the sealed trail alone, the
// multiset of abort reasons each carrier recorded, and requires every member of
// the closed enum exactly once per carrier and nothing else.
//
// This is a report-mode-only requirement. verifyCarrierConservation checks enum
// membership, which is the right rule for promotional evidence; "exactly one of
// each, per carrier" is the specific claim a forced-abort smoke exists to make,
// and a run that recorded five copies of one reason satisfies every count-based
// check but fails here.
func requireForcedAbortCoverage(path string) (
	map[carrierFamily]map[string]int,
	error,
) {
	return requireForcedAbortCoverageBounded(path, maximumCarrierAuditBytes)
}

func requireForcedAbortCoverageBounded(path string, limit int64) (
	map[carrierFamily]map[string]int,
	error,
) {
	file, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reasons := map[carrierFamily]map[string]int{
		carrierFamilyH3: {},
		carrierFamilyH2: {},
	}
	bounded := newBoundedReader(file, limit)
	scanner := bufio.NewScanner(bounded)
	scanner.Buffer(make([]byte, 4096), maximumCarrierAuditLine)
	lines := 0
	for scanner.Scan() {
		if bounded.exceeded() {
			return nil, bounded.check("the carrier audit trail")
		}
		lines++
		if lines > maximumCarrierAuditEvents {
			return nil, errors.New("carrier audit log is implausibly long")
		}
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		var entry carrierAuditRecord
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("carrier audit line %d: %w", lines, err)
		}
		if err := requireEOF(decoder); err != nil {
			return nil, fmt.Errorf("carrier audit line %d: %w", lines, err)
		}
		descriptor, tracked := carrierTerminalEvents[entry.Event]
		if !tracked || descriptor.class != carrierClassAborted {
			continue
		}
		_, _, _, reason, err := parseCarrierTerminalDetail(entry.Detail)
		if err != nil {
			return nil, fmt.Errorf("carrier audit line %d: %w", lines, err)
		}
		reasons[descriptor.family][reason]++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read carrier audit log: %w", err)
	}
	if err := bounded.check("the carrier audit trail"); err != nil {
		return nil, err
	}

	for _, family := range []carrierFamily{carrierFamilyH3, carrierFamilyH2} {
		observed := reasons[family]
		for _, reason := range carrierAbortReasons {
			if observed[reason] != 1 {
				return nil, fmt.Errorf(
					"forced-abort coverage: %s carrier sealed abort reason %s "+
						"%d times, the conservation report requires exactly "+
						"once (observed %s)",
					family, reason, observed[reason],
					formatAbortReasonMultiset(observed),
				)
			}
		}
		for reason := range observed {
			if !slices.Contains(carrierAbortReasons, reason) {
				return nil, fmt.Errorf(
					"forced-abort coverage: %s carrier sealed abort reason %q, "+
						"which is not a member of the closed enum",
					family, reason,
				)
			}
		}
		if len(observed) != len(carrierAbortReasons) {
			return nil, fmt.Errorf(
				"forced-abort coverage: %s carrier sealed %d distinct abort "+
					"reasons, the closed enum has %d",
				family, len(observed), len(carrierAbortReasons),
			)
		}
	}
	return reasons, nil
}

func formatAbortReasonMultiset(observed map[string]int) string {
	if len(observed) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(observed))
	for reason := range observed {
		keys = append(keys, reason)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, reason := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", reason, observed[reason]))
	}
	return strings.Join(parts, ",")
}

func verifyMatrixWithAnchorTrust(
	matrixRoot string,
	profilePath string,
	expectedSource string,
	expectedAWGEngine string,
	stagingEdgeReport bool,
	trust anchorTrust,
	checkpoint auditCheckpointPin,
	completeRecordName string,
) error {
	if completeRecordName == "" ||
		strings.ContainsAny(completeRecordName, "/\\") {
		return errors.New("completion record name must be a bare basename")
	}
	if matrixRoot == "" || profilePath == "" ||
		!lowerHex(expectedSource, sha256.Size*2) ||
		!lowerHex(expectedAWGEngine, sha256.Size*2) {
		return errors.New(
			"matrix-root, profiles, source, and AWG engine digests are required",
		)
	}
	root, err := filepath.Abs(matrixRoot)
	if err != nil {
		return err
	}
	profiles, profileDigest, err := loadProfiles(profilePath)
	if err != nil {
		return err
	}
	matrixEnvironment, err := parseKeyValueFile(
		filepath.Join(root, "matrix.env"),
	)
	if err != nil {
		return err
	}
	if matrixEnvironment["source_digest"] != expectedSource ||
		matrixEnvironment["awg_engine_sha256"] != expectedAWGEngine ||
		matrixEnvironment["profile_sha256"] != profileDigest {
		return errors.New(
			"matrix environment does not match pinned inputs",
		)
	}
	profiles, err = verificationProfile(
		profiles,
		matrixEnvironment,
		stagingEdgeReport,
	)
	if err != nil {
		return err
	}
	complete, err := parseKeyValueFile(
		filepath.Join(root, completeRecordName),
	)
	if err != nil {
		return fmt.Errorf("matrix is not complete: %w", err)
	}

	batches, err := loadBatches(root)
	if err != nil {
		return err
	}
	profileByID := make(map[string]networkProfile, len(profiles.Profiles))
	for _, current := range profiles.Profiles {
		if current.ID == "" {
			return errors.New("frozen profile has no ID")
		}
		if _, duplicate := profileByID[current.ID]; duplicate {
			return fmt.Errorf(
				"frozen profile %q is duplicated", current.ID,
			)
		}
		profileByID[current.ID] = current
	}
	allowedReadiness := make(
		map[measurement.ReadinessClass]struct{},
		len(profiles.ReadinessClasses),
	)
	for _, value := range profiles.ReadinessClasses {
		class := measurement.ReadinessClass(value)
		if class != measurement.ReadinessWarm &&
			class != measurement.ReadinessCold {
			return fmt.Errorf(
				"frozen readiness class %q is invalid", value,
			)
		}
		allowedReadiness[class] = struct{}{}
	}
	if profiles.Schema == profileSchemaV2 {
		if err := verifyExecutionInventory(
			root, matrixEnvironment, complete,
		); err != nil {
			return err
		}
		if err := verifyV2Schedule(
			root,
			profiles,
			matrixEnvironment,
			complete,
			batches,
		); err != nil {
			return err
		}
		if err := verifyDualProviderAnchors(
			root,
			profiles,
			matrixEnvironment,
			complete,
			batches,
			stagingEdgeReport,
			trust,
			false,
			checkpoint,
		); err != nil {
			return err
		}
	}

	cellAttempts := make(map[string][]measurement.Attempt)
	cellBatches := make(map[string][][]measurement.Attempt)
	attemptIDs := make(map[string]string)
	artifactDigests := make(map[string]struct{})
	total := 0
	for _, batch := range batches {
		profile, ok := profileByID[batch.profile]
		if !ok {
			return fmt.Errorf(
				"batch %s uses unknown profile %q",
				batch.key, batch.profile,
			)
		}
		if _, ok := allowedReadiness[batch.readiness]; !ok {
			return fmt.Errorf(
				"batch %s uses unknown readiness %q",
				batch.key, batch.readiness,
			)
		}
		attempts, err := verifyBatch(
			root,
			matrixEnvironment["matrix_id"],
			batch,
			profile,
			profiles.ScoreGate.IndividualAttemptMillisMax,
			expectedSource,
			expectedAWGEngine,
			profiles.Schema == profileSchemaV2,
			matrixEnvironment["execution_inventory_sha256"],
			checkpoint,
		)
		if err != nil {
			return fmt.Errorf("batch %s: %w", batch.key, err)
		}
		cell := cellID(batch.profile, batch.readiness)
		for _, attempt := range attempts {
			if previous, duplicate := attemptIDs[attempt.AttemptID]; duplicate {
				return fmt.Errorf(
					"attempt %s is duplicated in %s and %s",
					attempt.AttemptID, previous, batch.key,
				)
			}
			attemptIDs[attempt.AttemptID] = batch.key
			artifactDigests[attempt.ArtifactDigest] = struct{}{}
		}
		cellAttempts[cell] = append(cellAttempts[cell], attempts...)
		cellBatches[cell] = append(cellBatches[cell], attempts)
		total += len(attempts)
	}
	expectedTotal := len(profileByID) * len(allowedReadiness) *
		profiles.AttemptsPerReadinessPerProfile
	if total != expectedTotal {
		return fmt.Errorf(
			"matrix contains %d attempts, want %d", total, expectedTotal,
		)
	}
	if complete["attempts"] != strconv.Itoa(expectedTotal) {
		return errors.New("COMPLETE attempt count is inconsistent")
	}
	if len(artifactDigests) != 1 {
		return fmt.Errorf(
			"matrix has %d Auto artifact digests", len(artifactDigests),
		)
	}

	cells := make([]string, 0, len(cellAttempts))
	for cell := range cellAttempts {
		cells = append(cells, cell)
	}
	slices.Sort(cells)
	for _, cell := range cells {
		attempts := cellAttempts[cell]
		if len(attempts) != profiles.AttemptsPerReadinessPerProfile {
			return fmt.Errorf(
				"cell %s contains %d attempts, want %d",
				cell, len(attempts),
				profiles.AttemptsPerReadinessPerProfile,
			)
		}
		summary := measurement.Summarize(attempts)
		latencyUpper95 := float64(0)
		latencyExceedances := 0
		if profiles.Schema == profileSchemaV1 {
			if profiles.ScoreGate.Failures == nil ||
				summary.Failures != *profiles.ScoreGate.Failures {
				return fmt.Errorf(
					"cell %s failures=%d, want %v",
					cell, summary.Failures, profiles.ScoreGate.Failures,
				)
			}
		} else {
			securityFailures := countSecurityFailures(attempts)
			availabilityFailures := summary.Failures - securityFailures
			if profiles.ScoreGate.AvailabilityFailuresMax == nil ||
				profiles.ScoreGate.SecurityFailuresMax == nil ||
				availabilityFailures >
					*profiles.ScoreGate.AvailabilityFailuresMax ||
				securityFailures >
					*profiles.ScoreGate.SecurityFailuresMax {
				return fmt.Errorf(
					"cell %s availability failures=%d security failures=%d",
					cell, availabilityFailures, securityFailures,
				)
			}
			var confidenceErr error
			latencyUpper95, latencyExceedances, confidenceErr =
				clusterAwareExceedanceUpper95(
					cellBatches[cell],
					profiles.ScoreGate.LatencyThresholdMillis,
					profiles.ScoreGate.ClusterBatchSize,
					profiles.ScoreGate.ClusterBatchesPerCell,
					profiles.ScoreGate.ClusterTCritical95,
				)
			if confidenceErr != nil {
				return fmt.Errorf(
					"cell %s latency confidence: %w",
					cell, confidenceErr,
				)
			}
			if latencyUpper95 >
				profiles.ScoreGate.LatencyExceedanceUpper95Max {
				return fmt.Errorf(
					"cell %s latency exceedances=%d upper95=%.6f "+
						"exceeds %.6f",
					cell,
					latencyExceedances,
					latencyUpper95,
					profiles.ScoreGate.LatencyExceedanceUpper95Max,
				)
			}
		}
		if durationMillis(summary.OutcomeP50) >
			profiles.ScoreGate.P50MillisMax ||
			durationMillis(summary.OutcomeP95) >
				profiles.ScoreGate.P95MillisMax ||
			durationMillis(summary.OutcomeP99) >
				profiles.ScoreGate.P99MillisMax {
			return fmt.Errorf(
				"cell %s exceeds percentile gate: "+
					"p50=%s p95=%s p99=%s",
				cell,
				summary.OutcomeP50,
				summary.OutcomeP95,
				summary.OutcomeP99,
			)
		}
		if profiles.Schema == profileSchemaV2 {
			marker := "CELL_PASS"
			if stagingEdgeReport {
				marker = "STAGING_SCREEN_CELL_PASS"
			}
			fmt.Printf(
				"%s cell=%s attempts=%d failures=%d "+
					"p50=%s p95=%s p99=%s threshold_exceedances=%d "+
					"exceedance_upper95=%.6f\n",
				marker,
				cell,
				summary.Total,
				summary.Failures,
				summary.OutcomeP50,
				summary.OutcomeP95,
				summary.OutcomeP99,
				latencyExceedances,
				latencyUpper95,
			)
		} else {
			fmt.Printf(
				"CELL_PASS cell=%s attempts=%d failures=%d "+
					"p50=%s p95=%s p99=%s\n",
				cell,
				summary.Total,
				summary.Failures,
				summary.OutcomeP50,
				summary.OutcomeP95,
				summary.OutcomeP99,
			)
		}
	}
	if stagingEdgeReport {
		fmt.Printf(
			"STAGING_SCREEN_VERIFY_PASS attempts=%d cells=%d "+
				"source_digest=%s artifact_digest=%s profile_digest=%s "+
				"non_promotional=1 formal_matrix_required=1\n",
			total,
			len(cells),
			expectedSource,
			onlyKey(artifactDigests),
			profileDigest,
		)
	} else if completeRecordName != "COMPLETE" {
		// A candidate pass. The completion record this run read is not the
		// terminal one, so the matrix is not complete and this transcript must
		// not read like a promotion. The banner itself carries that, because a
		// transcript travels: pasted into a report or a ticket, internal state
		// does not travel with it, and a reader seeing MATRIX_VERIFY_PASS would
		// reasonably conclude the matrix had passed for real.
		fmt.Printf(
			"MATRIX_VERIFY_CANDIDATE_PASS non_promotional=1 "+
				"complete_record=%s attempts=%d cells=%d "+
				"source_digest=%s artifact_digest=%s profile_digest=%s\n",
			completeRecordName,
			total,
			len(cells),
			expectedSource,
			onlyKey(artifactDigests),
			profileDigest,
		)
	} else {
		fmt.Printf(
			"MATRIX_VERIFY_PASS attempts=%d cells=%d "+
				"source_digest=%s artifact_digest=%s profile_digest=%s\n",
			total,
			len(cells),
			expectedSource,
			onlyKey(artifactDigests),
			profileDigest,
		)
	}
	return nil
}

func verificationProfile(
	profiles profileDocument,
	environment map[string]string,
	stagingEdgeReport bool,
) (profileDocument, error) {
	if profiles.Schema != profileSchemaV2 {
		if stagingEdgeReport {
			return profileDocument{}, errors.New(
				"edge staging report requires the v2 profile",
			)
		}
		if environment["partial"] != "0" {
			return profileDocument{}, errors.New(
				"legacy matrix environment is partial",
			)
		}
		return profiles, nil
	}
	if !lowerHex(environment["schedule_sha256"], sha256.Size*2) ||
		environment["schedule_seed"] != profiles.ScheduleSeed {
		return profileDocument{}, errors.New(
			"matrix environment lacks the pinned randomized schedule",
		)
	}
	if !stagingEdgeReport {
		if environment["partial"] != "0" ||
			environment["batch_size"] != strconv.Itoa(profiles.BatchSize) ||
			environment["attempts_per_readiness_per_profile"] !=
				strconv.Itoa(profiles.AttemptsPerReadinessPerProfile) ||
			environment["profile_filter"] != "" {
			return profileDocument{}, errors.New(
				"matrix environment does not match frozen full-run inputs",
			)
		}
		return profiles, nil
	}
	if environment["partial"] != "1" ||
		environment["batch_size"] != strconv.Itoa(stagingBatchSize) ||
		environment["attempts_per_readiness_per_profile"] !=
			strconv.Itoa(stagingAttempts) ||
		environment["profile_filter"] != stagingEdgeProfileID ||
		profiles.BatchSize != stagingBatchSize {
		return profileDocument{}, errors.New(
			"staging screen must be exactly 1,000 edge attempts per readiness " +
				"in 100-attempt batches",
		)
	}
	var edge networkProfile
	found := false
	for _, current := range profiles.Profiles {
		if current.ID == stagingEdgeProfileID {
			edge = current
			found = true
			break
		}
	}
	if !found {
		return profileDocument{}, errors.New(
			"frozen profile lacks the required edge cell",
		)
	}
	zero := 0
	profiles.Profiles = []networkProfile{edge}
	profiles.AttemptsPerReadinessPerProfile = stagingAttempts
	profiles.ScoreGate.AvailabilityFailuresMax = &zero
	profiles.ScoreGate.SecurityFailuresMax = &zero
	profiles.ScoreGate.ClusterBatchSize = stagingBatchSize
	profiles.ScoreGate.ClusterBatchesPerCell = stagingBatches
	profiles.ScoreGate.ClusterTCritical95 = stagingTCritical95
	return profiles, nil
}

func verifyBatch(
	root string,
	matrixID string,
	batch matrixBatch,
	profile networkProfile,
	individualMillisMax float64,
	expectedSource string,
	expectedAWGEngine string,
	allowMeasuredFailures bool,
	expectedInventory string,
	checkpoint auditCheckpointPin,
) ([]measurement.Attempt, error) {
	archive, digest, err := resolveBatchArchive(root, matrixID, batch)
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	if digest != batch.digest {
		return nil, errors.New("archive digest mismatch")
	}
	evidenceDirectory, err := resolveEvidenceDirectory(root, batch, archive)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(evidenceDirectory)
	if err != nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New(
			"evidence directory is absent or not a real directory",
		)
	}
	result, err := readSecureRegular(
		filepath.Join(evidenceDirectory, "result.txt"),
		4<<10,
	)
	if err != nil || strings.TrimSpace(string(result)) != "PASS" {
		return nil, errors.New("evidence result is not PASS")
	}
	if err := verifyEvidenceManifest(evidenceDirectory); err != nil {
		return nil, err
	}
	if err := verifyQdiscEvidence(evidenceDirectory, profile); err != nil {
		return nil, err
	}
	environment, err := parseKeyValueFile(
		filepath.Join(evidenceDirectory, "environment.txt"),
	)
	if err != nil ||
		environment["awg_engine_sha256"] != expectedAWGEngine {
		return nil, errors.New(
			"evidence environment has the wrong Winn AWG engine",
		)
	}
	if allowMeasuredFailures {
		if err := verifyExperimentKnobs(environment); err != nil {
			return nil, err
		}
		if !lowerHex(expectedInventory, sha256.Size*2) ||
			batch.inventory != expectedInventory ||
			environment["execution_inventory_sha256"] !=
				expectedInventory {
			return nil, errors.New(
				"batch is not bound to the frozen execution inventory",
			)
		}
		inventoryDigest, err := sha256File(
			filepath.Join(
				evidenceDirectory, "execution-inventory.sha256",
			),
		)
		if err != nil || inventoryDigest != expectedInventory {
			return nil, errors.New(
				"evidence execution inventory digest mismatch",
			)
		}
		// Recompute the carrier conservation law from the sealed trail rather
		// than trusting the live harness's own reconciliation. Gated on the
		// schema-v2 profiles for the same reason verifyExperimentKnobs is:
		// those are the batches whose measured outcomes are scored, and they
		// are the only ones a promotion can rest on. Pre-conservation sealed
		// stages predate the terminal-event schema and are preserved as
		// non-promotional historical artifacts, not re-validated here.
		//
		// Ordered after the provenance checks above so that a batch that is
		// not even bound to the frozen inventory is reported as such, rather
		// than as a carrier-evidence defect.
		//
		// AUDIT-CLOSE runs first among the carrier-evidence checks. The
		// conservation law is arithmetic over whatever records the trail
		// happens to contain, and the HMAC chain cannot detect a tail
		// truncation, so a trail that was cut short — with the conservation
		// snapshot, the abort coverage, and the manifest all rewritten to
		// agree — reconciles perfectly. Only the finalizer-signed checkpoint,
		// which commits to the trail's length and head under a credential the
		// carrier never held, can see it. Checking conservation first would
		// mean reporting that conservation holds over evidence that was never
		// closed.
		//
		// The run identity is derived here, per batch, from the matrix identity
		// and this batch's own key — both already bound by the signed anchor
		// request — rather than pinned once for the whole matrix. Every batch
		// closes its own trail, so a matrix-wide identity would let one batch's
		// checkpoint be moved onto another batch of the same matrix unnoticed.
		if _, err := verifyAuditCheckpoint(
			evidenceDirectory,
			checkpoint.withBatchRun(matrixID, batch.key, expectedSource),
		); err != nil {
			return nil, err
		}
		if err := verifyCarrierConservation(evidenceDirectory); err != nil {
			return nil, err
		}
	}
	binaries, err := readSecureRegular(
		filepath.Join(evidenceDirectory, "binaries.sha256"),
		64<<10,
	)
	if err != nil ||
		!strings.Contains(
			string(binaries),
			expectedAWGEngine+"  /opt/winn-lab/bin/amneziawg-go-winn-v3-",
		) {
		return nil, errors.New(
			"binary inventory lacks the pinned Winn AWG engine",
		)
	}
	if allowMeasuredFailures {
		frozenInventory, err := readSecureRegular(
			filepath.Join(root, "execution-inventory.sha256"),
			256<<10,
		)
		if err != nil {
			return nil, fmt.Errorf("read frozen execution inventory: %w", err)
		}
		frozenLines, err := sha256ManifestLineSet(frozenInventory)
		if err != nil {
			return nil, fmt.Errorf("frozen execution inventory: %w", err)
		}
		actualLines, err := sha256ManifestLineSet(binaries)
		if err != nil {
			return nil, fmt.Errorf("batch binary inventory: %w", err)
		}
		for line := range actualLines {
			if _, ok := frozenLines[line]; !ok {
				return nil, errors.New(
					"batch executed a project binary outside the frozen inventory",
				)
			}
		}
	}
	logPath := filepath.Join(evidenceDirectory, "attempts.jsonl")
	keyPath := filepath.Join(evidenceDirectory, "attempts.key")
	if err := measurement.Verify(logPath, keyPath); err != nil {
		return nil, fmt.Errorf("measurement HMAC chain: %w", err)
	}
	log, err := measurement.Open(logPath, keyPath)
	if err != nil {
		return nil, err
	}
	attempts := log.Attempts()
	closeErr := log.Close()
	if closeErr != nil {
		return nil, closeErr
	}
	if len(attempts) != batch.attempts {
		return nil, fmt.Errorf(
			"measurement count=%d, want %d",
			len(attempts), batch.attempts,
		)
	}
	for _, attempt := range attempts {
		if attempt.SourceDigest != expectedSource ||
			attempt.ProtocolVersion != connectivity.Version ||
			attempt.Mode != connectivity.ModeAuto ||
			attempt.Readiness != batch.readiness ||
			attempt.Network.Impairment != profile.ID {
			return nil, fmt.Errorf(
				"attempt %s has inconsistent provenance/outcome",
				attempt.AttemptID,
			)
		}
		if !allowMeasuredFailures &&
			(attempt.Outcome != measurement.OutcomeSuccess ||
				attempt.Failure != connectivity.FailureNone) {
			return nil, fmt.Errorf(
				"attempt %s is not a legacy all-success outcome",
				attempt.AttemptID,
			)
		}
		if !sameFloat(
			attempt.Network.LossFraction, profile.LossFraction,
		) || !sameFloat(
			attempt.Network.CapacityMbps, profile.CapacityMbps,
		) || !rttMatches(
			attempt.Network.RTTMillis, profile.RTTMillis,
		) {
			return nil, fmt.Errorf(
				"attempt %s has mislabeled network values",
				attempt.AttemptID,
			)
		}
		if float64(attempt.Timeline.OutcomeMicros)/1000 >
			individualMillisMax {
			return nil, fmt.Errorf(
				"attempt %s exceeds individual deadline",
				attempt.AttemptID,
			)
		}
	}
	return attempts, nil
}

// verifyExperimentKnobs rejects sealed evidence that was produced with any
// experiment-altering harness knob engaged. It runs only where measured
// failures are scored rather than treated as harness faults, which is every
// schema-v2 profile: the formal matrix, the staging edge screen, and the
// anchored integration smoke.
//
// force_carrier must be recorded and empty. Merely accepting "empty or
// absent" would be no gate at all: a run restricted to one carrier prepares a
// different candidate set, yet evidence sealed by a harness that never wrote
// the key is byte-indistinguishable from an unrestricted run, so absence
// would silently readmit exactly the runs this check exists to catch.
// Requiring the key to be present makes the recording itself the evidence —
// only a harness that would have disclosed a forced carrier can produce a
// batch that passes. The key is covered by evidence-manifest.sha256, which
// the dual-provider anchor request commits to, so it cannot be added after
// the fact.
func verifyExperimentKnobs(environment map[string]string) error {
	if environment["direct_initial_outer_drop"] != "0s" ||
		environment["direct_click_delay"] != "0s" ||
		environment["awg_handshake_hedge_offsets"] !=
			"700ms,1100ms,1500ms,1900ms" {
		return errors.New(
			"formal evidence used a diagnostic drop or wrong AWG hedge",
		)
	}
	forced, recorded := environment["force_carrier"]
	if !recorded {
		return errors.New(
			"formal evidence does not record its forced-carrier state",
		)
	}
	if forced != "" {
		return errors.New(
			"formal evidence restricted preparation to one carrier",
		)
	}
	return nil
}

func verifyQdiscEvidence(
	evidenceDirectory string,
	profile networkProfile,
) error {
	for _, side := range []string{"client", "server"} {
		content, err := readSecureRegular(
			filepath.Join(
				evidenceDirectory,
				side+"-post-run-qdisc.json",
			),
			64<<10,
		)
		if err != nil {
			return fmt.Errorf("%s post-run qdisc evidence: %w", side, err)
		}
		decoder := json.NewDecoder(strings.NewReader(string(content)))
		var records []qdiscRecord
		if err := decoder.Decode(&records); err != nil {
			return fmt.Errorf("%s post-run qdisc JSON: %w", side, err)
		}
		if err := requireEOF(decoder); err != nil {
			return fmt.Errorf("%s post-run qdisc JSON: %w", side, err)
		}
		if len(records) == 0 {
			return fmt.Errorf("%s post-run qdisc evidence is empty", side)
		}
		netem := make([]qdiscRecord, 0, 1)
		for _, record := range records {
			if record.Kind == "netem" {
				netem = append(netem, record)
			}
		}
		if profile.ID == "baseline" {
			if len(netem) != 0 {
				return fmt.Errorf(
					"%s baseline unexpectedly has netem", side,
				)
			}
			continue
		}
		if profile.RTTMillis <= 0 ||
			profile.LossFraction <= 0 ||
			profile.LossFraction >= 1 ||
			profile.CapacityMbps <= 0 ||
			len(netem) != 1 ||
			!netem[0].Root ||
			netem[0].Packets == 0 {
			return fmt.Errorf(
				"%s shaped qdisc identity/counters are invalid", side,
			)
		}
		expectedDelay := profile.RTTMillis / 2000
		expectedLoss := 1 - math.Sqrt(1-profile.LossFraction)
		expectedRate := profile.CapacityMbps * 1_000_000 / 8
		if math.Abs(
			netem[0].Options.Delay.Delay-expectedDelay,
		) > 0.000001 ||
			math.Abs(
				netem[0].Options.LossRandom.Loss-expectedLoss,
			) > 0.000001 ||
			math.Abs(
				netem[0].Options.Rate.Rate-expectedRate,
			) > 0.5 {
			return fmt.Errorf(
				"%s shaped qdisc parameters differ from frozen profile",
				side,
			)
		}
	}
	return nil
}

func countSecurityFailures(attempts []measurement.Attempt) int {
	count := 0
	for _, attempt := range attempts {
		switch attempt.Failure {
		case connectivity.FailureManifestInvalid,
			connectivity.FailureCommitFailed,
			connectivity.FailureModePolicyViolation,
			connectivity.FailureTeardownFailed:
			count++
		}
	}
	return count
}

// clusterAwareExceedanceUpper95 tests the contract threshold directly. It
// takes the larger of a finite-sample exact binomial upper bound and a
// cluster-level t upper bound over independently recreated batches.
func clusterAwareExceedanceUpper95(
	batches [][]measurement.Attempt,
	thresholdMillis float64,
	expectedBatchSize int,
	expectedBatches int,
	tCritical float64,
) (float64, int, error) {
	if thresholdMillis <= 0 ||
		expectedBatchSize < 1 ||
		expectedBatches < 2 ||
		len(batches) != expectedBatches ||
		tCritical <= 0 {
		return 0, 0, errors.New(
			"cluster-aware latency gate configuration is invalid",
		)
	}
	proportions := make([]float64, 0, len(batches))
	exceedances := 0
	total := 0
	for _, batch := range batches {
		if len(batch) != expectedBatchSize {
			return 0, 0, fmt.Errorf(
				"cluster batch has %d attempts, want %d",
				len(batch), expectedBatchSize,
			)
		}
		current := 0
		for _, attempt := range batch {
			if float64(attempt.Timeline.OutcomeMicros)/1000 >
				thresholdMillis {
				current++
			}
		}
		exceedances += current
		total += len(batch)
		proportions = append(
			proportions,
			float64(current)/float64(len(batch)),
		)
	}
	mean := float64(exceedances) / float64(total)
	var squared float64
	for _, value := range proportions {
		delta := value - mean
		squared += delta * delta
	}
	sampleVariance := squared / float64(len(proportions)-1)
	clusterUpper := mean +
		tCritical*math.Sqrt(sampleVariance/float64(len(proportions)))
	exactUpper := exactBinomialUpper95(exceedances, total)
	upper := max(clusterUpper, exactUpper)
	if upper > 1 {
		upper = 1
	}
	return upper, exceedances, nil
}

func exactBinomialUpper95(successes int, trials int) float64 {
	if trials < 1 || successes < 0 || successes > trials {
		return math.NaN()
	}
	if successes == trials {
		return 1
	}
	const alpha = 0.05
	lower, upper := float64(0), float64(1)
	for range 100 {
		midpoint := (lower + upper) / 2
		if binomialCDF(successes, trials, midpoint) > alpha {
			lower = midpoint
		} else {
			upper = midpoint
		}
	}
	return upper
}

func binomialCDF(k int, n int, probability float64) float64 {
	if k < 0 {
		return 0
	}
	if k >= n || probability <= 0 {
		return 1
	}
	if probability >= 1 {
		return 0
	}
	logProbability := math.Log(probability)
	logComplement := math.Log1p(-probability)
	logs := make([]float64, k+1)
	maximum := math.Inf(-1)
	lgammaN, _ := math.Lgamma(float64(n + 1))
	for index := 0; index <= k; index++ {
		lgammaK, _ := math.Lgamma(float64(index + 1))
		lgammaRest, _ := math.Lgamma(float64(n - index + 1))
		current := lgammaN - lgammaK - lgammaRest +
			float64(index)*logProbability +
			float64(n-index)*logComplement
		logs[index] = current
		if current > maximum {
			maximum = current
		}
	}
	var scaled float64
	for _, current := range logs {
		scaled += math.Exp(current - maximum)
	}
	return math.Exp(maximum) * scaled
}

func loadProfiles(path string) (profileDocument, string, error) {
	digest, err := sha256File(path)
	if err != nil {
		return profileDocument{}, "", err
	}
	file, err := openSecureRegular(path)
	if err != nil {
		return profileDocument{}, "", err
	}
	defer file.Close()
	bounded := newBoundedReader(file, 1<<20)
	decoder := json.NewDecoder(bounded)
	decoder.DisallowUnknownFields()
	var document profileDocument
	if err := decoder.Decode(&document); err != nil {
		return profileDocument{}, "", bounded.classify(
			err, "the impairment profile document",
		)
	}
	// The bound before requireEOF's verdict. An oversized file is cut mid-value,
	// so requireEOF reports "unexpected EOF" for a document whose real defect is
	// that the decoder only saw part of the file — and a cut landing exactly
	// after a complete value would satisfy requireEOF outright, hiding whatever
	// followed.
	if err := requireEOF(decoder); err != nil {
		return profileDocument{}, "", bounded.classify(
			err, "the impairment profile document",
		)
	}
	if err := bounded.check("the impairment profile document"); err != nil {
		return profileDocument{}, "", err
	}
	if (document.Schema != profileSchemaV1 &&
		document.Schema != profileSchemaV2) ||
		document.ProtocolVersion != connectivity.Version ||
		document.AttemptsPerReadinessPerProfile < 1 ||
		len(document.Profiles) == 0 ||
		len(document.ReadinessClasses) == 0 {
		return profileDocument{}, "",
			errors.New("frozen profile document is invalid")
	}
	if document.ScoreGate.P50MillisMax <= 0 ||
		document.ScoreGate.P95MillisMax <= 0 ||
		document.ScoreGate.P99MillisMax <= 0 ||
		document.ScoreGate.IndividualAttemptMillisMax <= 0 {
		return profileDocument{}, "",
			errors.New("frozen score thresholds are invalid")
	}
	switch document.Schema {
	case profileSchemaV1:
		if document.ScoreGate.Failures == nil ||
			document.BatchSize != 0 ||
			document.ScheduleSeed != "" ||
			document.ScheduleSeedProvenance != "" ||
			len(document.FailureTaxonomy.Availability) != 0 ||
			len(document.FailureTaxonomy.Security) != 0 {
			return profileDocument{}, "",
				errors.New("legacy frozen score gate is invalid")
		}
	case profileSchemaV2:
		gate := document.ScoreGate
		if document.BatchSize < 1 ||
			document.AttemptsPerReadinessPerProfile%document.BatchSize != 0 ||
			!lowerHex(document.ScheduleSeed, sha256.Size*2) ||
			document.ScheduleSeedProvenance == "" ||
			!validFailureTaxonomy(document.FailureTaxonomy) ||
			gate.Failures != nil ||
			gate.AvailabilityFailuresMax == nil ||
			gate.SecurityFailuresMax == nil ||
			*gate.AvailabilityFailuresMax < 0 ||
			*gate.SecurityFailuresMax < 0 ||
			gate.LatencyThresholdMillis <= 0 ||
			gate.LatencyExceedanceUpper95Max <= 0 ||
			gate.LatencyExceedanceUpper95Max >= 1 ||
			gate.ClusterBatchSize != document.BatchSize ||
			gate.ClusterBatchesPerCell !=
				document.AttemptsPerReadinessPerProfile/document.BatchSize ||
			gate.ClusterTCritical95 <= 0 ||
			gate.StagingDesignTargetMillis <= 0 ||
			gate.StagingDesignTargetMillis >=
				gate.LatencyThresholdMillis {
			return profileDocument{}, "",
				errors.New("cluster-aware frozen score gate is invalid")
		}
	}
	return document, digest, nil
}

func validFailureTaxonomy(taxonomy failureTaxonomy) bool {
	expectedSecurity := []connectivity.FailureCode{
		connectivity.FailureManifestInvalid,
		connectivity.FailureCommitFailed,
		connectivity.FailureModePolicyViolation,
		connectivity.FailureTeardownFailed,
	}
	expectedAvailability := []connectivity.FailureCode{
		connectivity.FailureConnectDeadlineExceeded,
		connectivity.FailureNotReady,
		connectivity.FailureCredentialsExhausted,
		connectivity.FailureNoReachableCandidate,
		connectivity.FailureHandshakeFailed,
		connectivity.FailureBidirectionalFailed,
		connectivity.FailureDNSVerificationFailed,
		connectivity.FailureCanaryFailed,
		connectivity.FailureConnectInProgress,
		connectivity.FailureNetworkChanged,
		connectivity.FailurePostCommitHealth,
		connectivity.FailureStoppedByUser,
	}
	return slices.Equal(taxonomy.Security, expectedSecurity) &&
		slices.Equal(taxonomy.Availability, expectedAvailability)
}

func loadBatches(root string) ([]matrixBatch, error) {
	pattern := filepath.Join(root, "batches", "*.done")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("matrix has no completed batches")
	}
	slices.Sort(paths)
	batches := make([]matrixBatch, 0, len(paths))
	for _, path := range paths {
		values, err := parseKeyValueFile(path)
		if err != nil {
			return nil, err
		}
		count, err := strconv.Atoi(values["attempts"])
		if err != nil || count < 1 || count > 4000 {
			return nil, fmt.Errorf(
				"batch %s attempt count is invalid", path,
			)
		}
		readiness := measurement.ReadinessClass(values["readiness"])
		if values["batch_key"] == "" ||
			values["profile"] == "" ||
			(readiness != measurement.ReadinessWarm &&
				readiness != measurement.ReadinessCold) ||
			!lowerHex(values["archive_sha256"], sha256.Size*2) {
			return nil, fmt.Errorf(
				"batch %s metadata is invalid", path,
			)
		}
		block := 0
		if values["randomized_block"] != "" {
			block, err = strconv.Atoi(values["randomized_block"])
			if err != nil || block < 1 {
				return nil, fmt.Errorf(
					"batch %s randomized block is invalid", path,
				)
			}
		}
		if relative := values["archive_relative"]; relative != "" {
			if _, err := evidenceRelativeArchiveName(relative); err != nil {
				return nil, fmt.Errorf(
					"batch %s relative archive path is invalid: %w", path, err,
				)
			}
		}
		if relative := values["evidence_relative"]; relative != "" {
			if _, err := evidenceRelativeDirectoryName(relative); err != nil {
				return nil, fmt.Errorf(
					"batch %s relative evidence path is invalid: %w", path, err,
				)
			}
		}
		batches = append(batches, matrixBatch{
			schema:           values["schema"],
			key:              values["batch_key"],
			block:            block,
			orderDigest:      values["order_digest"],
			profile:          values["profile"],
			readiness:        readiness,
			attempts:         count,
			archive:          values["archive"],
			archiveRelative:  values["archive_relative"],
			evidenceRelative: values["evidence_relative"],
			digest:           values["archive_sha256"],
			inventory:        values["execution_inventory_sha256"],
			anchorMode:       values["anchor_mode"],
			requestHash:      values["anchor_request_sha256"],
			receiptOne:       values["anchor_provider_one_receipt_sha256"],
			receiptTwo:       values["anchor_provider_two_receipt_sha256"],
		})
	}
	return batches, nil
}

func verifyExecutionInventory(
	root string,
	matrixEnvironment map[string]string,
	complete map[string]string,
) error {
	expected := matrixEnvironment["execution_inventory_sha256"]
	if !lowerHex(expected, sha256.Size*2) ||
		complete["execution_inventory_sha256"] != expected {
		return errors.New(
			"matrix completion is not bound to an execution inventory",
		)
	}
	actual, err := sha256File(
		filepath.Join(root, "execution-inventory.sha256"),
	)
	if err != nil {
		return fmt.Errorf("execution inventory: %w", err)
	}
	if actual != expected {
		return errors.New("matrix execution inventory digest mismatch")
	}
	return nil
}

func verifyV2Schedule(
	root string,
	profiles profileDocument,
	matrixEnvironment map[string]string,
	complete map[string]string,
	batches []matrixBatch,
) error {
	// v2 and v3 differ in exactly one respect: a v3 batch record carries its
	// archive path relative to the matrix root, while a v2 batch record
	// carries only the absolute path of the sealing machine and the name is
	// derived from authenticated identity instead. The three schema strings
	// move together, so a root cannot present a v3 batch under a v2 matrix.
	var batchSchema, completeSchema string
	switch matrixEnvironment["schema"] {
	case matrixSchemaV2:
		batchSchema, completeSchema = batchSchemaV2, completeSchemaV2
	case matrixSchemaV3:
		batchSchema, completeSchema = batchSchemaV3, completeSchemaV3
	default:
		return errors.New("matrix environment has an unsupported schema")
	}
	if matrixEnvironment["protocol_version"] != connectivity.Version ||
		!safeMatrixIdentifier.MatchString(matrixEnvironment["matrix_id"]) ||
		complete["schema"] != completeSchema ||
		complete["matrix_id"] != matrixEnvironment["matrix_id"] ||
		complete["schedule_sha256"] !=
			matrixEnvironment["schedule_sha256"] {
		return errors.New(
			"matrix completion is not bound to the frozen environment",
		)
	}
	if _, err := os.Lstat(filepath.Join(root, "INVALID")); err == nil {
		return errors.New("matrix has an immutable invalidation marker")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect matrix invalidation marker: %w", err)
	}
	exclusionDirectory := filepath.Join(root, "exclusions")
	exclusionInfo, err := os.Lstat(exclusionDirectory)
	if err != nil || !exclusionInfo.IsDir() ||
		exclusionInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("matrix exclusion ledger is absent or unsafe")
	}
	exclusions, err := filepath.Glob(
		filepath.Join(exclusionDirectory, "*.abort"),
	)
	if err != nil {
		return err
	}
	if len(exclusions) != 0 {
		return fmt.Errorf(
			"matrix contains %d excluded batch aborts", len(exclusions),
		)
	}
	schedulePath := filepath.Join(root, "schedule.tsv")
	actualDigest, err := sha256File(schedulePath)
	if err != nil {
		return fmt.Errorf("randomized schedule: %w", err)
	}
	if actualDigest != matrixEnvironment["schedule_sha256"] {
		return errors.New("randomized schedule digest mismatch")
	}
	schedule, err := loadV2Schedule(schedulePath, profiles)
	if err != nil {
		return err
	}
	if len(batches) != len(schedule) {
		return fmt.Errorf(
			"matrix has %d completed batches, schedule requires %d",
			len(batches), len(schedule),
		)
	}
	scheduledByKey := make(map[string]scheduledBatch, len(schedule))
	for _, expected := range schedule {
		scheduledByKey[expected.key] = expected
	}
	seen := make(map[string]struct{}, len(batches))
	for _, batch := range batches {
		expected, ok := scheduledByKey[batch.key]
		if !ok {
			return fmt.Errorf(
				"completed batch %s is absent from the frozen schedule",
				batch.key,
			)
		}
		if _, duplicate := seen[batch.key]; duplicate {
			return fmt.Errorf("completed batch %s is duplicated", batch.key)
		}
		seen[batch.key] = struct{}{}
		if batch.schema != batchSchema ||
			batch.block != expected.block ||
			batch.orderDigest != expected.orderDigest ||
			batch.profile != expected.profile ||
			batch.readiness != expected.readiness ||
			batch.attempts != expected.attempts {
			return fmt.Errorf(
				"completed batch %s differs from its frozen schedule row",
				batch.key,
			)
		}
		if (batch.schema == batchSchemaV3) !=
			(batch.archiveRelative != "") {
			return fmt.Errorf(
				"completed batch %s does not carry the archive path its "+
					"schema requires",
				batch.key,
			)
		}
	}
	return nil
}

func loadV2Schedule(
	path string,
	profiles profileDocument,
) ([]scheduledBatch, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	expectedBlocks := profiles.AttemptsPerReadinessPerProfile /
		profiles.BatchSize
	expectedCells := len(profiles.Profiles) *
		len(profiles.ReadinessClasses)
	if expectedBlocks < 1 || expectedCells < 1 {
		return nil, errors.New("frozen schedule dimensions are invalid")
	}
	profileIDs := make(map[string]struct{}, len(profiles.Profiles))
	for _, profile := range profiles.Profiles {
		profileIDs[profile.ID] = struct{}{}
	}
	readinessClasses := make(
		map[measurement.ReadinessClass]struct{},
		len(profiles.ReadinessClasses),
	)
	for _, value := range profiles.ReadinessClasses {
		readinessClasses[measurement.ReadinessClass(value)] = struct{}{}
	}
	schedule := make(
		[]scheduledBatch,
		0,
		expectedBlocks*expectedCells,
	)
	keys := make(map[string]struct{}, cap(schedule))
	blockCells := make(map[int]map[string]struct{}, expectedBlocks)
	previousDigestByBlock := make(map[int]string, expectedBlocks)
	bounded := newBoundedReader(file, 4<<20)
	scanner := bufio.NewScanner(bounded)
	lineNumber := 0
	lastBlock := 0
	for scanner.Scan() {
		lineNumber++
		// The bound, before any row is interpreted. An oversized file is cut
		// mid-row, so the row parser would otherwise report a malformed line
		// for a file whose real defect is that it is too large — and a cut that
		// happened to land on a row boundary would parse cleanly and the
		// oversize would go unreported entirely.
		if bounded.exceeded() {
			return nil, bounded.check("the frozen schedule")
		}
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 6 {
			return nil, fmt.Errorf(
				"randomized schedule line %d is invalid", lineNumber,
			)
		}
		block, blockErr := strconv.Atoi(fields[0])
		attempts, attemptsErr := strconv.Atoi(fields[5])
		readiness := measurement.ReadinessClass(fields[4])
		if blockErr != nil || block < 1 || block > expectedBlocks ||
			attemptsErr != nil || attempts != profiles.BatchSize ||
			!lowerHex(fields[1], sha256.Size*2) ||
			fields[2] == "" {
			return nil, fmt.Errorf(
				"randomized schedule line %d has invalid fields",
				lineNumber,
			)
		}
		if (lastBlock == 0 && block != 1) ||
			(lastBlock != 0 &&
				block != lastBlock &&
				block != lastBlock+1) {
			return nil, fmt.Errorf(
				"randomized schedule line %d is out of block order",
				lineNumber,
			)
		}
		lastBlock = block
		if _, ok := profileIDs[fields[3]]; !ok {
			return nil, fmt.Errorf(
				"randomized schedule line %d has unknown profile",
				lineNumber,
			)
		}
		if _, ok := readinessClasses[readiness]; !ok {
			return nil, fmt.Errorf(
				"randomized schedule line %d has unknown readiness",
				lineNumber,
			)
		}
		expectedDigest := sha256.Sum256([]byte(fmt.Sprintf(
			"%s:%d:%s:%s",
			profiles.ScheduleSeed,
			block,
			fields[3],
			readiness,
		)))
		if fields[1] != hex.EncodeToString(expectedDigest[:]) {
			return nil, fmt.Errorf(
				"randomized schedule line %d has the wrong order digest",
				lineNumber,
			)
		}
		expectedKey := fmt.Sprintf(
			"%s--%s--b%03d", fields[3], readiness, block,
		)
		if fields[2] != expectedKey {
			return nil, fmt.Errorf(
				"randomized schedule line %d has the wrong batch key",
				lineNumber,
			)
		}
		if previous := previousDigestByBlock[block]; previous != "" &&
			fields[1] <= previous {
			return nil, fmt.Errorf(
				"randomized schedule block %d is not digest ordered",
				block,
			)
		}
		previousDigestByBlock[block] = fields[1]
		if _, duplicate := keys[fields[2]]; duplicate {
			return nil, fmt.Errorf(
				"randomized schedule batch %s is duplicated", fields[2],
			)
		}
		keys[fields[2]] = struct{}{}
		cell := cellID(fields[3], readiness)
		if blockCells[block] == nil {
			blockCells[block] = make(map[string]struct{}, expectedCells)
		}
		if _, duplicate := blockCells[block][cell]; duplicate {
			return nil, fmt.Errorf(
				"randomized schedule block %d duplicates cell %s",
				block,
				cell,
			)
		}
		blockCells[block][cell] = struct{}{}
		schedule = append(schedule, scheduledBatch{
			key:         fields[2],
			block:       block,
			orderDigest: fields[1],
			profile:     fields[3],
			readiness:   readiness,
			attempts:    attempts,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := bounded.check("the frozen schedule"); err != nil {
		return nil, err
	}
	if len(schedule) != expectedBlocks*expectedCells {
		return nil, fmt.Errorf(
			"randomized schedule has %d rows, want %d",
			len(schedule),
			expectedBlocks*expectedCells,
		)
	}
	for block := 1; block <= expectedBlocks; block++ {
		if len(blockCells[block]) != expectedCells {
			return nil, fmt.Errorf(
				"randomized schedule block %d has %d cells, want %d",
				block,
				len(blockCells[block]),
				expectedCells,
			)
		}
	}
	return schedule, nil
}

func parseKeyValueFile(path string) (map[string]string, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	values := make(map[string]string)
	bounded := newBoundedReader(file, 64<<10)
	scanner := bufio.NewScanner(bounded)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return nil, bounded.classify(
				fmt.Errorf("invalid key/value line in %s", path), path,
			)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, bounded.classify(
				fmt.Errorf("duplicate key %q in %s", key, path), path,
			)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := bounded.check(path); err != nil {
		return nil, err
	}
	return values, nil
}

// sha256ManifestLineSet turns a `sha256sum`-style manifest into a set of whole
// lines, for a set-membership comparison between the frozen execution inventory
// and a batch's own binary inventory.
//
// Every recorded name here is an OPAQUE PROTOCOL STRING. The lab that produced
// the evidence recorded Linux pathnames such as /opt/winn-lab/bin/…; nothing in
// this verifier ever opens one, and the whole line — digest and name together —
// is the map key, so the only operation performed on it is byte equality.
//
// It is therefore validated with `path`, not `filepath`. filepath.IsAbs is
// host-dependent: on Windows it requires a drive letter or UNC prefix, so it
// reports FALSE for "/opt/winn-lab/bin/winn-auto-e2e" and a Windows auditor
// would have rejected every honest inventory line in the corpus. path.IsAbs
// answers the question actually being asked — is this recorded protocol path
// rooted — identically on every platform.
func sha256ManifestLineSet(content []byte) (map[string]struct{}, error) {
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return nil, errors.New("SHA-256 manifest is empty")
	}
	result := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		digest, recorded, ok := strings.Cut(line, "  ")
		if !ok || !lowerHex(digest, sha256.Size*2) ||
			recorded == "" || !path.IsAbs(recorded) {
			return nil, errors.New("SHA-256 manifest line is invalid")
		}
		if _, duplicate := result[line]; duplicate {
			return nil, errors.New("SHA-256 manifest line is duplicated")
		}
		result[line] = struct{}{}
	}
	return result, nil
}

func verifyEvidenceManifest(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("evidence directory must be a real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.Open("evidence-manifest.sha256")
	if err != nil {
		return err
	}
	defer file.Close()
	bounded := newBoundedReader(file, 4<<20)
	scanner := bufio.NewScanner(bounded)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < sha256.Size*2+3 ||
			line[sha256.Size*2:sha256.Size*2+2] != "  " {
			return bounded.classify(
				errors.New("evidence manifest line is invalid"),
				"the evidence manifest",
			)
		}
		want := line[:sha256.Size*2]
		relative := strings.TrimPrefix(
			line[sha256.Size*2+2:], "./",
		)
		// A recorded manifest name is a slash-separated PROTOCOL path, so its
		// canonicality is decided with `path`. filepath.Clean is the host's
		// cleaner: on Windows filepath.Clean("diagnostics/client.json") returns
		// "diagnostics\\client.json", which never equals the recorded value — so
		// a filepath-based check rejected every legitimately NESTED manifest
		// entry on that platform while accepting the same evidence everywhere
		// else. Only the flat, single-component entries survived there, which is
		// why the defect was invisible in the flat fixtures.
		//
		// A backslash is not a separator in this protocol; it is an illegal
		// character, refused identically on every platform rather than silently
		// reinterpreted as a directory separator on Windows.
		if !lowerHex(want, sha256.Size*2) ||
			relative == "" || path.IsAbs(relative) ||
			strings.HasPrefix(relative, "/") ||
			path.Clean(relative) != relative ||
			strings.ContainsAny(relative, "\\\x00") ||
			strings.HasPrefix(relative, "..") {
			return errors.New("evidence manifest path is invalid")
		}
		// The OS filesystem boundary, and the only place a native separator is
		// correct. os.Root accepts "/" everywhere, but converting here keeps the
		// two concerns visibly separate: everything above this line reasons about
		// a protocol string, everything below it opens a file.
		local := filepath.FromSlash(relative)
		info, err := root.Lstat(local)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf(
				"evidence manifest target %s is invalid", relative,
			)
		}
		got, err := sha256RootFile(root, local)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf(
				"evidence manifest target %s changed", relative,
			)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := bounded.check("the evidence manifest"); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("evidence manifest is empty")
	}
	return nil
}

// resolveBatchArchive locates one batch archive inside the matrix root the
// auditor actually supplied, and returns that absolute path together with the
// SHA-256 read through the very handle that was opened.
//
// A sealed root is handed to an auditor as a byte-exact copy, so the absolute
// path a v2 .done record carries names a directory that exists only on the
// machine that produced it. That recorded path is therefore never opened. The
// file that is opened is always <root>/evidence/<name>, where <name> is either
// derived from the matrix and batch identity that the signed anchor request
// commits to (legacy v2) or read from the schema-v3 archive_relative field.
// Nothing returned here is trusted on its own: the caller still has to match
// the digest against the .done record and, under anchoring, against the signed
// request. This function changes only where a file is found, never whether its
// contents are believed.
func resolveBatchArchive(
	root string,
	matrixID string,
	batch matrixBatch,
) (string, string, error) {
	name, err := batchArchiveName(matrixID, batch)
	if err != nil {
		return "", "", err
	}
	evidence := filepath.Join(root, evidenceDirectoryName)
	info, err := os.Lstat(evidence)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New(
			"matrix evidence directory is absent or not a real directory",
		)
	}
	// Everything below this point comes out of the copied tree, so it is
	// reached only through a root handle: os.Root refuses any symbolic link
	// that would leave the evidence directory, and the Lstat below refuses a
	// symbolic link planted at the archive name itself even when its target
	// stays inside.
	evidenceRoot, err := os.OpenRoot(evidence)
	if err != nil {
		return "", "", err
	}
	defer evidenceRoot.Close()
	linkInfo, err := evidenceRoot.Lstat(name)
	if err != nil || !linkInfo.Mode().IsRegular() {
		return "", "", errors.New("batch archive is absent or not a regular file")
	}
	digest, err := sha256RootFile(evidenceRoot, name)
	if err != nil {
		return "", "", err
	}
	return filepath.Join(evidence, name), digest, nil
}

// batchArchiveName returns the archive filename, relative to the matrix
// evidence directory, for one batch.
func batchArchiveName(matrixID string, batch matrixBatch) (string, error) {
	if batch.archiveRelative != "" {
		return evidenceRelativeArchiveName(batch.archiveRelative)
	}
	// Legacy v2 roots record only an absolute archive path. The sealer builds
	// it as $MATRIX_ROOT/evidence/auto-e2e-$MATRIX_ID-$batch_key.tar.gz
	// (scripts/aicore_phase1_auto_matrix.sh:656-657,739,874), so the filename
	// is a pure function of the matrix and batch identity and needs no path
	// text from the copied tree.
	name, err := derivedArchiveName(matrixID, batch.key)
	if err != nil {
		return "", err
	}
	// The recorded absolute path still has to agree with the derived name.
	// This is a consistency check on sealed bytes, not a source of the open
	// target: the prefix in front of /evidence/ is discarded either way.
	suffix := "/" + evidenceDirectoryName + "/" + name
	if !strings.HasPrefix(batch.archive, "/") ||
		!strings.HasSuffix(batch.archive, suffix) {
		return "", errors.New(
			"sealed archive record does not name the derived evidence file",
		)
	}
	return name, nil
}

// derivedArchiveName rebuilds the sealer's archive filename from authenticated
// matrix and batch identity.
func derivedArchiveName(matrixID, batchKey string) (string, error) {
	if !safeMatrixIdentifier.MatchString(matrixID) ||
		!safeMatrixIdentifier.MatchString(batchKey) {
		return "", errors.New(
			"matrix or batch identity cannot name an archive file",
		)
	}
	return validArchiveFileName(
		archiveNamePrefix + matrixID + "-" + batchKey + archiveSuffix,
	)
}

// resolveEvidenceDirectory returns the evidence directory for one batch.
//
// It prefers the record's explicit evidence_relative mapping and falls back to
// the historical suffix trim only for records that predate the field. The
// fallback is deliberately narrow: it applies when the archive name is exactly
// the directory name plus ".tar.gz", which is the only shape it was ever
// correct for.
func resolveEvidenceDirectory(
	root string,
	batch matrixBatch,
	archive string,
) (string, error) {
	if batch.evidenceRelative != "" {
		name, err := evidenceRelativeDirectoryName(batch.evidenceRelative)
		if err != nil {
			return "", err
		}
		return filepath.Join(root, evidenceDirectoryName, name), nil
	}
	trimmed := strings.TrimSuffix(archive, archiveSuffix)
	if trimmed == archive {
		return "", errors.New(
			"batch record carries no evidence_relative mapping and its archive " +
				"name cannot be resolved to an evidence directory",
		)
	}
	return trimmed, nil
}

// evidenceRelativeDirectoryName validates an evidence_relative value and
// returns the bare directory name it names inside the evidence directory.
func evidenceRelativeDirectoryName(recorded string) (string, error) {
	directory, name, ok := strings.Cut(recorded, "/")
	if !ok || directory != evidenceDirectoryName {
		return "", errors.New(
			"recorded evidence path is not inside the matrix evidence directory",
		)
	}
	// `path`, not `filepath`: `recorded` is a slash-separated protocol value.
	// filepath.Base and filepath.Clean carry Windows volume semantics — Base
	// strips a "C:" prefix there and not here — so a filepath-based check
	// accepts and rejects different names depending on the auditor's platform.
	if name == "" || path.Base(name) != name ||
		path.Clean(name) != name ||
		strings.ContainsAny(name, `/\`) ||
		strings.ContainsRune(name, 0) {
		return "", errors.New("evidence directory name is not a plain name")
	}
	return name, nil
}

// evidenceRelativeArchiveName validates a schema-v3 archive_relative value and
// returns the bare filename it names inside the evidence directory.
func evidenceRelativeArchiveName(recorded string) (string, error) {
	directory, name, ok := strings.Cut(recorded, "/")
	if !ok || directory != evidenceDirectoryName {
		return "", errors.New(
			"recorded archive path is not inside the matrix evidence directory",
		)
	}
	return validArchiveFileName(name)
}

// validArchiveFileName rejects anything that is not a single, self-contained
// archive filename. A value that survives this contains no separator at all,
// so it cannot address any directory other than the one it is opened against.
func validArchiveFileName(name string) (string, error) {
	stem := strings.TrimSuffix(name, archiveSuffix)
	// `path`, not `filepath`, for the reason given on
	// evidenceRelativeDirectoryName: this is a recorded protocol value and the
	// accepted set must not vary by the auditor's operating system.
	if name == "" || stem == name || stem == "" ||
		path.IsAbs(name) || strings.HasPrefix(name, "/") ||
		path.Base(name) != name || path.Clean(name) != name ||
		strings.ContainsAny(name, `/\`) ||
		strings.ContainsRune(name, 0) {
		return "", errors.New("batch archive name is not a plain file name")
	}
	return name, nil
}

func sha256File(path string) (string, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return sha256Reader(file)
}

func sha256RootFile(root *os.Root, name string) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		if err != nil {
			return "", err
		}
		return "", errors.New("hash target is not a regular file")
	}
	return sha256Reader(file)
}

func sha256Reader(reader io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readSecureRegular(path string, maximum int64) ([]byte, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := io.LimitReader(file, maximum+1)
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, errors.New("file exceeds size limit")
	}
	return content, nil
}

// openSecureRegular resolves a caller-selected file to its canonical location,
// then opens the basename relative to an already-open directory root. That
// removes ambient path traversal from verifier reads and gives the final file
// a regular-file type check before it is trusted as evidence.
func openSecureRegular(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	absolute = resolved
	parent := filepath.Dir(absolute)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("file parent must be a real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	file, openErr := root.Open(filepath.Base(absolute))
	closeErr := root.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("file is not regular")
	}
	return file, nil
}

func rttMatches(measured, declared float64) bool {
	if declared == 0 {
		return measured >= 0 && measured <= 5
	}
	return measured >= declared*0.80 && measured <= declared*1.20
}

func sameFloat(first, second float64) bool {
	return !math.IsNaN(first) && !math.IsNaN(second) &&
		math.Abs(first-second) <= 1e-12
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && value == hex.EncodeToString(decoded)
}

func durationMillis(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func cellID(
	profile string,
	readiness measurement.ReadinessClass,
) string {
	return profile + "/" + string(readiness)
}

func onlyKey(values map[string]struct{}) string {
	for value := range values {
		return value
	}
	return ""
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
