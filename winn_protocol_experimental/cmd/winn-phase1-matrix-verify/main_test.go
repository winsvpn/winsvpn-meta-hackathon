package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/measurement"
)

func TestRTTMatchesFrozenTolerance(t *testing.T) {
	for _, test := range []struct {
		measured float64
		declared float64
		want     bool
	}{
		{0.05, 0, true},
		{6, 0, false},
		{24, 30, true},
		{36, 30, true},
		{23.99, 30, false},
		{300, 250, true},
		{300.01, 250, false},
	} {
		if got := rttMatches(test.measured, test.declared); got != test.want {
			t.Fatalf(
				"rttMatches(%v,%v)=%v, want %v",
				test.measured, test.declared, got, test.want,
			)
		}
	}
}

func TestVerificationProfileSeparatesFormalAndStagingModes(t *testing.T) {
	availabilityMax := 4
	securityMax := 0
	document := profileDocument{
		Schema:                         profileSchemaV2,
		AttemptsPerReadinessPerProfile: 10000,
		BatchSize:                      100,
		ScheduleSeed:                   strings.Repeat("a", sha256.Size*2),
		ReadinessClasses:               []string{"warm", "cold"},
		Profiles: []networkProfile{
			{ID: "baseline"},
			{
				ID:           stagingEdgeProfileID,
				RTTMillis:    250,
				LossFraction: 0.03,
				CapacityMbps: 10,
			},
		},
		ScoreGate: scoreGate{
			AvailabilityFailuresMax: &availabilityMax,
			SecurityFailuresMax:     &securityMax,
			ClusterBatchSize:        100,
			ClusterBatchesPerCell:   100,
			ClusterTCritical95:      1.660391,
		},
	}
	baseEnvironment := map[string]string{
		"schedule_sha256": strings.Repeat("b", sha256.Size*2),
		"schedule_seed":   document.ScheduleSeed,
		"batch_size":      "100",
	}
	formal := mapsClone(baseEnvironment)
	formal["partial"] = "0"
	formal["attempts_per_readiness_per_profile"] = "10000"
	formal["profile_filter"] = ""
	got, err := verificationProfile(document, formal, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Profiles) != 2 ||
		got.AttemptsPerReadinessPerProfile != 10000 {
		t.Fatalf("formal profile was narrowed: %#v", got)
	}

	staging := mapsClone(baseEnvironment)
	staging["partial"] = "1"
	staging["attempts_per_readiness_per_profile"] = "1000"
	staging["profile_filter"] = stagingEdgeProfileID
	got, err = verificationProfile(document, staging, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Profiles) != 1 ||
		got.Profiles[0].ID != stagingEdgeProfileID ||
		got.AttemptsPerReadinessPerProfile != stagingAttempts ||
		got.ScoreGate.ClusterBatchesPerCell != stagingBatches ||
		got.ScoreGate.ClusterTCritical95 != stagingTCritical95 ||
		got.ScoreGate.AvailabilityFailuresMax == nil ||
		*got.ScoreGate.AvailabilityFailuresMax != 0 {
		t.Fatalf("staging profile is not the exact conservative screen: %#v", got)
	}
	if _, err := verificationProfile(document, staging, false); err == nil {
		t.Fatal("formal verification accepted a partial staging matrix")
	}
	staging["attempts_per_readiness_per_profile"] = "999"
	if _, err := verificationProfile(document, staging, true); err == nil {
		t.Fatal("staging verification accepted the wrong attempt count")
	}
}

func mapsClone(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestVerifyEvidenceManifestDetectsMutation(t *testing.T) {
	directory := t.TempDir()
	content := []byte("immutable evidence\n")
	target := filepath.Join(directory, "record.txt")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	manifest := hex.EncodeToString(digest[:]) + "  ./record.txt\n"
	if err := os.WriteFile(
		filepath.Join(directory, "evidence-manifest.sha256"),
		[]byte(manifest),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceManifest(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceManifest(directory); err == nil ||
		!strings.Contains(err.Error(), "changed") {
		t.Fatalf("mutated evidence error = %v", err)
	}
}

func TestParseKeyValueFileRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values")
	if err := os.WriteFile(
		path, []byte("source=one\nsource=two\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyValueFile(path); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key error = %v", err)
	}
}

func TestVerifyExecutionInventoryBindsRootAndCompletion(t *testing.T) {
	root := t.TempDir()
	content := []byte(
		strings.Repeat("a", sha256.Size*2) +
			"  /opt/winn-lab/bin/winn-auto-e2e\n",
	)
	path := filepath.Join(root, "execution-inventory.sha256")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	pinned := hex.EncodeToString(digest[:])
	environment := map[string]string{
		"execution_inventory_sha256": pinned,
	}
	complete := map[string]string{
		"execution_inventory_sha256": pinned,
	}
	if err := verifyExecutionInventory(
		root, environment, complete,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path, append(content, []byte("tampered\n")...), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutionInventory(
		root, environment, complete,
	); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered inventory error = %v", err)
	}
}

func TestSHA256ManifestLineSetRejectsMalformedAndDuplicateLines(
	t *testing.T,
) {
	line := strings.Repeat("a", sha256.Size*2) + "  /opt/winn/bin\n"
	set, err := sha256ManifestLineSet([]byte(line))
	if err != nil || len(set) != 1 {
		t.Fatalf("valid manifest set=%v error=%v", set, err)
	}
	if _, err := sha256ManifestLineSet(
		[]byte(line + line),
	); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate manifest error=%v", err)
	}
	if _, err := sha256ManifestLineSet(
		[]byte(strings.Repeat("b", 64) + "  relative\n"),
	); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("relative manifest error=%v", err)
	}
}

func TestLoadFrozenProfileDocument(t *testing.T) {
	document, digest, err := loadProfiles(
		"../../config/phase1_auto_impairment_profiles_v1.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if document.ProtocolVersion != "winn/3" ||
		document.AttemptsPerReadinessPerProfile != 10000 ||
		len(document.Profiles) != 4 ||
		!lowerHex(digest, 64) {
		t.Fatalf(
			"loaded profile document=%#v digest=%q",
			document, digest,
		)
	}
}

func TestLoadClusterAwareFrozenProfileDocument(t *testing.T) {
	document, digest, err := loadProfiles(
		"../../config/phase1_auto_impairment_profiles_v2.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if document.Schema != profileSchemaV2 ||
		document.ProtocolVersion != "winn/3" ||
		document.AttemptsPerReadinessPerProfile != 10000 ||
		document.BatchSize != 100 ||
		document.ScoreGate.ClusterBatchesPerCell != 100 ||
		!lowerHex(document.ScheduleSeed, 64) ||
		!lowerHex(digest, 64) {
		t.Fatalf(
			"loaded cluster document=%#v digest=%q",
			document, digest,
		)
	}
}

func TestExactBinomialThresholdGateMatchesFrozenStagingRank(
	t *testing.T,
) {
	if upper := exactBinomialUpper95(38, 1000); upper > 0.05 {
		t.Fatalf("k=38 upper95 = %.9f, want <= 0.05", upper)
	}
	if upper := exactBinomialUpper95(39, 1000); upper <= 0.05 {
		t.Fatalf("k=39 upper95 = %.9f, want > 0.05", upper)
	}
}

func TestClusterAwareGatePenalizesConcentratedExceedances(t *testing.T) {
	makeBatches := func(concentrated bool) [][]measurement.Attempt {
		batches := make([][]measurement.Attempt, 100)
		for batch := range batches {
			batches[batch] = make([]measurement.Attempt, 100)
		}
		if concentrated {
			for batch := 0; batch < 4; batch++ {
				for attempt := 0; attempt < 10; attempt++ {
					batches[batch][attempt].Timeline.OutcomeMicros = 1_500_001
				}
			}
		} else {
			for batch := 0; batch < 40; batch++ {
				batches[batch][0].Timeline.OutcomeMicros = 1_500_001
			}
		}
		return batches
	}
	spread, spreadCount, err := clusterAwareExceedanceUpper95(
		makeBatches(false), 1500, 100, 100, 1.660391,
	)
	if err != nil {
		t.Fatal(err)
	}
	concentrated, concentratedCount, err := clusterAwareExceedanceUpper95(
		makeBatches(true), 1500, 100, 100, 1.660391,
	)
	if err != nil {
		t.Fatal(err)
	}
	if spreadCount != 40 || concentratedCount != 40 ||
		concentrated <= spread {
		t.Fatalf(
			"spread=%.6f/%d concentrated=%.6f/%d",
			spread, spreadCount, concentrated, concentratedCount,
		)
	}
}

func TestSecurityFailureClassificationIsFailClosed(t *testing.T) {
	attempts := []measurement.Attempt{
		{Failure: connectivity.FailureManifestInvalid},
		{Failure: connectivity.FailureCommitFailed},
		{Failure: connectivity.FailureModePolicyViolation},
		{Failure: connectivity.FailureTeardownFailed},
		{Failure: connectivity.FailureHandshakeFailed},
		{Failure: connectivity.FailureConnectDeadlineExceeded},
	}
	if got := countSecurityFailures(attempts); got != 4 {
		t.Fatalf("security failure count=%d, want 4", got)
	}
}

func TestV2ScheduleBindsEveryRandomizedBatch(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(
		filepath.Join(root, "exclusions"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	document := profileDocument{
		Schema:                         profileSchemaV2,
		ProtocolVersion:                connectivity.Version,
		AttemptsPerReadinessPerProfile: 2,
		BatchSize:                      1,
		ScheduleSeed: strings.Repeat(
			"1", sha256.Size*2,
		),
		ReadinessClasses: []string{
			string(measurement.ReadinessWarm),
			string(measurement.ReadinessCold),
		},
		Profiles: []networkProfile{
			{ID: "baseline"},
			{ID: "edge"},
		},
	}
	var rows []string
	for block := 1; block <= 2; block++ {
		var blockRows []string
		for _, profile := range document.Profiles {
			for _, readiness := range document.ReadinessClasses {
				digest := sha256.Sum256([]byte(fmt.Sprintf(
					"%s:%d:%s:%s",
					document.ScheduleSeed,
					block,
					profile.ID,
					readiness,
				)))
				orderDigest := hex.EncodeToString(digest[:])
				key := fmt.Sprintf(
					"%s--%s--b%03d",
					profile.ID,
					readiness,
					block,
				)
				blockRows = append(blockRows, fmt.Sprintf(
					"%06d\t%s\t%s\t%s\t%s\t1",
					block,
					orderDigest,
					key,
					profile.ID,
					readiness,
				))
			}
		}
		slices.SortFunc(blockRows, func(left, right string) int {
			leftDigest := strings.Split(left, "\t")[1]
			rightDigest := strings.Split(right, "\t")[1]
			return strings.Compare(leftDigest, rightDigest)
		})
		rows = append(rows, blockRows...)
	}
	scheduleContent := strings.Join(rows, "\n") + "\n"
	schedulePath := filepath.Join(root, "schedule.tsv")
	if err := os.WriteFile(
		schedulePath,
		[]byte(scheduleContent),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	schedule, err := loadV2Schedule(schedulePath, document)
	if err != nil {
		t.Fatal(err)
	}
	if len(schedule) != 8 {
		t.Fatalf("schedule rows=%d, want 8", len(schedule))
	}
	batches := make([]matrixBatch, 0, len(schedule))
	for _, row := range schedule {
		batches = append(batches, matrixBatch{
			schema:      "winn-phase1-auto-matrix-batch/v2",
			key:         row.key,
			block:       row.block,
			orderDigest: row.orderDigest,
			profile:     row.profile,
			readiness:   row.readiness,
			attempts:    row.attempts,
		})
	}
	scheduleDigest := sha256.Sum256([]byte(scheduleContent))
	environment := map[string]string{
		"schema":           "winn-phase1-auto-matrix/v2",
		"protocol_version": connectivity.Version,
		"matrix_id":        "test-matrix",
		"schedule_sha256":  hex.EncodeToString(scheduleDigest[:]),
	}
	complete := map[string]string{
		"schema":          "winn-phase1-auto-matrix-complete/v2",
		"matrix_id":       "test-matrix",
		"schedule_sha256": environment["schedule_sha256"],
	}
	if err := verifyV2Schedule(
		root,
		document,
		environment,
		complete,
		batches,
	); err != nil {
		t.Fatal(err)
	}
	batches[0].orderDigest = strings.Repeat("0", sha256.Size*2)
	if err := verifyV2Schedule(
		root,
		document,
		environment,
		complete,
		batches,
	); err == nil || !strings.Contains(err.Error(), "schedule row") {
		t.Fatalf("tampered batch schedule error=%v", err)
	}
	batches[0].orderDigest = schedule[0].orderDigest
	if err := os.WriteFile(
		filepath.Join(root, "INVALID"),
		[]byte("invalidated\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyV2Schedule(
		root,
		document,
		environment,
		complete,
		batches,
	); err == nil || !strings.Contains(err.Error(), "invalidation") {
		t.Fatalf("invalidated matrix error=%v", err)
	}
}

func TestVerifyQdiscEvidenceBindsFrozenShapedProfile(t *testing.T) {
	directory := t.TempDir()
	document := `[{
		"kind":"netem",
		"root":true,
		"options":{
			"delay":{"delay":0.125},
			"loss-random":{"loss":0.0151142},
			"rate":{"rate":1250000}
		},
		"packets":1234
	}]`
	for _, side := range []string{"client", "server"} {
		if err := os.WriteFile(
			filepath.Join(directory, side+"-post-run-qdisc.json"),
			[]byte(document),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	profile := networkProfile{
		ID:           "envelope-edge-250ms-3pct-10mbps",
		RTTMillis:    250,
		LossFraction: 0.03,
		CapacityMbps: 10,
	}
	if err := verifyQdiscEvidence(directory, profile); err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(document, `"packets":1234`, `"packets":0`, 1)
	if err := os.WriteFile(
		filepath.Join(directory, "server-post-run-qdisc.json"),
		[]byte(tampered),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyQdiscEvidence(directory, profile); err == nil ||
		!strings.Contains(err.Error(), "counters") {
		t.Fatalf("zero-traffic qdisc error = %v", err)
	}
}

func TestVerifyQdiscEvidenceRejectsNetemForBaseline(t *testing.T) {
	directory := t.TempDir()
	document := `[{"kind":"noqueue","root":true,"packets":0}]`
	for _, side := range []string{"client", "server"} {
		if err := os.WriteFile(
			filepath.Join(directory, side+"-post-run-qdisc.json"),
			[]byte(document),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyQdiscEvidence(
		directory, networkProfile{ID: "baseline"},
	); err != nil {
		t.Fatal(err)
	}
	netem := `[{"kind":"netem","root":true,"packets":1}]`
	if err := os.WriteFile(
		filepath.Join(directory, "client-post-run-qdisc.json"),
		[]byte(netem),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyQdiscEvidence(
		directory, networkProfile{ID: "baseline"},
	); err == nil || !strings.Contains(err.Error(), "unexpectedly") {
		t.Fatalf("baseline netem error = %v", err)
	}
}

// TestVerifyExperimentKnobsRequiresARecordedEmptyForcedCarrier states the
// semantics directly: every experiment-altering knob has to be recorded at its
// neutral value, and force_carrier has to be recorded at all. An environment
// that simply omits the key is silent about a knob that changes which
// candidates the harness prepares, and silence is refused.
func TestVerifyExperimentKnobsRequiresARecordedEmptyForcedCarrier(
	t *testing.T,
) {
	neutral := func() map[string]string {
		return map[string]string{
			"direct_initial_outer_drop":   "0s",
			"direct_click_delay":          "0s",
			"awg_handshake_hedge_offsets": "700ms,1100ms,1500ms,1900ms",
			"force_carrier":               "",
		}
	}
	if err := verifyExperimentKnobs(neutral()); err != nil {
		t.Fatalf("neutral environment error = %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{
			name: "forced_carrier_key_is_absent",
			mutate: func(values map[string]string) {
				delete(values, "force_carrier")
			},
			want: "does not record its forced-carrier state",
		},
		{
			name: "carrier_is_forced_to_direct_awg",
			mutate: func(values map[string]string) {
				values["force_carrier"] = "direct-awg"
			},
			want: "restricted preparation to one carrier",
		},
		{
			name: "carrier_is_forced_to_http3",
			mutate: func(values map[string]string) {
				values["force_carrier"] = "http3"
			},
			want: "restricted preparation to one carrier",
		},
		{
			name: "diagnostic_outer_drop",
			mutate: func(values map[string]string) {
				values["direct_initial_outer_drop"] = "200ms"
			},
			want: "diagnostic drop or wrong AWG hedge",
		},
		{
			name: "diagnostic_click_delay",
			mutate: func(values map[string]string) {
				values["direct_click_delay"] = "500ms"
			},
			want: "diagnostic drop or wrong AWG hedge",
		},
		{
			name: "altered_awg_hedge_offsets",
			mutate: func(values map[string]string) {
				values["awg_handshake_hedge_offsets"] = "700ms,1100ms"
			},
			want: "diagnostic drop or wrong AWG hedge",
		},
		{
			name:   "empty_environment",
			mutate: func(values map[string]string) { clear(values) },
			want:   "diagnostic drop or wrong AWG hedge",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := neutral()
			test.mutate(values)
			err := verifyExperimentKnobs(values)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("knob error = %v, want %q", err, test.want)
			}
		})
	}
}
