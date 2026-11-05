package measurement

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func TestMeasurementLogPreservesSuccessFailureAndSummary(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	logPath := filepath.Join(directory, "measurement.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	log, err := Create(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	success := validAttempt(1, OutcomeSuccess, connectivity.FailureNone, 500_000)
	failure := validAttempt(
		2,
		OutcomeFailure,
		connectivity.FailureConnectDeadlineExceeded,
		3_000_000,
	)
	failure.SelectedCandidate = ""
	failure.Timeline = Timeline{OutcomeMicros: 3_000_000}
	if err := log.Append(success); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(failure); err != nil {
		t.Fatal(err)
	}
	summary := log.Summary()
	if summary.Total != 2 || summary.Successes != 1 || summary.Failures != 1 ||
		summary.OutcomeP50 != 500*time.Millisecond ||
		summary.OutcomeP99 != 3*time.Second ||
		summary.SuccessfulOutcomeP99 != 500*time.Millisecond ||
		summary.FailureCounts[connectivity.FailureConnectDeadlineExceeded] != 1 {
		t.Fatalf("measurement summary = %#v", summary)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reopened.Attempts()); got != 2 {
		t.Fatalf("reopened attempts = %d, want 2", got)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err != nil {
		t.Fatal(err)
	}
}

func TestMeasurementLogDetectsTampering(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	logPath := filepath.Join(directory, "measurement.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x51}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	log, err := Create(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(
		validAttempt(1, OutcomeSuccess, connectivity.FailureNone, 700_000),
	); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(
		string(encoded),
		`"throughput_mbps":900`,
		`"throughput_mbps":990`,
		1,
	)
	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err == nil ||
		!strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tampered measurement verification error = %v", err)
	}
}

func TestMeasurementRejectsHiddenSuccessAndInvalidDigest(t *testing.T) {
	attempt := validAttempt(
		1,
		OutcomeFailure,
		connectivity.FailureDNSVerificationFailed,
		600_000,
	)
	attempt.SelectedCandidate = "h3-primary"
	if err := ValidateAttempt(attempt); err == nil ||
		!strings.Contains(err.Error(), "impossible selected") {
		t.Fatalf("hidden success validation error = %v", err)
	}
	attempt = validAttempt(
		1, OutcomeSuccess, connectivity.FailureNone, 600_000,
	)
	attempt.SourceDigest = "not-a-digest"
	if err := ValidateAttempt(attempt); err == nil ||
		!strings.Contains(err.Error(), "source digest") {
		t.Fatalf("digest validation error = %v", err)
	}
}

func TestMeasurementOpenRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	target := filepath.Join(directory, "target.jsonl")
	link := filepath.Join(directory, "measurement.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x62}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, keyPath); err == nil ||
		!strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink open error = %v", err)
	}
}

func TestMeasurementDetectsTruncationAgainstAnchor(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	logPath := filepath.Join(directory, "measurement.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x73}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	log, err := Create(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(
		validAttempt(
			1, OutcomeSuccess, connectivity.FailureNone, 500_000,
		),
	); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err == nil ||
		!strings.Contains(err.Error(), "anchor sequence") {
		t.Fatalf("truncation verification error = %v", err)
	}
}

func TestMeasurementOpenReconcilesOneDurableRecordAfterAnchorCrash(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	logPath := filepath.Join(directory, "measurement.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x74}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	log, err := Create(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(
		validAttempt(
			1, OutcomeSuccess, connectivity.FailureNone, 500_000,
		),
	); err != nil {
		t.Fatal(err)
	}
	oldAnchor, err := os.ReadFile(logPath + ".anchor")
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(
		validAttempt(
			2, OutcomeSuccess, connectivity.FailureNone, 600_000,
		),
	); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".anchor", oldAnchor, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err == nil ||
		!strings.Contains(err.Error(), "anchor sequence") {
		t.Fatalf("read-only verification unexpectedly repaired: %v", err)
	}
	recovered, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Attempts()) != 2 {
		t.Fatal("recovery lost the durable final record")
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err != nil {
		t.Fatalf("reconciled evidence did not verify: %v", err)
	}
}

func TestMeasurementVerifyMissingDoesNotCreateEvidence(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	logPath := filepath.Join(directory, "missing.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x75}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err == nil {
		t.Fatal("missing evidence verified")
	}
	for _, path := range []string{logPath, logPath + ".anchor"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("verification created %s: %v", path, err)
		}
	}
}

func TestMeasurementRejectsDuplicateAttemptAndUnknownFailure(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	logPath := filepath.Join(directory, "measurement.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x76}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	log, err := Create(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	attempt := validAttempt(
		1, OutcomeSuccess, connectivity.FailureNone, 500_000,
	)
	if err := log.Append(attempt); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(attempt); err == nil ||
		!strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate attempt error = %v", err)
	}
	unknown := validAttempt(
		2,
		OutcomeFailure,
		connectivity.FailureCode("made-up-failure"),
		500_000,
	)
	unknown.Timeline = Timeline{OutcomeMicros: 500_000}
	if err := ValidateAttempt(unknown); err == nil {
		t.Fatal("unknown failure code was accepted")
	}
}

func TestMeasurementRejectsUnderreportedOutcomeDuration(t *testing.T) {
	attempt := validAttempt(
		1,
		OutcomeFailure,
		connectivity.FailureConnectDeadlineExceeded,
		3_000_000,
	)
	attempt.Timeline = Timeline{OutcomeMicros: 0}
	if err := ValidateAttempt(attempt); err == nil ||
		!strings.Contains(err.Error(), "outcome timeline") {
		t.Fatalf("underreported duration error = %v", err)
	}
}

func TestMeasurementRejectsSecondWriter(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "measurement.key")
	logPath := filepath.Join(directory, "measurement.jsonl")
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x77}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	first, err := Create(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(logPath, keyPath); err == nil ||
		!strings.Contains(err.Error(), "another process owns") {
		t.Fatalf("second writer error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMeasurementBuildsFromAuthoritativeConnectivityResult(t *testing.T) {
	started := time.Date(2026, 7, 24, 2, 0, 0, 0, time.UTC)
	result := connectivity.Result{
		AttemptID:        strings.Repeat("a", 32),
		TrustFingerprint: strings.Repeat("b", 64),
		Profile:          "default",
		Mode:             connectivity.ModeAuto,
		State:            connectivity.StateOnline,
		CandidateID:      "h3-primary",
		Carrier:          connectivity.CarrierHTTP3,
		StartedAt:        started,
		FinishedAt:       started.Add(500 * time.Millisecond),
		Predicates: connectivity.Predicates{
			FreshAWGHandshake: true,
			Bidirectional:     true,
			ProtectedDNS:      true,
			TunnelCanary:      true,
		},
		Timings: connectivity.Timings{
			Dial:          100 * time.Millisecond,
			Handshake:     250 * time.Millisecond,
			Bidirectional: 300 * time.Millisecond,
			DNS:           280 * time.Millisecond,
			Canary:        290 * time.Millisecond,
			Commit:        350 * time.Millisecond,
			Outcome:       500 * time.Millisecond,
		},
	}
	attempt, err := FromConnectivityResult(result, validMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Outcome != OutcomeSuccess ||
		attempt.Timeline.OutcomeMicros != 500_000 ||
		attempt.TrustFingerprint != result.TrustFingerprint {
		t.Fatalf("derived attempt = %#v", attempt)
	}
}

func TestMeasurementAllowsSelectedCandidateOnlyAfterSelection(t *testing.T) {
	started := time.Date(2026, 7, 24, 2, 0, 0, 0, time.UTC)
	result := connectivity.Result{
		AttemptID:        strings.Repeat("c", 32),
		TrustFingerprint: strings.Repeat("d", 64),
		Profile:          "default",
		Mode:             connectivity.ModeAuto,
		State:            connectivity.StateFailed,
		CandidateID:      "h3-primary",
		Carrier:          connectivity.CarrierHTTP3,
		StartedAt:        started,
		FinishedAt:       started.Add(2 * time.Second),
		Failure:          connectivity.FailurePostCommitHealth,
		Timings: connectivity.Timings{
			Dial:          100 * time.Millisecond,
			Handshake:     250 * time.Millisecond,
			Bidirectional: 300 * time.Millisecond,
			DNS:           280 * time.Millisecond,
			Canary:        290 * time.Millisecond,
			Commit:        350 * time.Millisecond,
			Outcome:       2 * time.Second,
		},
	}
	if _, err := FromConnectivityResult(result, validMetadata()); err != nil {
		t.Fatal(err)
	}
	result.Failure = connectivity.FailureDNSVerificationFailed
	if _, err := FromConnectivityResult(result, validMetadata()); err == nil ||
		!strings.Contains(err.Error(), "impossible selected") {
		t.Fatalf("pre-selection failure with candidate error = %v", err)
	}
}

func TestMeasurementRebasesTrueColdAttemptOntoPreparationStart(t *testing.T) {
	preparationStarted := time.Date(
		2026, 7, 24, 1, 59, 59, 800_000_000, time.UTC,
	)
	connectStarted := preparationStarted.Add(200 * time.Millisecond)
	result := connectivity.Result{
		AttemptID:        strings.Repeat("7", 32),
		TrustFingerprint: strings.Repeat("8", 64),
		Profile:          "phase1-auto",
		Mode:             connectivity.ModeAuto,
		State:            connectivity.StateOnline,
		CandidateID:      "direct-primary",
		Carrier:          connectivity.CarrierDirectAWG,
		StartedAt:        connectStarted,
		FinishedAt:       connectStarted.Add(500 * time.Millisecond),
		Predicates: connectivity.Predicates{
			FreshAWGHandshake: true,
			Bidirectional:     true,
			ProtectedDNS:      true,
			TunnelCanary:      true,
		},
		Timings: connectivity.Timings{
			Dial:          100 * time.Millisecond,
			Handshake:     250 * time.Millisecond,
			Bidirectional: 300 * time.Millisecond,
			DNS:           280 * time.Millisecond,
			Canary:        290 * time.Millisecond,
			Commit:        350 * time.Millisecond,
			Outcome:       500 * time.Millisecond,
		},
	}
	metadata := validMetadata()
	metadata.Readiness = ReadinessCold
	metadata.EvidenceStartedAt = preparationStarted
	attempt, err := FromConnectivityResult(result, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.StartedAt != preparationStarted.Format(time.RFC3339Nano) ||
		attempt.Timeline.DialMicros != 300_000 ||
		attempt.Timeline.CommitMicros != 550_000 ||
		attempt.Timeline.OutcomeMicros != 700_000 {
		t.Fatalf("rebased cold attempt = %#v", attempt)
	}
}

func TestMeasurementOperationFailureCannotDisappearFromDenominator(
	t *testing.T,
) {
	started := time.Date(2026, 7, 24, 2, 0, 0, 0, time.UTC)
	finished := started.Add(175 * time.Millisecond)
	metadata := validMetadata()
	metadata.Readiness = ReadinessCold
	attempt, err := FromOperationFailure(
		connectivity.ModeAuto,
		connectivity.FailureNotReady,
		started,
		finished,
		metadata,
	)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Outcome != OutcomeFailure ||
		attempt.Failure != connectivity.FailureNotReady ||
		attempt.SelectedCandidate != "" ||
		attempt.Timeline.OutcomeMicros != 175_000 ||
		len(attempt.AttemptID) != 32 ||
		len(attempt.TrustFingerprint) != 64 {
		t.Fatalf("operation failure attempt = %#v", attempt)
	}
	if err := ValidateAttempt(attempt); err != nil {
		t.Fatalf("ValidateAttempt() error = %v", err)
	}
}

func TestMeasurementRejectsInvalidColdEvidenceStart(t *testing.T) {
	started := time.Date(2026, 7, 24, 2, 0, 0, 0, time.UTC)
	result := connectivity.Result{
		AttemptID:        strings.Repeat("9", 32),
		TrustFingerprint: strings.Repeat("a", 64),
		Mode:             connectivity.ModeAuto,
		State:            connectivity.StateFailed,
		StartedAt:        started,
		FinishedAt:       started.Add(time.Second),
		Failure:          connectivity.FailureNoReachableCandidate,
		Timings:          connectivity.Timings{Outcome: time.Second},
	}
	metadata := validMetadata()
	metadata.EvidenceStartedAt = started.Add(time.Nanosecond)
	if _, err := FromConnectivityResult(result, metadata); err == nil ||
		!strings.Contains(err.Error(), "follows connectivity start") {
		t.Fatalf("future evidence start error = %v", err)
	}
	metadata.EvidenceStartedAt = time.Date(
		2026, 7, 24, 1, 0, 0, 0, time.FixedZone("not-utc", 3600),
	)
	if _, err := FromConnectivityResult(result, metadata); err == nil ||
		!strings.Contains(err.Error(), "must be UTC") {
		t.Fatalf("non-UTC evidence start error = %v", err)
	}
}

func TestMeasurementRejectsNonAuthoritativeResultTiming(t *testing.T) {
	started := time.Date(2026, 7, 24, 2, 0, 0, 0, time.UTC)
	result := connectivity.Result{
		AttemptID:        strings.Repeat("e", 32),
		TrustFingerprint: strings.Repeat("f", 64),
		Mode:             connectivity.ModeAuto,
		State:            connectivity.StateFailed,
		StartedAt:        started,
		FinishedAt:       started.Add(time.Second),
		Failure:          connectivity.FailureNoReachableCandidate,
		Timings:          connectivity.Timings{Outcome: 999 * time.Millisecond},
	}
	if _, err := FromConnectivityResult(result, validMetadata()); err == nil ||
		!strings.Contains(err.Error(), "not authoritative") {
		t.Fatalf("non-authoritative timing error = %v", err)
	}
}

func validMetadata() AttemptMetadata {
	return AttemptMetadata{
		SourceDigest:   strings.Repeat("1", 64),
		ArtifactDigest: strings.Repeat("2", 64),
		ManifestDigest: strings.Repeat("3", 64),
		Platform:       "linux",
		OSVersion:      "Ubuntu 24.04",
		Device:         "aicore",
		Readiness:      ReadinessWarm,
		CandidateIDs:   []string{"direct-primary", "h3-primary"},
		Network: NetworkProfile{
			Interface:      "ethernet",
			IPFamily:       "dual",
			RTTMillis:      20,
			LossFraction:   0.001,
			CapacityMbps:   1000,
			ClientRegion:   "us-atl",
			ServerRegion:   "us-nyc",
			ServerProvider: "vultr",
		},
		Metrics: Metrics{
			ThroughputMbps:  900,
			BaselineMbps:    1000,
			CPUPercent:      80,
			PeakMemoryBytes: 64 << 20,
			UserBytes:       1 << 30,
		},
	}
}

func validAttempt(
	index int,
	outcome Outcome,
	failure connectivity.FailureCode,
	outcomeMicros int64,
) Attempt {
	started := time.Date(2026, 7, 23, 20, 0, index, 0, time.UTC)
	finished := started.Add(time.Duration(outcomeMicros) * time.Microsecond)
	attempt := Attempt{
		AttemptID:         strings.Repeat(string(rune('a'+index)), 32),
		SourceDigest:      strings.Repeat("1", 64),
		ArtifactDigest:    strings.Repeat("2", 64),
		ProtocolVersion:   connectivity.Version,
		ManifestDigest:    strings.Repeat("3", 64),
		TrustFingerprint:  strings.Repeat("4", 64),
		Platform:          "linux",
		OSVersion:         "Ubuntu 24.04",
		Device:            "aicore",
		Mode:              connectivity.ModeAuto,
		Readiness:         ReadinessWarm,
		CandidateIDs:      []string{"direct-primary", "h3-primary"},
		SelectedCandidate: "h3-primary",
		Network: NetworkProfile{
			Interface:      "ethernet",
			IPFamily:       "dual",
			RTTMillis:      20,
			LossFraction:   0.001,
			CapacityMbps:   1000,
			ClientRegion:   "us-atl",
			ServerRegion:   "us-nyc",
			ServerProvider: "vultr",
		},
		StartedAt:  started.Format(time.RFC3339Nano),
		FinishedAt: finished.Format(time.RFC3339Nano),
		Outcome:    outcome,
		Failure:    failure,
		Timeline: Timeline{
			DialMicros:          100_000,
			HandshakeMicros:     250_000,
			BidirectionalMicros: 300_000,
			DNSMicros:           280_000,
			CanaryMicros:        290_000,
			CommitMicros:        350_000,
			OutcomeMicros:       outcomeMicros,
		},
		Metrics: Metrics{
			ThroughputMbps:  900,
			BaselineMbps:    1000,
			CPUPercent:      80,
			PeakMemoryBytes: 64 << 20,
			CoverBytes:      0,
			UserBytes:       1 << 30,
		},
	}
	if outcome == OutcomeFailure {
		attempt.SelectedCandidate = ""
	}
	return attempt
}
