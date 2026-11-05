package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyCompletedMaximumPrivacyLowRun(t *testing.T) {
	path, cfg := writeValidRun(t)
	summary, err := verify(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Records != 2 ||
		summary.RunID != "01234567-89ab-cdef-0123-456789abcdef" ||
		summary.EvidenceDurabilityBarrier != evidenceDurabilityFullFsync ||
		!summary.EnergyAvailable ||
		summary.EnergyDeltaNanojoules != 50 {
		t.Fatalf("summary = %#v", summary)
	}
	_ = path
}

func TestVerifyUsesOneSealedInputSetAfterCallerPathsChange(t *testing.T) {
	t.Run("evidence and start receipt", func(t *testing.T) {
		path, cfg := writeValidRun(t)
		originalHook := afterEvidenceInputsSealed
		t.Cleanup(func() { afterEvidenceInputsSealed = originalHook })
		afterEvidenceInputsSealed = func() {
			if err := os.WriteFile(path, []byte("replaced\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				cfg.startReceipt, []byte("{}\n"), 0o600,
			); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := verify(cfg); err != nil {
			t.Fatalf("sealed verification failed: %v", err)
		}
	})

	t.Run("evidence and both receipts", func(t *testing.T) {
		cfg, path := writeValidStopRun(t)
		originalHook := afterEvidenceInputsSealed
		t.Cleanup(func() { afterEvidenceInputsSealed = originalHook })
		afterEvidenceInputsSealed = func() {
			for _, input := range []string{
				path, cfg.startReceipt, cfg.stopReceipt,
			} {
				if err := os.WriteFile(input, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := verify(cfg); err != nil {
			t.Fatalf("sealed Stop verification failed: %v", err)
		}
	})
}

func TestSealOneInputRejectsDestinationTraversal(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(source, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	sealedRoot := t.TempDir()
	escaped := filepath.Join(filepath.Dir(sealedRoot), "escaped-sealed-input")
	if _, err := sealOneInput(
		sealedRoot, "../escaped-sealed-input", source, 1024, 0o400,
	); err == nil {
		t.Fatal("destination traversal accepted")
	}
	if _, err := os.Lstat(escaped); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination traversal created %q: %v", escaped, err)
	}
}

func TestVerifyRejectsRetainedDropInLowProfile(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].DataPath.DroppedCells = 1
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "occupancy, drop, or delay") {
		t.Fatalf("drop error = %v", err)
	}
}

func TestVerifyRejectsRetainedDropOrBackpressureInIdleProfile(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	for index := range records {
		records[index].TrafficProfile = "idle"
	}
	data := records[1].DataPath
	data.CommonPathUnits = 0
	data.CommonPathActiveNanoseconds = 0
	data.CommonPathChecksum = deterministicChecksum(0)
	writeTestRun(t, path, cfg.startReceipt, records)
	cfg.expectedProfile = "idle"
	if _, err := verify(cfg); err != nil {
		t.Fatalf("valid idle fixture: %v", err)
	}

	t.Run("droppedCells", func(t *testing.T) {
		records := decodeTestRecords(t, path)
		records[1].DataPath.DroppedCells = 1
		writeTestRun(t, path, cfg.startReceipt, records)
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(err.Error(), "idle profile retained drop or backpressure") {
			t.Fatalf("idle drop error = %v", err)
		}
	})
	t.Run("backpressure", func(t *testing.T) {
		records := decodeTestRecords(t, path)
		records[1].DataPath.DroppedCells = 0
		records[1].DataPath.BackpressureEvents = 1
		records[1].DataPath.BackpressuredCells = 1
		writeTestRun(t, path, cfg.startReceipt, records)
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(err.Error(), "idle profile retained drop or backpressure") {
			t.Fatalf("idle backpressure error = %v", err)
		}
	})
}

func TestVerifyRejectsCompletedCoverLeftQueued(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	data := records[1].DataPath
	data.InboundQueueDepth = 60
	data.OutboundQueueDepth = 60
	data.InboundHighWatermark = 60
	data.OutboundHighWatermark = 60
	data.EmittedCells = 6_000
	data.QueueDelaySamples = 6_000
	data.CoverPairsEmitted = 0
	data.CoverInboundCellsEmitted = 0
	data.CoverOutboundCellsEmitted = 0
	data.CoverInboundCellsPending = 60
	data.CoverOutboundCellsPending = 60
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "actually emitted") {
		t.Fatalf("queued-cover error = %v", err)
	}
}

func TestVerifyRejectsUnknownJSONField(t *testing.T) {
	path, cfg := writeValidRun(t)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{\"unknown\":true}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), `member "unknown" is not declared`) {
		t.Fatalf("unknown-field error = %v", err)
	}
}

func TestVerifyRejectsOversizedEvidenceBeforeScanning(t *testing.T) {
	path, cfg := writeValidRun(t)
	if err := os.Truncate(path, (64<<20)+1); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "file size") {
		t.Fatalf("oversized evidence error = %v", err)
	}
}

func TestVerifyRejectsUnexpectedArtifactDigest(t *testing.T) {
	_, cfg := writeValidRun(t)
	cfg.expectedArtifact = strings.Repeat("c", 64)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "expected build") {
		t.Fatalf("artifact error = %v", err)
	}
}

func TestVerifyRejectsAllZeroProvenanceDigest(t *testing.T) {
	_, cfg := writeValidRun(t)
	cfg.expectedArtifact = strings.Repeat("0", 64)
	if _, err := verify(cfg); err == nil {
		t.Fatal("all-zero artifact digest accepted")
	}
}

func TestVerifyRejectsQueueDelayRatioWithoutOverflow(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].DataPath.QueueDelaySamples = 100
	records[1].DataPath.QueueDelayOver25Milliseconds = ^uint64(0)
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "occupancy, drop, or delay") {
		t.Fatalf("delay-ratio error = %v", err)
	}
}

func TestVerifyRejectsArbitraryCommonPathChecksum(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].DataPath.CommonPathChecksum++
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "checksum") {
		t.Fatalf("checksum error = %v", err)
	}
}

func TestVerifyRejectsIntermediateCorePrivacyLeakage(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	convertToCoreRun(records, &cfg)
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err != nil {
		t.Fatalf("valid Core fixture: %v", err)
	}

	intermediate := records[0]
	intermediate.Event = "sample-window"
	intermediate.MonotonicNanoseconds = 30_000_000_000
	// Only the first record may carry the start binding, so a copied
	// intermediate must drop it or it fails for that reason instead.
	intermediate.StartAttemptNonce = nil
	intermediate.StartRequestedAtMonotonicNanoseconds = nil
	intermediate.ProviderReceivedAtMonotonicNanoseconds = nil
	leaked := *intermediate.DataPath
	leaked.AcceptedCells = 1
	intermediate.DataPath = &leaked
	records = append(
		[]metricRecord{records[0], intermediate},
		records[1:]...,
	)
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "core baseline performed privacy-path work") {
		t.Fatalf("intermediate Core leakage error = %v", err)
	}
}

func TestVerifyRejectsCoreRotationResources(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	convertToCoreRun(records, &cfg)
	records[1].RotationResources = &rotationResources{Samples: 1}
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "rotation resources") {
		t.Fatalf("Core rotation-resources error = %v", err)
	}
}

func TestVerifyRejectsProtocolRotationResources(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].RotationResources = &rotationResources{Samples: 1}
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "rotation resources") {
		t.Fatalf("protocol rotation-resources error = %v", err)
	}
}

func TestCheckedSumRejectsOverflow(t *testing.T) {
	if _, ok := checkedSum(^uint64(0), 1); ok {
		t.Fatal("checkedSum accepted uint64 overflow")
	}
	if sum, ok := checkedSum(1, 2, 3, 4); !ok || sum != 10 {
		t.Fatalf("checkedSum(1,2,3,4) = %d, %t; want 10, true", sum, ok)
	}
}

func TestVerifyRejectsFabricatedWholeRunSamplingSpan(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].WholeRunResourceWindow.
		FirstSampleMonotonicNanoseconds = 60_800_000_000
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "resource") {
		t.Fatalf("resource-span error = %v", err)
	}
}

func TestVerifyRejectsShortCompletedRun(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].MonotonicNanoseconds = 60_999_999_999
	records[1].ResourceWindow.LastSampleMonotonicNanoseconds =
		60_999_999_999
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "duration") {
		t.Fatalf("duration error = %v", err)
	}
}

func TestVerifyRejectsInsufficientSamplingCoverage(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].WholeRunResourceWindow.SampleCount = 10
	records[1].WholeRunResourceWindow.ScheduledSampleCount = 60
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "sampling coverage") {
		t.Fatalf("sampling error = %v", err)
	}
}

func TestVerifyStopRequiresMeasuredHostRoundTrip(t *testing.T) {
	cfg, receiptPath := writeValidStopRun(t)
	if _, err := verify(cfg); err != nil {
		t.Fatal(err)
	}
	receipt := decodeStopReceipt(t, receiptPath)
	receipt.HostReceivedAtMonotonicNanoseconds = 7_260_000_000
	receipt.RoundTripNanoseconds = 260_000_000
	writeStopReceipt(t, receiptPath, receipt)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "round-trip") {
		t.Fatalf("slow Stop error = %v", err)
	}
}

// writeValidStopRun builds an accepted idle Stop run and returns its options
// together with the Stop receipt's path, so tests can mutate either half.
func writeValidStopRun(t *testing.T) (options, string) {
	t.Helper()
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	for index := range records {
		records[index].TrafficProfile = "idle"
		records[index].TestCondition = "stop-latency"
	}
	records[1].Event = "stop-acknowledged"
	records[1].MonotonicNanoseconds = 7_080_000_000
	records[1].ResourceWindow.FirstSampleMonotonicNanoseconds =
		2_000_000_000
	records[1].ResourceWindow.LastSampleMonotonicNanoseconds =
		7_050_000_000
	records[1].ResourceWindow.SampleCount = 6
	records[1].ResourceWindow.ScheduledSampleCount = 6
	records[1].WholeRunResourceWindow.LastSampleMonotonicNanoseconds =
		7_050_000_000
	records[1].WholeRunResourceWindow.SampleCount = 7
	records[1].WholeRunResourceWindow.ScheduledSampleCount = 7
	data := records[1].DataPath
	data.InboundQueueDepth = 1
	data.OutboundQueueDepth = 1
	data.InboundHighWatermark = 2
	data.OutboundHighWatermark = 2
	data.CommonPathUnits = 0
	data.CommonPathActiveNanoseconds = 0
	data.CommonPathChecksum = deterministicChecksum(0)
	data.AcceptedCells = 12
	data.EmittedCells = 10
	data.QueueDelaySamples = 10
	data.CoverPairsAccepted = 6
	data.CoverInboundCellsAccepted = 6
	data.CoverOutboundCellsAccepted = 6
	data.CoverPairsEmitted = 5
	data.CoverInboundCellsEmitted = 5
	data.CoverOutboundCellsEmitted = 5
	data.CoverInboundCellsPending = 1
	data.CoverOutboundCellsPending = 1
	cancellation := uint64(80_000_000)
	records[1].ControlLatencyNanoseconds = &cancellation
	writeTestRun(t, path, cfg.startReceipt, records)
	evidence, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(evidence)
	receipt := stopReceipt{
		Schema:                                 "winn-ios-privacy-spike-stop-receipt/1",
		ProtocolVersion:                        protocolVersion,
		RunID:                                  records[1].RunID,
		EvidenceFileName:                       filepath.Base(path),
		EvidenceSHA256:                         hex.EncodeToString(digest[:]),
		RequestedAtMonotonicNanoseconds:        7_000_000_000,
		ProviderReceivedAtMonotonicNanoseconds: 7_050_000_000,
		ProviderAcknowledgedAtMonotonicNanoseconds: 7_090_000_000,
		HostReceivedAtMonotonicNanoseconds:         7_100_000_000,
		RoundTripNanoseconds:                       100_000_000,
	}
	receiptPath := filepath.Join(t.TempDir(), "stop-receipt.json")
	writeStopReceipt(t, receiptPath, receipt)
	cfg.expectedTerminal = "stop-acknowledged"
	cfg.expectedProfile = "idle"
	cfg.expectedCondition = "stop-latency"
	cfg.stopReceipt = receiptPath
	return cfg, receiptPath
}

func decodeStopReceipt(t *testing.T, path string) stopReceipt {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt stopReceipt
	if err := json.Unmarshal(content, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

// MARK: start-latency receipt

func TestVerifyRequiresAStartReceipt(t *testing.T) {
	_, cfg := writeValidRun(t)
	cfg.startReceipt = ""
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "start receipt") {
		t.Fatalf("missing start receipt error = %v", err)
	}
}

func TestVerifyStartReceiptReportsTheMeasuredActivation(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	summary, err := verify(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := startReceiptFor(t, path, records).HostStartLatencyNanoseconds
	if summary.HostStartLatencyNanoseconds != want {
		t.Fatalf(
			"activation latency = %d, want %d",
			summary.HostStartLatencyNanoseconds,
			want,
		)
	}
}

// The digest must cover the trailing line feed. Hashing the stripped line is
// the specific mistake a line scanner invites, and it must be refused.
func TestVerifyStartReceiptDigestMustIncludeTheLineFeed(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstLine := testFirstLineWithLineFeed(t, content)
	stripped := sha256.Sum256(firstLine[:len(firstLine)-1])
	receipt := startReceiptFor(t, path, records)
	if receipt.FirstRecordSHA256 == hex.EncodeToString(stripped[:]) {
		t.Fatal("the line feed made no difference to the digest")
	}
	receipt.FirstRecordSHA256 = hex.EncodeToString(stripped[:])
	writeStartReceipt(t, cfg.startReceipt, receipt)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "pin the first evidence record") {
		t.Fatalf("line-feed digest error = %v", err)
	}
}

func TestVerifyStartReceiptRejectsAMutatedFirstRecord(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	// The receipt is generated for the original bytes, then the evidence's
	// first record is altered without regenerating it.
	records[0].WallTimeUTC = "2026-07-24T00:00:01Z"
	writeTestRecords(t, path, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "pin the first evidence record") {
		t.Fatalf("mutated first-record error = %v", err)
	}
}

func TestVerifyStartReceiptAcceptsFsyncOnlyBarrier(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	receipt := startReceiptFor(t, path, records)
	receipt.EvidenceDurabilityBarrier = evidenceDurabilityFsyncOnly
	writeStartReceipt(t, cfg.startReceipt, receipt)
	if _, err := verify(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyStartReceiptRejectsEveryMalformedField(t *testing.T) {
	cases := map[string]func(*startReceipt){
		"schema or scope": func(r *startReceipt) {
			r.Schema = "winn-ios-privacy-spike-start-receipt/3"
		},
		"schema or scope\x00protocol": func(r *startReceipt) {
			r.ProtocolVersion = "winn/2"
		},
		"schema or scope\x00measurement": func(r *startReceipt) {
			r.MeasurementScope = "usable-vpn-connection"
		},
		"evidence durability barrier is invalid": func(r *startReceipt) {
			r.EvidenceDurabilityBarrier = "fakedsync"
		},
		"artifact or host-receipt scope is invalid": func(r *startReceipt) {
			r.ArtifactScope = "wrong-artifact-scope"
		},
		"artifact or host-receipt scope is invalid\x00host": func(
			r *startReceipt,
		) {
			r.HostReceiptDurabilityScope = "wrong-host-receipt-scope"
		},
		"identifiers are invalid": func(r *startReceipt) {
			r.AttemptNonce = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
		},
		"identifiers are invalid\x00digest": func(r *startReceipt) {
			r.FirstRecordSHA256 = strings.Repeat("A", 64)
		},
		"identifiers are invalid\x00zero source": func(r *startReceipt) {
			r.SourceDigest = strings.Repeat("0", 64)
		},
		"not bound to this run\x00run id": func(r *startReceipt) {
			r.RunID = "fedcba98-7654-3210-fedc-ba9876543210"
		},
		"not bound to this run\x00file name": func(r *startReceipt) {
			r.EvidenceFileName = "somewhere-else.jsonl"
		},
		"first-record length": func(r *startReceipt) {
			r.FirstRecordBytes++
		},
		"start binding": func(r *startReceipt) {
			r.AttemptNonce = "ffffffff-1111-2222-3333-444444444444"
		},
	}
	for name, mutate := range cases {
		path, cfg := writeValidRun(t)
		records := decodeTestRecords(t, path)
		receipt := startReceiptFor(t, path, records)
		mutate(&receipt)
		writeStartReceipt(t, cfg.startReceipt, receipt)
		expected := strings.Split(name, "\x00")[0]
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(err.Error(), expected) {
			t.Fatalf("%s error = %v", name, err)
		}
	}
}

func TestVerifyStartReceiptRejectsAnUnknownField(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	encoded, err := json.Marshal(startReceiptFor(t, path, records))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["extra"] = true
	tampered, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		cfg.startReceipt,
		append(tampered, '\n'),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), `member "extra" is not declared`) {
		t.Fatalf("unknown start-receipt field error = %v", err)
	}
}

func TestVerifyStartReceiptBoundaryIsExactlyThreeSeconds(t *testing.T) {
	for _, testCase := range []struct {
		latency uint64
		accept  bool
	}{
		{maximumHostStartLatencyNanoseconds, true},
		{maximumHostStartLatencyNanoseconds + 1, false},
	} {
		path, cfg := writeValidRun(t)
		records := decodeTestRecords(t, path)
		receipt := startReceiptFor(t, path, records)
		receipt.HostObservedConnectedAtMonotonicNanoseconds =
			receipt.RequestedAtMonotonicNanoseconds + testCase.latency
		receipt.HostStartLatencyNanoseconds = testCase.latency
		writeStartReceipt(t, cfg.startReceipt, receipt)
		_, err := verify(cfg)
		if testCase.accept && err != nil {
			t.Fatalf("latency %d must pass: %v", testCase.latency, err)
		}
		if !testCase.accept &&
			(err == nil || !strings.Contains(err.Error(), "exceeds")) {
			t.Fatalf("latency %d error = %v", testCase.latency, err)
		}
	}
}

func TestVerifyStartReceiptRejectsInconsistentClocks(t *testing.T) {
	cases := map[string]func(*startReceipt){
		"host start latency does not match": func(r *startReceipt) {
			r.HostStartLatencyNanoseconds++
		},
		"provider start latency does not match": func(r *startReceipt) {
			r.ProviderStartLatencyNanoseconds++
		},
		"provider start latency interval is reversed": func(
			r *startReceipt,
		) {
			r.ProviderReadyAtMonotonicNanoseconds =
				r.ProviderReceivedAtMonotonicNanoseconds - 1
			r.ProviderStartLatencyNanoseconds = 0
		},
		"host observed connected before the provider was ready": func(
			r *startReceipt,
		) {
			r.HostObservedConnectedAtMonotonicNanoseconds =
				r.ProviderReadyAtMonotonicNanoseconds - 1
			r.HostStartLatencyNanoseconds =
				r.HostObservedConnectedAtMonotonicNanoseconds -
					r.RequestedAtMonotonicNanoseconds
		},
		"host start latency overflows": func(r *startReceipt) {
			r.HostStartLatencyNanoseconds = ^uint64(0)
		},
		"started record time is outside": func(r *startReceipt) {
			r.ProviderReadyAtMonotonicNanoseconds =
				r.ProviderReceivedAtMonotonicNanoseconds + 1
			r.ProviderStartLatencyNanoseconds = 1
		},
	}
	for expected, mutate := range cases {
		path, cfg := writeValidRun(t)
		records := decodeTestRecords(t, path)
		receipt := startReceiptFor(t, path, records)
		mutate(&receipt)
		writeStartReceipt(t, cfg.startReceipt, receipt)
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(err.Error(), expected) {
			t.Fatalf("%q error = %v", expected, err)
		}
	}
}

// The provider cannot receive a request before the host issued it. Both the
// record and the receipt carry those two timestamps, so the case is built by
// mutating the record and regenerating the receipt from it; otherwise the
// cross-binding check would fire first and prove nothing about the ordering.
func TestVerifyRejectsAProviderReceiptBeforeTheRequest(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	later := *records[0].ProviderReceivedAtMonotonicNanoseconds + 1
	records[0].StartRequestedAtMonotonicNanoseconds = &later
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "provider receipt interval is reversed") {
		t.Fatalf("reversed provider receipt error = %v", err)
	}
}

func TestVerifyRejectsAMisplacedStartBinding(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].StartAttemptNonce = records[0].StartAttemptNonce
	records[1].StartRequestedAtMonotonicNanoseconds =
		records[0].StartRequestedAtMonotonicNanoseconds
	records[1].ProviderReceivedAtMonotonicNanoseconds =
		records[0].ProviderReceivedAtMonotonicNanoseconds
	writeTestRun(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "outside the first record") {
		t.Fatalf("misplaced start-binding error = %v", err)
	}
}

func TestVerifyRejectsAStartedRecordWithoutTheBinding(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	receipt := startReceiptFor(t, path, records)
	records[0].StartAttemptNonce = nil
	records[0].StartRequestedAtMonotonicNanoseconds = nil
	records[0].ProviderReceivedAtMonotonicNanoseconds = nil
	writeTestRecords(t, path, records)
	// Repin the receipt to the rewritten first record so the digest check
	// cannot be what fails.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstLine := testFirstLineWithLineFeed(t, content)
	digest := sha256.Sum256(firstLine)
	receipt.FirstRecordSHA256 = hex.EncodeToString(digest[:])
	receipt.FirstRecordBytes = uint64(len(firstLine))
	writeStartReceipt(t, cfg.startReceipt, receipt)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "start binding") {
		t.Fatalf("absent start-binding error = %v", err)
	}
}

// firstLineWithLineFeed's error branch is not reachable through verify,
// because a file with two records necessarily contains a line feed. It is
// exercised directly so the helper is known to be total rather than assumed.
func TestFirstLineWithLineFeedRequiresATerminator(t *testing.T) {
	if _, err := firstLineWithLineFeed([]byte("{}")); err == nil {
		t.Fatal("a first line without a terminator was accepted")
	}
	line, err := firstLineWithLineFeed([]byte("{}\n{}\n"))
	if err != nil || string(line) != "{}\n" {
		t.Fatalf("firstLineWithLineFeed = %q, %v", line, err)
	}
}

func writeValidRun(t *testing.T) (string, options) {
	t.Helper()
	source := strings.Repeat("a", 64)
	artifact := strings.Repeat("b", 64)
	energy := uint64(50)
	resident := uint64(12_000_000)
	active := 0
	thermal := "nominal"
	lowPower := false
	startNonce := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	startRequested := uint64(900_000_000)
	providerReceived := uint64(950_000_000)
	records := []metricRecord{
		{
			Schema:                   schemaVersion,
			ProtocolVersion:          protocolVersion,
			FrameVersion:             frameVersion,
			Platform:                 "ios",
			OSVersion:                "fixture-ios",
			HardwareModel:            "fixture-iphone",
			RunID:                    "01234567-89ab-cdef-0123-456789abcdef",
			Event:                    "started",
			MonotonicNanoseconds:     1_000_000_000,
			WallTimeUTC:              "2026-07-24T00:00:00Z",
			Mode:                     "maximum-privacy",
			TrafficProfile:           "low",
			CoverSemantics:           "continuousWhileConnected",
			RotationCadence:          "protocol-15m",
			TestCondition:            "foreground-wifi",
			PairID:                   "11111111-2222-3333-4444-555555555555",
			DurationNanoseconds:      60_000_000_000,
			TrafficActiveNanoseconds: 60_000_000_000,
			SourceDigest:             source,
			ArtifactDigest:           artifact,
			Constants:                validConstants(),
			Resources: &resourceSnapshot{
				ThermalState: &thermal,
				LowPowerMode: &lowPower,
			},
			StartAttemptNonce:                      &startNonce,
			StartRequestedAtMonotonicNanoseconds:   &startRequested,
			ProviderReceivedAtMonotonicNanoseconds: &providerReceived,
		},
		{
			Schema:                   schemaVersion,
			ProtocolVersion:          protocolVersion,
			FrameVersion:             frameVersion,
			Platform:                 "ios",
			OSVersion:                "fixture-ios",
			HardwareModel:            "fixture-iphone",
			RunID:                    "01234567-89ab-cdef-0123-456789abcdef",
			Event:                    "completed",
			MonotonicNanoseconds:     61_000_000_000,
			WallTimeUTC:              "2026-07-24T00:01:00Z",
			Mode:                     "maximum-privacy",
			TrafficProfile:           "low",
			CoverSemantics:           "continuousWhileConnected",
			RotationCadence:          "protocol-15m",
			TestCondition:            "foreground-wifi",
			PairID:                   "11111111-2222-3333-4444-555555555555",
			DurationNanoseconds:      60_000_000_000,
			TrafficActiveNanoseconds: 60_000_000_000,
			SourceDigest:             source,
			ArtifactDigest:           artifact,
			Constants:                validConstants(),
			ResourceWindow: &resourceWindow{
				FirstSampleMonotonicNanoseconds: 31_000_000_000,
				LastSampleMonotonicNanoseconds:  61_000_000_000,
				SampleCount:                     30,
				ScheduledSampleCount:            30,
				PeakResidentBytes:               &resident,
				PeakPhysicalFootprintBytes:      &resident,
				EnergyDeltaNanojoules:           &energy,
				WorstThermalState:               &thermal,
				LowPowerModeAlwaysEnabled:       false,
			},
			WholeRunResourceWindow: &resourceWindow{
				FirstSampleMonotonicNanoseconds: 900_000_000,
				LastSampleMonotonicNanoseconds:  60_900_000_000,
				SampleCount:                     61,
				ScheduledSampleCount:            61,
				PeakResidentBytes:               &resident,
				PeakPhysicalFootprintBytes:      &resident,
				UserCPUDeltaNanoseconds:         &energy,
				SystemCPUDeltaNanoseconds:       &energy,
				InterruptWakeupDelta:            &energy,
				PackageIdleWakeupDelta:          &energy,
				EnergyDeltaNanojoules:           &energy,
				WorstThermalState:               &thermal,
				LowPowerModeAlwaysEnabled:       false,
			},
			DataPath: &dataPathSnapshot{
				AllocatedPrivacyCellBytes:            privacyPoolBytes,
				InboundQueueDepth:                    2,
				OutboundQueueDepth:                   2,
				InboundHighWatermark:                 10,
				OutboundHighWatermark:                10,
				OccupancySamples:                     6_000,
				InboundOccupancyP99Cells:             3,
				OutboundOccupancyP99Cells:            3,
				AcceptedCells:                        6_120,
				EmittedCells:                         6_116,
				CommonPathUnits:                      6_000,
				CommonPathActiveNanoseconds:          60_000_000_000,
				CommonPathChecksum:                   deterministicChecksum(6_000),
				CoverPairsAccepted:                   60,
				CoverInboundCellsAccepted:            60,
				CoverOutboundCellsAccepted:           60,
				CoverPairsEmitted:                    59,
				CoverInboundCellsEmitted:             59,
				CoverOutboundCellsEmitted:            59,
				CoverInboundCellsPending:             1,
				CoverOutboundCellsPending:            1,
				MaximumCoverLatenessNanoseconds:      10_000_000,
				QueueDelaySamples:                    6_116,
				QueueDelayP99UpperBoundNanoseconds:   20_100_000,
				MaximumObservedQueueDelayNanoseconds: 20_000_000,
				RotationActiveCircuit:                &active,
			},
		},
	}
	directory := t.TempDir()
	// The receipt binds `<runID>.jsonl`, which is how the host names every
	// collected file, so the fixture must use the same name.
	path := filepath.Join(
		directory,
		"01234567-89ab-cdef-0123-456789abcdef.jsonl",
	)
	receiptPath := filepath.Join(
		directory,
		"01234567-89ab-cdef-0123-456789abcdef.start-receipt.json",
	)
	writeTestRun(t, path, receiptPath, records)
	return path, options{
		evidence:                path,
		startReceipt:            receiptPath,
		expectedSource:          source,
		expectedArtifact:        artifact,
		expectedMode:            "maximum-privacy",
		expectedProfile:         "low",
		expectedCover:           "continuousWhileConnected",
		expectedRotation:        "protocol-15m",
		expectedCondition:       "foreground-wifi",
		expectedPairID:          "11111111-2222-3333-4444-555555555555",
		expectedOSVersion:       "fixture-ios",
		expectedHardwareModel:   "fixture-iphone",
		expectedLowPowerMode:    "off",
		expectedStartThermal:    "nominal",
		expectedDurationSeconds: 60,
		expectedTerminal:        "completed",
	}
}

// writeTestRun writes the records and then regenerates the start receipt so it
// pins whatever first record the caller just produced. Every existing test
// therefore keeps failing for its own reason instead of tripping over a stale
// receipt digest; the receipt-specific tests mutate the receipt afterwards.
//
// It also re-derives the wall clock from the monotonic clock, so a test that
// moves a record in time keeps failing for the reason it is named for instead
// of tripping over the wall-versus-monotonic consistency gate. The wall-clock
// tests deliberately bypass this by writing records directly.
func writeTestRun(
	t *testing.T,
	path string,
	receiptPath string,
	records []metricRecord,
) {
	t.Helper()
	syncFixtureWallClock(records)
	writeTestRecords(t, path, records)
	writeStartReceipt(t, receiptPath, startReceiptFor(t, path, records))
}

// fixtureWallBase is the instant the first record of every fixture run is
// stamped with.
var fixtureWallBase = time.Date(
	2026, time.July, 24, 0, 0, 0, 0, time.UTC,
)

// syncFixtureWallClock stamps each record with the wall time implied by its
// monotonic offset from the first record. It formats the value directly rather
// than calling the production parser, so a change to what the verifier accepts
// cannot quietly move the fixture with it.
func syncFixtureWallClock(records []metricRecord) {
	if len(records) == 0 {
		return
	}
	origin := records[0].MonotonicNanoseconds
	for index := range records {
		offset := time.Duration(
			int64(records[index].MonotonicNanoseconds) - int64(origin),
		)
		records[index].WallTimeUTC = fixtureWallBase.Add(offset).
			Format("2006-01-02T15:04:05.000") + "Z"
	}
}

func startReceiptFor(
	t *testing.T,
	path string,
	records []metricRecord,
) startReceipt {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstLine := testFirstLineWithLineFeed(t, content)
	digest := sha256.Sum256(firstLine)
	first := records[0]
	requested := *first.StartRequestedAtMonotonicNanoseconds
	providerReceived := *first.ProviderReceivedAtMonotonicNanoseconds
	providerReady := first.MonotonicNanoseconds + 10_000_000
	connected := providerReady + 40_000_000
	return startReceipt{
		Schema:                                 startReceiptSchema,
		ProtocolVersion:                        protocolVersion,
		RunID:                                  first.RunID,
		AttemptNonce:                           *first.StartAttemptNonce,
		SourceDigest:                           first.SourceDigest,
		EvidenceFileName:                       filepath.Base(path),
		FirstRecordSHA256:                      hex.EncodeToString(digest[:]),
		FirstRecordBytes:                       uint64(len(firstLine)),
		EvidenceDurabilityBarrier:              evidenceDurabilityFullFsync,
		RequestedAtMonotonicNanoseconds:        requested,
		ProviderReceivedAtMonotonicNanoseconds: providerReceived,
		ProviderReadyAtMonotonicNanoseconds:    providerReady,
		ProviderStartLatencyNanoseconds:        providerReady - providerReceived,
		HostObservedConnectedAtMonotonicNanoseconds: connected,
		HostStartLatencyNanoseconds:                 connected - requested,
		MeasurementScope:                            startMeasurementScope,
		ArtifactScope:                               startArtifactScope,
		HostReceiptDurabilityScope:                  startHostReceiptDurabilityScope,
	}
}

// testFirstLineWithLineFeed deliberately does NOT call the production helper.
// A fixture built with the function under test moves with it, so a mutation
// that dropped the line feed would be invisible; this recomputes the slice
// independently.
func testFirstLineWithLineFeed(t *testing.T, content []byte) []byte {
	t.Helper()
	index := bytes.IndexByte(content, '\n')
	if index < 0 {
		t.Fatal("fixture evidence has no line feed")
	}
	return content[:index+1]
}

func writeStartReceipt(
	t *testing.T,
	path string,
	receipt startReceipt,
) {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func convertToCoreRun(records []metricRecord, cfg *options) {
	cfg.expectedMode = "core-baseline"
	for index := range records {
		records[index].Mode = "core-baseline"
		commonPathChecksum := deterministicChecksum(0)
		var commonPathUnits uint64
		var commonPathActiveNanoseconds uint64
		if records[index].DataPath != nil {
			commonPathUnits = records[index].DataPath.CommonPathUnits
			commonPathActiveNanoseconds =
				records[index].DataPath.CommonPathActiveNanoseconds
			commonPathChecksum =
				records[index].DataPath.CommonPathChecksum
		}
		records[index].DataPath = &dataPathSnapshot{
			CommonPathUnits:             commonPathUnits,
			CommonPathActiveNanoseconds: commonPathActiveNanoseconds,
			CommonPathChecksum:          commonPathChecksum,
		}
		records[index].RotationResources = nil
	}
}

func writeTestRecords(
	t *testing.T,
	path string,
	records []metricRecord,
) {
	t.Helper()
	var content strings.Builder
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		content.Write(encoded)
		content.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeStopReceipt(t *testing.T, path string, receipt stopReceipt) {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func decodeTestRecords(t *testing.T, path string) []metricRecord {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	records := make([]metricRecord, 0, len(lines))
	for _, line := range lines {
		var record metricRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func validConstants() constantsSnapshot {
	return constantsSnapshot{
		CellBytes:                  privacyCellBytes,
		PayloadBytes:               privacyPayloadBytes,
		RingCapacityPerDirection:   ringCapacity,
		MaximumCircuits:            maximumCircuits,
		ShuffleNanoseconds:         20_000_000,
		CoverIntervalNanoseconds:   1_000_000_000,
		CoverTailNanoseconds:       30_000_000_000,
		CircuitRotationNanoseconds: 900_000_000_000,
		SpikeOverlapNanoseconds:    5_000_000_000,
	}
}
