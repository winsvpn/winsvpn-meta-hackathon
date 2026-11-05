// Command matrixverify checks cross-run properties that cannot be established
// by evidenceverify's strict single-run gate: matched Core/Maximum Privacy
// workload identity, required Stage A coverage, median energy/battery overhead,
// and incremental idle wakeups.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	manifestSchema   = "winn-ios-privacy-matrix/1"
	evidenceSchema   = "winn-ios-privacy-spike/3"
	protocolVersion  = "winn/3"
	maxManifestBytes = 2 << 20
	maxEvidenceBytes = 64 << 20

	// Start-latency evidence. The bound covers host-observed iOS Packet
	// Tunnel activation only: the Stage A provider installs a synthetic
	// RFC 2544 route, performs no handshake, and forwards no packet, so this
	// is neither a usable-connection nor a first-protected-packet
	// measurement.
	startReceiptSchema                 = "winn-ios-privacy-spike-start-receipt/2"
	startMeasurementScope              = "ios-packet-tunnel-activation-only"
	startArtifactScope                 = "activation-observation-not-attempt-success-or-persistence-timing"
	startHostReceiptDurabilityScope    = "host-receipt-barrier-not-encoded-no-power-loss-claim"
	evidenceDurabilityFullFsync        = "f-fullfsync"
	evidenceDurabilityFsyncOnly        = "fsync-only"
	maximumHostStartLatencyNanoseconds = 3_000_000_000
)

var canonicalEvidencePass = regexp.MustCompile(
	`^IOS_SPIKE_VERIFY_PASS records=[1-9][0-9]* ` +
		`run_id=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} ` +
		`artifact=[0-9a-f]{64} ` +
		`evidence_barrier=(?:f-fullfsync|fsync-only) ` +
		`resident_slope_bytes_per_hour=-?[0-9]+\.[0-9]{3} ` +
		`energy_available=(?:true|false) energy_delta_nj=[0-9]+ ` +
		`host_packet_tunnel_activation_latency_ns=[0-9]+\n$`,
)

type matrixManifest struct {
	Schema          string        `json:"schema"`
	ProtocolVersion string        `json:"protocolVersion"`
	SourceDigest    string        `json:"sourceDigest"`
	ArtifactDigest  string        `json:"artifactDigest"`
	OSVersion       string        `json:"osVersion"`
	HardwareModel   string        `json:"hardwareModel"`
	Runs            []manifestRun `json:"runs"`
}

type manifestRun struct {
	Evidence                 string  `json:"evidence"`
	EvidenceSHA256           string  `json:"evidenceSHA256"`
	Mode                     string  `json:"mode"`
	TrafficProfile           string  `json:"trafficProfile"`
	CoverSemantics           string  `json:"coverSemantics"`
	RotationCadence          string  `json:"rotationCadence"`
	TestCondition            string  `json:"testCondition"`
	PairID                   string  `json:"pairID"`
	Repeat                   int     `json:"repeat"`
	DurationSeconds          uint64  `json:"durationSeconds"`
	ExpectedTerminal         string  `json:"expectedTerminal"`
	LowPowerMode             string  `json:"lowPowerMode"`
	StartThermal             string  `json:"startThermal"`
	Unplugged                bool    `json:"unplugged"`
	BatteryStartBasisPoints  *uint64 `json:"batteryStartBasisPoints,omitempty"`
	BatteryEndBasisPoints    *uint64 `json:"batteryEndBasisPoints,omitempty"`
	StopReceipt              string  `json:"stopReceipt,omitempty"`
	StopReceiptSHA256        string  `json:"stopReceiptSHA256,omitempty"`
	StartReceipt             string  `json:"startReceipt"`
	StartReceiptSHA256       string  `json:"startReceiptSHA256"`
	originalEvidenceFileName string
}

// startReceipt mirrors the host activation receipt. matrixverify revalidates
// it independently instead of trusting that the single-run verifier did.
type startReceipt struct {
	Schema                                      string `json:"schema"`
	ProtocolVersion                             string `json:"protocolVersion"`
	RunID                                       string `json:"runID"`
	AttemptNonce                                string `json:"attemptNonce"`
	SourceDigest                                string `json:"sourceDigest"`
	EvidenceFileName                            string `json:"evidenceFileName"`
	FirstRecordSHA256                           string `json:"firstRecordSHA256"`
	FirstRecordBytes                            uint64 `json:"firstRecordBytes"`
	EvidenceDurabilityBarrier                   string `json:"evidenceDurabilityBarrier"`
	RequestedAtMonotonicNanoseconds             uint64 `json:"requestedAtMonotonicNanoseconds"`
	ProviderReceivedAtMonotonicNanoseconds      uint64 `json:"providerReceivedAtMonotonicNanoseconds"`
	ProviderReadyAtMonotonicNanoseconds         uint64 `json:"providerReadyAtMonotonicNanoseconds"`
	ProviderStartLatencyNanoseconds             uint64 `json:"providerStartLatencyNanoseconds"`
	HostObservedConnectedAtMonotonicNanoseconds uint64 `json:"hostObservedConnectedAtMonotonicNanoseconds"`
	HostStartLatencyNanoseconds                 uint64 `json:"hostStartLatencyNanoseconds"`
	MeasurementScope                            string `json:"measurementScope"`
	ArtifactScope                               string `json:"artifactScope"`
	HostReceiptDurabilityScope                  string `json:"hostReceiptDurabilityScope"`
}

type resourceSnapshot struct {
	ThermalState *string `json:"thermalState,omitempty"`
	LowPowerMode *bool   `json:"lowPowerMode,omitempty"`
}

type resourceWindow struct {
	InterruptWakeupDelta      *uint64 `json:"interruptWakeupDelta,omitempty"`
	PackageIdleWakeupDelta    *uint64 `json:"packageIdleWakeupDelta,omitempty"`
	EnergyDeltaNanojoules     *uint64 `json:"energyDeltaNanojoules,omitempty"`
	LowPowerModeObserved      bool    `json:"lowPowerModeObserved"`
	LowPowerModeAlwaysEnabled bool    `json:"lowPowerModeAlwaysEnabled"`
}

type dataPathSnapshot struct {
	CommonPathUnits             uint64 `json:"commonPathUnits"`
	CommonPathActiveNanoseconds uint64 `json:"commonPathActiveNanoseconds"`
	CommonPathChecksum          uint64 `json:"commonPathChecksum"`
	RotationCount               uint64 `json:"rotationCount"`
	CoverPairsAccepted          uint64 `json:"coverPairsAccepted"`
	CoverDeadlinesMissed        uint64 `json:"coverDeadlinesMissed"`
}

type metricRecord struct {
	Schema                                 string            `json:"schema"`
	ProtocolVersion                        string            `json:"protocolVersion"`
	FrameVersion                           string            `json:"frameVersion"`
	Platform                               string            `json:"platform"`
	OSVersion                              string            `json:"osVersion"`
	HardwareModel                          string            `json:"hardwareModel"`
	RunID                                  string            `json:"runID"`
	Event                                  string            `json:"event"`
	MonotonicNanoseconds                   uint64            `json:"monotonicNanoseconds"`
	WallTimeUTC                            string            `json:"wallTimeUTC"`
	Mode                                   string            `json:"mode"`
	TrafficProfile                         string            `json:"trafficProfile"`
	CoverSemantics                         string            `json:"coverSemantics"`
	RotationCadence                        string            `json:"rotationCadence"`
	TestCondition                          string            `json:"testCondition"`
	PairID                                 string            `json:"pairID"`
	DurationNanoseconds                    uint64            `json:"durationNanoseconds"`
	TrafficActiveNanoseconds               uint64            `json:"trafficActiveNanoseconds"`
	SourceDigest                           string            `json:"sourceDigest"`
	ArtifactDigest                         string            `json:"artifactDigest"`
	Resources                              *resourceSnapshot `json:"resources,omitempty"`
	WholeRunResourceWindow                 *resourceWindow   `json:"wholeRunResourceWindow,omitempty"`
	DataPath                               *dataPathSnapshot `json:"dataPath,omitempty"`
	StartAttemptNonce                      *string           `json:"startAttemptNonce,omitempty"`
	StartRequestedAtMonotonicNanoseconds   *uint64           `json:"startRequestedAtMonotonicNanoseconds,omitempty"`
	ProviderReceivedAtMonotonicNanoseconds *uint64           `json:"providerReceivedAtMonotonicNanoseconds,omitempty"`
}

type checkedRun struct {
	manifest manifestRun
	terminal metricRecord
}

type matchedPair struct {
	core    checkedRun
	privacy checkedRun
}

type matrixSummary struct {
	Pairs                        int
	FullFsyncEvidenceRuns        int
	FsyncOnlyEvidenceRuns        int
	WiFiKernelMedianOverhead     float64
	WiFiBatteryMedianOverhead    float64
	CellKernelMedianOverhead     float64
	CellBatteryMedianOverhead    float64
	IdleIncrementalWakeupsSecond float64
	WorstHostStartLatency        uint64
}

func main() {
	var path string
	var evidenceVerifier string
	var expectedEvidenceVerifierSHA256 string
	flag.StringVar(&path, "manifest", "", "strict Stage A matrix manifest")
	flag.StringVar(
		&evidenceVerifier,
		"evidence-verifier",
		"",
		"pinned evidenceverify executable",
	)
	flag.StringVar(
		&expectedEvidenceVerifierSHA256,
		"expected-evidence-verifier-sha256",
		"",
		"required evidenceverify executable digest",
	)
	flag.Parse()
	summary, err := verifyMatrix(
		path,
		evidenceVerifier,
		expectedEvidenceVerifierSHA256,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "IOS_SPIKE_MATRIX_VERIFY_FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf(
		"IOS_SPIKE_MATRIX_VERIFY_PASS pairs=%d "+
			"evidence_fullfsync_runs=%d evidence_fsync_only_runs=%d "+
			"wifi_worst_profile_kernel_median_overhead=%.4f "+
			"wifi_observed_worst_profile_battery_median_overhead=%.4f "+
			"cellular_worst_profile_kernel_median_overhead=%.4f "+
			"cellular_observed_worst_profile_battery_median_overhead=%.4f "+
			"idle_incremental_wakeups_per_second=%.4f "+
			"worst_host_packet_tunnel_activation_latency_ns=%d\n",
		summary.Pairs,
		summary.FullFsyncEvidenceRuns,
		summary.FsyncOnlyEvidenceRuns,
		summary.WiFiKernelMedianOverhead,
		summary.WiFiBatteryMedianOverhead,
		summary.CellKernelMedianOverhead,
		summary.CellBatteryMedianOverhead,
		summary.IdleIncrementalWakeupsSecond,
		summary.WorstHostStartLatency,
	)
}

func verifyMatrix(
	path string,
	evidenceVerifier string,
	expectedEvidenceVerifierSHA256 string,
) (matrixSummary, error) {
	verifierPath, err := validateEvidenceVerifier(
		evidenceVerifier,
		expectedEvidenceVerifierSHA256,
	)
	if err != nil {
		return matrixSummary{}, err
	}
	sealedVerifierPath, cleanupVerifier, err := sealEvidenceVerifier(
		verifierPath,
		expectedEvidenceVerifierSHA256,
	)
	if err != nil {
		return matrixSummary{}, err
	}
	defer cleanupVerifier()
	verifierPath = sealedVerifierPath
	manifest, base, manifestContent, err := readManifest(path)
	if err != nil {
		return matrixSummary{}, err
	}
	if err := validateManifestHeader(manifest); err != nil {
		return matrixSummary{}, err
	}
	for index, run := range manifest.Runs {
		if err := validateManifestRun(run); err != nil {
			return matrixSummary{}, fmt.Errorf("runs[%d]: %w", index, err)
		}
	}
	base, manifest, cleanupInputs, err := sealMatrixInputs(
		base, manifest, manifestContent,
	)
	if err != nil {
		return matrixSummary{}, fmt.Errorf("seal matrix inputs: %w", err)
	}
	defer cleanupInputs()

	checked := make([]checkedRun, 0, len(manifest.Runs))
	paths := make(map[string]struct{}, len(manifest.Runs))
	runIDs := make(map[string]struct{}, len(manifest.Runs))
	worstStartLatency := uint64(0)
	fullFsyncEvidenceRuns := 0
	fsyncOnlyEvidenceRuns := 0
	for index, run := range manifest.Runs {
		if _, exists := paths[run.Evidence]; exists {
			return matrixSummary{}, fmt.Errorf("runs[%d]: duplicate evidence path", index)
		}
		paths[run.Evidence] = struct{}{}
		terminal, err := readAndCheckEvidence(base, manifest, run)
		if err != nil {
			return matrixSummary{}, fmt.Errorf("runs[%d]: %w", index, err)
		}
		if err := runEvidenceVerifier(
			verifierPath,
			base,
			manifest,
			run,
		); err != nil {
			return matrixSummary{}, fmt.Errorf(
				"runs[%d]: single-run verifier: %w", index, err,
			)
		}
		if err := recheckEvidenceDigest(base, run); err != nil {
			return matrixSummary{}, fmt.Errorf(
				"runs[%d]: %w", index, err,
			)
		}
		evidenceBarrier := ""
		latency, err := verifyStartReceiptBinding(
			base,
			manifest,
			run,
			terminal,
			&evidenceBarrier,
		)
		if err != nil {
			return matrixSummary{}, fmt.Errorf("runs[%d]: %w", index, err)
		}
		switch evidenceBarrier {
		case evidenceDurabilityFullFsync:
			fullFsyncEvidenceRuns++
		case evidenceDurabilityFsyncOnly:
			fsyncOnlyEvidenceRuns++
		default:
			return matrixSummary{}, fmt.Errorf(
				"runs[%d]: unreported evidence barrier",
				index,
			)
		}
		worstStartLatency = max(worstStartLatency, latency)
		if _, exists := runIDs[terminal.RunID]; exists {
			return matrixSummary{}, fmt.Errorf("runs[%d]: duplicate run ID", index)
		}
		runIDs[terminal.RunID] = struct{}{}
		checked = append(checked, checkedRun{manifest: run, terminal: terminal})
	}

	pairs, singles, err := formPairs(checked)
	if err != nil {
		return matrixSummary{}, err
	}
	if err := verifyRequiredCoverage(pairs, singles); err != nil {
		return matrixSummary{}, err
	}

	wifiKernel, wifiBattery, err := energyMedians(
		pairs, "foreground-wifi", 0.20,
	)
	if err != nil {
		return matrixSummary{}, err
	}
	cellKernel, cellBattery, err := energyMedians(
		pairs, "unplugged-cellular", 0.25,
	)
	if err != nil {
		return matrixSummary{}, err
	}
	idleWakeups, err := verifyIdleWakeups(pairs)
	if err != nil {
		return matrixSummary{}, err
	}
	if _, err := validateEvidenceVerifier(
		verifierPath,
		expectedEvidenceVerifierSHA256,
	); err != nil {
		return matrixSummary{}, errors.New(
			"evidence verifier changed during matrix verification",
		)
	}
	return matrixSummary{
		Pairs:                        len(pairs),
		FullFsyncEvidenceRuns:        fullFsyncEvidenceRuns,
		FsyncOnlyEvidenceRuns:        fsyncOnlyEvidenceRuns,
		WiFiKernelMedianOverhead:     wifiKernel,
		WiFiBatteryMedianOverhead:    wifiBattery,
		CellKernelMedianOverhead:     cellKernel,
		CellBatteryMedianOverhead:    cellBattery,
		IdleIncrementalWakeupsSecond: idleWakeups,
		WorstHostStartLatency:        worstStartLatency,
	}, nil
}

// verifyStartReceiptBinding revalidates one run's activation receipt against
// the evidence it claims to describe, independently of the single-run
// verifier. The first-record digest is taken over the raw first line
// INCLUDING its trailing line feed, matching what the provider hashed.
//
// Wall-clock validation is DELIBERATELY NOT REPEATED HERE: this function's
// documented scope is receipt binding (nonce, timestamps, digests, and scope
// declarations). The pinned child evidenceverify validates every record's
// wallTimeUTC for canonical RFC 3339 spelling, nondecreasing ordering, and
// wall-vs-monotonic consistency. Keeping wall-clock reparse in exactly one
// place prevents the two verifiers from diverging on what they accept.
//
// SCOPE: the bound applies to host-observed Packet Tunnel activation. It is
// not a usable-connection measurement and not time-to-first-protected-packet.
func verifyStartReceiptBinding(
	base string,
	manifest matrixManifest,
	run manifestRun,
	terminal metricRecord,
	evidenceBarrier *string,
) (uint64, error) {
	content, err := readRegularWithin(
		base,
		filepath.Clean(run.StartReceipt),
		64<<10,
	)
	if err != nil {
		return 0, fmt.Errorf("read start receipt: %w", err)
	}
	var receipt startReceipt
	if err := validateStrictJSON(content, startReceiptShape); err != nil {
		return 0, fmt.Errorf("strict start receipt: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return 0, fmt.Errorf("decode start receipt: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return 0, err
	}
	if receipt.Schema != startReceiptSchema ||
		receipt.ProtocolVersion != protocolVersion ||
		receipt.MeasurementScope != startMeasurementScope {
		return 0, errors.New("start receipt schema or scope is invalid")
	}
	if !oneOf(receipt.EvidenceDurabilityBarrier, evidenceDurabilityFullFsync, evidenceDurabilityFsyncOnly) {
		return 0, errors.New("start receipt evidence durability barrier is invalid")
	}
	if receipt.ArtifactScope != startArtifactScope ||
		receipt.HostReceiptDurabilityScope != startHostReceiptDurabilityScope {
		return 0, errors.New("start receipt artifact or host-receipt scope is invalid")
	}
	*evidenceBarrier = receipt.EvidenceDurabilityBarrier
	if !validUUID(receipt.RunID) ||
		!validUUID(receipt.AttemptNonce) ||
		!lowerHex(receipt.SourceDigest, 64) ||
		!lowerHex(receipt.FirstRecordSHA256, 64) {
		return 0, errors.New("start receipt identifiers are invalid")
	}
	if receipt.RunID != terminal.RunID ||
		receipt.SourceDigest != manifest.SourceDigest ||
		receipt.EvidenceFileName != evidenceFileName(run) ||
		receipt.EvidenceFileName != terminal.RunID+".jsonl" {
		return 0, errors.New("start receipt is not bound to this run")
	}
	evidence, err := readRegularWithin(
		base,
		filepath.Clean(run.Evidence),
		maxEvidenceBytes,
	)
	if err != nil {
		return 0, err
	}
	feed := bytes.IndexByte(evidence, '\n')
	if feed < 0 {
		return 0, errors.New("evidence first record has no line feed")
	}
	firstLine := evidence[:feed+1]
	digest := sha256.Sum256(firstLine)
	// Two distinct messages on purpose: sharing one would let a verifier that
	// hashed the stripped line still satisfy a digest test by failing the
	// length check instead.
	if hex.EncodeToString(digest[:]) != receipt.FirstRecordSHA256 {
		return 0, errors.New(
			"start receipt does not pin the first evidence record",
		)
	}
	if uint64(len(firstLine)) != receipt.FirstRecordBytes {
		return 0, errors.New(
			"start receipt first-record length is invalid",
		)
	}
	if err := validateStrictJSON(
		bytes.TrimSuffix(firstLine, []byte{'\n'}),
		metricRecordShape,
	); err != nil {
		return 0, fmt.Errorf("strict first evidence record: %w", err)
	}
	var first metricRecord
	firstDecoder := json.NewDecoder(bytes.NewReader(firstLine))
	if err := firstDecoder.Decode(&first); err != nil {
		return 0, fmt.Errorf("decode first evidence record: %w", err)
	}
	if err := requireJSONEOF(firstDecoder); err != nil {
		return 0, err
	}
	if first.Event != "started" ||
		first.RunID != terminal.RunID ||
		first.SourceDigest != manifest.SourceDigest ||
		first.ArtifactDigest != manifest.ArtifactDigest ||
		first.StartAttemptNonce == nil ||
		*first.StartAttemptNonce != receipt.AttemptNonce ||
		first.StartRequestedAtMonotonicNanoseconds == nil ||
		*first.StartRequestedAtMonotonicNanoseconds !=
			receipt.RequestedAtMonotonicNanoseconds ||
		first.ProviderReceivedAtMonotonicNanoseconds == nil ||
		*first.ProviderReceivedAtMonotonicNanoseconds !=
			receipt.ProviderReceivedAtMonotonicNanoseconds {
		return 0, errors.New(
			"start receipt is not bound to the first record identity",
		)
	}
	if receipt.ProviderReceivedAtMonotonicNanoseconds <
		receipt.RequestedAtMonotonicNanoseconds ||
		receipt.ProviderReadyAtMonotonicNanoseconds <
			receipt.ProviderReceivedAtMonotonicNanoseconds ||
		receipt.HostObservedConnectedAtMonotonicNanoseconds <
			receipt.ProviderReadyAtMonotonicNanoseconds {
		return 0, errors.New("start receipt clocks are reversed")
	}
	if first.MonotonicNanoseconds <
		receipt.ProviderReceivedAtMonotonicNanoseconds ||
		first.MonotonicNanoseconds >
			receipt.ProviderReadyAtMonotonicNanoseconds {
		return 0, errors.New(
			"first record is outside the provider activation interval",
		)
	}
	providerEnd, providerCarry := bits.Add64(
		receipt.ProviderReceivedAtMonotonicNanoseconds,
		receipt.ProviderStartLatencyNanoseconds,
		0,
	)
	hostEnd, hostCarry := bits.Add64(
		receipt.RequestedAtMonotonicNanoseconds,
		receipt.HostStartLatencyNanoseconds,
		0,
	)
	if providerCarry != 0 || hostCarry != 0 {
		return 0, errors.New("start receipt latencies overflow")
	}
	if providerEnd != receipt.ProviderReadyAtMonotonicNanoseconds ||
		hostEnd != receipt.HostObservedConnectedAtMonotonicNanoseconds {
		return 0, errors.New("start receipt latencies do not match")
	}
	if receipt.HostStartLatencyNanoseconds >
		maximumHostStartLatencyNanoseconds {
		return 0, fmt.Errorf(
			"host Packet Tunnel activation %d ns exceeds %d ns",
			receipt.HostStartLatencyNanoseconds,
			uint64(maximumHostStartLatencyNanoseconds),
		)
	}
	return receipt.HostStartLatencyNanoseconds, nil
}

func readManifest(path string) (
	matrixManifest,
	string,
	[]byte,
	error,
) {
	if path == "" {
		return matrixManifest{}, "", nil, errors.New("manifest is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return matrixManifest{}, "", nil, err
	}
	base := filepath.Dir(absolute)
	content, err := readRegularWithin(
		base,
		filepath.Base(absolute),
		maxManifestBytes,
	)
	if err != nil {
		return matrixManifest{}, "", nil, fmt.Errorf("read manifest: %w", err)
	}
	if err := validateStrictJSON(content, matrixManifestShape); err != nil {
		return matrixManifest{}, "", nil, fmt.Errorf(
			"strict manifest: %w", err,
		)
	}
	var manifest matrixManifest
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return matrixManifest{}, "", nil, fmt.Errorf("decode manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return matrixManifest{}, "", nil, err
	}
	return manifest, base, content, nil
}

func evidenceFileName(run manifestRun) string {
	if run.originalEvidenceFileName != "" {
		return run.originalEvidenceFileName
	}
	return filepath.Base(run.Evidence)
}

func validateManifestHeader(manifest matrixManifest) error {
	if manifest.Schema != manifestSchema ||
		manifest.ProtocolVersion != protocolVersion ||
		!boundDigest(manifest.SourceDigest) ||
		!boundDigest(manifest.ArtifactDigest) ||
		manifest.OSVersion == "" ||
		manifest.HardwareModel == "" ||
		len(manifest.Runs) < 1 || len(manifest.Runs) > 128 {
		return errors.New("manifest header or run count is invalid")
	}
	return nil
}

func validateManifestRun(run manifestRun) error {
	clean := filepath.Clean(run.Evidence)
	if run.Evidence == "" || filepath.IsAbs(run.Evidence) ||
		clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
		!lowerHex(run.EvidenceSHA256, 64) ||
		!oneOf(run.Mode, "core-baseline", "maximum-privacy") ||
		!oneOf(run.TrafficProfile, "idle", "low", "medium", "saturated") ||
		!oneOf(run.CoverSemantics, "continuousWhileConnected", "activityWithThirtySecondTail") ||
		!oneOf(run.RotationCadence, "protocol-15m", "accelerated-allocation") ||
		!oneOf(
			run.TestCondition,
			"foreground-wifi", "locked-wifi", "unplugged-cellular",
			"low-power-mode", "accelerated-allocation",
			"eight-hour-locked", "stop-latency",
		) ||
		!validUUID(run.PairID) ||
		run.Repeat < 1 || run.Repeat > 20 ||
		!oneOfUint64(run.DurationSeconds, 60, 300, 1_800, 28_800) ||
		!oneOf(run.ExpectedTerminal, "completed", "stop-acknowledged") ||
		!oneOf(run.LowPowerMode, "on", "off") ||
		!oneOf(run.StartThermal, "nominal", "fair", "serious") {
		return errors.New("run selectors are invalid")
	}
	if (run.BatteryStartBasisPoints == nil) !=
		(run.BatteryEndBasisPoints == nil) {
		return errors.New("battery start and end must be present together")
	}
	if run.BatteryStartBasisPoints != nil &&
		(*run.BatteryStartBasisPoints > 10_000 ||
			*run.BatteryEndBasisPoints > 10_000 ||
			*run.BatteryStartBasisPoints <= *run.BatteryEndBasisPoints) {
		return errors.New("battery basis points must show positive discharge")
	}
	if run.ExpectedTerminal == "stop-acknowledged" {
		cleanReceipt := filepath.Clean(run.StopReceipt)
		if run.StopReceipt == "" ||
			filepath.IsAbs(run.StopReceipt) ||
			cleanReceipt == "." || cleanReceipt == ".." ||
			strings.HasPrefix(
				cleanReceipt,
				".."+string(filepath.Separator),
			) ||
			!lowerHex(run.StopReceiptSHA256, 64) {
			return errors.New("stop receipt path or digest is invalid")
		}
	} else if run.StopReceipt != "" ||
		run.StopReceiptSHA256 != "" {
		return errors.New("non-Stop run includes a Stop receipt")
	}
	// Every run, not only the Stop run, must carry its activation receipt.
	cleanStart := filepath.Clean(run.StartReceipt)
	if run.StartReceipt == "" ||
		filepath.IsAbs(run.StartReceipt) ||
		cleanStart == "." || cleanStart == ".." ||
		strings.HasPrefix(
			cleanStart,
			".."+string(filepath.Separator),
		) ||
		!lowerHex(run.StartReceiptSHA256, 64) {
		return errors.New("start receipt path or digest is invalid")
	}
	return nil
}

func validateEvidenceVerifier(
	path string,
	expectedDigest string,
) (string, error) {
	if path == "" || !boundDigest(expectedDigest) {
		return "", errors.New(
			"pinned evidence verifier path and SHA-256 are required",
		)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect evidence verifier: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o111 == 0 ||
		info.Size() < 1 ||
		info.Size() > 64<<20 {
		return "", errors.New(
			"evidence verifier is not a bounded executable regular file",
		)
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(absolute))
	if err != nil {
		return "", err
	}
	defer file.Close()
	content, err := readOpenRegular(file, 64<<20)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return "", errors.New("evidence verifier SHA-256 mismatch")
	}
	return absolute, nil
}

func sealEvidenceVerifier(
	verifiedPath string,
	expectedDigest string,
) (string, func(), error) {
	root, err := os.OpenRoot(filepath.Dir(verifiedPath))
	if err != nil {
		return "", func() {}, err
	}
	content, err := func() ([]byte, error) {
		defer root.Close()
		file, openErr := root.Open(filepath.Base(verifiedPath))
		if openErr != nil {
			return nil, openErr
		}
		defer file.Close()
		return readOpenRegular(file, 64<<20)
	}()
	if err != nil {
		return "", func() {}, err
	}
	contentDigest := sha256.Sum256(content)
	if hex.EncodeToString(contentDigest[:]) != expectedDigest {
		return "", func() {}, errors.New(
			"evidence verifier changed before it could be sealed",
		)
	}
	directory, err := os.MkdirTemp(
		"",
		"winn-ios-evidenceverify-sealed-",
	)
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() {
		_ = os.RemoveAll(directory)
	}
	sealedPath := filepath.Join(directory, "evidenceverify")
	sealedRoot, err := os.OpenRoot(directory)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	file, err := sealedRoot.OpenFile(
		"evidenceverify",
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		_ = sealedRoot.Close()
		cleanup()
		return "", func() {}, err
	}
	written := 0
	for err == nil && written < len(content) {
		var count int
		count, err = file.Write(content[written:])
		if err == nil && count == 0 {
			err = errors.New("sealed verifier write made no progress")
		}
		written += count
	}
	if err == nil {
		err = file.Chmod(0o500)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	rootCloseErr := sealedRoot.Close()
	if err == nil {
		err = rootCloseErr
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := syncDirectoryWithin(directory, "."); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return sealedPath, cleanup, nil
}

func runEvidenceVerifier(
	verifierPath string,
	base string,
	manifest matrixManifest,
	run manifestRun,
) error {
	evidencePath := filepath.Join(base, filepath.Clean(run.Evidence))
	arguments := []string{
		"-evidence", evidencePath,
		"-expected-source-digest", manifest.SourceDigest,
		"-expected-artifact-digest", manifest.ArtifactDigest,
		"-expected-mode", run.Mode,
		"-expected-profile", run.TrafficProfile,
		"-expected-cover", run.CoverSemantics,
		"-expected-rotation", run.RotationCadence,
		"-expected-condition", run.TestCondition,
		"-expected-pair-id", run.PairID,
		"-expected-os-version", manifest.OSVersion,
		"-expected-hardware-model", manifest.HardwareModel,
		"-expected-low-power-mode", run.LowPowerMode,
		"-expected-start-thermal", run.StartThermal,
		"-expected-duration-seconds",
		fmt.Sprintf("%d", run.DurationSeconds),
		"-expected-terminal", run.ExpectedTerminal,
	}
	if run.ExpectedTerminal == "stop-acknowledged" {
		receiptContent, err := readRegularWithin(
			base,
			filepath.Clean(run.StopReceipt),
			64<<10,
		)
		if err != nil {
			return fmt.Errorf("read Stop receipt: %w", err)
		}
		digest := sha256.Sum256(receiptContent)
		if hex.EncodeToString(digest[:]) != run.StopReceiptSHA256 {
			return errors.New("stop receipt SHA-256 mismatch")
		}
		if err := validateStrictJSON(
			receiptContent, stopReceiptShape,
		); err != nil {
			return fmt.Errorf("strict Stop receipt: %w", err)
		}
		arguments = append(
			arguments,
			"-stop-receipt",
			filepath.Join(base, filepath.Clean(run.StopReceipt)),
		)
	}
	startReceiptContent, err := readRegularWithin(
		base,
		filepath.Clean(run.StartReceipt),
		64<<10,
	)
	if err != nil {
		return fmt.Errorf("read start receipt: %w", err)
	}
	startDigest := sha256.Sum256(startReceiptContent)
	if hex.EncodeToString(startDigest[:]) != run.StartReceiptSHA256 {
		return errors.New("start receipt SHA-256 mismatch")
	}
	arguments = append(
		arguments,
		"-start-receipt",
		filepath.Join(base, filepath.Clean(run.StartReceipt)),
	)
	if (run.TestCondition == "foreground-wifi" ||
		run.TestCondition == "unplugged-cellular") &&
		(run.TrafficProfile == "low" ||
			run.TrafficProfile == "medium") {
		arguments = append(arguments, "-require-energy")
	}
	if run.TrafficProfile == "idle" {
		arguments = append(arguments, "-require-wakeups")
	}
	// #nosec G204 -- the executable is copied into a private immutable
	// snapshot after the caller-pinned SHA-256 is checked.
	command := exec.Command(verifierPath, arguments...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	if err != nil {
		return fmt.Errorf(
			"rejected evidence: %v: stdout=%q stderr=%q",
			err,
			stdout.String(),
			stderr.String(),
		)
	}
	if stderr.Len() != 0 {
		return fmt.Errorf(
			"verifier wrote stderr on success: %q", stderr.String(),
		)
	}
	if !canonicalEvidencePass.Match(stdout.Bytes()) {
		return fmt.Errorf(
			"verifier returned a non-canonical PASS receipt: %q",
			stdout.String(),
		)
	}
	return nil
}

func recheckEvidenceDigest(base string, run manifestRun) error {
	content, err := readRegularWithin(
		base,
		filepath.Clean(run.Evidence),
		maxEvidenceBytes,
	)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != run.EvidenceSHA256 {
		return errors.New(
			"evidence changed while the single-run verifier executed",
		)
	}
	return nil
}

func readAndCheckEvidence(
	base string,
	manifest matrixManifest,
	run manifestRun,
) (metricRecord, error) {
	content, err := readRegularWithin(
		base,
		filepath.Clean(run.Evidence),
		maxEvidenceBytes,
	)
	if err != nil {
		return metricRecord{}, fmt.Errorf("read evidence: %w", err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != run.EvidenceSHA256 {
		return metricRecord{}, errors.New("evidence SHA-256 mismatch")
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	var terminal metricRecord
	records := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			return metricRecord{}, errors.New("evidence contains blank line")
		}
		if err := validateStrictJSON(line, metricRecordShape); err != nil {
			return metricRecord{}, fmt.Errorf(
				"strict evidence record %d: %w", records+1, err,
			)
		}
		var record metricRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return metricRecord{}, fmt.Errorf("decode evidence record: %w", err)
		}
		terminal = record
		records++
	}
	if err := scanner.Err(); err != nil {
		return metricRecord{}, err
	}
	if records < 2 || terminal.DataPath == nil ||
		terminal.WholeRunResourceWindow == nil {
		return metricRecord{}, errors.New("evidence lacks terminal data/resources")
	}
	if terminal.Schema != evidenceSchema ||
		terminal.ProtocolVersion != protocolVersion ||
		terminal.Platform != "ios" ||
		terminal.OSVersion != manifest.OSVersion ||
		terminal.HardwareModel != manifest.HardwareModel ||
		terminal.SourceDigest != manifest.SourceDigest ||
		terminal.ArtifactDigest != manifest.ArtifactDigest ||
		terminal.Event != run.ExpectedTerminal ||
		terminal.Mode != run.Mode ||
		terminal.TrafficProfile != run.TrafficProfile ||
		terminal.CoverSemantics != run.CoverSemantics ||
		terminal.RotationCadence != run.RotationCadence ||
		terminal.TestCondition != run.TestCondition ||
		terminal.PairID != run.PairID ||
		terminal.DurationNanoseconds != run.DurationSeconds*1_000_000_000 {
		return metricRecord{}, errors.New("terminal record does not match manifest")
	}
	if !validUUID(terminal.RunID) {
		return metricRecord{}, errors.New("terminal run ID is invalid")
	}
	return terminal, nil
}

func formPairs(
	runs []checkedRun,
) ([]matchedPair, []checkedRun, error) {
	pairRuns := make(map[string][]checkedRun)
	var singles []checkedRun
	for _, run := range runs {
		switch run.manifest.TestCondition {
		case "foreground-wifi", "locked-wifi", "unplugged-cellular":
			pairRuns[run.manifest.PairID] =
				append(pairRuns[run.manifest.PairID], run)
		default:
			singles = append(singles, run)
		}
	}
	pairs := make([]matchedPair, 0, len(pairRuns))
	for pairID, group := range pairRuns {
		if len(group) != 2 {
			return nil, nil, fmt.Errorf(
				"pair %s has %d runs, want 2", pairID, len(group),
			)
		}
		var pair matchedPair
		for _, run := range group {
			if run.manifest.Mode == "core-baseline" {
				pair.core = run
			} else {
				pair.privacy = run
			}
		}
		if pair.core.manifest.Evidence == "" ||
			pair.privacy.manifest.Evidence == "" {
			return nil, nil, fmt.Errorf(
				"pair %s does not contain one run of each mode", pairID,
			)
		}
		if err := verifyPair(pair); err != nil {
			return nil, nil, fmt.Errorf("pair %s: %w", pairID, err)
		}
		pairs = append(pairs, pair)
	}
	return pairs, singles, nil
}

func verifyPair(pair matchedPair) error {
	core := pair.core
	privacy := pair.privacy
	if core.manifest.TrafficProfile != privacy.manifest.TrafficProfile ||
		core.manifest.CoverSemantics != privacy.manifest.CoverSemantics ||
		core.manifest.RotationCadence != privacy.manifest.RotationCadence ||
		core.manifest.TestCondition != privacy.manifest.TestCondition ||
		core.manifest.Repeat != privacy.manifest.Repeat ||
		core.manifest.DurationSeconds != privacy.manifest.DurationSeconds ||
		core.manifest.ExpectedTerminal != privacy.manifest.ExpectedTerminal ||
		core.manifest.LowPowerMode != privacy.manifest.LowPowerMode ||
		core.manifest.StartThermal != privacy.manifest.StartThermal {
		return errors.New("A/B selectors are not identical")
	}
	if core.terminal.DataPath.CommonPathUnits !=
		privacy.terminal.DataPath.CommonPathUnits ||
		core.terminal.DataPath.CommonPathActiveNanoseconds !=
			privacy.terminal.DataPath.CommonPathActiveNanoseconds ||
		core.terminal.DataPath.CommonPathChecksum !=
			privacy.terminal.DataPath.CommonPathChecksum {
		return errors.New("A/B common-path workload differs")
	}
	return nil
}

func verifyRequiredCoverage(
	pairs []matchedPair,
	singles []checkedRun,
) error {
	required := map[string]int{
		"foreground-wifi/idle":      1,
		"foreground-wifi/low":       3,
		"foreground-wifi/medium":    3,
		"foreground-wifi/saturated": 1,
		"locked-wifi/low":           1,
		"locked-wifi/medium":        1,
		"unplugged-cellular/low":    3,
		"unplugged-cellular/medium": 3,
	}
	counts := make(map[string]int)
	repeats := make(map[string]map[int]struct{})
	for _, pair := range pairs {
		m := pair.core.manifest
		expectedDuration := uint64(1_800)
		if m.TrafficProfile == "idle" {
			expectedDuration = 300
		}
		if m.ExpectedTerminal != "completed" ||
			m.CoverSemantics != "continuousWhileConnected" ||
			m.RotationCadence != "protocol-15m" ||
			m.LowPowerMode != "off" ||
			m.StartThermal != "nominal" ||
			m.DurationSeconds != expectedDuration {
			return fmt.Errorf(
				"%s/%s repeat %d is not a canonical completed matrix pair",
				m.TestCondition, m.TrafficProfile, m.Repeat,
			)
		}
		key := pair.core.manifest.TestCondition + "/" +
			pair.core.manifest.TrafficProfile
		counts[key]++
		if repeats[key] == nil {
			repeats[key] = make(map[int]struct{})
		}
		repeat := pair.core.manifest.Repeat
		if _, exists := repeats[key][repeat]; exists {
			return fmt.Errorf("%s has duplicate repeat %d", key, repeat)
		}
		repeats[key][repeat] = struct{}{}
	}
	for key, minimum := range required {
		if counts[key] < minimum {
			return fmt.Errorf(
				"declared-condition coverage %s=%d pairs, want at least %d",
				key, counts[key], minimum,
			)
		}
	}

	standalone := map[string]bool{}
	for _, run := range singles {
		m := run.manifest
		switch {
		case m.TestCondition == "low-power-mode" &&
			m.Mode == "maximum-privacy" &&
			m.TrafficProfile == "low" &&
			m.CoverSemantics == "continuousWhileConnected" &&
			m.RotationCadence == "protocol-15m" &&
			m.DurationSeconds == 1_800 &&
			m.ExpectedTerminal == "completed" &&
			m.LowPowerMode == "on" &&
			m.StartThermal == "nominal" &&
			run.terminal.WholeRunResourceWindow.LowPowerModeAlwaysEnabled:
			standalone["low-power-mode"] = true
		case m.TestCondition == "accelerated-allocation" &&
			m.Mode == "maximum-privacy" &&
			m.TrafficProfile == "low" &&
			m.CoverSemantics == "continuousWhileConnected" &&
			m.RotationCadence == "accelerated-allocation" &&
			m.DurationSeconds == 60 &&
			m.ExpectedTerminal == "completed" &&
			m.LowPowerMode == "off" &&
			m.StartThermal == "nominal" &&
			run.terminal.DataPath.RotationCount >= 500:
			standalone["accelerated-allocation"] = true
		case m.TestCondition == "eight-hour-locked" &&
			m.Mode == "maximum-privacy" &&
			m.TrafficProfile == "low" &&
			m.CoverSemantics == "continuousWhileConnected" &&
			m.RotationCadence == "protocol-15m" &&
			m.DurationSeconds == 28_800 &&
			m.ExpectedTerminal == "completed" &&
			m.LowPowerMode == "off" &&
			m.StartThermal == "nominal":
			standalone["eight-hour-locked"] = true
		case m.TestCondition == "stop-latency" &&
			m.Mode == "maximum-privacy" &&
			m.TrafficProfile == "idle" &&
			m.CoverSemantics == "continuousWhileConnected" &&
			m.RotationCadence == "protocol-15m" &&
			m.DurationSeconds == 60 &&
			m.ExpectedTerminal == "stop-acknowledged" &&
			m.LowPowerMode == "off" &&
			m.StartThermal == "nominal":
			standalone["stop-latency"] = true
		}
	}
	for _, condition := range []string{
		"low-power-mode",
		"accelerated-allocation",
		"eight-hour-locked",
		"stop-latency",
	} {
		if !standalone[condition] {
			return fmt.Errorf("required %s evidence is absent", condition)
		}
	}
	return nil
}

func energyMedians(
	pairs []matchedPair,
	condition string,
	limit float64,
) (float64, float64, error) {
	kernelOverheads := map[string][]float64{
		"low": {}, "medium": {},
	}
	batteryOverheads := map[string][]float64{
		"low": {}, "medium": {},
	}
	durations := make(map[string]uint64)
	for _, pair := range pairs {
		m := pair.core.manifest
		if m.TestCondition != condition ||
			(m.TrafficProfile != "low" &&
				m.TrafficProfile != "medium") {
			continue
		}
		if previous, exists := durations[m.TrafficProfile]; exists &&
			previous != m.DurationSeconds {
			return 0, 0, fmt.Errorf(
				"%s/%s energy durations differ",
				condition, m.TrafficProfile,
			)
		}
		durations[m.TrafficProfile] = m.DurationSeconds
		coreEnergy := pair.core.terminal.
			WholeRunResourceWindow.EnergyDeltaNanojoules
		privacyEnergy := pair.privacy.terminal.
			WholeRunResourceWindow.EnergyDeltaNanojoules
		if coreEnergy == nil || privacyEnergy == nil ||
			*coreEnergy == 0 || *privacyEnergy == 0 {
			return 0, 0, fmt.Errorf(
				"%s/%s repeat %d lacks task energy",
				condition, m.TrafficProfile, m.Repeat,
			)
		}
		if !m.Unplugged || !pair.privacy.manifest.Unplugged {
			return 0, 0, fmt.Errorf(
				"%s/%s repeat %d was not unplugged",
				condition, m.TrafficProfile, m.Repeat,
			)
		}
		coreDrain, err := batteryDrain(m)
		if err != nil {
			return 0, 0, err
		}
		privacyDrain, err := batteryDrain(pair.privacy.manifest)
		if err != nil {
			return 0, 0, err
		}
		kernelOverheads[m.TrafficProfile] = append(
			kernelOverheads[m.TrafficProfile],
			overhead(*privacyEnergy, *coreEnergy),
		)
		batteryOverheads[m.TrafficProfile] = append(
			batteryOverheads[m.TrafficProfile],
			overhead(privacyDrain, coreDrain),
		)
	}
	worstKernelMedian := -math.MaxFloat64
	worstBatteryMedian := -math.MaxFloat64
	for _, profile := range []string{"low", "medium"} {
		if len(kernelOverheads[profile]) < 3 ||
			len(batteryOverheads[profile]) < 3 {
			return 0, 0, fmt.Errorf(
				"%s/%s has %d energy pairs, want at least 3",
				condition, profile, len(kernelOverheads[profile]),
			)
		}
		kernelMedian := median(kernelOverheads[profile])
		batteryMedian := median(batteryOverheads[profile])
		if kernelMedian > limit {
			return 0, 0, fmt.Errorf(
				"%s/%s median task-energy overhead %.4f exceeds %.2f",
				condition, profile, kernelMedian, limit,
			)
		}
		worstKernelMedian = max(worstKernelMedian, kernelMedian)
		worstBatteryMedian = max(worstBatteryMedian, batteryMedian)
	}
	return worstKernelMedian, worstBatteryMedian, nil
}

func verifyIdleWakeups(pairs []matchedPair) (float64, error) {
	found := 0
	worst := float64(0)
	for _, pair := range pairs {
		m := pair.core.manifest
		if m.TestCondition != "foreground-wifi" ||
			m.TrafficProfile != "idle" {
			continue
		}
		if m.CoverSemantics != "continuousWhileConnected" ||
			m.DurationSeconds < 300 {
			return 0, errors.New(
				"idle wakeup pair must be continuous and at least five minutes",
			)
		}
		core, err := totalWakeups(
			pair.core.terminal.WholeRunResourceWindow,
		)
		if err != nil {
			return 0, err
		}
		privacy, err := totalWakeups(
			pair.privacy.terminal.WholeRunResourceWindow,
		)
		if err != nil {
			return 0, err
		}
		incremental := uint64(0)
		if privacy > core {
			incremental = privacy - core
		}
		perSecond := float64(incremental) /
			float64(m.DurationSeconds)
		if perSecond > 1.5 {
			return 0, fmt.Errorf(
				"idle incremental wakeups %.4f/s exceed 1.5/s",
				perSecond,
			)
		}
		found++
		worst = max(worst, perSecond)
	}
	if found == 0 {
		return 0, errors.New("idle wakeup pair is absent")
	}
	return worst, nil
}

func totalWakeups(window *resourceWindow) (uint64, error) {
	if window.InterruptWakeupDelta == nil ||
		window.PackageIdleWakeupDelta == nil ||
		math.MaxUint64-*window.InterruptWakeupDelta <
			*window.PackageIdleWakeupDelta {
		return 0, errors.New("wakeup counters are absent or overflow")
	}
	return *window.InterruptWakeupDelta +
		*window.PackageIdleWakeupDelta, nil
}

func batteryDrain(run manifestRun) (uint64, error) {
	if run.BatteryStartBasisPoints == nil ||
		run.BatteryEndBasisPoints == nil {
		return 0, fmt.Errorf(
			"%s/%s repeat %d lacks battery observations",
			run.TestCondition, run.TrafficProfile, run.Repeat,
		)
	}
	return *run.BatteryStartBasisPoints -
		*run.BatteryEndBasisPoints, nil
}

func overhead(test, baseline uint64) float64 {
	return float64(test)/float64(baseline) - 1
}

func median(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

func readRegularWithin(
	base string,
	name string,
	maximum int64,
) ([]byte, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("input path must not be a symbolic link")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readOpenRegular(file, maximum)
}

func readOpenRegular(
	file *os.File,
	maximum int64,
) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 ||
		info.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, errors.New("file exceeds size limit")
	}
	return content, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("manifest contains trailing JSON")
		}
		return err
	}
	return nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func boundDigest(value string) bool {
	return lowerHex(value, 64) &&
		value != strings.Repeat("0", 64)
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range []byte(value) {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f')) {
				return false
			}
		}
	}
	return true
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func oneOfUint64(value uint64, choices ...uint64) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
