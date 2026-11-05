// Command evidenceverify independently checks one collected physical-iPhone
// Stage A JSONL run against the frozen Winn v3 feasibility gates.
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
	"path/filepath"
	"strings"
)

const (
	schemaVersion       = "winn-ios-privacy-spike/3"
	protocolVersion     = "winn/3"
	frameVersion        = "WCF3"
	privacyCellBytes    = 1_024
	privacyPayloadBytes = 960
	ringCapacity        = 512
	maximumCircuits     = 2
	privacyPoolBytes    = 2_097_152

	// Start-latency evidence. The bound applies to the host-observed
	// activation interval only. It is NOT a usable-connection measurement and
	// NOT time-to-first-protected-packet; the Stage A provider installs a
	// synthetic RFC 2544 route, performs no handshake, and forwards nothing.
	startReceiptSchema                 = "winn-ios-privacy-spike-start-receipt/2"
	startMeasurementScope              = "ios-packet-tunnel-activation-only"
	startArtifactScope                 = "activation-observation-not-attempt-success-or-persistence-timing"
	startHostReceiptDurabilityScope    = "host-receipt-barrier-not-encoded-no-power-loss-claim"
	evidenceDurabilityFullFsync        = "f-fullfsync"
	evidenceDurabilityFsyncOnly        = "fsync-only"
	maximumHostStartLatencyNanoseconds = 3_000_000_000
	minimumFirstRecordBytes            = 2
	maximumFirstRecordBytes            = 1 << 20
)

type options struct {
	evidence                string
	evidenceFileName        string
	expectedSource          string
	expectedArtifact        string
	expectedMode            string
	expectedProfile         string
	expectedCover           string
	expectedRotation        string
	expectedCondition       string
	expectedPairID          string
	expectedOSVersion       string
	expectedHardwareModel   string
	expectedLowPowerMode    string
	expectedStartThermal    string
	expectedDurationSeconds uint64
	expectedTerminal        string
	stopReceipt             string
	startReceipt            string
	requireEnergy           bool
	requireWakeups          bool
}

type constantsSnapshot struct {
	CellBytes                  int    `json:"cellBytes"`
	PayloadBytes               int    `json:"payloadBytes"`
	RingCapacityPerDirection   int    `json:"ringCapacityPerDirection"`
	MaximumCircuits            int    `json:"maximumCircuits"`
	ShuffleNanoseconds         uint64 `json:"shuffleNanoseconds"`
	CoverIntervalNanoseconds   uint64 `json:"coverIntervalNanoseconds"`
	CoverTailNanoseconds       uint64 `json:"coverTailNanoseconds"`
	CircuitRotationNanoseconds uint64 `json:"circuitRotationNanoseconds"`
	SpikeOverlapNanoseconds    uint64 `json:"spikeOverlapNanoseconds"`
}

type resourceSnapshot struct {
	ResidentBytes          *uint64 `json:"residentBytes,omitempty"`
	PhysicalFootprintBytes *uint64 `json:"physicalFootprintBytes,omitempty"`
	AvailableProcessBytes  *uint64 `json:"availableProcessBytes,omitempty"`
	UserCPUNanoseconds     *uint64 `json:"userCPUNanoseconds,omitempty"`
	SystemCPUNanoseconds   *uint64 `json:"systemCPUNanoseconds,omitempty"`
	InterruptWakeups       *uint64 `json:"interruptWakeups,omitempty"`
	PackageIdleWakeups     *uint64 `json:"packageIdleWakeups,omitempty"`
	EnergyNanojoules       *uint64 `json:"energyNanojoules,omitempty"`
	ThermalState           *string `json:"thermalState,omitempty"`
	LowPowerMode           *bool   `json:"lowPowerMode,omitempty"`
}

type resourceWindow struct {
	FirstSampleMonotonicNanoseconds uint64  `json:"firstSampleMonotonicNanoseconds"`
	LastSampleMonotonicNanoseconds  uint64  `json:"lastSampleMonotonicNanoseconds"`
	SampleCount                     uint64  `json:"sampleCount"`
	ScheduledSampleCount            uint64  `json:"scheduledSampleCount"`
	PeakResidentBytes               *uint64 `json:"peakResidentBytes,omitempty"`
	PeakPhysicalFootprintBytes      *uint64 `json:"peakPhysicalFootprintBytes,omitempty"`
	MinimumAvailableProcessBytes    *uint64 `json:"minimumAvailableProcessBytes,omitempty"`
	UserCPUDeltaNanoseconds         *uint64 `json:"userCPUDeltaNanoseconds,omitempty"`
	SystemCPUDeltaNanoseconds       *uint64 `json:"systemCPUDeltaNanoseconds,omitempty"`
	InterruptWakeupDelta            *uint64 `json:"interruptWakeupDelta,omitempty"`
	PackageIdleWakeupDelta          *uint64 `json:"packageIdleWakeupDelta,omitempty"`
	EnergyDeltaNanojoules           *uint64 `json:"energyDeltaNanojoules,omitempty"`
	WorstThermalState               *string `json:"worstThermalState,omitempty"`
	LowPowerModeObserved            bool    `json:"lowPowerModeObserved"`
	LowPowerModeAlwaysEnabled       bool    `json:"lowPowerModeAlwaysEnabled"`
}

type dataPathSnapshot struct {
	AllocatedPrivacyCellBytes            int     `json:"allocatedPrivacyCellBytes"`
	InboundQueueDepth                    int     `json:"inboundQueueDepth"`
	OutboundQueueDepth                   int     `json:"outboundQueueDepth"`
	InboundHighWatermark                 int     `json:"inboundHighWatermark"`
	OutboundHighWatermark                int     `json:"outboundHighWatermark"`
	OccupancySamples                     uint64  `json:"occupancySamples"`
	InboundOccupancyP99Cells             int     `json:"inboundOccupancyP99Cells"`
	OutboundOccupancyP99Cells            int     `json:"outboundOccupancyP99Cells"`
	AcceptedCells                        uint64  `json:"acceptedCells"`
	EmittedCells                         uint64  `json:"emittedCells"`
	DroppedCells                         uint64  `json:"droppedCells"`
	RetiredDataCells                     uint64  `json:"retiredDataCells"`
	RetiredCoverCells                    uint64  `json:"retiredCoverCells"`
	CommonPathUnits                      uint64  `json:"commonPathUnits"`
	CommonPathActiveNanoseconds          uint64  `json:"commonPathActiveNanoseconds"`
	CommonPathChecksum                   uint64  `json:"commonPathChecksum"`
	CoverPairsAccepted                   uint64  `json:"coverPairsAccepted"`
	CoverInboundCellsAccepted            uint64  `json:"coverInboundCellsAccepted"`
	CoverOutboundCellsAccepted           uint64  `json:"coverOutboundCellsAccepted"`
	CoverPairsEmitted                    uint64  `json:"coverPairsEmitted"`
	CoverInboundCellsEmitted             uint64  `json:"coverInboundCellsEmitted"`
	CoverOutboundCellsEmitted            uint64  `json:"coverOutboundCellsEmitted"`
	CoverInboundCellsPending             int     `json:"coverInboundCellsPending"`
	CoverOutboundCellsPending            int     `json:"coverOutboundCellsPending"`
	CoverInboundCellsRetired             uint64  `json:"coverInboundCellsRetired"`
	CoverOutboundCellsRetired            uint64  `json:"coverOutboundCellsRetired"`
	CoverDeadlinesMissed                 uint64  `json:"coverDeadlinesMissed"`
	MaximumCoverLatenessNanoseconds      uint64  `json:"maximumCoverLatenessNanoseconds"`
	QueueDelaySamples                    uint64  `json:"queueDelaySamples"`
	QueueDelayP99UpperBoundNanoseconds   uint64  `json:"queueDelayP99UpperBoundNanoseconds"`
	QueueDelayOver25Milliseconds         uint64  `json:"queueDelayOver25Milliseconds"`
	MaximumObservedQueueDelayNanoseconds uint64  `json:"maximumObservedQueueDelayNanoseconds"`
	UnaccountedWorkNanoseconds           uint64  `json:"unaccountedWorkNanoseconds"`
	BackpressureEvents                   uint64  `json:"backpressureEvents"`
	BackpressuredCells                   uint64  `json:"backpressuredCells"`
	RotationCount                        uint64  `json:"rotationCount"`
	MaximumRotationOverlapNanoseconds    uint64  `json:"maximumRotationOverlapNanoseconds"`
	RotationActiveCircuit                *int    `json:"rotationActiveCircuit,omitempty"`
	RotationStandbyCircuit               *int    `json:"rotationStandbyCircuit,omitempty"`
	RotationOverlapDeadlineNanoseconds   *uint64 `json:"rotationOverlapDeadlineNanoseconds,omitempty"`
}

type rotationResources struct {
	Samples                            uint64  `json:"samples"`
	LastRotationCount                  uint64  `json:"lastRotationCount"`
	FirstTenPeakResidentBytes          *uint64 `json:"firstTenPeakResidentBytes,omitempty"`
	FirstTenPeakPhysicalFootprintBytes *uint64 `json:"firstTenPeakPhysicalFootprintBytes,omitempty"`
	PostTenPeakResidentBytes           *uint64 `json:"postTenPeakResidentBytes,omitempty"`
	PostTenPeakPhysicalFootprintBytes  *uint64 `json:"postTenPeakPhysicalFootprintBytes,omitempty"`
}

type metricRecord struct {
	Schema                    string             `json:"schema"`
	ProtocolVersion           string             `json:"protocolVersion"`
	FrameVersion              string             `json:"frameVersion"`
	Platform                  string             `json:"platform"`
	OSVersion                 string             `json:"osVersion"`
	HardwareModel             string             `json:"hardwareModel"`
	RunID                     string             `json:"runID"`
	Event                     string             `json:"event"`
	MonotonicNanoseconds      uint64             `json:"monotonicNanoseconds"`
	WallTimeUTC               string             `json:"wallTimeUTC"`
	Mode                      string             `json:"mode"`
	TrafficProfile            string             `json:"trafficProfile"`
	CoverSemantics            string             `json:"coverSemantics"`
	RotationCadence           string             `json:"rotationCadence"`
	TestCondition             string             `json:"testCondition"`
	PairID                    string             `json:"pairID"`
	DurationNanoseconds       uint64             `json:"durationNanoseconds"`
	TrafficActiveNanoseconds  uint64             `json:"trafficActiveNanoseconds"`
	SourceDigest              string             `json:"sourceDigest"`
	ArtifactDigest            string             `json:"artifactDigest"`
	Constants                 constantsSnapshot  `json:"constants"`
	Resources                 *resourceSnapshot  `json:"resources,omitempty"`
	ResourceWindow            *resourceWindow    `json:"resourceWindow,omitempty"`
	WholeRunResourceWindow    *resourceWindow    `json:"wholeRunResourceWindow,omitempty"`
	DataPath                  *dataPathSnapshot  `json:"dataPath,omitempty"`
	RotationResources         *rotationResources `json:"rotationResources,omitempty"`
	ControlLatencyNanoseconds *uint64            `json:"controlLatencyNanoseconds,omitempty"`
	// Present only on the first `started` record, which is the record the
	// host start receipt pins byte-for-byte.
	StartAttemptNonce                      *string `json:"startAttemptNonce,omitempty"`
	StartRequestedAtMonotonicNanoseconds   *uint64 `json:"startRequestedAtMonotonicNanoseconds,omitempty"`
	ProviderReceivedAtMonotonicNanoseconds *uint64 `json:"providerReceivedAtMonotonicNanoseconds,omitempty"`
	FailureCode                            *string `json:"failureCode,omitempty"`
}

type verificationSummary struct {
	Records                     int
	RunID                       string
	ArtifactDigest              string
	EvidenceDurabilityBarrier   string
	ResidentSlopeBytesHour      float64
	EnergyDeltaNanojoules       uint64
	EnergyAvailable             bool
	HostStartLatencyNanoseconds uint64
}

// startReceipt is the host's structured acceptance receipt for one Packet
// Tunnel activation attempt. Every field is revalidated here; the offline
// verifier intentionally enforces exact semantics rather than JSON key order
// or whitespace.
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

type stopReceipt struct {
	Schema                                     string `json:"schema"`
	ProtocolVersion                            string `json:"protocolVersion"`
	RunID                                      string `json:"runID"`
	EvidenceFileName                           string `json:"evidenceFileName"`
	EvidenceSHA256                             string `json:"evidenceSHA256"`
	RequestedAtMonotonicNanoseconds            uint64 `json:"requestedAtMonotonicNanoseconds"`
	ProviderReceivedAtMonotonicNanoseconds     uint64 `json:"providerReceivedAtMonotonicNanoseconds"`
	ProviderAcknowledgedAtMonotonicNanoseconds uint64 `json:"providerAcknowledgedAtMonotonicNanoseconds"`
	HostReceivedAtMonotonicNanoseconds         uint64 `json:"hostReceivedAtMonotonicNanoseconds"`
	RoundTripNanoseconds                       uint64 `json:"roundTripNanoseconds"`
}

func main() {
	cfg := options{}
	flag.StringVar(&cfg.evidence, "evidence", "", "collected Stage A JSONL")
	flag.StringVar(&cfg.expectedSource, "expected-source-digest", "", "required source digest")
	flag.StringVar(
		&cfg.expectedArtifact,
		"expected-artifact-digest",
		"",
		"required Packet Tunnel provider executable digest",
	)
	flag.StringVar(&cfg.expectedMode, "expected-mode", "", "core-baseline or maximum-privacy")
	flag.StringVar(&cfg.expectedProfile, "expected-profile", "", "idle, low, medium, or saturated")
	flag.StringVar(&cfg.expectedCover, "expected-cover", "continuousWhileConnected", "cover semantics")
	flag.StringVar(&cfg.expectedRotation, "expected-rotation", "protocol-15m", "rotation cadence")
	flag.StringVar(
		&cfg.expectedCondition,
		"expected-condition",
		"",
		"operator-declared test-condition selector",
	)
	flag.StringVar(&cfg.expectedPairID, "expected-pair-id", "", "matched A/B pair UUID")
	flag.StringVar(&cfg.expectedOSVersion, "expected-os-version", "", "independently observed iOS version")
	flag.StringVar(&cfg.expectedHardwareModel, "expected-hardware-model", "", "independently observed iPhone hardware model")
	flag.StringVar(&cfg.expectedLowPowerMode, "expected-low-power-mode", "", "on or off")
	flag.StringVar(&cfg.expectedStartThermal, "expected-start-thermal", "", "nominal, fair, or serious")
	flag.Uint64Var(&cfg.expectedDurationSeconds, "expected-duration-seconds", 0, "selected run duration")
	flag.StringVar(&cfg.expectedTerminal, "expected-terminal", "completed", "completed or stop-acknowledged")
	flag.StringVar(&cfg.stopReceipt, "stop-receipt", "", "host Stop round-trip receipt")
	flag.StringVar(
		&cfg.startReceipt,
		"start-receipt",
		"",
		"required host Packet Tunnel activation receipt",
	)
	flag.BoolVar(&cfg.requireEnergy, "require-energy", false, "require a positive whole-run task-energy delta")
	flag.BoolVar(&cfg.requireWakeups, "require-wakeups", false, "require whole-run wakeup counters")
	flag.Parse()
	summary, err := verify(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "IOS_SPIKE_VERIFY_FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf(
		"IOS_SPIKE_VERIFY_PASS records=%d run_id=%s artifact=%s "+
			"evidence_barrier=%s "+
			"resident_slope_bytes_per_hour=%.3f energy_available=%t "+
			"energy_delta_nj=%d "+
			"host_packet_tunnel_activation_latency_ns=%d\n",
		summary.Records,
		summary.RunID,
		summary.ArtifactDigest,
		summary.EvidenceDurabilityBarrier,
		summary.ResidentSlopeBytesHour,
		summary.EnergyAvailable,
		summary.EnergyDeltaNanojoules,
		summary.HostStartLatencyNanoseconds,
	)
}

func verify(cfg options) (verificationSummary, error) {
	if cfg.evidence == "" ||
		cfg.startReceipt == "" ||
		!boundDigest(cfg.expectedSource) ||
		!boundDigest(cfg.expectedArtifact) ||
		!oneOfUint64(
			cfg.expectedDurationSeconds, 60, 300, 1_800, 28_800,
		) {
		return verificationSummary{}, errors.New(
			"evidence, start receipt, expected source/artifact digests, " +
				"and duration are required",
		)
	}
	if !oneOf(cfg.expectedMode, "core-baseline", "maximum-privacy") ||
		!oneOf(cfg.expectedProfile, "idle", "low", "medium", "saturated") ||
		!oneOf(cfg.expectedCover, "continuousWhileConnected", "activityWithThirtySecondTail") ||
		!oneOf(cfg.expectedRotation, "protocol-15m", "accelerated-allocation") ||
		!oneOf(
			cfg.expectedCondition,
			"foreground-wifi",
			"locked-wifi",
			"unplugged-cellular",
			"low-power-mode",
			"accelerated-allocation",
			"eight-hour-locked",
			"stop-latency",
			"smoke",
		) ||
		!validRunID(cfg.expectedPairID) ||
		cfg.expectedOSVersion == "" ||
		cfg.expectedHardwareModel == "" ||
		!oneOf(cfg.expectedLowPowerMode, "on", "off") ||
		!oneOf(cfg.expectedStartThermal, "nominal", "fair", "serious") ||
		!oneOf(cfg.expectedTerminal, "completed", "stop-acknowledged") {
		return verificationSummary{}, errors.New("expected run selectors are invalid")
	}
	cfg.evidenceFileName = filepath.Base(cfg.evidence)
	sealed, cleanup, err := sealVerificationInputs(cfg)
	if err != nil {
		return verificationSummary{}, fmt.Errorf(
			"seal verification inputs: %w", err,
		)
	}
	defer cleanup()
	cfg = sealed
	content, err := readEvidenceContent(cfg.evidence)
	if err != nil {
		return verificationSummary{}, err
	}
	records, err := readRecords(content)
	if err != nil {
		return verificationSummary{}, err
	}
	if len(records) < 2 || records[0].Event != "started" {
		return verificationSummary{}, errors.New("evidence must start with a started record")
	}
	activation, err := verifyStartReceipt(cfg, content, records)
	if err != nil {
		return verificationSummary{}, err
	}
	verifiedStartReceipt, err := readStartReceipt(cfg.startReceipt)
	if err != nil {
		return verificationSummary{}, err
	}
	last := records[len(records)-1]
	if last.Event != cfg.expectedTerminal {
		return verificationSummary{}, fmt.Errorf(
			"terminal event=%q, want %q", last.Event, cfg.expectedTerminal,
		)
	}
	expectedDuration := cfg.expectedDurationSeconds * 1_000_000_000
	expectedTrafficActive := expectedDuration
	if cfg.expectedCover == "activityWithThirtySecondTail" {
		expectedTrafficActive -= 30_000_000_000
	}
	first := records[0]
	if !validRunID(first.RunID) {
		return verificationSummary{}, errors.New("run ID is not a lowercase UUID")
	}
	artifact := first.ArtifactDigest
	if artifact != cfg.expectedArtifact {
		return verificationSummary{}, errors.New("artifact digest is not the expected build")
	}
	expectedLowPower := cfg.expectedLowPowerMode == "on"
	if first.Resources == nil ||
		first.Resources.LowPowerMode == nil ||
		*first.Resources.LowPowerMode != expectedLowPower ||
		first.Resources.ThermalState == nil ||
		*first.Resources.ThermalState != cfg.expectedStartThermal {
		return verificationSummary{}, errors.New("starting power or thermal state is not the expected condition")
	}
	var previous uint64
	var previousWindowEnd uint64
	var memoryPoints [][2]float64
	var energyDelta uint64
	var energyAvailable bool
	for index, record := range records {
		if index > 0 && index < len(records)-1 &&
			record.Event != "sample-window" {
			return verificationSummary{}, fmt.Errorf(
				"record %d has unexpected event %q", index+1, record.Event,
			)
		}
		if record.Schema != schemaVersion ||
			record.ProtocolVersion != protocolVersion ||
			record.FrameVersion != frameVersion ||
			record.Platform != "ios" ||
			record.OSVersion != cfg.expectedOSVersion ||
			record.HardwareModel != cfg.expectedHardwareModel ||
			record.RunID != first.RunID ||
			record.SourceDigest != cfg.expectedSource ||
			record.ArtifactDigest != artifact ||
			record.Mode != cfg.expectedMode ||
			record.TrafficProfile != cfg.expectedProfile ||
			record.CoverSemantics != cfg.expectedCover ||
			record.RotationCadence != cfg.expectedRotation ||
			record.TestCondition != cfg.expectedCondition ||
			record.PairID != cfg.expectedPairID ||
			record.DurationNanoseconds != expectedDuration ||
			record.TrafficActiveNanoseconds != expectedTrafficActive {
			return verificationSummary{}, fmt.Errorf(
				"record %d has inconsistent provenance", index+1,
			)
		}
		if record.FailureCode != nil || record.Event == "failed" {
			return verificationSummary{}, fmt.Errorf(
				"record %d retains failure %q", index+1, value(record.FailureCode),
			)
		}
		if index > 0 && record.MonotonicNanoseconds <= previous {
			return verificationSummary{}, errors.New("record time is not strictly monotonic")
		}
		previous = record.MonotonicNanoseconds
		if err := verifyConstants(record.Constants); err != nil {
			return verificationSummary{}, fmt.Errorf("record %d: %w", index+1, err)
		}
		if err := verifyRecordPrivacyShape(cfg, record); err != nil {
			return verificationSummary{}, fmt.Errorf(
				"record %d: %w", index+1, err,
			)
		}
		if window := record.ResourceWindow; window != nil {
			if window.SampleCount == 0 ||
				window.ScheduledSampleCount < window.SampleCount ||
				window.LastSampleMonotonicNanoseconds <
					window.FirstSampleMonotonicNanoseconds ||
				window.FirstSampleMonotonicNanoseconds <= previousWindowEnd ||
				window.LastSampleMonotonicNanoseconds >
					record.MonotonicNanoseconds ||
				window.PeakResidentBytes == nil ||
				window.PeakPhysicalFootprintBytes == nil {
				return verificationSummary{}, errors.New("resource window is invalid")
			}
			if err := verifySamplingSpan(window, 35_000_000_000); err != nil {
				return verificationSummary{}, fmt.Errorf(
					"resource window is invalid: %w", err,
				)
			}
			previousWindowEnd = window.LastSampleMonotonicNanoseconds
			if window.FirstSampleMonotonicNanoseconds >=
				first.MonotonicNanoseconds &&
				window.FirstSampleMonotonicNanoseconds-
					first.MonotonicNanoseconds >= 900_000_000_000 {
				midpoint := window.FirstSampleMonotonicNanoseconds +
					(window.LastSampleMonotonicNanoseconds-
						window.FirstSampleMonotonicNanoseconds)/2
				memoryPoints = append(memoryPoints, [2]float64{
					float64(midpoint-first.MonotonicNanoseconds) /
						float64(3_600_000_000_000),
					float64(*window.PeakResidentBytes),
				})
			}
		}
		if record.WholeRunResourceWindow != nil &&
			index != len(records)-1 {
			return verificationSummary{}, errors.New("whole-run resources appear before terminal")
		}
	}
	// Runs after the loop above, which is what establishes that
	// MonotonicNanoseconds is strictly increasing and therefore usable as the
	// reference the wall clock is measured against.
	if err := verifyWallClock(records); err != nil {
		return verificationSummary{}, err
	}
	if last.DataPath == nil {
		return verificationSummary{}, errors.New("terminal data-path snapshot is absent")
	}
	if cfg.expectedTerminal == "completed" {
		elapsed := last.MonotonicNanoseconds - first.MonotonicNanoseconds
		if elapsed < expectedDuration ||
			elapsed > expectedDuration+5_000_000_000 {
			return verificationSummary{}, errors.New("completed run duration is outside the allowed range")
		}
	} else {
		elapsed := last.MonotonicNanoseconds - first.MonotonicNanoseconds
		if cfg.expectedMode != "maximum-privacy" ||
			cfg.expectedProfile != "idle" ||
			cfg.expectedCover != "continuousWhileConnected" ||
			cfg.expectedCondition != "stop-latency" ||
			elapsed < 5_000_000_000 ||
			elapsed >= expectedDuration {
			return verificationSummary{}, errors.New(
				"stop gate must be an idle continuous privacy run stopped after at least five seconds",
			)
		}
	}
	wholeRun := last.WholeRunResourceWindow
	if wholeRun == nil ||
		wholeRun.SampleCount == 0 ||
		wholeRun.ScheduledSampleCount < wholeRun.SampleCount ||
		wholeRun.LastSampleMonotonicNanoseconds <
			wholeRun.FirstSampleMonotonicNanoseconds ||
		wholeRun.LastSampleMonotonicNanoseconds >
			last.MonotonicNanoseconds ||
		wholeRun.PeakResidentBytes == nil ||
		wholeRun.PeakPhysicalFootprintBytes == nil ||
		wholeRun.UserCPUDeltaNanoseconds == nil ||
		wholeRun.SystemCPUDeltaNanoseconds == nil {
		return verificationSummary{}, errors.New("whole-run resource evidence is incomplete")
	}
	if wholeRun.FirstSampleMonotonicNanoseconds >
		first.MonotonicNanoseconds ||
		first.MonotonicNanoseconds-
			wholeRun.FirstSampleMonotonicNanoseconds >
			5_000_000_000 ||
		last.MonotonicNanoseconds-
			wholeRun.LastSampleMonotonicNanoseconds >
			1_000_000_000 {
		return verificationSummary{}, errors.New(
			"whole-run resource endpoints do not bind the run",
		)
	}
	runElapsed := last.MonotonicNanoseconds - first.MonotonicNanoseconds
	resourceSpan := wholeRun.LastSampleMonotonicNanoseconds -
		wholeRun.FirstSampleMonotonicNanoseconds
	if resourceSpan+1_000_000_000 < runElapsed ||
		resourceSpan > runElapsed+5_000_000_000 {
		return verificationSummary{}, errors.New(
			"whole-run resource span does not match run duration",
		)
	}
	if err := verifySamplingSpan(wholeRun, runElapsed+5_000_000_000); err != nil {
		return verificationSummary{}, fmt.Errorf(
			"whole-run resource evidence is incomplete: %w", err,
		)
	}
	if (expectedLowPower && !wholeRun.LowPowerModeAlwaysEnabled) ||
		(!expectedLowPower && wholeRun.LowPowerModeObserved) ||
		!oneOf(
			value(wholeRun.WorstThermalState),
			"nominal",
			"fair",
			"serious",
		) {
		return verificationSummary{}, errors.New("whole-run power or thermal evidence is invalid")
	}
	if cfg.expectedTerminal == "completed" {
		minimumSamples := cfg.expectedDurationSeconds -
			cfg.expectedDurationSeconds/10
		missingSamples := wholeRun.ScheduledSampleCount -
			wholeRun.SampleCount
		if wholeRun.SampleCount < minimumSamples ||
			missingSamples > wholeRun.ScheduledSampleCount/20 {
			return verificationSummary{}, fmt.Errorf(
				"resource sampling coverage=%d/%d scheduled is insufficient",
				wholeRun.SampleCount,
				wholeRun.ScheduledSampleCount,
			)
		}
	}
	if wholeRun.EnergyDeltaNanojoules != nil {
		energyDelta = *wholeRun.EnergyDeltaNanojoules
		energyAvailable = energyDelta > 0
	}
	if cfg.requireEnergy && !energyAvailable {
		return verificationSummary{}, errors.New("positive whole-run energy evidence is required")
	}
	if cfg.requireWakeups &&
		(wholeRun.InterruptWakeupDelta == nil ||
			wholeRun.PackageIdleWakeupDelta == nil) {
		return verificationSummary{}, errors.New("whole-run wakeup evidence is required")
	}
	if err := verifyDataPath(cfg, first, last); err != nil {
		return verificationSummary{}, err
	}
	slope := regressionSlope(memoryPoints)
	if cfg.expectedDurationSeconds >= 1_800 && len(memoryPoints) < 2 {
		return verificationSummary{}, errors.New("post-warmup memory trend is under-sampled")
	}
	if len(memoryPoints) >= 2 && (math.IsInf(slope, 0) || math.IsNaN(slope)) {
		return verificationSummary{}, errors.New("post-warmup memory trend is not a finite number")
	}
	if len(memoryPoints) >= 2 && slope > 1_048_576 {
		return verificationSummary{}, fmt.Errorf(
			"resident-memory slope %.3f bytes/hour exceeds 1 MiB/hour", slope,
		)
	}
	if cfg.expectedDurationSeconds >= 60 {
		hasWindow := false
		for _, record := range records {
			hasWindow = hasWindow || record.ResourceWindow != nil
		}
		if !hasWindow {
			return verificationSummary{}, errors.New("run has no resource window")
		}
	}
	return verificationSummary{
		Records:                     len(records),
		RunID:                       first.RunID,
		ArtifactDigest:              artifact,
		EvidenceDurabilityBarrier:   verifiedStartReceipt.EvidenceDurabilityBarrier,
		ResidentSlopeBytesHour:      slope,
		EnergyDeltaNanojoules:       energyDelta,
		EnergyAvailable:             energyAvailable,
		HostStartLatencyNanoseconds: activation,
	}, nil
}

// verifyStartReceipt requires the host activation receipt, revalidates every
// field, and binds it to this exact evidence file.
//
// The digest is taken over the raw first line INCLUDING its trailing line
// feed, which is what the provider hashed. Hashing the stripped line would
// silently disagree with the provider and is exactly the mistake this check
// exists to prevent.
//
// SCOPE: `hostStartLatencyNanoseconds` is the interval from the host's start
// request to the host's first observed `NEVPNStatus.connected`. Passing the
// 3.000-second bound proves iOS Packet Tunnel activation. It does not prove a
// usable VPN connection and does not measure time-to-first-protected-packet.
func verifyStartReceipt(
	cfg options,
	content []byte,
	records []metricRecord,
) (uint64, error) {
	receipt, err := readStartReceipt(cfg.startReceipt)
	if err != nil {
		return 0, err
	}
	first := records[0]
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
	if !validRunID(receipt.RunID) ||
		!validRunID(receipt.AttemptNonce) ||
		!lowerHex(receipt.SourceDigest, 64) ||
		receipt.SourceDigest == strings.Repeat("0", 64) ||
		!lowerHex(receipt.FirstRecordSHA256, 64) {
		return 0, errors.New("start receipt identifiers are invalid")
	}
	if receipt.RunID != first.RunID ||
		receipt.SourceDigest != cfg.expectedSource ||
		receipt.EvidenceFileName != cfg.evidenceFileName ||
		receipt.EvidenceFileName != first.RunID+".jsonl" {
		return 0, errors.New("start receipt is not bound to this run")
	}
	firstLine, err := firstLineWithLineFeed(content)
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(firstLine)
	if hex.EncodeToString(digest[:]) != receipt.FirstRecordSHA256 {
		return 0, errors.New(
			"start receipt does not pin the first evidence record",
		)
	}
	if uint64(len(firstLine)) != receipt.FirstRecordBytes ||
		receipt.FirstRecordBytes < minimumFirstRecordBytes ||
		receipt.FirstRecordBytes > maximumFirstRecordBytes {
		return 0, errors.New("start receipt first-record length is invalid")
	}
	if first.StartAttemptNonce == nil ||
		first.StartRequestedAtMonotonicNanoseconds == nil ||
		first.ProviderReceivedAtMonotonicNanoseconds == nil ||
		*first.StartAttemptNonce != receipt.AttemptNonce ||
		*first.StartRequestedAtMonotonicNanoseconds !=
			receipt.RequestedAtMonotonicNanoseconds ||
		*first.ProviderReceivedAtMonotonicNanoseconds !=
			receipt.ProviderReceivedAtMonotonicNanoseconds {
		return 0, errors.New(
			"started record does not carry the receipt's start binding",
		)
	}
	for index, record := range records[1:] {
		if record.StartAttemptNonce != nil ||
			record.StartRequestedAtMonotonicNanoseconds != nil ||
			record.ProviderReceivedAtMonotonicNanoseconds != nil {
			return 0, fmt.Errorf(
				"record %d carries a start binding outside the first record",
				index+2,
			)
		}
	}
	if err := requireInterval(
		receipt.RequestedAtMonotonicNanoseconds,
		receipt.ProviderReceivedAtMonotonicNanoseconds,
		0,
		false,
		"provider receipt",
	); err != nil {
		return 0, err
	}
	if err := requireInterval(
		receipt.ProviderReceivedAtMonotonicNanoseconds,
		receipt.ProviderReadyAtMonotonicNanoseconds,
		receipt.ProviderStartLatencyNanoseconds,
		true,
		"provider start latency",
	); err != nil {
		return 0, err
	}
	// The started record is timestamped after the provider received the
	// request and before it reported ready, so it must fall inside that
	// interval.
	if first.MonotonicNanoseconds <
		receipt.ProviderReceivedAtMonotonicNanoseconds ||
		first.MonotonicNanoseconds >
			receipt.ProviderReadyAtMonotonicNanoseconds {
		return 0, errors.New(
			"started record time is outside the provider start interval",
		)
	}
	if receipt.HostObservedConnectedAtMonotonicNanoseconds <
		receipt.ProviderReadyAtMonotonicNanoseconds {
		return 0, errors.New(
			"host observed connected before the provider was ready",
		)
	}
	if err := requireInterval(
		receipt.RequestedAtMonotonicNanoseconds,
		receipt.HostObservedConnectedAtMonotonicNanoseconds,
		receipt.HostStartLatencyNanoseconds,
		true,
		"host start latency",
	); err != nil {
		return 0, err
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

// requireInterval refuses a reversed interval and, when a duration is
// declared, requires start+duration == end computed with overflow reporting.
//
// Honest note: the reversed check is diagnostic rather than independently
// load-bearing, because a reversed pair with a declared duration also fails
// the arithmetic identity. The overflow-reported addition IS load-bearing: a
// declared duration large enough to wrap is refused only here.
func requireInterval(
	start uint64,
	end uint64,
	declared uint64,
	hasDeclared bool,
	name string,
) error {
	if end < start {
		return fmt.Errorf("%s interval is reversed", name)
	}
	if !hasDeclared {
		return nil
	}
	sum, carry := bits.Add64(start, declared, 0)
	if carry != 0 {
		return fmt.Errorf("%s overflows", name)
	}
	if sum != end {
		return fmt.Errorf("%s does not match its endpoints", name)
	}
	return nil
}

func firstLineWithLineFeed(content []byte) ([]byte, error) {
	index := bytes.IndexByte(content, '\n')
	if index < 0 {
		return nil, errors.New(
			"first evidence record has no terminating line feed",
		)
	}
	return content[:index+1], nil
}

func verifyDataPath(
	cfg options,
	started metricRecord,
	terminal metricRecord,
) error {
	data := terminal.DataPath
	if data.InboundQueueDepth < 0 ||
		data.InboundQueueDepth > ringCapacity ||
		data.OutboundQueueDepth < 0 ||
		data.OutboundQueueDepth > ringCapacity ||
		data.InboundHighWatermark < data.InboundQueueDepth ||
		data.InboundHighWatermark > ringCapacity ||
		data.OutboundHighWatermark < data.OutboundQueueDepth ||
		data.OutboundHighWatermark > ringCapacity ||
		data.InboundOccupancyP99Cells < 0 ||
		data.InboundOccupancyP99Cells > ringCapacity ||
		data.OutboundOccupancyP99Cells < 0 ||
		data.OutboundOccupancyP99Cells > ringCapacity {
		return errors.New("fixed-capacity queue invariant failed")
	}
	rate := map[string]uint64{
		"idle": 0, "low": 50, "medium": 1_250, "saturated": 5_000,
	}[cfg.expectedProfile]
	activeSeconds := cfg.expectedDurationSeconds
	if cfg.expectedCover == "activityWithThirtySecondTail" {
		activeSeconds -= 30
	}
	maximumCommonPathNanoseconds := activeSeconds * 1_000_000_000
	if data.CommonPathActiveNanoseconds > maximumCommonPathNanoseconds {
		return errors.New("matched common-path active interval exceeds selection")
	}
	if cfg.expectedTerminal == "completed" &&
		rate > 0 &&
		data.CommonPathActiveNanoseconds != maximumCommonPathNanoseconds {
		return errors.New("completed matched common-path interval is incomplete")
	}
	if cfg.expectedTerminal == "stop-acknowledged" &&
		rate > 0 &&
		data.CommonPathActiveNanoseconds < 5_000_000_000 {
		return errors.New("stop workload ran for less than five seconds")
	}
	expectedCommonPathUnits :=
		rate * data.CommonPathActiveNanoseconds / 1_000_000_000 * 2
	if data.CommonPathUnits != expectedCommonPathUnits {
		return fmt.Errorf(
			"matched common-path units=%d, want %d",
			data.CommonPathUnits,
			expectedCommonPathUnits,
		)
	}
	if data.CommonPathChecksum != deterministicChecksum(data.CommonPathUnits) {
		return errors.New("matched common-path checksum is invalid")
	}
	if data.UnaccountedWorkNanoseconds != 0 {
		return fmt.Errorf(
			"busy workload was under-driven by %d ns",
			data.UnaccountedWorkNanoseconds,
		)
	}
	if cfg.expectedMode == "core-baseline" {
		if err := verifyEmptyCorePrivacyPath(data); err != nil {
			return err
		}
		return verifyStop(cfg, started, terminal)
	}
	if data.AllocatedPrivacyCellBytes != privacyPoolBytes {
		return errors.New("maximum privacy allocation is not exactly 2 MiB")
	}
	if data.RotationActiveCircuit == nil ||
		(*data.RotationActiveCircuit != 0 &&
			*data.RotationActiveCircuit != 1) {
		return errors.New("maximum privacy has no valid active circuit")
	}
	// Idle still runs cover (continuousWhileConnected) and must not record
	// drops or backpressure. This is a separate gate from low/medium because
	// idle+activityWithThirtySecondTail can legitimately have
	// QueueDelaySamples==0, which that gate treats as a failure.
	if cfg.expectedProfile == "idle" &&
		(data.DroppedCells != 0 ||
			data.BackpressureEvents != 0 ||
			data.BackpressuredCells != 0) {
		return errors.New("idle profile retained drop or backpressure")
	}
	if cfg.expectedProfile == "low" || cfg.expectedProfile == "medium" {
		if data.DroppedCells != 0 ||
			data.BackpressureEvents != 0 ||
			data.BackpressuredCells != 0 ||
			data.RetiredDataCells != 0 ||
			data.RetiredCoverCells != 0 ||
			data.InboundOccupancyP99Cells >= ringCapacity/2 ||
			data.OutboundOccupancyP99Cells >= ringCapacity/2 ||
			data.QueueDelaySamples == 0 ||
			data.QueueDelayOver25Milliseconds >
				data.QueueDelaySamples/100 ||
			data.QueueDelayP99UpperBoundNanoseconds > 25_100_000 {
			return errors.New("low/medium occupancy, drop, or delay gate failed")
		}
	}
	if cfg.expectedProfile == "saturated" &&
		(data.DroppedCells == 0 ||
			data.BackpressureEvents == 0 ||
			data.BackpressuredCells == 0) {
		return errors.New("saturated profile did not demonstrate bounded backpressure")
	}
	// #nosec G115 -- both nonnegative depths were range-checked against the
	// frozen 512-cell capacity immediately above.
	occupied := uint64(data.InboundQueueDepth + data.OutboundQueueDepth)
	accountedCells, ok := checkedSum(
		data.EmittedCells,
		occupied,
		data.RetiredDataCells,
		data.RetiredCoverCells,
	)
	if !ok ||
		data.AcceptedCells != accountedCells ||
		data.QueueDelaySamples != data.EmittedCells ||
		data.OccupancySamples == 0 {
		return errors.New("cell accounting or occupancy evidence is incomplete")
	}
	// #nosec G115 -- both pending depths are checked nonnegative below.
	inboundPending := uint64(max(data.CoverInboundCellsPending, 0))
	// #nosec G115 -- both pending depths are checked nonnegative below.
	outboundPending := uint64(max(data.CoverOutboundCellsPending, 0))
	inboundCoverAccounted, inboundOK := checkedSum(
		data.CoverInboundCellsEmitted,
		inboundPending,
		data.CoverInboundCellsRetired,
	)
	outboundCoverAccounted, outboundOK := checkedSum(
		data.CoverOutboundCellsEmitted,
		outboundPending,
		data.CoverOutboundCellsRetired,
	)
	retiredCoverAccounted, retiredOK := checkedSum(
		data.CoverInboundCellsRetired,
		data.CoverOutboundCellsRetired,
	)
	if data.CoverInboundCellsEmitted != data.CoverOutboundCellsEmitted ||
		data.CoverPairsEmitted != data.CoverInboundCellsEmitted ||
		data.CoverInboundCellsAccepted != data.CoverPairsAccepted ||
		data.CoverOutboundCellsAccepted != data.CoverPairsAccepted ||
		data.CoverInboundCellsPending < 0 ||
		data.CoverOutboundCellsPending < 0 ||
		!inboundOK ||
		!outboundOK ||
		!retiredOK ||
		data.CoverInboundCellsAccepted != inboundCoverAccounted ||
		data.CoverOutboundCellsAccepted != outboundCoverAccounted ||
		data.RetiredCoverCells != retiredCoverAccounted ||
		data.CoverDeadlinesMissed != 0 ||
		data.MaximumCoverLatenessNanoseconds > 20_000_000 {
		return errors.New("cover emission invariant failed")
	}
	if cfg.expectedTerminal == "completed" {
		expectedAccepted := uint64(0)
		if cfg.expectedCover == "continuousWhileConnected" {
			expectedAccepted = cfg.expectedDurationSeconds
		} else if cfg.expectedProfile != "idle" {
			expectedAccepted = cfg.expectedDurationSeconds
		}
		if data.CoverPairsAccepted != expectedAccepted {
			return fmt.Errorf(
				"accepted cover pairs=%d, want %d",
				data.CoverPairsAccepted,
				expectedAccepted,
			)
		}
		expectedPending := uint64(0)
		if expectedAccepted > 0 {
			expectedPending = 1
		}
		expectedEmitted := expectedAccepted - expectedPending
		if uint64(data.CoverInboundCellsPending) != expectedPending ||
			uint64(data.CoverOutboundCellsPending) != expectedPending ||
			data.CoverInboundCellsRetired != 0 ||
			data.CoverOutboundCellsRetired != 0 ||
			data.CoverInboundCellsEmitted != expectedEmitted ||
			data.CoverOutboundCellsEmitted != expectedEmitted ||
			data.CoverPairsEmitted != expectedEmitted {
			return errors.New(
				"completed cover was not actually emitted at the required rate",
			)
		}
	}
	if data.MaximumRotationOverlapNanoseconds > 10_000_000_000 ||
		data.RotationStandbyCircuit != nil ||
		data.RotationOverlapDeadlineNanoseconds != nil {
		return errors.New("rotation did not return to single-active ownership")
	}
	if cfg.expectedRotation == "accelerated-allocation" {
		if data.RotationCount < 500 || terminal.RotationResources == nil {
			return errors.New("500-rotation evidence is incomplete")
		}
		resources := terminal.RotationResources
		if resources.Samples < 500 ||
			resources.LastRotationCount != data.RotationCount ||
			exceedsOneMiB(
				resources.FirstTenPeakResidentBytes,
				resources.PostTenPeakResidentBytes,
			) ||
			exceedsOneMiB(
				resources.FirstTenPeakPhysicalFootprintBytes,
				resources.PostTenPeakPhysicalFootprintBytes,
			) {
			return errors.New("accelerated-rotation memory gate failed")
		}
	} else if cfg.expectedDurationSeconds >= 900 {
		minimum := (cfg.expectedDurationSeconds - 1) / 900
		if data.RotationCount < minimum {
			return errors.New("protocol rotation count is too low")
		}
	}
	return verifyStop(cfg, started, terminal)
}

func verifyEmptyCorePrivacyPath(data *dataPathSnapshot) error {
	if data.AllocatedPrivacyCellBytes != 0 ||
		data.InboundQueueDepth != 0 ||
		data.OutboundQueueDepth != 0 ||
		data.InboundHighWatermark != 0 ||
		data.OutboundHighWatermark != 0 ||
		data.OccupancySamples != 0 ||
		data.InboundOccupancyP99Cells != 0 ||
		data.OutboundOccupancyP99Cells != 0 ||
		data.AcceptedCells != 0 ||
		data.EmittedCells != 0 ||
		data.DroppedCells != 0 ||
		data.RetiredDataCells != 0 ||
		data.RetiredCoverCells != 0 ||
		data.CoverPairsAccepted != 0 ||
		data.CoverInboundCellsAccepted != 0 ||
		data.CoverOutboundCellsAccepted != 0 ||
		data.CoverPairsEmitted != 0 ||
		data.CoverInboundCellsEmitted != 0 ||
		data.CoverOutboundCellsEmitted != 0 ||
		data.CoverInboundCellsPending != 0 ||
		data.CoverOutboundCellsPending != 0 ||
		data.CoverInboundCellsRetired != 0 ||
		data.CoverOutboundCellsRetired != 0 ||
		data.CoverDeadlinesMissed != 0 ||
		data.MaximumCoverLatenessNanoseconds != 0 ||
		data.QueueDelaySamples != 0 ||
		data.QueueDelayP99UpperBoundNanoseconds != 0 ||
		data.QueueDelayOver25Milliseconds != 0 ||
		data.MaximumObservedQueueDelayNanoseconds != 0 ||
		data.BackpressureEvents != 0 ||
		data.BackpressuredCells != 0 ||
		data.RotationCount != 0 ||
		data.MaximumRotationOverlapNanoseconds != 0 ||
		data.RotationActiveCircuit != nil ||
		data.RotationStandbyCircuit != nil ||
		data.RotationOverlapDeadlineNanoseconds != nil {
		return errors.New("core baseline performed privacy-path work")
	}
	return nil
}

func verifyRecordPrivacyShape(cfg options, record metricRecord) error {
	if cfg.expectedMode == "core-baseline" {
		if record.DataPath == nil {
			return errors.New("core baseline data-path snapshot is absent")
		}
		if err := verifyEmptyCorePrivacyPath(record.DataPath); err != nil {
			return err
		}
	}
	if record.RotationResources != nil &&
		(cfg.expectedMode == "core-baseline" ||
			cfg.expectedRotation != "accelerated-allocation") {
		return errors.New(
			"rotation resources are present outside accelerated Maximum Privacy",
		)
	}
	return nil
}

func checkedSum(values ...uint64) (uint64, bool) {
	total := uint64(0)
	for _, value := range values {
		var carry uint64
		total, carry = bits.Add64(total, value, 0)
		if carry != 0 {
			return 0, false
		}
	}
	return total, true
}

func deterministicChecksum(units uint64) uint64 {
	accumulator := uint64(0xbb67ae8584caa73b)
	for unit := uint64(0); unit < units; unit++ {
		accumulator ^= unit + 0x9e3779b97f4a7c15
		accumulator = bits.RotateLeft64(accumulator, 7)
	}
	return accumulator
}

func verifySamplingSpan(window *resourceWindow, maximumSpan uint64) error {
	span := window.LastSampleMonotonicNanoseconds -
		window.FirstSampleMonotonicNanoseconds
	if span > maximumSpan {
		return errors.New("sample timestamps span an implausible interval")
	}
	wholeSeconds := span / 1_000_000_000
	minimumScheduled := wholeSeconds
	if span == 0 {
		minimumScheduled = 1
	}
	if window.ScheduledSampleCount < minimumScheduled ||
		window.ScheduledSampleCount > wholeSeconds+2 {
		return errors.New("scheduled count does not match timestamp span")
	}
	return nil
}

func verifyStop(
	cfg options,
	started metricRecord,
	terminal metricRecord,
) error {
	if cfg.expectedTerminal != "stop-acknowledged" {
		return nil
	}
	if terminal.ControlLatencyNanoseconds == nil ||
		*terminal.ControlLatencyNanoseconds > 250_000_000 {
		return errors.New("provider Stop cancellation exceeded 250 ms")
	}
	if cfg.stopReceipt == "" {
		return errors.New("host Stop round-trip receipt is required")
	}
	receipt, err := readStopReceipt(cfg.stopReceipt)
	if err != nil {
		return err
	}
	digest, err := secureFileSHA256(cfg.evidence)
	if err != nil {
		return err
	}
	if receipt.Schema != "winn-ios-privacy-spike-stop-receipt/1" ||
		receipt.ProtocolVersion != protocolVersion ||
		receipt.RunID != terminal.RunID ||
		receipt.EvidenceFileName != cfg.evidenceFileName ||
		receipt.EvidenceSHA256 != digest ||
		receipt.ProviderReceivedAtMonotonicNanoseconds <
			receipt.RequestedAtMonotonicNanoseconds ||
		receipt.ProviderAcknowledgedAtMonotonicNanoseconds <
			receipt.ProviderReceivedAtMonotonicNanoseconds ||
		terminal.MonotonicNanoseconds <
			receipt.ProviderReceivedAtMonotonicNanoseconds ||
		terminal.MonotonicNanoseconds >
			receipt.ProviderAcknowledgedAtMonotonicNanoseconds ||
		receipt.HostReceivedAtMonotonicNanoseconds <
			receipt.ProviderAcknowledgedAtMonotonicNanoseconds ||
		receipt.RoundTripNanoseconds !=
			receipt.HostReceivedAtMonotonicNanoseconds-
				receipt.RequestedAtMonotonicNanoseconds ||
		receipt.RoundTripNanoseconds > 250_000_000 ||
		*terminal.ControlLatencyNanoseconds >
			receipt.RoundTripNanoseconds {
		return errors.New("host Stop round-trip receipt is invalid")
	}
	if receipt.ProviderReceivedAtMonotonicNanoseconds <
		started.MonotonicNanoseconds {
		return errors.New("stop receipt predates the started record")
	}
	elapsedAtStop := receipt.ProviderReceivedAtMonotonicNanoseconds -
		started.MonotonicNanoseconds
	expectedCover := elapsedAtStop / 1_000_000_000
	if terminal.DataPath.CoverPairsAccepted != expectedCover {
		return fmt.Errorf(
			"stop cover pairs=%d, want %d before provider receipt",
			terminal.DataPath.CoverPairsAccepted,
			expectedCover,
		)
	}
	pending := terminal.DataPath.CoverInboundCellsPending
	if pending < 0 || pending > 1 ||
		terminal.DataPath.CoverOutboundCellsPending != pending {
		return errors.New(
			"stop cover has invalid terminal pending depth",
		)
	}
	// #nosec G115 -- pending is constrained to the closed interval [0,1].
	expectedEmitted := expectedCover - uint64(pending)
	if terminal.DataPath.CoverPairsEmitted != expectedEmitted ||
		terminal.DataPath.CoverInboundCellsEmitted != expectedEmitted ||
		terminal.DataPath.CoverOutboundCellsEmitted != expectedEmitted {
		return errors.New("stop cover was not emitted through provider receipt")
	}
	return nil
}

func verifyConstants(value constantsSnapshot) error {
	if value.CellBytes != privacyCellBytes ||
		value.PayloadBytes != privacyPayloadBytes ||
		value.RingCapacityPerDirection != ringCapacity ||
		value.MaximumCircuits != maximumCircuits ||
		value.ShuffleNanoseconds != 20_000_000 ||
		value.CoverIntervalNanoseconds != 1_000_000_000 ||
		value.CoverTailNanoseconds != 30_000_000_000 ||
		value.CircuitRotationNanoseconds != 900_000_000_000 ||
		value.SpikeOverlapNanoseconds != 5_000_000_000 {
		return errors.New("frozen constants changed")
	}
	return nil
}

// readEvidenceContent returns the evidence file's exact bytes. The raw bytes
// are needed because the start receipt pins the first line INCLUDING its
// trailing line feed, which a line scanner discards.
func readEvidenceContent(path string) ([]byte, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := requireBoundedFile(file, 64<<20); err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > 64<<20 {
		return nil, errors.New("evidence exceeds 64 MiB")
	}
	return content, nil
}

func readRecords(content []byte) ([]metricRecord, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	records := make([]metricRecord, 0, 64)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Strict member validation runs on the raw line first, so the typed
		// decode below can never be reached by a duplicated member, a
		// case-variant name, or an absent required member.
		if err := validateStrictJSON(line, metricRecordShape); err != nil {
			return nil, fmt.Errorf("record %d: %w", len(records)+1, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var record metricRecord
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("decode record %d: %w", len(records)+1, err)
		}
		if err := requireEOF(decoder); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("evidence is empty")
	}
	return records, nil
}

func readStopReceipt(path string) (stopReceipt, error) {
	var receipt stopReceipt
	if err := readStrictJSON(path, stopReceiptShape, &receipt); err != nil {
		return stopReceipt{}, fmt.Errorf("read stop receipt: %w", err)
	}
	return receipt, nil
}

func readStartReceipt(path string) (startReceipt, error) {
	var receipt startReceipt
	if err := readStrictJSON(path, startReceiptShape, &receipt); err != nil {
		return startReceipt{}, fmt.Errorf("read start receipt: %w", err)
	}
	return receipt, nil
}

func readStrictJSON(path string, shape *jsonShape, target any) error {
	file, err := openSecureRegular(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := requireBoundedFile(file, 64<<10); err != nil {
		return err
	}
	content, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return err
	}
	if len(content) > 64<<10 {
		return errors.New("receipt exceeds 64 KiB")
	}
	// Same order as the JSONL boundary: exact member set first, typed decode
	// only afterwards.
	if err := validateStrictJSON(content, shape); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func secureFileSHA256(path string) (string, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, (64<<20)+1)); err != nil {
		return "", err
	}
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > 64<<20 {
		return "", errors.New("evidence exceeds 64 MiB")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func openSecureRegular(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	clean := filepath.Clean(absolute)
	originalInfo, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if originalInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence path must not be a symbolic link")
	}
	originalParentInfo, err := os.Lstat(filepath.Dir(clean))
	if err != nil ||
		!originalParentInfo.IsDir() ||
		originalParentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence parent must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(resolved)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence parent must be a real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	file, openErr := root.Open(filepath.Base(resolved))
	closeErr := root.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	fileInfo, err := file.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("evidence is not a regular file")
	}
	return file, nil
}

func requireBoundedFile(file *os.File, maximum int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() < 1 || info.Size() > maximum {
		return errors.New("evidence file size is outside the allowed range")
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("record contains trailing JSON")
	}
	return err
}

func regressionSlope(points [][2]float64) float64 {
	if len(points) < 2 {
		return 0
	}
	var sumX, sumY float64
	for _, point := range points {
		sumX += point[0]
		sumY += point[1]
	}
	meanX := sumX / float64(len(points))
	meanY := sumY / float64(len(points))
	var numerator, denominator float64
	for _, point := range points {
		x := point[0] - meanX
		numerator += x * (point[1] - meanY)
		denominator += x * x
	}
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}

func exceedsOneMiB(first, later *uint64) bool {
	if first == nil || later == nil {
		return true
	}
	if *later <= *first {
		return false
	}
	return *later-*first > 1_048_576
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && value == hex.EncodeToString(decoded)
}

func boundDigest(value string) bool {
	return lowerHex(value, 64) &&
		value != strings.Repeat("0", 64)
}

func validRunID(value string) bool {
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

func value(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}
