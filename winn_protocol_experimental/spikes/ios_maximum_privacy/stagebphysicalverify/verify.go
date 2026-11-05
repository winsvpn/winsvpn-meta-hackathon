package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	manifestSchema                         = "winn-stageb-physical-manifest/1"
	attemptSchema                          = "winn-stageb-physical-attempt/2"
	topologySchema                         = "winn-stageb-physical-topology/1"
	protocolVersion                        = "winn/3"
	measurementScope                       = "physical-first-protected-flow"
	t0Source                               = "first-connect-button-handler-operation"
	bindingDomain                          = "winn-stageb-physical-binding/v1\x00"
	deadlineNanoseconds                    = uint64(3_000_000_000)
	maxDeadlineFailureReportingNanoseconds = uint64(50_000_000)
	maxCleanupNanoseconds                  = uint64(250_000_000)
	maxManifestBytes                       = int64(1 << 20)
	maxEvidenceBytes                       = int64(4 << 20)
)

var (
	lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lowerUUID  = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-` +
			`[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
)

type Manifest struct {
	Schema                      string `json:"schema"`
	ProtocolVersion             string `json:"protocolVersion"`
	MeasurementScope            string `json:"measurementScope"`
	ContractSHA256              string `json:"contractSHA256"`
	SourceSHA256                string `json:"sourceSHA256"`
	HostArtifactSHA256          string `json:"hostArtifactSHA256"`
	ProviderArtifactSHA256      string `json:"providerArtifactSHA256"`
	AWGArtifactSHA256           string `json:"awgArtifactSHA256"`
	AWGConfigSHA256             string `json:"awgConfigSHA256"`
	ExpectedAWGPeerSHA256       string `json:"expectedAWGPeerSHA256"`
	AWGEngineInstanceNonce      string `json:"awgEngineInstanceNonce"`
	AWGEngineGeneration         uint64 `json:"awgEngineGeneration"`
	WinningPathGeneration       uint64 `json:"winningPathGeneration"`
	WinningInterfaceTokenSHA256 string `json:"winningInterfaceTokenSHA256"`
	ReflectorArtifactSHA256     string `json:"reflectorArtifactSHA256"`
	ReflectorConfigSHA256       string `json:"reflectorConfigSHA256"`
	DNSConfigSHA256             string `json:"dnsConfigSHA256"`
	VerifierSHA256              string `json:"verifierSHA256"`
	EvidencePath                string `json:"evidencePath"`
	EvidenceSHA256              string `json:"evidenceSHA256"`
	TopologyPath                string `json:"topologyPath"`
	TopologySHA256              string `json:"topologySHA256"`
}

type Pins struct {
	ContractSHA256              string `json:"contractSHA256"`
	SourceSHA256                string `json:"sourceSHA256"`
	HostArtifactSHA256          string `json:"hostArtifactSHA256"`
	ProviderArtifactSHA256      string `json:"providerArtifactSHA256"`
	AWGArtifactSHA256           string `json:"awgArtifactSHA256"`
	AWGConfigSHA256             string `json:"awgConfigSHA256"`
	ExpectedAWGPeerSHA256       string `json:"expectedAWGPeerSHA256"`
	AWGEngineInstanceNonce      string `json:"awgEngineInstanceNonce"`
	AWGEngineGeneration         uint64 `json:"awgEngineGeneration"`
	WinningPathGeneration       uint64 `json:"winningPathGeneration"`
	WinningInterfaceTokenSHA256 string `json:"winningInterfaceTokenSHA256"`
	ReflectorArtifactSHA256     string `json:"reflectorArtifactSHA256"`
	ReflectorConfigSHA256       string `json:"reflectorConfigSHA256"`
	DNSConfigSHA256             string `json:"dnsConfigSHA256"`
	VerifierSHA256              string `json:"verifierSHA256"`
}

type Binding struct {
	RunID                           string `json:"runID"`
	AttemptNonce                    string `json:"attemptNonce"`
	PathID                          string `json:"pathID"`
	WCF3SessionID                   string `json:"wcf3SessionID"`
	WCF3BindingID                   string `json:"wcf3BindingID"`
	PSKGeneration                   uint64 `json:"pskGeneration"`
	SequenceEpoch                   uint64 `json:"sequenceEpoch"`
	CanarySequence                  uint64 `json:"canarySequence"`
	RequestedAtMonotonicNanoseconds uint64 `json:"requestedAtMonotonicNanoseconds"`
	AWGConfigSHA256                 string `json:"awgConfigSHA256"`
	ExpectedAWGPeerSHA256           string `json:"expectedAWGPeerSHA256"`
	AWGEngineInstanceNonce          string `json:"awgEngineInstanceNonce"`
	AWGEngineGeneration             uint64 `json:"awgEngineGeneration"`
	WinningPathGeneration           uint64 `json:"winningPathGeneration"`
	WinningInterfaceTokenSHA256     string `json:"winningInterfaceTokenSHA256"`
	BindingSHA256                   string `json:"bindingSHA256"`
}

type Predicate struct {
	Observed               bool   `json:"observed"`
	AtMonotonicNanoseconds uint64 `json:"atMonotonicNanoseconds"`
	BindingSHA256          string `json:"bindingSHA256"`
}

type Predicates struct {
	FreshAWGHandshake               Predicate `json:"freshAWGHandshake"`
	AuthenticatedBidirectionalBytes Predicate `json:"authenticatedBidirectionalBytes"`
	ProtectedDNS                    Predicate `json:"protectedDNS"`
	AuthenticatedReflector          Predicate `json:"authenticatedReflector"`
}

type AWGSampleIdentity struct {
	PeerPublicKeySHA256         string `json:"peerPublicKeySHA256"`
	ConfigSHA256                string `json:"configSHA256"`
	EngineInstanceNonce         string `json:"engineInstanceNonce"`
	EngineGeneration            uint64 `json:"engineGeneration"`
	PathGeneration              uint64 `json:"pathGeneration"`
	WinningInterfaceTokenSHA256 string `json:"winningInterfaceTokenSHA256"`
}

type AWGProof struct {
	BaselineSampleAtMonotonicNanoseconds      uint64            `json:"baselineSampleAtMonotonicNanoseconds"`
	HandshakePostSampleAtMonotonicNanoseconds uint64            `json:"handshakePostSampleAtMonotonicNanoseconds"`
	CounterPostSampleAtMonotonicNanoseconds   uint64            `json:"counterPostSampleAtMonotonicNanoseconds"`
	BaselineIdentity                          AWGSampleIdentity `json:"baselineIdentity"`
	HandshakePostIdentity                     AWGSampleIdentity `json:"handshakePostIdentity"`
	CounterPostIdentity                       AWGSampleIdentity `json:"counterPostIdentity"`
	BaselineLatestHandshakeUnixMilliseconds   uint64            `json:"baselineLatestHandshakeUnixMilliseconds"`
	PostLatestHandshakeUnixMilliseconds       uint64            `json:"postLatestHandshakeUnixMilliseconds"`
	BaselineAuthenticatedTxBytes              uint64            `json:"baselineAuthenticatedTxBytes"`
	PostAuthenticatedTxBytes                  uint64            `json:"postAuthenticatedTxBytes"`
	BaselineAuthenticatedRxBytes              uint64            `json:"baselineAuthenticatedRxBytes"`
	PostAuthenticatedRxBytes                  uint64            `json:"postAuthenticatedRxBytes"`
	AuthenticatedOutboundDeltaBytes           uint64            `json:"authenticatedOutboundDeltaBytes"`
	AuthenticatedInboundDeltaBytes            uint64            `json:"authenticatedInboundDeltaBytes"`
	PSKGeneration                             uint64            `json:"pskGeneration"`
	BindingSHA256                             string            `json:"bindingSHA256"`
	Fresh                                     bool              `json:"fresh"`
}

type DNSProof struct {
	Attempted                      bool   `json:"attempted"`
	Observed                       bool   `json:"observed"`
	RequestAtMonotonicNanoseconds  uint64 `json:"requestAtMonotonicNanoseconds"`
	ResponseAtMonotonicNanoseconds uint64 `json:"responseAtMonotonicNanoseconds"`
	QueryNonceSHA256               string `json:"queryNonceSHA256"`
	ResponsePayloadSHA256          string `json:"responsePayloadSHA256"`
	ConfigSHA256                   string `json:"configSHA256"`
	TopologySHA256                 string `json:"topologySHA256"`
	BindingSHA256                  string `json:"bindingSHA256"`
	CacheBypassed                  bool   `json:"cacheBypassed"`
	TunnelOnly                     bool   `json:"tunnelOnly"`
}

type ReflectorProof struct {
	Attempted                              bool   `json:"attempted"`
	Observed                               bool   `json:"observed"`
	RequestSentAtMonotonicNanoseconds      uint64 `json:"requestSentAtMonotonicNanoseconds"`
	ResponseObservedAtMonotonicNanoseconds uint64 `json:"responseObservedAtMonotonicNanoseconds"`
	CanarySequence                         uint64 `json:"canarySequence"`
	ArtifactSHA256                         string `json:"artifactSHA256"`
	ConfigSHA256                           string `json:"configSHA256"`
	TopologySHA256                         string `json:"topologySHA256"`
	BindingSHA256                          string `json:"bindingSHA256"`
	Authenticated                          bool   `json:"authenticated"`
	TunnelOnly                             bool   `json:"tunnelOnly"`
}

type Terminal struct {
	State                                     string `json:"state"`
	FailureCode                               string `json:"failureCode"`
	TerminalAtMonotonicNanoseconds            uint64 `json:"terminalAtMonotonicNanoseconds"`
	TDataMonotonicNanoseconds                 uint64 `json:"tDataMonotonicNanoseconds"`
	TUIMonotonicNanoseconds                   uint64 `json:"tUIMonotonicNanoseconds"`
	DeadlineFailureReportingBudgetNanoseconds uint64 `json:"deadlineFailureReportingBudgetNanoseconds"`
	CleanupState                              string `json:"cleanupState"`
	CleanupAtMonotonicNanoseconds             uint64 `json:"cleanupAtMonotonicNanoseconds"`
	CleanupBudgetNanoseconds                  uint64 `json:"cleanupBudgetNanoseconds"`
}

type CleanHost struct {
	Admitted           bool   `json:"admitted"`
	DeviceThermalState string `json:"deviceThermalState"`
	LowPowerMode       string `json:"lowPowerMode"`
	OtherVPNActive     bool   `json:"otherVPNActive"`
	HostStressActive   bool   `json:"hostStressActive"`
	ObservationSHA256  string `json:"observationSHA256"`
}

type AttemptEvidence struct {
	Schema                              string         `json:"schema"`
	ProtocolVersion                     string         `json:"protocolVersion"`
	MeasurementScope                    string         `json:"measurementScope"`
	RunID                               string         `json:"runID"`
	AttemptNonce                        string         `json:"attemptNonce"`
	Mode                                string         `json:"mode"`
	Radio                               string         `json:"radio"`
	Readiness                           string         `json:"readiness"`
	T0Source                            string         `json:"t0Source"`
	ConnectButtonT0MonotonicNanoseconds uint64         `json:"connectButtonT0MonotonicNanoseconds"`
	Binding                             Binding        `json:"binding"`
	Predicates                          Predicates     `json:"predicates"`
	AWG                                 AWGProof       `json:"awg"`
	DNS                                 DNSProof       `json:"dns"`
	Reflector                           ReflectorProof `json:"reflector"`
	Terminal                            Terminal       `json:"terminal"`
	CleanHost                           CleanHost      `json:"cleanHost"`
	Pins                                Pins           `json:"pins"`
}

type TopologyEvidence struct {
	Schema                          string `json:"schema"`
	ProtocolVersion                 string `json:"protocolVersion"`
	MeasurementScope                string `json:"measurementScope"`
	RunID                           string `json:"runID"`
	AWGArtifactSHA256               string `json:"awgArtifactSHA256"`
	AWGConfigSHA256                 string `json:"awgConfigSHA256"`
	ExpectedAWGPeerSHA256           string `json:"expectedAWGPeerSHA256"`
	AWGEngineInstanceNonce          string `json:"awgEngineInstanceNonce"`
	AWGEngineGeneration             uint64 `json:"awgEngineGeneration"`
	WinningPathGeneration           uint64 `json:"winningPathGeneration"`
	WinningInterfaceTokenSHA256     string `json:"winningInterfaceTokenSHA256"`
	ReflectorArtifactSHA256         string `json:"reflectorArtifactSHA256"`
	ReflectorConfigSHA256           string `json:"reflectorConfigSHA256"`
	DNSConfigSHA256                 string `json:"dnsConfigSHA256"`
	DNSDirectPreTunnel              string `json:"dnsDirectPreTunnel"`
	DNSDirectPostTeardown           string `json:"dnsDirectPostTeardown"`
	ReflectorDirectPreTunnel        string `json:"reflectorDirectPreTunnel"`
	ReflectorDirectPostTeardown     string `json:"reflectorDirectPostTeardown"`
	ReflectorAcceptedIngress        string `json:"reflectorAcceptedIngress"`
	OuterPlaintextDNSObserved       bool   `json:"outerPlaintextDNSObserved"`
	OuterPlaintextReflectorObserved bool   `json:"outerPlaintextReflectorObserved"`
	FirewallSnapshotSHA256          string `json:"firewallSnapshotSHA256"`
	RouteSnapshotSHA256             string `json:"routeSnapshotSHA256"`
	OuterCaptureSHA256              string `json:"outerCaptureSHA256"`
	ObserverReceiptSHA256           string `json:"observerReceiptSHA256"`
}

type Result struct {
	Manifest Manifest
	Attempt  AttemptEvidence
	Topology TopologyEvidence
}

type verificationHooks struct {
	afterOpen func(name string)
}

func Verify(
	manifestPath string,
	expectedManifestSHA256 string,
	expectedContractSHA256 string,
	expectedSourceSHA256 string,
	expectedVerifierSHA256 string,
) (Result, error) {
	return verifyWithHooks(
		manifestPath,
		expectedManifestSHA256,
		expectedContractSHA256,
		expectedSourceSHA256,
		expectedVerifierSHA256,
		verificationHooks{},
	)
}

func verifyWithHooks(
	manifestPath string,
	expectedManifestSHA256 string,
	expectedContractSHA256 string,
	expectedSourceSHA256 string,
	expectedVerifierSHA256 string,
	hooks verificationHooks,
) (Result, error) {
	var result Result
	if err := validateDigest(expectedManifestSHA256); err != nil {
		return result, errors.New("expected manifest pin is invalid")
	}
	if err := validateDigest(expectedContractSHA256); err != nil {
		return result, errors.New("expected contract pin is invalid")
	}
	if err := validateDigest(expectedSourceSHA256); err != nil {
		return result, errors.New("expected source pin is invalid")
	}
	if err := validateDigest(expectedVerifierSHA256); err != nil {
		return result, errors.New("expected verifier pin is invalid")
	}
	if filepath.Clean(manifestPath) != manifestPath ||
		filepath.Base(manifestPath) != "manifest.json" {
		return result, errors.New("manifest path or filename is not fixed")
	}
	root, err := openSecureRoot(filepath.Dir(manifestPath))
	if err != nil {
		return result, errors.New("cannot open evidence root")
	}
	defer root.Close()
	manifestBytes, err := root.readRegular(
		"manifest.json",
		maxManifestBytes,
		hooks,
	)
	if err != nil {
		return result, fmt.Errorf("manifest: %w", err)
	}
	if digest(manifestBytes) != expectedManifestSHA256 {
		return result, errors.New("manifest bytes do not match independent pin")
	}
	if err := decodeCanonicalJSON(manifestBytes, &result.Manifest); err != nil {
		return result, fmt.Errorf("manifest: %w", err)
	}
	if err := validateManifest(
		result.Manifest,
		expectedContractSHA256,
		expectedSourceSHA256,
		expectedVerifierSHA256,
	); err != nil {
		return result, err
	}
	evidenceBytes, err := root.readRegular(
		result.Manifest.EvidencePath,
		maxEvidenceBytes,
		hooks,
	)
	if err != nil {
		return result, fmt.Errorf("attempt evidence: %w", err)
	}
	topologyBytes, err := root.readRegular(
		result.Manifest.TopologyPath,
		maxEvidenceBytes,
		hooks,
	)
	if err != nil {
		return result, fmt.Errorf("topology evidence: %w", err)
	}
	if digest(evidenceBytes) != result.Manifest.EvidenceSHA256 {
		return result, errors.New("attempt evidence digest mismatch")
	}
	if digest(topologyBytes) != result.Manifest.TopologySHA256 {
		return result, errors.New("topology evidence digest mismatch")
	}
	if err := decodeCanonicalJSON(
		evidenceBytes,
		&result.Attempt,
	); err != nil {
		return result, fmt.Errorf("attempt evidence: %w", err)
	}
	if err := decodeCanonicalJSON(
		topologyBytes,
		&result.Topology,
	); err != nil {
		return result, fmt.Errorf("topology evidence: %w", err)
	}
	if err := validateAttempt(result.Attempt, result.Manifest); err != nil {
		return result, err
	}
	if err := validateTopology(result.Topology, result.Manifest, result.Attempt); err != nil {
		return result, err
	}
	return result, nil
}

func validateManifest(
	manifest Manifest,
	expectedContract string,
	expectedSource string,
	expectedVerifier string,
) error {
	if manifest.Schema != manifestSchema {
		return errors.New("manifest schema is not physical Stage B schema")
	}
	if manifest.ProtocolVersion != protocolVersion ||
		manifest.MeasurementScope != measurementScope {
		return errors.New("manifest protocol or measurement scope mismatch")
	}
	for name, value := range map[string]string{
		"contract":           manifest.ContractSHA256,
		"source":             manifest.SourceSHA256,
		"host artifact":      manifest.HostArtifactSHA256,
		"provider artifact":  manifest.ProviderArtifactSHA256,
		"AWG artifact":       manifest.AWGArtifactSHA256,
		"AWG config":         manifest.AWGConfigSHA256,
		"expected AWG peer":  manifest.ExpectedAWGPeerSHA256,
		"interface token":    manifest.WinningInterfaceTokenSHA256,
		"reflector artifact": manifest.ReflectorArtifactSHA256,
		"reflector config":   manifest.ReflectorConfigSHA256,
		"DNS config":         manifest.DNSConfigSHA256,
		"verifier":           manifest.VerifierSHA256,
		"attempt evidence":   manifest.EvidenceSHA256,
		"topology evidence":  manifest.TopologySHA256,
	} {
		if err := validateDigest(value); err != nil {
			return fmt.Errorf("%s pin is invalid", name)
		}
	}
	if manifest.ContractSHA256 != expectedContract {
		return errors.New("contract pin mismatch")
	}
	if manifest.SourceSHA256 != expectedSource {
		return errors.New("source pin mismatch")
	}
	if manifest.VerifierSHA256 != expectedVerifier {
		return errors.New("verifier pin mismatch")
	}
	if manifest.EvidencePath != "evidence/attempt.json" ||
		manifest.TopologyPath != "proof/topology.json" {
		return errors.New("manifest paths are not the fixed evidence allowlist")
	}
	if !validUUID(manifest.AWGEngineInstanceNonce) ||
		manifest.AWGEngineGeneration == 0 ||
		manifest.WinningPathGeneration == 0 {
		return errors.New("manifest AWG engine or path precommit is invalid")
	}
	return nil
}

func validateAttempt(attempt AttemptEvidence, manifest Manifest) error {
	if attempt.Schema != attemptSchema {
		return errors.New("attempt schema is not physical Stage B schema")
	}
	if attempt.ProtocolVersion != protocolVersion ||
		attempt.MeasurementScope != measurementScope {
		return errors.New("attempt protocol or measurement scope mismatch")
	}
	if attempt.T0Source != t0Source {
		return errors.New("T0 source is not the first Connect-handler operation")
	}
	if !validUUID(attempt.RunID) || !validUUID(attempt.AttemptNonce) {
		return errors.New("run or attempt identifier is invalid")
	}
	if attempt.Mode != "core" && attempt.Mode != "maximum-privacy" {
		return errors.New("mode is invalid")
	}
	if attempt.Radio != "wifi" && attempt.Radio != "cellular" {
		return errors.New("radio is invalid")
	}
	if attempt.Readiness != "warm" && attempt.Readiness != "cold" {
		return errors.New("readiness is invalid")
	}
	if err := validatePins(attempt.Pins, manifest); err != nil {
		return err
	}
	if err := validateBinding(attempt); err != nil {
		return err
	}
	deadline, overflow := checkedAdd(
		attempt.ConnectButtonT0MonotonicNanoseconds,
		deadlineNanoseconds,
	)
	if overflow {
		return errors.New("T0 deadline overflows")
	}
	if err := validatePredicates(attempt, deadline); err != nil {
		return err
	}
	if err := validateAWG(attempt, deadline); err != nil {
		return err
	}
	if err := validateDNS(attempt, manifest.TopologySHA256, deadline); err != nil {
		return err
	}
	if err := validateReflector(attempt, manifest.TopologySHA256, deadline); err != nil {
		return err
	}
	if err := validateTerminal(attempt, deadline); err != nil {
		return err
	}
	if !attempt.CleanHost.Admitted ||
		attempt.CleanHost.DeviceThermalState != "nominal" ||
		attempt.CleanHost.LowPowerMode != "off" ||
		attempt.CleanHost.OtherVPNActive ||
		attempt.CleanHost.HostStressActive {
		return errors.New("clean-host admission failed")
	}
	if err := validateDigest(attempt.CleanHost.ObservationSHA256); err != nil {
		return errors.New("clean-host observation pin is invalid")
	}
	return nil
}

func validatePins(pins Pins, manifest Manifest) error {
	expected := Pins{
		ContractSHA256:              manifest.ContractSHA256,
		SourceSHA256:                manifest.SourceSHA256,
		HostArtifactSHA256:          manifest.HostArtifactSHA256,
		ProviderArtifactSHA256:      manifest.ProviderArtifactSHA256,
		AWGArtifactSHA256:           manifest.AWGArtifactSHA256,
		AWGConfigSHA256:             manifest.AWGConfigSHA256,
		ExpectedAWGPeerSHA256:       manifest.ExpectedAWGPeerSHA256,
		AWGEngineInstanceNonce:      manifest.AWGEngineInstanceNonce,
		AWGEngineGeneration:         manifest.AWGEngineGeneration,
		WinningPathGeneration:       manifest.WinningPathGeneration,
		WinningInterfaceTokenSHA256: manifest.WinningInterfaceTokenSHA256,
		ReflectorArtifactSHA256:     manifest.ReflectorArtifactSHA256,
		ReflectorConfigSHA256:       manifest.ReflectorConfigSHA256,
		DNSConfigSHA256:             manifest.DNSConfigSHA256,
		VerifierSHA256:              manifest.VerifierSHA256,
	}
	if pins != expected {
		return errors.New("attempt provenance pins do not match manifest")
	}
	return nil
}

func validateBinding(attempt AttemptEvidence) error {
	binding := attempt.Binding
	if binding.RunID != attempt.RunID ||
		binding.AttemptNonce != attempt.AttemptNonce ||
		binding.RequestedAtMonotonicNanoseconds !=
			attempt.ConnectButtonT0MonotonicNanoseconds {
		return errors.New("T0 or attempt identity changed before binding")
	}
	for _, identifier := range []string{
		binding.RunID,
		binding.AttemptNonce,
		binding.PathID,
		binding.WCF3SessionID,
		binding.WCF3BindingID,
		binding.AWGEngineInstanceNonce,
	} {
		if !validUUID(identifier) {
			return errors.New("binding identifier is invalid")
		}
	}
	if !allDistinct(
		binding.RunID,
		binding.AttemptNonce,
		binding.PathID,
		binding.WCF3SessionID,
		binding.WCF3BindingID,
		binding.AWGEngineInstanceNonce,
	) {
		return errors.New("binding identifiers are not independently generated")
	}
	if binding.PSKGeneration == 0 ||
		binding.SequenceEpoch == 0 ||
		binding.CanarySequence == 0 ||
		binding.AWGEngineGeneration == 0 ||
		binding.WinningPathGeneration == 0 {
		return errors.New("binding generation or sequence is zero")
	}
	if binding.AWGConfigSHA256 != attempt.Pins.AWGConfigSHA256 ||
		binding.ExpectedAWGPeerSHA256 != attempt.Pins.ExpectedAWGPeerSHA256 ||
		binding.AWGEngineInstanceNonce != attempt.Pins.AWGEngineInstanceNonce ||
		binding.AWGEngineGeneration != attempt.Pins.AWGEngineGeneration ||
		binding.WinningPathGeneration != attempt.Pins.WinningPathGeneration ||
		binding.WinningInterfaceTokenSHA256 !=
			attempt.Pins.WinningInterfaceTokenSHA256 {
		return errors.New("binding AWG engine or winning path precommit mismatch")
	}
	for _, value := range []string{
		binding.AWGConfigSHA256,
		binding.ExpectedAWGPeerSHA256,
		binding.WinningInterfaceTokenSHA256,
	} {
		if err := validateDigest(value); err != nil {
			return errors.New("binding AWG digest is invalid")
		}
	}
	if err := validateDigest(binding.BindingSHA256); err != nil {
		return errors.New("binding digest is invalid")
	}
	if binding.BindingSHA256 != bindingDigest(binding) {
		return errors.New("binding digest mismatch")
	}
	return nil
}

func validatePredicates(attempt AttemptEvidence, deadline uint64) error {
	for name, predicate := range map[string]Predicate{
		"fresh AWG handshake":               attempt.Predicates.FreshAWGHandshake,
		"authenticated bidirectional bytes": attempt.Predicates.AuthenticatedBidirectionalBytes,
		"protected DNS":                     attempt.Predicates.ProtectedDNS,
		"authenticated reflector":           attempt.Predicates.AuthenticatedReflector,
	} {
		if predicate.BindingSHA256 != attempt.Binding.BindingSHA256 {
			return fmt.Errorf("%s binding mismatch", name)
		}
		if predicate.Observed {
			if predicate.AtMonotonicNanoseconds <
				attempt.ConnectButtonT0MonotonicNanoseconds ||
				predicate.AtMonotonicNanoseconds > deadline {
				return fmt.Errorf("%s timestamp is outside the deadline", name)
			}
		} else if predicate.AtMonotonicNanoseconds != 0 {
			return fmt.Errorf("%s has a timestamp without observation", name)
		}
	}
	return nil
}

func validateAWG(attempt AttemptEvidence, deadline uint64) error {
	proof := attempt.AWG
	if proof.BindingSHA256 != attempt.Binding.BindingSHA256 ||
		proof.PSKGeneration != attempt.Binding.PSKGeneration {
		return errors.New("AWG proof binding mismatch")
	}
	expectedIdentity := AWGSampleIdentity{
		PeerPublicKeySHA256:         attempt.Binding.ExpectedAWGPeerSHA256,
		ConfigSHA256:                attempt.Binding.AWGConfigSHA256,
		EngineInstanceNonce:         attempt.Binding.AWGEngineInstanceNonce,
		EngineGeneration:            attempt.Binding.AWGEngineGeneration,
		PathGeneration:              attempt.Binding.WinningPathGeneration,
		WinningInterfaceTokenSHA256: attempt.Binding.WinningInterfaceTokenSHA256,
	}
	if proof.BaselineIdentity != expectedIdentity ||
		proof.HandshakePostIdentity != expectedIdentity ||
		proof.CounterPostIdentity != expectedIdentity {
		return errors.New("AWG baseline or post sample identity changed")
	}
	if proof.BaselineSampleAtMonotonicNanoseconds <
		attempt.ConnectButtonT0MonotonicNanoseconds ||
		proof.HandshakePostSampleAtMonotonicNanoseconds <
			proof.BaselineSampleAtMonotonicNanoseconds ||
		proof.CounterPostSampleAtMonotonicNanoseconds <
			proof.BaselineSampleAtMonotonicNanoseconds ||
		proof.CounterPostSampleAtMonotonicNanoseconds <
			proof.HandshakePostSampleAtMonotonicNanoseconds ||
		proof.HandshakePostSampleAtMonotonicNanoseconds > deadline ||
		proof.CounterPostSampleAtMonotonicNanoseconds > deadline {
		return errors.New("AWG sample order is invalid")
	}
	txDelta, txUnderflow := checkedSubtract(
		proof.PostAuthenticatedTxBytes,
		proof.BaselineAuthenticatedTxBytes,
	)
	rxDelta, rxUnderflow := checkedSubtract(
		proof.PostAuthenticatedRxBytes,
		proof.BaselineAuthenticatedRxBytes,
	)
	if txUnderflow || rxUnderflow {
		return errors.New("AWG authenticated counter rolled back")
	}
	if txDelta != proof.AuthenticatedOutboundDeltaBytes ||
		rxDelta != proof.AuthenticatedInboundDeltaBytes {
		return errors.New("AWG authenticated counter delta mismatch")
	}
	fresh := proof.PostLatestHandshakeUnixMilliseconds >
		proof.BaselineLatestHandshakeUnixMilliseconds
	if proof.Fresh != fresh ||
		proof.Fresh != attempt.Predicates.FreshAWGHandshake.Observed {
		return errors.New("AWG fresh-handshake proof mismatch")
	}
	if proof.Fresh &&
		attempt.Predicates.FreshAWGHandshake.AtMonotonicNanoseconds !=
			proof.HandshakePostSampleAtMonotonicNanoseconds {
		return errors.New("AWG handshake predicate is not the supporting sample")
	}
	bidirectional := txDelta > 0 && rxDelta > 0
	if bidirectional !=
		attempt.Predicates.AuthenticatedBidirectionalBytes.Observed {
		return errors.New("AWG bidirectional-byte proof mismatch")
	}
	if bidirectional &&
		attempt.Predicates.AuthenticatedBidirectionalBytes.
			AtMonotonicNanoseconds !=
			proof.CounterPostSampleAtMonotonicNanoseconds {
		return errors.New("byte predicate is not the supporting sample")
	}
	return nil
}

func validateDNS(
	attempt AttemptEvidence,
	topologySHA256 string,
	deadline uint64,
) error {
	proof := attempt.DNS
	if proof.BindingSHA256 != attempt.Binding.BindingSHA256 ||
		proof.ConfigSHA256 != attempt.Pins.DNSConfigSHA256 ||
		proof.TopologySHA256 != topologySHA256 {
		return errors.New("protected-DNS proof binding mismatch")
	}
	for name, value := range map[string]string{
		"query nonce":      proof.QueryNonceSHA256,
		"response payload": proof.ResponsePayloadSHA256,
	} {
		if err := validateDigest(value); err != nil {
			return fmt.Errorf("protected-DNS %s pin is invalid", name)
		}
	}
	if proof.Observed != attempt.Predicates.ProtectedDNS.Observed {
		return errors.New("protected-DNS predicate mismatch")
	}
	switch {
	case !proof.Attempted:
		if proof.Observed ||
			proof.RequestAtMonotonicNanoseconds != 0 ||
			proof.ResponseAtMonotonicNanoseconds != 0 ||
			proof.CacheBypassed ||
			proof.TunnelOnly {
			return errors.New("unattempted protected DNS has event state")
		}
	case proof.Observed:
		if !attempt.Predicates.AuthenticatedBidirectionalBytes.Observed ||
			!proof.CacheBypassed ||
			!proof.TunnelOnly {
			return errors.New("protected-DNS success lacks tunnel/cache proof")
		}
		if !withinAttempt(
			proof.RequestAtMonotonicNanoseconds,
			attempt.ConnectButtonT0MonotonicNanoseconds,
			deadline,
		) ||
			proof.RequestAtMonotonicNanoseconds <
				attempt.Predicates.AuthenticatedBidirectionalBytes.
					AtMonotonicNanoseconds ||
			proof.ResponseAtMonotonicNanoseconds <
				proof.RequestAtMonotonicNanoseconds ||
			proof.ResponseAtMonotonicNanoseconds > deadline ||
			proof.ResponseAtMonotonicNanoseconds !=
				attempt.Predicates.ProtectedDNS.AtMonotonicNanoseconds {
			return errors.New("protected-DNS time proof mismatch")
		}
	default:
		if !attempt.Predicates.AuthenticatedBidirectionalBytes.Observed ||
			!proof.CacheBypassed ||
			!proof.TunnelOnly ||
			!withinAttempt(
				proof.RequestAtMonotonicNanoseconds,
				attempt.ConnectButtonT0MonotonicNanoseconds,
				deadline,
			) ||
			proof.RequestAtMonotonicNanoseconds <
				attempt.Predicates.AuthenticatedBidirectionalBytes.
					AtMonotonicNanoseconds ||
			proof.ResponseAtMonotonicNanoseconds != 0 {
			return errors.New("attempted unobserved protected DNS is inconsistent")
		}
	}
	return nil
}

func validateReflector(
	attempt AttemptEvidence,
	topologySHA256 string,
	deadline uint64,
) error {
	proof := attempt.Reflector
	if proof.BindingSHA256 != attempt.Binding.BindingSHA256 ||
		proof.ArtifactSHA256 != attempt.Pins.ReflectorArtifactSHA256 ||
		proof.ConfigSHA256 != attempt.Pins.ReflectorConfigSHA256 ||
		proof.TopologySHA256 != topologySHA256 ||
		proof.CanarySequence != attempt.Binding.CanarySequence {
		return errors.New("reflector proof binding mismatch")
	}
	if proof.Observed != attempt.Predicates.AuthenticatedReflector.Observed {
		return errors.New("reflector predicate mismatch")
	}
	switch {
	case !proof.Attempted:
		if proof.Observed ||
			proof.RequestSentAtMonotonicNanoseconds != 0 ||
			proof.ResponseObservedAtMonotonicNanoseconds != 0 ||
			proof.Authenticated ||
			proof.TunnelOnly {
			return errors.New("unattempted reflector has event state")
		}
	case proof.Observed:
		if !attempt.Predicates.ProtectedDNS.Observed ||
			!proof.Authenticated ||
			!proof.TunnelOnly {
			return errors.New("reflector success lacks authentication/topology proof")
		}
		if !withinAttempt(
			proof.RequestSentAtMonotonicNanoseconds,
			attempt.ConnectButtonT0MonotonicNanoseconds,
			deadline,
		) ||
			proof.RequestSentAtMonotonicNanoseconds <
				attempt.Predicates.ProtectedDNS.AtMonotonicNanoseconds ||
			proof.ResponseObservedAtMonotonicNanoseconds <
				proof.RequestSentAtMonotonicNanoseconds ||
			proof.ResponseObservedAtMonotonicNanoseconds > deadline ||
			proof.ResponseObservedAtMonotonicNanoseconds !=
				attempt.Predicates.AuthenticatedReflector.AtMonotonicNanoseconds {
			return errors.New("reflector time proof mismatch")
		}
	default:
		if !attempt.Predicates.ProtectedDNS.Observed ||
			proof.Authenticated ||
			!proof.TunnelOnly ||
			!withinAttempt(
				proof.RequestSentAtMonotonicNanoseconds,
				attempt.ConnectButtonT0MonotonicNanoseconds,
				deadline,
			) ||
			proof.RequestSentAtMonotonicNanoseconds <
				attempt.Predicates.ProtectedDNS.AtMonotonicNanoseconds ||
			proof.ResponseObservedAtMonotonicNanoseconds != 0 {
			return errors.New("attempted unobserved reflector is inconsistent")
		}
	}
	return nil
}

func validateTerminal(attempt AttemptEvidence, deadline uint64) error {
	terminal := attempt.Terminal
	if terminal.TerminalAtMonotonicNanoseconds <
		attempt.ConnectButtonT0MonotonicNanoseconds ||
		terminal.TUIMonotonicNanoseconds <
			terminal.TerminalAtMonotonicNanoseconds {
		return errors.New("terminal or UI chronology is invalid")
	}
	if terminal.State == "failed" &&
		terminal.FailureCode == "deadline-exceeded" {
		firstFailureInstant, overflow := checkedAdd(deadline, 1)
		if overflow ||
			terminal.DeadlineFailureReportingBudgetNanoseconds !=
				maxDeadlineFailureReportingNanoseconds {
			return errors.New("deadline failure reporting contract is invalid")
		}
		reportingDeadline, overflow := checkedAdd(
			deadline,
			terminal.DeadlineFailureReportingBudgetNanoseconds,
		)
		if overflow ||
			terminal.TerminalAtMonotonicNanoseconds < firstFailureInstant ||
			terminal.TerminalAtMonotonicNanoseconds > reportingDeadline ||
			terminal.TUIMonotonicNanoseconds > reportingDeadline {
			return errors.New("deadline failure UI exceeds its bounded reporting window")
		}
	} else if terminal.TerminalAtMonotonicNanoseconds > deadline ||
		terminal.TUIMonotonicNanoseconds > deadline ||
		terminal.DeadlineFailureReportingBudgetNanoseconds != 0 {
		return errors.New("non-deadline terminal or UI decision exceeds the success deadline")
	}
	if err := validateNoLateEvents(attempt, terminal.TerminalAtMonotonicNanoseconds); err != nil {
		return err
	}
	all := attempt.Predicates.FreshAWGHandshake.Observed &&
		attempt.Predicates.AuthenticatedBidirectionalBytes.Observed &&
		attempt.Predicates.ProtectedDNS.Observed &&
		attempt.Predicates.AuthenticatedReflector.Observed
	switch terminal.State {
	case "succeeded":
		if terminal.FailureCode != "none" ||
			!all ||
			terminal.TDataMonotonicNanoseconds == 0 ||
			terminal.TDataMonotonicNanoseconds >
				terminal.TerminalAtMonotonicNanoseconds ||
			terminal.TDataMonotonicNanoseconds > deadline ||
			terminal.CleanupState != "not-required" ||
			terminal.CleanupAtMonotonicNanoseconds != 0 ||
			terminal.CleanupBudgetNanoseconds != maxCleanupNanoseconds {
			return errors.New("success terminal evidence is inconsistent")
		}
		for _, predicate := range []Predicate{
			attempt.Predicates.FreshAWGHandshake,
			attempt.Predicates.AuthenticatedBidirectionalBytes,
			attempt.Predicates.ProtectedDNS,
			attempt.Predicates.AuthenticatedReflector,
		} {
			if terminal.TDataMonotonicNanoseconds <
				predicate.AtMonotonicNanoseconds {
				return errors.New("tdata precedes a required predicate")
			}
		}
	case "failed", "cancelled", "superseded":
		if terminal.FailureCode == "none" ||
			!validFailureCode(terminal.State, terminal.FailureCode) ||
			terminal.CleanupState != "complete" ||
			terminal.CleanupBudgetNanoseconds != maxCleanupNanoseconds ||
			terminal.CleanupAtMonotonicNanoseconds <
				terminal.TerminalAtMonotonicNanoseconds {
			return errors.New("failure terminal evidence is inconsistent")
		}
		cleanupDeadline, overflow := checkedAdd(
			terminal.TerminalAtMonotonicNanoseconds,
			terminal.CleanupBudgetNanoseconds,
		)
		if overflow ||
			terminal.CleanupAtMonotonicNanoseconds > cleanupDeadline {
			return errors.New("cleanup exceeds its bounded budget")
		}
		if terminal.State == "failed" &&
			terminal.FailureCode == "evidence-persistence-failed" {
			if !all ||
				terminal.TDataMonotonicNanoseconds == 0 ||
				terminal.TDataMonotonicNanoseconds >
					terminal.TerminalAtMonotonicNanoseconds {
				return errors.New("persistence failure lacks completed data proof")
			}
		} else if all || terminal.TDataMonotonicNanoseconds != 0 {
			return errors.New("non-persistence failure has success data state")
		}
		if err := validateFailureProgression(attempt); err != nil {
			return err
		}
	default:
		return errors.New("terminal state is invalid")
	}
	return nil
}

func validateNoLateEvents(attempt AttemptEvidence, terminal uint64) error {
	events := []uint64{
		attempt.Binding.RequestedAtMonotonicNanoseconds,
		attempt.Predicates.FreshAWGHandshake.AtMonotonicNanoseconds,
		attempt.Predicates.AuthenticatedBidirectionalBytes.AtMonotonicNanoseconds,
		attempt.Predicates.ProtectedDNS.AtMonotonicNanoseconds,
		attempt.Predicates.AuthenticatedReflector.AtMonotonicNanoseconds,
		attempt.AWG.BaselineSampleAtMonotonicNanoseconds,
		attempt.AWG.HandshakePostSampleAtMonotonicNanoseconds,
		attempt.AWG.CounterPostSampleAtMonotonicNanoseconds,
		attempt.DNS.RequestAtMonotonicNanoseconds,
		attempt.DNS.ResponseAtMonotonicNanoseconds,
		attempt.Reflector.RequestSentAtMonotonicNanoseconds,
		attempt.Reflector.ResponseObservedAtMonotonicNanoseconds,
	}
	for _, event := range events {
		if event != 0 && event > terminal {
			return errors.New("predicate, sample, request, or response follows terminal state")
		}
	}
	return nil
}

func validateFailureProgression(attempt AttemptEvidence) error {
	handshake := attempt.Predicates.FreshAWGHandshake.Observed
	bytes := attempt.Predicates.AuthenticatedBidirectionalBytes.Observed
	dns := attempt.Predicates.ProtectedDNS.Observed
	reflector := attempt.Predicates.AuthenticatedReflector.Observed
	if (!handshake && (bytes || dns || reflector)) ||
		(!bytes && (dns || reflector)) ||
		(!dns && reflector) ||
		(!bytes && attempt.DNS.Attempted) ||
		(!dns && attempt.Reflector.Attempted) {
		return errors.New("failure contains an out-of-order or late predicate")
	}
	if attempt.Terminal.State != "failed" {
		return nil
	}
	switch attempt.Terminal.FailureCode {
	case "awg-handshake-failed":
		if handshake || bytes || dns || reflector {
			return errors.New("AWG-handshake failure code mismatches predicates")
		}
	case "tunnel-bytes-failed":
		if !handshake || bytes || dns || reflector {
			return errors.New("tunnel-byte failure code mismatches predicates")
		}
	case "protected-dns-failed":
		if !handshake || !bytes || dns || reflector ||
			!attempt.DNS.Attempted {
			return errors.New("protected-DNS failure code mismatches predicates")
		}
	case "reflector-failed":
		if !handshake || !bytes || !dns || reflector ||
			!attempt.Reflector.Attempted {
			return errors.New("reflector failure code mismatches predicates")
		}
	case "deadline-exceeded":
		if handshake && bytes && dns && reflector {
			return errors.New("deadline failure cannot follow all predicates")
		}
	case "evidence-persistence-failed":
		if !handshake || !bytes || !dns || !reflector {
			return errors.New("persistence failure precedes a required predicate")
		}
	}
	return nil
}

func validateTopology(
	topology TopologyEvidence,
	manifest Manifest,
	attempt AttemptEvidence,
) error {
	if topology.Schema != topologySchema ||
		topology.ProtocolVersion != protocolVersion ||
		topology.MeasurementScope != measurementScope {
		return errors.New("topology schema, protocol, or scope mismatch")
	}
	if topology.RunID != attempt.RunID ||
		topology.AWGArtifactSHA256 != manifest.AWGArtifactSHA256 ||
		topology.AWGConfigSHA256 != manifest.AWGConfigSHA256 ||
		topology.ExpectedAWGPeerSHA256 != manifest.ExpectedAWGPeerSHA256 ||
		topology.AWGEngineInstanceNonce != manifest.AWGEngineInstanceNonce ||
		topology.AWGEngineGeneration != manifest.AWGEngineGeneration ||
		topology.WinningPathGeneration != manifest.WinningPathGeneration ||
		topology.WinningInterfaceTokenSHA256 !=
			manifest.WinningInterfaceTokenSHA256 ||
		topology.ReflectorArtifactSHA256 != manifest.ReflectorArtifactSHA256 ||
		topology.ReflectorConfigSHA256 != manifest.ReflectorConfigSHA256 ||
		topology.DNSConfigSHA256 != manifest.DNSConfigSHA256 {
		return errors.New("topology provenance pins do not match manifest")
	}
	if topology.DNSDirectPreTunnel != "blocked" ||
		topology.DNSDirectPostTeardown != "blocked" ||
		topology.ReflectorDirectPreTunnel != "blocked" ||
		topology.ReflectorDirectPostTeardown != "blocked" ||
		topology.ReflectorAcceptedIngress != "awg-inner-only" ||
		topology.OuterPlaintextDNSObserved ||
		topology.OuterPlaintextReflectorObserved {
		return errors.New("tunnel-only topology proof failed")
	}
	for name, value := range map[string]string{
		"firewall snapshot": topology.FirewallSnapshotSHA256,
		"route snapshot":    topology.RouteSnapshotSHA256,
		"outer capture":     topology.OuterCaptureSHA256,
		"observer receipt":  topology.ObserverReceiptSHA256,
	} {
		if err := validateDigest(value); err != nil {
			return fmt.Errorf("%s pin is invalid", name)
		}
	}
	return nil
}

func validFailureCode(state, code string) bool {
	switch state {
	case "cancelled":
		return code == "cancelled"
	case "superseded":
		return code == "superseded"
	case "failed":
		switch code {
		case "deadline-exceeded",
			"awg-handshake-failed",
			"tunnel-bytes-failed",
			"protected-dns-failed",
			"reflector-failed",
			"evidence-persistence-failed":
			return true
		}
	}
	return false
}

func bindingDigest(binding Binding) string {
	values := []string{
		binding.RunID,
		binding.AttemptNonce,
		binding.PathID,
		binding.WCF3SessionID,
		binding.WCF3BindingID,
		strconv.FormatUint(binding.PSKGeneration, 10),
		strconv.FormatUint(binding.SequenceEpoch, 10),
		strconv.FormatUint(binding.CanarySequence, 10),
		strconv.FormatUint(binding.RequestedAtMonotonicNanoseconds, 10),
		binding.AWGConfigSHA256,
		binding.ExpectedAWGPeerSHA256,
		binding.AWGEngineInstanceNonce,
		strconv.FormatUint(binding.AWGEngineGeneration, 10),
		strconv.FormatUint(binding.WinningPathGeneration, 10),
		binding.WinningInterfaceTokenSHA256,
	}
	hash := sha256.New()
	_, _ = io.WriteString(hash, bindingDomain)
	_, _ = io.WriteString(hash, strings.Join(values, "\x00"))
	return hex.EncodeToString(hash.Sum(nil))
}

func validateDigest(value string) error {
	if !lowerHex64.MatchString(value) ||
		value == strings.Repeat("0", 64) {
		return errors.New("not a nonzero lowercase SHA-256")
	}
	return nil
}

func validUUID(value string) bool {
	return lowerUUID.MatchString(value) &&
		value != "00000000-0000-0000-0000-000000000000"
}

func allDistinct(values ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func withinAttempt(value, t0, deadline uint64) bool {
	return value >= t0 && value <= deadline
}

func validateRelativePath(name string) error {
	switch name {
	case "manifest.json", "evidence/attempt.json", "proof/topology.json":
		return nil
	default:
		return errors.New("path is not in the fixed evidence allowlist")
	}
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, errors.New("cannot read file")
	}
	if len(content) == 0 || int64(len(content)) > maximum {
		return nil, errors.New("file size is outside the allowed range")
	}
	return content, nil
}

func checkedSubtract(post, baseline uint64) (uint64, bool) {
	if post < baseline {
		return 0, true
	}
	return post - baseline, false
}

func checkedAdd(left, right uint64) (uint64, bool) {
	sum := left + right
	return sum, sum < left
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// MarshalCanonical is used only by deterministic tests and future fixture
// producers. Production verification still accepts caller-owned bytes only
// after strict parsing and byte-for-byte canonical comparison.
func MarshalCanonical(value any) ([]byte, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}
