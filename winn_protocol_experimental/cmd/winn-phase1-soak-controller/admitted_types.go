package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

const (
	admittedMode               = "admitted-e3-preflight"
	admittedModeSchema         = "winn-phase1-controller-mode/v1"
	admittedReceiptSchema      = "winn-phase1-admitted-preflight-receipt/v1"
	admittedCheckpointSchema   = "winn-phase1-admitted-preflight-checkpoint/v1"
	admittedResultSchema       = "winn-real-cycle-admitted-adapter-preflight/v2"
	admittedReceiptDomain      = "winn-phase1-admitted-preflight-receipt-object/v1"
	admittedCheckpointDomain   = "winn-phase1-admitted-preflight-checkpoint-object/v1"
	admittedModeDomain         = "winn-phase1-controller-mode-object/v1"
	admittedCollectionDomain   = "winn-phase1-admitted-preflight-receipt-collection/v1"
	admittedGenesisDigest      = "0000000000000000000000000000000000000000000000000000000000000000"
	admittedModeFile           = "controller-mode.json"
	admittedReceiptFile        = "admitted-preflight-receipts.jsonl"
	admittedCheckpointFile     = "admitted-checkpoint.json"
	admittedCheckpointKeyFile  = "admitted-checkpoint.key"
	admittedNonceFile          = "admitted-instance.nonce"
	admittedAttemptsDirectory  = "admitted-attempts"
	admittedContractsDirectory = "admitted-contracts"
	admittedMaximumObjectBytes = 256 << 10
	admittedMaximumReceipts    = 1_000_000
)

var admittedRelativePathPattern = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,511}$`,
)

var admittedPlatform = runtime.GOOS

type AdmittedConfig struct {
	RunID string

	StateRoot    string
	EvidenceRoot string
	SnapshotRoot string

	AdmissionPath string
	TrustPath     string
	TopologyPath  string

	LauncherPath   string
	LauncherSHA256 string
	AdapterPath    string
	AdapterSHA256  string
	ManifestPath   string
	VerifierPath   string

	Profile             string
	MatrixRelativePath  string
	MatrixSHA256        string
	SnapshotSHA256      string
	SnapshotFileCount   uint64
	SourceSHA256        string
	ManifestSHA256      string
	VerifierSHA256      string
	ConfigurationSHA256 string
	Timeout             time.Duration
}

func (c AdmittedConfig) Validate() error {
	if admittedPlatform != "linux" {
		return errors.New(
			"admitted E3 preflight is Linux-only; refusing before attempt creation",
		)
	}
	if !identifierPattern.MatchString(c.RunID) ||
		!identifierPattern.MatchString(c.Profile) {
		return errors.New("admitted run ID and profile must be valid identifiers")
	}
	for label, value := range map[string]string{
		"launcher": c.LauncherSHA256, "adapter": c.AdapterSHA256,
		"matrix": c.MatrixSHA256, "snapshot": c.SnapshotSHA256,
		"source": c.SourceSHA256, "manifest": c.ManifestSHA256,
		"verifier": c.VerifierSHA256, "configuration": c.ConfigurationSHA256,
	} {
		if !digestPattern.MatchString(value) {
			return fmt.Errorf("%s SHA-256 is malformed", label)
		}
	}
	if c.SnapshotFileCount == 0 {
		return errors.New("snapshot file count must be positive")
	}
	for label, value := range map[string]string{
		"state root": c.StateRoot, "evidence root": c.EvidenceRoot,
		"snapshot root": c.SnapshotRoot, "admission": c.AdmissionPath,
		"trust": c.TrustPath, "topology": c.TopologyPath,
		"launcher": c.LauncherPath, "adapter": c.AdapterPath,
		"manifest": c.ManifestPath, "verifier": c.VerifierPath,
	} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%s must be absolute", label)
		}
	}
	if err := requireDisjoint(
		"-state-root", c.StateRoot, "-evidence-root", c.EvidenceRoot,
	); err != nil {
		return err
	}
	if err := requireDisjoint(
		"-state-root", c.StateRoot, "-snapshot-root", c.SnapshotRoot,
	); err != nil {
		return err
	}
	if err := requireDisjoint(
		"-evidence-root", c.EvidenceRoot, "-snapshot-root", c.SnapshotRoot,
	); err != nil {
		return err
	}
	if !admittedRelativePathPattern.MatchString(c.MatrixRelativePath) ||
		filepath.IsAbs(c.MatrixRelativePath) ||
		filepath.Clean(c.MatrixRelativePath) != c.MatrixRelativePath ||
		c.MatrixRelativePath == "." {
		return errors.New("matrix relative path is invalid")
	}
	if c.Timeout <= 0 || c.Timeout > 5*time.Minute {
		return errors.New("admitted timeout must be positive and at most five minutes")
	}
	return nil
}

func (c AdmittedConfig) digest() (string, error) {
	type frozen struct {
		RunID, StateRoot, EvidenceRoot, SnapshotRoot string
		AdmissionPath, TrustPath, TopologyPath       string
		LauncherPath, LauncherSHA256                 string
		AdapterPath, AdapterSHA256                   string
		ManifestPath, VerifierPath                   string
		Profile, MatrixRelativePath, MatrixSHA256    string
		SnapshotSHA256                               string
		SnapshotFileCount                            uint64
		SourceSHA256, ManifestSHA256                 string
		VerifierSHA256, ConfigurationSHA256          string
		TimeoutNanos                                 int64
	}
	return admittedDigest("winn-phase1-admitted-config/v1", frozen{
		RunID: c.RunID, StateRoot: c.StateRoot,
		EvidenceRoot: c.EvidenceRoot, SnapshotRoot: c.SnapshotRoot,
		AdmissionPath: c.AdmissionPath, TrustPath: c.TrustPath,
		TopologyPath: c.TopologyPath, LauncherPath: c.LauncherPath,
		LauncherSHA256: c.LauncherSHA256, AdapterPath: c.AdapterPath,
		AdapterSHA256: c.AdapterSHA256, ManifestPath: c.ManifestPath,
		VerifierPath: c.VerifierPath, Profile: c.Profile,
		MatrixRelativePath: c.MatrixRelativePath, MatrixSHA256: c.MatrixSHA256,
		SnapshotSHA256:    c.SnapshotSHA256,
		SnapshotFileCount: c.SnapshotFileCount, SourceSHA256: c.SourceSHA256,
		ManifestSHA256: c.ManifestSHA256, VerifierSHA256: c.VerifierSHA256,
		ConfigurationSHA256: c.ConfigurationSHA256,
		TimeoutNanos:        int64(c.Timeout),
	})
}

type admittedModeMarker struct {
	Schema                 string `json:"schema"`
	Mode                   string `json:"mode"`
	RunID                  string `json:"run_id"`
	ControllerConfigSHA256 string `json:"controller_config_sha256"`
	LauncherSHA256         string `json:"launcher_sha256"`
	AdapterSHA256          string `json:"adapter_sha256"`
	CreatedInstanceNonce   string `json:"created_instance_nonce"`
	Authority              bool   `json:"authority"`
	ObjectDigest           string `json:"object_digest"`
}

type admittedAdapterResult struct {
	Schema                   string `json:"schema"`
	Status                   string `json:"status"`
	Mode                     string `json:"mode"`
	CycleID                  string `json:"cycle_id"`
	AttemptID                string `json:"attempt_id"`
	TopologyID               string `json:"topology_id"`
	ControllerBindingDigest  string `json:"controller_binding_digest"`
	ControllerIntentDigest   string `json:"controller_intent_digest"`
	AdmissionBundleSHA256    string `json:"admission_bundle_sha256"`
	DispatchAuthorized       bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted bool   `json:"external_topology_executed"`
	MatrixExecuted           bool   `json:"matrix_executed"`
	ProviderAccess           bool   `json:"provider_access"`
	CredentialAccess         bool   `json:"credential_access"`
	Mutation                 string `json:"mutation"`
	Authority                bool   `json:"authority"`
}

type admittedReceipt struct {
	Schema           string `json:"schema"`
	RunID            string `json:"run_id"`
	Sequence         uint64 `json:"sequence"`
	InstanceNonce    string `json:"instance_nonce"`
	PredecessorNonce string `json:"predecessor_nonce"`
	PreviousDigest   string `json:"previous_receipt_digest"`

	AdmissionBundleSHA256   string `json:"admission_bundle_sha256"`
	AdmissionBindingDigest  string `json:"admission_binding_digest"`
	RuntimeCollectionDigest string `json:"runtime_collection_digest"`
	ReservationObjectDigest string `json:"reservation_object_digest"`

	BindingSHA256       string                `json:"controller_binding_sha256"`
	BindingObjectDigest string                `json:"controller_binding_object_digest"`
	IntentSHA256        string                `json:"controller_intent_sha256"`
	IntentObjectDigest  string                `json:"controller_intent_object_digest"`
	IntentState         string                `json:"controller_intent_state"`
	ResultSHA256        string                `json:"adapter_result_sha256"`
	Result              admittedAdapterResult `json:"adapter_result"`

	LauncherSHA256           string   `json:"launcher_sha256"`
	AdapterSHA256            string   `json:"adapter_sha256"`
	MatrixSHA256             string   `json:"matrix_sha256"`
	SnapshotSHA256           string   `json:"snapshot_sha256"`
	SourceSHA256             string   `json:"source_sha256"`
	ManifestSHA256           string   `json:"manifest_sha256"`
	VerifierSHA256           string   `json:"verifier_sha256"`
	ConfigurationSHA256      string   `json:"configuration_sha256"`
	ChildEnvironmentNames    []string `json:"child_environment_names"`
	AttemptDirectoryIdentity string   `json:"attempt_directory_identity"`

	DispatchAuthorized       bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted bool   `json:"external_topology_executed"`
	MatrixExecuted           bool   `json:"matrix_executed"`
	ProviderAccess           bool   `json:"provider_access"`
	CredentialAccess         bool   `json:"credential_access"`
	Mutation                 string `json:"mutation"`
	Authority                bool   `json:"authority"`
	ObjectDigest             string `json:"object_digest"`
}

type admittedCheckpoint struct {
	Schema                   string `json:"schema"`
	Mode                     string `json:"mode"`
	RunID                    string `json:"run_id"`
	ControllerConfigSHA256   string `json:"controller_config_sha256"`
	InstanceNonce            string `json:"instance_nonce"`
	PredecessorNonce         string `json:"predecessor_nonce"`
	ReceiptCount             uint64 `json:"receipt_count"`
	NextSequence             uint64 `json:"next_sequence"`
	LastReceiptDigest        string `json:"last_receipt_digest"`
	ReceiptCollectionDigest  string `json:"receipt_collection_digest"`
	LastBindingDigest        string `json:"last_binding_digest"`
	LastIntentDigest         string `json:"last_intent_digest"`
	LastResultSHA256         string `json:"last_result_sha256"`
	AttemptInventoryDigest   string `json:"attempt_inventory_digest"`
	MatrixCyclesExecuted     uint64 `json:"matrix_cycles_executed"`
	HandoffReady             bool   `json:"handoff_ready"`
	DispatchAuthorized       bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted bool   `json:"external_topology_executed"`
	ProviderAccess           bool   `json:"provider_access"`
	CredentialAccess         bool   `json:"credential_access"`
	Authority                bool   `json:"authority"`
	ObjectDigest             string `json:"object_digest"`
}

func admittedDigest(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func admittedRawSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func admittedCollectionDigest(digests []string) (string, error) {
	copyOf := append([]string(nil), digests...)
	return admittedDigest(admittedCollectionDomain, copyOf)
}
