package realcycle

import (
	"errors"
	"fmt"
	"path"
	"slices"
)

const (
	ControllerCycleBindingSchema = "winn-real-controller-cycle-binding/v1"

	controllerCycleBindingCoreDomain   = "winn-real-controller-cycle-binding-core/v1"
	controllerCycleBindingObjectDomain = "winn-real-controller-cycle-binding-object/v1"
)

var admittedReadinessValues = []string{"cold", "warm"}

var controllerAdapterEnvironmentNames = []string{
	"READINESS",
	"WINN_SOAK_ADAPTER_MODE",
	"WINN_SOAK_CYCLE_SEQUENCE",
	"WINN_SOAK_INSTANCE_NONCE",
	"WINN_SOAK_MATRIX_RELATIVE_PATH",
	"WINN_SOAK_MATRIX_SHA256",
	"WINN_SOAK_PROFILE",
	"WINN_SOAK_RUN_ID",
}

// ControllerBindingInput is the public, offline controller contract selected
// for one admitted preflight. It intentionally contains no credential, provider,
// endpoint, or execution authority.
type ControllerBindingInput struct {
	SoakRunID             string   `json:"soak_run_id"`
	Sequence              uint64   `json:"sequence"`
	InstanceNonce         string   `json:"instance_nonce"`
	PredecessorNonce      string   `json:"predecessor_nonce"`
	ResumeCount           uint64   `json:"resume_count"`
	Readiness             string   `json:"readiness"`
	Profile               string   `json:"profile"`
	RunnerSHA256          string   `json:"runner_sha256"`
	MatrixRelativePath    string   `json:"matrix_relative_path"`
	MatrixSHA256          string   `json:"matrix_sha256"`
	SnapshotSHA256        string   `json:"snapshot_sha256"`
	SnapshotFileCount     uint64   `json:"snapshot_file_count"`
	SourceSHA256          string   `json:"source_sha256"`
	ManifestSHA256        string   `json:"manifest_sha256"`
	VerifierSHA256        string   `json:"verifier_sha256"`
	ConfigurationSHA256   string   `json:"configuration_sha256"`
	ChildEnvironmentNames []string `json:"child_environment_names"`
}

// ControllerCycleBinding binds one validated E2 admission result to the exact
// offline controller inputs that may perform a preflight. The object is
// deliberately nonauthorizing and cannot represent an executed topology.
type ControllerCycleBinding struct {
	Schema string `json:"schema"`

	CycleID                 string `json:"cycle_id"`
	AttemptID               string `json:"attempt_id"`
	TopologyID              string `json:"topology_id"`
	AdmissionBindingDigest  string `json:"admission_binding_digest"`
	AdmissionBundleSHA256   string `json:"admission_bundle_sha256"`
	RuntimeCollectionDigest string `json:"runtime_collection_digest"`
	ReservationObjectDigest string `json:"reservation_object_digest"`
	AdmissionNonce          string `json:"admission_nonce"`
	CounterDomain           string `json:"counter_domain"`
	AcceptedCounter         uint64 `json:"accepted_counter"`
	ExpectedTransport       string `json:"expected_transport"`
	StartNotBefore          string `json:"start_not_before"`
	StartDeadline           string `json:"start_deadline"`
	FinishDeadline          string `json:"finish_deadline"`

	SoakRunID             string   `json:"soak_run_id"`
	Sequence              uint64   `json:"sequence"`
	InstanceNonce         string   `json:"instance_nonce"`
	PredecessorNonce      string   `json:"predecessor_nonce"`
	ResumeCount           uint64   `json:"resume_count"`
	Readiness             string   `json:"readiness"`
	Profile               string   `json:"profile"`
	RunnerSHA256          string   `json:"runner_sha256"`
	MatrixRelativePath    string   `json:"matrix_relative_path"`
	MatrixSHA256          string   `json:"matrix_sha256"`
	SnapshotSHA256        string   `json:"snapshot_sha256"`
	SnapshotFileCount     uint64   `json:"snapshot_file_count"`
	SourceSHA256          string   `json:"source_sha256"`
	ManifestSHA256        string   `json:"manifest_sha256"`
	VerifierSHA256        string   `json:"verifier_sha256"`
	ConfigurationSHA256   string   `json:"configuration_sha256"`
	ChildEnvironmentNames []string `json:"child_environment_names"`

	DispatchAuthorized       bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted bool   `json:"external_topology_executed"`
	Mutation                 string `json:"mutation"`
	ObjectDigest             string `json:"object_digest"`
}

type controllerCycleBindingCore struct {
	Schema string `json:"schema"`

	CycleID                 string `json:"cycle_id"`
	AttemptID               string `json:"attempt_id"`
	TopologyID              string `json:"topology_id"`
	AdmissionBindingDigest  string `json:"admission_binding_digest"`
	AdmissionBundleSHA256   string `json:"admission_bundle_sha256"`
	RuntimeCollectionDigest string `json:"runtime_collection_digest"`
	ReservationObjectDigest string `json:"reservation_object_digest"`
	AdmissionNonce          string `json:"admission_nonce"`
	CounterDomain           string `json:"counter_domain"`
	AcceptedCounter         uint64 `json:"accepted_counter"`
	ExpectedTransport       string `json:"expected_transport"`
	StartNotBefore          string `json:"start_not_before"`
	StartDeadline           string `json:"start_deadline"`
	FinishDeadline          string `json:"finish_deadline"`

	SoakRunID             string   `json:"soak_run_id"`
	Sequence              uint64   `json:"sequence"`
	InstanceNonce         string   `json:"instance_nonce"`
	PredecessorNonce      string   `json:"predecessor_nonce"`
	ResumeCount           uint64   `json:"resume_count"`
	Readiness             string   `json:"readiness"`
	Profile               string   `json:"profile"`
	RunnerSHA256          string   `json:"runner_sha256"`
	MatrixRelativePath    string   `json:"matrix_relative_path"`
	MatrixSHA256          string   `json:"matrix_sha256"`
	SnapshotSHA256        string   `json:"snapshot_sha256"`
	SnapshotFileCount     uint64   `json:"snapshot_file_count"`
	SourceSHA256          string   `json:"source_sha256"`
	ManifestSHA256        string   `json:"manifest_sha256"`
	VerifierSHA256        string   `json:"verifier_sha256"`
	ConfigurationSHA256   string   `json:"configuration_sha256"`
	ChildEnvironmentNames []string `json:"child_environment_names"`

	DispatchAuthorized       bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted bool   `json:"external_topology_executed"`
	Mutation                 string `json:"mutation"`
}

func controllerCycleBindingCoreOf(
	value ControllerCycleBinding,
) controllerCycleBindingCore {
	return controllerCycleBindingCore{
		Schema:                   value.Schema,
		CycleID:                  value.CycleID,
		AttemptID:                value.AttemptID,
		TopologyID:               value.TopologyID,
		AdmissionBindingDigest:   value.AdmissionBindingDigest,
		AdmissionBundleSHA256:    value.AdmissionBundleSHA256,
		RuntimeCollectionDigest:  value.RuntimeCollectionDigest,
		ReservationObjectDigest:  value.ReservationObjectDigest,
		AdmissionNonce:           value.AdmissionNonce,
		CounterDomain:            value.CounterDomain,
		AcceptedCounter:          value.AcceptedCounter,
		ExpectedTransport:        value.ExpectedTransport,
		StartNotBefore:           value.StartNotBefore,
		StartDeadline:            value.StartDeadline,
		FinishDeadline:           value.FinishDeadline,
		SoakRunID:                value.SoakRunID,
		Sequence:                 value.Sequence,
		InstanceNonce:            value.InstanceNonce,
		PredecessorNonce:         value.PredecessorNonce,
		ResumeCount:              value.ResumeCount,
		Readiness:                value.Readiness,
		Profile:                  value.Profile,
		RunnerSHA256:             value.RunnerSHA256,
		MatrixRelativePath:       value.MatrixRelativePath,
		MatrixSHA256:             value.MatrixSHA256,
		SnapshotSHA256:           value.SnapshotSHA256,
		SnapshotFileCount:        value.SnapshotFileCount,
		SourceSHA256:             value.SourceSHA256,
		ManifestSHA256:           value.ManifestSHA256,
		VerifierSHA256:           value.VerifierSHA256,
		ConfigurationSHA256:      value.ConfigurationSHA256,
		ChildEnvironmentNames:    slices.Clone(value.ChildEnvironmentNames),
		DispatchAuthorized:       value.DispatchAuthorized,
		ExternalTopologyExecuted: value.ExternalTopologyExecuted,
		Mutation:                 value.Mutation,
	}
}

// NewControllerCycleBinding constructs and validates a canonical E3 binding.
// It grants no execution authority and always fixes mutation to "none".
func NewControllerCycleBinding(
	admission AdmissionResult,
	input ControllerBindingInput,
) (ControllerCycleBinding, []byte, error) {
	value := ControllerCycleBinding{
		Schema:                   ControllerCycleBindingSchema,
		CycleID:                  admission.CycleID,
		AttemptID:                admission.AttemptID,
		TopologyID:               admission.TopologyID,
		AdmissionBindingDigest:   admission.BindingDigest,
		AdmissionBundleSHA256:    admission.AdmissionBundleSHA256,
		RuntimeCollectionDigest:  admission.RuntimeCollectionDigest,
		ReservationObjectDigest:  admission.ReservationObjectDigest,
		AdmissionNonce:           admission.Nonce,
		CounterDomain:            admission.CounterDomain,
		AcceptedCounter:          admission.AcceptedCounter,
		ExpectedTransport:        admission.ExpectedTransport,
		StartNotBefore:           admission.StartNotBefore,
		StartDeadline:            admission.StartDeadline,
		FinishDeadline:           admission.FinishDeadline,
		SoakRunID:                input.SoakRunID,
		Sequence:                 input.Sequence,
		InstanceNonce:            input.InstanceNonce,
		PredecessorNonce:         input.PredecessorNonce,
		ResumeCount:              input.ResumeCount,
		Readiness:                input.Readiness,
		Profile:                  input.Profile,
		RunnerSHA256:             input.RunnerSHA256,
		MatrixRelativePath:       input.MatrixRelativePath,
		MatrixSHA256:             input.MatrixSHA256,
		SnapshotSHA256:           input.SnapshotSHA256,
		SnapshotFileCount:        input.SnapshotFileCount,
		SourceSHA256:             input.SourceSHA256,
		ManifestSHA256:           input.ManifestSHA256,
		VerifierSHA256:           input.VerifierSHA256,
		ConfigurationSHA256:      input.ConfigurationSHA256,
		ChildEnvironmentNames:    slices.Clone(input.ChildEnvironmentNames),
		DispatchAuthorized:       false,
		ExternalTopologyExecuted: false,
		Mutation:                 "none",
	}
	if err := validateControllerCycleBindingCore(value); err != nil {
		return ControllerCycleBinding{}, nil, err
	}
	digest, err := digestObject(
		controllerCycleBindingCoreDomain,
		controllerCycleBindingCoreOf(value),
	)
	if err != nil {
		return ControllerCycleBinding{}, nil, err
	}
	value.ObjectDigest = digest
	encoded, err := marshalCanonical(value)
	if err != nil {
		return ControllerCycleBinding{}, nil, err
	}
	return value, encoded, nil
}

// ParseControllerBindingInput strictly decodes the controller-selected half of
// an E3 binding. Validation that depends on E2 is performed by the constructor.
func ParseControllerBindingInput(data []byte) (ControllerBindingInput, error) {
	var value ControllerBindingInput
	if len(data) == 0 || len(data) > MaxTrustFileBytes {
		return ControllerBindingInput{}, errors.New(
			"controller binding input size is invalid",
		)
	}
	if err := decodeCanonical(data, &value); err != nil {
		return ControllerBindingInput{}, fmt.Errorf(
			"decode controller binding input: %w", err,
		)
	}
	return value, nil
}

// LoadControllerBindingInput reads one safe, bounded standalone contract and
// rechecks its identity and bytes after strict parsing.
func LoadControllerBindingInput(path string) (ControllerBindingInput, error) {
	if path == "" {
		return ControllerBindingInput{}, errors.New(
			"controller binding input path is required",
		)
	}
	data, snapshot, err := readStandalone(path, MaxTrustFileBytes)
	if err != nil {
		return ControllerBindingInput{}, fmt.Errorf(
			"read controller binding input: %w", err,
		)
	}
	value, err := ParseControllerBindingInput(data)
	if err != nil {
		return ControllerBindingInput{}, err
	}
	if err := recheckStandalone(path, snapshot); err != nil {
		return ControllerBindingInput{}, fmt.Errorf(
			"recheck controller binding input: %w", err,
		)
	}
	return value, nil
}

// ParseControllerCycleBinding strictly decodes and replays an E3 binding.
func ParseControllerCycleBinding(data []byte) (ControllerCycleBinding, error) {
	var value ControllerCycleBinding
	if len(data) == 0 || len(data) > MaxTrustFileBytes {
		return ControllerCycleBinding{}, errors.New(
			"controller cycle binding size is invalid",
		)
	}
	if err := decodeCanonical(data, &value); err != nil {
		return ControllerCycleBinding{}, fmt.Errorf(
			"decode controller cycle binding: %w", err,
		)
	}
	if err := validateControllerCycleBindingCore(value); err != nil {
		return ControllerCycleBinding{}, err
	}
	expected, err := digestObject(
		controllerCycleBindingCoreDomain,
		controllerCycleBindingCoreOf(value),
	)
	if err != nil {
		return ControllerCycleBinding{}, err
	}
	if value.ObjectDigest != expected {
		return ControllerCycleBinding{}, errors.New(
			"controller cycle binding object digest mismatch",
		)
	}
	// Keep a distinct object domain available to later intent/receipt chains
	// without changing the self-contained object digest above.
	if _, err := digestObject(controllerCycleBindingObjectDomain, value); err != nil {
		return ControllerCycleBinding{}, err
	}
	return value, nil
}

func validateControllerCycleBindingCore(value ControllerCycleBinding) error {
	if value.Schema != ControllerCycleBindingSchema ||
		!validID(value.CycleID) || !validID(value.AttemptID) ||
		!validID(value.TopologyID) ||
		!validDigest(value.AdmissionBindingDigest) ||
		!validDigest(value.AdmissionBundleSHA256) ||
		!validDigest(value.RuntimeCollectionDigest) ||
		!validDigest(value.ReservationObjectDigest) ||
		!validNonce(value.AdmissionNonce) ||
		!validID(value.CounterDomain) || value.AcceptedCounter == 0 ||
		!slices.Contains(
			[]string{TransportDirect, TransportH3},
			value.ExpectedTransport,
		) ||
		!validID(value.SoakRunID) || value.Sequence == 0 ||
		!validNonce(value.InstanceNonce) ||
		!validResumeLineage(
			value.ResumeCount, value.InstanceNonce, value.PredecessorNonce,
		) ||
		!slices.Contains(admittedReadinessValues, value.Readiness) ||
		!validID(value.Profile) ||
		!validDigest(value.RunnerSHA256) ||
		!validMatrixRelativePath(value.MatrixRelativePath) ||
		!validDigest(value.MatrixSHA256) ||
		!validDigest(value.SnapshotSHA256) ||
		value.SnapshotFileCount == 0 ||
		!validDigest(value.SourceSHA256) ||
		!validDigest(value.ManifestSHA256) ||
		!validDigest(value.VerifierSHA256) ||
		!validDigest(value.ConfigurationSHA256) ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.Mutation != "none" {
		return errors.New("controller cycle binding fields are invalid")
	}
	start, err := parseTime(value.StartNotBefore)
	if err != nil {
		return fmt.Errorf("binding start_not_before: %w", err)
	}
	deadline, err := parseTime(value.StartDeadline)
	if err != nil {
		return fmt.Errorf("binding start_deadline: %w", err)
	}
	finish, err := parseTime(value.FinishDeadline)
	if err != nil || !start.Before(deadline) || !deadline.Before(finish) {
		return errors.New("controller cycle binding chronology is invalid")
	}
	if !slices.Equal(
		value.ChildEnvironmentNames,
		controllerAdapterEnvironmentNames,
	) {
		return errors.New("child environment contract is not exact")
	}
	return nil
}

func validResumeLineage(
	resumeCount uint64,
	instanceNonce, predecessorNonce string,
) bool {
	if resumeCount == 0 {
		return predecessorNonce == ""
	}
	return validNonce(predecessorNonce) && predecessorNonce != instanceNonce
}

func validMatrixRelativePath(value string) bool {
	if value == "" || len(value) > MaxStringBytes ||
		path.IsAbs(value) || path.Clean(value) != value ||
		value == "." || value == ".." ||
		len(value) >= 3 && value[:3] == "../" {
		return false
	}
	return true
}
