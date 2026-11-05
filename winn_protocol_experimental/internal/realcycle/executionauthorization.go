package realcycle

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	ExecutionAuthorizationSchema            = "winn-real-cycle-explicit-execution-authorization/v1"
	SupervisorAuthorizationAcceptanceSchema = "winn-real-cycle-supervisor-authorization-acceptance/v1"

	ExecutionAuthorizationFile            = "execution-authorization.json"
	SupervisorAuthorizationAcceptanceFile = "supervisor-authorization-acceptance.json"

	executionAuthorizationSignatureDomain            = "winn-real-cycle-explicit-execution-authorization-signature/v1"
	executionAuthorizationObjectDomain               = "winn-real-cycle-explicit-execution-authorization-object/v1"
	supervisorAuthorizationAcceptanceSignatureDomain = "winn-real-cycle-supervisor-authorization-acceptance-signature/v1"
	supervisorAuthorizationAcceptanceObjectDomain    = "winn-real-cycle-supervisor-authorization-acceptance-object/v1"
	executionAuthorizationCollectionDomain           = "winn-real-cycle-execution-authorization-collection/v1"
)

var executionAuthorizationFiles = []string{
	ExecutionAuthorizationFile,
	SupervisorAuthorizationAcceptanceFile,
}

type ExecutionAuthorizationExpectation struct {
	RunID                      string
	CycleID                    string
	AttemptID                  string
	TopologyID                 string
	PlanSHA256                 string
	PlanObjectDigest           string
	TrustSHA256                string
	E6ReceiptSHA256            string
	E6ReceiptObjectDigest      string
	HandoffCollectionDigest    string
	OneTimeNonce               string
	MinimumActivationCounter   uint64
	LastObservedCounter        uint64
	ValidNotBefore             string
	ValidNotAfter              string
	MaxExecutionSeconds        uint64
	SupervisorExecutablePath   string
	SupervisorExecutableSHA256 string
	SupervisorConfigPath       string
	SupervisorConfigSHA256     string
	RoleKeys                   [2]HandoffRoleKey
}

type ExecutionAuthorization struct {
	Schema                     string `json:"schema"`
	State                      string `json:"state"`
	Scope                      string `json:"scope"`
	DecisionID                 string `json:"decision_id"`
	RunID                      string `json:"run_id"`
	CycleID                    string `json:"cycle_id"`
	AttemptID                  string `json:"attempt_id"`
	TopologyID                 string `json:"topology_id"`
	PlanSHA256                 string `json:"plan_sha256"`
	PlanObjectDigest           string `json:"plan_object_digest"`
	TrustSHA256                string `json:"trust_sha256"`
	E6ReceiptSHA256            string `json:"e6_receipt_sha256"`
	E6ReceiptObjectDigest      string `json:"e6_receipt_object_digest"`
	HandoffCollectionDigest    string `json:"handoff_collection_digest"`
	OneTimeNonce               string `json:"one_time_nonce"`
	ActivationCounter          uint64 `json:"activation_counter"`
	ValidNotBefore             string `json:"valid_not_before"`
	ValidNotAfter              string `json:"valid_not_after"`
	MaxExecutionSeconds        uint64 `json:"max_execution_seconds"`
	SupervisorExecutablePath   string `json:"supervisor_executable_path"`
	SupervisorExecutableSHA256 string `json:"supervisor_executable_sha256"`
	SupervisorConfigPath       string `json:"supervisor_config_path"`
	SupervisorConfigSHA256     string `json:"supervisor_config_sha256"`
	AuthorizerKeyID            string `json:"authorizer_key_id"`
	Signature                  string `json:"signature"`
}

type SupervisorAuthorizationAcceptance struct {
	Schema                     string `json:"schema"`
	State                      string `json:"state"`
	DecisionSHA256             string `json:"decision_sha256"`
	DecisionObjectDigest       string `json:"decision_object_digest"`
	E6ReceiptSHA256            string `json:"e6_receipt_sha256"`
	E6ReceiptObjectDigest      string `json:"e6_receipt_object_digest"`
	RunID                      string `json:"run_id"`
	CycleID                    string `json:"cycle_id"`
	AttemptID                  string `json:"attempt_id"`
	TopologyID                 string `json:"topology_id"`
	OneTimeNonce               string `json:"one_time_nonce"`
	ActivationCounter          uint64 `json:"activation_counter"`
	SupervisorExecutablePath   string `json:"supervisor_executable_path"`
	SupervisorExecutableSHA256 string `json:"supervisor_executable_sha256"`
	SupervisorConfigPath       string `json:"supervisor_config_path"`
	SupervisorConfigSHA256     string `json:"supervisor_config_sha256"`
	SupervisorKeyID            string `json:"supervisor_key_id"`
	Signature                  string `json:"signature"`
}

type ExecutionAuthorizationResult struct {
	Decision               ExecutionAuthorization
	Acceptance             SupervisorAuthorizationAcceptance
	DecisionSHA256         string
	DecisionObjectDigest   string
	DecisionID             string
	AuthorizerKeyID        string
	AuthorizerSignature    string
	AcceptanceSHA256       string
	AcceptanceObjectDigest string
	SupervisorKeyID        string
	SupervisorSignature    string
	CollectionDigest       string
	ActivationCounter      uint64
	ValidNotBefore         string
	ValidNotAfter          string
	MaxExecutionSeconds    uint64
}

type executionAuthorizationUnsigned ExecutionAuthorization
type supervisorAuthorizationAcceptanceUnsigned SupervisorAuthorizationAcceptance

func executionAuthorizationUnsignedOf(
	value ExecutionAuthorization,
) executionAuthorizationUnsigned {
	value.Signature = ""
	return executionAuthorizationUnsigned(value)
}

func supervisorAuthorizationAcceptanceUnsignedOf(
	value SupervisorAuthorizationAcceptance,
) supervisorAuthorizationAcceptanceUnsigned {
	value.Signature = ""
	return supervisorAuthorizationAcceptanceUnsigned(value)
}

// ValidateExecutionAuthorization validates the exact two-party, explicit
// authorization input for one future supervisor execution. It observes no
// clock, reserves no counter, releases no credential, launches no process and
// grants no dispatch authority.
func ValidateExecutionAuthorization(
	rootPath string, expected ExecutionAuthorizationExpectation,
) (ExecutionAuthorizationResult, error) {
	if err := validateExecutionAuthorizationSupervisor(expected); err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	root, entries, err := openExactRoot(rootPath, executionAuthorizationFiles)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	defer root.Close()
	documents := make(map[string][]byte, len(entries))
	snapshots := make(map[string]fileSnapshot, len(entries))
	for _, name := range entries {
		data, snapshot, readErr := readRootFile(root, name, MaxHandoffFileBytes)
		if readErr != nil {
			return ExecutionAuthorizationResult{}, readErr
		}
		documents[name], snapshots[name] = data, snapshot
	}
	var decision ExecutionAuthorization
	if err := decodeCanonical(
		documents[ExecutionAuthorizationFile], &decision,
	); err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	var acceptance SupervisorAuthorizationAcceptance
	if err := decodeCanonical(
		documents[SupervisorAuthorizationAcceptanceFile], &acceptance,
	); err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	result, err := VerifyExecutionAuthorizationObjects(
		expected, decision, acceptance,
	)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	if result.DecisionSHA256 != rawSHA(documents[ExecutionAuthorizationFile]) ||
		result.AcceptanceSHA256 !=
			rawSHA(documents[SupervisorAuthorizationAcceptanceFile]) {
		return ExecutionAuthorizationResult{},
			errors.New("execution authorization canonical bytes mismatch")
	}
	if err := recheckExactRoot(rootPath, root, entries, snapshots); err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	if err := validateExecutionAuthorizationSupervisor(expected); err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	return result, nil
}

// VerifyExecutionAuthorizationObjects replays the signed objects projected by
// a durable E7 receipt without observing or consuming authority.
func VerifyExecutionAuthorizationObjects(
	expected ExecutionAuthorizationExpectation,
	decision ExecutionAuthorization,
	acceptance SupervisorAuthorizationAcceptance,
) (ExecutionAuthorizationResult, error) {
	if err := validateExecutionAuthorizationSupervisor(expected); err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	keys, err := executionAuthorizationKeyIndex(expected.RoleKeys)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	if expected.LastObservedCounter == ^uint64(0) ||
		expected.MinimumActivationCounter != expected.LastObservedCounter+1 {
		return ExecutionAuthorizationResult{},
			errors.New("execution authorization counter is not exact successor")
	}
	if decision.Schema != ExecutionAuthorizationSchema ||
		decision.State != "explicit-authority-input-only" ||
		decision.Scope != "one-provider-neutral-supervisor-execution" ||
		!validID(decision.DecisionID) ||
		decision.RunID != expected.RunID ||
		decision.CycleID != expected.CycleID ||
		decision.AttemptID != expected.AttemptID ||
		decision.TopologyID != expected.TopologyID ||
		decision.PlanSHA256 != expected.PlanSHA256 ||
		decision.PlanObjectDigest != expected.PlanObjectDigest ||
		decision.TrustSHA256 != expected.TrustSHA256 ||
		decision.E6ReceiptSHA256 != expected.E6ReceiptSHA256 ||
		decision.E6ReceiptObjectDigest != expected.E6ReceiptObjectDigest ||
		decision.HandoffCollectionDigest != expected.HandoffCollectionDigest ||
		decision.OneTimeNonce != expected.OneTimeNonce ||
		decision.ActivationCounter != expected.MinimumActivationCounter ||
		decision.ValidNotBefore != expected.ValidNotBefore ||
		decision.ValidNotAfter != expected.ValidNotAfter ||
		decision.MaxExecutionSeconds != expected.MaxExecutionSeconds ||
		decision.SupervisorExecutablePath != expected.SupervisorExecutablePath ||
		decision.SupervisorExecutableSHA256 !=
			expected.SupervisorExecutableSHA256 ||
		decision.SupervisorConfigPath != expected.SupervisorConfigPath ||
		decision.SupervisorConfigSHA256 != expected.SupervisorConfigSHA256 {
		return ExecutionAuthorizationResult{},
			errors.New("execution authorization decision is not exact")
	}
	validStart, startErr := time.Parse(time.RFC3339Nano, decision.ValidNotBefore)
	validEnd, endErr := time.Parse(time.RFC3339Nano, decision.ValidNotAfter)
	if startErr != nil || endErr != nil || !validEnd.After(validStart) ||
		decision.MaxExecutionSeconds == 0 ||
		decision.MaxExecutionSeconds > MaximumExecutionSeconds ||
		validEnd.Sub(validStart) >
			time.Duration(decision.MaxExecutionSeconds)*time.Second {
		return ExecutionAuthorizationResult{},
			errors.New("execution authorization time window is invalid")
	}
	if err := verifySignature(
		keys, decision.AuthorizerKeyID, KeyRoleDispatchAuthorizer, "",
		executionAuthorizationSignatureDomain, decision.Signature,
		executionAuthorizationUnsignedOf(decision),
	); err != nil {
		return ExecutionAuthorizationResult{}, fmt.Errorf(
			"execution authorization signature: %w", err,
		)
	}
	decisionObject, err := digestObject(
		executionAuthorizationObjectDomain, decision,
	)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	decisionBytes, err := marshalCanonical(decision)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	if acceptance.Schema != SupervisorAuthorizationAcceptanceSchema ||
		acceptance.State != "accepted-for-future-atomic-consumption" ||
		acceptance.DecisionSHA256 != rawSHA(decisionBytes) ||
		acceptance.DecisionObjectDigest != decisionObject ||
		acceptance.E6ReceiptSHA256 != expected.E6ReceiptSHA256 ||
		acceptance.E6ReceiptObjectDigest != expected.E6ReceiptObjectDigest ||
		acceptance.RunID != expected.RunID ||
		acceptance.CycleID != expected.CycleID ||
		acceptance.AttemptID != expected.AttemptID ||
		acceptance.TopologyID != expected.TopologyID ||
		acceptance.OneTimeNonce != expected.OneTimeNonce ||
		acceptance.ActivationCounter != expected.MinimumActivationCounter ||
		acceptance.SupervisorExecutablePath != expected.SupervisorExecutablePath ||
		acceptance.SupervisorExecutableSHA256 !=
			expected.SupervisorExecutableSHA256 ||
		acceptance.SupervisorConfigPath != expected.SupervisorConfigPath ||
		acceptance.SupervisorConfigSHA256 != expected.SupervisorConfigSHA256 {
		return ExecutionAuthorizationResult{},
			errors.New("supervisor authorization acceptance is not exact")
	}
	if err := verifySignature(
		keys, acceptance.SupervisorKeyID, KeyRoleExecutionSupervisor, "",
		supervisorAuthorizationAcceptanceSignatureDomain, acceptance.Signature,
		supervisorAuthorizationAcceptanceUnsignedOf(acceptance),
	); err != nil {
		return ExecutionAuthorizationResult{}, fmt.Errorf(
			"supervisor authorization signature: %w", err,
		)
	}
	acceptanceObject, err := digestObject(
		supervisorAuthorizationAcceptanceObjectDomain, acceptance,
	)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	acceptanceBytes, err := marshalCanonical(acceptance)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	collection, err := digestObject(
		executionAuthorizationCollectionDomain,
		[]string{decisionObject, acceptanceObject},
	)
	if err != nil {
		return ExecutionAuthorizationResult{}, err
	}
	return ExecutionAuthorizationResult{
		Decision:               decision,
		Acceptance:             acceptance,
		DecisionSHA256:         rawSHA(decisionBytes),
		DecisionObjectDigest:   decisionObject,
		DecisionID:             decision.DecisionID,
		AuthorizerKeyID:        decision.AuthorizerKeyID,
		AuthorizerSignature:    decision.Signature,
		AcceptanceSHA256:       rawSHA(acceptanceBytes),
		AcceptanceObjectDigest: acceptanceObject,
		SupervisorKeyID:        acceptance.SupervisorKeyID,
		SupervisorSignature:    acceptance.Signature,
		CollectionDigest:       collection,
		ActivationCounter:      decision.ActivationCounter,
		ValidNotBefore:         decision.ValidNotBefore,
		ValidNotAfter:          decision.ValidNotAfter,
		MaxExecutionSeconds:    decision.MaxExecutionSeconds,
	}, nil
}

func executionAuthorizationKeyIndex(
	rows [2]HandoffRoleKey,
) (trustIndex, error) {
	if rows[0].Role != KeyRoleDispatchAuthorizer ||
		rows[1].Role != KeyRoleExecutionSupervisor ||
		rows[0].KeyID == rows[1].KeyID {
		return nil, errors.New("execution authorization role keys are not exact")
	}
	index := make(trustIndex, 2)
	for _, row := range rows {
		decoded, err := base64.StdEncoding.DecodeString(row.PublicKey)
		if err != nil || len(decoded) != 32 ||
			base64.StdEncoding.EncodeToString(decoded) != row.PublicKey ||
			!validID(row.KeyID) {
			return nil, errors.New("execution authorization role key is invalid")
		}
		index[row.KeyID] = trustedKey{
			row: TrustKey{
				KeyID: row.KeyID, Role: row.Role, PublicKey: row.PublicKey,
			},
			key: ed25519.PublicKey(decoded),
		}
	}
	return index, nil
}

func validateExecutionAuthorizationSupervisor(
	expected ExecutionAuthorizationExpectation,
) error {
	executable, executableSnapshot, err := readNoSymlinkRegular(
		expected.SupervisorExecutablePath, 64<<20,
	)
	if err != nil || rawSHA(executable) != expected.SupervisorExecutableSHA256 ||
		executableSnapshot.info.Mode().Perm()&0o111 == 0 ||
		executableSnapshot.info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("execution authorization supervisor executable is not exact")
	}
	config, configSnapshot, err := readNoSymlinkRegular(
		expected.SupervisorConfigPath, MaxHandoffFileBytes,
	)
	if err != nil || rawSHA(config) != expected.SupervisorConfigSHA256 ||
		configSnapshot.info.Mode().Perm()&0o111 != 0 {
		return errors.New("execution authorization supervisor config is not exact")
	}
	return nil
}
