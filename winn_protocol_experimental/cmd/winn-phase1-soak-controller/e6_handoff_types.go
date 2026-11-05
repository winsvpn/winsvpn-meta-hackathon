package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	e6ReceiptSchema   = "winn-real-cycle-sealed-handoff-verification/v1"
	e6ReceiptDomain   = "winn-real-cycle-sealed-handoff-verification-object/v1"
	e6SummarySchema   = "winn-real-cycle-sealed-handoff-summary/v1"
	e6Mode            = "admitted-e6-sealed-handoff"
	e6ReceiptFile     = "sealed-handoff-verification.json"
	e6ReceiptMaxBytes = 128 << 10
)

type e6VerificationReceipt struct {
	Schema                       string                      `json:"schema"`
	Mode                         string                      `json:"mode"`
	RunID                        string                      `json:"run_id"`
	CycleID                      string                      `json:"cycle_id"`
	AttemptID                    string                      `json:"attempt_id"`
	TopologyID                   string                      `json:"topology_id"`
	PlanSHA256                   string                      `json:"plan_sha256"`
	PlanObjectDigest             string                      `json:"plan_object_digest"`
	TrustSHA256                  string                      `json:"trust_sha256"`
	AdmissionBindingDigest       string                      `json:"admission_binding_digest"`
	AdmissionBundleSHA256        string                      `json:"admission_bundle_sha256"`
	RuntimeCollectionDigest      string                      `json:"runtime_collection_digest"`
	ReservationObjectDigest      string                      `json:"reservation_object_digest"`
	AdmissionNonce               string                      `json:"admission_nonce"`
	CounterDomain                string                      `json:"counter_domain"`
	AcceptedCounter              uint64                      `json:"accepted_counter"`
	LastObservedCounter          uint64                      `json:"last_observed_counter"`
	ExpectedTransport            string                      `json:"expected_transport"`
	StartNotBefore               string                      `json:"start_not_before"`
	StartDeadline                string                      `json:"start_deadline"`
	FinishDeadline               string                      `json:"finish_deadline"`
	AuthorizationSHA256          string                      `json:"authorization_sha256"`
	AuthorizationObjectDigest    string                      `json:"authorization_object_digest"`
	AuthorizationKeyID           string                      `json:"authorization_key_id"`
	AuthorizationSignature       string                      `json:"authorization_signature"`
	RoleExtensionSHA256          string                      `json:"role_extension_sha256"`
	RoleExtensionObjectDigest    string                      `json:"role_extension_object_digest"`
	RoleExtensionControllerKeyID string                      `json:"role_extension_controller_key_id"`
	RoleExtensionSignature       string                      `json:"role_extension_signature"`
	RoleExtensionKeys            [2]realcycle.HandoffRoleKey `json:"role_extension_keys"`
	SupervisorSHA256             string                      `json:"supervisor_sha256"`
	SupervisorObjectDigest       string                      `json:"supervisor_object_digest"`
	SupervisorKeyID              string                      `json:"supervisor_key_id"`
	SupervisorSignature          string                      `json:"supervisor_signature"`
	HandoffCollectionDigest      string                      `json:"handoff_collection_digest"`
	MinimumActivationCounter     uint64                      `json:"minimum_activation_counter"`
	ValidNotBefore               string                      `json:"valid_not_before"`
	ValidNotAfter                string                      `json:"valid_not_after"`
	MaxRuntimeAgeSeconds         uint64                      `json:"max_runtime_age_seconds"`
	MaxExecutionSeconds          uint64                      `json:"max_execution_seconds"`
	OneTimeNonce                 string                      `json:"one_time_nonce"`
	SupervisorExecutablePath     string                      `json:"supervisor_executable_path"`
	SupervisorExecutableSHA256   string                      `json:"supervisor_executable_sha256"`
	SupervisorConfigPath         string                      `json:"supervisor_config_path"`
	SupervisorConfigSHA256       string                      `json:"supervisor_config_sha256"`
	VerificationState            string                      `json:"verification_state"`
	ActivationObserved           bool                        `json:"activation_observed"`
	SecureTimeObserved           bool                        `json:"secure_time_observed"`
	ActivationCounterReserved    bool                        `json:"activation_counter_reserved"`
	LiveRuntimeRechecked         bool                        `json:"live_runtime_rechecked"`
	CredentialHandleReleased     bool                        `json:"credential_handle_released"`
	SupervisorExecuted           bool                        `json:"supervisor_executed"`
	DispatchAuthorized           bool                        `json:"dispatch_authorized"`
	ExternalTopologyExecuted     bool                        `json:"external_topology_executed"`
	ProviderAccess               bool                        `json:"provider_access"`
	CredentialAccess             bool                        `json:"credential_access"`
	NetworkAccess                bool                        `json:"network_access"`
	LiveNodesContacted           bool                        `json:"live_nodes_contacted"`
	SpendAuthorized              bool                        `json:"spend_authorized"`
	HandoffReady                 bool                        `json:"handoff_ready"`
	Mutation                     string                      `json:"mutation"`
	Authority                    bool                        `json:"authority"`
	ObjectDigest                 string                      `json:"object_digest"`
}

type e6Summary struct {
	Schema                   string `json:"schema"`
	Mode                     string `json:"mode"`
	RunID                    string `json:"run_id"`
	CycleID                  string `json:"cycle_id"`
	AttemptID                string `json:"attempt_id"`
	PlanSHA256               string `json:"plan_sha256"`
	ReceiptSHA256            string `json:"receipt_sha256"`
	ReceiptObjectDigest      string `json:"receipt_object_digest"`
	HandoffCollectionDigest  string `json:"handoff_collection_digest"`
	VerificationState        string `json:"verification_state"`
	DispatchAuthorized       bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted bool   `json:"external_topology_executed"`
	ProviderAccess           bool   `json:"provider_access"`
	CredentialAccess         bool   `json:"credential_access"`
	NetworkAccess            bool   `json:"network_access"`
	LiveNodesContacted       bool   `json:"live_nodes_contacted"`
	SpendAuthorized          bool   `json:"spend_authorized"`
	HandoffReady             bool   `json:"handoff_ready"`
	Authority                bool   `json:"authority"`
}

type e6PublicationError struct {
	Stage                string
	FinalReceiptMayExist bool
	DirectorySynced      bool
	ReceiptAuthenticated bool
	Cause                error
}

func (e *e6PublicationError) Error() string {
	return fmt.Sprintf(
		"E6 publication failed at %s (final_may_exist=%t directory_synced=%t receipt_authenticated=%t): %v",
		e.Stage, e.FinalReceiptMayExist, e.DirectorySynced,
		e.ReceiptAuthenticated, e.Cause,
	)
}

func (e *e6PublicationError) Unwrap() error { return e.Cause }

func indeterminateE6Publication(
	stage string, directorySynced, authenticated bool, cause error,
) error {
	return &e6PublicationError{
		Stage: stage, FinalReceiptMayExist: true,
		DirectorySynced: directorySynced, ReceiptAuthenticated: authenticated,
		Cause: cause,
	}
}

func buildE6Receipt(
	plan e5FourNodePlan, planSHA string, result realcycle.SealedHandoffResult,
) (e6VerificationReceipt, []byte, error) {
	return encodeE6Receipt(e6VerificationReceipt{
		RunID: plan.RunID, CycleID: plan.CycleID,
		AttemptID: plan.AttemptID, TopologyID: plan.TopologyID,
		PlanSHA256: planSHA, PlanObjectDigest: plan.ObjectDigest,
		TrustSHA256:                  result.TrustSHA256,
		AdmissionBindingDigest:       plan.AdmissionBindingDigest,
		AdmissionBundleSHA256:        plan.AdmissionBundleSHA256,
		RuntimeCollectionDigest:      plan.RuntimeCollectionDigest,
		ReservationObjectDigest:      plan.ReservationObjectDigest,
		AdmissionNonce:               plan.AdmissionNonce,
		CounterDomain:                plan.CounterDomain,
		AcceptedCounter:              result.AcceptedCounter,
		LastObservedCounter:          result.LastObservedCounter,
		ExpectedTransport:            result.ExpectedTransport,
		StartNotBefore:               result.StartNotBefore,
		StartDeadline:                result.StartDeadline,
		FinishDeadline:               result.FinishDeadline,
		AuthorizationSHA256:          result.AuthorizationSHA256,
		AuthorizationObjectDigest:    result.AuthorizationObjectDigest,
		AuthorizationKeyID:           result.AuthorizationKeyID,
		AuthorizationSignature:       result.AuthorizationSignature,
		RoleExtensionSHA256:          result.RoleExtensionSHA256,
		RoleExtensionObjectDigest:    result.RoleExtensionObjectDigest,
		RoleExtensionControllerKeyID: result.RoleExtensionControllerKeyID,
		RoleExtensionSignature:       result.RoleExtensionSignature,
		RoleExtensionKeys:            result.RoleExtensionKeys,
		SupervisorSHA256:             result.SupervisorSHA256,
		SupervisorObjectDigest:       result.SupervisorObjectDigest,
		SupervisorKeyID:              result.SupervisorKeyID,
		SupervisorSignature:          result.SupervisorSignature,
		HandoffCollectionDigest:      result.CollectionDigest,
		MinimumActivationCounter:     result.MinimumActivationCounter,
		ValidNotBefore:               result.ValidNotBefore, ValidNotAfter: result.ValidNotAfter,
		MaxRuntimeAgeSeconds:       result.MaxRuntimeAgeSeconds,
		MaxExecutionSeconds:        result.MaxExecutionSeconds,
		OneTimeNonce:               result.OneTimeNonce,
		SupervisorExecutablePath:   result.SupervisorExecutablePath,
		SupervisorExecutableSHA256: result.SupervisorExecutableSHA256,
		SupervisorConfigPath:       result.SupervisorConfigPath,
		SupervisorConfigSHA256:     result.SupervisorConfigSHA256,
		VerificationState:          "sealed-inputs-verified-pending-activation",
		Mutation:                   "none",
	})
}

func encodeE6Receipt(
	value e6VerificationReceipt,
) (e6VerificationReceipt, []byte, error) {
	value.Schema = e6ReceiptSchema
	value.Mode = e6Mode
	value.ObjectDigest = ""
	digest, err := admittedDigest(e6ReceiptDomain, value)
	if err != nil {
		return e6VerificationReceipt{}, nil, err
	}
	value.ObjectDigest = digest
	if err := validateE6Receipt(value); err != nil {
		return e6VerificationReceipt{}, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > e6ReceiptMaxBytes {
		return e6VerificationReceipt{}, nil,
			errors.New("E6 receipt encoding exceeds bound")
	}
	return value, encoded, nil
}

func validateE6Receipt(value e6VerificationReceipt) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(e6ReceiptDomain, value)
	if err != nil || digest != expected {
		return errors.New("E6 receipt object digest mismatch")
	}
	if value.Schema != e6ReceiptSchema || value.Mode != e6Mode ||
		value.RunID == "" || value.CycleID == "" || value.AttemptID == "" ||
		value.TopologyID == "" ||
		value.VerificationState != "sealed-inputs-verified-pending-activation" ||
		value.ActivationObserved || value.SecureTimeObserved ||
		value.ActivationCounterReserved || value.LiveRuntimeRechecked ||
		value.CredentialHandleReleased || value.SupervisorExecuted ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.ProviderAccess || value.CredentialAccess || value.NetworkAccess ||
		value.LiveNodesContacted || value.SpendAuthorized ||
		value.HandoffReady || value.Mutation != "none" || value.Authority {
		return errors.New("E6 receipt is not exact nonauthorizing state")
	}
	for _, candidate := range []string{
		value.PlanSHA256, value.PlanObjectDigest,
		value.TrustSHA256,
		value.AdmissionBindingDigest, value.AdmissionBundleSHA256,
		value.RuntimeCollectionDigest, value.ReservationObjectDigest,
		value.AuthorizationSHA256, value.AuthorizationObjectDigest,
		value.RoleExtensionSHA256, value.RoleExtensionObjectDigest,
		value.SupervisorSHA256, value.SupervisorObjectDigest,
		value.HandoffCollectionDigest, value.SupervisorExecutableSHA256,
		value.SupervisorConfigSHA256, digest,
	} {
		if !digestPattern.MatchString(candidate) {
			return errors.New("E6 receipt contains malformed digest")
		}
	}
	if value.MinimumActivationCounter == 0 ||
		value.LastObservedCounter < value.AcceptedCounter ||
		value.MinimumActivationCounter <= value.LastObservedCounter ||
		value.MaxRuntimeAgeSeconds == 0 || value.MaxExecutionSeconds == 0 ||
		value.MaxExecutionSeconds > realcycle.MaximumExecutionSeconds ||
		!noncePattern.MatchString(value.OneTimeNonce) ||
		!noncePattern.MatchString(value.AdmissionNonce) ||
		value.CounterDomain == "" || value.ExpectedTransport == "" ||
		value.StartNotBefore == "" || value.StartDeadline == "" ||
		value.FinishDeadline == "" ||
		value.ValidNotBefore == "" || value.ValidNotAfter == "" {
		return errors.New("E6 receipt contains malformed commitment projection")
	}
	if !cleanE6AbsolutePath(value.SupervisorExecutablePath) ||
		!cleanE6AbsolutePath(value.SupervisorConfigPath) ||
		value.SupervisorExecutablePath == value.SupervisorConfigPath {
		return errors.New("E6 receipt contains malformed supervisor paths")
	}
	if value.AuthorizationKeyID == "" ||
		value.RoleExtensionControllerKeyID == "" ||
		value.SupervisorKeyID == "" ||
		!canonicalE6Signature(value.AuthorizationSignature) ||
		!canonicalE6Signature(value.RoleExtensionSignature) ||
		!canonicalE6Signature(value.SupervisorSignature) ||
		value.RoleExtensionKeys[0].Role !=
			realcycle.KeyRoleDispatchAuthorizer ||
		value.RoleExtensionKeys[1].Role !=
			realcycle.KeyRoleExecutionSupervisor ||
		value.RoleExtensionKeys[0].KeyID != value.AuthorizationKeyID ||
		value.RoleExtensionKeys[1].KeyID != value.SupervisorKeyID ||
		value.RoleExtensionKeys[0].KeyID ==
			value.RoleExtensionKeys[1].KeyID ||
		!distinctCanonicalE6Keys(value.RoleExtensionKeys) {
		return errors.New("E6 receipt contains malformed signature replay data")
	}
	start, startErr := time.Parse(time.RFC3339Nano, value.StartNotBefore)
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, value.StartDeadline)
	finish, finishErr := time.Parse(time.RFC3339Nano, value.FinishDeadline)
	validStart, validStartErr := time.Parse(time.RFC3339Nano, value.ValidNotBefore)
	validEnd, validEndErr := time.Parse(time.RFC3339Nano, value.ValidNotAfter)
	if startErr != nil || deadlineErr != nil || finishErr != nil ||
		validStartErr != nil || validEndErr != nil ||
		validStart.Before(start) || validEnd.After(deadline) ||
		!validEnd.After(validStart) ||
		validEnd.Add(time.Duration(value.MaxExecutionSeconds)*time.Second).
			After(finish) {
		return errors.New("E6 receipt contains invalid time projection")
	}
	return nil
}

func canonicalE6Signature(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == ed25519.SignatureSize &&
		base64.StdEncoding.EncodeToString(decoded) == value
}

func distinctCanonicalE6Keys(rows [2]realcycle.HandoffRoleKey) bool {
	first, err := base64.StdEncoding.DecodeString(rows[0].PublicKey)
	if err != nil || len(first) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(first) != rows[0].PublicKey {
		return false
	}
	second, err := base64.StdEncoding.DecodeString(rows[1].PublicKey)
	return err == nil && len(second) == ed25519.PublicKeySize &&
		base64.StdEncoding.EncodeToString(second) == rows[1].PublicKey &&
		!bytes.Equal(first, second)
}

func cleanE6AbsolutePath(path string) bool {
	return filepath.IsAbs(path) && path != string(filepath.Separator) &&
		filepath.Clean(path) == path
}

// parseE6ReceiptStructure validates only the canonical, nonauthorizing receipt
// envelope. Call parseAuthenticatedE6Receipt when the signed handoff
// projection must be trusted.
func parseE6ReceiptStructure(data []byte) (e6VerificationReceipt, error) {
	var value e6VerificationReceipt
	if len(data) == 0 || len(data) > e6ReceiptMaxBytes {
		return value, errors.New("E6 receipt size is invalid")
	}
	if err := decodeStrictObject(data, &value); err != nil {
		return value, err
	}
	if err := validateE6Receipt(value); err != nil {
		return value, err
	}
	return value, nil
}

// parseAuthenticatedE6Receipt validates the canonical receipt and
// cryptographically reconstructs every signed handoff object against the
// separately accepted trust file and the exact supervisor files.
func parseAuthenticatedE6Receipt(
	data []byte, trustPath string,
) (e6VerificationReceipt, realcycle.SealedHandoffResult, error) {
	value, err := parseE6ReceiptStructure(data)
	if err != nil {
		return e6VerificationReceipt{}, realcycle.SealedHandoffResult{}, err
	}
	result, err := verifyE6ReceiptProjection(value, trustPath)
	if err != nil {
		return e6VerificationReceipt{}, realcycle.SealedHandoffResult{},
			fmt.Errorf("authenticate E6 receipt: %w", err)
	}
	return value, result, nil
}

func e6SummaryJSON(value e6Summary) ([]byte, error) {
	return json.Marshal(value)
}

func e6ReplayObjects(value e6VerificationReceipt) (
	realcycle.HandoffExpectation,
	realcycle.AuthorizationCommitment,
	realcycle.HandoffRoleExtension,
	realcycle.SupervisorCommitment,
) {
	expected := realcycle.HandoffExpectation{
		RunID: value.RunID, CycleID: value.CycleID,
		AttemptID: value.AttemptID, TopologyID: value.TopologyID,
		PlanSHA256: value.PlanSHA256, PlanObjectDigest: value.PlanObjectDigest,
		TrustSHA256:             value.TrustSHA256,
		AdmissionBindingDigest:  value.AdmissionBindingDigest,
		AdmissionBundleSHA256:   value.AdmissionBundleSHA256,
		RuntimeCollectionDigest: value.RuntimeCollectionDigest,
		ReservationObjectDigest: value.ReservationObjectDigest,
		AdmissionNonce:          value.AdmissionNonce, CounterDomain: value.CounterDomain,
		AcceptedCounter:     value.AcceptedCounter,
		LastObservedCounter: value.LastObservedCounter,
		ExpectedTransport:   value.ExpectedTransport,
		StartNotBefore:      value.StartNotBefore, StartDeadline: value.StartDeadline,
		FinishDeadline: value.FinishDeadline,
	}
	authorization := realcycle.AuthorizationCommitment{
		Schema: realcycle.AuthorizationCommitmentSchema,
		State:  "sealed-pending-activation", Scope: "execute-one-four-node-cycle",
		RunID: value.RunID, CycleID: value.CycleID,
		AttemptID: value.AttemptID, TopologyID: value.TopologyID,
		PlanSHA256: value.PlanSHA256, PlanObjectDigest: value.PlanObjectDigest,
		AdmissionBindingDigest:  value.AdmissionBindingDigest,
		AdmissionBundleSHA256:   value.AdmissionBundleSHA256,
		RuntimeCollectionDigest: value.RuntimeCollectionDigest,
		ReservationObjectDigest: value.ReservationObjectDigest,
		AdmissionNonce:          value.AdmissionNonce, CounterDomain: value.CounterDomain,
		MinimumActivationCounter: value.MinimumActivationCounter,
		ValidNotBefore:           value.ValidNotBefore, ValidNotAfter: value.ValidNotAfter,
		MaxRuntimeAgeSeconds: value.MaxRuntimeAgeSeconds,
		MaxExecutionSeconds:  value.MaxExecutionSeconds,
		OneTimeNonce:         value.OneTimeNonce,
		AuthorizerKeyID:      value.AuthorizationKeyID,
		Signature:            value.AuthorizationSignature,
	}
	extension := realcycle.HandoffRoleExtension{
		Schema:     realcycle.HandoffRoleExtensionSchema,
		State:      "public-key-extension-only",
		PlanSHA256: value.PlanSHA256, PlanObjectDigest: value.PlanObjectDigest,
		AcceptedTrustSHA256: value.TrustSHA256,
		Keys:                value.RoleExtensionKeys,
		ControllerKeyID:     value.RoleExtensionControllerKeyID,
		Signature:           value.RoleExtensionSignature,
	}
	supervisor := realcycle.SupervisorCommitment{
		Schema: realcycle.SupervisorCommitmentSchema,
		State:  "sealed-pending-activation",
		RunID:  value.RunID, CycleID: value.CycleID,
		AttemptID: value.AttemptID, TopologyID: value.TopologyID,
		PlanSHA256: value.PlanSHA256, PlanObjectDigest: value.PlanObjectDigest,
		ExpectedTransport:          value.ExpectedTransport,
		SupervisorExecutablePath:   value.SupervisorExecutablePath,
		SupervisorExecutableSHA256: value.SupervisorExecutableSHA256,
		SupervisorConfigPath:       value.SupervisorConfigPath,
		SupervisorConfigSHA256:     value.SupervisorConfigSHA256,
		MaxExecutionSeconds:        value.MaxExecutionSeconds,
		OneTimeNonce:               value.OneTimeNonce,
		SupervisorKeyID:            value.SupervisorKeyID,
		Signature:                  value.SupervisorSignature,
	}
	return expected, authorization, extension, supervisor
}

func e6ResultProjection(
	value e6VerificationReceipt,
) realcycle.SealedHandoffResult {
	return realcycle.SealedHandoffResult{
		TrustSHA256:                  value.TrustSHA256,
		AcceptedCounter:              value.AcceptedCounter,
		LastObservedCounter:          value.LastObservedCounter,
		ExpectedTransport:            value.ExpectedTransport,
		StartNotBefore:               value.StartNotBefore,
		StartDeadline:                value.StartDeadline,
		FinishDeadline:               value.FinishDeadline,
		AuthorizationSHA256:          value.AuthorizationSHA256,
		AuthorizationObjectDigest:    value.AuthorizationObjectDigest,
		RoleExtensionSHA256:          value.RoleExtensionSHA256,
		RoleExtensionObjectDigest:    value.RoleExtensionObjectDigest,
		RoleExtensionControllerKeyID: value.RoleExtensionControllerKeyID,
		RoleExtensionSignature:       value.RoleExtensionSignature,
		RoleExtensionKeys:            value.RoleExtensionKeys,
		AuthorizationKeyID:           value.AuthorizationKeyID,
		AuthorizationSignature:       value.AuthorizationSignature,
		SupervisorSHA256:             value.SupervisorSHA256,
		SupervisorObjectDigest:       value.SupervisorObjectDigest,
		SupervisorKeyID:              value.SupervisorKeyID,
		SupervisorSignature:          value.SupervisorSignature,
		CollectionDigest:             value.HandoffCollectionDigest,
		MinimumActivationCounter:     value.MinimumActivationCounter,
		ValidNotBefore:               value.ValidNotBefore, ValidNotAfter: value.ValidNotAfter,
		MaxRuntimeAgeSeconds:       value.MaxRuntimeAgeSeconds,
		MaxExecutionSeconds:        value.MaxExecutionSeconds,
		OneTimeNonce:               value.OneTimeNonce,
		SupervisorExecutablePath:   value.SupervisorExecutablePath,
		SupervisorExecutableSHA256: value.SupervisorExecutableSHA256,
		SupervisorConfigPath:       value.SupervisorConfigPath,
		SupervisorConfigSHA256:     value.SupervisorConfigSHA256,
	}
}

func verifyE6ReceiptProjection(
	value e6VerificationReceipt, trustPath string,
) (realcycle.SealedHandoffResult, error) {
	expected, authorization, extension, supervisor := e6ReplayObjects(value)
	result, err := replaySealedHandoffOperation(
		trustPath, expected, authorization, extension, supervisor,
	)
	if err != nil {
		return realcycle.SealedHandoffResult{}, err
	}
	if result != e6ResultProjection(value) {
		return realcycle.SealedHandoffResult{},
			errors.New("E6 receipt signed projection mismatch")
	}
	return result, nil
}
