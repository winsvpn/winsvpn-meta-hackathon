package main

import (
	"encoding/json"
	"errors"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	e7ReceiptSchema   = "winn-real-cycle-execution-authorization-verification/v1"
	e7ReceiptDomain   = "winn-real-cycle-execution-authorization-verification-object/v1"
	e7SummarySchema   = "winn-real-cycle-execution-authorization-summary/v1"
	e7Mode            = "admitted-e7-execution-authorization"
	e7ReceiptFile     = "execution-authorization-verification.json"
	e7ReceiptMaxBytes = 192 << 10
)

type e7VerificationReceipt struct {
	Schema                        string                                      `json:"schema"`
	Mode                          string                                      `json:"mode"`
	E6ReceiptSHA256               string                                      `json:"e6_receipt_sha256"`
	E6ReceiptObjectDigest         string                                      `json:"e6_receipt_object_digest"`
	ExecutionAuthorization        realcycle.ExecutionAuthorization            `json:"execution_authorization"`
	SupervisorAcceptance          realcycle.SupervisorAuthorizationAcceptance `json:"supervisor_acceptance"`
	DecisionSHA256                string                                      `json:"decision_sha256"`
	DecisionObjectDigest          string                                      `json:"decision_object_digest"`
	AcceptanceSHA256              string                                      `json:"acceptance_sha256"`
	AcceptanceObjectDigest        string                                      `json:"acceptance_object_digest"`
	AuthorizationCollectionDigest string                                      `json:"authorization_collection_digest"`
	VerificationState             string                                      `json:"verification_state"`
	SecureTimeObserved            bool                                        `json:"secure_time_observed"`
	ActivationCounterReserved     bool                                        `json:"activation_counter_reserved"`
	LiveRuntimeRechecked          bool                                        `json:"live_runtime_rechecked"`
	CredentialHandleReleased      bool                                        `json:"credential_handle_released"`
	ExplicitAuthorityConsumed     bool                                        `json:"explicit_authority_consumed"`
	SupervisorExecuted            bool                                        `json:"supervisor_executed"`
	DispatchAuthorized            bool                                        `json:"dispatch_authorized"`
	ExternalTopologyExecuted      bool                                        `json:"external_topology_executed"`
	ProviderAccess                bool                                        `json:"provider_access"`
	CredentialAccess              bool                                        `json:"credential_access"`
	NetworkAccess                 bool                                        `json:"network_access"`
	LiveNodesContacted            bool                                        `json:"live_nodes_contacted"`
	SpendAuthorized               bool                                        `json:"spend_authorized"`
	HandoffReady                  bool                                        `json:"handoff_ready"`
	Mutation                      string                                      `json:"mutation"`
	Authority                     bool                                        `json:"authority"`
	ObjectDigest                  string                                      `json:"object_digest"`
}

type e7Summary struct {
	Schema                        string `json:"schema"`
	Mode                          string `json:"mode"`
	RunID                         string `json:"run_id"`
	CycleID                       string `json:"cycle_id"`
	AttemptID                     string `json:"attempt_id"`
	DecisionID                    string `json:"decision_id"`
	E6ReceiptSHA256               string `json:"e6_receipt_sha256"`
	ReceiptSHA256                 string `json:"receipt_sha256"`
	ReceiptObjectDigest           string `json:"receipt_object_digest"`
	AuthorizationCollectionDigest string `json:"authorization_collection_digest"`
	VerificationState             string `json:"verification_state"`
	DispatchAuthorized            bool   `json:"dispatch_authorized"`
	ProviderAccess                bool   `json:"provider_access"`
	CredentialAccess              bool   `json:"credential_access"`
	NetworkAccess                 bool   `json:"network_access"`
	LiveNodesContacted            bool   `json:"live_nodes_contacted"`
	SpendAuthorized               bool   `json:"spend_authorized"`
	HandoffReady                  bool   `json:"handoff_ready"`
	Authority                     bool   `json:"authority"`
}

func buildE7Receipt(
	e6 e6VerificationReceipt,
	e6SHA string,
	decision realcycle.ExecutionAuthorization,
	acceptance realcycle.SupervisorAuthorizationAcceptance,
	result realcycle.ExecutionAuthorizationResult,
) (e7VerificationReceipt, []byte, error) {
	return encodeE7Receipt(e7VerificationReceipt{
		E6ReceiptSHA256:               e6SHA,
		E6ReceiptObjectDigest:         e6.ObjectDigest,
		ExecutionAuthorization:        decision,
		SupervisorAcceptance:          acceptance,
		DecisionSHA256:                result.DecisionSHA256,
		DecisionObjectDigest:          result.DecisionObjectDigest,
		AcceptanceSHA256:              result.AcceptanceSHA256,
		AcceptanceObjectDigest:        result.AcceptanceObjectDigest,
		AuthorizationCollectionDigest: result.CollectionDigest,
		VerificationState:             "explicit-authority-inputs-verified-pending-atomic-consumption",
		Mutation:                      "none",
	})
}

func encodeE7Receipt(
	value e7VerificationReceipt,
) (e7VerificationReceipt, []byte, error) {
	value.Schema = e7ReceiptSchema
	value.Mode = e7Mode
	value.ObjectDigest = ""
	digest, err := admittedDigest(e7ReceiptDomain, value)
	if err != nil {
		return e7VerificationReceipt{}, nil, err
	}
	value.ObjectDigest = digest
	if err := validateE7ReceiptStructure(value); err != nil {
		return e7VerificationReceipt{}, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > e7ReceiptMaxBytes {
		return e7VerificationReceipt{}, nil,
			errors.New("E7 receipt encoding exceeds bound")
	}
	return value, encoded, nil
}

func validateE7ReceiptStructure(value e7VerificationReceipt) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(e7ReceiptDomain, value)
	if err != nil || digest != expected {
		return errors.New("E7 receipt object digest mismatch")
	}
	if value.Schema != e7ReceiptSchema || value.Mode != e7Mode ||
		value.VerificationState !=
			"explicit-authority-inputs-verified-pending-atomic-consumption" ||
		value.SecureTimeObserved || value.ActivationCounterReserved ||
		value.LiveRuntimeRechecked || value.CredentialHandleReleased ||
		value.ExplicitAuthorityConsumed || value.SupervisorExecuted ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.ProviderAccess || value.CredentialAccess ||
		value.NetworkAccess || value.LiveNodesContacted ||
		value.SpendAuthorized || value.HandoffReady ||
		value.Mutation != "none" || value.Authority {
		return errors.New("E7 receipt is not exact nonauthorizing state")
	}
	for _, candidate := range []string{
		value.E6ReceiptSHA256, value.E6ReceiptObjectDigest,
		value.DecisionSHA256, value.DecisionObjectDigest,
		value.AcceptanceSHA256, value.AcceptanceObjectDigest,
		value.AuthorizationCollectionDigest, digest,
	} {
		if !digestPattern.MatchString(candidate) {
			return errors.New("E7 receipt contains malformed digest")
		}
	}
	return nil
}

//lint:ignore U1000 used by Linux E7 publication and replay.
func parseE7ReceiptStructure(
	data []byte,
) (e7VerificationReceipt, error) {
	var value e7VerificationReceipt
	if len(data) == 0 || len(data) > e7ReceiptMaxBytes {
		return value, errors.New("E7 receipt size is invalid")
	}
	if err := decodeStrictObject(data, &value); err != nil {
		return value, err
	}
	if err := validateE7ReceiptStructure(value); err != nil {
		return value, err
	}
	return value, nil
}

func verifyE7ReceiptProjection(
	value e7VerificationReceipt,
	expected realcycle.ExecutionAuthorizationExpectation,
) (realcycle.ExecutionAuthorizationResult, error) {
	if value.E6ReceiptSHA256 != expected.E6ReceiptSHA256 ||
		value.E6ReceiptObjectDigest != expected.E6ReceiptObjectDigest ||
		value.ExecutionAuthorization.E6ReceiptSHA256 !=
			expected.E6ReceiptSHA256 ||
		value.ExecutionAuthorization.E6ReceiptObjectDigest !=
			expected.E6ReceiptObjectDigest ||
		value.SupervisorAcceptance.E6ReceiptSHA256 !=
			expected.E6ReceiptSHA256 ||
		value.SupervisorAcceptance.E6ReceiptObjectDigest !=
			expected.E6ReceiptObjectDigest {
		return realcycle.ExecutionAuthorizationResult{},
			errors.New("E7 outer and signed E6 bindings disagree")
	}
	result, err := realcycle.VerifyExecutionAuthorizationObjects(
		expected, value.ExecutionAuthorization, value.SupervisorAcceptance,
	)
	if err != nil {
		return realcycle.ExecutionAuthorizationResult{}, err
	}
	if result.DecisionSHA256 != value.DecisionSHA256 ||
		result.DecisionObjectDigest != value.DecisionObjectDigest ||
		result.AcceptanceSHA256 != value.AcceptanceSHA256 ||
		result.AcceptanceObjectDigest != value.AcceptanceObjectDigest ||
		result.CollectionDigest != value.AuthorizationCollectionDigest {
		return realcycle.ExecutionAuthorizationResult{},
			errors.New("E7 signed projection mismatch")
	}
	return result, nil
}

func e7SummaryJSON(value e7Summary) ([]byte, error) {
	return json.Marshal(value)
}
