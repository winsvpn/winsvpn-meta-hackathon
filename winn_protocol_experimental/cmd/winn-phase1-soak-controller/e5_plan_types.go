package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	e5PlanSchema    = "winn-real-cycle-four-node-plan/v1"
	e5PlanDomain    = "winn-real-cycle-four-node-plan-object/v1"
	e5PlanSummaryV1 = "winn-real-cycle-four-node-plan-summary/v1"
	e5PlanFile      = "four-node-plan.json"
	e5PlanMode      = "admitted-e5-four-node-plan"
	e5PlanMaxBytes  = 256 << 10
	e5PlanNodeCount = 4
	e5PlanGateCount = 7
)

var e5RequiredRoles = [e5PlanNodeCount]string{
	"control", "entry-primary", "entry-secondary", "exit",
}

var e5RequiredFutureGates = [e5PlanGateCount]string{
	"winn-real-cycle-dispatch-authorization/v1",
	"winn-real-cycle-secure-time-observation/v1",
	"winn-real-cycle-live-runtime-recheck/v1",
	"winn-real-cycle-credential-handle-release/v1",
	"winn-real-cycle-execution-supervisor-receipt/v1",
	"winn-real-cycle-terminal-set/v1",
	"winn-real-cycle-lease-terminal/v1",
}

type e5PlanNode struct {
	RuntimeSchema          string `json:"runtime_schema"`
	CycleBindingDigest     string `json:"cycle_binding_digest"`
	Role                   string `json:"role"`
	InstanceUUID           string `json:"instance_uuid"`
	NodeID                 string `json:"node_id"`
	ServiceID              string `json:"service_id"`
	Provider               string `json:"provider"`
	OperatorID             string `json:"operator_id"`
	BootID                 string `json:"boot_id"`
	ProcessID              uint64 `json:"process_id"`
	ProcessStartTicks      uint64 `json:"process_start_ticks"`
	ExecutableSHA256       string `json:"executable_sha256"`
	ConfigSHA256           string `json:"config_sha256"`
	CertificateSHA256      string `json:"certificate_sha256"`
	Endpoint               string `json:"endpoint"`
	RuntimeStatus          string `json:"runtime_status"`
	RuntimeObservedAt      string `json:"runtime_observed_at"`
	RuntimeCounterDomain   string `json:"runtime_counter_domain"`
	RuntimeObservedCounter uint64 `json:"runtime_observed_counter"`
	RuntimeKeyID           string `json:"runtime_key_id"`
	RuntimeSignature       string `json:"runtime_signature"`
	RuntimeObjectDigest    string `json:"runtime_object_digest"`
}

type e5FourNodePlan struct {
	Schema                     string                      `json:"schema"`
	Mode                       string                      `json:"mode"`
	RunID                      string                      `json:"run_id"`
	CycleID                    string                      `json:"cycle_id"`
	AttemptID                  string                      `json:"attempt_id"`
	TopologyID                 string                      `json:"topology_id"`
	AdmissionBindingDigest     string                      `json:"admission_binding_digest"`
	AdmissionBundleSHA256      string                      `json:"admission_bundle_sha256"`
	RuntimeCollectionDigest    string                      `json:"runtime_collection_digest"`
	ReservationObjectDigest    string                      `json:"reservation_object_digest"`
	AdmissionNonce             string                      `json:"admission_nonce"`
	CounterDomain              string                      `json:"counter_domain"`
	AcceptedCounter            uint64                      `json:"accepted_counter"`
	ExpectedTransport          string                      `json:"expected_transport"`
	StartNotBefore             string                      `json:"start_not_before"`
	StartDeadline              string                      `json:"start_deadline"`
	FinishDeadline             string                      `json:"finish_deadline"`
	ControllerConfigSHA256     string                      `json:"controller_config_sha256"`
	E4ReceiptCount             uint64                      `json:"e4_receipt_count"`
	E4LastReceiptDigest        string                      `json:"e4_last_receipt_digest"`
	E4CheckpointContentAddress string                      `json:"e4_checkpoint_content_address"`
	E4AttemptInventoryDigest   string                      `json:"e4_attempt_inventory_digest"`
	ExercisedNodeCount         int                         `json:"exercised_node_count"`
	ExercisedNodeOrder         [e5PlanNodeCount]string     `json:"exercised_node_order"`
	Nodes                      [e5PlanNodeCount]e5PlanNode `json:"nodes"`
	RequiredFutureGates        [e5PlanGateCount]string     `json:"required_future_gates"`
	AuthorizationState         string                      `json:"authorization_state"`
	DispatchAuthorized         bool                        `json:"dispatch_authorized"`
	ExternalTopologyExecuted   bool                        `json:"external_topology_executed"`
	MatrixExecuted             bool                        `json:"matrix_executed"`
	ProviderAccess             bool                        `json:"provider_access"`
	CredentialAccess           bool                        `json:"credential_access"`
	NetworkAccess              bool                        `json:"network_access"`
	LiveNodesContacted         bool                        `json:"live_nodes_contacted"`
	SpendAuthorized            bool                        `json:"spend_authorized"`
	HandoffReady               bool                        `json:"handoff_ready"`
	Mutation                   string                      `json:"mutation"`
	Authority                  bool                        `json:"authority"`
	ObjectDigest               string                      `json:"object_digest"`
}

type e5PlanSummary struct {
	Schema                     string `json:"schema"`
	Mode                       string `json:"mode"`
	RunID                      string `json:"run_id"`
	CycleID                    string `json:"cycle_id"`
	AttemptID                  string `json:"attempt_id"`
	ExercisedNodeCount         int    `json:"exercised_node_count"`
	PlanSHA256                 string `json:"plan_sha256"`
	PlanObjectDigest           string `json:"plan_object_digest"`
	E4LastReceiptDigest        string `json:"e4_last_receipt_digest"`
	E4CheckpointContentAddress string `json:"e4_checkpoint_content_address"`
	DispatchAuthorized         bool   `json:"dispatch_authorized"`
	ExternalTopologyExecuted   bool   `json:"external_topology_executed"`
	ProviderAccess             bool   `json:"provider_access"`
	CredentialAccess           bool   `json:"credential_access"`
	NetworkAccess              bool   `json:"network_access"`
	LiveNodesContacted         bool   `json:"live_nodes_contacted"`
	SpendAuthorized            bool   `json:"spend_authorized"`
	HandoffReady               bool   `json:"handoff_ready"`
	Authority                  bool   `json:"authority"`
}

func e5PlanSummaryJSON(value e5PlanSummary) ([]byte, error) {
	return json.Marshal(value)
}

func e5NodeFrom(
	deployment realcycle.DeploymentBinding,
	runtime realcycle.RuntimeAttestation,
	runtimeDigest string,
) (e5PlanNode, error) {
	if runtime.Role != deployment.Role ||
		runtime.InstanceUUID != deployment.InstanceUUID ||
		runtime.NodeID != deployment.NodeID ||
		runtime.ServiceID != deployment.ServiceID ||
		runtime.Provider != deployment.Provider ||
		runtime.OperatorID != deployment.OperatorID {
		return e5PlanNode{}, errors.New("runtime/deployment projection mismatch")
	}
	recomputed, err := realcycle.RuntimeAttestationObjectDigest(runtime)
	if err != nil || recomputed != runtimeDigest {
		return e5PlanNode{}, errors.New("runtime object digest mismatch")
	}
	return e5PlanNode{
		RuntimeSchema:      runtime.Schema,
		CycleBindingDigest: runtime.CycleBindingDigest,
		Role:               deployment.Role, InstanceUUID: deployment.InstanceUUID,
		NodeID: deployment.NodeID, ServiceID: deployment.ServiceID,
		Provider: deployment.Provider, OperatorID: deployment.OperatorID,
		BootID: runtime.BootID, ProcessID: runtime.ProcessID,
		ProcessStartTicks: runtime.ProcessStartTicks,
		ExecutableSHA256:  runtime.ExecutableSHA256,
		ConfigSHA256:      runtime.ConfigSHA256,
		CertificateSHA256: runtime.CertificateSHA256,
		Endpoint:          runtime.Endpoint, RuntimeStatus: runtime.Status,
		RuntimeObservedAt:      runtime.ObservedAt,
		RuntimeCounterDomain:   runtime.CounterDomain,
		RuntimeObservedCounter: runtime.ObservedCounter,
		RuntimeKeyID:           runtime.KeyID,
		RuntimeSignature:       runtime.Signature,
		RuntimeObjectDigest:    runtimeDigest,
	}, nil
}

func (value e5PlanNode) runtimeAttestation() realcycle.RuntimeAttestation {
	return realcycle.RuntimeAttestation{
		Schema:             value.RuntimeSchema,
		CycleBindingDigest: value.CycleBindingDigest,
		Role:               value.Role, InstanceUUID: value.InstanceUUID,
		NodeID: value.NodeID, ServiceID: value.ServiceID,
		Provider: value.Provider, OperatorID: value.OperatorID,
		BootID: value.BootID, ProcessID: value.ProcessID,
		ProcessStartTicks: value.ProcessStartTicks,
		ExecutableSHA256:  value.ExecutableSHA256,
		ConfigSHA256:      value.ConfigSHA256,
		CertificateSHA256: value.CertificateSHA256,
		Endpoint:          value.Endpoint, Status: value.RuntimeStatus,
		ObservedAt:      value.RuntimeObservedAt,
		CounterDomain:   value.RuntimeCounterDomain,
		ObservedCounter: value.RuntimeObservedCounter,
		KeyID:           value.RuntimeKeyID, Signature: value.RuntimeSignature,
	}
}

func validateE5Plan(value e5FourNodePlan) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(e5PlanDomain, value)
	if err != nil || digest != expected {
		return errors.New("E5 plan object digest mismatch")
	}
	if value.Schema != e5PlanSchema || value.Mode != e5PlanMode ||
		value.RunID == "" || value.CycleID == "" || value.AttemptID == "" ||
		value.TopologyID == "" || value.ExercisedNodeCount != e5PlanNodeCount ||
		value.E4ReceiptCount == 0 ||
		!noncePattern.MatchString(value.AdmissionNonce) ||
		(value.ExpectedTransport != realcycle.TransportDirect &&
			value.ExpectedTransport != realcycle.TransportH3) ||
		value.StartNotBefore == "" || value.StartDeadline == "" ||
		value.FinishDeadline == "" ||
		value.AuthorizationState != "absent" ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.MatrixExecuted || value.ProviderAccess || value.CredentialAccess ||
		value.NetworkAccess || value.LiveNodesContacted ||
		value.SpendAuthorized || value.HandoffReady ||
		value.Mutation != "none" || value.Authority ||
		!slices.Equal(value.RequiredFutureGates[:], e5RequiredFutureGates[:]) {
		return errors.New("E5 plan is not exact nonauthorizing state")
	}
	for _, candidate := range []string{
		value.AdmissionBindingDigest, value.AdmissionBundleSHA256,
		value.RuntimeCollectionDigest, value.ReservationObjectDigest,
		value.ControllerConfigSHA256, value.E4LastReceiptDigest,
		value.E4CheckpointContentAddress, value.E4AttemptInventoryDigest,
		digest,
	} {
		if !digestPattern.MatchString(candidate) {
			return errors.New("E5 plan contains malformed digest")
		}
	}
	seenNodes := make(map[string]bool, e5PlanNodeCount)
	for index, node := range value.Nodes {
		if node.Role != e5RequiredRoles[index] ||
			node.RuntimeSchema != realcycle.RuntimeSchema ||
			node.CycleBindingDigest != value.AdmissionBindingDigest ||
			!digestPattern.MatchString(node.ExecutableSHA256) ||
			!digestPattern.MatchString(node.ConfigSHA256) ||
			!digestPattern.MatchString(node.CertificateSHA256) ||
			!digestPattern.MatchString(node.RuntimeObjectDigest) ||
			node.NodeID == "" || node.InstanceUUID == "" ||
			node.ServiceID == "" || node.Provider == "" ||
			node.OperatorID == "" || node.BootID == "" ||
			node.ProcessID == 0 || node.ProcessStartTicks == 0 ||
			node.Endpoint == "" || node.RuntimeStatus != "running" ||
			node.RuntimeObservedAt == "" || node.RuntimeKeyID == "" ||
			node.RuntimeSignature == "" ||
			node.RuntimeCounterDomain != value.CounterDomain ||
			node.RuntimeObservedCounter <= value.AcceptedCounter {
			return fmt.Errorf("E5 node %d is invalid", index)
		}
		if seenNodes[node.NodeID] {
			return errors.New("E5 plan contains duplicate node identity")
		}
		seenNodes[node.NodeID] = true
		recomputed, err := realcycle.RuntimeAttestationObjectDigest(
			node.runtimeAttestation(),
		)
		if err != nil || recomputed != node.RuntimeObjectDigest {
			return fmt.Errorf("E5 node %d runtime digest mismatch", index)
		}
	}
	seenExercised := make(map[string]bool, e5PlanNodeCount)
	for _, nodeID := range value.ExercisedNodeOrder {
		if nodeID == "" || seenExercised[nodeID] || !seenNodes[nodeID] {
			return errors.New("E5 exercised-node order is not the exact node set")
		}
		seenExercised[nodeID] = true
	}
	return nil
}

func encodeE5Plan(value e5FourNodePlan) (e5FourNodePlan, []byte, error) {
	value.Schema = e5PlanSchema
	value.Mode = e5PlanMode
	value.ObjectDigest = ""
	digest, err := admittedDigest(e5PlanDomain, value)
	if err != nil {
		return e5FourNodePlan{}, nil, err
	}
	value.ObjectDigest = digest
	if err := validateE5Plan(value); err != nil {
		return e5FourNodePlan{}, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > e5PlanMaxBytes {
		return e5FourNodePlan{}, nil, errors.New("E5 plan encoding exceeds bound")
	}
	return value, encoded, nil
}

func parseE5Plan(data []byte) (e5FourNodePlan, error) {
	var value e5FourNodePlan
	if len(data) == 0 || len(data) > e5PlanMaxBytes {
		return value, errors.New("E5 plan size is invalid")
	}
	if err := decodeStrictObject(data, &value); err != nil {
		return value, err
	}
	if err := validateE5Plan(value); err != nil {
		return value, err
	}
	return value, nil
}
