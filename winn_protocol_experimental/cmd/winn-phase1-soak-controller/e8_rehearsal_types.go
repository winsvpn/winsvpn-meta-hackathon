//go:build winn_incomplete_e8

package main

import (
	"encoding/json"
	"errors"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	e8Mode            = "admitted-e8-r4-local-sealed-rehearsal"
	e8ReceiptSchema   = "winn-local-sealed-four-node-rehearsal-receipt/v4"
	e8ReceiptDomain   = "winn-local-sealed-four-node-rehearsal-receipt-object/v4"
	e8ReceiptFile     = "local-sealed-rehearsal-receipt.json"
	e8ReceiptMaxBytes = 512 << 10
)

type e8NodeEvidence struct {
	Contract                    realcycle.LocalRehearsalNodeContract `json:"contract"`
	Ready                       realcycle.LocalRehearsalNodeFrame    `json:"ready"`
	Start                       realcycle.LocalRehearsalNodeFrame    `json:"start"`
	Terminal                    realcycle.LocalRehearsalNodeFrame    `json:"terminal"`
	ExitCode                    int                                  `json:"exit_code"`
	ChannelEOFObserved          bool                                 `json:"channel_eof_observed"`
	ZeroSurvivorsObserved       bool                                 `json:"zero_survivors_observed"`
	SandboxThreadCount          uint64                               `json:"sandbox_thread_count"`
	SandboxStatusDigest         string                               `json:"sandbox_status_digest"`
	PidfdRetained               bool                                 `json:"pidfd_retained"`
	PidfdReaped                 bool                                 `json:"pidfd_reaped"`
	LifecyclePolicyDigest       string                               `json:"lifecycle_policy_digest"`
	DescriptorCount             uint64                               `json:"descriptor_count"`
	DescriptorCensusDigest      string                               `json:"descriptor_census_digest"`
	AndroidPackageBindingDigest string                               `json:"android_package_binding_digest,omitempty"`
}

type e8Receipt struct {
	Schema                          string            `json:"schema"`
	Mode                            string            `json:"mode"`
	RunID                           string            `json:"run_id"`
	CycleID                         string            `json:"cycle_id"`
	AttemptID                       string            `json:"attempt_id"`
	TopologyID                      string            `json:"topology_id"`
	E3RunID                         string            `json:"e3_run_id"`
	E3CycleID                       string            `json:"e3_cycle_id"`
	E3AttemptID                     string            `json:"e3_attempt_id"`
	E3TopologyID                    string            `json:"e3_topology_id"`
	E3Sequence                      uint64            `json:"e3_sequence"`
	E3ReceiptDigest                 string            `json:"e3_receipt_digest"`
	E3CheckpointAddress             string            `json:"e3_checkpoint_content_address"`
	E3InventoryDigest               string            `json:"e3_attempt_inventory_digest"`
	PlanSHA256                      string            `json:"plan_sha256"`
	PlanObjectDigest                string            `json:"plan_object_digest"`
	E6ReceiptSHA256                 string            `json:"e6_receipt_sha256"`
	E6ReceiptObjectDigest           string            `json:"e6_receipt_object_digest"`
	E7ReceiptSHA256                 string            `json:"e7_receipt_sha256"`
	E7ReceiptObjectDigest           string            `json:"e7_receipt_object_digest"`
	RehearsalGrantSHA256            string            `json:"rehearsal_grant_sha256"`
	RehearsalGrantObjectDigest      string            `json:"rehearsal_grant_object_digest"`
	RehearsalAcceptanceSHA256       string            `json:"rehearsal_acceptance_sha256"`
	RehearsalAcceptanceObjectDigest string            `json:"rehearsal_acceptance_object_digest"`
	RehearsalGrantCollectionDigest  string            `json:"rehearsal_grant_collection_digest"`
	WorkerSHA256                    string            `json:"worker_sha256"`
	SupervisorExecutableSHA256      string            `json:"supervisor_executable_sha256"`
	SupervisorExecutableDevice      uint64            `json:"supervisor_executable_device"`
	SupervisorExecutableInode       uint64            `json:"supervisor_executable_inode"`
	SupervisorExecutableSize        int64             `json:"supervisor_executable_size"`
	SupervisorExecutableMode        uint32            `json:"supervisor_executable_mode"`
	SupervisorIdentityDigest        string            `json:"supervisor_identity_digest"`
	Nodes                           [4]e8NodeEvidence `json:"nodes"`
	RehearsalCompleted              bool              `json:"rehearsal_completed"`
	MatrixExecuted                  bool              `json:"matrix_executed"`
	ProviderAccess                  bool              `json:"provider_access"`
	CredentialAccess                bool              `json:"credential_access"`
	NetworkAccess                   bool              `json:"network_access"`
	LiveNodesContacted              bool              `json:"live_nodes_contacted"`
	SpendAuthorized                 bool              `json:"spend_authorized"`
	DispatchAuthorized              bool              `json:"dispatch_authorized"`
	ExplicitAuthorityConsumed       bool              `json:"explicit_authority_consumed"`
	ProductionE7Consumed            bool              `json:"production_e7_consumed"`
	SandboxEnforced                 bool              `json:"sandbox_enforced"`
	Mutation                        string            `json:"mutation"`
	Authority                       bool              `json:"authority"`
	ObjectDigest                    string            `json:"object_digest"`
}

type e8Summary struct {
	Schema             string `json:"schema"`
	Mode               string `json:"mode"`
	RunID              string `json:"run_id"`
	CycleID            string `json:"cycle_id"`
	AttemptID          string `json:"attempt_id"`
	NodeCount          int    `json:"node_count"`
	ReceiptSHA256      string `json:"receipt_sha256"`
	ReceiptDigest      string `json:"receipt_object_digest"`
	RehearsalComplete  bool   `json:"rehearsal_complete"`
	ProviderAccess     bool   `json:"provider_access"`
	CredentialAccess   bool   `json:"credential_access"`
	NetworkAccess      bool   `json:"network_access"`
	LiveNodesContacted bool   `json:"live_nodes_contacted"`
	SpendAuthorized    bool   `json:"spend_authorized"`
	Authority          bool   `json:"authority"`
}

func encodeE8Receipt(value e8Receipt) (e8Receipt, []byte, error) {
	value.Schema = e8ReceiptSchema
	value.Mode = e8Mode
	value.ObjectDigest = ""
	digest, err := admittedDigest(e8ReceiptDomain, value)
	if err != nil {
		return e8Receipt{}, nil, err
	}
	value.ObjectDigest = digest
	if err := validateE8Receipt(value); err != nil {
		return e8Receipt{}, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > e8ReceiptMaxBytes {
		return e8Receipt{}, nil, errors.New("E8 receipt encoding exceeds bound")
	}
	return value, encoded, nil
}

func validateE8Receipt(value e8Receipt) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(e8ReceiptDomain, value)
	if err != nil || digest != expected {
		return errors.New("E8 receipt object digest mismatch")
	}
	if value.Schema != e8ReceiptSchema || value.Mode != e8Mode ||
		len(value.Nodes) != 4 || !value.RehearsalCompleted ||
		value.MatrixExecuted || value.ProviderAccess || value.CredentialAccess ||
		value.NetworkAccess || value.LiveNodesContacted ||
		value.SpendAuthorized || value.DispatchAuthorized ||
		value.ExplicitAuthorityConsumed || value.ProductionE7Consumed ||
		!value.SandboxEnforced || value.Mutation != "local-evidence-only" ||
		value.Authority {
		return errors.New("E8 receipt authority state is unsafe")
	}
	for _, candidate := range []string{
		value.E3ReceiptDigest, value.E3CheckpointAddress,
		value.E3InventoryDigest, value.PlanSHA256, value.PlanObjectDigest,
		value.E6ReceiptSHA256, value.E6ReceiptObjectDigest,
		value.E7ReceiptSHA256, value.E7ReceiptObjectDigest,
		value.RehearsalGrantSHA256, value.RehearsalGrantObjectDigest,
		value.RehearsalAcceptanceSHA256,
		value.RehearsalAcceptanceObjectDigest,
		value.RehearsalGrantCollectionDigest, value.WorkerSHA256, digest,
		value.SupervisorExecutableSHA256, value.SupervisorIdentityDigest,
	} {
		if !digestPattern.MatchString(candidate) {
			return errors.New("E8 receipt digest is malformed")
		}
	}
	if value.SupervisorExecutableDevice == 0 ||
		value.SupervisorExecutableInode == 0 ||
		value.SupervisorExecutableSize <= 0 ||
		value.SupervisorExecutableMode&0o111 == 0 {
		return errors.New("E8 retained supervisor identity is incomplete")
	}
	seenNodes := map[string]bool{}
	seenServices := map[string]bool{}
	seenProcesses := map[uint64]bool{}
	seenNonces := map[string]bool{}
	seenStartTokens := map[string]bool{}
	androidBindingDigest := ""
	androidBindingCount := 0
	for index, node := range value.Nodes {
		if err := realcycle.ValidateLocalRehearsalContract(node.Contract); err != nil {
			return err
		}
		if value.E3RunID != value.RunID || value.E3CycleID != value.CycleID ||
			value.E3AttemptID != value.AttemptID ||
			value.E3TopologyID != value.TopologyID || value.E3Sequence == 0 ||
			node.Contract.RunID != value.RunID ||
			node.Contract.CycleID != value.CycleID ||
			node.Contract.AttemptID != value.AttemptID ||
			node.Contract.TopologyID != value.TopologyID ||
			node.Contract.PlanSHA256 != value.PlanSHA256 ||
			node.Contract.PlanObjectDigest != value.PlanObjectDigest ||
			node.Contract.E6ReceiptSHA256 != value.E6ReceiptSHA256 ||
			node.Contract.E6ReceiptObjectDigest != value.E6ReceiptObjectDigest ||
			node.Contract.E7ReceiptSHA256 != value.E7ReceiptSHA256 ||
			node.Contract.E7ReceiptObjectDigest != value.E7ReceiptObjectDigest ||
			node.Contract.RehearsalGrantDigest !=
				value.RehearsalGrantCollectionDigest ||
			node.Contract.WorkerSHA256 != value.WorkerSHA256 {
			return errors.New("E8 node contract does not bind receipt")
		}
		for _, frame := range []realcycle.LocalRehearsalNodeFrame{
			node.Ready, node.Start, node.Terminal,
		} {
			if err := realcycle.ValidateLocalRehearsalFrame(frame); err != nil {
				return err
			}
			if frame.ContractDigest != node.Contract.ObjectDigest ||
				frame.Role != node.Contract.Role || frame.NodeID != node.Contract.NodeID {
				return errors.New("E8 node frame cross-binding mismatch")
			}
		}
		if node.Ready.State != "ready" || node.Start.State != "start" ||
			node.Terminal.State != "terminal-success" ||
			node.Start.ProcessID != node.Ready.ProcessID ||
			node.Start.ProcessStart != node.Ready.ProcessStart ||
			node.Terminal.ProcessID != node.Ready.ProcessID ||
			node.Terminal.ProcessStart != node.Ready.ProcessStart ||
			node.Terminal.StartToken != node.Start.StartToken ||
			node.ExitCode != 0 || !node.ChannelEOFObserved ||
			!node.ZeroSurvivorsObserved || node.SandboxThreadCount == 0 ||
			!digestPattern.MatchString(node.SandboxStatusDigest) ||
			!node.PidfdRetained || !node.PidfdReaped ||
			node.LifecyclePolicyDigest != e8LifecyclePolicyDigest() ||
			node.DescriptorCount < 6 || node.DescriptorCount > 64 ||
			!digestPattern.MatchString(node.DescriptorCensusDigest) ||
			seenNodes[node.Contract.NodeID] ||
			seenServices[node.Contract.ServiceID] ||
			seenProcesses[node.Ready.ProcessID] ||
			seenNonces[node.Contract.RehearsalNonce] ||
			seenStartTokens[node.Start.StartToken] {
			return errors.New("E8 node terminal evidence is inconsistent")
		}
		if node.AndroidPackageBindingDigest != "" {
			if !digestPattern.MatchString(
				node.AndroidPackageBindingDigest,
			) {
				return errors.New(
					"E8 Android package binding digest is malformed",
				)
			}
			if androidBindingDigest == "" {
				androidBindingDigest = node.AndroidPackageBindingDigest
			}
			if node.AndroidPackageBindingDigest != androidBindingDigest {
				return errors.New(
					"E8 Android package binding differs across nodes",
				)
			}
			androidBindingCount++
		}
		expectedInput, expectedOutput, expectedOperation, operationErr :=
			realcycle.LocalRehearsalOperationEvidence(
				node.Contract, node.Start.StartToken,
				node.Ready.ProcessID, node.Ready.ProcessStart,
			)
		if operationErr != nil ||
			node.Terminal.OperationKind !=
				"sealed-local-service-self-check" ||
			node.Terminal.OperationInput != expectedInput ||
			node.Terminal.OperationOutput != expectedOutput ||
			node.Terminal.OperationDigest != expectedOperation {
			return errors.New("E8 node service operation evidence is inconsistent")
		}
		seenNodes[node.Contract.NodeID] = true
		seenServices[node.Contract.ServiceID] = true
		seenProcesses[node.Ready.ProcessID] = true
		seenNonces[node.Contract.RehearsalNonce] = true
		seenStartTokens[node.Start.StartToken] = true
		if node.Contract.Role != e5RequiredRoles[index] {
			return errors.New("E8 node role order is invalid")
		}
	}
	if androidBindingCount != 0 && androidBindingCount != len(value.Nodes) {
		return errors.New("E8 Android package binding is incomplete")
	}
	return nil
}

func e8LifecyclePolicyDigest() string {
	digest, err := admittedDigest(
		"winn-e8-r3-pidfd-lifecycle-policy/v1",
		[]string{
			"retain_pidfd_before_ready", "bind_pid_and_proc_start_ticks",
			"require_credentialed_terminal_then_channel_eof",
			"wait_before_pidfd_esrch_reap_proof",
			"failure_kill_pidfd_and_group_before_wait",
			"propagate_channel_kill_wait_and_pidfd_close_errors",
		},
	)
	if err != nil {
		panic(err)
	}
	return digest
}
