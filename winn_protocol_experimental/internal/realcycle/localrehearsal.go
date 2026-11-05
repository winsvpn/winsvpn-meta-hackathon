package realcycle

import (
	"errors"
	"regexp"
)

// Local sealed four-node rehearsal contract and frame objects.
//
// These objects are consumed by the E8 local sealed rehearsal subsystem in
// cmd/winn-phase1-soak-controller. They are defined here, in the protocol
// package, so the canonical encoding and the domain separation stay with the
// rest of the real-cycle object model instead of living in a command binary.
//
// Digest construction uses digestObject, which is byte identical to the
// soak controller's admittedDigest helper: sha256 over the domain string, a
// single zero byte, then the encoding/json representation of the value. The
// controller and this package therefore derive the same digest for the same
// object without sharing code.
//
// Every validator here is fail closed. A validator returns nil only when
// every stated invariant holds; any unknown state, malformed digest, empty
// identifier, or out-of-band operation field is rejected.

const (
	localRehearsalContractDomain = "winn-realcycle-local-rehearsal-contract/v1"

	localRehearsalOperationInputDomain = "winn-realcycle-local-rehearsal-" +
		"operation-evidence-input/v1"
	localRehearsalOperationOutputDomain = "winn-realcycle-local-rehearsal-" +
		"operation-evidence-output/v1"
	localRehearsalOperationDomain = "winn-realcycle-local-rehearsal-" +
		"operation-evidence/v1"

	// LocalRehearsalOperationKind is the only operation a terminal-success
	// frame may report.
	LocalRehearsalOperationKind = "sealed-local-service-self-check"

	localRehearsalStateReady    = "ready"
	localRehearsalStateStart    = "start"
	localRehearsalStateTerminal = "terminal-success"
)

// localRehearsalRoles is the fixed role set and order of the four-node
// topology. It mirrors e5RequiredRoles in the soak controller.
var localRehearsalRoles = [4]string{
	"control", "entry-primary", "entry-secondary", "exit",
}

var localRehearsalServicePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// LocalRehearsalNodeContract binds one rehearsal node to the run, the E5
// plan, the E6 and E7 receipts, and the rehearsal grant collection. Field
// order is the canonical encoding order and must not be reordered: the
// object digest is computed over the encoding/json representation of this
// struct, so declaration order is protocol state.
type LocalRehearsalNodeContract struct {
	RunID                 string `json:"run_id"`
	CycleID               string `json:"cycle_id"`
	AttemptID             string `json:"attempt_id"`
	TopologyID            string `json:"topology_id"`
	PlanSHA256            string `json:"plan_sha256"`
	PlanObjectDigest      string `json:"plan_object_digest"`
	E6ReceiptSHA256       string `json:"e6_receipt_sha256"`
	E6ReceiptObjectDigest string `json:"e6_receipt_object_digest"`
	E7ReceiptSHA256       string `json:"e7_receipt_sha256"`
	E7ReceiptObjectDigest string `json:"e7_receipt_object_digest"`
	RehearsalGrantDigest  string `json:"rehearsal_grant_digest"`
	WorkerSHA256          string `json:"worker_sha256"`
	Role                  string `json:"role"`
	NodeID                string `json:"node_id"`
	ServiceID             string `json:"service_id"`
	RehearsalNonce        string `json:"rehearsal_nonce"`
	ObjectDigest          string `json:"object_digest"`
}

// LocalRehearsalNodeFrame is one observed lifecycle frame for a node. The
// ready, start, and terminal-success frames of a node all carry the same
// contract digest, role, node identifier, process identity, and, from the
// start frame onward, the same start token.
type LocalRehearsalNodeFrame struct {
	ContractDigest  string `json:"contract_digest"`
	Role            string `json:"role"`
	NodeID          string `json:"node_id"`
	State           string `json:"state"`
	ProcessID       uint64 `json:"process_id"`
	ProcessStart    uint64 `json:"process_start"`
	StartToken      string `json:"start_token"`
	OperationKind   string `json:"operation_kind"`
	OperationInput  string `json:"operation_input"`
	OperationOutput string `json:"operation_output"`
	OperationDigest string `json:"operation_digest"`
}

// LocalRehearsalContractObjectDigest returns the canonical object digest of a
// node contract. The digest is taken over the contract with ObjectDigest
// cleared, so a contract can carry its own digest without self reference.
func LocalRehearsalContractObjectDigest(
	contract LocalRehearsalNodeContract,
) (string, error) {
	contract.ObjectDigest = ""
	return digestObject(localRehearsalContractDomain, contract)
}

func localRehearsalRoleAdmitted(role string) bool {
	for _, candidate := range localRehearsalRoles {
		if role == candidate {
			return true
		}
	}
	return false
}

func localRehearsalBoundedID(value string) bool {
	return value != "" && len(value) <= MaxStringBytes
}

// ValidateLocalRehearsalContract returns nil only when every contract
// invariant holds: bounded non-empty identifiers, an admitted role, well
// formed digests and hashes, a well formed single-use nonce, a printable
// service identifier, and a self digest that re-derives exactly.
func ValidateLocalRehearsalContract(
	contract LocalRehearsalNodeContract,
) error {
	if !localRehearsalBoundedID(contract.RunID) ||
		!localRehearsalBoundedID(contract.CycleID) ||
		!localRehearsalBoundedID(contract.AttemptID) ||
		!localRehearsalBoundedID(contract.TopologyID) {
		return errors.New(
			"ValidateLocalRehearsalContract: run, cycle, attempt, and " +
				"topology identifiers must be non-empty",
		)
	}
	if !localRehearsalBoundedID(contract.NodeID) {
		return errors.New(
			"ValidateLocalRehearsalContract: node_id must be non-empty",
		)
	}
	if contract.ServiceID == "" {
		return errors.New(
			"ValidateLocalRehearsalContract: service_id must be non-empty",
		)
	}
	if !localRehearsalBoundedID(contract.ServiceID) ||
		!localRehearsalServicePattern.MatchString(contract.ServiceID) {
		return errors.New(
			"ValidateLocalRehearsalContract: service_id is malformed",
		)
	}
	if !localRehearsalRoleAdmitted(contract.Role) {
		return errors.New(
			"ValidateLocalRehearsalContract: role is not admitted",
		)
	}
	for _, digest := range []string{
		contract.PlanSHA256, contract.PlanObjectDigest,
		contract.E6ReceiptSHA256, contract.E6ReceiptObjectDigest,
		contract.E7ReceiptSHA256, contract.E7ReceiptObjectDigest,
		contract.RehearsalGrantDigest, contract.WorkerSHA256,
		contract.ObjectDigest,
	} {
		if !validDigest(digest) {
			return errors.New(
				"ValidateLocalRehearsalContract: digest field is malformed",
			)
		}
	}
	if !validNonce(contract.RehearsalNonce) {
		return errors.New(
			"ValidateLocalRehearsalContract: rehearsal_nonce is malformed",
		)
	}
	expected, err := LocalRehearsalContractObjectDigest(contract)
	if err != nil {
		return errors.New(
			"ValidateLocalRehearsalContract: object_digest is not derivable",
		)
	}
	if expected != contract.ObjectDigest {
		return errors.New(
			"ValidateLocalRehearsalContract: object_digest mismatch",
		)
	}
	return nil
}

// ValidateLocalRehearsalFrame returns nil only when every frame invariant
// holds. Operation evidence is admitted only on a terminal-success frame; a
// ready or start frame that carries any operation field is rejected, which
// prevents premature operation evidence injection.
func ValidateLocalRehearsalFrame(frame LocalRehearsalNodeFrame) error {
	if !validDigest(frame.ContractDigest) {
		return errors.New(
			"ValidateLocalRehearsalFrame: contract_digest is malformed",
		)
	}
	if !localRehearsalRoleAdmitted(frame.Role) {
		return errors.New(
			"ValidateLocalRehearsalFrame: role is not admitted",
		)
	}
	if !localRehearsalBoundedID(frame.NodeID) {
		return errors.New(
			"ValidateLocalRehearsalFrame: node_id must be non-empty",
		)
	}
	switch frame.State {
	case localRehearsalStateReady, localRehearsalStateStart,
		localRehearsalStateTerminal:
	default:
		return errors.New("ValidateLocalRehearsalFrame: state is not admitted")
	}
	if frame.ProcessID == 0 || frame.ProcessStart == 0 {
		return errors.New(
			"ValidateLocalRehearsalFrame: process identity must be non-zero",
		)
	}
	if frame.State == localRehearsalStateReady {
		if frame.StartToken != "" {
			return errors.New(
				"ValidateLocalRehearsalFrame: ready frame must not carry a " +
					"start_token",
			)
		}
	} else if !localRehearsalBoundedID(frame.StartToken) {
		return errors.New(
			"ValidateLocalRehearsalFrame: start_token must be non-empty",
		)
	}
	if frame.State == localRehearsalStateTerminal {
		if frame.OperationKind != LocalRehearsalOperationKind {
			return errors.New(
				"ValidateLocalRehearsalFrame: operation_kind is not admitted",
			)
		}
		if !validDigest(frame.OperationInput) ||
			!validDigest(frame.OperationOutput) ||
			!validDigest(frame.OperationDigest) {
			return errors.New(
				"ValidateLocalRehearsalFrame: operation evidence is malformed",
			)
		}
		return nil
	}
	if frame.OperationKind != "" || frame.OperationInput != "" ||
		frame.OperationOutput != "" || frame.OperationDigest != "" {
		return errors.New(
			"ValidateLocalRehearsalFrame: operation evidence is not admitted " +
				"before terminal-success",
		)
	}
	return nil
}

// LocalRehearsalOperationEvidence derives the expected operation evidence for
// one node. The input evidence binds the contract digest to the start token,
// the output evidence binds the contract digest to the observed process
// identity, and the operation digest chains the two. Each derivation is
// domain separated.
//
// The caller compares the three evidence values against the terminal frame
// and propagates the fourth return value. This is the exact frozen contract
// arity; derivation errors are never collapsed into an implicit empty tuple.
func LocalRehearsalOperationEvidence(
	contract LocalRehearsalNodeContract,
	startToken string,
	processID, processStart uint64,
) (
	expectedInput, expectedOutput, expectedOperation string,
	err error,
) {
	evidenceInput, err := digestObject(
		localRehearsalOperationInputDomain,
		map[string]any{
			"contract_digest": contract.ObjectDigest,
			"start_token":     startToken,
		},
	)
	if err != nil {
		return "", "", "", err
	}
	evidenceOutput, err := digestObject(
		localRehearsalOperationOutputDomain,
		map[string]any{
			"contract_digest": contract.ObjectDigest,
			"process_id":      processID,
			"process_start":   processStart,
		},
	)
	if err != nil {
		return "", "", "", err
	}
	evidenceOperation, err := digestObject(
		localRehearsalOperationDomain,
		map[string]any{
			"operation_input":  evidenceInput,
			"operation_output": evidenceOutput,
		},
	)
	if err != nil {
		return "", "", "", err
	}
	return evidenceInput, evidenceOutput, evidenceOperation, nil
}
