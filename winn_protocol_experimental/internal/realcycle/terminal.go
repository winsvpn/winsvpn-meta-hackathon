package realcycle

import (
	"errors"
	"fmt"
	"slices"
)

const (
	terminalSignatureDomain    = "winn-real-terminal-receipt-signature/v1"
	terminalObjectDomain       = "winn-real-terminal-receipt-object/v1"
	terminalCollectionDomain   = "winn-real-terminal-receipt-collection/v1"
	terminalSetSignatureDomain = "winn-real-terminal-receipt-set-signature/v1"
)

type TerminalReceipt struct {
	Schema                   string `json:"schema"`
	CycleBindingDigest       string `json:"cycle_binding_digest"`
	RuntimeCollectionDigest  string `json:"runtime_collection_digest"`
	RuntimeAttestationDigest string `json:"runtime_attestation_digest"`
	LeaseObjectDigest        string `json:"lease_object_digest"`
	AttemptID                string `json:"attempt_id"`
	Transport                string `json:"transport"`
	NodeID                   string `json:"node_id"`
	ServiceID                string `json:"service_id"`
	BootID                   string `json:"boot_id"`
	ProcessID                uint64 `json:"process_id"`
	ProcessStartTicks        uint64 `json:"process_start_ticks"`
	CorrelationID            string `json:"correlation_id"`
	Outcome                  string `json:"outcome"`
	Reason                   string `json:"reason"`
	Authenticated            uint64 `json:"authenticated"`
	Redeemed                 uint64 `json:"redeemed"`
	AuthOnly                 uint64 `json:"auth_only"`
	Opened                   uint64 `json:"opened"`
	Closed                   uint64 `json:"closed"`
	Aborted                  uint64 `json:"aborted"`
	ObservedAt               string `json:"observed_at"`
	CounterDomain            string `json:"counter_domain"`
	ObservedCounter          uint64 `json:"observed_counter"`
	KeyID                    string `json:"key_id"`
	Signature                string `json:"signature"`
}

type TerminalSet struct {
	Schema             string            `json:"schema"`
	CycleBindingDigest string            `json:"cycle_binding_digest"`
	Receipts           []TerminalReceipt `json:"receipts"`
	CollectionDigest   string            `json:"collection_digest"`
	ControllerKeyID    string            `json:"controller_key_id"`
	Signature          string            `json:"signature"`
}

type terminalUnsigned struct {
	Schema                   string `json:"schema"`
	CycleBindingDigest       string `json:"cycle_binding_digest"`
	RuntimeCollectionDigest  string `json:"runtime_collection_digest"`
	RuntimeAttestationDigest string `json:"runtime_attestation_digest"`
	LeaseObjectDigest        string `json:"lease_object_digest"`
	AttemptID                string `json:"attempt_id"`
	Transport                string `json:"transport"`
	NodeID                   string `json:"node_id"`
	ServiceID                string `json:"service_id"`
	BootID                   string `json:"boot_id"`
	ProcessID                uint64 `json:"process_id"`
	ProcessStartTicks        uint64 `json:"process_start_ticks"`
	CorrelationID            string `json:"correlation_id"`
	Outcome                  string `json:"outcome"`
	Reason                   string `json:"reason"`
	Authenticated            uint64 `json:"authenticated"`
	Redeemed                 uint64 `json:"redeemed"`
	AuthOnly                 uint64 `json:"auth_only"`
	Opened                   uint64 `json:"opened"`
	Closed                   uint64 `json:"closed"`
	Aborted                  uint64 `json:"aborted"`
	ObservedAt               string `json:"observed_at"`
	CounterDomain            string `json:"counter_domain"`
	ObservedCounter          uint64 `json:"observed_counter"`
	KeyID                    string `json:"key_id"`
}

type terminalSetUnsigned struct {
	Schema             string            `json:"schema"`
	CycleBindingDigest string            `json:"cycle_binding_digest"`
	Receipts           []TerminalReceipt `json:"receipts"`
	CollectionDigest   string            `json:"collection_digest"`
	ControllerKeyID    string            `json:"controller_key_id"`
}

func terminalUnsignedOf(row TerminalReceipt) terminalUnsigned {
	return terminalUnsigned{
		Schema:                   row.Schema,
		CycleBindingDigest:       row.CycleBindingDigest,
		RuntimeCollectionDigest:  row.RuntimeCollectionDigest,
		RuntimeAttestationDigest: row.RuntimeAttestationDigest,
		LeaseObjectDigest:        row.LeaseObjectDigest, AttemptID: row.AttemptID,
		Transport: row.Transport, NodeID: row.NodeID,
		ServiceID: row.ServiceID, BootID: row.BootID,
		ProcessID: row.ProcessID, ProcessStartTicks: row.ProcessStartTicks,
		CorrelationID: row.CorrelationID, Outcome: row.Outcome,
		Reason: row.Reason, Authenticated: row.Authenticated,
		Redeemed: row.Redeemed, AuthOnly: row.AuthOnly,
		Opened: row.Opened, Closed: row.Closed, Aborted: row.Aborted,
		ObservedAt: row.ObservedAt, CounterDomain: row.CounterDomain,
		ObservedCounter: row.ObservedCounter,
		KeyID:           row.KeyID,
	}
}

func validateTerminal(
	set TerminalSet,
	cycle Cycle,
	runtime RuntimeSet,
	runtimeResult runtimeValidation,
	leaseResult leaseValidation,
	keys trustIndex,
	acceptedAt, trustExpiry int64,
) error {
	if set.Schema != TerminalSetSchema ||
		set.CycleBindingDigest != cycle.BindingDigest ||
		len(set.Receipts) != len(cycle.ExercisedNodes) ||
		!validDigest(set.CollectionDigest) {
		return errors.New("terminal receipt set fields are invalid")
	}
	rowDigests := make([]string, len(set.Receipts))
	previousCounter := leaseResult.committedCounter
	previousAt := leaseResult.committedAt
	successes := 0
	for index, row := range set.Receipts {
		if row.NodeID != cycle.ExercisedNodes[index] {
			return errors.New(
				"terminal nodes do not equal ordered exercised_nodes",
			)
		}
		if row.Schema != TerminalSchema ||
			row.CycleBindingDigest != cycle.BindingDigest ||
			row.RuntimeCollectionDigest != runtime.CollectionDigest ||
			row.LeaseObjectDigest != leaseResult.commitDigest ||
			row.AttemptID != cycle.AttemptID ||
			row.Transport != cycle.ExpectedTransport ||
			!validNonce(row.CorrelationID) ||
			!slices.Contains([]string{"success", "aborted"}, row.Outcome) ||
			!validID(row.Reason) ||
			row.ProcessID == 0 || row.ProcessStartTicks == 0 ||
			row.CounterDomain != cycle.CounterDomain ||
			row.ObservedCounter <= previousCounter ||
			row.ObservedCounter >= leaseResult.terminalCounter {
			return errors.New("terminal receipt fields are invalid")
		}
		runtimeEvidence, ok := runtimeResult.byNode[row.NodeID]
		if !ok || row.RuntimeAttestationDigest != runtimeEvidence.digest {
			return errors.New("terminal receipt runtime binding is invalid")
		}
		runtimeRow := runtimeEvidence.row
		if row.ServiceID != runtimeRow.ServiceID ||
			row.BootID != runtimeRow.BootID ||
			row.ProcessID != runtimeRow.ProcessID ||
			row.ProcessStartTicks != runtimeRow.ProcessStartTicks {
			return errors.New("terminal receipt process identity mismatch")
		}
		observedAt, err := parseTime(row.ObservedAt)
		if err != nil || observedAt.UnixNano() <= previousAt ||
			observedAt.UnixNano() < acceptedAt ||
			observedAt.UnixNano() >= trustExpiry ||
			observedAt.UnixNano() >= leaseResult.terminalAt ||
			observedAt.UnixNano() >= leaseResult.expiresAt {
			return errors.New(
				"terminal receipt chronology is invalid",
			)
		}
		if row.Transport == TransportH3 {
			if row.Authenticated != row.Redeemed ||
				row.Authenticated != row.AuthOnly+row.Opened+row.Aborted ||
				row.Opened != row.Closed ||
				leaseResult.consumedByNode[row.NodeID] != row.Redeemed {
				return errors.New("H3 terminal conservation failed")
			}
			if row.Outcome == "success" &&
				(row.Authenticated != 1 || row.Opened != 1 ||
					row.Closed != 1 || row.Aborted != 0 ||
					row.Reason != "none") {
				return errors.New("H3 success terminal is inconsistent")
			}
			if row.Outcome == "aborted" &&
				(row.Authenticated != 1 || row.Aborted != 1 ||
					row.Opened != 0 || row.Closed != 0 ||
					row.Reason == "none") {
				return errors.New("H3 abort terminal is inconsistent")
			}
		} else {
			if row.Authenticated != 0 || row.Redeemed != 0 ||
				row.AuthOnly != 0 {
				//lint:ignore ST1005 Direct AWG is a proper product term.
				return errors.New("Direct AWG receipt contains H3 counts")
			}
			if row.Outcome == "success" &&
				(row.Opened != 1 || row.Closed != 1 ||
					row.Aborted != 0 || row.Reason != "none") {
				//lint:ignore ST1005 Direct AWG is a proper product term.
				return errors.New(
					"Direct AWG success terminal is inconsistent",
				)
			}
			if row.Outcome == "aborted" &&
				(row.Opened != 0 || row.Closed != 0 ||
					row.Aborted != 1 || row.Reason == "none") {
				//lint:ignore ST1005 Direct AWG is a proper product term.
				return errors.New(
					"Direct AWG abort terminal is inconsistent",
				)
			}
		}
		if row.Outcome == "success" {
			successes++
		}
		if err := verifySignature(
			keys, row.KeyID, KeyRoleTerminal, row.NodeID,
			terminalSignatureDomain, row.Signature, terminalUnsignedOf(row),
		); err != nil {
			return fmt.Errorf("terminal receipt %d: %w", index, err)
		}
		rowDigests[index], err = digestObject(terminalObjectDomain, row)
		if err != nil {
			return err
		}
		previousCounter = row.ObservedCounter
		previousAt = observedAt.UnixNano()
	}
	expectedDisposition := "burned"
	if successes > 0 {
		expectedDisposition = "consumed"
	}
	if leaseResult.disposition != expectedDisposition {
		return errors.New(
			"lease disposition and terminal outcomes are incoherent",
		)
	}
	expectedCollection, err := digestObject(
		terminalCollectionDomain, rowDigests,
	)
	if err != nil || expectedCollection != set.CollectionDigest {
		return errors.New("terminal collection digest mismatch")
	}
	unsignedSet := terminalSetUnsigned{
		Schema: set.Schema, CycleBindingDigest: set.CycleBindingDigest,
		Receipts:         slices.Clone(set.Receipts),
		CollectionDigest: set.CollectionDigest,
		ControllerKeyID:  set.ControllerKeyID,
	}
	if err := verifySignature(
		keys, set.ControllerKeyID, KeyRoleController, "",
		terminalSetSignatureDomain, set.Signature, unsignedSet,
	); err != nil {
		return fmt.Errorf("terminal receipt set: %w", err)
	}
	return nil
}
