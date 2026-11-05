package realcycle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	ControllerCycleIntentSchema = "winn-real-controller-cycle-intent/v1"

	controllerCycleIntentCoreDomain = "winn-real-controller-cycle-intent-entry/v1"
)

// ControllerCycleIntent is the immutable write-ahead entry that must be made
// durable before an admitted adapter may be spawned. "pending" is intentionally
// the only state: terminal facts belong in a later receipt, never this object.
type ControllerCycleIntent struct {
	Schema                  string `json:"schema"`
	CycleID                 string `json:"cycle_id"`
	AttemptID               string `json:"attempt_id"`
	SoakRunID               string `json:"soak_run_id"`
	Sequence                uint64 `json:"sequence"`
	InstanceNonce           string `json:"instance_nonce"`
	ControllerBindingDigest string `json:"controller_binding_digest"`
	ControllerBindingSHA256 string `json:"controller_binding_sha256"`
	AdmissionBundleSHA256   string `json:"admission_bundle_sha256"`
	State                   string `json:"state"`
	DispatchAuthorized      bool   `json:"dispatch_authorized"`
	Mutation                string `json:"mutation"`
	ObjectDigest            string `json:"object_digest"`
}

type controllerCycleIntentCore struct {
	Schema                  string `json:"schema"`
	CycleID                 string `json:"cycle_id"`
	AttemptID               string `json:"attempt_id"`
	SoakRunID               string `json:"soak_run_id"`
	Sequence                uint64 `json:"sequence"`
	InstanceNonce           string `json:"instance_nonce"`
	ControllerBindingDigest string `json:"controller_binding_digest"`
	ControllerBindingSHA256 string `json:"controller_binding_sha256"`
	AdmissionBundleSHA256   string `json:"admission_bundle_sha256"`
	State                   string `json:"state"`
	DispatchAuthorized      bool   `json:"dispatch_authorized"`
	Mutation                string `json:"mutation"`
}

func controllerCycleIntentCoreOf(
	value ControllerCycleIntent,
) controllerCycleIntentCore {
	return controllerCycleIntentCore{
		Schema:                  value.Schema,
		CycleID:                 value.CycleID,
		AttemptID:               value.AttemptID,
		SoakRunID:               value.SoakRunID,
		Sequence:                value.Sequence,
		InstanceNonce:           value.InstanceNonce,
		ControllerBindingDigest: value.ControllerBindingDigest,
		ControllerBindingSHA256: value.ControllerBindingSHA256,
		AdmissionBundleSHA256:   value.AdmissionBundleSHA256,
		State:                   value.State,
		DispatchAuthorized:      value.DispatchAuthorized,
		Mutation:                value.Mutation,
	}
}

// NewControllerCycleIntent derives a pending write-ahead entry from exact
// canonical binding bytes.
func NewControllerCycleIntent(
	bindingBytes []byte,
) (ControllerCycleIntent, []byte, error) {
	binding, err := ParseControllerCycleBinding(bindingBytes)
	if err != nil {
		return ControllerCycleIntent{}, nil, err
	}
	bindingSHA := sha256.Sum256(bindingBytes)
	value := ControllerCycleIntent{
		Schema:                  ControllerCycleIntentSchema,
		CycleID:                 binding.CycleID,
		AttemptID:               binding.AttemptID,
		SoakRunID:               binding.SoakRunID,
		Sequence:                binding.Sequence,
		InstanceNonce:           binding.InstanceNonce,
		ControllerBindingDigest: binding.ObjectDigest,
		ControllerBindingSHA256: hex.EncodeToString(bindingSHA[:]),
		AdmissionBundleSHA256:   binding.AdmissionBundleSHA256,
		State:                   "pending",
		DispatchAuthorized:      false,
		Mutation:                "none",
	}
	digest, err := digestObject(
		controllerCycleIntentCoreDomain,
		controllerCycleIntentCoreOf(value),
	)
	if err != nil {
		return ControllerCycleIntent{}, nil, err
	}
	value.ObjectDigest = digest
	encoded, err := marshalCanonical(value)
	if err != nil {
		return ControllerCycleIntent{}, nil, err
	}
	return value, encoded, nil
}

// ParseControllerCycleIntent strictly replays a pending intent. Callers must
// treat a durable intent without a matching terminal receipt as ambiguous and
// must not retry it.
func ParseControllerCycleIntent(data []byte) (ControllerCycleIntent, error) {
	var value ControllerCycleIntent
	if len(data) == 0 || len(data) > MaxTrustFileBytes {
		return ControllerCycleIntent{}, errors.New(
			"controller cycle intent size is invalid",
		)
	}
	if err := decodeCanonical(data, &value); err != nil {
		return ControllerCycleIntent{}, fmt.Errorf(
			"decode controller cycle intent: %w", err,
		)
	}
	if value.Schema != ControllerCycleIntentSchema ||
		!validID(value.CycleID) || !validID(value.AttemptID) ||
		!validID(value.SoakRunID) || value.Sequence == 0 ||
		!validNonce(value.InstanceNonce) ||
		!validDigest(value.ControllerBindingDigest) ||
		!validDigest(value.ControllerBindingSHA256) ||
		!validDigest(value.AdmissionBundleSHA256) ||
		value.State != "pending" || value.DispatchAuthorized ||
		value.Mutation != "none" {
		return ControllerCycleIntent{}, errors.New(
			"controller cycle intent fields are invalid",
		)
	}
	expected, err := digestObject(
		controllerCycleIntentCoreDomain,
		controllerCycleIntentCoreOf(value),
	)
	if err != nil {
		return ControllerCycleIntent{}, err
	}
	if value.ObjectDigest != expected {
		return ControllerCycleIntent{}, errors.New(
			"controller cycle intent object digest mismatch",
		)
	}
	return value, nil
}
