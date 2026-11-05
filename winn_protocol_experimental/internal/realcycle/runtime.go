package realcycle

import (
	"errors"
	"fmt"
	"slices"
)

const (
	runtimeObjectDomain       = "winn-real-runtime-attestation-object/v1"
	runtimeSignatureDomain    = "winn-real-runtime-attestation-signature/v1"
	runtimeCollectionDomain   = "winn-real-runtime-attestation-collection/v1"
	runtimeSetSignatureDomain = "winn-real-runtime-attestation-set-signature/v1"
)

type RuntimeAttestation struct {
	Schema             string `json:"schema"`
	CycleBindingDigest string `json:"cycle_binding_digest"`
	Role               string `json:"role"`
	InstanceUUID       string `json:"instance_uuid"`
	NodeID             string `json:"node_id"`
	ServiceID          string `json:"service_id"`
	Provider           string `json:"provider"`
	OperatorID         string `json:"operator_id"`
	BootID             string `json:"boot_id"`
	ProcessID          uint64 `json:"process_id"`
	ProcessStartTicks  uint64 `json:"process_start_ticks"`
	ExecutableSHA256   string `json:"executable_sha256"`
	ConfigSHA256       string `json:"config_sha256"`
	CertificateSHA256  string `json:"certificate_sha256"`
	Endpoint           string `json:"endpoint"`
	Status             string `json:"status"`
	ObservedAt         string `json:"observed_at"`
	CounterDomain      string `json:"counter_domain"`
	ObservedCounter    uint64 `json:"observed_counter"`
	KeyID              string `json:"key_id"`
	Signature          string `json:"signature"`
}

type RuntimeSet struct {
	Schema             string               `json:"schema"`
	CycleBindingDigest string               `json:"cycle_binding_digest"`
	Attestations       []RuntimeAttestation `json:"attestations"`
	CollectionDigest   string               `json:"collection_digest"`
	ControllerKeyID    string               `json:"controller_key_id"`
	Signature          string               `json:"signature"`
}

type runtimeUnsigned struct {
	Schema             string `json:"schema"`
	CycleBindingDigest string `json:"cycle_binding_digest"`
	Role               string `json:"role"`
	InstanceUUID       string `json:"instance_uuid"`
	NodeID             string `json:"node_id"`
	ServiceID          string `json:"service_id"`
	Provider           string `json:"provider"`
	OperatorID         string `json:"operator_id"`
	BootID             string `json:"boot_id"`
	ProcessID          uint64 `json:"process_id"`
	ProcessStartTicks  uint64 `json:"process_start_ticks"`
	ExecutableSHA256   string `json:"executable_sha256"`
	ConfigSHA256       string `json:"config_sha256"`
	CertificateSHA256  string `json:"certificate_sha256"`
	Endpoint           string `json:"endpoint"`
	Status             string `json:"status"`
	ObservedAt         string `json:"observed_at"`
	CounterDomain      string `json:"counter_domain"`
	ObservedCounter    uint64 `json:"observed_counter"`
	KeyID              string `json:"key_id"`
}

type runtimeSetUnsigned struct {
	Schema             string               `json:"schema"`
	CycleBindingDigest string               `json:"cycle_binding_digest"`
	Attestations       []RuntimeAttestation `json:"attestations"`
	CollectionDigest   string               `json:"collection_digest"`
	ControllerKeyID    string               `json:"controller_key_id"`
}

type runtimeNodeEvidence struct {
	digest string
	row    RuntimeAttestation
}

type runtimeValidation struct {
	byNode        map[string]runtimeNodeEvidence
	latestAt      int64
	latestCounter uint64
}

// RuntimeAttestationObjectDigest exposes the exact digest that admission
// validation computed so downstream nonauthorizing projections can replay it
// without redefining the private domain or canonical encoding.
func RuntimeAttestationObjectDigest(row RuntimeAttestation) (string, error) {
	return digestObject(runtimeObjectDomain, row)
}

func runtimeUnsignedOf(row RuntimeAttestation) runtimeUnsigned {
	return runtimeUnsigned{
		Schema: row.Schema, CycleBindingDigest: row.CycleBindingDigest,
		Role: row.Role, InstanceUUID: row.InstanceUUID, NodeID: row.NodeID,
		ServiceID: row.ServiceID, Provider: row.Provider,
		OperatorID: row.OperatorID, BootID: row.BootID,
		ProcessID: row.ProcessID, ProcessStartTicks: row.ProcessStartTicks,
		ExecutableSHA256:  row.ExecutableSHA256,
		ConfigSHA256:      row.ConfigSHA256,
		CertificateSHA256: row.CertificateSHA256, Endpoint: row.Endpoint,
		Status: row.Status, ObservedAt: row.ObservedAt,
		CounterDomain:   row.CounterDomain,
		ObservedCounter: row.ObservedCounter, KeyID: row.KeyID,
	}
}

func validateRuntime(
	set RuntimeSet,
	cycle Cycle,
	keys trustIndex,
	acceptedAt, trustExpiry int64,
) (runtimeValidation, error) {
	if set.Schema != RuntimeSetSchema ||
		set.CycleBindingDigest != cycle.BindingDigest ||
		len(set.Attestations) != len(requiredRoles) ||
		!validDigest(set.CollectionDigest) {
		return runtimeValidation{}, errors.New("runtime set fields are invalid")
	}
	attestationDigests := make([]string, 0, len(set.Attestations))
	result := runtimeValidation{
		byNode: make(
			map[string]runtimeNodeEvidence, len(set.Attestations),
		),
	}
	for index, row := range set.Attestations {
		expected := cycle.Deployments[index]
		if row.Schema != RuntimeSchema ||
			row.CycleBindingDigest != cycle.BindingDigest ||
			row.Role != expected.Role ||
			row.InstanceUUID != expected.InstanceUUID ||
			row.NodeID != expected.NodeID ||
			row.ServiceID != expected.ServiceID ||
			row.Provider != expected.Provider ||
			row.OperatorID != expected.OperatorID ||
			!uuidPattern.MatchString(row.BootID) ||
			row.ProcessID == 0 || row.ProcessStartTicks == 0 ||
			!validDigest(row.ExecutableSHA256) ||
			!validDigest(row.ConfigSHA256) ||
			!validDigest(row.CertificateSHA256) ||
			!validEndpoint(row.Endpoint) || row.Status != "running" ||
			row.CounterDomain != cycle.CounterDomain ||
			row.ObservedCounter <= cycle.AcceptedCounter {
			return runtimeValidation{}, fmt.Errorf(
				"runtime attestation %d fields or E0 binding are invalid",
				index,
			)
		}
		observedAt, err := parseTime(row.ObservedAt)
		if err != nil ||
			observedAt.UnixNano() < acceptedAt ||
			observedAt.UnixNano() >= trustExpiry {
			return runtimeValidation{}, fmt.Errorf(
				"runtime attestation %d time is outside accepted trust",
				index,
			)
		}
		unsigned := runtimeUnsignedOf(row)
		if err := verifySignature(
			keys, row.KeyID, KeyRoleRuntime, row.NodeID,
			runtimeSignatureDomain, row.Signature, unsigned,
		); err != nil {
			return runtimeValidation{}, fmt.Errorf(
				"runtime attestation %d: %w", index, err,
			)
		}
		digest, err := digestObject(runtimeObjectDomain, row)
		if err != nil {
			return runtimeValidation{}, err
		}
		if _, exists := result.byNode[row.NodeID]; exists {
			return runtimeValidation{}, errors.New("duplicate runtime node")
		}
		result.byNode[row.NodeID] = runtimeNodeEvidence{
			digest: digest, row: row,
		}
		result.latestAt = max(result.latestAt, observedAt.UnixNano())
		result.latestCounter = max(
			result.latestCounter, row.ObservedCounter,
		)
		attestationDigests = append(attestationDigests, digest)
	}
	expectedCollection, err := digestObject(
		runtimeCollectionDomain, attestationDigests,
	)
	if err != nil || expectedCollection != set.CollectionDigest {
		return runtimeValidation{}, errors.New(
			"runtime collection digest mismatch",
		)
	}
	unsignedSet := runtimeSetUnsigned{
		Schema: set.Schema, CycleBindingDigest: set.CycleBindingDigest,
		Attestations:     slices.Clone(set.Attestations),
		CollectionDigest: set.CollectionDigest,
		ControllerKeyID:  set.ControllerKeyID,
	}
	if err := verifySignature(
		keys, set.ControllerKeyID, KeyRoleController, "",
		runtimeSetSignatureDomain, set.Signature, unsignedSet,
	); err != nil {
		return runtimeValidation{}, fmt.Errorf("runtime set: %w", err)
	}
	return result, nil
}
