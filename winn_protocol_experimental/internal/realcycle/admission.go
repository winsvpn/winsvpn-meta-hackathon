package realcycle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
)

const (
	AdmissionIntentSchema = "winn-real-cycle-admission-intent/v1"
	// #nosec G101 -- this is a public JSON schema identifier, not a credential.
	CredentialReservationSchema = "winn-real-credential-reservation/v1"
	ReadinessEnvelopeSchema     = "winn-real-cycle-readiness-envelope/v1"

	AdmissionIntentFile = "intent.json"
	ReservationFile     = "credential-reservation.json"
	ReadinessFile       = "readiness-envelope.json"

	admissionBindingDomain         = "winn-real-cycle-admission-binding/v1"
	admissionIntentSignatureDomain = "winn-real-cycle-admission-intent-signature/v1"
	reservationCommitmentDomain    = "winn-real-token-reservation-commitment/v1"
	reservationObjectDomain        = "winn-real-credential-reservation-object/v1"
	reservationSignatureDomain     = "winn-real-credential-reservation-signature/v1"
	readinessSignatureDomain       = "winn-real-cycle-readiness-envelope-signature/v1"
	readinessObjectDomain          = "winn-real-cycle-readiness-envelope-object/v1"
	admissionBundleDomain          = "winn-real-cycle-admission-bundle/v1"
)

var admissionFiles = []string{
	ReservationFile,
	AdmissionIntentFile,
	ReadinessFile,
	RuntimeFile,
}

var afterAdmissionRootRetained = func() {}
var beforeAdmissionFinalReplay = func() {}

type AdmissionIntent struct {
	Schema            string              `json:"schema"`
	CycleID           string              `json:"cycle_id"`
	AttemptID         string              `json:"attempt_id"`
	TopologyID        string              `json:"topology_id"`
	DescriptorSHA256  string              `json:"descriptor_sha256"`
	BundleSHA256      string              `json:"bundle_sha256"`
	TrustSHA256       string              `json:"trust_sha256"`
	Nonce             string              `json:"nonce"`
	AcceptedAt        string              `json:"accepted_at"`
	CounterDomain     string              `json:"counter_domain"`
	AcceptedCounter   uint64              `json:"accepted_counter"`
	ExpectedTransport string              `json:"expected_transport"`
	ExercisedNodes    []string            `json:"exercised_nodes"`
	Deployments       []DeploymentBinding `json:"deployments"`
	StartNotBefore    string              `json:"start_not_before"`
	StartDeadline     string              `json:"start_deadline"`
	FinishDeadline    string              `json:"finish_deadline"`
	BindingDigest     string              `json:"binding_digest"`
	ControllerKeyID   string              `json:"controller_key_id"`
	Signature         string              `json:"signature"`
}

type admissionIntentCore struct {
	Schema            string              `json:"schema"`
	CycleID           string              `json:"cycle_id"`
	AttemptID         string              `json:"attempt_id"`
	TopologyID        string              `json:"topology_id"`
	DescriptorSHA256  string              `json:"descriptor_sha256"`
	BundleSHA256      string              `json:"bundle_sha256"`
	TrustSHA256       string              `json:"trust_sha256"`
	Nonce             string              `json:"nonce"`
	AcceptedAt        string              `json:"accepted_at"`
	CounterDomain     string              `json:"counter_domain"`
	AcceptedCounter   uint64              `json:"accepted_counter"`
	ExpectedTransport string              `json:"expected_transport"`
	ExercisedNodes    []string            `json:"exercised_nodes"`
	Deployments       []DeploymentBinding `json:"deployments"`
	StartNotBefore    string              `json:"start_not_before"`
	StartDeadline     string              `json:"start_deadline"`
	FinishDeadline    string              `json:"finish_deadline"`
}

type admissionIntentUnsigned struct {
	admissionIntentCore
	BindingDigest   string `json:"binding_digest"`
	ControllerKeyID string `json:"controller_key_id"`
}

type TokenReservation struct {
	CandidateID      string `json:"candidate_id"`
	NodeID           string `json:"node_id"`
	ServiceID        string `json:"service_id"`
	Transport        string `json:"transport"`
	TokenKeyID       string `json:"token_key_id"`
	Scope            string `json:"scope"`
	IssuerDomain     string `json:"issuer_domain"`
	ReservedCount    uint64 `json:"reserved_count"`
	CommitmentSHA256 string `json:"commitment_sha256"`
}

type CredentialReservation struct {
	Schema                  string             `json:"schema"`
	CycleBindingDigest      string             `json:"cycle_binding_digest"`
	RuntimeCollectionDigest string             `json:"runtime_collection_digest"`
	LeaseID                 string             `json:"lease_id"`
	ReservationID           string             `json:"reservation_id"`
	AttemptID               string             `json:"attempt_id"`
	State                   string             `json:"state"`
	PreparedAt              string             `json:"prepared_at"`
	CounterDomain           string             `json:"counter_domain"`
	PreparedCounter         uint64             `json:"prepared_counter"`
	CommittedAt             string             `json:"committed_at"`
	CommittedCounter        uint64             `json:"committed_counter"`
	ExpiresAt               string             `json:"expires_at"`
	PSKGeneration           uint64             `json:"psk_generation"`
	PSKKeyID                string             `json:"psk_key_id"`
	PeerPublicKey           string             `json:"peer_public_key"`
	VaultRevisionBefore     uint64             `json:"vault_revision_before"`
	VaultRevisionAfter      uint64             `json:"vault_revision_after"`
	TokenClasses            []TokenReservation `json:"token_classes"`
	PublisherKeyID          string             `json:"publisher_key_id"`
	Signature               string             `json:"signature"`
}

type reservationUnsigned struct {
	Schema                  string             `json:"schema"`
	CycleBindingDigest      string             `json:"cycle_binding_digest"`
	RuntimeCollectionDigest string             `json:"runtime_collection_digest"`
	LeaseID                 string             `json:"lease_id"`
	ReservationID           string             `json:"reservation_id"`
	AttemptID               string             `json:"attempt_id"`
	State                   string             `json:"state"`
	PreparedAt              string             `json:"prepared_at"`
	CounterDomain           string             `json:"counter_domain"`
	PreparedCounter         uint64             `json:"prepared_counter"`
	CommittedAt             string             `json:"committed_at"`
	CommittedCounter        uint64             `json:"committed_counter"`
	ExpiresAt               string             `json:"expires_at"`
	PSKGeneration           uint64             `json:"psk_generation"`
	PSKKeyID                string             `json:"psk_key_id"`
	PeerPublicKey           string             `json:"peer_public_key"`
	VaultRevisionBefore     uint64             `json:"vault_revision_before"`
	VaultRevisionAfter      uint64             `json:"vault_revision_after"`
	TokenClasses            []TokenReservation `json:"token_classes"`
	PublisherKeyID          string             `json:"publisher_key_id"`
}

type ReadinessEnvelope struct {
	Schema                  string `json:"schema"`
	CycleBindingDigest      string `json:"cycle_binding_digest"`
	IntentSHA256            string `json:"intent_sha256"`
	RuntimeSHA256           string `json:"runtime_sha256"`
	RuntimeCollectionDigest string `json:"runtime_collection_digest"`
	ReservationSHA256       string `json:"reservation_sha256"`
	ReservationObjectDigest string `json:"reservation_object_digest"`
	AcceptedAt              string `json:"accepted_at"`
	CounterDomain           string `json:"counter_domain"`
	AcceptedCounter         uint64 `json:"accepted_counter"`
	StartNotBefore          string `json:"start_not_before"`
	StartDeadline           string `json:"start_deadline"`
	FinishDeadline          string `json:"finish_deadline"`
	ContractValid           bool   `json:"contract_valid"`
	DispatchAuthorized      bool   `json:"dispatch_authorized"`
	Mutation                string `json:"mutation"`
	ControllerKeyID         string `json:"controller_key_id"`
	Signature               string `json:"signature"`
}

type readinessUnsigned struct {
	Schema                  string `json:"schema"`
	CycleBindingDigest      string `json:"cycle_binding_digest"`
	IntentSHA256            string `json:"intent_sha256"`
	RuntimeSHA256           string `json:"runtime_sha256"`
	RuntimeCollectionDigest string `json:"runtime_collection_digest"`
	ReservationSHA256       string `json:"reservation_sha256"`
	ReservationObjectDigest string `json:"reservation_object_digest"`
	AcceptedAt              string `json:"accepted_at"`
	CounterDomain           string `json:"counter_domain"`
	AcceptedCounter         uint64 `json:"accepted_counter"`
	StartNotBefore          string `json:"start_not_before"`
	StartDeadline           string `json:"start_deadline"`
	FinishDeadline          string `json:"finish_deadline"`
	ContractValid           bool   `json:"contract_valid"`
	DispatchAuthorized      bool   `json:"dispatch_authorized"`
	Mutation                string `json:"mutation"`
	ControllerKeyID         string `json:"controller_key_id"`
}

// AdmissionResult reports only offline structural and cryptographic facts.
// It grants no authority to execute, access credentials, or contact providers.
type AdmissionResult struct {
	CycleID                 string
	AttemptID               string
	TopologyID              string
	BindingDigest           string
	Nonce                   string
	CounterDomain           string
	AcceptedCounter         uint64
	LastObservedCounter     uint64
	ExpectedTransport       string
	AdmissionBundleSHA256   string
	TrustSHA256             string
	RuntimeCollectionDigest string
	ReservationObjectDigest string
	RuntimeCount            int
	ReservedTokenCount      int
	StartNotBefore          string
	StartDeadline           string
	FinishDeadline          string
	ExercisedNodeCount      int
	ExercisedNodes          [4]string
	Deployments             [4]DeploymentBinding
	RuntimeAttestations     [4]RuntimeAttestation
	RuntimeObjectDigests    [4]string
}

func admissionIntentCoreOf(value AdmissionIntent) admissionIntentCore {
	return admissionIntentCore{
		Schema: value.Schema, CycleID: value.CycleID,
		AttemptID: value.AttemptID, TopologyID: value.TopologyID,
		DescriptorSHA256: value.DescriptorSHA256,
		BundleSHA256:     value.BundleSHA256, TrustSHA256: value.TrustSHA256,
		Nonce: value.Nonce, AcceptedAt: value.AcceptedAt,
		CounterDomain:     value.CounterDomain,
		AcceptedCounter:   value.AcceptedCounter,
		ExpectedTransport: value.ExpectedTransport,
		ExercisedNodes:    slices.Clone(value.ExercisedNodes),
		Deployments:       slices.Clone(value.Deployments),
		StartNotBefore:    value.StartNotBefore,
		StartDeadline:     value.StartDeadline,
		FinishDeadline:    value.FinishDeadline,
	}
}

func admissionIntentUnsignedOf(value AdmissionIntent) admissionIntentUnsigned {
	return admissionIntentUnsigned{
		admissionIntentCore: admissionIntentCoreOf(value),
		BindingDigest:       value.BindingDigest,
		ControllerKeyID:     value.ControllerKeyID,
	}
}

func reservationUnsignedOf(value CredentialReservation) reservationUnsigned {
	return reservationUnsigned{
		Schema: value.Schema, CycleBindingDigest: value.CycleBindingDigest,
		RuntimeCollectionDigest: value.RuntimeCollectionDigest,
		LeaseID:                 value.LeaseID, ReservationID: value.ReservationID,
		AttemptID: value.AttemptID, State: value.State,
		PreparedAt: value.PreparedAt, CounterDomain: value.CounterDomain,
		PreparedCounter: value.PreparedCounter,
		CommittedAt:     value.CommittedAt, CommittedCounter: value.CommittedCounter,
		ExpiresAt: value.ExpiresAt, PSKGeneration: value.PSKGeneration,
		PSKKeyID: value.PSKKeyID, PeerPublicKey: value.PeerPublicKey,
		VaultRevisionBefore: value.VaultRevisionBefore,
		VaultRevisionAfter:  value.VaultRevisionAfter,
		TokenClasses:        slices.Clone(value.TokenClasses),
		PublisherKeyID:      value.PublisherKeyID,
	}
}

func readinessUnsignedOf(value ReadinessEnvelope) readinessUnsigned {
	return readinessUnsigned{
		Schema: value.Schema, CycleBindingDigest: value.CycleBindingDigest,
		IntentSHA256: value.IntentSHA256, RuntimeSHA256: value.RuntimeSHA256,
		RuntimeCollectionDigest: value.RuntimeCollectionDigest,
		ReservationSHA256:       value.ReservationSHA256,
		ReservationObjectDigest: value.ReservationObjectDigest,
		AcceptedAt:              value.AcceptedAt, CounterDomain: value.CounterDomain,
		AcceptedCounter: value.AcceptedCounter,
		StartNotBefore:  value.StartNotBefore,
		StartDeadline:   value.StartDeadline, FinishDeadline: value.FinishDeadline,
		ContractValid:      value.ContractValid,
		DispatchAuthorized: value.DispatchAuthorized, Mutation: value.Mutation,
		ControllerKeyID: value.ControllerKeyID,
	}
}

// ValidateAdmission validates an offline pre-execution admission envelope.
// It retains and replays every input byte and never performs execution,
// networking, credential access, reservation mutation, or filesystem writes.
func ValidateAdmission(
	admissionPath, trustPath, topologyPath string,
) (AdmissionResult, error) {
	if admissionPath == "" || trustPath == "" || topologyPath == "" {
		return AdmissionResult{}, errors.New(
			"admission, trust, and E0 topology paths are required",
		)
	}
	e0, err := loadE0Bundle(topologyPath)
	if err != nil {
		return AdmissionResult{}, err
	}
	defer e0.close()
	trustBytes, trustSnapshot, err := readStandalone(
		trustPath, MaxTrustFileBytes,
	)
	if err != nil {
		return AdmissionResult{}, fmt.Errorf("read trust bundle: %w", err)
	}
	trust, keys, err := parseTrust(trustBytes)
	if err != nil {
		return AdmissionResult{}, err
	}
	trustSHA := fileSHA256(trustBytes)
	root, initial, err := openAdmissionRoot(admissionPath)
	if err != nil {
		return AdmissionResult{}, err
	}
	defer root.Close()
	afterAdmissionRootRetained()

	documents := make(map[string][]byte, len(admissionFiles))
	snapshots := make(map[string]fileSnapshot, len(admissionFiles))
	total := 0
	for _, name := range admissionFiles {
		data, snapshot, readErr := readRootFile(root, name, MaxEvidenceFileBytes)
		if readErr != nil {
			return AdmissionResult{}, fmt.Errorf("read %s: %w", name, readErr)
		}
		total += len(data)
		if total > MaxEvidenceBytes {
			return AdmissionResult{}, errors.New("admission bundle exceeds aggregate limit")
		}
		documents[name], snapshots[name] = data, snapshot
	}
	var intent AdmissionIntent
	var runtime RuntimeSet
	var reservation CredentialReservation
	var readiness ReadinessEnvelope
	if err := decodeCanonical(documents[AdmissionIntentFile], &intent); err != nil {
		return AdmissionResult{}, fmt.Errorf("decode admission intent: %w", err)
	}
	if err := decodeCanonical(documents[RuntimeFile], &runtime); err != nil {
		return AdmissionResult{}, fmt.Errorf("decode runtime: %w", err)
	}
	if err := decodeCanonical(documents[ReservationFile], &reservation); err != nil {
		return AdmissionResult{}, fmt.Errorf("decode reservation: %w", err)
	}
	if err := decodeCanonical(documents[ReadinessFile], &readiness); err != nil {
		return AdmissionResult{}, fmt.Errorf("decode readiness: %w", err)
	}
	fileSHA := make(map[string]string, len(documents))
	for name, data := range documents {
		fileSHA[name] = fileSHA256(data)
	}
	times, err := validateAdmissionIntent(
		intent, trust, trustSHA, keys, e0,
	)
	if err != nil {
		return AdmissionResult{}, err
	}
	cycle := Cycle{
		BindingDigest:   intent.BindingDigest,
		Deployments:     slices.Clone(intent.Deployments),
		CounterDomain:   intent.CounterDomain,
		AcceptedCounter: intent.AcceptedCounter,
	}
	runtimeResult, err := validateRuntime(
		runtime, cycle, keys, times.acceptedAt, times.trustExpiry,
	)
	if err != nil {
		return AdmissionResult{}, err
	}
	if err := validateRuntimeCausality(
		runtime, times.acceptedAt, times.startNotBefore,
	); err != nil {
		return AdmissionResult{}, err
	}
	reservationDigest, reserved, committedAt, err := validateReservation(
		reservation, intent, runtime, runtimeResult, keys,
		times.finishDeadline, times.trustExpiry,
	)
	if err != nil {
		return AdmissionResult{}, err
	}
	if err := validateReadiness(
		readiness, intent, runtime, reservation, fileSHA,
		reservationDigest, committedAt, times, keys,
	); err != nil {
		return AdmissionResult{}, err
	}
	beforeAdmissionFinalReplay()
	if err := recheckEvidenceRoot(admissionPath, root, initial, snapshots); err != nil {
		return AdmissionResult{}, fmt.Errorf("recheck admission bundle: %w", err)
	}
	if err := recheckStandalone(trustPath, trustSnapshot); err != nil {
		return AdmissionResult{}, fmt.Errorf("recheck trust bundle: %w", err)
	}
	if err := e0.recheck(); err != nil {
		return AdmissionResult{}, fmt.Errorf("recheck E0 topology: %w", err)
	}
	rows := make([]string, 0, len(admissionFiles))
	for _, name := range admissionFiles {
		rows = append(rows, name+"\x00"+fileSHA[name])
	}
	bundleDigest, err := digestObject(admissionBundleDomain, rows)
	if err != nil {
		return AdmissionResult{}, err
	}
	var exercisedNodes [4]string
	var deployments [4]DeploymentBinding
	var runtimeAttestations [4]RuntimeAttestation
	var runtimeObjectDigests [4]string
	copy(exercisedNodes[:], intent.ExercisedNodes)
	copy(deployments[:], intent.Deployments)
	copy(runtimeAttestations[:], runtime.Attestations)
	for index, row := range runtime.Attestations {
		runtimeObjectDigests[index] = runtimeResult.byNode[row.NodeID].digest
	}
	lastObservedCounter := intent.AcceptedCounter
	for _, row := range runtime.Attestations {
		if row.ObservedCounter > lastObservedCounter {
			lastObservedCounter = row.ObservedCounter
		}
	}
	for _, candidate := range []uint64{
		reservation.PreparedCounter, reservation.CommittedCounter,
		readiness.AcceptedCounter,
	} {
		if candidate > lastObservedCounter {
			lastObservedCounter = candidate
		}
	}
	return AdmissionResult{
		CycleID: intent.CycleID, AttemptID: intent.AttemptID,
		TopologyID: intent.TopologyID, BindingDigest: intent.BindingDigest,
		Nonce: intent.Nonce, CounterDomain: intent.CounterDomain,
		AcceptedCounter:         intent.AcceptedCounter,
		LastObservedCounter:     lastObservedCounter,
		ExpectedTransport:       intent.ExpectedTransport,
		AdmissionBundleSHA256:   bundleDigest,
		TrustSHA256:             intent.TrustSHA256,
		RuntimeCollectionDigest: runtime.CollectionDigest,
		ReservationObjectDigest: reservationDigest,
		RuntimeCount:            len(runtime.Attestations), ReservedTokenCount: reserved,
		StartNotBefore: intent.StartNotBefore,
		StartDeadline:  intent.StartDeadline, FinishDeadline: intent.FinishDeadline,
		ExercisedNodeCount:   len(intent.ExercisedNodes),
		ExercisedNodes:       exercisedNodes,
		Deployments:          deployments,
		RuntimeAttestations:  runtimeAttestations,
		RuntimeObjectDigests: runtimeObjectDigests,
	}, nil
}

type admissionTimes struct {
	acceptedAt, trustExpiry, startNotBefore, startDeadline, finishDeadline int64
}

func validateAdmissionIntent(
	value AdmissionIntent,
	trust TrustBundle,
	trustSHA string,
	keys trustIndex,
	e0 e0Snapshot,
) (admissionTimes, error) {
	if value.Schema != AdmissionIntentSchema ||
		!validID(value.CycleID) || !validID(value.AttemptID) ||
		!validID(value.TopologyID) ||
		value.TopologyID != e0.result.TopologyID ||
		value.DescriptorSHA256 != e0.result.DescriptorSHA256 ||
		value.BundleSHA256 != e0.result.BundleSHA256 ||
		value.TrustSHA256 != trustSHA || !validNonce(value.Nonce) ||
		!validID(value.CounterDomain) || value.AcceptedCounter == 0 ||
		!slices.Contains([]string{TransportDirect, TransportH3}, value.ExpectedTransport) ||
		len(value.Deployments) != len(requiredRoles) ||
		len(value.ExercisedNodes) == 0 ||
		len(value.ExercisedNodes) > len(requiredRoles) {
		return admissionTimes{}, errors.New("admission intent fields are invalid")
	}
	accepted, err := parseTime(value.AcceptedAt)
	if err != nil {
		return admissionTimes{}, fmt.Errorf("intent accepted_at: %w", err)
	}
	start, err := parseTime(value.StartNotBefore)
	if err != nil {
		return admissionTimes{}, fmt.Errorf("intent start_not_before: %w", err)
	}
	deadline, err := parseTime(value.StartDeadline)
	if err != nil {
		return admissionTimes{}, fmt.Errorf("intent start_deadline: %w", err)
	}
	finish, err := parseTime(value.FinishDeadline)
	if err != nil {
		return admissionTimes{}, fmt.Errorf("intent finish_deadline: %w", err)
	}
	trustAccepted, _ := parseTime(trust.AcceptedAt)
	trustExpires, _ := parseTime(trust.ExpiresAt)
	if accepted.Before(trustAccepted) || !accepted.Before(start) ||
		!start.Before(deadline) || !deadline.Before(finish) ||
		!finish.Before(trustExpires) {
		return admissionTimes{}, errors.New("admission intent chronology is invalid")
	}
	roles := make(map[string]struct{}, len(value.Deployments))
	nodes := make(map[string]struct{}, len(value.Deployments))
	global := make(map[string]struct{}, len(value.Deployments)*3)
	for index, row := range value.Deployments {
		expected := e0.descriptor.Deployments[index]
		if row.Role != requiredRoles[index] || row.Role != expected.Role ||
			row.InstanceUUID != expected.InstanceUUID ||
			row.NodeID != expected.NodeID || row.ServiceID != expected.ServiceID ||
			row.Provider != expected.Provider || row.OperatorID != expected.OperatorID ||
			!uuidPattern.MatchString(row.InstanceUUID) ||
			!validID(row.NodeID) || !validID(row.ServiceID) ||
			!validID(row.Provider) || !validID(row.OperatorID) {
			return admissionTimes{}, fmt.Errorf("admission deployment %d is invalid", index)
		}
		if _, ok := roles[row.Role]; ok {
			return admissionTimes{}, errors.New("duplicate admission role")
		}
		if _, ok := nodes[row.NodeID]; ok {
			return admissionTimes{}, errors.New("duplicate admission node")
		}
		for _, identity := range []string{row.InstanceUUID, row.NodeID, row.ServiceID} {
			if _, ok := global[identity]; ok {
				return admissionTimes{}, errors.New("admission identities are not unique")
			}
			global[identity] = struct{}{}
		}
		roles[row.Role], nodes[row.NodeID] = struct{}{}, struct{}{}
	}
	exercised := make(map[string]struct{}, len(value.ExercisedNodes))
	for _, node := range value.ExercisedNodes {
		if _, ok := nodes[node]; !ok {
			return admissionTimes{}, errors.New("exercised node is absent from E0")
		}
		if _, ok := exercised[node]; ok {
			return admissionTimes{}, errors.New("duplicate exercised node")
		}
		exercised[node] = struct{}{}
	}
	binding, err := digestObject(admissionBindingDomain, admissionIntentCoreOf(value))
	if err != nil || binding != value.BindingDigest {
		return admissionTimes{}, errors.New("admission binding digest mismatch")
	}
	if err := verifySignature(
		keys, value.ControllerKeyID, KeyRoleController, "",
		admissionIntentSignatureDomain, value.Signature,
		admissionIntentUnsignedOf(value),
	); err != nil {
		return admissionTimes{}, fmt.Errorf("admission intent: %w", err)
	}
	return admissionTimes{
		acceptedAt: accepted.UnixNano(), trustExpiry: trustExpires.UnixNano(),
		startNotBefore: start.UnixNano(), startDeadline: deadline.UnixNano(),
		finishDeadline: finish.UnixNano(),
	}, nil
}

func validateRuntimeCausality(
	runtime RuntimeSet, acceptedAt, startNotBefore int64,
) error {
	lastTime, lastCounter := acceptedAt, uint64(0)
	for index, row := range runtime.Attestations {
		observed, _ := parseTime(row.ObservedAt)
		if observed.UnixNano() <= lastTime ||
			observed.UnixNano() >= startNotBefore ||
			(index > 0 && row.ObservedCounter <= lastCounter) {
			return errors.New("runtime attestations are not strictly causal")
		}
		lastTime, lastCounter = observed.UnixNano(), row.ObservedCounter
	}
	return nil
}

func validateReservation(
	value CredentialReservation,
	intent AdmissionIntent,
	runtime RuntimeSet,
	runtimeResult runtimeValidation,
	keys trustIndex,
	finishDeadline, trustExpiry int64,
) (string, int, int64, error) {
	if value.Schema != CredentialReservationSchema ||
		value.CycleBindingDigest != intent.BindingDigest ||
		value.RuntimeCollectionDigest != runtime.CollectionDigest ||
		!validID(value.LeaseID) || !validID(value.ReservationID) ||
		value.AttemptID != intent.AttemptID || value.State != "committed" ||
		value.CounterDomain != intent.CounterDomain ||
		value.PreparedCounter <= runtimeResult.latestCounter ||
		value.CommittedCounter <= value.PreparedCounter ||
		value.PSKGeneration == 0 || !validID(value.PSKKeyID) ||
		value.VaultRevisionBefore == math.MaxUint64 ||
		value.VaultRevisionAfter != value.VaultRevisionBefore+1 ||
		len(value.TokenClasses) > MaxTokenClasses {
		return "", 0, 0, errors.New("credential reservation fields are invalid")
	}
	peer, err := base64.StdEncoding.DecodeString(value.PeerPublicKey)
	if err != nil || len(peer) != 32 ||
		base64.StdEncoding.EncodeToString(peer) != value.PeerPublicKey {
		return "", 0, 0, errors.New("reservation peer key is invalid")
	}
	prepared, err := parseTime(value.PreparedAt)
	if err != nil {
		return "", 0, 0, fmt.Errorf("reservation prepared_at: %w", err)
	}
	committed, err := parseTime(value.CommittedAt)
	if err != nil {
		return "", 0, 0, fmt.Errorf("reservation committed_at: %w", err)
	}
	expires, err := parseTime(value.ExpiresAt)
	if err != nil || prepared.UnixNano() <= runtimeResult.latestAt ||
		!prepared.Before(committed) || expires.UnixNano() <= finishDeadline ||
		expires.UnixNano() >= trustExpiry {
		return "", 0, 0, errors.New("credential reservation chronology is invalid")
	}
	exercised := make(map[string]DeploymentBinding, len(intent.ExercisedNodes))
	for _, node := range intent.ExercisedNodes {
		for _, deployment := range intent.Deployments {
			if deployment.NodeID == node {
				exercised[node] = deployment
			}
		}
	}
	if intent.ExpectedTransport == TransportDirect && len(value.TokenClasses) != 0 {
		return "", 0, 0, errors.New("direct transport must reserve zero tokens")
	}
	if intent.ExpectedTransport == TransportH3 &&
		len(value.TokenClasses) != len(exercised) {
		return "", 0, 0, errors.New("H3 requires one reservation per exercised node")
	}
	seen := make(map[string]struct{}, len(value.TokenClasses))
	for index, row := range value.TokenClasses {
		deployment, ok := exercised[row.NodeID]
		if !ok || row.ServiceID != deployment.ServiceID ||
			row.Transport != TransportH3 ||
			!validID(row.CandidateID) || !validID(row.TokenKeyID) ||
			!validID(row.Scope) || !validID(row.IssuerDomain) ||
			row.ReservedCount != 1 || !validDigest(row.CommitmentSHA256) {
			return "", 0, 0, fmt.Errorf("token reservation %d is invalid", index)
		}
		key := row.NodeID + "\x00" + row.ServiceID
		if _, ok := seen[key]; ok {
			return "", 0, 0, errors.New("duplicate token reservation")
		}
		seen[key] = struct{}{}
		expected, err := digestObject(reservationCommitmentDomain, struct {
			CandidateID   string `json:"candidate_id"`
			NodeID        string `json:"node_id"`
			ServiceID     string `json:"service_id"`
			Transport     string `json:"transport"`
			TokenKeyID    string `json:"token_key_id"`
			Scope         string `json:"scope"`
			IssuerDomain  string `json:"issuer_domain"`
			ReservedCount uint64 `json:"reserved_count"`
		}{
			row.CandidateID, row.NodeID, row.ServiceID, row.Transport,
			row.TokenKeyID, row.Scope, row.IssuerDomain, row.ReservedCount,
		})
		if err != nil || expected != row.CommitmentSHA256 {
			return "", 0, 0, errors.New("token reservation commitment mismatch")
		}
	}
	if err := verifySignature(
		keys, value.PublisherKeyID, KeyRoleLease, "",
		reservationSignatureDomain, value.Signature, reservationUnsignedOf(value),
	); err != nil {
		return "", 0, 0, fmt.Errorf("credential reservation: %w", err)
	}
	digest, err := digestObject(reservationObjectDomain, value)
	if err != nil {
		return "", 0, 0, err
	}
	return digest, len(value.TokenClasses), committed.UnixNano(), nil
}

func validateReadiness(
	value ReadinessEnvelope,
	intent AdmissionIntent,
	runtime RuntimeSet,
	reservation CredentialReservation,
	fileSHA map[string]string,
	reservationDigest string,
	committedAt int64,
	times admissionTimes,
	keys trustIndex,
) error {
	if value.Schema != ReadinessEnvelopeSchema ||
		value.CycleBindingDigest != intent.BindingDigest ||
		value.IntentSHA256 != fileSHA[AdmissionIntentFile] ||
		value.RuntimeSHA256 != fileSHA[RuntimeFile] ||
		value.RuntimeCollectionDigest != runtime.CollectionDigest ||
		value.ReservationSHA256 != fileSHA[ReservationFile] ||
		value.ReservationObjectDigest != reservationDigest ||
		value.CounterDomain != intent.CounterDomain ||
		value.AcceptedCounter <= reservation.CommittedCounter ||
		value.StartNotBefore != intent.StartNotBefore ||
		value.StartDeadline != intent.StartDeadline ||
		value.FinishDeadline != intent.FinishDeadline ||
		!value.ContractValid || value.DispatchAuthorized ||
		value.Mutation != "none" {
		return errors.New("readiness envelope fields are invalid")
	}
	accepted, err := parseTime(value.AcceptedAt)
	if err != nil || accepted.UnixNano() <= committedAt ||
		accepted.UnixNano() >= times.startNotBefore ||
		accepted.UnixNano() >= times.trustExpiry {
		return errors.New("readiness envelope chronology is invalid")
	}
	if err := verifySignature(
		keys, value.ControllerKeyID, KeyRoleController, "",
		readinessSignatureDomain, value.Signature, readinessUnsignedOf(value),
	); err != nil {
		return fmt.Errorf("readiness envelope: %w", err)
	}
	_, err = digestObject(readinessObjectDomain, value)
	return err
}

func openAdmissionRoot(path string) (*os.Root, []string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, nil, errors.New("admission directory is unsafe")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	retained, err := root.Stat(".")
	if err != nil || !os.SameFile(info, retained) {
		_ = root.Close()
		return nil, nil, errors.New("admission directory identity changed")
	}
	entries, err := rootEntries(root)
	if err != nil || !slices.Equal(entries, admissionFiles) {
		_ = root.Close()
		return nil, nil, fmt.Errorf(
			"admission directory entries %v, want %v", entries, admissionFiles,
		)
	}
	return root, entries, nil
}

func fileSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
