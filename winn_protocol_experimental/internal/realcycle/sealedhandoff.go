package realcycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	AuthorizationCommitmentSchema = "winn-real-cycle-authorization-commitment/v1"
	SupervisorCommitmentSchema    = "winn-real-cycle-supervisor-commitment/v1"
	HandoffRoleExtensionSchema    = "winn-real-cycle-handoff-role-extension/v1"

	AuthorizationCommitmentFile = "authorization-commitment.json"
	HandoffRoleExtensionFile    = "handoff-role-extension.json"
	SupervisorCommitmentFile    = "supervisor-commitment.json"

	authorizationSignatureDomain        = "winn-real-cycle-authorization-commitment-signature/v1"
	authorizationObjectDomain           = "winn-real-cycle-authorization-commitment-object/v1"
	supervisorSignatureDomain           = "winn-real-cycle-supervisor-commitment-signature/v1"
	supervisorObjectDomain              = "winn-real-cycle-supervisor-commitment-object/v1"
	handoffRoleExtensionSignatureDomain = "winn-real-cycle-handoff-role-extension-signature/v1"
	handoffRoleExtensionObjectDomain    = "winn-real-cycle-handoff-role-extension-object/v1"
	sealedHandoffCollectionDomain       = "winn-real-cycle-sealed-handoff-collection/v1"

	MaxHandoffFileBytes     = 256 << 10
	MaximumExecutionSeconds = 86400
)

var sealedHandoffFiles = []string{
	AuthorizationCommitmentFile,
	HandoffRoleExtensionFile,
	SupervisorCommitmentFile,
}

type HandoffExpectation struct {
	RunID                   string
	CycleID                 string
	AttemptID               string
	TopologyID              string
	PlanSHA256              string
	PlanObjectDigest        string
	TrustSHA256             string
	AdmissionBindingDigest  string
	AdmissionBundleSHA256   string
	RuntimeCollectionDigest string
	ReservationObjectDigest string
	AdmissionNonce          string
	CounterDomain           string
	AcceptedCounter         uint64
	LastObservedCounter     uint64
	ExpectedTransport       string
	StartNotBefore          string
	StartDeadline           string
	FinishDeadline          string
}

type HandoffRoleKey struct {
	KeyID     string `json:"key_id"`
	Role      string `json:"role"`
	PublicKey string `json:"public_key"`
}

type HandoffRoleExtension struct {
	Schema              string            `json:"schema"`
	State               string            `json:"state"`
	PlanSHA256          string            `json:"plan_sha256"`
	PlanObjectDigest    string            `json:"plan_object_digest"`
	AcceptedTrustSHA256 string            `json:"accepted_trust_sha256"`
	Keys                [2]HandoffRoleKey `json:"keys"`
	ControllerKeyID     string            `json:"controller_key_id"`
	Signature           string            `json:"signature"`
}

type AuthorizationCommitment struct {
	Schema                   string `json:"schema"`
	State                    string `json:"state"`
	Scope                    string `json:"scope"`
	RunID                    string `json:"run_id"`
	CycleID                  string `json:"cycle_id"`
	AttemptID                string `json:"attempt_id"`
	TopologyID               string `json:"topology_id"`
	PlanSHA256               string `json:"plan_sha256"`
	PlanObjectDigest         string `json:"plan_object_digest"`
	AdmissionBindingDigest   string `json:"admission_binding_digest"`
	AdmissionBundleSHA256    string `json:"admission_bundle_sha256"`
	RuntimeCollectionDigest  string `json:"runtime_collection_digest"`
	ReservationObjectDigest  string `json:"reservation_object_digest"`
	AdmissionNonce           string `json:"admission_nonce"`
	CounterDomain            string `json:"counter_domain"`
	MinimumActivationCounter uint64 `json:"minimum_activation_counter"`
	ValidNotBefore           string `json:"valid_not_before"`
	ValidNotAfter            string `json:"valid_not_after"`
	MaxRuntimeAgeSeconds     uint64 `json:"max_runtime_age_seconds"`
	MaxExecutionSeconds      uint64 `json:"max_execution_seconds"`
	OneTimeNonce             string `json:"one_time_nonce"`
	AuthorizerKeyID          string `json:"authorizer_key_id"`
	Signature                string `json:"signature"`
}

type SupervisorCommitment struct {
	Schema                     string `json:"schema"`
	State                      string `json:"state"`
	RunID                      string `json:"run_id"`
	CycleID                    string `json:"cycle_id"`
	AttemptID                  string `json:"attempt_id"`
	TopologyID                 string `json:"topology_id"`
	PlanSHA256                 string `json:"plan_sha256"`
	PlanObjectDigest           string `json:"plan_object_digest"`
	ExpectedTransport          string `json:"expected_transport"`
	SupervisorExecutablePath   string `json:"supervisor_executable_path"`
	SupervisorExecutableSHA256 string `json:"supervisor_executable_sha256"`
	SupervisorConfigPath       string `json:"supervisor_config_path"`
	SupervisorConfigSHA256     string `json:"supervisor_config_sha256"`
	MaxExecutionSeconds        uint64 `json:"max_execution_seconds"`
	OneTimeNonce               string `json:"one_time_nonce"`
	SupervisorKeyID            string `json:"supervisor_key_id"`
	Signature                  string `json:"signature"`
}

type SealedHandoffResult struct {
	TrustSHA256                  string
	AcceptedCounter              uint64
	LastObservedCounter          uint64
	ExpectedTransport            string
	StartNotBefore               string
	StartDeadline                string
	FinishDeadline               string
	AuthorizationSHA256          string
	AuthorizationObjectDigest    string
	SupervisorSHA256             string
	SupervisorObjectDigest       string
	RoleExtensionSHA256          string
	RoleExtensionObjectDigest    string
	RoleExtensionControllerKeyID string
	RoleExtensionSignature       string
	RoleExtensionKeys            [2]HandoffRoleKey
	AuthorizationKeyID           string
	AuthorizationSignature       string
	SupervisorKeyID              string
	SupervisorSignature          string
	CollectionDigest             string
	MinimumActivationCounter     uint64
	ValidNotBefore               string
	ValidNotAfter                string
	MaxRuntimeAgeSeconds         uint64
	MaxExecutionSeconds          uint64
	OneTimeNonce                 string
	SupervisorExecutablePath     string
	SupervisorExecutableSHA256   string
	SupervisorConfigPath         string
	SupervisorConfigSHA256       string
}

type authorizationUnsigned AuthorizationCommitment
type supervisorUnsigned SupervisorCommitment
type handoffRoleExtensionUnsigned HandoffRoleExtension

func authorizationUnsignedOf(v AuthorizationCommitment) authorizationUnsigned {
	v.Signature = ""
	return authorizationUnsigned(v)
}

func supervisorUnsignedOf(v SupervisorCommitment) supervisorUnsigned {
	v.Signature = ""
	return supervisorUnsigned(v)
}

func handoffRoleExtensionUnsignedOf(
	v HandoffRoleExtension,
) handoffRoleExtensionUnsigned {
	v.Signature = ""
	return handoffRoleExtensionUnsigned(v)
}

// ValidateSealedHandoff validates two signed, provider-neutral commitments.
// It performs no time observation, counter reservation, process launch,
// credential access, provider access, or network operation. A successful
// result is therefore evidence-input readiness only, never dispatch authority.
func ValidateSealedHandoff(
	rootPath, trustPath string, expected HandoffExpectation,
) (SealedHandoffResult, error) {
	if rootPath == "" || trustPath == "" {
		return SealedHandoffResult{}, errors.New("handoff root and trust are required")
	}
	trustBytes, trustSnapshot, err := readStandalone(trustPath, MaxTrustFileBytes)
	if err != nil {
		return SealedHandoffResult{}, fmt.Errorf("read handoff trust: %w", err)
	}
	trust, keys, err := parseTrust(trustBytes)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	root, entries, err := openExactRoot(rootPath, sealedHandoffFiles)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	defer root.Close()
	documents := make(map[string][]byte, len(entries))
	snapshots := make(map[string]fileSnapshot, len(entries))
	for _, name := range entries {
		data, snapshot, readErr := readRootFile(root, name, MaxHandoffFileBytes)
		if readErr != nil {
			return SealedHandoffResult{}, fmt.Errorf("read %s: %w", name, readErr)
		}
		documents[name], snapshots[name] = data, snapshot
	}
	var authorization AuthorizationCommitment
	if err := decodeCanonical(documents[AuthorizationCommitmentFile], &authorization); err != nil {
		return SealedHandoffResult{}, fmt.Errorf("decode authorization commitment: %w", err)
	}
	var extension HandoffRoleExtension
	if err := decodeCanonical(
		documents[HandoffRoleExtensionFile], &extension,
	); err != nil {
		return SealedHandoffResult{},
			fmt.Errorf("decode handoff role extension: %w", err)
	}
	var supervisor SupervisorCommitment
	if err := decodeCanonical(documents[SupervisorCommitmentFile], &supervisor); err != nil {
		return SealedHandoffResult{}, fmt.Errorf("decode supervisor commitment: %w", err)
	}
	result, err := validateSealedHandoffValues(
		authorization, extension, supervisor, trust, keys, expected,
		trustBytes, documents[AuthorizationCommitmentFile],
		documents[HandoffRoleExtensionFile],
		documents[SupervisorCommitmentFile],
	)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	if err := recheckExactRoot(rootPath, root, entries, snapshots); err != nil {
		return SealedHandoffResult{}, err
	}
	if err := recheckStandalone(trustPath, trustSnapshot); err != nil {
		return SealedHandoffResult{}, fmt.Errorf("recheck handoff trust: %w", err)
	}
	if err := validateSupervisorIdentities(result); err != nil {
		return SealedHandoffResult{}, err
	}
	return result, nil
}

// VerifySealedHandoffObjects independently replays canonical objects projected
// by a durable E6 receipt against the exact accepted trust and supervisor
// files. It remains offline and nonauthorizing.
func VerifySealedHandoffObjects(
	trustPath string,
	expected HandoffExpectation,
	authorization AuthorizationCommitment,
	extension HandoffRoleExtension,
	supervisor SupervisorCommitment,
) (SealedHandoffResult, error) {
	trustBytes, trustSnapshot, err := readStandalone(trustPath, MaxTrustFileBytes)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	trust, keys, err := parseTrust(trustBytes)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	authorizationBytes, err := marshalCanonical(authorization)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	extensionBytes, err := marshalCanonical(extension)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	supervisorBytes, err := marshalCanonical(supervisor)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	result, err := validateSealedHandoffValues(
		authorization, extension, supervisor, trust, keys, expected,
		trustBytes, authorizationBytes, extensionBytes, supervisorBytes,
	)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	if err := validateSupervisorIdentities(result); err != nil {
		return SealedHandoffResult{}, err
	}
	if err := recheckStandalone(trustPath, trustSnapshot); err != nil {
		return SealedHandoffResult{}, err
	}
	return result, nil
}

func validateSupervisorIdentities(result SealedHandoffResult) error {
	executableBytes, executableSnapshot, err := readNoSymlinkRegular(
		result.SupervisorExecutablePath, 64<<20,
	)
	if err != nil || rawSHA(executableBytes) != result.SupervisorExecutableSHA256 ||
		executableSnapshot.info.Mode().Perm()&0o111 == 0 ||
		executableSnapshot.info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("supervisor executable identity is not exact")
	}
	configBytes, configSnapshot, err := readNoSymlinkRegular(
		result.SupervisorConfigPath, MaxHandoffFileBytes,
	)
	if err != nil || rawSHA(configBytes) != result.SupervisorConfigSHA256 ||
		configSnapshot.info.Mode().Perm()&0o111 != 0 {
		return errors.New("supervisor config identity is not exact")
	}
	if err := recheckNoSymlinkRegular(
		result.SupervisorExecutablePath, executableSnapshot, 64<<20,
	); err != nil {
		return errors.New("supervisor executable changed after validation")
	}
	if err := recheckNoSymlinkRegular(
		result.SupervisorConfigPath, configSnapshot, MaxHandoffFileBytes,
	); err != nil {
		return errors.New("supervisor config changed after validation")
	}
	return nil
}

func validateSealedHandoffValues(
	authorization AuthorizationCommitment,
	extension HandoffRoleExtension,
	supervisor SupervisorCommitment,
	trust TrustBundle,
	keys trustIndex,
	expected HandoffExpectation,
	trustBytes, authorizationBytes, extensionBytes, supervisorBytes []byte,
) (SealedHandoffResult, error) {
	extendedKeys, extensionObject, err := validateHandoffRoleExtension(
		extension, keys, trustBytes, expected,
	)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	if authorization.Schema != AuthorizationCommitmentSchema ||
		authorization.State != "sealed-pending-activation" ||
		authorization.Scope != "execute-one-four-node-cycle" ||
		authorization.RunID != expected.RunID ||
		authorization.CycleID != expected.CycleID ||
		authorization.AttemptID != expected.AttemptID ||
		authorization.TopologyID != expected.TopologyID ||
		authorization.PlanSHA256 != expected.PlanSHA256 ||
		authorization.PlanObjectDigest != expected.PlanObjectDigest ||
		authorization.AdmissionBindingDigest != expected.AdmissionBindingDigest ||
		authorization.AdmissionBundleSHA256 != expected.AdmissionBundleSHA256 ||
		authorization.RuntimeCollectionDigest != expected.RuntimeCollectionDigest ||
		authorization.ReservationObjectDigest != expected.ReservationObjectDigest ||
		authorization.AdmissionNonce != expected.AdmissionNonce ||
		authorization.CounterDomain != expected.CounterDomain ||
		expected.LastObservedCounter < expected.AcceptedCounter ||
		authorization.MinimumActivationCounter <= expected.LastObservedCounter ||
		authorization.MaxRuntimeAgeSeconds == 0 ||
		authorization.MaxRuntimeAgeSeconds > 3600 ||
		authorization.MaxExecutionSeconds == 0 ||
		authorization.MaxExecutionSeconds > MaximumExecutionSeconds ||
		!hex32Pattern.MatchString(authorization.OneTimeNonce) {
		return SealedHandoffResult{}, errors.New("authorization commitment is not exact")
	}
	notBefore, err := parseTime(authorization.ValidNotBefore)
	if err != nil {
		return SealedHandoffResult{}, errors.New("authorization valid_not_before is invalid")
	}
	notAfter, err := parseTime(authorization.ValidNotAfter)
	if err != nil || !notAfter.After(notBefore) {
		return SealedHandoffResult{}, errors.New("authorization validity interval is invalid")
	}
	start, err := parseTime(expected.StartNotBefore)
	if err != nil || notBefore.Before(start) {
		return SealedHandoffResult{}, errors.New("authorization starts before admitted window")
	}
	startDeadline, err := parseTime(expected.StartDeadline)
	if err != nil || notAfter.After(startDeadline) {
		return SealedHandoffResult{}, errors.New("authorization ends after admitted start deadline")
	}
	finish, err := parseTime(expected.FinishDeadline)
	if err != nil || notAfter.Add(
		time.Duration(authorization.MaxExecutionSeconds)*time.Second,
	).After(finish) {
		return SealedHandoffResult{}, errors.New("authorization execution exceeds finish deadline")
	}
	trustStart, _ := parseTime(trust.AcceptedAt)
	trustEnd, _ := parseTime(trust.ExpiresAt)
	if notBefore.Before(trustStart) || notAfter.After(trustEnd) {
		return SealedHandoffResult{}, errors.New("authorization exceeds trust validity")
	}
	if err := verifySignature(
		extendedKeys, authorization.AuthorizerKeyID, KeyRoleDispatchAuthorizer, "",
		authorizationSignatureDomain, authorization.Signature,
		authorizationUnsignedOf(authorization),
	); err != nil {
		return SealedHandoffResult{}, fmt.Errorf("authorization signature: %w", err)
	}
	if supervisor.Schema != SupervisorCommitmentSchema ||
		supervisor.State != "sealed-pending-activation" ||
		supervisor.RunID != expected.RunID ||
		supervisor.CycleID != expected.CycleID ||
		supervisor.AttemptID != expected.AttemptID ||
		supervisor.TopologyID != expected.TopologyID ||
		supervisor.PlanSHA256 != expected.PlanSHA256 ||
		supervisor.PlanObjectDigest != expected.PlanObjectDigest ||
		supervisor.ExpectedTransport != expected.ExpectedTransport ||
		!cleanAbsolutePath(supervisor.SupervisorExecutablePath) ||
		!cleanAbsolutePath(supervisor.SupervisorConfigPath) ||
		supervisor.SupervisorExecutablePath == supervisor.SupervisorConfigPath ||
		!hex64Pattern.MatchString(supervisor.SupervisorExecutableSHA256) ||
		!hex64Pattern.MatchString(supervisor.SupervisorConfigSHA256) ||
		supervisor.MaxExecutionSeconds != authorization.MaxExecutionSeconds ||
		supervisor.OneTimeNonce != authorization.OneTimeNonce {
		return SealedHandoffResult{}, errors.New("supervisor commitment is not exact")
	}
	if err := verifySignature(
		extendedKeys, supervisor.SupervisorKeyID, KeyRoleExecutionSupervisor, "",
		supervisorSignatureDomain, supervisor.Signature,
		supervisorUnsignedOf(supervisor),
	); err != nil {
		return SealedHandoffResult{}, fmt.Errorf("supervisor signature: %w", err)
	}
	authObject, err := digestObject(authorizationObjectDomain, authorization)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	supervisorObject, err := digestObject(supervisorObjectDomain, supervisor)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	rows := []string{authObject, extensionObject, supervisorObject}
	collection, err := digestObject(sealedHandoffCollectionDomain, rows)
	if err != nil {
		return SealedHandoffResult{}, err
	}
	return SealedHandoffResult{
		TrustSHA256:                  expected.TrustSHA256,
		AcceptedCounter:              expected.AcceptedCounter,
		LastObservedCounter:          expected.LastObservedCounter,
		ExpectedTransport:            expected.ExpectedTransport,
		StartNotBefore:               expected.StartNotBefore,
		StartDeadline:                expected.StartDeadline,
		FinishDeadline:               expected.FinishDeadline,
		AuthorizationSHA256:          rawSHA(authorizationBytes),
		AuthorizationObjectDigest:    authObject,
		SupervisorSHA256:             rawSHA(supervisorBytes),
		SupervisorObjectDigest:       supervisorObject,
		RoleExtensionSHA256:          rawSHA(extensionBytes),
		RoleExtensionObjectDigest:    extensionObject,
		RoleExtensionControllerKeyID: extension.ControllerKeyID,
		RoleExtensionSignature:       extension.Signature,
		RoleExtensionKeys:            extension.Keys,
		AuthorizationKeyID:           authorization.AuthorizerKeyID,
		AuthorizationSignature:       authorization.Signature,
		SupervisorKeyID:              supervisor.SupervisorKeyID,
		SupervisorSignature:          supervisor.Signature,
		CollectionDigest:             collection,
		MinimumActivationCounter:     authorization.MinimumActivationCounter,
		ValidNotBefore:               authorization.ValidNotBefore,
		ValidNotAfter:                authorization.ValidNotAfter,
		MaxRuntimeAgeSeconds:         authorization.MaxRuntimeAgeSeconds,
		MaxExecutionSeconds:          authorization.MaxExecutionSeconds,
		OneTimeNonce:                 authorization.OneTimeNonce,
		SupervisorExecutablePath:     supervisor.SupervisorExecutablePath,
		SupervisorExecutableSHA256:   supervisor.SupervisorExecutableSHA256,
		SupervisorConfigPath:         supervisor.SupervisorConfigPath,
		SupervisorConfigSHA256:       supervisor.SupervisorConfigSHA256,
	}, nil
}

func cleanAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && path != string(filepath.Separator) &&
		filepath.Clean(path) == path
}

func validateHandoffRoleExtension(
	value HandoffRoleExtension,
	acceptedKeys trustIndex,
	trustBytes []byte,
	expected HandoffExpectation,
) (trustIndex, string, error) {
	if value.Schema != HandoffRoleExtensionSchema ||
		value.State != "public-key-extension-only" ||
		value.PlanSHA256 != expected.PlanSHA256 ||
		value.PlanObjectDigest != expected.PlanObjectDigest ||
		value.AcceptedTrustSHA256 != expected.TrustSHA256 ||
		value.AcceptedTrustSHA256 != rawSHA(trustBytes) ||
		value.Keys[0].Role != KeyRoleDispatchAuthorizer ||
		value.Keys[1].Role != KeyRoleExecutionSupervisor ||
		!validID(value.Keys[0].KeyID) || !validID(value.Keys[1].KeyID) ||
		value.Keys[0].KeyID == value.Keys[1].KeyID {
		return nil, "", errors.New("handoff role extension is not exact")
	}
	if err := verifySignature(
		acceptedKeys, value.ControllerKeyID, KeyRoleController, "",
		handoffRoleExtensionSignatureDomain, value.Signature,
		handoffRoleExtensionUnsignedOf(value),
	); err != nil {
		return nil, "", fmt.Errorf("handoff role extension signature: %w", err)
	}
	extended := make(trustIndex, len(acceptedKeys)+2)
	var acceptedMaterial [][]byte
	for id, entry := range acceptedKeys {
		extended[id] = entry
		acceptedMaterial = append(acceptedMaterial, []byte(entry.key))
	}
	var newMaterial [][]byte
	for _, row := range value.Keys {
		if _, exists := extended[row.KeyID]; exists {
			return nil, "", errors.New("handoff role key_id collides with accepted trust")
		}
		decoded, err := base64.StdEncoding.DecodeString(row.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(decoded) != row.PublicKey {
			return nil, "", errors.New("handoff role key is not canonical Ed25519")
		}
		for _, prior := range append(acceptedMaterial, newMaterial...) {
			if bytes.Equal(decoded, prior) {
				return nil, "", errors.New("handoff role key material is not distinct")
			}
		}
		copyOf := append([]byte(nil), decoded...)
		newMaterial = append(newMaterial, copyOf)
		extended[row.KeyID] = trustedKey{
			row: TrustKey{
				KeyID: row.KeyID, Role: row.Role, PublicKey: row.PublicKey,
			},
			key: ed25519.PublicKey(copyOf),
		}
	}
	objectDigest, err := digestObject(handoffRoleExtensionObjectDomain, value)
	if err != nil {
		return nil, "", err
	}
	return extended, objectDigest, nil
}

func rawSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func openExactRoot(path string, expected []string) (*os.Root, []string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, nil, errors.New("handoff directory is unsafe")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	retained, err := root.Stat(".")
	if err != nil || !os.SameFile(info, retained) {
		return nil, nil, closeRootError(
			root, errors.New("handoff directory identity changed"),
		)
	}
	entries, err := rootEntries(root)
	if err != nil || !slices.Equal(entries, expected) {
		return nil, nil, closeRootError(
			root, errors.New("handoff directory census is not exact"),
		)
	}
	return root, entries, nil
}

func recheckExactRoot(
	path string, root *os.Root, entries []string,
	snapshots map[string]fileSnapshot,
) error {
	info, err := os.Lstat(path)
	retained, retainedErr := root.Stat(".")
	if err != nil || retainedErr != nil || !os.SameFile(info, retained) {
		return errors.New("handoff directory changed after validation")
	}
	final, err := rootEntries(root)
	if err != nil || !slices.Equal(entries, final) {
		return errors.New("handoff directory census changed after validation")
	}
	for _, name := range entries {
		_, current, err := readRootFile(root, name, MaxHandoffFileBytes)
		if err != nil || !sameSnapshot(snapshots[name].info, current.info) ||
			snapshots[name].sha256 != current.sha256 {
			return errors.New("handoff object changed after validation")
		}
	}
	return nil
}
