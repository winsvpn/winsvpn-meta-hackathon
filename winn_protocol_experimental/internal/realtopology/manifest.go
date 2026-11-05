// Package realtopology validates the public, immutable input bundle proposed
// for a future real-topology Winn Phase 1 preflight.
//
// Validation is structural with one cryptographic exception: parseLinuxProfile
// calls directawg.VerifyLinuxDeploymentProfile. This package does not call
// gatewaymanifest.VerifyV2 or transparency.VerifyReceipt. It does not check
// wall-clock trust freshness (Linux verification is invoked at issued_at+1ns),
// cloud state, credentials, or network reachability, and it never makes
// network calls or writes files.
package realtopology

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/transparency"
)

const (
	Schema                 = "winn-phase1-external-topology/v1"
	ProtocolVersion        = "winn/3"
	DescriptorName         = "external-topology.json"
	MaxDescriptorBytes     = 64 << 10
	MaxPublicFileBytes     = 16 << 20
	MaxPublicBundleBytes   = 32 << 20
	MaxJSONDepth           = 32
	PreflightStatusSchema  = "winn-phase1-external-topology-preflight/v1"
	bundleDigestDomain     = "winn-phase1-external-topology-bundle/v1"
	maxIdentifierBytes     = 64
	expectedDeploymentRows = 4
)

const (
	RoleControl        = "control"
	RoleEntryPrimary   = "entry-primary"
	RoleEntrySecondary = "entry-secondary"
	RoleExit           = "exit"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	uuidPattern       = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
	)
	hexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// The order is part of the descriptor contract. Requiring it avoids two
	// byte-distinct inventories that claim the same public input set.
	AllowedPublicBasenames = []string{
		"accepted-trust-state-v2.json",
		"carrier-root-ca.pem",
		"controller-pq-pins.json",
		"gateway-manifest-v2.json",
		"linux-profile.json",
		"transparency.jsonl",
	}
	requiredRoles = []string{
		RoleControl,
		RoleEntryPrimary,
		RoleEntrySecondary,
		RoleExit,
	}
	secretFieldNames = []string{
		"clientprivatekey",
		"controllerpqseed",
		"devicepqseed",
		"gatewayprivatekey",
		"password",
		"passphrase",
		"privatekey",
		"privatekeyfile",
		"providerapitoken",
		"providertoken",
		"psk",
		"pskfile",
		"secret",
		"seed",
		"seedfile",
		"sshprivatekey",
		"sshkey",
		"tokenbundle",
	}
)

// Descriptor is the complete public E0 topology descriptor.
type Descriptor struct {
	Schema         string       `json:"schema"`
	TopologyID     string       `json:"topology_id"`
	Protocol       string       `json:"protocol_version"`
	LiveReady      bool         `json:"live_ready"`
	ExercisedNodes []string     `json:"exercised_nodes"`
	Deployments    []Deployment `json:"deployments"`
	Files          []PublicFile `json:"files"`
}

// Deployment binds one logical role to public deployment identifiers. These
// are identifiers only; their presence is not evidence that an instance or
// service currently exists or is running.
type Deployment struct {
	Role         string `json:"role"`
	InstanceUUID string `json:"instance_uuid"`
	NodeID       string `json:"node_id"`
	ServiceID    string `json:"service_id"`
	Provider     string `json:"provider"`
	OperatorID   string `json:"operator_id"`
}

// PublicFile binds one exact, non-secret basename to its bytes.
type PublicFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Result contains only properties established by ValidateBundle.
type Result struct {
	TopologyID       string
	DescriptorSHA256 string
	BundleSHA256     string
	PublicFileCount  int
}

type descriptorWire struct {
	Schema         string        `json:"schema"`
	TopologyID     string        `json:"topology_id"`
	Protocol       string        `json:"protocol_version"`
	LiveReady      *bool         `json:"live_ready"`
	ExercisedNodes *[]string     `json:"exercised_nodes"`
	Deployments    *[]Deployment `json:"deployments"`
	Files          *[]PublicFile `json:"files"`
}

// ValidateBundle validates an immutable public bundle without writing to it or
// consulting any external service.
func ValidateBundle(bundlePath string) (Result, error) {
	if bundlePath == "" {
		return Result{}, errors.New("external topology bundle path is required")
	}
	bundleInfo, err := os.Lstat(bundlePath)
	if err != nil {
		return Result{}, fmt.Errorf("inspect bundle directory: %w", err)
	}
	if bundleInfo.Mode()&os.ModeSymlink != 0 || !bundleInfo.IsDir() {
		return Result{}, errors.New("bundle path must be a real directory")
	}
	if bundleInfo.Mode().Perm()&0o022 != 0 {
		return Result{}, fmt.Errorf(
			"bundle directory is group/other writable (%04o)",
			bundleInfo.Mode().Perm(),
		)
	}
	root, err := os.OpenRoot(bundlePath)
	if err != nil {
		return Result{}, fmt.Errorf("open retained bundle root: %w", err)
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return Result{}, fmt.Errorf("stat retained bundle root: %w", err)
	}
	if !os.SameFile(bundleInfo, rootInfo) ||
		rootInfo.Mode() != bundleInfo.Mode() {
		return Result{}, errors.New(
			"bundle directory identity changed before it was retained",
		)
	}
	return validateRetainedRoot(root, rootInfo)
}

// ValidateRetainedRoot validates the exact directory capability supplied by
// the caller. It never resolves or reopens a pathname. Callers that need to
// compose E0 with later evidence can therefore keep one directory identity
// retained across both validations.
func ValidateRetainedRoot(root *os.Root) (Result, error) {
	if root == nil {
		return Result{}, errors.New("retained bundle root is required")
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		return Result{}, fmt.Errorf("stat retained bundle root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o022 != 0 {
		return Result{}, errors.New("retained bundle root is unsafe")
	}
	return validateRetainedRoot(root, rootInfo)
}

func validateRetainedRoot(
	root *os.Root,
	rootInfo os.FileInfo,
) (Result, error) {
	descriptorBytes, _, err := readCheckedPublic(
		root, DescriptorName, MaxDescriptorBytes,
	)
	if err != nil {
		return Result{}, fmt.Errorf("read descriptor: %w", err)
	}
	if err := inspectJSONNames(descriptorBytes); err != nil {
		return Result{}, fmt.Errorf("inspect descriptor JSON: %w", err)
	}
	var wire descriptorWire
	if err := decodeStrictJSON(descriptorBytes, &wire); err != nil {
		return Result{}, fmt.Errorf("decode descriptor: %w", err)
	}
	if wire.LiveReady == nil || wire.ExercisedNodes == nil ||
		wire.Deployments == nil || wire.Files == nil {
		return Result{}, errors.New(
			"descriptor must explicitly contain live_ready, exercised_nodes, deployments, and files",
		)
	}
	descriptor := Descriptor{
		Schema:         wire.Schema,
		TopologyID:     wire.TopologyID,
		Protocol:       wire.Protocol,
		LiveReady:      *wire.LiveReady,
		ExercisedNodes: *wire.ExercisedNodes,
		Deployments:    *wire.Deployments,
		Files:          *wire.Files,
	}
	if err := validateDescriptor(descriptor); err != nil {
		return Result{}, err
	}

	expectedNames := make(map[string]struct{}, len(AllowedPublicBasenames)+1)
	expectedNames[DescriptorName] = struct{}{}
	for _, name := range AllowedPublicBasenames {
		expectedNames[name] = struct{}{}
	}
	entries, err := readRootDirectory(root)
	if err != nil {
		return Result{}, err
	}
	if len(entries) != len(expectedNames) {
		return Result{}, fmt.Errorf(
			"bundle contains %d entries, want exactly %d",
			len(entries), len(expectedNames),
		)
	}
	for _, entry := range entries {
		if _, ok := expectedNames[entry.Name()]; !ok {
			return Result{}, fmt.Errorf(
				"bundle contains unallowlisted entry %q", entry.Name(),
			)
		}
	}

	publicBytes := make(map[string][]byte, len(descriptor.Files))
	var total int64
	for _, declared := range descriptor.Files {
		data, info, readErr := readCheckedPublic(
			root, declared.Name, MaxPublicFileBytes,
		)
		if readErr != nil {
			return Result{}, fmt.Errorf(
				"read public file %q: %w", declared.Name, readErr,
			)
		}
		total += info.Size()
		if total > MaxPublicBundleBytes {
			return Result{}, fmt.Errorf(
				"public bundle exceeds %d-byte aggregate limit",
				MaxPublicBundleBytes,
			)
		}
		if info.Size() != declared.Size {
			return Result{}, fmt.Errorf(
				"public file %q size is %d, want %d",
				declared.Name, info.Size(), declared.Size,
			)
		}
		digest := sha256.Sum256(data)
		actual := hex.EncodeToString(digest[:])
		if actual != declared.SHA256 {
			return Result{}, fmt.Errorf(
				"public file %q SHA-256 mismatch", declared.Name,
			)
		}
		if err := inspectPublicDocumentNames(declared.Name, data); err != nil {
			return Result{}, fmt.Errorf(
				"inspect public file %q: %w", declared.Name, err,
			)
		}
		publicBytes[declared.Name] = data
	}

	if err := validatePublicDocuments(publicBytes, descriptor); err != nil {
		return Result{}, err
	}
	finalEntries, err := readRootDirectory(root)
	if err != nil {
		return Result{}, err
	}
	if !reflect.DeepEqual(entryNames(entries), entryNames(finalEntries)) {
		return Result{}, errors.New(
			"bundle directory entries changed during validation",
		)
	}
	finalRootInfo, err := root.Stat(".")
	if err != nil {
		return Result{}, fmt.Errorf("restat retained bundle root: %w", err)
	}
	if !os.SameFile(rootInfo, finalRootInfo) ||
		finalRootInfo.Mode() != rootInfo.Mode() {
		return Result{}, errors.New(
			"bundle directory identity or mode changed during validation",
		)
	}

	descriptorDigest := sha256.Sum256(descriptorBytes)
	bundleDigest := digestBundle(descriptorDigest, descriptor.Files)
	return Result{
		TopologyID:       descriptor.TopologyID,
		DescriptorSHA256: hex.EncodeToString(descriptorDigest[:]),
		BundleSHA256:     hex.EncodeToString(bundleDigest[:]),
		PublicFileCount:  len(descriptor.Files),
	}, nil
}

func validateDescriptor(descriptor Descriptor) error {
	if descriptor.Schema != Schema {
		return fmt.Errorf(
			"descriptor schema is %q, want %q", descriptor.Schema, Schema,
		)
	}
	if descriptor.Protocol != ProtocolVersion {
		return fmt.Errorf(
			"protocol version is %q, want %q",
			descriptor.Protocol, ProtocolVersion,
		)
	}
	if !validIdentifier(descriptor.TopologyID) {
		return errors.New("topology_id is invalid")
	}
	if descriptor.LiveReady {
		return errors.New("E0 descriptor must set live_ready to false")
	}
	if descriptor.ExercisedNodes == nil || len(descriptor.ExercisedNodes) != 0 {
		return errors.New(
			"E0 descriptor must contain an explicit empty exercised_nodes array",
		)
	}
	if descriptor.Deployments == nil ||
		len(descriptor.Deployments) != expectedDeploymentRows {
		return fmt.Errorf(
			"deployments must contain exactly %d rows",
			expectedDeploymentRows,
		)
	}

	instanceIDs := make(map[string]struct{}, expectedDeploymentRows)
	logicalIDs := make(map[string]struct{}, expectedDeploymentRows*2)
	rows := make(map[string]Deployment, expectedDeploymentRows)
	for index, row := range descriptor.Deployments {
		if row.Role != requiredRoles[index] {
			return fmt.Errorf(
				"deployment %d role is %q, want %q",
				index, row.Role, requiredRoles[index],
			)
		}
		if !uuidPattern.MatchString(row.InstanceUUID) ||
			row.InstanceUUID == "00000000-0000-0000-0000-000000000000" {
			return fmt.Errorf(
				"deployment role %q has invalid instance UUID", row.Role,
			)
		}
		if _, duplicate := instanceIDs[row.InstanceUUID]; duplicate {
			return errors.New("deployment instance UUIDs must be unique")
		}
		instanceIDs[row.InstanceUUID] = struct{}{}
		for name, value := range map[string]string{
			"node_id":     row.NodeID,
			"service_id":  row.ServiceID,
			"provider":    row.Provider,
			"operator_id": row.OperatorID,
		} {
			if !validIdentifier(value) {
				return fmt.Errorf(
					"deployment role %q has invalid %s", row.Role, name,
				)
			}
		}
		for _, value := range []string{row.NodeID, row.ServiceID} {
			if _, duplicate := logicalIDs[value]; duplicate {
				return errors.New(
					"deployment node and service IDs must be globally unique",
				)
			}
			logicalIDs[value] = struct{}{}
		}
		rows[row.Role] = row
	}
	exit := rows[RoleExit]
	for _, entryRole := range []string{
		RoleEntryPrimary, RoleEntrySecondary,
	} {
		entry := rows[entryRole]
		if entry.Provider == exit.Provider ||
			entry.OperatorID == exit.OperatorID {
			return fmt.Errorf(
				"%s and exit require provider and operator separation",
				entryRole,
			)
		}
	}

	if descriptor.Files == nil ||
		len(descriptor.Files) != len(AllowedPublicBasenames) {
		return fmt.Errorf(
			"files must contain exactly %d rows",
			len(AllowedPublicBasenames),
		)
	}
	for index, file := range descriptor.Files {
		if file.Name != AllowedPublicBasenames[index] {
			return fmt.Errorf(
				"file inventory row %d is %q, want %q",
				index, file.Name, AllowedPublicBasenames[index],
			)
		}
		if file.Size < 1 || file.Size > MaxPublicFileBytes {
			return fmt.Errorf(
				"public file %q size is outside [1,%d]",
				file.Name, MaxPublicFileBytes,
			)
		}
		if !hexDigestPattern.MatchString(file.SHA256) {
			return fmt.Errorf(
				"public file %q SHA-256 is invalid", file.Name,
			)
		}
	}
	return nil
}

func validatePublicDocuments(
	documents map[string][]byte,
	descriptor Descriptor,
) error {
	trust, err := parseTrustState(
		documents["accepted-trust-state-v2.json"],
	)
	if err != nil {
		return fmt.Errorf("validate accepted trust state: %w", err)
	}
	if err := parseCarrierRoot(documents["carrier-root-ca.pem"]); err != nil {
		return fmt.Errorf("validate carrier root CA: %w", err)
	}
	pins, err := parseControllerPins(
		documents["controller-pq-pins.json"],
	)
	if err != nil {
		return fmt.Errorf("validate controller pins: %w", err)
	}
	manifest, manifestDigest, err := parseGatewayManifest(
		documents["gateway-manifest-v2.json"],
	)
	if err != nil {
		return fmt.Errorf("validate gateway manifest: %w", err)
	}
	if trust.ManifestDigest != manifestDigest ||
		trust.HighestSequence != manifest.Sequence {
		return errors.New(
			"accepted trust state does not bind the gateway manifest",
		)
	}
	if _, err := pins.Verifier(
		manifest.AuthAlgorithm, manifest.AuthKeyID,
	); err != nil {
		return fmt.Errorf(
			"gateway manifest signer is absent from controller pins: %w",
			err,
		)
	}
	if err := validateDeploymentBindings(descriptor, manifest); err != nil {
		return err
	}
	if err := parseLinuxProfile(
		documents["linux-profile.json"], manifest, manifestDigest, pins,
		descriptor,
	); err != nil {
		return fmt.Errorf("validate Linux profile: %w", err)
	}
	checkpoint, err := parseTransparencyLog(
		documents["transparency.jsonl"], pins, manifestDigest,
	)
	if err != nil {
		return fmt.Errorf("validate transparency log: %w", err)
	}
	if checkpoint != trust.Checkpoint {
		return errors.New(
			"accepted trust-state checkpoint does not equal the transparency log checkpoint",
		)
	}
	return nil
}

func validateDeploymentBindings(
	descriptor Descriptor,
	manifest gatewaymanifest.ManifestV2,
) error {
	rows := make(map[string]Deployment, len(descriptor.Deployments))
	for _, row := range descriptor.Deployments {
		rows[row.Role] = row
	}
	control := rows[RoleControl]
	if control.NodeID != manifest.ControllerID ||
		control.ServiceID != "service-"+manifest.ControllerID {
		return errors.New(
			"control deployment does not bind the manifest controller identity",
		)
	}
	for role, manifestRole := range map[string]string{
		RoleEntryPrimary:   gatewaymanifest.RoleEntry,
		RoleEntrySecondary: gatewaymanifest.RoleEntry,
		RoleExit:           gatewaymanifest.RoleExit,
	} {
		row := rows[role]
		node, err := manifest.Node(row.NodeID)
		if err != nil {
			return fmt.Errorf(
				"deployment role %q node is absent from manifest: %w",
				role, err,
			)
		}
		if node.Provider != row.Provider ||
			node.OperatorID != row.OperatorID ||
			!containsString(node.Roles, manifestRole) {
			return fmt.Errorf(
				"deployment role %q differs from its manifest node", role,
			)
		}
		if _, err := node.Transport(row.ServiceID); err != nil {
			return fmt.Errorf(
				"deployment role %q service is absent from manifest node: %w",
				role, err,
			)
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func parseTrustState(data []byte) (gatewaymanifest.TrustStateV2, error) {
	var state gatewaymanifest.TrustStateV2
	if err := decodeStrictJSON(data, &state); err != nil {
		return state, err
	}
	if state.Format != gatewaymanifest.TrustStateFormatV2 ||
		state.HighestSequence == 0 ||
		!hexDigestPattern.MatchString(state.ManifestDigest) ||
		state.Checkpoint.Size == 0 ||
		!hexDigestPattern.MatchString(state.Checkpoint.ReceiptDigest) {
		return state, errors.New("trust state fields are invalid")
	}
	return state, nil
}

func parseCarrierRoot(data []byte) error {
	remaining := data
	certificates := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(bytes.TrimSpace(remaining)) != 0 {
				return errors.New("PEM contains non-certificate bytes")
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("PEM block %q is not an unadorned certificate", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse X.509 certificate: %w", err)
		}
		if !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("carrier root certificate is not a certificate-signing CA")
		}
		certificates++
		remaining = rest
	}
	if certificates != 1 {
		return fmt.Errorf(
			"carrier root file contains %d certificates, want exactly one",
			certificates,
		)
	}
	return nil
}

func parseControllerPins(data []byte) (*pqauth.VerifierSet, error) {
	var document pqauth.VerifierSetFile
	if err := decodeStrictJSON(data, &document); err != nil {
		return nil, err
	}
	if document.Format != "winn-pq-verifier-set/v1" ||
		len(document.Keys) == 0 || len(document.Keys) > 2 {
		return nil, errors.New("controller verifier-set identity is invalid")
	}
	for algorithm, encodedKeys := range document.Keys {
		if algorithm != pqauth.MLDSA65 && algorithm != pqauth.MLDSA87 {
			return nil, fmt.Errorf(
				"controller verifier set uses unsupported algorithm %q",
				algorithm,
			)
		}
		if len(encodedKeys) == 0 || len(encodedKeys) > 4 {
			return nil, fmt.Errorf(
				"controller verifier set has invalid %s key count",
				algorithm,
			)
		}
		for _, encoded := range encodedKeys {
			publicKey, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				return nil, errors.New(
					"controller verifier key is not strict Base64",
				)
			}
			if _, err := pqauth.NewVerifier(algorithm, publicKey); err != nil {
				return nil, fmt.Errorf(
					"parse controller verifier key: %w", err,
				)
			}
		}
	}
	// LoadVerifierSet performs the same parse from a pathname. Construct the
	// immutable in-memory set through its public document constructor inputs
	// instead, so this verifier remains zero-write.
	return verifierSetFromDocument(document)
}

func verifierSetFromDocument(
	document pqauth.VerifierSetFile,
) (*pqauth.VerifierSet, error) {
	verifiers := make([]*pqauth.Verifier, 0)
	for algorithm, encodedKeys := range document.Keys {
		for _, encoded := range encodedKeys {
			publicKey, _ := base64.StdEncoding.Strict().DecodeString(encoded)
			verifier, err := pqauth.NewVerifier(algorithm, publicKey)
			if err != nil {
				return nil, err
			}
			verifiers = append(verifiers, verifier)
		}
	}
	return pqauth.NewVerifierSet(verifiers...)
}

func parseGatewayManifest(
	data []byte,
) (gatewaymanifest.ManifestV2, string, error) {
	var manifest gatewaymanifest.ManifestV2
	if err := decodeStrictJSON(data, &manifest); err != nil {
		return manifest, "", err
	}
	if _, err := gatewaymanifest.EncodeV2(manifest); err != nil {
		return manifest, "", err
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(
		manifest.AuthSignature,
	); err != nil {
		return manifest, "", errors.New(
			"gateway manifest signature is not strict Base64",
		)
	}
	digest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		return manifest, "", err
	}
	return manifest, digest, nil
}

func parseLinuxProfile(
	data []byte,
	manifest gatewaymanifest.ManifestV2,
	manifestDigest string,
	pins *pqauth.VerifierSet,
	descriptor Descriptor,
) error {
	var profile directawg.LinuxDeploymentProfile
	if err := decodeStrictJSON(data, &profile); err != nil {
		return err
	}
	issued, issuedErr := time.Parse(time.RFC3339, profile.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339, profile.ExpiresAt)
	if profile.Format != directawg.LinuxDeploymentProfileFormat ||
		profile.ManifestDigest != manifestDigest ||
		profile.NodeID == "" || profile.TransportID == "" ||
		issuedErr != nil || expiresErr != nil || !expires.After(issued) ||
		expires.Sub(issued) > 7*24*time.Hour ||
		profile.AuthAlgorithm != manifest.AuthAlgorithm ||
		profile.AuthKeyID != manifest.AuthKeyID ||
		profile.AuthSignature == "" {
		//lint:ignore ST1005 Linux is a proper noun.
		return errors.New("Linux deployment profile identity is invalid")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(
		profile.AuthSignature,
	); err != nil {
		//lint:ignore ST1005 Linux is a proper noun.
		return errors.New("Linux profile signature is not strict Base64")
	}
	if _, err := pins.Verifier(
		profile.AuthAlgorithm, profile.AuthKeyID,
	); err != nil {
		//lint:ignore ST1005 Linux is a proper noun.
		return fmt.Errorf("Linux profile signer is absent from pins: %w", err)
	}
	entryPrimary := descriptor.Deployments[1]
	if profile.NodeID != entryPrimary.NodeID ||
		profile.TransportID != entryPrimary.ServiceID {
		//lint:ignore ST1005 Linux is a proper noun.
		return errors.New(
			"Linux profile does not bind the primary entry deployment",
		)
	}
	node, err := manifest.Node(profile.NodeID)
	if err != nil {
		return err
	}
	if _, err := node.Transport(profile.TransportID); err != nil {
		return err
	}
	if profile.Interface.InnerAddressPool == "" ||
		len(profile.Interface.AllowedIPs) == 0 ||
		len(profile.Interface.VerificationRoutes) == 0 ||
		profile.Interface.MTU < 576 ||
		profile.Interface.ListenPortMin == 0 ||
		profile.Interface.ListenPortMax < profile.Interface.ListenPortMin ||
		profile.Probe.DNSResolver == "" ||
		profile.Probe.DNSQueryName == "" ||
		len(profile.Probe.ExpectedDNSAnswers) == 0 ||
		profile.Probe.CanaryEndpoint == "" ||
		profile.Probe.TimeoutMilliseconds == 0 {
		//lint:ignore ST1005 Linux is a proper noun.
		return errors.New("Linux deployment profile policy is incomplete")
	}
	if _, _, err := directawg.VerifyLinuxDeploymentProfile(
		profile, manifest, pins, issued.Add(time.Nanosecond),
	); err != nil {
		return fmt.Errorf(
			"authoritative Linux deployment-profile validation: %w", err,
		)
	}
	return nil
}

func parseTransparencyLog(
	data []byte,
	pins *pqauth.VerifierSet,
	selectedManifestDigest string,
) (transparency.Checkpoint, error) {
	var previous string
	var count uint64
	selectedSeen := false
	lines := bytes.Split(data, []byte{'\n'})
	for index, line := range lines {
		if len(line) == 0 {
			if index != len(lines)-1 {
				return transparency.Checkpoint{}, errors.New(
					"transparency log contains an empty row",
				)
			}
			continue
		}
		var receipt transparency.Receipt
		if err := decodeStrictJSON(line, &receipt); err != nil {
			return transparency.Checkpoint{}, err
		}
		count++
		timestamp, timeErr := time.Parse(time.RFC3339Nano, receipt.Timestamp)
		if receipt.Format != transparency.Format ||
			receipt.Sequence != count || timeErr != nil ||
			timestamp.Location() != time.UTC ||
			!hexDigestPattern.MatchString(receipt.ManifestDigest) ||
			receipt.PreviousReceiptDigest != previous ||
			receipt.AuthSignature == "" {
			return transparency.Checkpoint{}, fmt.Errorf(
				"transparency receipt %d fields are invalid", count,
			)
		}
		if receipt.ManifestDigest == selectedManifestDigest {
			selectedSeen = true
		}
		if _, err := pins.Verifier(
			receipt.AuthAlgorithm, receipt.AuthKeyID,
		); err != nil {
			return transparency.Checkpoint{}, fmt.Errorf(
				"transparency signer is absent from pins: %w", err,
			)
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(
			receipt.AuthSignature,
		); err != nil {
			return transparency.Checkpoint{}, errors.New(
				"transparency signature is not strict Base64",
			)
		}
		digest, err := transparency.Digest(receipt)
		if err != nil {
			return transparency.Checkpoint{}, err
		}
		previous = digest
	}
	if count == 0 {
		return transparency.Checkpoint{}, errors.New(
			"transparency log contains no receipts",
		)
	}
	if !selectedSeen {
		return transparency.Checkpoint{}, errors.New(
			"transparency log does not include the selected gateway manifest",
		)
	}
	return transparency.Checkpoint{
		Size: count, ReceiptDigest: previous,
	}, nil
}

func validIdentifier(value string) bool {
	return len(value) <= maxIdentifierBytes &&
		identifierPattern.MatchString(value)
}

func readRootDirectory(root *os.Root) ([]os.DirEntry, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open retained bundle directory: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return nil, fmt.Errorf("list retained bundle directory: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close retained bundle directory: %w", closeErr)
	}
	return entries, nil
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	slices.Sort(names)
	return names
}

func readCheckedPublic(
	root *os.Root,
	name string,
	maximum int64,
) ([]byte, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, errors.New("path is not a regular file")
	}
	if before.Mode().Perm()&0o022 != 0 {
		return nil, nil, fmt.Errorf(
			"public file is group/other writable (%04o)",
			before.Mode().Perm(),
		)
	}
	if nlink, ok := linkCount(before); !ok {
		return nil, nil, errors.New(
			"platform does not expose a hardlink count for public files",
		)
	} else if nlink != 1 {
		return nil, nil, fmt.Errorf(
			"public file has %d hardlinks, want exactly one", nlink,
		)
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, nil, errors.New(
			"validated file target changed before it was opened",
		)
	}
	if nlink, ok := linkCount(opened); !ok || nlink != 1 {
		return nil, nil, errors.New(
			"opened public file does not have exactly one hardlink",
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maximum {
		return nil, nil, fmt.Errorf(
			"file exceeds %d-byte limit", maximum,
		)
	}
	afterFD, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	afterPath, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	afterFDLinks, afterFDLinksOK := linkCount(afterFD)
	afterPathLinks, afterPathLinksOK := linkCount(afterPath)
	if !os.SameFile(opened, afterFD) || !os.SameFile(opened, afterPath) ||
		opened.Size() != int64(len(data)) ||
		afterFD.Size() != int64(len(data)) ||
		afterPath.Size() != int64(len(data)) ||
		afterFD.Mode() != opened.Mode() ||
		afterPath.Mode() != opened.Mode() ||
		!afterFD.ModTime().Equal(opened.ModTime()) ||
		!afterPath.ModTime().Equal(opened.ModTime()) ||
		!afterFDLinksOK || !afterPathLinksOK ||
		afterFDLinks != 1 || afterPathLinks != 1 {
		return nil, nil, errors.New(
			"public file identity, size, mode, timestamp, or link count changed while it was read",
		)
	}
	return data, opened, nil
}

func linkCount(info os.FileInfo) (uint64, bool) {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0, false
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, false
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return field.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64:
		if field.Int() < 0 {
			return 0, false
		}
		// #nosec G115 -- the negative signed range was rejected above.
		return uint64(field.Int()), true
	default:
		return 0, false
	}
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains more than one value")
		}
		return err
	}
	return nil
}

func inspectJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := inspectJSONValue(decoder, "$", 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return nil
}

func inspectPublicDocumentNames(name string, data []byte) error {
	switch filepath.Ext(name) {
	case ".json":
		return inspectJSONNames(data)
	case ".jsonl":
		lines := bytes.Split(data, []byte{'\n'})
		records := 0
		for index, line := range lines {
			if len(line) == 0 {
				if index != len(lines)-1 {
					return fmt.Errorf("JSONL row %d is empty", index+1)
				}
				continue
			}
			if err := inspectJSONNames(line); err != nil {
				return fmt.Errorf("JSONL row %d: %w", index+1, err)
			}
			records++
		}
		if records == 0 {
			return errors.New("JSONL file contains no records")
		}
	}
	return nil
}

func inspectJSONValue(
	decoder *json.Decoder,
	path string,
	depth int,
) error {
	if depth > MaxJSONDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, tokenErr := decoder.Token()
			if tokenErr != nil {
				return tokenErr
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate JSON field %s.%s", path, name)
			}
			seen[name] = struct{}{}
			if secretJSONName(name) {
				return fmt.Errorf("secret-named JSON field %s.%s", path, name)
			}
			if err := inspectJSONValue(
				decoder, path+"."+name, depth+1,
			); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		index := 0
		for decoder.More() {
			if err := inspectJSONValue(
				decoder,
				path+"["+strconv.Itoa(index)+"]",
				depth+1,
			); err != nil {
				return err
			}
			index++
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func secretJSONName(name string) bool {
	normalized := strings.ToLower(name)
	normalized = strings.NewReplacer(
		"_", "", "-", "", ".", "",
	).Replace(normalized)
	for _, forbidden := range secretFieldNames {
		if normalized == forbidden {
			return true
		}
	}
	return false
}

func digestBundle(
	descriptorDigest [sha256.Size]byte,
	files []PublicFile,
) [sha256.Size]byte {
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, bundleDigestDomain)
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(descriptorDigest[:])
	for _, file := range files {
		_, _ = hasher.Write([]byte{0})
		_, _ = io.WriteString(hasher, file.Name)
		_, _ = hasher.Write([]byte{0})
		_, _ = io.WriteString(hasher, strconv.FormatInt(file.Size, 10))
		_, _ = hasher.Write([]byte{0})
		digest, _ := hex.DecodeString(file.SHA256)
		_, _ = hasher.Write(digest)
	}
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}
