package gatewaymanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yosida95/uritemplate/v3"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/wcf3"
)

const (
	FormatV2              = "winn-gateway-manifest/v2"
	MaxV2Nodes            = 64
	MaxV2Transports       = 256
	MaxV2Circuits         = 64
	MaxV2RegionalPolicies = 32
	MinimumClientV3       = connectivity.Version

	RoleCarrier    = "carrier"
	RoleEntry      = "entry"
	RoleExit       = "exit"
	RoleController = "controller"
	RoleIssuer     = "issuer"
	RoleLab        = "lab"

	AuthAWGPSK = "awg-psk"
)

var requiredV2Capabilities = []string{
	"adaptive-inner-mtu",
	"awg-handshake-readiness",
	"ech-required-public-tls",
	"signed-gateway-manifest",
	"typed-transports-v2",
	"typed-two-hop-circuits",
	"wcf3-attempt-binding",
}

type TransportV2 struct {
	ID                  string               `json:"id"`
	Type                connectivity.Carrier `json:"type"`
	Endpoint            string               `json:"endpoint"`
	ServerName          string               `json:"server_name,omitempty"`
	IPv4Hints           []string             `json:"ipv4_hints,omitempty"`
	IPv6Hints           []string             `json:"ipv6_hints,omitempty"`
	ECHConfigList       string               `json:"ech_config_list,omitempty"`
	ALPN                []string             `json:"alpn,omitempty"`
	Suite               string               `json:"suite"`
	AuthenticationModes []string             `json:"authentication_modes"`
	TokenKeyID          string               `json:"token_key_id,omitempty"`
	PublicTarget        string               `json:"public_target,omitempty"`
	PublicAWGKey        string               `json:"public_awg_key"`
	FixedBackend        string               `json:"fixed_backend,omitempty"`
	MinInnerDatagram    int                  `json:"min_inner_datagram"`
	MaxInnerDatagram    int                  `json:"max_inner_datagram"`
	RegionPolicy        string               `json:"region_policy,omitempty"`
	SidecarConfigDigest string               `json:"sidecar_config_digest,omitempty"`
	Capabilities        []string             `json:"capabilities"`
}

type NodeV2 struct {
	ID           string        `json:"id"`
	OperatorID   string        `json:"operator_id"`
	Provider     string        `json:"provider"`
	Roles        []string      `json:"roles"`
	Transports   []TransportV2 `json:"transports"`
	Capabilities []string      `json:"capabilities"`
}

type CamouflageTargetV2 struct {
	ServerName string   `json:"server_name"`
	Endpoint   string   `json:"endpoint"`
	ALPN       []string `json:"alpn"`
}

type RegionalPolicyV2 struct {
	ID        string               `json:"id"`
	Regions   []string             `json:"regions"`
	NotBefore string               `json:"not_before"`
	NotAfter  string               `json:"not_after"`
	Targets   []CamouflageTargetV2 `json:"targets"`
}

type HopV2 struct {
	NodeID           string `json:"node_id"`
	TransportID      string `json:"transport_id"`
	CredentialDomain string `json:"credential_domain"`
	CredentialKeyID  string `json:"credential_key_id"`
}

type CircuitV2 struct {
	ID    string            `json:"id"`
	Mode  connectivity.Mode `json:"mode"`
	Entry HopV2             `json:"entry"`
	Exit  HopV2             `json:"exit"`
}

type ManifestV2 struct {
	Format           string             `json:"format"`
	Sequence         uint64             `json:"sequence"`
	IssuedAt         string             `json:"issued_at"`
	ExpiresAt        string             `json:"expires_at"`
	ControllerID     string             `json:"controller_id"`
	Suite            string             `json:"suite"`
	MinimumClient    string             `json:"minimum_client"`
	PreviousDigest   string             `json:"previous_digest,omitempty"`
	Capabilities     []string           `json:"capabilities"`
	Nodes            []NodeV2           `json:"nodes"`
	Circuits         []CircuitV2        `json:"circuits,omitempty"`
	PrivacyTokenKeys []PrivacyTokenKey  `json:"privacy_token_keys,omitempty"`
	RegionalPolicies []RegionalPolicyV2 `json:"regional_policies,omitempty"`
	AuthAlgorithm    string             `json:"auth_algorithm"`
	AuthKeyID        string             `json:"auth_key_id"`
	AuthSignature    string             `json:"auth_signature"`
}

func SignV2(manifest *ManifestV2, signer *pqauth.Signer) error {
	if manifest == nil || signer == nil {
		return errors.New("v2 manifest and controller signer are required")
	}
	manifest.AuthAlgorithm = signer.Algorithm()
	manifest.AuthKeyID = signer.KeyID()
	manifest.AuthSignature = ""
	if err := validateV2(*manifest, time.Time{}, 0, false); err != nil {
		return err
	}
	message, err := unsignedCanonicalV2(*manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	clear(message)
	signature, err := pqauth.SignDomainMessage(
		pqauth.ManifestV2SignatureDomain, digest[:], signer,
	)
	clear(digest[:])
	if err != nil {
		return err
	}
	defer clear(signature)
	manifest.AuthSignature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func VerifyV2(
	manifest ManifestV2,
	pins *pqauth.VerifierSet,
	now time.Time,
	maxSkew time.Duration,
) error {
	if pins == nil {
		return errors.New("v2 manifest controller pins are required")
	}
	if err := validateV2(manifest, now, maxSkew, true); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(
		manifest.AuthSignature,
	)
	if err != nil || len(signature) == 0 {
		return errors.New("invalid v2 manifest signature encoding")
	}
	defer clear(signature)
	verifier, err := pins.Verifier(
		manifest.AuthAlgorithm, manifest.AuthKeyID,
	)
	if err != nil {
		return err
	}
	message, err := unsignedCanonicalV2(manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	clear(message)
	defer clear(digest[:])
	if err := pqauth.VerifyDomainMessage(
		pqauth.ManifestV2SignatureDomain, digest[:], signature, verifier,
	); err != nil {
		return fmt.Errorf("verify v2 gateway manifest: %w", err)
	}
	return nil
}

func LoadV2(path string) (ManifestV2, error) {
	data, err := securefile.ReadPublicIntegrity(path, MaxDocumentSize)
	if err != nil {
		return ManifestV2{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest ManifestV2
	if err := decoder.Decode(&manifest); err != nil {
		return ManifestV2{}, err
	}
	if err := requireManifestEOF(decoder); err != nil {
		return ManifestV2{}, err
	}
	return manifest, nil
}

func EncodeV2(manifest ManifestV2) ([]byte, error) {
	if err := validateV2(
		manifest, time.Time{}, 0, manifest.AuthSignature != "",
	); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(encoded)+1 > MaxDocumentSize {
		return nil, errors.New("v2 manifest exceeds document size limit")
	}
	return append(encoded, '\n'), nil
}

func DigestV2(manifest ManifestV2) (string, error) {
	if manifest.AuthSignature == "" {
		return "", errors.New("cannot digest an unsigned v2 manifest")
	}
	encoded, err := canonicalV2(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func RequiredV2Capabilities() []string {
	return slices.Clone(requiredV2Capabilities)
}

func (manifest ManifestV2) Node(id string) (NodeV2, error) {
	for _, node := range manifest.Nodes {
		if node.ID == id {
			return node, nil
		}
	}
	return NodeV2{}, fmt.Errorf("v2 gateway node %q is not in the manifest", id)
}

func (node NodeV2) Transport(id string) (TransportV2, error) {
	for _, transport := range node.Transports {
		if transport.ID == id {
			return transport, nil
		}
	}
	return TransportV2{}, fmt.Errorf(
		"transport %q is not in node %q", id, node.ID,
	)
}

func (manifest ManifestV2) RegionalPolicy(
	id string,
) (RegionalPolicyV2, error) {
	for _, policy := range manifest.RegionalPolicies {
		if policy.ID == id {
			return policy, nil
		}
	}
	return RegionalPolicyV2{}, fmt.Errorf(
		"regional policy %q is not in the manifest", id,
	)
}

func (manifest ManifestV2) Circuit(id string) (CircuitV2, error) {
	for _, circuit := range manifest.Circuits {
		if circuit.ID == id {
			return circuit, nil
		}
	}
	return CircuitV2{}, fmt.Errorf(
		"v2 circuit %q is not in the manifest", id,
	)
}

func unsignedCanonicalV2(manifest ManifestV2) ([]byte, error) {
	manifest.AuthSignature = ""
	return canonicalV2(manifest)
}

func canonicalV2(manifest ManifestV2) ([]byte, error) {
	return json.Marshal(manifest)
}

func validateV2(
	manifest ManifestV2,
	now time.Time,
	maxSkew time.Duration,
	requireSignature bool,
) error {
	if manifest.Format != FormatV2 || manifest.Sequence == 0 {
		return errors.New("unsupported v2 gateway manifest format or sequence")
	}
	if !protocol.ValidDeviceID(manifest.ControllerID) {
		return errors.New("invalid v2 manifest controller identity")
	}
	if !protocol.ValidSuite(manifest.Suite) {
		return errors.New("invalid v2 manifest hybrid TLS suite")
	}
	if manifest.MinimumClient != MinimumClientV3 {
		return errors.New("invalid v2 manifest minimum client")
	}
	issuedAt, expiresAt, err := validateV2Lifetime(
		manifest.IssuedAt, manifest.ExpiresAt, now, maxSkew,
	)
	if err != nil {
		return err
	}
	if manifest.PreviousDigest != "" &&
		!validDigest(manifest.PreviousDigest) {
		return errors.New("invalid v2 previous manifest digest")
	}
	if err := validateCapabilities(
		manifest.Capabilities, requiredV2Capabilities,
	); err != nil {
		return fmt.Errorf("v2 manifest capabilities: %w", err)
	}
	if len(manifest.Nodes) == 0 || len(manifest.Nodes) > MaxV2Nodes {
		return errors.New("v2 gateway manifest node count is invalid")
	}

	tokenKeys := make(
		map[string]PrivacyTokenKey, len(manifest.PrivacyTokenKeys),
	)
	for _, key := range manifest.PrivacyTokenKeys {
		if err := validateTokenKey(key, issuedAt, expiresAt); err != nil {
			return fmt.Errorf("v2 privacy token key %q: %w", key.ID, err)
		}
		if !validShortToken(key.IssuerDomain, 64) ||
			!validCredentialScope(key.Scope) {
			return fmt.Errorf(
				"v2 privacy token key %q has invalid issuer or scope",
				key.ID,
			)
		}
		if _, duplicate := tokenKeys[key.ID]; duplicate {
			return fmt.Errorf("duplicate v2 privacy token key %q", key.ID)
		}
		tokenKeys[key.ID] = key
	}

	policies := make(map[string]RegionalPolicyV2, len(manifest.RegionalPolicies))
	if len(manifest.RegionalPolicies) > MaxV2RegionalPolicies {
		return errors.New("too many v2 regional policies")
	}
	for _, policy := range manifest.RegionalPolicies {
		if err := validateRegionalPolicyV2(
			policy, issuedAt, expiresAt,
		); err != nil {
			return fmt.Errorf("v2 regional policy %q: %w", policy.ID, err)
		}
		if _, duplicate := policies[policy.ID]; duplicate {
			return fmt.Errorf("duplicate v2 regional policy %q", policy.ID)
		}
		policies[policy.ID] = policy
	}

	nodesByID := make(map[string]NodeV2, len(manifest.Nodes))
	transportIDs := make(map[string]struct{})
	transportOwners := make(map[string]transportOwnerV2)
	transportCount := 0
	for _, node := range manifest.Nodes {
		if err := validateNodeV2(
			node, manifest.Suite, tokenKeys, policies, now, maxSkew,
		); err != nil {
			return fmt.Errorf("v2 gateway node %q: %w", node.ID, err)
		}
		if _, duplicate := nodesByID[node.ID]; duplicate {
			return fmt.Errorf("duplicate v2 gateway node %q", node.ID)
		}
		nodesByID[node.ID] = node
		for _, transport := range node.Transports {
			transportCount++
			if _, duplicate := transportIDs[transport.ID]; duplicate {
				return fmt.Errorf(
					"duplicate global v2 transport ID %q",
					transport.ID,
				)
			}
			transportIDs[transport.ID] = struct{}{}
			transportOwners[transport.ID] = transportOwnerV2{
				node:      node,
				transport: transport,
			}
		}
	}
	if transportCount == 0 || transportCount > MaxV2Transports {
		return errors.New("v2 gateway transport count is invalid")
	}
	if err := validateCircuitsV2(
		manifest.Circuits, nodesByID, transportOwners, tokenKeys,
	); err != nil {
		return err
	}
	if manifest.AuthAlgorithm != pqauth.MLDSA65 &&
		manifest.AuthAlgorithm != pqauth.MLDSA87 {
		return errors.New("invalid v2 manifest authentication algorithm")
	}
	if manifest.AuthAlgorithm != protocol.RequiredAuthAlgorithm(
		manifest.Suite,
	) {
		return errors.New(
			"v2 manifest authentication is weaker than its suite",
		)
	}
	if !validDigest(manifest.AuthKeyID) {
		return errors.New("invalid v2 manifest authentication key ID")
	}
	if requireSignature && manifest.AuthSignature == "" {
		return errors.New("v2 gateway manifest signature is required")
	}
	if len(manifest.AuthSignature) > 10<<10 {
		return errors.New("v2 gateway manifest signature is too large")
	}
	return nil
}

func validateV2Lifetime(
	issuedText string,
	expiresText string,
	now time.Time,
	maxSkew time.Duration,
) (time.Time, time.Time, error) {
	if maxSkew < 0 || maxSkew > DefaultClockSkew {
		return time.Time{}, time.Time{},
			errors.New("v2 manifest clock skew exceeds the frozen limit")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, issuedText)
	if err != nil || issuedAt.Location() != time.UTC {
		return time.Time{}, time.Time{},
			errors.New("v2 issued_at must be RFC3339Nano UTC")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresText)
	if err != nil || expiresAt.Location() != time.UTC {
		return time.Time{}, time.Time{},
			errors.New("v2 expires_at must be RFC3339Nano UTC")
	}
	if !expiresAt.After(issuedAt) ||
		expiresAt.Sub(issuedAt) > MaxLifetime {
		return time.Time{}, time.Time{},
			errors.New("v2 manifest lifetime is invalid")
	}
	if !now.IsZero() &&
		(now.Before(issuedAt.Add(-maxSkew)) ||
			!now.Before(expiresAt.Add(maxSkew))) {
		return time.Time{}, time.Time{},
			errors.New("v2 gateway manifest is not currently valid")
	}
	return issuedAt, expiresAt, nil
}

func validateNodeV2(
	node NodeV2,
	manifestSuite string,
	tokenKeys map[string]PrivacyTokenKey,
	policies map[string]RegionalPolicyV2,
	now time.Time,
	maxSkew time.Duration,
) error {
	if !protocol.ValidDeviceID(node.ID) ||
		!protocol.ValidDeviceID(node.OperatorID) ||
		!validShortToken(node.Provider, 64) {
		return errors.New("invalid node, operator, or provider identity")
	}
	if err := validateRolesV2(node.Roles); err != nil {
		return err
	}
	if len(node.Transports) == 0 ||
		len(node.Transports) > MaxV2Transports {
		return errors.New("node transport count is invalid")
	}
	if err := validateCapabilities(node.Capabilities, nil); err != nil {
		return fmt.Errorf("node capabilities: %w", err)
	}
	transportIDs := make(map[string]struct{}, len(node.Transports))
	for _, transport := range node.Transports {
		if err := validateTransportV2(
			transport, manifestSuite, tokenKeys, policies, now, maxSkew,
		); err != nil {
			return fmt.Errorf("transport %q: %w", transport.ID, err)
		}
		if _, duplicate := transportIDs[transport.ID]; duplicate {
			return fmt.Errorf("duplicate transport %q", transport.ID)
		}
		transportIDs[transport.ID] = struct{}{}
	}
	return nil
}

func validateRolesV2(roles []string) error {
	if len(roles) == 0 || len(roles) > 2 {
		return errors.New("node roles are required")
	}
	seen := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		switch role {
		case RoleCarrier, RoleEntry, RoleExit,
			RoleController, RoleIssuer, RoleLab:
		default:
			return fmt.Errorf("unsupported node role %q", role)
		}
		if _, duplicate := seen[role]; duplicate {
			return fmt.Errorf("duplicate node role %q", role)
		}
		seen[role] = struct{}{}
	}
	validCombination := false
	switch {
	case len(seen) == 1:
		for _, role := range []string{
			RoleCarrier, RoleController, RoleIssuer, RoleLab,
		} {
			if _, ok := seen[role]; ok {
				validCombination = true
				break
			}
		}
	case len(seen) == 2:
		_, carrier := seen[RoleCarrier]
		_, entry := seen[RoleEntry]
		_, exit := seen[RoleExit]
		validCombination = carrier && (entry != exit)
	}
	if !validCombination {
		return errors.New("conflicting v2 production node roles")
	}
	return nil
}

type transportOwnerV2 struct {
	node      NodeV2
	transport TransportV2
}

func validateCircuitsV2(
	circuits []CircuitV2,
	nodes map[string]NodeV2,
	transports map[string]transportOwnerV2,
	tokenKeys map[string]PrivacyTokenKey,
) error {
	if len(circuits) > MaxV2Circuits {
		return errors.New("too many v2 two-hop circuits")
	}
	referenced := make(map[string]struct{})
	circuitIDs := make(map[string]struct{}, len(circuits))
	for _, circuit := range circuits {
		if !protocol.ValidDeviceID(circuit.ID) {
			return errors.New("v2 circuit ID is invalid")
		}
		if _, collision := transports[circuit.ID]; collision {
			return errors.New(
				"v2 circuit ID collides with transport ID",
			)
		}
		if _, duplicate := circuitIDs[circuit.ID]; duplicate {
			return errors.New("duplicate v2 circuit ID")
		}
		circuitIDs[circuit.ID] = struct{}{}
		var expected connectivity.Carrier
		switch circuit.Mode {
		case connectivity.ModePrivateRelay:
			expected = connectivity.CarrierNativeTwoHop
		case connectivity.ModeMaximumPrivacy:
			expected = connectivity.CarrierPrivacyTwoHop
		default:
			return errors.New("v2 circuit mode is not two-hop")
		}
		if !validShortToken(circuit.Entry.CredentialDomain, 64) ||
			!validShortToken(circuit.Exit.CredentialDomain, 64) ||
			!validDigest(circuit.Entry.CredentialKeyID) ||
			!validDigest(circuit.Exit.CredentialKeyID) ||
			circuit.Entry.CredentialDomain ==
				circuit.Exit.CredentialDomain ||
			circuit.Entry.CredentialKeyID ==
				circuit.Exit.CredentialKeyID {
			return errors.New(
				"v2 circuit requires independent credential domains and keys",
			)
		}
		if circuit.Entry.NodeID == circuit.Exit.NodeID {
			return errors.New("v2 circuit co-hosts entry and exit")
		}
		entryNode, entryOK := nodes[circuit.Entry.NodeID]
		exitNode, exitOK := nodes[circuit.Exit.NodeID]
		if !entryOK || !exitOK ||
			!slices.Contains(entryNode.Roles, RoleEntry) ||
			!slices.Contains(exitNode.Roles, RoleExit) {
			return errors.New("v2 circuit hop roles are invalid")
		}
		if entryNode.OperatorID == exitNode.OperatorID ||
			entryNode.Provider == exitNode.Provider {
			return errors.New(
				"v2 circuit entry and exit lack operator/provider separation",
			)
		}
		entry, entryTransportOK := transports[circuit.Entry.TransportID]
		exit, exitTransportOK := transports[circuit.Exit.TransportID]
		if !entryTransportOK || !exitTransportOK ||
			entry.node.ID != entryNode.ID ||
			exit.node.ID != exitNode.ID ||
			entry.transport.Type != expected ||
			exit.transport.Type != expected {
			return errors.New("v2 circuit transport binding is invalid")
		}
		entryKey, entryKeyOK := tokenKeys[circuit.Entry.CredentialKeyID]
		exitKey, exitKeyOK := tokenKeys[circuit.Exit.CredentialKeyID]
		if !entryKeyOK || !exitKeyOK ||
			entry.transport.TokenKeyID != circuit.Entry.CredentialKeyID ||
			exit.transport.TokenKeyID != circuit.Exit.CredentialKeyID ||
			!slices.Contains(
				entry.transport.AuthenticationModes, AuthAnonymousToken,
			) ||
			!slices.Contains(
				exit.transport.AuthenticationModes, AuthAnonymousToken,
			) {
			return errors.New(
				"v2 circuit credentials are not bound to anonymous hop transports",
			)
		}
		if entryKey.Scope != circuit.Entry.CredentialDomain ||
			exitKey.Scope != circuit.Exit.CredentialDomain ||
			entryKey.Scope == exitKey.Scope ||
			entryKey.IssuerDomain == exitKey.IssuerDomain ||
			entryKey.PublicKey == exitKey.PublicKey {
			return errors.New(
				"v2 circuit lacks independent issuer, credential, or key material",
			)
		}
		referenced[entry.transport.ID] = struct{}{}
		referenced[exit.transport.ID] = struct{}{}
	}
	for id, owner := range transports {
		if owner.transport.Type != connectivity.CarrierNativeTwoHop &&
			owner.transport.Type != connectivity.CarrierPrivacyTwoHop {
			continue
		}
		if _, ok := referenced[id]; !ok {
			return fmt.Errorf(
				"two-hop transport %q is not bound to a circuit", id,
			)
		}
	}
	return nil
}

func validateTransportV2(
	transport TransportV2,
	manifestSuite string,
	tokenKeys map[string]PrivacyTokenKey,
	policies map[string]RegionalPolicyV2,
	now time.Time,
	maxSkew time.Duration,
) error {
	if !protocol.ValidDeviceID(transport.ID) ||
		!connectivity.ValidCarrier(transport.Type) {
		return errors.New("invalid transport ID or type")
	}
	if transport.Suite != manifestSuite ||
		!protocol.ValidSuite(transport.Suite) {
		return errors.New("transport suite differs from manifest")
	}
	if transport.Type == connectivity.CarrierDirectAWG {
		if !slices.Equal(
			transport.AuthenticationModes, []string{AuthAWGPSK},
		) || transport.TokenKeyID != "" {
			return errors.New("direct AWG authentication must be awg-psk")
		}
	} else {
		if err := validateModes(transport.AuthenticationModes); err != nil {
			return err
		}
		hasAnonymous := slices.Contains(
			transport.AuthenticationModes, AuthAnonymousToken,
		)
		if hasAnonymous {
			key, ok := tokenKeys[transport.TokenKeyID]
			if !ok {
				return errors.New(
					"anonymous transport token key is missing from manifest",
				)
			}
			if (transport.Type == connectivity.CarrierHTTP3 ||
				transport.Type == connectivity.CarrierHTTP2) &&
				key.Scope != "carrier:"+transport.PublicTarget {
				return errors.New(
					"carrier public target differs from anonymous credential scope",
				)
			}
		} else if transport.TokenKeyID != "" {
			return errors.New(
				"identity-only transport unexpectedly names token key",
			)
		}
		if err := validateFixedEndpoint(transport.FixedBackend); err != nil {
			return fmt.Errorf("fixed backend: %w", err)
		}
	}
	if err := validateRawKey("public AWG key", transport.PublicAWGKey); err != nil {
		return err
	}
	if transport.MinInnerDatagram < 576 ||
		transport.MaxInnerDatagram < transport.MinInnerDatagram ||
		transport.MaxInnerDatagram > 1500 {
		return errors.New("transport inner datagram range is invalid")
	}
	if transport.Type == connectivity.CarrierPrivacyTwoHop &&
		transport.MaxInnerDatagram > wcf3.PrivacyPayloadSize {
		return fmt.Errorf(
			"maximum-privacy inner datagram exceeds frozen WCF3 payload size %d",
			wcf3.PrivacyPayloadSize,
		)
	}
	if err := validateHints(transport.IPv4Hints, transport.IPv6Hints); err != nil {
		return err
	}
	if err := validateCapabilities(transport.Capabilities, nil); err != nil {
		return fmt.Errorf("transport capabilities: %w", err)
	}

	switch transport.Type {
	case connectivity.CarrierDirectAWG:
		if err := validateIPLiteralEndpoint(transport.Endpoint); err != nil {
			return fmt.Errorf("direct endpoint: %w", err)
		}
		if transport.FixedBackend != "" {
			return errors.New("direct AWG transport has a fixed backend")
		}
		if transport.PublicTarget != "" ||
			transport.ServerName != "" || transport.ECHConfigList != "" ||
			len(transport.ALPN) != 0 || transport.RegionPolicy != "" ||
			transport.SidecarConfigDigest != "" {
			return errors.New("direct AWG transport has TLS or sidecar fields")
		}
	case connectivity.CarrierHTTP3:
		if err := validateFixedEndpoint(
			transport.PublicTarget,
		); err != nil {
			return fmt.Errorf("HTTP/3 public target: %w", err)
		}
		if err := validateHTTPSCarrier(
			transport, true, "/.well-known/masque/",
		); err != nil {
			return err
		}
		if !slices.Equal(transport.ALPN, []string{"h3"}) {
			return errors.New("HTTP/3 transport ALPN must be h3")
		}
	case connectivity.CarrierHTTP2:
		if err := validateFixedEndpoint(
			transport.PublicTarget,
		); err != nil {
			return fmt.Errorf("HTTP/2 public target: %w", err)
		}
		if err := validateHTTPSCarrier(
			transport, false, "/winn/v3/udp-stream",
		); err != nil {
			return err
		}
		if !slices.Equal(transport.ALPN, []string{"h2"}) {
			return errors.New("HTTP/2 transport ALPN must be h2")
		}
	case connectivity.CarrierRealityXHTTP:
		if transport.PublicTarget != "" {
			return errors.New(
				"REALITY transport has an unrelated public target",
			)
		}
		if err := validateFixedEndpoint(transport.Endpoint); err != nil {
			return fmt.Errorf("REALITY endpoint: %w", err)
		}
		if !validServerName(transport.ServerName) ||
			transport.ECHConfigList != "" ||
			!validDigest(transport.SidecarConfigDigest) {
			return errors.New("REALITY transport TLS/sidecar fields are invalid")
		}
		policy, ok := policies[transport.RegionPolicy]
		if !ok {
			return errors.New("REALITY regional policy is missing")
		}
		if err := validateRegionalPolicyCurrent(
			policy, now, maxSkew,
		); err != nil {
			return err
		}
		if err := validateALPN(transport.ALPN); err != nil {
			return err
		}
		matched := false
		for _, target := range policy.Targets {
			if target.ServerName == transport.ServerName &&
				target.Endpoint == transport.Endpoint &&
				slices.Equal(target.ALPN, transport.ALPN) {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New(
				"REALITY transport is not bound to its regional target",
			)
		}
	case connectivity.CarrierWebSocketTLS:
		if transport.PublicTarget != "" {
			return errors.New(
				"WebSocket transport has an unrelated public target",
			)
		}
		parsed, err := url.Parse(transport.Endpoint)
		if err != nil || parsed.Scheme != "wss" || parsed.Host == "" ||
			parsed.Path == "" || parsed.RawQuery != "" ||
			parsed.User != nil || parsed.Fragment != "" ||
			parsed.ForceQuery || parsed.Opaque != "" ||
			!validURLAuthority(parsed) {
			return errors.New("invalid WebSocket TLS endpoint")
		}
		if err := validatePublicTLSFields(transport); err != nil {
			return err
		}
		if transport.RegionPolicy != "" ||
			transport.SidecarConfigDigest == "" ||
			!validDigest(transport.SidecarConfigDigest) {
			return errors.New("WebSocket sidecar fields are invalid")
		}
		if err := validateALPN(transport.ALPN); err != nil {
			return err
		}
	case connectivity.CarrierNativeTwoHop,
		connectivity.CarrierPrivacyTwoHop:
		if transport.PublicTarget != "" {
			return errors.New(
				"two-hop transport has an unrelated public target",
			)
		}
		if err := validateHTTPSCarrier(
			transport, false, "/winn/v3/relay",
		); err != nil {
			return err
		}
		if transport.RegionPolicy != "" ||
			transport.SidecarConfigDigest != "" {
			return errors.New("native relay has unrelated transport fields")
		}
		if err := validateALPN(transport.ALPN); err != nil {
			return err
		}
	default:
		return errors.New("unsupported v2 transport")
	}
	return nil
}

func validateHTTPSCarrier(
	transport TransportV2,
	template bool,
	requiredPath string,
) error {
	parsed, err := url.Parse(transport.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Opaque != "" || !validURLAuthority(parsed) {
		return errors.New("invalid HTTPS transport endpoint")
	}
	if template {
		templateValue, templateErr := uritemplate.New(transport.Endpoint)
		expectedPath := requiredPath + "udp/{target_host}/{target_port}/"
		if templateErr != nil ||
			!slices.Equal(
				templateValue.Varnames(),
				[]string{"target_host", "target_port"},
			) ||
			parsed.Path != expectedPath ||
			parsed.RawPath != expectedPath {
			return errors.New("invalid CONNECT-UDP URI template")
		}
	} else if parsed.Path != requiredPath || parsed.RawPath != "" {
		return errors.New("HTTPS transport path or query is invalid")
	}
	if err := validatePublicTLSFields(transport); err != nil {
		return err
	}
	if transport.RegionPolicy != "" ||
		transport.SidecarConfigDigest != "" {
		return errors.New("HTTPS carrier has unrelated transport fields")
	}
	return nil
}

func validURLAuthority(parsed *url.URL) bool {
	if parsed == nil || !validServerName(parsed.Hostname()) {
		return false
	}
	portText := parsed.Port()
	if portText == "" {
		return true
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535
}

func validatePublicTLSFields(transport TransportV2) error {
	if !validServerName(transport.ServerName) {
		return errors.New("public TLS transport server name is invalid")
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(
		transport.ECHConfigList,
	)
	if err != nil || len(encoded) > echconfig.MaxConfigSize {
		clear(encoded)
		return errors.New("public TLS transport requires valid ECH config")
	}
	if err := echconfig.ValidateConfigList(encoded); err != nil {
		clear(encoded)
		return fmt.Errorf(
			"public TLS transport ECH config: %w", err,
		)
	}
	clear(encoded)
	return nil
}

func validateRegionalPolicyV2(
	policy RegionalPolicyV2,
	manifestIssued time.Time,
	manifestExpires time.Time,
) error {
	if !protocol.ValidDeviceID(policy.ID) ||
		len(policy.Regions) == 0 || len(policy.Regions) > 64 ||
		len(policy.Targets) == 0 || len(policy.Targets) > 64 {
		return errors.New("regional policy shape is invalid")
	}
	notBefore, err := time.Parse(time.RFC3339Nano, policy.NotBefore)
	if err != nil || notBefore.Location() != time.UTC ||
		notBefore.Before(manifestIssued) {
		return errors.New("regional policy not_before is invalid")
	}
	notAfter, err := time.Parse(time.RFC3339Nano, policy.NotAfter)
	if err != nil || notAfter.Location() != time.UTC ||
		!notAfter.After(notBefore) || notAfter.After(manifestExpires) {
		return errors.New("regional policy not_after is invalid")
	}
	seenRegions := make(map[string]struct{}, len(policy.Regions))
	for _, region := range policy.Regions {
		if !validShortToken(region, 32) {
			return fmt.Errorf("invalid regional policy region %q", region)
		}
		if _, duplicate := seenRegions[region]; duplicate {
			return fmt.Errorf("duplicate regional policy region %q", region)
		}
		seenRegions[region] = struct{}{}
	}
	seenTargets := make(map[string]struct{}, len(policy.Targets))
	for _, target := range policy.Targets {
		if !validServerName(target.ServerName) {
			return errors.New("regional camouflage server name is invalid")
		}
		if err := validateFixedEndpoint(target.Endpoint); err != nil {
			return fmt.Errorf("regional camouflage endpoint: %w", err)
		}
		if err := validateALPN(target.ALPN); err != nil {
			return err
		}
		key := target.ServerName + "\x00" + target.Endpoint
		if _, duplicate := seenTargets[key]; duplicate {
			return errors.New("duplicate regional camouflage target")
		}
		seenTargets[key] = struct{}{}
	}
	return nil
}

func validateRegionalPolicyCurrent(
	policy RegionalPolicyV2,
	now time.Time,
	maxSkew time.Duration,
) error {
	if now.IsZero() {
		return nil
	}
	notBefore, err := time.Parse(time.RFC3339Nano, policy.NotBefore)
	if err != nil {
		return errors.New("regional policy not_before is invalid")
	}
	notAfter, err := time.Parse(time.RFC3339Nano, policy.NotAfter)
	if err != nil {
		return errors.New("regional policy not_after is invalid")
	}
	if now.Before(notBefore.Add(-maxSkew)) ||
		!now.Before(notAfter.Add(maxSkew)) {
		return errors.New("regional policy is not currently valid")
	}
	return nil
}

func validateFixedEndpoint(endpoint string) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return errors.New("endpoint must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("endpoint port is invalid")
	}
	return nil
}

func validateIPLiteralEndpoint(endpoint string) error {
	if err := validateFixedEndpoint(endpoint); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(endpoint)
	if net.ParseIP(host) == nil {
		return errors.New("direct endpoint host must be an IP literal")
	}
	return nil
}

func validateHints(ipv4, ipv6 []string) error {
	if len(ipv4) > 8 || len(ipv6) > 8 {
		return errors.New("too many transport address hints")
	}
	seen := make(map[string]struct{}, len(ipv4)+len(ipv6))
	for _, hint := range ipv4 {
		ip := net.ParseIP(hint)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("IPv4 hint %q is not IPv4", hint)
		}
		if _, duplicate := seen[hint]; duplicate {
			return fmt.Errorf("duplicate address hint %q", hint)
		}
		seen[hint] = struct{}{}
	}
	for _, hint := range ipv6 {
		ip := net.ParseIP(hint)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("IPv6 hint %q is not IPv6", hint)
		}
		if _, duplicate := seen[hint]; duplicate {
			return fmt.Errorf("duplicate address hint %q", hint)
		}
		seen[hint] = struct{}{}
	}
	return nil
}

func validateRawKey(name, value string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return fmt.Errorf("%s must be canonical base64 for 32 bytes", name)
	}
	var nonzero byte
	for _, current := range decoded {
		nonzero |= current
	}
	clear(decoded)
	if nonzero == 0 {
		return fmt.Errorf("%s must not be all zero", name)
	}
	return nil
}

func validateALPN(alpn []string) error {
	if len(alpn) == 0 || len(alpn) > 4 {
		return errors.New("transport ALPN list is invalid")
	}
	seen := make(map[string]struct{}, len(alpn))
	for _, value := range alpn {
		switch value {
		case "h3", "h2", "http/1.1":
		default:
			return fmt.Errorf("unsupported transport ALPN %q", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate transport ALPN %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil ||
		strings.ContainsAny(value, "/:@") {
		return false
	}
	parsed, err := url.Parse("https://" + value)
	return err == nil && parsed.Hostname() == value
}

func validShortToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validCredentialScope(value string) bool {
	if validShortToken(value, 64) {
		return true
	}
	const prefix = "carrier:"
	if !strings.HasPrefix(value, prefix) || len(value) > 128 {
		return false
	}
	return validateFixedEndpoint(
		strings.TrimPrefix(value, prefix),
	) == nil
}

func requireManifestEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("v2 gateway manifest contains extra JSON")
	}
	return err
}
