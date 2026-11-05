// Package gatewaymanifest defines the signed, expiry-bounded discovery object
// used by Winn clients. It is intentionally independent of DNS so a DNS
// response can select where to fetch a manifest without becoming a new trust
// anchor.
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
	"sort"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	Format             = "winn-gateway-manifest/v1"
	MaxDocumentSize    = 1 << 20
	MaxNodes           = 64
	MaxLifetime        = 7 * 24 * time.Hour
	DefaultClockSkew   = 5 * time.Minute
	AuthIdentity       = "identity"
	AuthAnonymousToken = "anonymous-token"
)

var requiredCapabilities = []string{
	"adaptive-inner-mtu",
	"ech-required",
	"happy-eyeballs-v2",
	"signed-gateway-manifest",
}

type Node struct {
	ID                  string   `json:"id"`
	MASQUETemplate      string   `json:"masque_template"`
	H2URL               string   `json:"h2_url"`
	ServerName          string   `json:"server_name"`
	IPv4Hints           []string `json:"ipv4_hints,omitempty"`
	IPv6Hints           []string `json:"ipv6_hints,omitempty"`
	ECHConfigList       string   `json:"ech_config_list"`
	MaxInnerDatagram    int      `json:"max_inner_datagram"`
	AuthenticationModes []string `json:"authentication_modes"`
	Capabilities        []string `json:"capabilities"`
}

type PrivacyTokenKey struct {
	ID           string `json:"id"`
	Scope        string `json:"scope"`
	IssuerDomain string `json:"issuer_domain,omitempty"`
	Algorithm    string `json:"algorithm"`
	PublicKey    string `json:"public_key"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

type Manifest struct {
	Format          string            `json:"format"`
	Sequence        uint64            `json:"sequence"`
	IssuedAt        string            `json:"issued_at"`
	ExpiresAt       string            `json:"expires_at"`
	ControllerID    string            `json:"controller_id"`
	Suite           string            `json:"suite"`
	MinimumClient   string            `json:"minimum_client"`
	PreviousDigest  string            `json:"previous_digest,omitempty"`
	Capabilities    []string          `json:"capabilities"`
	Nodes           []Node            `json:"nodes"`
	PrivacyTokenKey []PrivacyTokenKey `json:"privacy_token_keys,omitempty"`
	AuthAlgorithm   string            `json:"auth_algorithm"`
	AuthKeyID       string            `json:"auth_key_id"`
	AuthSignature   string            `json:"auth_signature"`
}

func Sign(manifest *Manifest, signer *pqauth.Signer) error {
	if manifest == nil || signer == nil {
		return errors.New("manifest and controller signer are required")
	}
	manifest.AuthAlgorithm = signer.Algorithm()
	manifest.AuthKeyID = signer.KeyID()
	manifest.AuthSignature = ""
	if err := validate(*manifest, time.Time{}, 0, false); err != nil {
		return err
	}
	message, err := unsignedCanonical(*manifest)
	if err != nil {
		return err
	}
	signature, err := pqauth.SignDomainMessage(pqauth.ManifestSignatureDomain, message, signer)
	if err != nil {
		return err
	}
	defer clear(signature)
	manifest.AuthSignature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func Verify(manifest Manifest, pins *pqauth.VerifierSet, now time.Time, maxSkew time.Duration) error {
	if pins == nil {
		return errors.New("controller manifest pins are required")
	}
	if err := validate(manifest, now, maxSkew, true); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(manifest.AuthSignature)
	if err != nil || len(signature) == 0 {
		return errors.New("invalid manifest signature encoding")
	}
	defer clear(signature)
	verifier, err := pins.Verifier(manifest.AuthAlgorithm, manifest.AuthKeyID)
	if err != nil {
		return err
	}
	message, err := unsignedCanonical(manifest)
	if err != nil {
		return err
	}
	if err := pqauth.VerifyDomainMessage(
		pqauth.ManifestSignatureDomain, message, signature, verifier,
	); err != nil {
		return fmt.Errorf("verify gateway manifest: %w", err)
	}
	return nil
}

func Load(path string) (Manifest, error) {
	data, err := securefile.ReadPublicIntegrity(path, MaxDocumentSize)
	if err != nil {
		return Manifest{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, errors.New("gateway manifest contains extra JSON")
		}
		return Manifest{}, err
	}
	return manifest, nil
}

func Encode(manifest Manifest) ([]byte, error) {
	if err := validate(manifest, time.Time{}, 0, manifest.AuthSignature != ""); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func Digest(manifest Manifest) (string, error) {
	if manifest.AuthSignature == "" {
		return "", errors.New("cannot digest an unsigned gateway manifest")
	}
	encoded, err := canonical(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (manifest Manifest) Node(id string) (Node, error) {
	for _, node := range manifest.Nodes {
		if node.ID == id {
			return node, nil
		}
	}
	return Node{}, fmt.Errorf("gateway node %q is not in the signed manifest", id)
}

func (manifest Manifest) TokenKey(id string) (PrivacyTokenKey, error) {
	for _, key := range manifest.PrivacyTokenKey {
		if key.ID == id {
			return key, nil
		}
	}
	return PrivacyTokenKey{}, fmt.Errorf("privacy token key %q is not in the signed manifest", id)
}

func (key PrivacyTokenKey) Validity() (time.Time, time.Time, error) {
	notBefore, err := time.Parse(time.RFC3339Nano, key.NotBefore)
	if err != nil || notBefore.Location() != time.UTC {
		return time.Time{}, time.Time{}, errors.New("invalid privacy token not_before")
	}
	notAfter, err := time.Parse(time.RFC3339Nano, key.NotAfter)
	if err != nil || notAfter.Location() != time.UTC || !notAfter.After(notBefore) {
		return time.Time{}, time.Time{}, errors.New("invalid privacy token not_after")
	}
	return notBefore, notAfter, nil
}

func (key PrivacyTokenKey) PublicKeyDER() ([]byte, error) {
	der, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
	if err != nil || len(der) == 0 || len(der) > 16<<10 {
		clear(der)
		return nil, errors.New("invalid privacy token public key")
	}
	return der, nil
}

func (node Node) ECHConfigs() ([]byte, error) {
	configs, err := base64.StdEncoding.Strict().DecodeString(node.ECHConfigList)
	if err != nil || len(configs) < 6 || len(configs) > echconfig.MaxConfigSize {
		clear(configs)
		return nil, errors.New("gateway node contains an invalid ECHConfigList")
	}
	if err := echconfig.ValidateConfigList(configs); err != nil {
		clear(configs)
		return nil, errors.New("gateway node contains an invalid ECHConfigList")
	}
	return configs, nil
}

func RequiredCapabilities() []string {
	return slices.Clone(requiredCapabilities)
}

func unsignedCanonical(manifest Manifest) ([]byte, error) {
	manifest.AuthSignature = ""
	return canonical(manifest)
}

func canonical(manifest Manifest) ([]byte, error) {
	return json.Marshal(manifest)
}

func validate(manifest Manifest, now time.Time, maxSkew time.Duration, requireSignature bool) error {
	if manifest.Format != Format || manifest.Sequence == 0 {
		return errors.New("unsupported gateway manifest format or sequence")
	}
	if !protocol.ValidDeviceID(manifest.ControllerID) {
		return errors.New("invalid manifest controller identity")
	}
	switch manifest.Suite {
	case "x25519-mlkem768", "p256-mlkem768", "p384-mlkem1024":
	default:
		return errors.New("invalid manifest hybrid TLS suite")
	}
	if manifest.MinimumClient == "" || len(manifest.MinimumClient) > 64 {
		return errors.New("invalid minimum client version")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil || issuedAt.Location() != time.UTC {
		return errors.New("manifest issued_at must be RFC3339Nano UTC")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC {
		return errors.New("manifest expires_at must be RFC3339Nano UTC")
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxLifetime {
		return errors.New("manifest lifetime is invalid")
	}
	if maxSkew < 0 || maxSkew > DefaultClockSkew {
		return errors.New("manifest clock skew exceeds the frozen limit")
	}
	if !now.IsZero() {
		if issuedAt.After(now.Add(maxSkew)) || !expiresAt.After(now.Add(-maxSkew)) {
			return errors.New("gateway manifest is not currently valid")
		}
	}
	if manifest.PreviousDigest != "" && !validDigest(manifest.PreviousDigest) {
		return errors.New("invalid previous manifest digest")
	}
	if err := validateCapabilities(manifest.Capabilities, requiredCapabilities); err != nil {
		return err
	}
	if len(manifest.Nodes) == 0 || len(manifest.Nodes) > MaxNodes {
		return errors.New("gateway manifest node count is invalid")
	}
	nodeIDs := make(map[string]struct{}, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		if err := validateNode(node); err != nil {
			return fmt.Errorf("gateway node %q: %w", node.ID, err)
		}
		if _, duplicate := nodeIDs[node.ID]; duplicate {
			return fmt.Errorf("duplicate gateway node %q", node.ID)
		}
		nodeIDs[node.ID] = struct{}{}
	}
	tokenIDs := make(map[string]struct{}, len(manifest.PrivacyTokenKey))
	for _, key := range manifest.PrivacyTokenKey {
		if err := validateTokenKey(key, issuedAt, expiresAt); err != nil {
			return fmt.Errorf("privacy token key %q: %w", key.ID, err)
		}
		if _, duplicate := tokenIDs[key.ID]; duplicate {
			return fmt.Errorf("duplicate privacy token key %q", key.ID)
		}
		tokenIDs[key.ID] = struct{}{}
	}
	if manifest.AuthAlgorithm != pqauth.MLDSA65 && manifest.AuthAlgorithm != pqauth.MLDSA87 {
		return errors.New("invalid manifest authentication algorithm")
	}
	if !validDigest(manifest.AuthKeyID) {
		return errors.New("invalid manifest authentication key ID")
	}
	if requireSignature && manifest.AuthSignature == "" {
		return errors.New("gateway manifest signature is required")
	}
	if len(manifest.AuthSignature) > 10<<10 {
		return errors.New("gateway manifest signature is too large")
	}
	return nil
}

func validateNode(node Node) error {
	if !protocol.ValidDeviceID(node.ID) || node.ServerName == "" || len(node.ServerName) > 253 {
		return errors.New("invalid node identity or server name")
	}
	masqueURL, err := url.Parse(node.MASQUETemplate)
	if err != nil || masqueURL.Scheme != "https" || masqueURL.Host == "" ||
		!strings.Contains(node.MASQUETemplate, "{target_host}") ||
		!strings.Contains(node.MASQUETemplate, "{target_port}") {
		return errors.New("invalid HTTPS MASQUE template")
	}
	h2URL, err := url.Parse(node.H2URL)
	if err != nil || h2URL.Scheme != "https" || h2URL.Host == "" ||
		h2URL.Path != "/winn/v2/udp-stream" || h2URL.RawQuery != "" {
		return errors.New("invalid HTTP/2 carrier URL")
	}
	if node.MaxInnerDatagram < 576 || node.MaxInnerDatagram > 1500 {
		return errors.New("max_inner_datagram must be between 576 and 1500")
	}
	if _, err := node.ECHConfigs(); err != nil {
		return err
	}
	if err := validateModes(node.AuthenticationModes); err != nil {
		return err
	}
	if err := validateCapabilities(node.Capabilities, requiredCapabilities); err != nil {
		return err
	}
	for _, hint := range append(slices.Clone(node.IPv4Hints), node.IPv6Hints...) {
		if net.ParseIP(hint) == nil {
			return fmt.Errorf("invalid address hint %q", hint)
		}
	}
	for _, hint := range node.IPv4Hints {
		if net.ParseIP(hint).To4() == nil {
			return fmt.Errorf("IPv4 hint %q is not IPv4", hint)
		}
	}
	for _, hint := range node.IPv6Hints {
		ip := net.ParseIP(hint)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("IPv6 hint %q is not IPv6", hint)
		}
	}
	return nil
}

func validateModes(modes []string) error {
	if len(modes) == 0 || len(modes) > 2 {
		return errors.New("authentication modes are required")
	}
	seen := make(map[string]struct{}, len(modes))
	for _, mode := range modes {
		if mode != AuthIdentity && mode != AuthAnonymousToken {
			return fmt.Errorf("unsupported authentication mode %q", mode)
		}
		if _, duplicate := seen[mode]; duplicate {
			return errors.New("duplicate authentication mode")
		}
		seen[mode] = struct{}{}
	}
	return nil
}

func validateCapabilities(capabilities, required []string) error {
	if len(capabilities) == 0 || len(capabilities) > 32 {
		return errors.New("manifest capabilities are invalid")
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if capability == "" || len(capability) > 64 {
			return errors.New("invalid manifest capability")
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("duplicate manifest capability %q", capability)
		}
		seen[capability] = struct{}{}
	}
	for _, capability := range required {
		if _, ok := seen[capability]; !ok {
			return fmt.Errorf("required manifest capability %q is missing", capability)
		}
	}
	return nil
}

func validateTokenKey(key PrivacyTokenKey, manifestNotBefore, manifestNotAfter time.Time) error {
	if !validDigest(key.ID) || key.Scope == "" || len(key.Scope) > 128 ||
		key.Algorithm != "rsabssa-sha384-pss-randomized" {
		return errors.New("invalid token key metadata")
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
	if err != nil {
		return errors.New("invalid token public key")
	}
	parsed, parseErr := privacytoken.ParseIssuerPublicKeyDER(publicKey)
	clear(publicKey)
	if parseErr != nil || parsed.E != 65537 {
		return errors.New("invalid token public key")
	}
	expectedID, err := privacytoken.IssuerKeyID(parsed)
	if err != nil || expectedID != key.ID {
		return errors.New("token key ID does not match public key")
	}
	notBefore, err := time.Parse(time.RFC3339Nano, key.NotBefore)
	if err != nil {
		return errors.New("invalid token key not_before")
	}
	notAfter, err := time.Parse(time.RFC3339Nano, key.NotAfter)
	if err != nil || !notAfter.After(notBefore) {
		return errors.New("invalid token key not_after")
	}
	if notBefore.Before(manifestNotBefore) || notAfter.After(manifestNotAfter) {
		return errors.New("token key validity exceeds manifest validity")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

// SortedCapabilities makes authored manifests deterministic before signing.
func SortedCapabilities(capabilities []string) []string {
	result := slices.Clone(capabilities)
	sort.Strings(result)
	return result
}
