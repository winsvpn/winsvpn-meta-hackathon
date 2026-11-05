package directawg

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	LinuxDeploymentProfileFormat  = "winn-linux-directawg-profile/v1"
	linuxDeploymentProfileDomain  = "winn-linux-directawg-profile/v1/prehash-sha256"
	maxLinuxProfileLifetime       = 7 * 24 * time.Hour
	maxLinuxDeploymentProfileSize = 256 << 10
)

type LinuxInterfaceProfile struct {
	InnerAddressPool    string         `json:"inner_address_pool"`
	AllowedIPs          []string       `json:"allowed_ips"`
	VerificationRoutes  []string       `json:"verification_routes"`
	MTU                 int            `json:"mtu"`
	ListenPortMin       uint16         `json:"listen_port_min"`
	ListenPortMax       uint16         `json:"listen_port_max"`
	PersistentKeepalive uint16         `json:"persistent_keepalive"`
	Obfuscation         AWGObfuscation `json:"obfuscation"`
}

type LinuxProbeProfile struct {
	DNSResolver         string   `json:"dns_resolver"`
	DNSQueryName        string   `json:"dns_query_name"`
	ExpectedDNSAnswers  []string `json:"expected_dns_answers"`
	CanaryEndpoint      string   `json:"canary_endpoint"`
	TimeoutMilliseconds uint32   `json:"timeout_milliseconds"`
}

// LinuxDeploymentProfile is a controller-signed supplement bound to one
// already signed ManifestV2 digest and direct-AWG transport. It prevents local
// flags from silently choosing AWG, verification, DNS, or canary parameters.
// Physical underlay interface/mark remain local platform state and are not
// controller policy.
type LinuxDeploymentProfile struct {
	Format         string                `json:"format"`
	ManifestDigest string                `json:"manifest_digest"`
	NodeID         string                `json:"node_id"`
	TransportID    string                `json:"transport_id"`
	IssuedAt       string                `json:"issued_at"`
	ExpiresAt      string                `json:"expires_at"`
	Interface      LinuxInterfaceProfile `json:"interface"`
	Probe          LinuxProbeProfile     `json:"probe"`
	AuthAlgorithm  string                `json:"auth_algorithm"`
	AuthKeyID      string                `json:"auth_key_id"`
	AuthSignature  string                `json:"auth_signature"`
}

// LoadLinuxDeploymentProfile reads one integrity-protected strict JSON
// document. Signature, lifetime, manifest, node, and transport binding remain
// the responsibility of VerifyLinuxDeploymentProfile.
func LoadLinuxDeploymentProfile(
	path string,
) (LinuxDeploymentProfile, error) {
	data, err := securefile.ReadPublicIntegrity(
		path, maxLinuxDeploymentProfileSize,
	)
	if err != nil {
		return LinuxDeploymentProfile{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile LinuxDeploymentProfile
	if err := decoder.Decode(&profile); err != nil {
		return LinuxDeploymentProfile{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return LinuxDeploymentProfile{},
			errors.New(
				"linux deployment profile contains extra JSON",
			)
	}
	return profile, nil
}

func SignLinuxDeploymentProfile(
	profile *LinuxDeploymentProfile,
	signer *pqauth.Signer,
) error {
	if profile == nil || signer == nil {
		return errors.New(
			"linux deployment profile and controller signer are required",
		)
	}
	profile.AuthAlgorithm = signer.Algorithm()
	profile.AuthKeyID = signer.KeyID()
	profile.AuthSignature = ""
	if _, _, err := validateLinuxDeploymentProfile(
		*profile, time.Time{}, false,
	); err != nil {
		return err
	}
	message, err := canonicalUnsignedLinuxProfile(*profile)
	if err != nil {
		return err
	}
	digest := linuxProfileDigest(message)
	clear(message)
	defer clear(digest[:])
	signature, err := pqauth.SignDomainMessage(
		pqauth.ManifestV2SignatureDomain, digest[:], signer,
	)
	if err != nil {
		return err
	}
	defer clear(signature)
	profile.AuthSignature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func VerifyLinuxDeploymentProfile(
	profile LinuxDeploymentProfile,
	manifest gatewaymanifest.ManifestV2,
	pins *pqauth.VerifierSet,
	now time.Time,
) (LinuxSignedInterfaceConfig, LinuxVerificationConfig, error) {
	if pins == nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New("linux deployment profile controller pins are required")
	}
	interfaceConfig, verificationConfig, err :=
		validateLinuxDeploymentProfile(profile, now, true)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{}, err
	}
	manifestDigest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			fmt.Errorf("digest signed v2 manifest: %w", err)
	}
	if profile.ManifestDigest != manifestDigest ||
		profile.AuthAlgorithm != manifest.AuthAlgorithm ||
		profile.AuthKeyID != manifest.AuthKeyID {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New(
				"linux deployment profile does not bind the selected manifest signer and digest",
			)
	}
	node, err := manifest.Node(profile.NodeID)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{}, err
	}
	transport, err := node.Transport(profile.TransportID)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{}, err
	}
	if transport.Type != connectivity.CarrierDirectAWG {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New(
				"linux deployment profile selected a non-direct-AWG transport",
			)
	}
	if transport.MinInnerDatagram > interfaceConfig.MTU ||
		transport.MaxInnerDatagram < interfaceConfig.MTU {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New(
				"linux deployment MTU is outside manifest transport limits",
			)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(
		profile.AuthSignature,
	)
	if err != nil || len(signature) == 0 {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New(
				"linux deployment profile signature encoding is invalid",
			)
	}
	defer clear(signature)
	verifier, err := pins.Verifier(
		profile.AuthAlgorithm, profile.AuthKeyID,
	)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{}, err
	}
	message, err := canonicalUnsignedLinuxProfile(profile)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{}, err
	}
	digest := linuxProfileDigest(message)
	clear(message)
	defer clear(digest[:])
	if err := pqauth.VerifyDomainMessage(
		pqauth.ManifestV2SignatureDomain, digest[:], signature, verifier,
	); err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			fmt.Errorf("verify Linux deployment profile: %w", err)
	}
	return interfaceConfig, verificationConfig, nil
}

func validateLinuxDeploymentProfile(
	profile LinuxDeploymentProfile,
	now time.Time,
	requireSignature bool,
) (LinuxSignedInterfaceConfig, LinuxVerificationConfig, error) {
	if profile.Format != LinuxDeploymentProfileFormat ||
		len(profile.ManifestDigest) != 64 ||
		profile.NodeID == "" || profile.TransportID == "" {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New("linux deployment profile identity is invalid")
	}
	for _, character := range profile.ManifestDigest {
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f')) {
			return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
				errors.New(
					"linux deployment profile manifest digest is invalid",
				)
		}
	}
	issuedAt, err := time.Parse(time.RFC3339, profile.IssuedAt)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New("linux deployment profile issued_at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, profile.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) ||
		expiresAt.Sub(issuedAt) > maxLinuxProfileLifetime {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New("linux deployment profile lifetime is invalid")
	}
	if !now.IsZero() &&
		(now.Before(issuedAt.Add(-gatewaymanifest.DefaultClockSkew)) ||
			now.After(expiresAt.Add(gatewaymanifest.DefaultClockSkew))) {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New("linux deployment profile is outside its validity window")
	}
	interfaceConfig, err := profile.Interface.config()
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{}, err
	}
	verificationConfig, err := profile.Probe.config()
	if err != nil {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{}, err
	}
	for _, endpoint := range []string{
		verificationConfig.DNSResolver,
		verificationConfig.CanaryEndpoint,
	} {
		address, parseError := parseIPLiteralAddrPort(endpoint)
		if parseError != nil ||
			!linuxProbeRouteContains(
				interfaceConfig.VerificationRoutes, address.Addr(),
			) {
			return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
				errors.New(
					"linux profile probe endpoint is outside verification routes",
				)
		}
	}
	if profile.AuthAlgorithm != pqauth.MLDSA65 &&
		profile.AuthAlgorithm != pqauth.MLDSA87 {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New(
				"linux deployment profile authentication algorithm is invalid",
			)
	}
	if len(profile.AuthKeyID) != 64 {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New(
				"linux deployment profile authentication key ID is invalid",
			)
	}
	if requireSignature && profile.AuthSignature == "" {
		return LinuxSignedInterfaceConfig{}, LinuxVerificationConfig{},
			errors.New("linux deployment profile signature is missing")
	}
	return interfaceConfig, verificationConfig, nil
}

func (profile LinuxInterfaceProfile) config() (
	LinuxSignedInterfaceConfig,
	error,
) {
	pool, err := netip.ParsePrefix(profile.InnerAddressPool)
	if err != nil {
		return LinuxSignedInterfaceConfig{},
			errors.New("linux profile inner address pool is invalid")
	}
	allowed, err := parseLinuxProfilePrefixes(profile.AllowedIPs)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, fmt.Errorf(
			"linux profile allowed IPs: %w", err,
		)
	}
	verification, err := parseLinuxProfilePrefixes(
		profile.VerificationRoutes,
	)
	if err != nil {
		return LinuxSignedInterfaceConfig{}, fmt.Errorf(
			"linux profile verification routes: %w", err,
		)
	}
	config := LinuxSignedInterfaceConfig{
		InnerAddressPool:    pool,
		AllowedIPs:          allowed,
		VerificationRoutes:  verification,
		MTU:                 profile.MTU,
		ListenPortMin:       profile.ListenPortMin,
		ListenPortMax:       profile.ListenPortMax,
		PersistentKeepalive: profile.PersistentKeepalive,
		Obfuscation:         profile.Obfuscation,
	}
	if err := validateLinuxSignedConfig(config); err != nil {
		return LinuxSignedInterfaceConfig{}, err
	}
	return config, nil
}

func (profile LinuxProbeProfile) config() (
	LinuxVerificationConfig,
	error,
) {
	answers := make([]netip.Addr, 0, len(profile.ExpectedDNSAnswers))
	for _, text := range profile.ExpectedDNSAnswers {
		address, err := netip.ParseAddr(text)
		if err != nil {
			return LinuxVerificationConfig{},
				errors.New(
					"linux profile DNS expected answer is invalid",
				)
		}
		answers = append(answers, address)
	}
	timeout := time.Duration(profile.TimeoutMilliseconds) * time.Millisecond
	config := LinuxVerificationConfig{
		DNSResolver:        profile.DNSResolver,
		DNSQueryName:       profile.DNSQueryName,
		ExpectedDNSAnswers: answers,
		CanaryEndpoint:     profile.CanaryEndpoint,
		Timeout:            timeout,
	}
	if err := validateLinuxVerificationConfig(config); err != nil {
		return LinuxVerificationConfig{}, err
	}
	if timeout == 0 {
		config.Timeout = defaultLinuxProbeTimeout
	}
	return config, nil
}

func parseLinuxProfilePrefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, errors.New("prefix is invalid")
		}
		result = append(result, prefix)
	}
	return result, nil
}

func canonicalUnsignedLinuxProfile(
	profile LinuxDeploymentProfile,
) ([]byte, error) {
	profile.Interface.AllowedIPs = slices.Clone(
		profile.Interface.AllowedIPs,
	)
	profile.Interface.VerificationRoutes = slices.Clone(
		profile.Interface.VerificationRoutes,
	)
	profile.Probe.ExpectedDNSAnswers = slices.Clone(
		profile.Probe.ExpectedDNSAnswers,
	)
	profile.AuthSignature = ""
	return json.Marshal(profile)
}

func linuxProfileDigest(message []byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(linuxDeploymentProfileDomain))
	hash.Write([]byte{0})
	hash.Write(message)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}
