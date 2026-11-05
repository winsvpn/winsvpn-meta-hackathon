// Package carrierhost is the Go host that builds an internal/carrier dialer so
// datapath.OpenWithCarrier can be reached from a platform whose host process is
// not written in Go.
//
// # Why this package exists at all
//
// datapath/carrier.go states the boundary and the reason for it: a carrier
// needs "a URI template or absolute HTTPS URL, a public target, a device
// identity or anonymous credential source, a TLS suite and a response
// verifier", none of which belongs in a JSON blob crossing the C ABI, so "a
// host that wants a carrier constructs the dialer itself and calls
// OpenWithCarrier".
//
// That is a design decision, not an oversight, and this package does not
// overturn it. It observes that on Android the host that reaches the datapath
// is NOT the C ABI. Android runs cmd/winn-datapath as a subprocess over the
// framed duplex channel (see datapath/duplex), and that subprocess IS a Go
// host. It has argv, it has a filesystem, and it runs as the application's own
// uid. So the Go host the comment asks for already exists on Android; it simply
// had no way to build a dialer. This package is that way.
//
// # What crosses which boundary
//
// Nothing here travels on the duplex frame channel. The Create frame keeps
// carrying exactly datapath.Config and nothing else, so the C ABI in cdatapath
// is untouched and iOS and macOS are unaffected. The carrier configuration
// arrives as a FILE PATH on argv, and this package opens and interprets that
// file itself. The distinction matters: a path is a reference the child
// resolves under its own authority, whereas an authenticated configuration
// inlined into a frame would be material the child had to trust because the
// peer said so.
//
// Key material never appears in the profile document. Every secret — the device
// ML-DSA seed, the client private key — is named by path and read by the loader
// that already owns that file format (pqauth.LoadSigner, tlsconfig.Client*),
// which is also what keeps this package free of any private-key parsing of its
// own.
//
// # What this route does and does not prove
//
// A session built from this profile really does perform the post-quantum
// carrier handshake: TLS 1.3 restricted to the profile's hybrid group
// (x25519-mlkem768 and friends, see tlsconfig.ParseSuite), Encrypted Client
// Hello from the configured config list, ML-DSA request signing by the device
// key, and ML-DSA response verification against PINNED controller keys. Those
// are the properties internal/carrier enforces, and they hold whatever
// delivered the profile.
//
// What it does NOT prove is node selection. The production route binds the
// transport, the suite, the ECH list and the public target to a
// controller-signed, transparency-logged gateway manifest
// (gatewaymanifest.LoadVerifiedNodeV2), which additionally defeats rollback and
// equivocation by a compromised control plane. This package deliberately
// REFUSES a profile that names a manifest — see ErrManifestRouteUnimplemented —
// rather than pretending to verify one. A profile without a manifest is the
// direct-pin route: it is exactly as trustworthy as the channel that wrote the
// file, and no more.
//
// # Fail closed
//
// Every refusal below is a named error. There is no default that turns a
// missing credential into a weaker session, and there is no path from this
// package back to direct-awg: a profile that cannot be honoured returns an
// error, and the caller's only correct response is to fail the tunnel.
package carrierhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/knock"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// ProfileVersion identifies the shape of Profile. It is deliberately distinct
// from datapath.ContractVersion, which versions the Create-frame configuration,
// because the two documents cross different boundaries and will not change
// together.
const ProfileVersion = "winn-carrier-profile/1"

// MaxProfileBytes bounds the profile document. A carrier profile is a few
// hundred bytes of scalars and paths; anything larger is a mistake or an
// attempt to make the child allocate.
const MaxProfileBytes = 64 << 10

// Carrier names accepted here. They are taken from internal/connectivity rather
// than repeated as literals, so a rename in the v3 contract breaks the build
// instead of producing a profile that names a carrier nothing implements.
const (
	CarrierHTTP3 = string(connectivity.CarrierHTTP3)
	CarrierHTTP2 = string(connectivity.CarrierHTTP2)
)

// SPA modes for Profile.SPAMode — the alternative connection-initiation step.
//
// The mode is a separate field from the key path on purpose. If "configured a
// key path" implied "SPA is on", then a misspelled or dropped path would read
// as "SPA is off" and the operator would believe a defence was running that was
// not. Naming the mode makes the missing path a refusal instead.
const (
	// SPAModeOff is the default and today's behaviour: the carrier dials
	// straight away and every other spa_* field must be absent.
	SPAModeOff = "off"

	// SPAModeRequired sends one internal/knock Single Packet Authorization
	// datagram over the host's protected socket immediately before the carrier
	// dials. See internal/knockdial.
	SPAModeRequired = "required"
)

var (
	// ErrProfileVersion means the document does not declare ProfileVersion.
	ErrProfileVersion = errors.New(
		"winn carrier profile version is not " + ProfileVersion,
	)

	// ErrCarrierUnsupported means the profile names a carrier this host cannot
	// build. Only the two carriers whose dialers accept a caller-supplied,
	// already-protected socket are buildable here; every other carrier would
	// have to open a socket of its own, which is the exact failure the Android
	// handoff exists to prevent.
	ErrCarrierUnsupported = errors.New(
		"winn carrier profile names a carrier this host cannot build: only " +
			CarrierHTTP3 + " and " + CarrierHTTP2 + " ride a caller-supplied " +
			"socket",
	)

	// ErrManifestRouteUnimplemented is returned for a profile that names a
	// gateway manifest.
	//
	// It is not a stub. Honouring it means running
	// gatewaymanifest.LoadVerifiedNodeV2 over a controller-signed manifest, a
	// transparency log and a persisted trust state, then deriving the
	// transport, suite, ECH list and public target from the VERIFIED node
	// rather than from the profile. Reading those fields from the profile while
	// a manifest path sat unopened beside them would be worse than refusing:
	// the operator would believe the manifest was checked.
	ErrManifestRouteUnimplemented = errors.New(
		"winn carrier profile names a gateway manifest, which this host does " +
			"not verify: the manifest route needs LoadVerifiedNodeV2 over a " +
			"transparency log and a persisted trust state, so refusing rather " +
			"than reading the profile's own transport fields and calling it " +
			"verified",
	)

	// ErrAnonymousRouteUnimplemented is returned for authorization_mode
	// "anonymous-token". The anonymous route needs a pool of one-time blind
	// tokens from a token issuer, each verified against the signed manifest's
	// issuer keys, and a policy for exhausting and refilling that pool. None of
	// that is a file this loader can simply read.
	ErrAnonymousRouteUnimplemented = errors.New(
		"winn carrier profile requests anonymous-token authorization, which " +
			"this host does not implement: it needs an issued privacy-token " +
			"pool verified against the signed manifest's issuer keys",
	)

	// ErrCarrierFieldMismatch means a field belongs to a different carrier than
	// the one the profile names, or the field the named carrier needs is
	// missing.
	ErrCarrierFieldMismatch = errors.New(
		"winn carrier profile field does not belong to the carrier it names",
	)

	// ErrSPAFieldWithoutMode means an spa_* field was set while spa_mode was
	// off or absent. Ignoring it would leave the operator believing a knock was
	// configured; refusing says so.
	ErrSPAFieldWithoutMode = errors.New(
		"winn carrier profile sets an spa_ field without spa_mode " +
			SPAModeRequired + ": refusing rather than silently ignoring a " +
			"configured single-packet-authorization parameter",
	)

	// ErrDuplicateJSONKey means the document named the same field twice.
	// encoding/json keeps the last value and reports no error, which would let
	// a merged or tampered profile silently disable padding or SPA.
	ErrDuplicateJSONKey = errors.New(
		"winn carrier profile contains a duplicate JSON key",
	)

	// ErrSPAStreamCarrierUnsupported means a profile asks for SPA on the
	// HTTP/2 carrier.
	//
	// It is not an oversight. The stream carrier is handed a CONNECTED TCP
	// socket, a UDP knock cannot ride it, and opening a separate UDP socket
	// beside it would be less protected than the transport on exactly the
	// platform this route exists for — on Android an unprotected socket can
	// loop the knock back into the tunnel it is trying to establish. Lifting
	// this needs a second, host-protected UDP descriptor in the argv and C-ABI
	// contract, which is a host change, not a profile change. See
	// internal/knockdial.
	ErrSPAStreamCarrierUnsupported = errors.New(
		"winn carrier profile requests SPA on " + CarrierHTTP2 + ", which this " +
			"host cannot do: a UDP knock cannot ride the connected TCP socket " +
			"a stream carrier is given, and a separate UDP socket would be " +
			"less protected than the transport",
	)
)

// Profile is the authenticated carrier configuration datapath.Config
// deliberately does not carry. It is read from a file, never from a frame.
//
// Unknown fields are rejected, for the same reason datapath.ParseConfig rejects
// them: a misspelled key must be a loud failure, not a silent default that
// leaves the operator believing something took effect.
type Profile struct {
	// Profile must equal ProfileVersion.
	Profile string `json:"profile"`

	// Carrier is CarrierHTTP3 or CarrierHTTP2. It must equal the carrier the
	// datapath.Config names; the caller checks that, because only the caller
	// holds both documents.
	Carrier string `json:"carrier"`

	// MASQUETemplate is the RFC 9298 CONNECT-UDP URI template. HTTP/3 only.
	MASQUETemplate string `json:"masque_template,omitempty"`

	// H2URL is the absolute HTTPS URL of the HTTP/2 stream endpoint. HTTP/2
	// only. Its path must be carrier.H2Path.
	H2URL string `json:"h2_url,omitempty"`

	// PublicTarget is the UDP endpoint the proxy is asked to reach on the
	// client's behalf: the AmneziaWG gateway. It is the value the carrier binds
	// into every signed request, so it is authenticated end to end and is NOT
	// the same thing as datapath.Config.GatewayEndpoint, which on a carrier is
	// carried for correlation only.
	PublicTarget string `json:"public_target"`

	// ServerName is the TLS server name presented in the INNER ClientHello,
	// under ECH.
	ServerName string `json:"server_name"`

	// Suite names the hybrid post-quantum key agreement, e.g.
	// "x25519-mlkem768". tlsconfig.ParseSuite is the authority on the list.
	Suite string `json:"suite"`

	// ControllerID identifies the controller whose ML-DSA signature every
	// carrier response must carry.
	ControllerID string `json:"controller_id"`

	// ControllerPinsPath is a pqauth verifier-set file: the PINNED controller
	// public keys. This is the profile's trust anchor, and it is mandatory.
	// Without it a response verifier would have nothing to verify against.
	ControllerPinsPath string `json:"controller_pins_path"`

	// RootCAPath is the PEM certificate pool the carrier's TLS certificate must
	// chain to. Mandatory under the default private-ca trust anchor, and
	// forbidden under webpki. See TrustAnchor.
	RootCAPath string `json:"root_ca_path,omitempty"`

	// TrustAnchor selects where trust in the carrier's TLS certificate comes
	// from: tlsconfig.TrustPrivateCA (the default, and what every profile
	// written before this field existed gets) or tlsconfig.TrustWebPKI, for a
	// deployment behind a TLS-TERMINATING CDN.
	//
	// It is the profile-level expression of the defect
	// WINN3_UDP_BLOCK_SURVIVABILITY_20260808.md §4.1 named: with a mandatory
	// private root, the TCP carrier could only terminate at the gateway itself,
	// so surviving a UDP block cost the node's real address. See
	// tlsconfig.TrustAnchor for why the public WebPKI is a sound anchor on this
	// carrier specifically — the carrier response is ML-DSA-verified against
	// pinned controller keys, so TLS supplies camouflage rather than
	// authentication.
	//
	// Empty means private-ca. That default is deliberate HERE and deliberately
	// not the default inside tlsconfig: this document has a version and a
	// schema, so an absent field means "written before the field existed" and
	// resolving it to today's behaviour is the only reading that leaves
	// existing profiles working. tlsconfig has no such context and refuses.
	TrustAnchor string `json:"trust_anchor,omitempty"`

	// ECHConfigListPath is the Encrypted Client Hello config list. Mandatory,
	// because the Winn TLS profile is a single-probe fingerprint without it.
	ECHConfigListPath string `json:"ech_config_list_path"`

	// AuthorizationMode is carrierauth.AuthModeIdentity. The anonymous-token
	// mode is refused; see ErrAnonymousRouteUnimplemented.
	AuthorizationMode string `json:"authorization_mode"`

	// DeviceID is the registered device identifier the carrier signs as.
	DeviceID string `json:"device_id"`

	// DeviceAlgorithm is the device's ML-DSA parameter set: pqauth.MLDSA65 or
	// pqauth.MLDSA87.
	DeviceAlgorithm string `json:"device_pq_algorithm"`

	// DeviceSeedPath is the device's ML-DSA private seed. Never inlined.
	DeviceSeedPath string `json:"device_seed_path"`

	// ClientCertPath and ClientKeyPath are the mTLS client credential identity
	// mode requires.
	ClientCertPath string `json:"client_cert_path"`
	ClientKeyPath  string `json:"client_key_path"`

	// SessionID is 32 lowercase hex characters, per mobility.ValidSessionID. It
	// is bound into every signed carrier request.
	SessionID string `json:"session_id"`

	// SequenceEpoch defaults to SessionID when empty, matching NewH3Dialer and
	// NewH2Dialer.
	SequenceEpoch string `json:"sequence_epoch,omitempty"`

	// ManifestDigest is the 64-character lowercase hex digest of the gateway
	// manifest this session claims to be operating under. The server compares
	// it. carrierauth.LabManifestDigest (all zeros) is the lab value.
	ManifestDigest string `json:"manifest_digest"`

	// MaxInnerDatagram bounds one AmneziaWG datagram inside the envelope. Zero
	// selects carrier.DefaultMaxDatagram.
	MaxInnerDatagram int `json:"max_inner_datagram,omitempty"`

	// PrivacyProfile is carrierauth.PrivacyStandard or PrivacyHighRisk. It
	// decides envelope length padding: high-risk pads, standard does not.
	PrivacyProfile string `json:"privacy_profile,omitempty"`

	// ManifestPath is present only so a profile that names a manifest is
	// REFUSED loudly rather than silently ignored. See
	// ErrManifestRouteUnimplemented.
	ManifestPath string `json:"manifest_path,omitempty"`

	// --- Alternative connection initiation (Single Packet Authorization) ---
	//
	// Every field below is optional and every one is inert unless SPAMode is
	// SPAModeRequired; setting any of them without the mode is a refusal, not a
	// default. A profile that omits all of them parses exactly as it did before
	// these fields existed, which is why adding them does not invalidate a
	// profile any platform host writes today.

	// SPAMode is SPAModeOff (the default, and what an absent field means) or
	// SPAModeRequired.
	SPAMode string `json:"spa_mode,omitempty"`

	// SPAKeyPath names the file holding this client's current SPA key, one
	// hex-encoded key per line, exactly one line for a client. It is a PATH,
	// like every other credential here: this package never opens it and never
	// parses a key. knock.LoadKeysFromFile, the loader that owns the format,
	// reads it in BuildDialer.
	//
	// The key is a deployment-scoped shared secret with no analogue in the
	// per-device ML-DSA registry. It is generated and rotated by the owner, out
	// of band, through the same channel as the trust-root fingerprint; nothing
	// in this module generates, prints, or persists one.
	SPAKeyPath string `json:"spa_key_path,omitempty"`

	// SPATarget is the "IP:port" the knock datagram is addressed to. It is
	// REQUIRED when SPA is on and deliberately has no default: the gate may sit
	// in front of the carrier listener or in front of the AmneziaWG gateway
	// named by PublicTarget, and a wrong guess would send the deployment's
	// shared credential to a host that is not supposed to have it. Same IP
	// literal rule as PublicTarget, for the same reason.
	SPATarget string `json:"spa_target,omitempty"`

	// SPAPacketSize is the exact knock datagram size, which must equal the
	// gate's. Zero derives the size the way cmd/winn-carrier-server already
	// sizes this deployment's QUIC Initial packets —
	// carrier.H3InitialPacketSize(MaxInnerDatagram + CarrierEnvelopeOverhead) —
	// so a knock is the same size class as the only other pre-handshake
	// datagram the carrier port legitimately receives, rather than a new one.
	// An explicit value exists because a gate in front of an AmneziaWG port has
	// a different population to blend into than one in front of a QUIC port.
	SPAPacketSize int `json:"spa_packet_size,omitempty"`

	// SPABucketWindowSeconds and SPAMaxSkewSeconds are the freshness policy: no
	// timestamp is transmitted, so the verifier tries time buckets near its own
	// clock, and these say how wide a bucket is and how far either way to try.
	// They are policy, not secrets. They must match the gate's or every knock
	// simply fails to verify — which fails closed, not open. Zero uses
	// internal/knock's defaults (10s buckets, 60s skew).
	SPABucketWindowSeconds int `json:"spa_bucket_window_seconds,omitempty"`
	SPAMaxSkewSeconds      int `json:"spa_max_skew_seconds,omitempty"`
}

// SPAOptions returns the freshness policy this profile describes. It is only
// meaningful when SPAMode is SPAModeRequired.
func (profile Profile) SPAOptions() knock.Options {
	return knock.Options{
		BucketWindow: time.Duration(profile.SPABucketWindowSeconds) * time.Second,
		MaxSkew:      time.Duration(profile.SPAMaxSkewSeconds) * time.Second,
	}
}

// LoadProfile reads and validates a carrier profile document.
//
// The file is read with securefile.ReadPrivateLimited, so a profile whose mode
// lets another uid read it is refused before it is parsed. On Android the
// profile lives under the application's own files directory, which is 0700 and
// not backed up.
func LoadProfile(path string) (Profile, error) {
	if strings.TrimSpace(path) == "" {
		return Profile{}, errors.New("winn carrier profile path is required")
	}
	blob, err := securefile.ReadPrivateLimited(path, MaxProfileBytes)
	if err != nil {
		return Profile{}, fmt.Errorf("winn carrier profile: %w", err)
	}
	return ParseProfile(blob)
}

// ParseProfile decodes and validates a profile document.
func ParseProfile(blob []byte) (Profile, error) {
	if err := rejectDuplicateJSONKeys(blob); err != nil {
		return Profile{}, fmt.Errorf("winn carrier profile: %w", err)
	}
	var profile Profile
	decoder := json.NewDecoder(strings.NewReader(string(blob)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("winn carrier profile: %w", err)
	}
	if decoder.More() {
		return Profile{}, errors.New(
			"winn carrier profile must be a single JSON object",
		)
	}
	return profile.normalize()
}

func (profile Profile) normalize() (Profile, error) {
	if profile.Profile != ProfileVersion {
		return Profile{}, fmt.Errorf("%w (got %q)",
			ErrProfileVersion, profile.Profile)
	}
	// Refused before anything else is read, so a profile that believes it is
	// manifest-verified never has its own transport fields consulted.
	if strings.TrimSpace(profile.ManifestPath) != "" {
		return Profile{}, ErrManifestRouteUnimplemented
	}
	switch profile.AuthorizationMode {
	case carrierauth.AuthModeIdentity:
	case carrierauth.AuthModeAnonymousToken:
		return Profile{}, ErrAnonymousRouteUnimplemented
	case "":
		return Profile{}, errors.New(
			"winn carrier profile authorization_mode is required",
		)
	default:
		return Profile{}, fmt.Errorf(
			"winn carrier profile authorization_mode %q is unknown",
			profile.AuthorizationMode,
		)
	}

	switch profile.Carrier {
	case CarrierHTTP3:
		if profile.MASQUETemplate == "" {
			return Profile{}, fmt.Errorf(
				"%w: %s needs masque_template",
				ErrCarrierFieldMismatch, CarrierHTTP3,
			)
		}
		if profile.H2URL != "" {
			return Profile{}, fmt.Errorf(
				"%w: h2_url is set on a %s profile",
				ErrCarrierFieldMismatch, CarrierHTTP3,
			)
		}
		if err := validateAbsoluteHTTPS(profile.MASQUETemplate); err != nil {
			return Profile{}, fmt.Errorf(
				"winn carrier profile masque_template: %w", err,
			)
		}
	case CarrierHTTP2:
		if profile.H2URL == "" {
			return Profile{}, fmt.Errorf(
				"%w: %s needs h2_url",
				ErrCarrierFieldMismatch, CarrierHTTP2,
			)
		}
		if profile.MASQUETemplate != "" {
			return Profile{}, fmt.Errorf(
				"%w: masque_template is set on a %s profile",
				ErrCarrierFieldMismatch, CarrierHTTP2,
			)
		}
		if err := validateAbsoluteHTTPS(profile.H2URL); err != nil {
			return Profile{}, fmt.Errorf("winn carrier profile h2_url: %w", err)
		}
	case "":
		return Profile{}, errors.New("winn carrier profile carrier is required")
	default:
		return Profile{}, fmt.Errorf("%w (requested %q)",
			ErrCarrierUnsupported, profile.Carrier)
	}

	// The public target is the address the proxy is asked to reach, and it is
	// authenticated into every request. A hostname here would be resolved by
	// the PROXY, not by this device, so the DNS-leak rule that governs
	// datapath.Config.GatewayEndpoint does not apply — but an IP literal is
	// still required, because the AmneziaWG gateway is named by address
	// everywhere else in this client and a hostname would be a second, silent
	// naming scheme.
	if err := validateIPLiteralEndpoint(profile.PublicTarget); err != nil {
		return Profile{}, fmt.Errorf(
			"winn carrier profile public_target: %w", err,
		)
	}
	if strings.TrimSpace(profile.ServerName) == "" {
		return Profile{}, errors.New(
			"winn carrier profile server_name is required; it is the inner " +
				"ClientHello name the carrier certificate must match",
		)
	}
	if strings.TrimSpace(profile.Suite) == "" {
		return Profile{}, errors.New("winn carrier profile suite is required")
	}
	if strings.TrimSpace(profile.ControllerID) == "" {
		return Profile{}, errors.New(
			"winn carrier profile controller_id is required",
		)
	}
	normalizedProfile, err := profile.normalizeTrustAnchor()
	if err != nil {
		return Profile{}, err
	}
	profile = normalizedProfile

	required := []struct {
		field string
		value string
	}{
		{"controller_pins_path", profile.ControllerPinsPath},
		{"ech_config_list_path", profile.ECHConfigListPath},
		{"device_seed_path", profile.DeviceSeedPath},
		{"client_cert_path", profile.ClientCertPath},
		{"client_key_path", profile.ClientKeyPath},
	}
	if profile.TrustAnchor == string(tlsconfig.TrustPrivateCA) {
		required = append(required, struct {
			field string
			value string
		}{"root_ca_path", profile.RootCAPath})
	}
	for _, entry := range required {
		if strings.TrimSpace(entry.value) == "" {
			return Profile{}, fmt.Errorf(
				"winn carrier profile %s is required", entry.field,
			)
		}
	}
	if strings.TrimSpace(profile.DeviceID) == "" {
		return Profile{}, errors.New(
			"winn carrier profile device_id is required in identity mode",
		)
	}
	switch profile.DeviceAlgorithm {
	case pqauth.MLDSA65, pqauth.MLDSA87:
	case "":
		return Profile{}, errors.New(
			"winn carrier profile device_pq_algorithm is required; it names " +
				"the ML-DSA parameter set the device key was generated for",
		)
	default:
		return Profile{}, fmt.Errorf(
			"winn carrier profile device_pq_algorithm %q is not an ML-DSA "+
				"parameter set this build knows", profile.DeviceAlgorithm,
		)
	}
	if !mobility.ValidSessionID(profile.SessionID) {
		return Profile{}, errors.New(
			"winn carrier profile session_id must be 32 lowercase hexadecimal " +
				"characters",
		)
	}
	if profile.SequenceEpoch == "" {
		profile.SequenceEpoch = profile.SessionID
	} else if !mobility.ValidSessionID(profile.SequenceEpoch) {
		return Profile{}, errors.New(
			"winn carrier profile sequence_epoch must be 32 lowercase " +
				"hexadecimal characters",
		)
	}
	if !validManifestDigest(profile.ManifestDigest) {
		return Profile{}, errors.New(
			"winn carrier profile manifest_digest must be 64 lowercase " +
				"hexadecimal characters; it is the digest the carrier server " +
				"compares, so an absent value would silently claim a different " +
				"deployment",
		)
	}
	if profile.MaxInnerDatagram == 0 {
		profile.MaxInnerDatagram = carrier.DefaultMaxDatagram
	}
	if profile.MaxInnerDatagram < minInnerDatagram ||
		profile.MaxInnerDatagram > carrier.AbsoluteMaxDatagram {
		return Profile{}, fmt.Errorf(
			"winn carrier profile max_inner_datagram must be within [%d, %d], "+
				"got %d",
			minInnerDatagram, carrier.AbsoluteMaxDatagram,
			profile.MaxInnerDatagram,
		)
	}
	switch profile.PrivacyProfile {
	case carrierauth.PrivacyHighRisk:
	case "":
		// The zero value pads, matching EnvelopeConfig.DisableLengthPadding,
		// so a profile that says nothing about padding still gets the defence.
		profile.PrivacyProfile = carrierauth.PrivacyHighRisk
	case carrierauth.PrivacyStandard:
	default:
		return Profile{}, fmt.Errorf(
			"winn carrier profile privacy_profile %q is unknown",
			profile.PrivacyProfile,
		)
	}
	// Last, because the derived knock size depends on MaxInnerDatagram having
	// already been defaulted and range-checked above.
	return profile.normalizeSPA()
}

// normalizeSPA validates the alternative-initiation fields.
//
// The whole block is written as "off unless the mode says otherwise, and any
// other spa_ field without the mode is an error", so there is no arrangement of
// these fields that quietly half-enables SPA.
func (profile Profile) normalizeSPA() (Profile, error) {
	switch profile.SPAMode {
	case "":
		profile.SPAMode = SPAModeOff
		fallthrough
	case SPAModeOff:
		// Refused, not ignored: a key path or target left behind after SPA was
		// turned off is the operator believing something is armed that is not.
		for _, stray := range []struct {
			field string
			set   bool
		}{
			{"spa_key_path", strings.TrimSpace(profile.SPAKeyPath) != ""},
			{"spa_target", strings.TrimSpace(profile.SPATarget) != ""},
			{"spa_packet_size", profile.SPAPacketSize != 0},
			{"spa_bucket_window_seconds", profile.SPABucketWindowSeconds != 0},
			{"spa_max_skew_seconds", profile.SPAMaxSkewSeconds != 0},
		} {
			if stray.set {
				return Profile{}, fmt.Errorf("%w (%s is set)",
					ErrSPAFieldWithoutMode, stray.field)
			}
		}
		return profile, nil
	case SPAModeRequired:
	default:
		return Profile{}, fmt.Errorf(
			"winn carrier profile spa_mode %q is unknown; it is %q or %q",
			profile.SPAMode, SPAModeOff, SPAModeRequired,
		)
	}

	// A UDP knock cannot ride the stream carrier's connected TCP socket.
	if profile.Carrier == CarrierHTTP2 {
		return Profile{}, ErrSPAStreamCarrierUnsupported
	}
	if strings.TrimSpace(profile.SPAKeyPath) == "" {
		return Profile{}, errors.New(
			"winn carrier profile spa_key_path is required when spa_mode is " +
				SPAModeRequired,
		)
	}
	if err := validateIPLiteralEndpoint(profile.SPATarget); err != nil {
		return Profile{}, fmt.Errorf(
			"winn carrier profile spa_target: %w", err,
		)
	}
	if profile.SPAPacketSize == 0 {
		profile.SPAPacketSize = int(carrier.H3InitialPacketSize(
			profile.MaxInnerDatagram + carrier.CarrierEnvelopeOverhead,
		))
	}
	// One datagram, never fragmented: a censor that already drops or flags
	// fragmented UDP would make the knock a worse fingerprint than no SPA at
	// all. AbsoluteMaxDatagram is this module's own single-datagram ceiling.
	if profile.SPAPacketSize < knock.HeaderSize ||
		profile.SPAPacketSize > carrier.AbsoluteMaxDatagram {
		return Profile{}, fmt.Errorf(
			"winn carrier profile spa_packet_size must be within [%d, %d], got %d",
			knock.HeaderSize, carrier.AbsoluteMaxDatagram, profile.SPAPacketSize,
		)
	}
	if profile.SPABucketWindowSeconds < 0 || profile.SPAMaxSkewSeconds < 0 {
		return Profile{}, errors.New(
			"winn carrier profile spa_bucket_window_seconds and " +
				"spa_max_skew_seconds must not be negative",
		)
	}
	// knock.Options.resolve is the authority on the rest of the rules (bucket
	// at least a second, skew at least a bucket, bounded candidate count).
	// Rather than restate them here and let the two drift, ask it directly, on
	// a throwaway packet size it will not reject.
	if _, _, err := knock.Verify(
		make([]byte, knock.HeaderSize), [][]byte{make([]byte, 32)},
		time.Unix(0, 0), profile.SPAOptions(),
	); err != nil && !errors.Is(err, knock.ErrUnauthenticated) {
		return Profile{}, fmt.Errorf(
			"winn carrier profile spa freshness policy: %w", err,
		)
	}
	return profile, nil
}

// minInnerDatagram mirrors datapath.MinDatagram: a WireGuard transport-data
// message is 32 bytes of header plus a 16-byte tag, so nothing shorter is a
// frame worth carrying. It is restated rather than imported because importing
// datapath here would make the dependency circular.
const minInnerDatagram = 32

// SocketKind reports the socket the host must open, protect and hand over for
// this profile. A host can read it before it opens anything.
func (profile Profile) SocketKind() carrier.SocketKind {
	if profile.Carrier == CarrierHTTP2 {
		return carrier.SocketKindStream
	}
	return carrier.SocketKindPacket
}

// DescribeForLog is a redacted summary. The profile itself names private files
// and must never be logged whole.
// normalizeTrustAnchor resolves and validates the trust anchor, and enforces
// the one coupling that makes a fronted profile safe rather than merely
// possible.
//
// A TLS-terminating CDN is the peer of the mTLS handshake, so the ORIGIN never
// sees the device certificate that identity-mode authorization compares the
// signed claims against (carrierauth.RequestVerifier.Verify). A webpki profile
// in identity mode would therefore connect and then be refused at the origin,
// having handed the CDN a persistent device identifier on the way. Refusing it
// here turns that into a configuration error, which is where it belongs.
func (profile Profile) normalizeTrustAnchor() (Profile, error) {
	switch profile.TrustAnchor {
	case "":
		// Written before the field existed. See the field comment.
		profile.TrustAnchor = string(tlsconfig.TrustPrivateCA)
	case string(tlsconfig.TrustPrivateCA):
	case string(tlsconfig.TrustWebPKI):
		if strings.TrimSpace(profile.RootCAPath) != "" {
			return Profile{}, fmt.Errorf("%w: %s names root_ca_path",
				tlsconfig.ErrTrustRootCAConflict, tlsconfig.TrustWebPKI)
		}
		if profile.AuthorizationMode != carrierauth.AuthModeAnonymousToken {
			return Profile{}, fmt.Errorf(
				"%w: trust_anchor %s requires authorization_mode %s",
				tlsconfig.ErrTrustWebPKIWithClientCertificate,
				tlsconfig.TrustWebPKI, carrierauth.AuthModeAnonymousToken,
			)
		}
	default:
		return Profile{}, fmt.Errorf("%w (got %q)",
			tlsconfig.ErrTrustAnchorUnknown, profile.TrustAnchor)
	}
	return profile, nil
}

// ClientTrust is the trust anchor this profile describes, in the form
// tlsconfig takes. It is the single place the profile's string is turned into
// the typed anchor, so a profile field and a TLS configuration cannot drift.
func (profile Profile) ClientTrust() tlsconfig.ClientTrust {
	anchor := profile.TrustAnchor
	if anchor == "" {
		anchor = string(tlsconfig.TrustPrivateCA)
	}
	return tlsconfig.ClientTrust{
		Anchor:     tlsconfig.TrustAnchor(anchor),
		RootCAPath: profile.RootCAPath,
	}
}

// CarrierEndpoint is what this profile connects to, as the failover path needs
// it for mobility.Path.Endpoint.
//
// It reads the field belonging to the carrier the profile names rather than
// picking whichever is non-empty, because normalize has already refused a
// profile that sets the other carrier's field and that refusal is worth
// depending on rather than working around.
func (profile Profile) CarrierEndpoint() string {
	switch profile.Carrier {
	case CarrierHTTP3:
		return profile.MASQUETemplate
	case CarrierHTTP2:
		return profile.H2URL
	default:
		return ""
	}
}

func (profile Profile) DescribeForLog() string {
	spaMode := profile.SPAMode
	if spaMode == "" {
		spaMode = SPAModeOff
	}
	return fmt.Sprintf(
		"winn carrier profile: carrier=%s suite=%s mode=%s privacy=%s "+
			"socket=%s max_inner_datagram=%d manifest_verified=false spa=%s "+
			"trust=%s",
		profile.Carrier, profile.Suite, profile.AuthorizationMode,
		profile.PrivacyProfile, profile.SocketKind(), profile.MaxInnerDatagram,
		spaMode, profile.ClientTrust().Anchor,
	)
}

func validateAbsoluteHTTPS(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("does not parse as a URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return errors.New("must use the https scheme")
	}
	if parsed.Host == "" {
		return errors.New("must be absolute and name a host")
	}
	return nil
}

// validateIPLiteralEndpoint applies datapath.validateIPLiteralEndpoint's rule.
func validateIPLiteralEndpoint(endpoint string) error {
	if endpoint == "" {
		return errors.New("endpoint is required")
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return fmt.Errorf(
			"endpoint must be an IP literal with a port, not a hostname: %w",
			err,
		)
	}
	if address.Port() == 0 {
		return errors.New("endpoint port must be nonzero")
	}
	ip := address.Addr()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("endpoint address is not a routable unicast literal")
	}
	return nil
}

func validManifestDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		default:
			return false
		}
	}
	return true
}

// rejectDuplicateJSONKeys walks the document once and refuses a repeated
// object key. encoding/json otherwise keeps the last value with no error,
// which is a silent override of whatever the first occurrence configured.
func rejectDuplicateJSONKeys(blob []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(blob)))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("must be a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("object key is not a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w %q", ErrDuplicateJSONKey, key)
		}
		seen[key] = struct{}{}
		if err := skipJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %v", delim)
	}
}
