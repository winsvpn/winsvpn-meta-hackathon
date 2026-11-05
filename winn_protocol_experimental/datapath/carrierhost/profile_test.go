package carrierhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pqauth"
)

// validProfile is the baseline every case below mutates. The paths do not have
// to exist: normalize validates the DOCUMENT, and BuildDialer is what opens the
// files. Keeping the two apart is deliberate — a host should be able to reject a
// malformed profile without touching a private key.
func validProfile() Profile {
	return Profile{
		Profile:            ProfileVersion,
		Carrier:            CarrierHTTP3,
		MASQUETemplate:     "https://carrier.invalid/.well-known/masque/udp/{target_host}/{target_port}/",
		PublicTarget:       "203.0.113.9:51820",
		ServerName:         "carrier.invalid",
		Suite:              "x25519-mlkem768",
		ControllerID:       "lab-controller",
		ControllerPinsPath: "/winn/pins.json",
		RootCAPath:         "/winn/ca.pem",
		ECHConfigListPath:  "/winn/ech.bin",
		AuthorizationMode:  carrierauth.AuthModeIdentity,
		DeviceID:           "device-0001",
		DeviceAlgorithm:    pqauth.MLDSA65,
		DeviceSeedPath:     "/winn/device.seed",
		ClientCertPath:     "/winn/device.crt",
		ClientKeyPath:      "/winn/device.key",
		SessionID:          "0123456789abcdef0123456789abcdef",
		ManifestDigest:     carrierauth.LabManifestDigest,
	}
}

func encode(t *testing.T, profile Profile) []byte {
	t.Helper()
	blob, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("encode profile: %v", err)
	}
	return blob
}

func TestValidProfileNormalizes(t *testing.T) {
	parsed, err := ParseProfile(encode(t, validProfile()))
	if err != nil {
		t.Fatalf("valid profile was refused: %v", err)
	}
	if parsed.SequenceEpoch != parsed.SessionID {
		t.Fatalf("sequence_epoch defaulted to %q, want the session id",
			parsed.SequenceEpoch)
	}
	if parsed.MaxInnerDatagram != carrier.DefaultMaxDatagram {
		t.Fatalf("max_inner_datagram defaulted to %d, want %d",
			parsed.MaxInnerDatagram, carrier.DefaultMaxDatagram)
	}
	// The zero value must pad. A profile that says nothing about padding is the
	// common case, and the defence has to be on by default or "says nothing"
	// becomes "leaks inner datagram lengths one-to-one".
	if parsed.PrivacyProfile != carrierauth.PrivacyHighRisk {
		t.Fatalf("privacy_profile defaulted to %q, want %q",
			parsed.PrivacyProfile, carrierauth.PrivacyHighRisk)
	}
	if parsed.SocketKind() != carrier.SocketKindPacket {
		t.Fatalf("%s wants a %q socket, want %q",
			parsed.Carrier, parsed.SocketKind(), carrier.SocketKindPacket)
	}
}

// TestHTTP2ProfileWantsAStreamSocket is the field a host reads BEFORE it opens
// anything. Getting it wrong means protecting the wrong kind of socket.
func TestHTTP2ProfileWantsAStreamSocket(t *testing.T) {
	profile := validProfile()
	profile.Carrier = CarrierHTTP2
	profile.MASQUETemplate = ""
	profile.H2URL = "https://carrier.invalid" + carrier.H2Path
	parsed, err := ParseProfile(encode(t, profile))
	if err != nil {
		t.Fatalf("valid HTTP/2 profile was refused: %v", err)
	}
	if parsed.SocketKind() != carrier.SocketKindStream {
		t.Fatalf("%s wants a %q socket, want %q",
			parsed.Carrier, parsed.SocketKind(), carrier.SocketKindStream)
	}
}

// TestManifestRouteIsRefusedNotIgnored is the one refusal that is about honesty
// rather than correctness: a profile that names a manifest must not have its own
// transport fields read as though the manifest had been checked.
func TestManifestRouteIsRefusedNotIgnored(t *testing.T) {
	profile := validProfile()
	profile.ManifestPath = "/winn/manifest-v2.json"
	_, err := ParseProfile(encode(t, profile))
	if !errors.Is(err, ErrManifestRouteUnimplemented) {
		t.Fatalf("manifest profile error = %v, want ErrManifestRouteUnimplemented", err)
	}
}

func TestAnonymousModeIsRefused(t *testing.T) {
	profile := validProfile()
	profile.AuthorizationMode = carrierauth.AuthModeAnonymousToken
	_, err := ParseProfile(encode(t, profile))
	if !errors.Is(err, ErrAnonymousRouteUnimplemented) {
		t.Fatalf("anonymous profile error = %v, want ErrAnonymousRouteUnimplemented", err)
	}
}

// TestDirectAWGIsNotABuildableCarrierHere keeps the profile from becoming a
// second way to ask for the unauthenticated carrier. direct-awg has no dialer;
// a profile that named it could only ever mean "downgrade me".
func TestDirectAWGIsNotABuildableCarrierHere(t *testing.T) {
	profile := validProfile()
	profile.Carrier = "direct-awg"
	_, err := ParseProfile(encode(t, profile))
	if !errors.Is(err, ErrCarrierUnsupported) {
		t.Fatalf("direct-awg profile error = %v, want ErrCarrierUnsupported", err)
	}
}

// TestCarriersWithoutASuppliedSocketDialerAreRefused covers the four carriers
// internal/connectivity names but internal/carrier has no dialer for. They must
// not be reachable through the profile either.
func TestCarriersWithoutASuppliedSocketDialerAreRefused(t *testing.T) {
	for _, name := range []string{
		"reality-xhttp", "websocket-tls", "native-two-hop", "privacy-two-hop",
	} {
		profile := validProfile()
		profile.Carrier = name
		if _, err := ParseProfile(encode(t, profile)); !errors.Is(
			err, ErrCarrierUnsupported,
		) {
			t.Fatalf("carrier %q error = %v, want ErrCarrierUnsupported",
				name, err)
		}
	}
}

func TestCarrierFieldsMayNotCrossOver(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Profile)
		wantErr error
	}{
		{
			name: "http3 without a template",
			mutate: func(profile *Profile) {
				profile.MASQUETemplate = ""
			},
			wantErr: ErrCarrierFieldMismatch,
		},
		{
			name: "http3 carrying an h2 url",
			mutate: func(profile *Profile) {
				profile.H2URL = "https://carrier.invalid" + carrier.H2Path
			},
			wantErr: ErrCarrierFieldMismatch,
		},
		{
			name: "http2 without a url",
			mutate: func(profile *Profile) {
				profile.Carrier = CarrierHTTP2
				profile.MASQUETemplate = ""
			},
			wantErr: ErrCarrierFieldMismatch,
		},
		{
			name: "http2 carrying a masque template",
			mutate: func(profile *Profile) {
				profile.Carrier = CarrierHTTP2
				profile.H2URL = "https://carrier.invalid" + carrier.H2Path
			},
			wantErr: ErrCarrierFieldMismatch,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			profile := validProfile()
			testCase.mutate(&profile)
			if _, err := ParseProfile(encode(t, profile)); !errors.Is(
				err, testCase.wantErr,
			) {
				t.Fatalf("error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

// TestEveryTrustAnchorIsMandatory is the heart of the refusal matrix. Each of
// these fields is something the session's post-quantum guarantees depend on;
// none may default to absent.
func TestEveryTrustAnchorIsMandatory(t *testing.T) {
	cases := map[string]func(*Profile){
		"controller_pins_path": func(p *Profile) { p.ControllerPinsPath = "" },
		"root_ca_path":         func(p *Profile) { p.RootCAPath = "" },
		"ech_config_list_path": func(p *Profile) { p.ECHConfigListPath = "" },
		"device_seed_path":     func(p *Profile) { p.DeviceSeedPath = "" },
		"client_cert_path":     func(p *Profile) { p.ClientCertPath = "" },
		"client_key_path":      func(p *Profile) { p.ClientKeyPath = "" },
		"controller_id":        func(p *Profile) { p.ControllerID = "" },
		"server_name":          func(p *Profile) { p.ServerName = "" },
		"suite":                func(p *Profile) { p.Suite = "" },
		"device_id":            func(p *Profile) { p.DeviceID = "" },
		"device_pq_algorithm":  func(p *Profile) { p.DeviceAlgorithm = "" },
		"manifest_digest":      func(p *Profile) { p.ManifestDigest = "" },
		"authorization_mode":   func(p *Profile) { p.AuthorizationMode = "" },
		"public_target":        func(p *Profile) { p.PublicTarget = "" },
		"session_id":           func(p *Profile) { p.SessionID = "" },
	}
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			if _, err := ParseProfile(encode(t, profile)); err == nil {
				t.Fatalf("a profile with no %s was accepted", field)
			}
		})
	}
}

func TestMalformedScalarsAreRefused(t *testing.T) {
	cases := map[string]func(*Profile){
		"hostname public target":    func(p *Profile) { p.PublicTarget = "gateway.invalid:51820" },
		"unspecified public target": func(p *Profile) { p.PublicTarget = "0.0.0.0:51820" },
		"zero-port public target":   func(p *Profile) { p.PublicTarget = "203.0.113.9:0" },
		"http template":             func(p *Profile) { p.MASQUETemplate = "http://carrier.invalid/x" },
		"relative template":         func(p *Profile) { p.MASQUETemplate = "/relative/path" },
		"short session id":          func(p *Profile) { p.SessionID = "0123" },
		"uppercase session id":      func(p *Profile) { p.SessionID = "0123456789ABCDEF0123456789ABCDEF" },
		"short manifest digest":     func(p *Profile) { p.ManifestDigest = "abc" },
		"uppercase manifest digest": func(p *Profile) { p.ManifestDigest = strings.ToUpper(carrierauth.LabManifestDigest[:63]) + "A" },
		"unknown device algorithm":  func(p *Profile) { p.DeviceAlgorithm = "ed25519" },
		"unknown privacy profile":   func(p *Profile) { p.PrivacyProfile = "medium" },
		"tiny max inner datagram":   func(p *Profile) { p.MaxInnerDatagram = 31 },
		"oversize max inner datagram": func(p *Profile) {
			p.MaxInnerDatagram = carrier.AbsoluteMaxDatagram + 1
		},
		"bad sequence epoch": func(p *Profile) { p.SequenceEpoch = "not-hex" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			if _, err := ParseProfile(encode(t, profile)); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestUnknownFieldsAndWrongVersionAreRefused(t *testing.T) {
	if _, err := ParseProfile([]byte(
		`{"profile":"` + ProfileVersion + `","carier":"http3-connect-udp"}`,
	)); err == nil {
		t.Fatal("a misspelled key was accepted")
	}
	profile := validProfile()
	profile.Profile = "winn-carrier-profile/0"
	if _, err := ParseProfile(encode(t, profile)); !errors.Is(
		err, ErrProfileVersion,
	) {
		t.Fatalf("version error = %v, want ErrProfileVersion", err)
	}
	blob := encode(t, validProfile())
	if _, err := ParseProfile(append(blob, blob...)); err == nil {
		t.Fatal("two concatenated objects were accepted")
	}
}

// TestLoadProfileRefusesAWorldReadableFile is the file-mode half of the
// boundary. The profile names private key files; a profile another uid can read
// is a map to them.
func TestLoadProfileRefusesAWorldReadableFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "carrier-profile.json")
	if err := os.WriteFile(path, encode(t, validProfile()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); err == nil {
		t.Fatal("a group/other-readable carrier profile was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); err != nil {
		t.Fatalf("an owner-only carrier profile was refused: %v", err)
	}
}

func TestLoadProfileRequiresAPath(t *testing.T) {
	if _, err := LoadProfile("   "); err == nil {
		t.Fatal("a blank carrier profile path was accepted")
	}
}

// TestDescribeForLogNamesNoPath is what keeps a stderr line from turning into a
// list of the private files on the device.
func TestDescribeForLogNamesNoPath(t *testing.T) {
	profile, err := ParseProfile(encode(t, validProfile()))
	if err != nil {
		t.Fatal(err)
	}
	description := profile.DescribeForLog()
	for _, secret := range []string{
		profile.ControllerPinsPath, profile.RootCAPath,
		profile.ECHConfigListPath, profile.DeviceSeedPath,
		profile.ClientCertPath, profile.ClientKeyPath,
		profile.SessionID, profile.DeviceID, profile.MASQUETemplate,
	} {
		if strings.Contains(description, secret) {
			t.Fatalf("DescribeForLog leaked %q: %s", secret, description)
		}
	}
	// It must still say the one thing an operator needs to know about this
	// route, which is that no manifest was verified.
	if !strings.Contains(description, "manifest_verified=false") {
		t.Fatalf("DescribeForLog does not disclose the route: %s", description)
	}
}

// TestDuplicateJSONKeysAreRefused is the silent-override guard. encoding/json
// keeps the last value of a repeated key and reports no error, so a document
// that named privacy_profile twice could disable length padding while still
// looking like a high-risk profile in the first occurrence.
func TestDuplicateJSONKeysAreRefused(t *testing.T) {
	blob := encode(t, validProfile())
	dup := append(append([]byte(nil), blob[:len(blob)-1]...),
		[]byte(`,"privacy_profile":"high-risk","privacy_profile":"standard"}`)...)
	_, err := ParseProfile(dup)
	if !errors.Is(err, ErrDuplicateJSONKey) {
		t.Fatalf("duplicate privacy_profile error = %v, want ErrDuplicateJSONKey", err)
	}
	if err == nil || !strings.Contains(err.Error(), "privacy_profile") {
		t.Fatalf("duplicate-key error does not name the field: %v", err)
	}
	// Control: the same field, once, still parses. This is the no-mutation
	// half — without it a broken parser would make the refusal above a false
	// green.
	profile := validProfile()
	profile.PrivacyProfile = carrierauth.PrivacyStandard
	parsed, err := ParseProfile(encode(t, profile))
	if err != nil {
		t.Fatalf("a single privacy_profile was refused: %v", err)
	}
	if parsed.PrivacyProfile != carrierauth.PrivacyStandard {
		t.Fatalf("privacy_profile = %q, want %q",
			parsed.PrivacyProfile, carrierauth.PrivacyStandard)
	}
}
