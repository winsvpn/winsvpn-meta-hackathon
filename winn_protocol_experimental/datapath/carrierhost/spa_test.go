package carrierhost

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/knock"
	"winsvpn.local/winnprotocol/internal/knockdial"
)

// validSPAProfile is validProfile plus the minimum that turns SPA on.
func validSPAProfile() Profile {
	profile := validProfile()
	profile.SPAMode = SPAModeRequired
	profile.SPAKeyPath = "/winn/spa.key"
	profile.SPATarget = "203.0.113.9:9110"
	return profile
}

// TestSchemaKeysArePinned is the schema pin. Adding a field to Profile without
// adding it here is a failure, which is the point: the document is mirrored by
// hand in WinnCarrierProfile.kt (CARRIER_KEYS), WinsWinnCarrierProfile.swift
// (carrierProfileKeys) and linux_winn_host.cc (kKnownKeys), none of which the
// Go compiler can check. A field that exists here and nowhere there is a field
// no platform host can ever set, and this list is where that is noticed.
//
// The five spa_ keys below are NOT yet in those three mirrors. That is
// deliberate and recorded rather than hidden: they are all omitempty and all
// inert without spa_mode, so every profile those hosts write today parses
// byte-for-byte as it did before, and wiring them into the hosts is a separate,
// app-side change.
func TestSchemaKeysArePinned(t *testing.T) {
	want := []string{
		"authorization_mode",
		"carrier",
		"client_cert_path",
		"client_key_path",
		"controller_id",
		"controller_pins_path",
		"device_id",
		"device_pq_algorithm",
		"device_seed_path",
		"ech_config_list_path",
		"h2_url",
		"manifest_digest",
		"manifest_path",
		"masque_template",
		"max_inner_datagram",
		"privacy_profile",
		"profile",
		"public_target",
		"root_ca_path",
		"sequence_epoch",
		"server_name",
		"session_id",
		"spa_bucket_window_seconds",
		"spa_key_path",
		"spa_max_skew_seconds",
		"spa_mode",
		"spa_packet_size",
		"spa_target",
		"suite",
		"trust_anchor",
	}
	profileType := reflect.TypeOf(Profile{})
	got := make([]string, 0, profileType.NumField())
	for index := range profileType.NumField() {
		tag := profileType.Field(index).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			t.Fatalf("field %s has no json name", profileType.Field(index).Name)
		}
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("profile json keys changed.\n got: %v\nwant: %v", got, want)
	}
	// The count is restated so a same-size swap (one key renamed to another)
	// cannot pass by accident if the lists are ever edited together carelessly.
	if len(got) != 30 {
		t.Fatalf("profile has %d json keys, want 30", len(got))
	}
}

// TestProfileWithoutSPAIsUnchanged is the backward-compatibility guarantee:
// every profile a platform host writes today still parses, and reads as off.
func TestProfileWithoutSPAIsUnchanged(t *testing.T) {
	parsed, err := ParseProfile(encode(t, validProfile()))
	if err != nil {
		t.Fatalf("a profile with no spa_ fields was refused: %v", err)
	}
	if parsed.SPAMode != SPAModeOff {
		t.Fatalf("spa_mode defaulted to %q, want %q", parsed.SPAMode, SPAModeOff)
	}
	if parsed.SPAPacketSize != 0 || parsed.SPATarget != "" || parsed.SPAKeyPath != "" {
		t.Fatal("an off profile grew spa values it never asked for")
	}
	if !strings.Contains(parsed.DescribeForLog(), "spa="+SPAModeOff) {
		t.Fatalf("DescribeForLog does not report the spa mode: %q",
			parsed.DescribeForLog())
	}
}

// TestSPAPacketSizeDerivesFromTheCarrierSizing: an unset size must land on the
// same value cmd/winn-carrier-server uses for this deployment's QUIC Initial
// packets, so a knock is the same size class as the only other pre-handshake
// datagram the port legitimately sees rather than a new one.
func TestSPAPacketSizeDerivesFromTheCarrierSizing(t *testing.T) {
	parsed, err := ParseProfile(encode(t, validSPAProfile()))
	if err != nil {
		t.Fatalf("a valid SPA profile was refused: %v", err)
	}
	want := int(carrier.H3InitialPacketSize(
		carrier.DefaultMaxDatagram + carrier.CarrierEnvelopeOverhead,
	))
	if parsed.SPAPacketSize != want {
		t.Fatalf("spa_packet_size derived to %d, want %d", parsed.SPAPacketSize, want)
	}
	if !strings.Contains(parsed.DescribeForLog(), "spa="+SPAModeRequired) {
		t.Fatalf("DescribeForLog does not report the spa mode: %q",
			parsed.DescribeForLog())
	}
	// The freshness policy defaults to internal/knock's, not to zero.
	options := parsed.SPAOptions()
	if options.BucketWindow != 0 || options.MaxSkew != 0 {
		t.Fatalf("unset freshness fields produced %+v, want the zero Options "+
			"that internal/knock resolves to its own defaults", options)
	}
}

// TestSPAPacketSizeFollowsMaxInnerDatagram proves the derivation is not a
// constant: the ORDER in normalize matters, because the size depends on
// max_inner_datagram having been defaulted and range-checked first.
func TestSPAPacketSizeFollowsMaxInnerDatagram(t *testing.T) {
	profile := validSPAProfile()
	profile.MaxInnerDatagram = 600
	parsed, err := ParseProfile(encode(t, profile))
	if err != nil {
		t.Fatal(err)
	}
	want := int(carrier.H3InitialPacketSize(600 + carrier.CarrierEnvelopeOverhead))
	if parsed.SPAPacketSize != want {
		t.Fatalf("spa_packet_size = %d, want %d derived from max_inner_datagram",
			parsed.SPAPacketSize, want)
	}
	if want == int(carrier.H3InitialPacketSize(
		carrier.DefaultMaxDatagram+carrier.CarrierEnvelopeOverhead,
	)) {
		t.Fatal("this case does not actually differ from the default; it proves nothing")
	}
}

// TestSPAFieldsWithoutTheModeAreRefused is the honesty rule: a key path or a
// target left behind after SPA was turned off must not read as "off, nothing to
// see here". The operator would believe a defence was armed.
func TestSPAFieldsWithoutTheModeAreRefused(t *testing.T) {
	cases := map[string]func(*Profile){
		"spa_key_path":              func(p *Profile) { p.SPAKeyPath = "/winn/spa.key" },
		"spa_target":                func(p *Profile) { p.SPATarget = "203.0.113.9:9110" },
		"spa_packet_size":           func(p *Profile) { p.SPAPacketSize = 1200 },
		"spa_bucket_window_seconds": func(p *Profile) { p.SPABucketWindowSeconds = 10 },
		"spa_max_skew_seconds":      func(p *Profile) { p.SPAMaxSkewSeconds = 60 },
	}
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			profile := validProfile() // spa_mode absent
			mutate(&profile)
			_, err := ParseProfile(encode(t, profile))
			if !errors.Is(err, ErrSPAFieldWithoutMode) {
				t.Fatalf("error = %v, want ErrSPAFieldWithoutMode", err)
			}
			// Explicit "off" must behave identically to absent.
			profile.SPAMode = SPAModeOff
			if _, err := ParseProfile(encode(t, profile)); !errors.Is(
				err, ErrSPAFieldWithoutMode,
			) {
				t.Fatalf("explicit off error = %v, want ErrSPAFieldWithoutMode", err)
			}
		})
	}
}

// TestSPAOnTheStreamCarrierIsRefused. A UDP knock cannot ride the connected TCP
// socket the HTTP/2 carrier is handed, and a separate UDP socket would be less
// protected than the transport on the platform this route exists for.
func TestSPAOnTheStreamCarrierIsRefused(t *testing.T) {
	profile := validSPAProfile()
	profile.Carrier = CarrierHTTP2
	profile.MASQUETemplate = ""
	profile.H2URL = "https://carrier.invalid" + carrier.H2Path
	_, err := ParseProfile(encode(t, profile))
	if !errors.Is(err, ErrSPAStreamCarrierUnsupported) {
		t.Fatalf("error = %v, want ErrSPAStreamCarrierUnsupported", err)
	}
}

func TestSPAMalformedFieldsAreRefused(t *testing.T) {
	cases := map[string]func(*Profile){
		"unknown mode":            func(p *Profile) { p.SPAMode = "maybe" },
		"no key path":             func(p *Profile) { p.SPAKeyPath = "" },
		"blank key path":          func(p *Profile) { p.SPAKeyPath = "   " },
		"no target":               func(p *Profile) { p.SPATarget = "" },
		"hostname target":         func(p *Profile) { p.SPATarget = "gateway.invalid:9110" },
		"unspecified target":      func(p *Profile) { p.SPATarget = "0.0.0.0:9110" },
		"zero-port target":        func(p *Profile) { p.SPATarget = "203.0.113.9:0" },
		"portless target":         func(p *Profile) { p.SPATarget = "203.0.113.9" },
		"packet below the header": func(p *Profile) { p.SPAPacketSize = knock.HeaderSize - 1 },
		"packet needing fragmentation": func(p *Profile) {
			p.SPAPacketSize = carrier.AbsoluteMaxDatagram + 1
		},
		"negative packet size": func(p *Profile) { p.SPAPacketSize = -1 },
		"negative bucket":      func(p *Profile) { p.SPABucketWindowSeconds = -1 },
		"negative skew":        func(p *Profile) { p.SPAMaxSkewSeconds = -1 },
		// Not malformed: both zero is the DEFAULT and must be accepted. Kept in
		// this table so the boundary between "unset" and "wrong" is explicit.
		"unset freshness is not malformed": func(p *Profile) {
			p.SPABucketWindowSeconds = 0
			p.SPAMaxSkewSeconds = 0
		},
		"skew narrower than the bucket": func(p *Profile) {
			p.SPABucketWindowSeconds = 60
			p.SPAMaxSkewSeconds = 10
		},
		"skew needing too many buckets": func(p *Profile) {
			p.SPABucketWindowSeconds = 1
			p.SPAMaxSkewSeconds = 100000
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := validSPAProfile()
			mutate(&profile)
			_, err := ParseProfile(encode(t, profile))
			if name == "unset freshness is not malformed" {
				if err != nil {
					t.Fatalf("unset freshness fields were refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

// TestSPAFreshnessPolicyReachesKnock proves the seconds in the document become
// the durations internal/knock actually uses, rather than being parsed and
// dropped.
func TestSPAFreshnessPolicyReachesKnock(t *testing.T) {
	profile := validSPAProfile()
	profile.SPABucketWindowSeconds = 15
	profile.SPAMaxSkewSeconds = 120
	parsed, err := ParseProfile(encode(t, profile))
	if err != nil {
		t.Fatal(err)
	}
	options := parsed.SPAOptions()
	if options.BucketWindow != 15*time.Second || options.MaxSkew != 120*time.Second {
		t.Fatalf("SPAOptions = %+v, want 15s/120s", options)
	}
	// And a knock built under that policy verifies under it.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	packet, err := knock.Build(key, parsed.SPAPacketSize, time.Now(), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := knock.Verify(packet, [][]byte{key}, time.Now(), options); err != nil {
		t.Fatalf("a knock built under the profile's policy does not verify: %v", err)
	}
}

// --- wrapSPA --------------------------------------------------------------

type fakeCarrierDialer struct{ supplied net.PacketConn }

func (f *fakeCarrierDialer) Dial(context.Context) (net.PacketConn, error) {
	return nil, errors.New("not dialed in this test")
}
func (f *fakeCarrierDialer) SuppliedSocketKind() carrier.SocketKind {
	return carrier.SocketKindPacket
}
func (f *fakeCarrierDialer) HasSuppliedSocket() bool { return f.supplied != nil }
func (f *fakeCarrierDialer) UseSuppliedSocket(c net.PacketConn) error {
	f.supplied = c
	return nil
}

func writeSPAKeyFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spa.key")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestWrapSPALeavesAnOffProfileAlone: the decorator must be entirely absent, not
// merely inert, when SPA is off.
func TestWrapSPALeavesAnOffProfileAlone(t *testing.T) {
	inner := &fakeCarrierDialer{}
	got, err := wrapSPA(validProfile(), inner)
	if err != nil {
		t.Fatal(err)
	}
	if got != carrier.SuppliedSocketDialer(inner) {
		t.Fatal("an off profile still wrapped the dialer")
	}
}

// TestWrapSPAWrapsAndStillHoldsNoSocket is the invariant
// datapath.OpenWithCarrier enforces with ErrCarrierSocketReused. The wrapper
// must not make the dialer look pre-loaded.
func TestWrapSPAWrapsAndStillHoldsNoSocket(t *testing.T) {
	profile := validSPAProfile()
	profile.SPAKeyPath = writeSPAKeyFile(t,
		"# this deployment's current SPA key",
		hex.EncodeToString(make([]byte, 32)),
	)
	normalized, err := profile.normalize()
	if err != nil {
		t.Fatal(err)
	}
	inner := &fakeCarrierDialer{}
	got, err := wrapSPA(normalized, inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(*knockdial.Dialer); !ok {
		t.Fatalf("wrapSPA returned %T, want *knockdial.Dialer", got)
	}
	if got.HasSuppliedSocket() {
		t.Fatal("the wrapped dialer reported holding a socket")
	}
	if got.SuppliedSocketKind() != carrier.SocketKindPacket {
		t.Fatalf("socket kind = %q, want %q",
			got.SuppliedSocketKind(), carrier.SocketKindPacket)
	}
}

func TestWrapSPAKeyFileRefusals(t *testing.T) {
	oneKey := hex.EncodeToString(make([]byte, 32))
	cases := map[string]struct {
		path      string
		wantInErr string
	}{
		"missing file": {
			path: filepath.Join(t.TempDir(), "absent.key"),
		},
		"two keys for a client": {
			path:      writeSPAKeyFile(t, oneKey, hex.EncodeToString(make([]byte, 24))),
			wantInErr: "exactly one key",
		},
		"empty file": {
			path: writeSPAKeyFile(t, "# only a comment"),
		},
		"not hex": {
			path: writeSPAKeyFile(t, "not-hex-at-all"),
		},
		"key too short": {
			path: writeSPAKeyFile(t, hex.EncodeToString(make([]byte, 8))),
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			profile := validSPAProfile()
			profile.SPAKeyPath = testCase.path
			normalized, err := profile.normalize()
			if err != nil {
				t.Fatal(err)
			}
			_, err = wrapSPA(normalized, &fakeCarrierDialer{})
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if testCase.wantInErr != "" && !strings.Contains(err.Error(), testCase.wantInErr) {
				t.Fatalf("error %q does not mention %q", err, testCase.wantInErr)
			}
			// No key file failure may ever quote the file's contents.
			if strings.Contains(err.Error(), oneKey) {
				t.Fatal("an error message quoted key material")
			}
		})
	}
}
