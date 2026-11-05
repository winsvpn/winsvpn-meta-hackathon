//go:build darwin

package main

// NOTE ON SCOPE: this file deliberately does not `import "C"`. Go's toolchain
// refuses cgo in a _test.go file belonging to `package main`
// ("use of cgo in test ... not supported"), so the cgo-exported
// WinnTunnelCreateWithCarrier itself cannot be exercised by `go test` here.
// openWithCarrierProfile is factored out precisely so the decision logic
// behind it can still be tested directly, with plain []byte and no C types.
// The cgo shell around it -- the two NULL checks and the handle-registry
// bookkeeping -- is identical in shape to WinnTunnelCreate's, which
// tools/verify_apple_winn_seam.sh and tools/verify_winn_abi_conformance.sh
// already exercise by compiling and linking a real C/Objective-C/Swift
// harness against the real archive; that is the intended coverage for the
// marshaling layer, not a Go-internal test.

import (
	"strings"
	"testing"
)

// validCarrierConfigJSON is the datapath.Config half of a carrier session:
// unchanged shape from a direct-awg config, only the carrier name differs.
func validCarrierConfigJSON(carrier string) []byte {
	return []byte(`{
		"contract": "winn-datapath/1",
		"payload": "awg-datagram",
		"carrier": "` + carrier + `",
		"gateway_endpoint": "203.0.113.9:51820"
	}`)
}

// validCarrierProfileJSON is a structurally complete carrierhost.Profile:
// every required field set, credential paths pointing at files that do not
// exist on this machine (on purpose -- see
// TestOpenWithCarrierProfile_MatchingProfileFailsClosedWithoutCredentials).
func validCarrierProfileJSON(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
		"profile": "winn-carrier-profile/1",
		"carrier": "http3-connect-udp",
		"masque_template": "https://carrier.example.invalid/.well-known/masque/udp/{target_host}/{target_port}/",
		"public_target": "203.0.113.9:51820",
		"server_name": "carrier.example.invalid",
		"suite": "x25519-mlkem768",
		"controller_id": "controller-under-test",
		"controller_pins_path": "/nonexistent/winn-carrier-profile-test/controller_pins.json",
		"root_ca_path": "/nonexistent/winn-carrier-profile-test/winn_root_ca.pem",
		"ech_config_list_path": "/nonexistent/winn-carrier-profile-test/ech_config_list.bin",
		"authorization_mode": "identity",
		"device_id": "device-under-test",
		"device_pq_algorithm": "mldsa65",
		"device_seed_path": "/nonexistent/winn-carrier-profile-test/device_mldsa_seed.bin",
		"client_cert_path": "/nonexistent/winn-carrier-profile-test/client_cert.pem",
		"client_key_path": "/nonexistent/winn-carrier-profile-test/client_key.pem",
		"session_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"manifest_digest": "0000000000000000000000000000000000000000000000000000000000000000",
		"privacy_profile": "high-risk"
	}`)
}

func TestOpenWithCarrierProfile_InvalidProfileJSON(t *testing.T) {
	_, err := openWithCarrierProfile(
		validCarrierConfigJSON("http3-connect-udp"),
		[]byte("{not json"),
		-1,
	)
	if err == nil {
		t.Fatal("expected an error for malformed carrier profile JSON, got nil")
	}
	if !strings.Contains(err.Error(), "carrier profile") {
		t.Fatalf("expected the error to name the carrier profile, got: %v", err)
	}
}

func TestOpenWithCarrierProfile_InvalidConfigJSON(t *testing.T) {
	_, err := openWithCarrierProfile(
		[]byte("{not json"),
		validCarrierProfileJSON(t),
		-1,
	)
	if err == nil {
		t.Fatal("expected an error for malformed datapath configuration JSON, got nil")
	}
	if !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("expected the error to name the datapath configuration, got: %v", err)
	}
}

// TestOpenWithCarrierProfile_RefusesDirectAWGWithProfile is the anti-downgrade
// check this function exists to enforce: a caller that already went to the
// trouble of building an authenticated carrier profile must never have it
// silently ignored in favour of plain UDP because the configuration named
// direct-awg (stale, mismatched, or forged).
func TestOpenWithCarrierProfile_RefusesDirectAWGWithProfile(t *testing.T) {
	_, err := openWithCarrierProfile(
		validCarrierConfigJSON("direct-awg"),
		validCarrierProfileJSON(t),
		-1,
	)
	if err == nil {
		t.Fatal("expected direct-awg with a carrier profile to be refused, got nil error")
	}
	if !strings.Contains(err.Error(), "refusing rather than opening an unauthenticated carrier") {
		t.Fatalf("expected the anti-downgrade refusal message, got: %v", err)
	}
}

// TestOpenWithCarrierProfile_RefusesCarrierMismatch proves the two documents
// cannot quietly disagree about which carrier this session runs.
func TestOpenWithCarrierProfile_RefusesCarrierMismatch(t *testing.T) {
	_, err := openWithCarrierProfile(
		validCarrierConfigJSON("http2-stream"),
		validCarrierProfileJSON(t), // profile carrier is http3-connect-udp
		-1,
	)
	if err == nil {
		t.Fatal("expected a carrier mismatch between config and profile to be refused, got nil error")
	}
	if !strings.Contains(err.Error(), "carrier disagreement") {
		t.Fatalf("expected the carrier-disagreement refusal message, got: %v", err)
	}
}

// TestOpenWithCarrierProfile_MatchingProfileFailsClosedWithoutCredentials is
// the honest, current state of this platform, exactly as it is on Android and
// Linux today: the seam is wired, the document is built and validated
// end-to-end by the REAL carrierhost.ParseProfile and REAL
// carrierhost.BuildDialer, and it fails closed -- loudly, before any socket or
// network is touched -- because no credential provisioning pipeline exists
// yet on any platform. This is what proves the engine, not the caller, opens
// the credential files the profile only names: BuildDialer's failure names a
// file this test process never touched.
func TestOpenWithCarrierProfile_MatchingProfileFailsClosedWithoutCredentials(t *testing.T) {
	_, err := openWithCarrierProfile(
		validCarrierConfigJSON("http3-connect-udp"),
		validCarrierProfileJSON(t),
		-1,
	)
	if err == nil {
		t.Fatal("expected a carrier session with unprovisioned credentials to fail, got nil error")
	}
	// BuildDialer loads the controller pins first (datapath/carrierhost/dialer.go),
	// so that is the file this fails on. Asserting the substring rather than
	// exact equality keeps this test from being rewritten every time the
	// wrapping changes upstream, while still proving the failure is a real
	// file-open failure and not a parse or validation failure.
	if !strings.Contains(err.Error(), "controller pins") {
		t.Fatalf(
			"expected the failure to name the controller pins (the first file "+
				"BuildDialer loads), got: %v", err,
		)
	}
}

// TestOpenWithCarrierProfile_UnbuildableCarrierIsNamed proves that a carrier
// this host cannot build at all (as opposed to one it can build but was not
// given a profile for) is refused with a message a caller can act on, and
// that it is refused before any file is touched.
func TestOpenWithCarrierProfile_UnbuildableCarrierIsNamed(t *testing.T) {
	profile := validCarrierProfileJSON(t)
	// A profile version this host cannot claim to honour.
	mutated := strings.Replace(
		string(profile), `"profile": "winn-carrier-profile/1"`,
		`"profile": "winn-carrier-profile/999"`, 1,
	)
	_, err := openWithCarrierProfile(
		validCarrierConfigJSON("http3-connect-udp"),
		[]byte(mutated),
		-1,
	)
	if err == nil {
		t.Fatal("expected an unrecognised carrier profile version to be refused, got nil error")
	}
	if !strings.Contains(err.Error(), "winn-carrier-profile/1") {
		t.Fatalf("expected the refusal to name the expected profile version, got: %v", err)
	}
}
