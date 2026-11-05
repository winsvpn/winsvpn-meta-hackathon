package clientbinding

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestTunnelIsNotAdvertisedWithoutAnEngine is the load-bearing negative half of
// this package. A client that advertises winn/3 without a carrier would
// silently downgrade a post-quantum negotiation, which is exactly what the
// Flutter engine's refusal exists to prevent. When NO relay engine is present,
// every one of these must hold: TunnelSupported false, an empty carrier list,
// safe_to_advertise_protocol false, Connect failing closed, and Disconnect
// reporting a condition. If someone flips TunnelSupported or the advertise flag
// without a backend to back it, this fails.
func TestTunnelIsNotAdvertisedWithoutAnEngine(t *testing.T) {
	t.Setenv(engineEnv, "") // force the no-backend build for this test
	var report struct {
		TunnelSupported bool     `json:"tunnel_supported"`
		Advertise       bool     `json:"safe_to_advertise_protocol"`
		Carriers        []string `json:"carrier_backends_available"`
	}
	if TunnelSupported() {
		t.Fatal("without an engine, TunnelSupported must be false")
	}
	if err := json.Unmarshal([]byte(TunnelBackendJSON()), &report); err != nil {
		t.Fatalf("TunnelBackendJSON is not valid JSON: %v", err)
	}
	if report.TunnelSupported || report.Advertise || len(report.Carriers) != 0 {
		t.Fatalf("backend report claims capability this build does not have: %+v", report)
	}
	if _, err := Connect("{}"); err == nil {
		t.Fatal("Connect must fail closed while no carrier backend exists")
	}
	if err := SendPacket("x"); err == nil {
		t.Fatal("SendPacket with no session must error, never drop silently")
	}
	// The line-34 contract: Disconnect must report a condition when nothing is
	// up. Cleared first so a session from another test cannot mask it.
	_ = Disconnect()
	if err := Disconnect(); err == nil {
		t.Fatal("Disconnect must report a condition when nothing is connected")
	} else if !errors.Is(err, ErrNoActiveSession) {
		t.Fatalf("Disconnect = %v, want the no-session condition", err)
	}
}

func TestVersionsAreDistinct(t *testing.T) {
	if ProtocolVersion() != "winn/3" {
		t.Fatalf("ProtocolVersion = %q, want winn/3", ProtocolVersion())
	}
	if RekeyProtocolVersion() != "winn/2" {
		t.Fatalf("RekeyProtocolVersion = %q, want winn/2", RekeyProtocolVersion())
	}
	if ProtocolVersion() == RekeyProtocolVersion() {
		t.Fatal("the connectivity contract and the rekey sub-protocol are separately versioned")
	}
}

func TestSuiteAndAuthAlgorithmBinding(t *testing.T) {
	for suite, algorithm := range map[string]string{
		"x25519-mlkem768": "mldsa65",
		"p256-mlkem768":   "mldsa65",
		"p384-mlkem1024":  "mldsa87",
	} {
		got, err := RequiredAuthAlgorithm(suite)
		if err != nil {
			t.Fatalf("RequiredAuthAlgorithm(%q): %v", suite, err)
		}
		if got != algorithm {
			t.Fatalf("RequiredAuthAlgorithm(%q) = %q, want %q", suite, got, algorithm)
		}
		capabilities, err := CapabilitiesJSON(suite)
		if err != nil {
			t.Fatalf("CapabilitiesJSON(%q): %v", suite, err)
		}
		if !strings.Contains(capabilities, "awg-preshared-key-32") {
			t.Fatalf("CapabilitiesJSON(%q) missing the PSK capability: %s", suite, capabilities)
		}
	}
	if _, err := RequiredAuthAlgorithm("rsa2048"); err == nil {
		t.Fatal("an unsupported suite must be an error, never a silent empty algorithm")
	}
	if _, err := CapabilitiesJSON("rsa2048"); err == nil {
		t.Fatal("an unsupported suite must not yield an empty capability list")
	}
}

func TestModeCarrierPolicy(t *testing.T) {
	// Fast must never permit an obfuscated carrier, and stealth must never
	// permit bare direct AWG. These are the two directions that matter.
	fast, err := CarriersForModeJSON("fast")
	if err != nil {
		t.Fatalf("CarriersForModeJSON(fast): %v", err)
	}
	if fast != `["direct-awg"]` {
		t.Fatalf("fast carriers = %s, want [\"direct-awg\"]", fast)
	}
	stealth, err := CarriersForModeJSON("stealth")
	if err != nil {
		t.Fatalf("CarriersForModeJSON(stealth): %v", err)
	}
	if strings.Contains(stealth, "direct-awg") {
		t.Fatalf("stealth must not permit direct-awg: %s", stealth)
	}
	if _, err := CarriersForModeJSON("turbo"); err == nil {
		t.Fatal("an unknown mode must be rejected")
	}
}

func TestValidatorsRejectBadDocuments(t *testing.T) {
	if err := ValidateReadinessJSON(`{"Profile":"p"}`); err == nil {
		t.Fatal("an incomplete readiness document must be rejected")
	}
	if err := ValidateReadinessJSON(`not json`); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
	if err := ValidateBindingJSON(`{"AttemptID":"short"}`); err == nil {
		t.Fatal("an invalid binding must be rejected")
	}
	if err := ValidateDeviceID("bad id with spaces"); err == nil {
		t.Fatal("device IDs with spaces must be rejected")
	}
	if err := ValidateDeviceID("device-01"); err != nil {
		t.Fatalf("a well-formed device ID must be accepted: %v", err)
	}
	// 32 zero bytes, base64: a structurally valid but forbidden peer key.
	if err := ValidatePeerPublicKey(strings.Repeat("A", 42) + "="); err == nil {
		t.Fatal("an all-zero peer public key must be rejected")
	}
}

func TestValidateBindingAcceptsAWellFormedDocument(t *testing.T) {
	document := map[string]any{
		"AttemptID":      strings.Repeat("a", 32),
		"Profile":        "default",
		"Mode":           "auto",
		"ManifestDigest": strings.Repeat("0", 64),
		"CandidateID":    "candidate-1",
		"NodeID":         "node-1",
		"SessionID":      strings.Repeat("b", 32),
		"PSKGeneration":  1,
		"SequenceEpoch":  1,
		"Nonce":          strings.Repeat("c", 32),
		"ExpiresAt":      time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBindingJSON(string(encoded)); err != nil {
		t.Fatalf("a well-formed binding must validate: %v", err)
	}
}

// TestOmittedEngineSocketFDIsNotStdin is the negative half of the descriptor
// contract at parse time. spawnEngine treats engine_socket_fd >= 0 as "hand
// this descriptor to the child as fd 3". encoding/json leaves an omitted int
// at 0, and 0 is stdin. The documented Connect JSON omits the field, so a
// caller following that document would currently donate stdin to the engine.
// An explicit 0 must still decode as 0: that is a real (if unusual) descriptor
// the caller named, not the omit case.
func TestOmittedEngineSocketFDIsNotStdin(t *testing.T) {
	cfg, err := parseConnectConfig(`{"keys":"/x","create":{"payload":"ip-packet"}}`)
	if err != nil {
		t.Fatalf("parseConnectConfig: %v", err)
	}
	if cfg.EngineSocketFD >= 0 {
		t.Fatalf("omitted engine_socket_fd decoded as %d; 0 is stdin and spawnEngine would hand it to the child as fd 3",
			cfg.EngineSocketFD)
	}
	explicitZero, err := parseConnectConfig(`{"keys":"/x","engine_socket_fd":0,"create":{"payload":"ip-packet"}}`)
	if err != nil {
		t.Fatalf("explicit 0: %v", err)
	}
	if explicitZero.EngineSocketFD != 0 {
		t.Fatalf("explicit engine_socket_fd 0 decoded as %d, want 0", explicitZero.EngineSocketFD)
	}
	explicitNeg, err := parseConnectConfig(`{"keys":"/x","engine_socket_fd":-1,"create":{"payload":"ip-packet"}}`)
	if err != nil {
		t.Fatalf("explicit -1: %v", err)
	}
	if explicitNeg.EngineSocketFD != -1 {
		t.Fatalf("explicit engine_socket_fd -1 decoded as %d, want -1", explicitNeg.EngineSocketFD)
	}
}
