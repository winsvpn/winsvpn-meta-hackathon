package main

// Tests for the -carrier-fallback shipping entry point.
//
// This is the seam that makes internal/carrier.Manager's multi-candidate
// failover reachable from something other than a lab client. What the tests
// below protect is not the failover itself — datapath/failover_test.go does
// that against real sockets — but the two things this process is uniquely
// responsible for: it holds the descriptor, so it must be the one to refuse a
// failover that would need an unprotected socket; and it holds every profile,
// so it must refuse a malformed set BEFORE a transport exists rather than at
// Create time, when a censor is already blocking the primary.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/datapath/carrierhost"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pqauth"
)

func writeProfileFile(t *testing.T, profile carrierhost.Profile) string {
	t.Helper()
	blob, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// syntacticProfile is well-formed enough for LoadProfile. It names paths that
// need not exist, because nothing here builds a dialer: every test below fails
// before BuildDialer, which is the point — these are the refusals that must
// happen before any credential is opened.
func syntacticProfile(carrierName string) carrierhost.Profile {
	profile := carrierhost.Profile{
		Profile:            carrierhost.ProfileVersion,
		Carrier:            carrierName,
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
	switch carrierName {
	case carrierhost.CarrierHTTP3:
		profile.MASQUETemplate =
			"https://carrier.invalid/.well-known/masque/udp/{target_host}/{target_port}/"
	case carrierhost.CarrierHTTP2:
		profile.H2URL = "https://carrier.invalid/winn/stream"
	}
	return profile
}

// TestFallbackWithoutAPrimaryIsTheMeasuredCase. direct-awg has no profile — the
// datapath builds it from the gateway endpoint — so the invocation that answers
// the measured defect is fallbacks with NO -carrier-profile at all. Requiring a
// primary would have excluded exactly the case this feature exists for.
func TestFallbackWithoutAPrimaryIsTheMeasuredCase(t *testing.T) {
	path := writeProfileFile(t, syntacticProfile(carrierhost.CarrierHTTP2))
	carriers, err := loadCarriers(options{carrierFallback: profilePaths{path}})
	if err != nil {
		t.Fatalf("a fallback without a primary must be accepted: %v", err)
	}
	if carriers.head != nil {
		t.Fatal("no primary profile was supplied")
	}
	if len(carriers.fallbacks) != 1 ||
		carriers.fallbacks[0].Carrier != carrierhost.CarrierHTTP2 {
		t.Fatalf("fallbacks are %v", carriers.fallbacks)
	}
}

func TestFallbackRefusesADuplicateCarrier(t *testing.T) {
	head := writeProfileFile(t, syntacticProfile(carrierhost.CarrierHTTP2))
	same := writeProfileFile(t, syntacticProfile(carrierhost.CarrierHTTP2))
	_, err := loadCarriers(options{
		carrierProfile:  head,
		carrierFallback: profilePaths{same},
	})
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("the same carrier twice must be refused: %v", err)
	}
}

// TestEveryProfileIsValidatedBeforeAnyTransport is the ordering guarantee. A
// malformed FALLBACK must kill the process at startup, not at Create time, when
// the primary is already being blocked and there is no second chance.
func TestEveryProfileIsValidatedBeforeAnyTransport(t *testing.T) {
	head := writeProfileFile(t, syntacticProfile(carrierhost.CarrierHTTP3))
	broken := syntacticProfile(carrierhost.CarrierHTTP2)
	broken.Suite = ""
	brokenPath := writeProfileFile(t, broken)
	_, err := loadCarriers(options{
		carrierProfile:  head,
		carrierFallback: profilePaths{brokenPath},
	})
	if err == nil || !strings.Contains(err.Error(), "suite") {
		t.Fatalf("a malformed fallback must be refused at load: %v", err)
	}
}

func TestLoadCarriersWithoutFallbacksIsUnchanged(t *testing.T) {
	// No profile at all: the shape every shipping Android host starts in.
	carriers, err := loadCarriers(options{})
	if err != nil {
		t.Fatal(err)
	}
	if carriers.head != nil || len(carriers.fallbacks) != 0 {
		t.Fatal("a plain invocation must carry no carrier profile")
	}

	head := writeProfileFile(t, syntacticProfile(carrierhost.CarrierHTTP3))
	carriers, err = loadCarriers(options{carrierProfile: head})
	if err != nil {
		t.Fatal(err)
	}
	if carriers.head == nil {
		t.Fatal("the primary profile was dropped")
	}
	if len(carriers.fallbacks) != 0 {
		t.Fatalf("a single-profile invocation gained %d fallbacks",
			len(carriers.fallbacks))
	}
}

// TestFailoverRefusesASuppliedDescriptor is this process's own half of the
// socket rule. The datapath refuses too, but this is the process that HOLDS the
// descriptor, so it is the one that can say what the operator should do
// instead — and it must refuse before it builds a dialer that would open the
// device's ML-DSA seed.
func TestFailoverRefusesASuppliedDescriptor(t *testing.T) {
	fallback := syntacticProfile(carrierhost.CarrierHTTP2)
	carriers := carrierSet{fallbacks: []carrierhost.Profile{fallback}}
	blob := measuredScenarioConfig(t)
	_, err := openWithFailover(blob, 7, carriers)
	if !errors.Is(err, datapath.ErrFailoverSuppliedSocket) {
		t.Fatalf("failover with a descriptor must be refused: %v", err)
	}
	if !strings.Contains(err.Error(), "allow_own_socket") {
		t.Fatalf("the refusal must say what to do instead: %v", err)
	}
}

// TestFailoverRefusesACarrierDisagreementOnTheHead also exercises the rule that
// http3-connect-udp is legal as a plan HEAD and illegal as a target: a session
// may legitimately be running on it for mobility and still want a plan.
func TestFailoverRefusesACarrierDisagreementOnTheHead(t *testing.T) {
	head := syntacticProfile(carrierhost.CarrierHTTP2)
	fallback := syntacticProfile(carrierhost.CarrierHTTP2)
	carriers := carrierSet{head: &head, fallbacks: []carrierhost.Profile{fallback}}

	config := datapath.Config{
		Contract:        datapath.ContractVersion,
		Payload:         datapath.PayloadAWGDatagram,
		Carrier:         datapath.CarrierHTTP3,
		GatewayEndpoint: "127.0.0.1:51820",
		AllowOwnSocket:  true,
		Escalation: datapath.EscalationConfig{
			Mode: datapath.EscalationObserve,
			Plan: []string{datapath.CarrierHTTP3, datapath.CarrierHTTP2},
		},
	}
	blob, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = openWithFailover(blob, -1, carriers)
	if err == nil || !strings.Contains(err.Error(), "carrier disagreement") {
		t.Fatalf("a head disagreement must be refused: %v", err)
	}
}

// TestFailoverNeedsAProfileForANonDirectHead closes the other direction: a
// configuration naming an envelope carrier with no profile to build it must be
// refused rather than silently starting on the fallback.
func TestFailoverNeedsAProfileForANonDirectHead(t *testing.T) {
	fallback := syntacticProfile(carrierhost.CarrierHTTP2)
	carriers := carrierSet{fallbacks: []carrierhost.Profile{fallback}}
	config := datapath.Config{
		Contract:        datapath.ContractVersion,
		Payload:         datapath.PayloadAWGDatagram,
		Carrier:         datapath.CarrierHTTP3,
		GatewayEndpoint: "127.0.0.1:51820",
		AllowOwnSocket:  true,
		Escalation: datapath.EscalationConfig{
			Mode: datapath.EscalationObserve,
			Plan: []string{datapath.CarrierHTTP3, datapath.CarrierHTTP2},
		},
	}
	blob, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = openWithFailover(blob, -1, carriers)
	if err == nil || !strings.Contains(err.Error(), "-carrier-profile") {
		t.Fatalf("a head with no profile must be refused: %v", err)
	}
}

// measuredScenarioConfig is scenario B's shape: a session on direct-awg with a
// plan that escalates to the one carrier a UDP block does not touch.
func measuredScenarioConfig(t *testing.T) []byte {
	t.Helper()
	blob, err := json.Marshal(datapath.Config{
		Contract:        datapath.ContractVersion,
		Payload:         datapath.PayloadAWGDatagram,
		Carrier:         datapath.CarrierDirectAWG,
		GatewayEndpoint: "127.0.0.1:51820",
		AllowOwnSocket:  true,
		Escalation: datapath.EscalationConfig{
			Mode: datapath.EscalationObserve,
			Plan: []string{
				datapath.CarrierDirectAWG, datapath.CarrierHTTP2,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestProfilePathsFlagRefusesAnEmptyValue(t *testing.T) {
	var paths profilePaths
	if err := paths.Set("  "); err == nil {
		t.Fatal("an empty -carrier-fallback must be refused")
	}
	if err := paths.Set("/winn/a.json"); err != nil {
		t.Fatal(err)
	}
	if err := paths.Set("/winn/b.json"); err != nil {
		t.Fatal(err)
	}
	if got := paths.String(); got != "/winn/a.json,/winn/b.json" {
		t.Fatalf("flag renders as %q", got)
	}
}
