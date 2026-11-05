package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestControllerEnrollmentEndToEnd runs hop 2 of the E3 chain against a
// locally started controller: POST /v2/rekeys mints an x25519-mlkem768 AWG
// key with a 24h TTL, and the RekeyResponse names the registering device.
// Hub hops 1 and 3 are TestE3EnrollmentChain in chain_test.go.
func TestControllerEnrollmentEndToEnd(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-emit", "-"}, &buf); err != nil {
		t.Fatalf("controller enrollment end-to-end failed: %v", err)
	}
	var res result
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		t.Fatalf("decode probe result: %v\n%s", err, buf.String())
	}
	if res.Suite != "x25519-mlkem768" {
		t.Errorf("suite = %q, want x25519-mlkem768", res.Suite)
	}
	if res.Generation != 1 {
		t.Errorf("generation = %d, want 1", res.Generation)
	}
	if !res.KeyIDMatches {
		t.Error("served key_id does not bind controller/device/peer/generation/PSK")
	}
	if !res.LifetimeMatches {
		t.Errorf("key lifetime %s does not match -ttl %s", res.Lifetime, res.LifetimeTTL)
	}
	if res.LifetimeTTL != (24 * time.Hour).String() {
		t.Errorf("default -ttl = %s, want 24h0m0s", res.LifetimeTTL)
	}
	if !res.DescriptorNamesNode {
		t.Error("served descriptor does not name the registering node")
	}
	if !res.PSKAppliedBoth {
		t.Error("controller and device applied different PSKs")
	}
	if res.PSKSize != 32 {
		t.Errorf("issued AWG PSK is %d bytes, want 32", res.PSKSize)
	}
	if res.DeviceID != "device-android-1" {
		t.Errorf("device_id = %q, want device-android-1", res.DeviceID)
	}
}

// TestControllerEnrollmentHonorsTTL proves the probe passes the requested
// lifetime through to the minted key, so a deployer can shorten it.
func TestControllerEnrollmentHonorsTTL(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"-ttl", "1h", "-emit", "-"}, &buf); err != nil {
		t.Fatalf("controller enrollment with -ttl 1h failed: %v", err)
	}
	var res result
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		t.Fatalf("decode probe result: %v", err)
	}
	if res.LifetimeTTL != "1h0m0s" || !res.LifetimeMatches {
		t.Errorf("probe did not honor -ttl 1h: %+v", res)
	}
}

// TestControllerEnrollmentRejectsBadSuite guards the suite seam: the probe
// must fail closed rather than silently mint keys outside x25519-mlkem768.
func TestControllerEnrollmentRejectsBadSuite(t *testing.T) {
	var buf bytes.Buffer
	err := run([]string{"-suite", "not-a-suite", "-emit", "-"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "invalid suite") {
		t.Fatalf("expected invalid-suite rejection, got %v", err)
	}
}

// TestControllerEnrollmentRejectsBadTTL guards the lifetime seam.
func TestControllerEnrollmentRejectsBadTTL(t *testing.T) {
	var buf bytes.Buffer
	err := run([]string{"-ttl", "0s", "-emit", "-"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "-ttl must be positive") {
		t.Fatalf("expected bad-ttl rejection, got %v", err)
	}
}
