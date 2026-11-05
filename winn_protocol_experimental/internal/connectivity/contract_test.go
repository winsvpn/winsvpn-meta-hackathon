package connectivity

import (
	"strings"
	"testing"
	"time"
)

func TestModesNeverSilentlyWeaken(t *testing.T) {
	tests := []struct {
		mode    Mode
		allowed []Carrier
	}{
		{ModeFast, []Carrier{CarrierDirectAWG}},
		{ModeAuto, []Carrier{
			CarrierDirectAWG, CarrierHTTP3, CarrierHTTP2,
			CarrierRealityXHTTP, CarrierWebSocketTLS,
		}},
		{ModeStealth, []Carrier{CarrierRealityXHTTP, CarrierWebSocketTLS}},
		{ModePrivateRelay, []Carrier{CarrierNativeTwoHop}},
		{ModeMaximumPrivacy, []Carrier{CarrierPrivacyTwoHop}},
	}
	all := []Carrier{
		CarrierDirectAWG, CarrierHTTP3, CarrierHTTP2,
		CarrierRealityXHTTP, CarrierWebSocketTLS,
		CarrierNativeTwoHop, CarrierPrivacyTwoHop,
	}
	for _, test := range tests {
		for _, carrier := range all {
			want := false
			for _, allowed := range test.allowed {
				want = want || carrier == allowed
			}
			if got := test.mode.Allows(carrier); got != want {
				t.Fatalf(
					"mode %q allows %q = %v, want %v",
					test.mode, carrier, got, want,
				)
			}
		}
	}
}

func TestReadinessRejectsExpiredAndModeDowngrade(t *testing.T) {
	now := time.Now().UTC()
	readiness := validReadiness(now, ModeStealth, []CandidateDescriptor{{
		ID:        "direct",
		Carrier:   CarrierDirectAWG,
		NodeID:    "node-1",
		ExpiresAt: now.Add(time.Minute),
	}})
	if err := readiness.Validate(now); err == nil ||
		!strings.Contains(err.Error(), "does not permit") {
		t.Fatalf("stealth downgrade validation error = %v", err)
	}
	readiness.Mode = ModeFast
	readiness.ExpiresAt = now
	if err := readiness.Validate(now); err == nil ||
		!strings.Contains(err.Error(), "lifetime") {
		t.Fatalf("expired readiness validation error = %v", err)
	}
}

func validReadiness(
	now time.Time,
	mode Mode,
	candidates []CandidateDescriptor,
) Readiness {
	return Readiness{
		Profile:           "default",
		Mode:              mode,
		ManifestDigest:    strings.Repeat("a", 64),
		ManifestExpiresAt: now.Add(time.Hour),
		PSKGeneration:     7,
		PSKExpiresAt:      now.Add(time.Hour),
		UnusedCredentials: 8,
		PreparedAt:        now.Add(-time.Second),
		ExpiresAt:         now.Add(59 * time.Second),
		Candidates:        candidates,
	}
}
