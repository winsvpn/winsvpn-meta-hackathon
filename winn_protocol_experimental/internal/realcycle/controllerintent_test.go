package realcycle

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestControllerCycleIntentRoundTripAndNonAuthority(t *testing.T) {
	fixture := newAdmissionFixture(t, TransportH3)
	admission, err := ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, bindingBytes, err := NewControllerCycleBinding(
		admission, validControllerBindingInput(),
	)
	if err != nil {
		t.Fatal(err)
	}
	intent, encoded, err := NewControllerCycleIntent(bindingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if intent.State != "pending" || intent.DispatchAuthorized ||
		intent.Mutation != "none" || !validDigest(intent.ObjectDigest) {
		t.Fatalf("unsafe intent: %+v", intent)
	}
	replayed, err := ParseControllerCycleIntent(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ControllerBindingDigest != intent.ControllerBindingDigest ||
		replayed.ControllerBindingSHA256 != intent.ControllerBindingSHA256 ||
		replayed.AdmissionBundleSHA256 != admission.AdmissionBundleSHA256 {
		t.Fatalf("unexpected replay: %+v", replayed)
	}
	reencoded, err := marshalCanonical(replayed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("intent did not round-trip canonically")
	}
}

func TestControllerCycleIntentRejectsTerminalOrAuthorityClaims(t *testing.T) {
	fixture := newAdmissionFixture(t, TransportDirect)
	admission, err := ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, bindingBytes, err := NewControllerCycleBinding(
		admission, validControllerBindingInput(),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, encoded, err := NewControllerCycleIntent(bindingBytes)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name  string
		field string
		value any
	}{
		{"terminal-state", "state", "complete"},
		{"dispatch", "dispatch_authorized", true},
		{"mutation", "mutation", "spawn"},
		{"digest", "controller_binding_sha256", raw["object_digest"]},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			copyMap := make(map[string]any, len(raw))
			for key, value := range raw {
				copyMap[key] = value
			}
			copyMap[mutation.field] = mutation.value
			data, err := json.Marshal(copyMap)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseControllerCycleIntent(data); err == nil {
				t.Fatal("mutated intent unexpectedly accepted")
			}
		})
	}
}
