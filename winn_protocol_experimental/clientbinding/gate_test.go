package clientbinding

import "testing"

// TestConfigEligibilityRefusalBothDirections proves the config-issuance gate
// through the client-facing binding in both directions: an old client is
// refused a winn/3 config, a winn/3-capable client is not.
func TestConfigEligibilityRefusalBothDirections(t *testing.T) {
	// Negative: every pre-winn/3 client must be refused issuance.
	for _, version := range []string{"winn/1", "winn/2", "winn/v1", ""} {
		if refusal := ConfigEligibilityRefusal(version, true); refusal == "" {
			t.Fatalf(
				"ConfigEligibilityRefusal(%q, ready=true) = empty, want refusal: "+
					"an old client must never receive a winn/3 config",
				version,
			)
		}
	}
	// Negative 2: declaring winn/3 without the ability to negotiate must also
	// be refused — it is the safe_to_advertise_protocol=false case.
	if refusal := ConfigEligibilityRefusal(ProtocolVersion(), false); refusal == "" {
		t.Fatal(
			"ConfigEligibilityRefusal(winn/3, ready=false) = empty, want refusal",
		)
	}
	// Positive: a winn/3-capable client is eligible.
	if refusal := ConfigEligibilityRefusal(ProtocolVersion(), true); refusal != "" {
		t.Fatalf(
			"ConfigEligibilityRefusal(winn/3, ready=true) = %q, want empty",
			refusal,
		)
	}
}
