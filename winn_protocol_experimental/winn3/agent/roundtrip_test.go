package agent

import (
	"bytes"
	"encoding/json"
	"testing"
)

// roundtripCases returns one canonical Action per kind that exercises the wire
// form. Params are chosen to match productionContracts where the kind has
// required params, so the instance is also valid under ContractRegistry.
func roundtripCases() []Action {
	return []Action{
		{
			Kind: ActionConnect,
			Params: []Param{
				{Name: "gateway_id", Value: "gx10"},
				{Name: "host", Value: "spain-madrid:443"},
			},
			Policy: PolicyRef{Name: "default", Version: 3},
		},
		{
			Kind: ActionRotateKey,
			Params: []Param{
				{Name: "key_id", Value: "k-001"},
				{Name: "algorithm", Value: "ml-kem-768"},
			},
			Policy: PolicyRef{Name: "default", Version: 3},
		},
		{
			Kind:   ActionReport,
			Params: nil,
			Policy: PolicyRef{Name: "default", Version: 3},
		},
	}
}

// TestRoundtripActionByteStability marshals an Action, unmarshals it,
// re-marshals, and asserts the two byte slices are equal. It runs across every
// kind returned by AllKinds so the wire form cannot drift for any kind.
func TestRoundtripActionByteStability(t *testing.T) {
	cases := roundtripCases()

	// Verify we cover every kind in the closed set.
	kinds := AllKinds()
	if len(kinds) != len(cases) {
		t.Fatalf("roundtrip cases %d != valid kinds %d; update roundtripCases", len(cases), len(kinds))
	}
	seen := map[ActionKind]bool{}
	for _, c := range cases {
		seen[c.Kind] = true
	}
	for _, k := range kinds {
		if !seen[k] {
			t.Fatalf("kind %q missing from roundtrip cases", k)
		}
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.Kind), func(t *testing.T) {
			first, err := json.Marshal(tc)
			if err != nil {
				t.Fatalf("first marshal kind %q: %v", tc.Kind, err)
			}
			var decoded Action
			if err := json.Unmarshal(first, &decoded); err != nil {
				t.Fatalf("unmarshal kind %q: %v", tc.Kind, err)
			}
			second, err := json.Marshal(decoded)
			if err != nil {
				t.Fatalf("second marshal kind %q: %v", tc.Kind, err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("byte stability failed for kind %q\nfirst : %s\nsecond: %s", tc.Kind, string(first), string(second))
			}
			// Also verify structural equality survives the roundtrip.
			if decoded.Kind != tc.Kind {
				t.Errorf("kind after roundtrip %q != before %q", decoded.Kind, tc.Kind)
			}
			if decoded.Policy != tc.Policy {
				t.Errorf("policy after roundtrip %+v != before %+v", decoded.Policy, tc.Policy)
			}
			if len(decoded.Params) != len(tc.Params) {
				t.Errorf("params len after roundtrip %d != before %d", len(decoded.Params), len(tc.Params))
			} else {
				for i := range tc.Params {
					if decoded.Params[i] != tc.Params[i] {
						t.Errorf("param[%d] after %+v != before %+v", i, decoded.Params[i], tc.Params[i])
					}
				}
			}
			// Double roundtrip to catch non-idempotent encodings.
			var decoded2 Action
			if err := json.Unmarshal(second, &decoded2); err != nil {
				t.Fatalf("second unmarshal kind %q: %v", tc.Kind, err)
			}
			third, err := json.Marshal(decoded2)
			if err != nil {
				t.Fatalf("third marshal kind %q: %v", tc.Kind, err)
			}
			if !bytes.Equal(second, third) {
				t.Fatalf("second byte stability failed for kind %q\nsecond: %s\nthird : %s", tc.Kind, string(second), string(third))
			}
		})
	}
}

// TestRoundtripActionWithEmptyParamsByteStability covers the omitempty edge:
// a report with nil params and one with an explicit empty slice must both
// roundtrip to identical bytes (field omitted) and stay stable.
func TestRoundtripActionWithEmptyParamsByteStability(t *testing.T) {
	variants := []Action{
		{Kind: ActionReport, Params: nil, Policy: PolicyRef{Name: "default", Version: 3}},
		{Kind: ActionReport, Params: []Param{}, Policy: PolicyRef{Name: "default", Version: 3}},
		{Kind: ActionConnect, Params: []Param{{Name: "gateway_id", Value: "gx10"}, {Name: "host", Value: "h"}}, Policy: PolicyRef{Name: "default", Version: 3}},
	}
	for _, tc := range variants {
		tc := tc
		label := string(tc.Kind)
		if tc.Params == nil {
			label += "_nil_params"
		} else if len(tc.Params) == 0 {
			label += "_empty_params"
		}
		t.Run(label, func(t *testing.T) {
			first, err := json.Marshal(tc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded Action
			if err := json.Unmarshal(first, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			second, err := json.Marshal(decoded)
			if err != nil {
				t.Fatalf("remarshal: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("empty params byte stability failed\nfirst : %s\nsecond: %s", string(first), string(second))
			}
		})
	}
}

// TestRoundtripActionSpecialCharsByteStability ensures escaping is stable:
// values containing quotes, slashes and unicode must survive a roundtrip
// without byte drift.
func TestRoundtripActionSpecialCharsByteStability(t *testing.T) {
	tc := Action{
		Kind: ActionReport,
		Params: []Param{
			{Name: "note", Value: "a \"quoted\" value with / slash and unicode \u00e9"},
		},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
	first, err := json.Marshal(tc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Action
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	second, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("special chars byte stability failed\nfirst : %s\nsecond: %s", string(first), string(second))
	}
}

// TestRoundtripDecisionStringStability pins Decision.String so the wire
// vocabulary for allow and deny cannot drift. Any change to the strings is a
// wire-visible change.
func TestRoundtripDecisionStringStability(t *testing.T) {
	if got := Deny.String(); got != "deny" {
		t.Fatalf("Deny.String() = %q, want %q", got, "deny")
	}
	if got := Allow.String(); got != "allow" {
		t.Fatalf("Allow.String() = %q, want %q", got, "allow")
	}
	// Default branch must stay deny for any unknown Decision value.
	for _, v := range []Decision{Decision(2), Decision(99), Decision(-1)} {
		if got := v.String(); got != "deny" {
			t.Fatalf("Decision(%d).String() = %q, want %q", int(v), got, "deny")
		}
	}
}

// TestRoundtripActionStringDecisionsStable verifies that String decisions
// observed through the policy engine remain stable across marshal roundtrips.
// An action that is allowed before serialization must still be allowed after.
func TestRoundtripActionStringDecisionsStable(t *testing.T) {
	engine := NewPolicyEngine()
	if err := engine.Register(ActionConnect, DenyGateway("banned-gateway")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := engine.Register(ActionRotateKey, AllowRule()); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := engine.Register(ActionReport, AllowRule()); err != nil {
		t.Fatalf("register: %v", err)
	}

	cases := []struct {
		action Action
		want   string
	}{
		{Action{Kind: ActionConnect, Params: []Param{{Name: "gateway_id", Value: "gx10"}}, Policy: PolicyRef{Name: "default", Version: 3}}, "allow"},
		{Action{Kind: ActionConnect, Params: []Param{{Name: "gateway_id", Value: "banned-gateway"}}, Policy: PolicyRef{Name: "default", Version: 3}}, "deny"},
		{Action{Kind: ActionRotateKey, Policy: PolicyRef{Name: "default", Version: 3}}, "allow"},
		{Action{Kind: ActionReport, Policy: PolicyRef{Name: "default", Version: 3}}, "allow"},
	}

	for _, tc := range cases {
		raw, err := json.Marshal(tc.action)
		if err != nil {
			t.Fatalf("marshal %q: %v", tc.action.Kind, err)
		}
		var decoded Action
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal %q: %v", tc.action.Kind, err)
		}
		// Re-marshal must be byte identical, and decision string must match.
		again, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("remarshal %q: %v", tc.action.Kind, err)
		}
		if !bytes.Equal(raw, again) {
			t.Fatalf("byte drift for %q: %s vs %s", tc.action.Kind, string(raw), string(again))
		}
		// Decision stability before and after roundtrip.
		before := engine.Evaluate(nil, &tc.action).String()
		after := engine.Evaluate(nil, &decoded).String()
		if before != tc.want {
			t.Errorf("kind %q before String() = %q, want %q", tc.action.Kind, before, tc.want)
		}
		if after != tc.want {
			t.Errorf("kind %q after String() = %q, want %q", tc.action.Kind, after, tc.want)
		}
		if before != after {
			t.Errorf("kind %q String() drift: before %q after %q", tc.action.Kind, before, after)
		}
	}
}
