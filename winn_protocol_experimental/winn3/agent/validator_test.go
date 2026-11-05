package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testSchema is the contract the three controls are validated against. It is
// owned by this test file as a stand-in for whatever per-kind contract the
// policy engine is configured with. Keeping it here, rather than reaching into
// a production registry, means the three controls cannot be made green by an
// accidental widening of a shared schema.
var testSchema = NewSchema(map[ActionKind]ParamContract{
	ActionConnect: {
		Required: []string{"host"},
		Allowed:  []string{"host"},
	},
	ActionRotateKey: {},
	ActionReport:    {},
})

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

// TestControl_ValidActionMustPass is control one: a fully valid action must be
// accepted. If the validator rejects this, the gate has no working path at all.
func TestControl_ValidActionMustPass(t *testing.T) {
	raw := readFixture(t, "valid.json")
	act, err := testSchema.DecodeAndValidate(raw)
	if err != nil {
		t.Fatalf("valid action was rejected: %v", err)
	}
	if act.Kind != ActionConnect {
		t.Fatalf("decoded kind = %q, want connect", act.Kind)
	}
	if len(act.Params) != 1 || act.Params[0].Name != "host" || act.Params[0].Value != "spain-madrid:443" {
		t.Fatalf("decoded params = %+v, want host=spain-madrid:443", act.Params)
	}
}

// TestControl_UnknownKindMustBeDenied is control two: an action that is well
// formed but carries a kind that is not in the closed set must be denied before
// the policy engine sees it. A validator that answers nil here is a gateway
// that lets any unknown action through.
func TestControl_UnknownKindMustBeDenied(t *testing.T) {
	raw := readFixture(t, "unknown_kind.json")
	_, err := testSchema.DecodeAndValidate(raw)
	if err == nil {
		t.Fatal("unknown kind was accepted; expected ErrUnknownKind")
	}
	if !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown kind produced %v, want ErrUnknownKind", err)
	}
}

// TestControl_SchemaInvalidMustBeRejected is control three: an action whose
// kind is known but whose params miss a required member must be rejected.
func TestControl_SchemaInvalidMustBeRejected(t *testing.T) {
	raw := readFixture(t, "schema_invalid.json")
	_, err := testSchema.DecodeAndValidate(raw)
	if err == nil {
		t.Fatal("schema-invalid action was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("schema-invalid action produced %v, want ErrMalformed", err)
	}
}

// TestSentinelErrorsAreDistinct guards against a regression that collapses both
// failure classes into a single error. If they become the same value, the
// unknown-kind and schema-invalid controls above could not tell a denied action
// from a rejected one.
func TestSentinelErrorsAreDistinct(t *testing.T) {
	if ErrUnknownKind == ErrMalformed {
		t.Fatal("ErrUnknownKind and ErrMalformed are the same value")
	}
}
