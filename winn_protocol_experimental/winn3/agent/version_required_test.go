package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestDecodeAndValidate_PolicyVersionMissingRejected is the wire-form bound
// matching schema.json: policy.version is required. Before this guard,
// DecodeAndValidate accepted `{"kind":"report","policy":{"name":"default"}}`
// and decoded Version as 0, which is indistinguishable from an explicit 0
// after encoding/json into int. The structural schema helper must also reject
// the same payload so the two gates agree.
func TestDecodeAndValidate_PolicyVersionMissingRejected(t *testing.T) {
	raw := []byte(`{"kind":"report","policy":{"name":"default"}}`)
	reg := NewContractRegistry()
	_, err := reg.DecodeAndValidate(raw)
	if err == nil {
		t.Fatal("missing policy.version was accepted; expected ErrMalformed")
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("missing policy.version produced %v, want ErrMalformed", err)
	}
	if !strings.Contains(err.Error(), "policy version missing") {
		t.Fatalf("error %q does not name policy version missing", err.Error())
	}

	schemaRaw, err := json.Marshal(JSONSchema())
	if err != nil {
		t.Fatalf("marshal derived schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		t.Fatalf("decode derived schema: %v", err)
	}
	var inst map[string]any
	if err := json.Unmarshal(raw, &inst); err != nil {
		t.Fatalf("decode instance: %v", err)
	}
	if err := schemaViolation(schema, inst, "root"); err == nil {
		t.Fatal("derived JSON Schema accepted missing policy.version; expected rejection")
	}

	explicit0 := []byte(`{"kind":"report","policy":{"name":"default","version":0}}`)
	got, err := reg.DecodeAndValidate(explicit0)
	if err != nil {
		t.Fatalf("explicit version 0 was rejected: %v", err)
	}
	if got.Policy.Version != 0 {
		t.Fatalf("explicit version 0 decoded as %d", got.Policy.Version)
	}
}
