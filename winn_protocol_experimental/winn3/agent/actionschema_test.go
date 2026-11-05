package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// goldenAction is the canonical action instance this suite pins. It exercises
// all three record parts: a non-empty kind, a one-param list, and a policy
// reference. The string is the byte-for-byte canonical wire form; re-marshaling
// a decoded copy must reproduce it exactly.
const goldenAction = `{"kind":"connect","params":[{"name":"gateway_id","value":"gx10"}],"policy":{"name":"default","version":3}}`

// packageDir resolves the directory holding this test file, independent of the
// test working directory, so the schema artifact is always written beside the
// source that derives it.
func packageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// deriveSchemaArtifact builds the JSON Schema from the Go types and writes it
// to schema.json in this package directory, then returns both the bytes and
// the decoded value. The artifact is derived on every run rather than read from
// disk, so the file can never be a stale hand-maintained copy.
func deriveSchemaArtifact(t *testing.T) ([]byte, map[string]any) {
	t.Helper()
	raw, err := json.MarshalIndent(JSONSchema(), "", "  ")
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("derived schema is not valid JSON: %v", err)
	}
	path := filepath.Join(packageDir(t), "schema.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write schema artifact: %v", err)
	}
	return raw, decoded
}

// schemaViolation validates an instance against a decoded JSON Schema using the
// subset of draft 2020-12 this package relies on (type, enum, properties,
// required, items, additionalProperties). It returns nil when the instance
// conforms and a descriptive error when it does not. Being side-effect-free and
// value-driven, it serves both the positive control (must be nil) and the
// negative controls (must be non-nil).
func schemaViolation(schema map[string]any, instance any, path string) error {
	if rawEnum, ok := schema["enum"]; ok {
		var enumVals []any
		switch v := rawEnum.(type) {
		case []any:
			enumVals = v
		case []string:
			for _, s := range v {
				enumVals = append(enumVals, s)
			}
		}
		if enumVals != nil {
			found := false
			for _, e := range enumVals {
				if e == instance {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: value %v not in enum", path, instance)
			}
		}
	}

	ty, _ := schema["type"].(string)
	switch ty {
	case "object":
		obj, ok := instance.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want object, got %T", path, instance)
		}
		props, _ := schema["properties"].(map[string]any)
		if rawReq, ok := schema["required"]; ok {
			var reqList []string
			switch v := rawReq.(type) {
			case []any:
				for _, r := range v {
					reqList = append(reqList, r.(string))
				}
			case []string:
				reqList = v
			}
			for _, key := range reqList {
				if _, present := obj[key]; !present {
					return fmt.Errorf("%s: required property %q missing", path, key)
				}
			}
		}
		for key, val := range obj {
			sub, hasProp := props[key]
			if !hasProp {
				if add, _ := schema["additionalProperties"].(bool); !add {
					return fmt.Errorf("%s: unexpected property %q", path, key)
				}
				continue
			}
			if err := schemaViolation(sub.(map[string]any), val, path+"."+key); err != nil {
				return err
			}
		}
	case "array":
		arr, ok := instance.([]any)
		if !ok {
			return fmt.Errorf("%s: want array, got %T", path, instance)
		}
		items, _ := schema["items"].(map[string]any)
		for i, v := range arr {
			if err := schemaViolation(items, v, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case "string":
		if _, ok := instance.(string); !ok {
			return fmt.Errorf("%s: want string, got %T", path, instance)
		}
	case "integer":
		if _, ok := instance.(float64); !ok {
			return fmt.Errorf("%s: want integer, got %T", path, instance)
		}
	}
	return nil
}

// TestSchemaArtifactDerivedFromTypes asserts the on-disk schema.json artifact is
// produced from the Go types and carries the structural facts a JSON Schema
// consumer needs: an object with kind, params and policy, kind restricted to the
// valid enum, and policy required. These are positive facts; each is paired with
// a negative control in TestSchemaValidationHasTeeth.
func TestSchemaArtifactDerivedFromTypes(t *testing.T) {
	raw, schema := deriveSchemaArtifact(t)

	if schema["type"] != "object" {
		t.Fatalf("schema root type = %v, want object", schema["type"])
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema root has no properties")
	}
	for _, p := range []string{"kind", "params", "policy"} {
		if _, ok := props[p]; !ok {
			t.Errorf("schema.properties missing %q", p)
		}
	}
	kind, ok := props["kind"].(map[string]any)
	if !ok {
		t.Fatalf("kind property is missing")
	}
	enum, ok := kind["enum"].([]any)
	if !ok {
		t.Fatalf("kind property has no enum")
	}
	wantKinds := []string{string(ActionConnect), string(ActionRotateKey), string(ActionReport)}
	for i, w := range wantKinds {
		if i >= len(enum) || enum[i].(string) != w {
			t.Errorf("kind enum[%d] = %v, want %q", i, enum[i], w)
		}
	}

	onDisk, err := os.ReadFile(filepath.Join(packageDir(t), "schema.json"))
	if err != nil {
		t.Fatalf("schema.json missing on disk: %v", err)
	}
	if !bytes.Equal(onDisk, raw) {
		t.Errorf("on-disk schema.json differs from the just-derived bytes")
	}
}

// TestGoldenActionParsesAndReserializesLosslessly is the round-trip assertion:
// the golden action instance must decode into the typed record with the right
// field values, and re-encoding it must reproduce the canonical bytes exactly.
func TestGoldenActionParsesAndReserializesLosslessly(t *testing.T) {
	var act Action
	if err := json.Unmarshal([]byte(goldenAction), &act); err != nil {
		t.Fatalf("golden action failed to parse: %v", err)
	}

	if act.Kind != ActionConnect {
		t.Errorf("kind = %q, want %q", act.Kind, ActionConnect)
	}
	if len(act.Params) != 1 || act.Params[0].Name != "gateway_id" || act.Params[0].Value != "gx10" {
		t.Errorf("params parsed wrong: %+v", act.Params)
	}
	if act.Policy.Name != "default" || act.Policy.Version != 3 {
		t.Errorf("policy parsed wrong: %+v", act.Policy)
	}

	reencoded, err := json.Marshal(&act)
	if err != nil {
		t.Fatalf("re-encode action: %v", err)
	}
	if string(reencoded) != goldenAction {
		t.Errorf("lossless round-trip failed\n got: %s\nwant: %s", reencoded, goldenAction)
	}
}

// TestGoldenActionConformsToSchema feeds the golden instance through the schema
// validator. It is the positive control: the thing the schema advertises must
// actually be accepted.
func TestGoldenActionConformsToSchema(t *testing.T) {
	_, schema := deriveSchemaArtifact(t)
	var instance map[string]any
	if err := json.Unmarshal([]byte(goldenAction), &instance); err != nil {
		t.Fatalf("decode golden instance: %v", err)
	}
	if err := schemaViolation(schema, instance, "root"); err != nil {
		t.Errorf("golden instance rejected by schema: %v", err)
	}
}

// TestSchemaValidationHasTeeth is the negative-control companion to the tests
// above. Each mutation must be rejected by the schema: an unknown kind, a
// missing required policy, an extra property, and a wrong-typed field. If any
// of these is accepted, the schema is a validator that can never fail and the
// positive facts above prove nothing.
func TestSchemaValidationHasTeeth(t *testing.T) {
	_, schema := deriveSchemaArtifact(t)

	cases := []struct {
		name  string
		json  string
		valid bool
	}{
		{"valid golden", goldenAction, true},
		{"unknown kind", `{"kind":"wipe_disk","params":[],"policy":{"name":"default","version":3}}`, false},
		{"missing policy", `{"kind":"connect","params":[],"policy":{}}`, false},
		{"extra property", `{"kind":"connect","policy":{"name":"default","version":3},"surprise":true}`, false},
		{"kind not string", `{"kind":7,"policy":{"name":"default","version":3}}`, false},
		{"params wrong element type", `{"kind":"connect","params":[7],"policy":{"name":"default","version":3}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var instance map[string]any
			if err := json.Unmarshal([]byte(c.json), &instance); err != nil {
				t.Fatalf("decode %s: %v", c.name, err)
			}
			err := schemaViolation(schema, instance, "root")
			got := err == nil
			if got != c.valid {
				t.Errorf("validity = %v, want %v (violation: %v)", got, c.valid, err)
			}
		})
	}
}
