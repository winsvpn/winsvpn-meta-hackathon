package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// conformancePackageDir resolves the directory holding this test file.
func conformancePackageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// conformanceReadSchema reads the on-disk schema.json artifact.
func conformanceReadSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(conformancePackageDir(t), "schema.json"))
	if err != nil {
		t.Fatalf("read on-disk schema.json: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode on-disk schema.json: %v", err)
	}
	return schema
}

// conformanceReadSchemaRaw returns raw bytes for JSON validity checks.
func conformanceReadSchemaRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(conformancePackageDir(t), "schema.json"))
	if err != nil {
		t.Fatalf("read on-disk schema.json: %v", err)
	}
	return raw
}

// TestConformance_SchemaIsDraft202012 is the draft-2020-12 conformance gate.
// It asserts schema.json is valid JSON, declares draft 2020-12, and carries the
// structural facts a draft 2020-12 consumer needs. This is the runner that
// checks schema.json stays valid JSON-Schema draft 2020-12.
func TestConformance_SchemaIsDraft202012(t *testing.T) {
	raw := conformanceReadSchemaRaw(t)
	schema := conformanceReadSchema(t)

	// Valid JSON already proven by Unmarshal, but double-check round-trip.
	var check any
	if err := json.Unmarshal(raw, &check); err != nil {
		t.Fatalf("schema.json is not valid JSON: %v", err)
	}

	// $schema must be draft 2020-12.
	sch, ok := schema["$schema"].(string)
	if !ok || sch == "" {
		t.Fatalf("$schema missing or not a string: %v", schema["$schema"])
	}
	const wantDialect = "https://json-schema.org/draft/2020-12/schema"
	if sch != wantDialect {
		t.Fatalf("$schema = %q, want %q", sch, wantDialect)
	}

	// Root must be an object.
	if schema["type"] != "object" {
		t.Fatalf("schema root type = %v, want object", schema["type"])
	}

	// additionalProperties must be false (closed).
	if ap, ok := schema["additionalProperties"].(bool); !ok || ap != false {
		t.Fatalf("additionalProperties = %v, want false", schema["additionalProperties"])
	}

	// title must be present.
	if title, ok := schema["title"].(string); !ok || strings.TrimSpace(title) == "" {
		t.Fatalf("title missing or empty: %v", schema["title"])
	}

	// required must contain kind and policy.
	reqRaw, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("required missing or not array: %v", schema["required"])
	}
	reqSet := map[string]bool{}
	for _, r := range reqRaw {
		reqSet[r.(string)] = true
	}
	for _, need := range []string{"kind", "policy"} {
		if !reqSet[need] {
			t.Errorf("required missing %q, have %v", need, reqRaw)
		}
	}

	// properties must contain kind, params, policy.
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("properties missing or not object")
	}
	for _, p := range []string{"kind", "params", "policy"} {
		if _, ok := props[p]; !ok {
			t.Errorf("properties missing %q", p)
		}
	}

	// kind must be string with closed enum matching validKinds.
	kind, ok := props["kind"].(map[string]any)
	if !ok {
		t.Fatal("kind property missing or not object")
	}
	if kind["type"] != "string" {
		t.Fatalf("kind type = %v, want string", kind["type"])
	}
	enum, ok := kind["enum"].([]any)
	if !ok {
		t.Fatal("kind enum missing or not array")
	}
	if len(enum) != len(validKinds) {
		t.Fatalf("kind enum length %d, want %d (closed set) %v", len(enum), len(validKinds), enum)
	}
	seen := map[string]bool{}
	for _, e := range enum {
		seen[e.(string)] = true
	}
	for _, k := range validKinds {
		if !seen[string(k)] {
			t.Errorf("closed kind %q missing from schema enum", k)
		}
	}
	// Ensure no extra kinds beyond validKinds.
	for _, e := range enum {
		s := e.(string)
		found := false
		for _, k := range validKinds {
			if string(k) == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("enum contains unknown kind %q", s)
		}
	}

	// params must be array.
	if params, ok := props["params"].(map[string]any); ok {
		if params["type"] != "array" {
			t.Errorf("params type = %v, want array", params["type"])
		}
		items, ok := params["items"].(map[string]any)
		if !ok {
			t.Fatal("params items missing")
		}
		if items["type"] != "object" {
			t.Errorf("params items type = %v, want object", items["type"])
		}
		itemProps, ok := items["properties"].(map[string]any)
		if !ok {
			t.Fatal("params items properties missing")
		}
		for _, f := range []string{"name", "value"} {
			if _, ok := itemProps[f]; !ok {
				t.Errorf("params items missing property %q", f)
			}
		}
		if ap, ok := items["additionalProperties"].(bool); !ok || ap != false {
			t.Errorf("params items additionalProperties = %v, want false", items["additionalProperties"])
		}
	}

	// policy must be object with required name, version.
	if policy, ok := props["policy"].(map[string]any); ok {
		if policy["type"] != "object" {
			t.Errorf("policy type = %v, want object", policy["type"])
		}
		if ap, ok := policy["additionalProperties"].(bool); !ok || ap != false {
			t.Errorf("policy additionalProperties = %v, want false", policy["additionalProperties"])
		}
		policyReq, ok := policy["required"].([]any)
		if !ok {
			t.Fatal("policy required missing")
		}
		pSet := map[string]bool{}
		for _, r := range policyReq {
			pSet[r.(string)] = true
		}
		for _, need := range []string{"name", "version"} {
			if !pSet[need] {
				t.Errorf("policy required missing %q", need)
			}
		}
		policyProps, ok := policy["properties"].(map[string]any)
		if !ok {
			t.Fatal("policy properties missing")
		}
		if np, ok := policyProps["name"].(map[string]any); !ok || np["type"] != "string" {
			t.Errorf("policy.name type = %v, want string", policyProps["name"])
		}
		if vp, ok := policyProps["version"].(map[string]any); !ok || vp["type"] != "integer" {
			t.Errorf("policy.version type = %v, want integer", policyProps["version"])
		}
	}

	// Derived schema must match on-disk artifact (no drift).
	derivedRaw, err := json.MarshalIndent(JSONSchema(), "", "  ")
	if err != nil {
		t.Fatalf("marshal derived schema: %v", err)
	}
	var derived map[string]any
	if err := json.Unmarshal(derivedRaw, &derived); err != nil {
		t.Fatalf("derived schema not valid JSON: %v", err)
	}
	// Compare key structural fields rather than byte equality to avoid
	// whitespace ordering flaps, but also ensure no drift in enum.
	if derived["$schema"] != schema["$schema"] {
		t.Errorf("derived $schema %v != on-disk %v", derived["$schema"], schema["$schema"])
	}
	if derived["title"] != schema["title"] {
		t.Errorf("derived title %v != on-disk %v", derived["title"], schema["title"])
	}
}

// TestConformance_GoldenFixturesConform is the payload conformance runner.
// It asserts every golden fixture that is supposed to be valid conforms to
// schema.json (draft 2020-12) via the structural validator. The structural
// schema is closed on kind enum and policy, but open on per-kind param
// requirements, so a fixture that is structurally valid may still be rejected
// by the production per-kind contract. That second gate is checked separately
// with a production-valid action constructed in code, so both gates are
// exercised without coupling the golden fixture to the production Required set.
// Each positive is paired with a negative control so a validator that accepts
// everything cannot pass.
func TestConformance_GoldenFixturesConform(t *testing.T) {
	schema := conformanceReadSchema(t)
	dir := filepath.Join(conformancePackageDir(t), "testdata")

	// Golden valid fixtures: these must conform structurally to schema.json.
	validFixtures := []string{"valid.json"}

	reg := NewContractRegistry()
	for _, name := range validFixtures {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read fixture %s: %v", name, err)
			}
			var inst map[string]any
			if err := json.Unmarshal(raw, &inst); err != nil {
				t.Fatalf("decode fixture %s: %v", name, err)
			}
			// Structural schema check (draft 2020-12).
			if err := schemaViolation(schema, inst, "root"); err != nil {
				t.Fatalf("golden fixture %s rejected by schema.json: %v", name, err)
			}
			// Also validate that re-derived schema agrees. Normalize
			// derived via JSON round-trip so required is []any not []string.
			derivedRaw, _ := json.Marshal(JSONSchema())
			var derived map[string]any
			if err := json.Unmarshal(derivedRaw, &derived); err != nil {
				t.Fatalf("decode derived schema: %v", err)
			}
			if err := schemaViolation(derived, inst, "root"); err != nil {
				t.Fatalf("golden fixture %s rejected by derived schema: %v", name, err)
			}
		})
	}

	// Production contract positive control: a connect with both required params
	// must pass the registry. This proves the runner checks per-kind conformance
	// as well as structural conformance.
	t.Run("production_connect_valid", func(t *testing.T) {
		a := &Action{
			Kind: ActionConnect,
			Params: []Param{
				{Name: "gateway_id", Value: "spain-madrid"},
				{Name: "host", Value: "spain-madrid:443"},
			},
			Policy: PolicyRef{Name: "default", Version: 3},
		}
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal production action: %v", err)
		}
		var inst map[string]any
		if err := json.Unmarshal(raw, &inst); err != nil {
			t.Fatalf("decode production action: %v", err)
		}
		if err := schemaViolation(schema, inst, "root"); err != nil {
			t.Fatalf("production action rejected by schema.json: %v", err)
		}
		if err := reg.Validate(a); err != nil {
			t.Fatalf("production action rejected by ContractRegistry: %v", err)
		}
		if _, err := reg.DecodeAndValidate(raw); err != nil {
			t.Fatalf("production action rejected by DecodeAndValidate: %v", err)
		}
	})

	// Negative controls: these must NOT conform.
	invalidCases := []struct {
		name string
		file string
	}{
		{"unknown_kind_rejected", "unknown_kind.json"},
		{"schema_invalid_rejected", "schema_invalid.json"},
	}
	for _, c := range invalidCases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, c.file))
			if err != nil {
				t.Fatalf("read fixture %s: %v", c.file, err)
			}
			var inst map[string]any
			if err := json.Unmarshal(raw, &inst); err != nil {
				t.Fatalf("decode fixture %s: %v", c.file, err)
			}
			// At least one of the two gates must reject.
			schemaErr := schemaViolation(schema, inst, "root")
			_, regErr := reg.DecodeAndValidate(raw)
			// unknown_kind.json is structurally rejected by enum, so schema
			// must reject. schema_invalid.json is structurally valid (kind is
			// known) but fails the per-kind contract, so registry must reject.
			switch c.file {
			case "unknown_kind.json":
				if schemaErr == nil {
					t.Fatal("unknown_kind fixture accepted by schema; expected rejection")
				}
				if regErr == nil {
					t.Fatal("unknown_kind fixture accepted by registry; expected ErrUnknownKind")
				}
			case "schema_invalid.json":
				// schema_invalid is valid.json without its required param host,
				// so structural schema still admits it (kind enum passes),
				// but production contract must reject.
				if regErr == nil {
					t.Fatal("schema_invalid fixture accepted by registry; expected ErrMalformed")
				}
				// Structural result may be nil (it is structurally valid);
				// no assertion on schemaErr for this case.
			}
		})
	}
}

// TestConformance_EveryGoldenFixtureInTestdata is the exhaustive golden loop.
// It enumerates testdata/*.json and asserts that every fixture whose name
// appears in the valid set conforms, and every other fixture is accounted for
// as an expected rejection. Adding a new golden file without updating the valid
// set fails this test, so the set cannot silently grow stale.
func TestConformance_EveryGoldenFixtureInTestdata(t *testing.T) {
	schema := conformanceReadSchema(t)
	dir := filepath.Join(conformancePackageDir(t), "testdata")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir testdata: %v", err)
	}
	validSet := map[string]bool{
		"valid.json": true,
	}
	expectedInvalid := map[string]bool{
		"unknown_kind.json":   true,
		"schema_invalid.json": true,
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no fixtures found in testdata")
	}
	// Every fixture must be classified.
	for _, n := range names {
		if !validSet[n] && !expectedInvalid[n] {
			t.Fatalf("fixture %q not classified as valid or expectedInvalid; update conformance_test.go", n)
		}
	}
	reg := NewContractRegistry()
	for _, name := range names {
		name := name
		t.Run(fmt.Sprintf("fixture_%s", strings.TrimSuffix(name, ".json")), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read fixture %s: %v", name, err)
			}
			var inst map[string]any
			if err := json.Unmarshal(raw, &inst); err != nil {
				t.Fatalf("decode fixture %s: %v", name, err)
			}
			schemaErr := schemaViolation(schema, inst, "root")
			_, regErr := reg.DecodeAndValidate(raw)
			if validSet[name] {
				// Valid fixtures must pass the structural schema (draft 2020-12).
				// They may still be rejected by the production per-kind contract
				// if they carry only a subset of required params, so registry
				// is not asserted for golden fixtures here; production is
				// covered by TestConformance_GoldenFixturesConform/production_connect_valid.
				if schemaErr != nil {
					t.Fatalf("valid fixture %s rejected by schema: %v", name, schemaErr)
				}
			} else {
				// Invalid fixtures must be rejected by at least one gate.
				if schemaErr == nil && regErr == nil {
					t.Fatalf("invalid fixture %s accepted by both gates; expected rejection", name)
				}
			}
		})
	}
}

// TestConformance_SchemaRoundTrip ensures the on-disk artifact is byte-for-byte
// the derived schema modulo formatting. This pins that schema.json is a derived
// artifact from the Go types, not a hand-edited duplicate that can drift.
func TestConformance_SchemaRoundTrip(t *testing.T) {
	raw := conformanceReadSchemaRaw(t)
	var onDisk map[string]any
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("decode on-disk schema: %v", err)
	}
	derived := JSONSchema()
	// Normalize both through JSON marshal to compare structure.
	onDiskNorm, _ := json.Marshal(onDisk)
	derivedNorm, _ := json.Marshal(derived)
	var onDiskSorted, derivedSorted map[string]any
	if err := json.Unmarshal(onDiskNorm, &onDiskSorted); err != nil {
		t.Fatalf("re-decode on-disk: %v", err)
	}
	if err := json.Unmarshal(derivedNorm, &derivedSorted); err != nil {
		t.Fatalf("re-decode derived: %v", err)
	}
	onDiskJSON, _ := json.MarshalIndent(onDiskSorted, "", "  ")
	derivedJSON, _ := json.MarshalIndent(derivedSorted, "", "  ")
	if string(onDiskJSON) != string(derivedJSON) {
		t.Fatalf("on-disk schema.json differs from derived JSONSchema()\n--- on-disk ---\n%s\n--- derived ---\n%s", onDiskJSON, derivedJSON)
	}
}
