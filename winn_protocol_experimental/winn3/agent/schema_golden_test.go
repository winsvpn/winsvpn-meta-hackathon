package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// goldenPackageDir resolves the directory holding this test file, so the
// on-disk schema.json artifact can be read regardless of the test working
// directory. This is the artifact the golden controls pin, not a freshly
// derived copy.
func goldenPackageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// goldenSchema reads the on-disk schema.json artifact and decodes it. Reading
// the artifact rather than re-deriving from the Go types means a stale or
// hand-edited schema.json is tested, not silently regenerated.
func goldenSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenPackageDir(t), "schema.json"))
	if err != nil {
		t.Fatalf("read on-disk schema.json: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode on-disk schema.json: %v", err)
	}
	return schema
}

// goldenFixture reads one of the testdata fixtures and decodes it into the
// generic instance form the schema validator consumes.
func goldenFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenPackageDir(t), "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var inst map[string]any
	if err := json.Unmarshal(raw, &inst); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return inst
}

// TestActionSchemaGoldenAdmitsValidFixture is the positive control on the on-disk
// artifact: schema.json as committed must admit the action in testdata/valid.json.
// If the artifact drifted to reject a kind it advertises, this goes red.
func TestActionSchemaGoldenAdmitsValidFixture(t *testing.T) {
	schema := goldenSchema(t)
	inst := goldenFixture(t, "valid.json")
	if err := schemaViolation(schema, inst, "root"); err != nil {
		t.Fatalf("on-disk schema rejected testdata/valid.json: %v", err)
	}
}

// TestActionSchemaGoldenRejectsUnknownKindFixture is the negative control on the
// on-disk artifact: the kind in testdata/unknown_kind.json is outside the closed
// kind set, so schema.json as committed must refuse the whole action. A schema
// that accepts it is a gate that can never fail.
func TestActionSchemaGoldenRejectsUnknownKindFixture(t *testing.T) {
	schema := goldenSchema(t)
	inst := goldenFixture(t, "unknown_kind.json")
	if err := schemaViolation(schema, inst, "root"); err == nil {
		t.Fatal("on-disk schema accepted testdata/unknown_kind.json; expected rejection")
	}
}

// TestActionSchemaGoldenKindEnumIsClosed pins the exact kind enum schema.json advertises.
// Params are carried whether or not the kind is meaningful, but an unknown kind is
// refused by the enum before any param is read. This asserts the closed-set claim
// directly: the set of kinds the artifact admits is exactly the three constants.
func TestActionSchemaGoldenKindEnumIsClosed(t *testing.T) {
	schema := goldenSchema(t)
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("schema has no properties")
	}
	kind, ok := props["kind"].(map[string]any)
	if !ok {
		t.Fatal("schema has no kind property")
	}
	enum, ok := kind["enum"].([]any)
	if !ok {
		t.Fatal("kind property has no enum")
	}
	seen := map[string]bool{}
	for _, e := range enum {
		seen[e.(string)] = true
	}
	for _, k := range validKinds {
		if !seen[string(k)] {
			t.Errorf("closed kind %q missing from schema.json enum", k)
		}
	}
	if len(enum) != len(validKinds) {
		t.Errorf("schema enum has %d kinds, want %d (closed set) %v", len(enum), len(validKinds), enum)
	}
}

// TestActionSchemaGoldenParamOrderIsMeaningless pins the param-order contract from
// actionschema.go: Params is a list of named values whose order carries no
// meaning. Two actions differing only in param order must validate identically
// against the on-disk artifact. If the schema or validator came to read
// position out of the list, these two would diverge.
func TestActionSchemaGoldenParamOrderIsMeaningless(t *testing.T) {
	schema := goldenSchema(t)
	decode := func(t *testing.T, raw string) map[string]any {
		t.Helper()
		var inst map[string]any
		if err := json.Unmarshal([]byte(raw), &inst); err != nil {
			t.Fatalf("decode instance: %v", err)
		}
		return inst
	}
	a := decode(t, `{"kind":"connect","params":[{"name":"gateway_id","value":"gx10"},{"name":"host","value":"spain-madrid:443"}],"policy":{"name":"default","version":3}}`)
	b := decode(t, `{"kind":"connect","params":[{"name":"host","value":"spain-madrid:443"},{"name":"gateway_id","value":"gx10"}],"policy":{"name":"default","version":3}}`)
	if err := schemaViolation(schema, a, "root"); err != nil {
		t.Fatalf("schema rejected order A: %v", err)
	}
	if err := schemaViolation(schema, b, "root"); err != nil {
		t.Fatalf("schema rejected order B: %v", err)
	}
}
