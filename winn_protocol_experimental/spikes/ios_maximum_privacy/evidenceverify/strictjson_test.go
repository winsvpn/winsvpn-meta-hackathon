package main

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// MARK: mechanism

func TestStrictJSONRejectsADuplicateMember(t *testing.T) {
	shape := newJSONShape("fixture").required("alpha").optional("beta")
	if err := validateStrictJSON(
		[]byte(`{"alpha":1,"beta":2,"alpha":3}`),
		shape,
	); err == nil || !strings.Contains(err.Error(), `repeats member "alpha"`) {
		t.Fatalf("duplicate member error = %v", err)
	}
	// The same bytes decode without complaint through the permissive path
	// this validator exists to close, which is why the check is needed at all.
	var decoded struct {
		Alpha int `json:"alpha"`
	}
	decoder := json.NewDecoder(
		strings.NewReader(`{"alpha":1,"beta":2,"alpha":3}`),
	)
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("encoding/json unexpectedly refused the duplicate: %v", err)
	}
	if decoded.Alpha != 3 {
		t.Fatalf("last duplicate did not win: %d", decoded.Alpha)
	}
}

func TestStrictJSONRejectsACaseVariantMember(t *testing.T) {
	shape := newJSONShape("fixture").required("alpha")
	for _, variant := range []string{"Alpha", "ALPHA", "aLpHa"} {
		err := validateStrictJSON(
			[]byte(`{"`+variant+`":1}`),
			shape,
		)
		if err == nil ||
			!strings.Contains(err.Error(), "case variant") ||
			!strings.Contains(err.Error(), `"alpha"`) {
			t.Fatalf("%q error = %v", variant, err)
		}
	}
	// An unrelated undeclared name must report the plain reason, so the
	// case-variant message cannot be satisfied by any unknown member.
	if err := validateStrictJSON(
		[]byte(`{"alpha":1,"gamma":2}`),
		shape,
	); err == nil ||
		strings.Contains(err.Error(), "case variant") ||
		!strings.Contains(err.Error(), "is not declared") {
		t.Fatalf("undeclared member error = %v", err)
	}
}

func TestStrictJSONRequiresPresenceNotZeroValue(t *testing.T) {
	shape := newJSONShape("fixture").required("alpha", "beta")
	if err := validateStrictJSON([]byte(`{"alpha":0}`), shape); err == nil ||
		!strings.Contains(err.Error(), `missing required member "beta"`) {
		t.Fatalf("missing member error = %v", err)
	}
	// Zero is a value, not an absence.
	if err := validateStrictJSON(
		[]byte(`{"alpha":0,"beta":0}`),
		shape,
	); err != nil {
		t.Fatalf("zero-valued members must be accepted: %v", err)
	}
	if err := validateStrictJSON(
		[]byte(`{"alpha":0,"beta":null}`),
		shape,
	); err == nil || !strings.Contains(err.Error(), "is null") {
		t.Fatalf("null member error = %v", err)
	}
}

func TestStrictJSONRecursesIntoNestedObjectsAndArrays(t *testing.T) {
	leaf := newJSONShape("leaf").required("value")
	shape := newJSONShape("fixture").
		requiredObject("nested", leaf).
		requiredArray("list", leaf)
	valid := `{"nested":{"value":1},"list":[{"value":2},{"value":3}]}`
	if err := validateStrictJSON([]byte(valid), shape); err != nil {
		t.Fatalf("valid nested document: %v", err)
	}
	for name, document := range map[string]string{
		"nested duplicate": `{"nested":{"value":1,"value":2},` +
			`"list":[{"value":3}]}`,
		"nested case variant": `{"nested":{"Value":1},` +
			`"list":[{"value":3}]}`,
		"nested missing": `{"nested":{},"list":[{"value":3}]}`,
		"element duplicate": `{"nested":{"value":1},` +
			`"list":[{"value":2},{"value":3,"value":4}]}`,
		"element case variant": `{"nested":{"value":1},` +
			`"list":[{"VALUE":2}]}`,
		"element missing": `{"nested":{"value":1},"list":[{}]}`,
	} {
		if err := validateStrictJSON([]byte(document), shape); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// The array index must appear, so a failure names the offending element.
	err := validateStrictJSON(
		[]byte(`{"nested":{"value":1},"list":[{"value":2},{}]}`),
		shape,
	)
	if err == nil || !strings.Contains(err.Error(), "list[1]") {
		t.Fatalf("element path error = %v", err)
	}
}

func TestStrictJSONRejectsTrailingContentAndNonObjects(t *testing.T) {
	shape := newJSONShape("fixture").required("alpha")
	if err := validateStrictJSON(
		[]byte(`{"alpha":1}{"alpha":2}`),
		shape,
	); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing JSON error = %v", err)
	}
	if err := validateStrictJSON([]byte(`[1,2]`), shape); err == nil ||
		!strings.Contains(err.Error(), "not a JSON object") {
		t.Fatalf("non-object error = %v", err)
	}
	if err := validateStrictJSON(
		[]byte(`{"alpha":{"nested":1}}`),
		shape,
	); err == nil || !strings.Contains(err.Error(), "must be a scalar") {
		t.Fatalf("composite scalar error = %v", err)
	}
}

// The declared shapes and the Go structs are two independent statements of the
// same schema. This proves they agree, so a field added to a struct without a
// declaration fails here instead of silently widening what is accepted.
func TestShapesMatchTheGoStructTags(t *testing.T) {
	for _, testCase := range []struct {
		shape *jsonShape
		value any
	}{
		{constantsShape, constantsSnapshot{}},
		{resourceSnapshotShape, resourceSnapshot{}},
		{resourceWindowShape, resourceWindow{}},
		{dataPathShape, dataPathSnapshot{}},
		{rotationResourcesShape, rotationResources{}},
		{metricRecordShape, metricRecord{}},
		{startReceiptShape, startReceipt{}},
		{stopReceiptShape, stopReceipt{}},
	} {
		gotRequired, gotOptional := shapeMemberNames(testCase.shape)
		wantRequired, wantOptional := structTagNames(t, testCase.value)
		if !reflect.DeepEqual(gotRequired, wantRequired) {
			t.Fatalf(
				"%s required = %v, struct = %v",
				testCase.shape.name, gotRequired, wantRequired,
			)
		}
		if !reflect.DeepEqual(gotOptional, wantOptional) {
			t.Fatalf(
				"%s optional = %v, struct = %v",
				testCase.shape.name, gotOptional, wantOptional,
			)
		}
	}
}

func shapeMemberNames(shape *jsonShape) ([]string, []string) {
	required := []string{}
	optional := []string{}
	for name, member := range shape.members {
		if member.required {
			required = append(required, name)
		} else {
			optional = append(optional, name)
		}
	}
	sort.Strings(required)
	sort.Strings(optional)
	return required, optional
}

// structTagNames treats `omitempty` as the struct's own statement that a
// member may be absent.
func structTagNames(t *testing.T, value any) ([]string, []string) {
	t.Helper()
	required := []string{}
	optional := []string{}
	structType := reflect.TypeOf(value)
	for index := 0; index < structType.NumField(); index++ {
		tag := structType.Field(index).Tag.Get("json")
		if tag == "" || tag == "-" {
			t.Fatalf(
				"%s.%s has no JSON tag",
				structType.Name(),
				structType.Field(index).Name,
			)
		}
		parts := strings.Split(tag, ",")
		if len(parts) > 1 && parts[1] == "omitempty" {
			optional = append(optional, parts[0])
			continue
		}
		required = append(required, parts[0])
	}
	sort.Strings(required)
	sort.Strings(optional)
	return required, optional
}

// MARK: trust boundaries

func TestVerifyRejectsADuplicateMemberInEveryDocument(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		member string
		target func(cfg options) string
	}{
		{
			name:   "evidence record",
			member: "runID",
			target: func(cfg options) string { return cfg.evidence },
		},
		{
			name:   "start receipt",
			member: "hostStartLatencyNanoseconds",
			target: func(cfg options) string { return cfg.startReceipt },
		},
	} {
		path, cfg := writeValidRun(t)
		_ = path
		file := testCase.target(cfg)
		duplicateFirstJSONMember(t, file, testCase.member)
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(err.Error(), "repeats member") {
			t.Fatalf("%s duplicate error = %v", testCase.name, err)
		}
	}
}

func TestVerifyRejectsACaseVariantMemberInEveryDocument(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		member  string
		variant string
		target  func(cfg options) string
	}{
		{
			name:    "evidence record",
			member:  `"runID"`,
			variant: `"RunID"`,
			target:  func(cfg options) string { return cfg.evidence },
		},
		{
			name:    "nested constants",
			member:  `"cellBytes"`,
			variant: `"CellBytes"`,
			target:  func(cfg options) string { return cfg.evidence },
		},
		{
			name:    "start receipt",
			member:  `"measurementScope"`,
			variant: `"MeasurementScope"`,
			target:  func(cfg options) string { return cfg.startReceipt },
		},
	} {
		_, cfg := writeValidRun(t)
		file := testCase.target(cfg)
		rewriteFileText(t, file, testCase.member, testCase.variant)
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(err.Error(), "case variant") {
			t.Fatalf("%s case-variant error = %v", testCase.name, err)
		}
	}
}

func TestVerifyRejectsAMissingRequiredMemberInEveryDocument(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		member string
		target func(cfg options) string
	}{
		{
			name:   "evidence record",
			member: "wallTimeUTC",
			target: func(cfg options) string { return cfg.evidence },
		},
		{
			name:   "nested constants",
			member: "spikeOverlapNanoseconds",
			target: func(cfg options) string { return cfg.evidence },
		},
		{
			name:   "nested resource window",
			member: "sampleCount",
			target: func(cfg options) string { return cfg.evidence },
		},
		{
			name:   "start receipt",
			member: "attemptNonce",
			target: func(cfg options) string { return cfg.startReceipt },
		},
	} {
		_, cfg := writeValidRun(t)
		file := testCase.target(cfg)
		removeFirstJSONMember(t, file, testCase.member)
		_, err := verify(cfg)
		if err == nil ||
			!strings.Contains(err.Error(), "missing required member") ||
			!strings.Contains(err.Error(), testCase.member) {
			t.Fatalf("%s missing-member error = %v", testCase.name, err)
		}
	}
}

func TestVerifyStopReceiptRejectsStrictMemberViolations(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string){
		"repeats member": func(t *testing.T, path string) {
			duplicateFirstJSONMember(t, path, "roundTripNanoseconds")
		},
		"case variant": func(t *testing.T, path string) {
			rewriteFileText(t, path, `"evidenceSHA256"`, `"evidenceSha256"`)
		},
		"missing required member": func(t *testing.T, path string) {
			removeFirstJSONMember(t, path, "hostReceivedAtMonotonicNanoseconds")
		},
	} {
		cfg, receiptPath := writeValidStopRun(t)
		mutate(t, receiptPath)
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(err.Error(), name) {
			t.Fatalf("stop receipt %q error = %v", name, err)
		}
	}
}

// MARK: raw-text fixture surgery
//
// These edit the encoded document rather than the Go struct on purpose: a
// duplicated or case-variant member cannot be expressed by re-marshalling a
// struct, which is exactly why the typed decode cannot see them.

func rewriteFileText(t *testing.T, path, from, to string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), from) {
		t.Fatalf("%s does not contain %s", path, from)
	}
	updated := strings.Replace(string(content), from, to, 1)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
}

func duplicateFirstJSONMember(t *testing.T, path, member string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := `"` + member + `":`
	start := strings.Index(string(content), marker)
	if start < 0 {
		t.Fatalf("%s does not contain member %s", path, member)
	}
	end := memberValueEnd(t, string(content), start+len(marker))
	clause := string(content)[start:end]
	updated := string(content)[:start] + clause + "," +
		string(content)[start:]
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
}

func removeFirstJSONMember(t *testing.T, path, member string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := `"` + member + `":`
	start := strings.Index(string(content), marker)
	if start < 0 {
		t.Fatalf("%s does not contain member %s", path, member)
	}
	end := memberValueEnd(t, string(content), start+len(marker))
	if end < len(content) && content[end] == ',' {
		end++
	} else if start > 0 && content[start-1] == ',' {
		start--
	}
	updated := string(content)[:start] + string(content)[end:]
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
}

// memberValueEnd returns the offset just past one member's value. The fixture
// documents contain no strings with escapes or braces, so a depth counter that
// tracks quoting is sufficient and stays obvious.
func memberValueEnd(t *testing.T, content string, from int) int {
	t.Helper()
	depth := 0
	inString := false
	for index := from; index < len(content); index++ {
		character := content[index]
		if inString {
			if character == '\\' {
				index++
				continue
			}
			if character == '"' {
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return index
			}
			depth--
		case ',':
			if depth == 0 {
				return index
			}
		case '\n':
			if depth == 0 {
				return index
			}
		}
	}
	t.Fatalf("member value beginning at %d is unterminated", from)
	return 0
}
