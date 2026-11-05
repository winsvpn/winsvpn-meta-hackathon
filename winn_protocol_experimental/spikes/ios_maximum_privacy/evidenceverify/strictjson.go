package main

// Strict JSON member validation, applied at every trust boundary BEFORE any
// typed decode.
//
// Go's encoding/json is permissive in three ways that matter for evidence:
//
//  1. Member names are matched case-insensitively, so `"Schema"`, `"SCHEMA"`
//     and `"schema"` all populate the same field and `DisallowUnknownFields`
//     raises no objection, because from its point of view the member IS known.
//  2. When an object repeats a member, the last occurrence silently wins. A
//     producer can therefore hand this verifier one document and any other
//     reader — a browser, jq, a Swift decoder — a different one.
//  3. An absent member and a zero-valued member are indistinguishable after
//     decoding into a non-pointer field.
//
// Each of those turns "the verifier accepted these bytes" into a weaker claim
// than it looks. Every object is therefore walked as a token stream first, and
// the typed decode only ever runs on bytes whose member set is already known to
// be exact, unique, and complete.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// jsonShape is the exact member set one JSON object is permitted to present.
type jsonShape struct {
	name    string
	members map[string]jsonMember
}

// jsonMember describes one declared member. At most one of object/element is
// set; when both are nil the member's value must be a non-null scalar.
type jsonMember struct {
	required bool
	object   *jsonShape
	element  *jsonShape
}

func newJSONShape(name string) *jsonShape {
	return &jsonShape{name: name, members: make(map[string]jsonMember)}
}

// declare panics on a repeated declaration because that is a source defect in
// this program, not untrusted input; it is reached at package initialization
// and therefore fails every test binary immediately.
func (shape *jsonShape) declare(
	name string,
	member jsonMember,
) *jsonShape {
	if _, exists := shape.members[name]; exists {
		panic("duplicate member declaration " + shape.name + "." + name)
	}
	shape.members[name] = member
	return shape
}

func (shape *jsonShape) required(names ...string) *jsonShape {
	for _, name := range names {
		shape.declare(name, jsonMember{required: true})
	}
	return shape
}

func (shape *jsonShape) optional(names ...string) *jsonShape {
	for _, name := range names {
		shape.declare(name, jsonMember{})
	}
	return shape
}

func (shape *jsonShape) requiredObject(
	name string,
	nested *jsonShape,
) *jsonShape {
	return shape.declare(name, jsonMember{required: true, object: nested})
}

func (shape *jsonShape) optionalObject(
	name string,
	nested *jsonShape,
) *jsonShape {
	return shape.declare(name, jsonMember{object: nested})
}

func (shape *jsonShape) requiredArray(
	name string,
	element *jsonShape,
) *jsonShape {
	return shape.declare(name, jsonMember{required: true, element: element})
}

// validateStrictJSON walks content as a token stream and refuses anything the
// typed decode would silently normalise away. It recurses into every nested
// object and array element, so the guarantee holds at every depth.
func validateStrictJSON(content []byte, shape *jsonShape) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := validateJSONObject(decoder, shape, shape.name); err != nil {
		return err
	}
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("%s is followed by trailing JSON", shape.name)
	}
	return err
}

func validateJSONObject(
	decoder *json.Decoder,
	shape *jsonShape,
	path string,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%s is not a JSON object", path)
	}
	seen := make(map[string]struct{}, len(shape.members))
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("%s has a non-string member name", path)
		}
		if _, repeated := seen[name]; repeated {
			return fmt.Errorf("%s repeats member %q", path, name)
		}
		seen[name] = struct{}{}
		member, declared := shape.members[name]
		if !declared {
			return fmt.Errorf(
				"%s: %s", path, undeclaredMemberReason(shape, name),
			)
		}
		if err := validateJSONMember(
			decoder, member, path+"."+name,
		); err != nil {
			return err
		}
	}
	// Consumes the closing brace; a malformed object surfaces here.
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for _, name := range sortedRequiredMembers(shape) {
		if _, present := seen[name]; !present {
			return fmt.Errorf(
				"%s is missing required member %q", path, name,
			)
		}
	}
	return nil
}

func validateJSONMember(
	decoder *json.Decoder,
	member jsonMember,
	path string,
) error {
	switch {
	case member.object != nil:
		return validateJSONObject(decoder, member.object, path)
	case member.element != nil:
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
			return fmt.Errorf("%s is not a JSON array", path)
		}
		for index := 0; decoder.More(); index++ {
			if err := validateJSONObject(
				decoder,
				member.element,
				fmt.Sprintf("%s[%d]", path, index),
			); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if _, composite := token.(json.Delim); composite {
			return fmt.Errorf("%s must be a scalar", path)
		}
		if token == nil {
			return fmt.Errorf(
				"%s is null; absent and null are not interchangeable", path,
			)
		}
		return nil
	}
}

// undeclaredMemberReason names the case-variant collision explicitly. Without
// it, `"Schema": "…"` alongside no `"schema"` would report only "not
// declared", which reads like a typo rather than the case-insensitive decode
// this check exists to prevent.
func undeclaredMemberReason(shape *jsonShape, name string) string {
	variants := make([]string, 0, 1)
	for declared := range shape.members {
		if declared != name && strings.EqualFold(declared, name) {
			variants = append(variants, declared)
		}
	}
	if len(variants) > 0 {
		sort.Strings(variants)
		return fmt.Sprintf(
			"member %q is a case variant of declared member %q",
			name,
			variants[0],
		)
	}
	return fmt.Sprintf("member %q is not declared", name)
}

// sortedRequiredMembers keeps the missing-member message deterministic; Go map
// iteration order is not, and a nondeterministic error string makes a test
// that matches on it flaky rather than meaningful.
func sortedRequiredMembers(shape *jsonShape) []string {
	names := make([]string, 0, len(shape.members))
	for name, member := range shape.members {
		if member.required {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
