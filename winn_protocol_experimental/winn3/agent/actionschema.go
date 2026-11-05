// Package agent defines the typed action record and the structural schema that
// governs it, and (in validator.go, authored as a companion lane) the per-kind
// contract that sits on top of it.
//
// This file owns the record itself: a stamped action is a Kind, a list of
// Params, and a PolicyRef. The three parts are kept deliberately distinct.
//
//   - Kind names the operation. The set of valid kinds is closed and lives here
//     as validKinds so that the structural JSON Schema enum can only ever
//     contain kinds that exist as Go constants.
//   - Params carry the operation's arguments as a list of named string values.
//     They are orderless by design; a consumer must not read position out of
//     them. The list is empty for an action that takes no arguments.
//   - PolicyRef names the authorization policy (and its version) that governs
//     whether the action is allowed. It is separate from the params so a policy
//     can never be smuggled in as a data parameter, and so an audit can see
//     which rule applied to which action without parsing free-form input.
//
// The JSON encoding is the wire form: Action marshals to an object whose field
// order is fixed by the struct layout (kind, params, policy), which is what
// makes a re-serialized copy byte-identical to its source. schema.json is a
// derived artifact, not a hand-maintained duplicate: JSONSchema() builds it
// from these same types by reflection, so when a field or a kind changes here
// the schema changes with it and the round-trip tests stay honest.
//
// validator.go (in this same package) layers per-kind param contracts on top of
// this structural record and the IsValidKind check, and rejects any action that
// violates either. Its Action is this Action, not a second copy.
package agent

import (
	"reflect"
	"strings"
)

// ActionKind is the closed set of operations an action record may name.
type ActionKind string

// The valid action kinds. Keep this slice in sync with the constants below;
// validKinds is both the source for the JSON Schema enum and the reject list
// used by the negative controls in actionschema_test.go.
const (
	ActionConnect   ActionKind = "connect"
	ActionRotateKey ActionKind = "rotate_key"
	ActionReport    ActionKind = "report"
)

// validKinds is the authoritative enumeration of acceptable ActionKind values.
// The schema encoder attaches this to the "kind" property by reflecting on the
// Go type, so the enum is derived from these constants and cannot drift from
// them.
var validKinds = []ActionKind{
	ActionConnect,
	ActionRotateKey,
	ActionReport,
}

// Param is a single named argument to an action. Order within a slice of
// params is not meaningful; the name is the identity.
type Param struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PolicyRef points at the authorization policy that governs an action. It is a
// reference only: the policy body lives elsewhere, addressed by name and
// version.
type PolicyRef struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Action is the typed action record: kind, params, policy ref.
type Action struct {
	Kind   ActionKind `json:"kind"`
	Params []Param    `json:"params,omitempty"`
	Policy PolicyRef  `json:"policy"`
}

// AllKinds returns the complete set of valid action kinds.
func AllKinds() []ActionKind {
	out := make([]ActionKind, len(validKinds))
	copy(out, validKinds)
	return out
}

// IsValidKind reports whether k is a member of the closed kind set.
func IsValidKind(k ActionKind) bool {
	for _, v := range validKinds {
		if v == k {
			return true
		}
	}
	return false
}

// kindEnums lets the reflective schema encoder attach an enum to any field
// whose Go type is ActionKind. Registration happens in init so the map is
// populated before any test builds a schema.
var kindEnums = map[reflect.Type][]string{}

func init() {
	ks := make([]string, len(validKinds))
	for i, k := range validKinds {
		ks[i] = string(k)
	}
	kindEnums[reflect.TypeOf(ActionKind(""))] = ks
}

// JSONSchema derives a JSON Schema (draft 2020-12) document that describes the
// Action type and its nested types. It is produced from the Go types above by
// reflection, not written by hand, so the schema and the types cannot drift.
func JSONSchema() map[string]any {
	root := deriveSchema(reflect.TypeOf(Action{}), map[reflect.Type]bool{})
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["title"] = "Winn v3 agent action"
	return root
}

// deriveSchema turns a Go type into an equivalent JSON Schema fragment. It
// supports the shapes this package uses (struct, slice, string, integer) and
// refuses anything else; refusing makes a schema here fail to build rather than
// silently producing a schema that accepts everything.
func deriveSchema(t reflect.Type, seen map[reflect.Type]bool) map[string]any {
	res := map[string]any{}
	switch t.Kind() {
	case reflect.Struct:
		if seen[t] {
			return map[string]any{"type": "object"}
		}
		seen[t] = true
		defer delete(seen, t)
		res["type"] = "object"
		props := map[string]any{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag := field.Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			omitted := strings.Contains(tag, "omitempty")
			props[name] = deriveSchema(field.Type, seen)
			if !omitted {
				required = append(required, name)
			}
		}
		res["properties"] = props
		res["required"] = required
		res["additionalProperties"] = false
	case reflect.Slice:
		res["type"] = "array"
		res["items"] = deriveSchema(t.Elem(), seen)
	case reflect.String:
		res["type"] = "string"
		if enum, ok := kindEnums[t]; ok {
			res["enum"] = enum
		}
	case reflect.Int:
		res["type"] = "integer"
	default:
		panic("agent: unsupported type in schema derivation: " + t.String())
	}
	return res
}
