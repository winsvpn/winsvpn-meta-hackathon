// Package agent validates agent-produced actions against a per-kind action
// contract before they reach the policy engine. It rejects anything that does
// not satisfy the contract, so that no out-of-schema action is ever offered to
// the policy engine for a decision.
//
// This validator layers a per-kind param contract on top of the structural
// Action record (see actionschema.go). The structural schema is deliberately
// coarse: it constrains the closed kind set, the presence of the policy
// reference, and that no stray top-level keys appear. It cannot express "a
// connect action must carry a host param". That requirement is the job of the
// ActionSchema here, enforced ahead of the policy engine.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Sentinel errors distinguishing the two failure classes. They are separate
// values so a test can assert which rejection happened rather than only that
// some rejection happened.
var (
	// ErrUnknownKind reports an action whose Kind is not in the closed set of
	// valid kinds. The action itself may be perfectly well-formed; it is
	// rejected here because the kind is not in the closed set.
	ErrUnknownKind = errors.New("agent: action kind not in schema")

	// ErrMalformed reports an action whose Kind is known but whose Params,
	// policy reference, or JSON envelope do not satisfy the contract for that
	// kind (for example a required param is absent, a duplicate name appears,
	// the policy name is empty, or a stray JSON key is present).
	ErrMalformed = errors.New("agent: action schema violation")
)

// ParamContract describes the param requirements of a single action kind.
// Required lists params that must be present. Allowed is the complete set of
// param names the kind may carry. If Allowed is empty it defaults to Required:
// only the required names are permitted, and if Required is also empty the
// kind takes no arguments. A params entry whose name is outside the effective
// allow set is a schema violation. Duplicate names are always a violation.
type ParamContract struct {
	Required []string
	Allowed  []string
}

// ActionSchema is an immutable map from action kind to its param contract.
// Kinds not listed here fall back to the structural schema: they are accepted
// only if the closed kind set (actionschema.go) admits them, and may carry no
// params (empty ParamContract).
type ActionSchema struct {
	contracts map[ActionKind]ParamContract
}

// NewSchema builds an ActionSchema from a map of kind to contract. The map and
// its slices are copied, so the returned schema is immutable with respect to
// the caller.
func NewSchema(contracts map[ActionKind]ParamContract) *ActionSchema {
	copied := make(map[ActionKind]ParamContract, len(contracts))
	for k, c := range contracts {
		req := make([]string, len(c.Required))
		copy(req, c.Required)
		allow := make([]string, len(c.Allowed))
		copy(allow, c.Allowed)
		copied[k] = ParamContract{Required: req, Allowed: allow}
	}
	return &ActionSchema{contracts: copied}
}

// productionContracts is the authoritative per-kind param contract the running
// agent validates against. It is the single source of truth for what each kind
// may carry, and it is what ContractRegistry is built from. A kind listed here
// with a non-empty Required must carry every named param before the policy
// engine sees it. An empty ParamContract (ActionReport) takes no arguments.
//
//   - connect requires both gateway_id (which gateway to attach) and host
//     (the dial target) before a session can be attempted.
//   - rotate_key requires key_id and algorithm so the rotation is unambiguous,
//     and may also carry principal so RequirePrincipal can decide ownership
//     after the schema gate.
//   - report takes no arguments. Extra params are refused so a report cannot
//     smuggle register or ssh_host past an AllowRule.
var productionContracts = map[ActionKind]ParamContract{
	ActionConnect: {
		Required: []string{"gateway_id", "host"},
		Allowed:  []string{"gateway_id", "host"},
	},
	ActionRotateKey: {
		Required: []string{"key_id", "algorithm"},
		Allowed:  []string{"key_id", "algorithm", "principal"},
	},
	ActionReport: {},
}

// ContractRegistry is the production registry of per-kind param contracts. It
// fixes the Agent contract to the production set above, so a caller does not
// have to assemble its own param contract to get policy-engine-safe behaviour:
// the same Production schema that this registry wraps is what the agent runs
// on. It is immutable with respect to its constructor.
type ContractRegistry struct {
	schema *ActionSchema
}

// NewContractRegistry builds the production registry from productionContracts.
// It is safe to call repeatedly; each registry is independent of the map and
// slices it was built from.
func NewContractRegistry() *ContractRegistry {
	return &ContractRegistry{schema: NewSchema(productionContracts)}
}

// Validate checks an action against the production contract registry. Its
// contract is that of ActionSchema.Validate: nil for an action that is both a
// member of the closed kind set and complete for its kind, ErrUnknownKind for
// a well-formed but unknown kind, and ErrMalformed for a known kind whose
// Params violate its production contract.
func (r *ContractRegistry) Validate(a *Action) error {
	if r == nil || r.schema == nil {
		return fmt.Errorf("%w: nil registry", ErrMalformed)
	}
	return r.schema.Validate(a)
}

// DecodeAndValidate parses a raw action payload and validates it against the
// production contract registry in one step. An undecodable payload is reported
// as ErrMalformed, matching ActionSchema.DecodeAndValidate.
func (r *ContractRegistry) DecodeAndValidate(raw []byte) (*Action, error) {
	if r == nil || r.schema == nil {
		return nil, fmt.Errorf("%w: nil registry", ErrMalformed)
	}
	return r.schema.DecodeAndValidate(raw)
}

// Admit validates a against the production contract and then evaluates it on
// e. A validation failure returns Deny and the validation error, so a caller
// that ignores the error still cannot proceed. A nil registry, nil engine, or
// nil action returns Deny.
func (r *ContractRegistry) Admit(ctx context.Context, e *PolicyEngine, a *Action) (Decision, error) {
	if r == nil || r.schema == nil {
		return Deny, fmt.Errorf("%w: nil registry", ErrMalformed)
	}
	if e == nil {
		return Deny, fmt.Errorf("%w: nil engine", ErrMalformed)
	}
	if err := r.schema.Validate(a); err != nil {
		return Deny, err
	}
	return e.Evaluate(ctx, a), nil
}

// IsKnown reports whether k has an explicit contract in this schema. A nil
// schema reports false.
func (s *ActionSchema) IsKnown(k ActionKind) bool {
	if s == nil {
		return false
	}
	_, ok := s.contracts[k]
	return ok
}

// Validate checks an action against the schema. It returns nil only for an
// action that is both a member of the closed kind set and structurally
// complete for its kind. It returns ErrUnknownKind for a well-formed but
// unknown kind, and ErrMalformed for a known kind whose Params violate its
// contract, whose policy name is empty, or that carries duplicate param names.
//
// Negative controls: unknown kinds are rejected via IsValidKind, any Param
// with an empty Name is rejected as malformed regardless of kind or contract,
// duplicate names are rejected, an empty policy name is rejected, and a kind
// whose effective allow set is empty (report; or a valid kind with no
// contract) is rejected if it carries any params.
func (s *ActionSchema) Validate(a *Action) error {
	if s == nil {
		return fmt.Errorf("%w: nil schema", ErrMalformed)
	}
	if a == nil {
		return fmt.Errorf("%w: nil action", ErrMalformed)
	}
	if a.Policy.Name == "" {
		return fmt.Errorf("%w: policy name empty", ErrMalformed)
	}
	for _, p := range a.Params {
		if p.Name == "" {
			return fmt.Errorf("%w: param name empty", ErrMalformed)
		}
	}

	contract, known := s.contracts[a.Kind]
	if !known {
		// No explicit contract: the structural schema decides. An action whose
		// kind is not even in the closed set is denied outright. A valid kind
		// with no contract may carry no params.
		if !IsValidKind(a.Kind) {
			return fmt.Errorf("%w: kind %q", ErrUnknownKind, a.Kind)
		}
		contract = ParamContract{}
	}

	have := make(map[string]bool, len(a.Params))
	for _, p := range a.Params {
		if have[p.Name] {
			return fmt.Errorf("%w: kind %q duplicate param %q", ErrMalformed, a.Kind, p.Name)
		}
		have[p.Name] = true
	}

	for _, name := range contract.Required {
		if !have[name] {
			return fmt.Errorf("%w: kind %q missing required param %q", ErrMalformed, a.Kind, name)
		}
	}

	allow := contract.Allowed
	if len(allow) == 0 {
		allow = contract.Required
	}
	if len(allow) == 0 {
		if len(a.Params) > 0 {
			return fmt.Errorf("%w: kind %q takes no params (got %q)", ErrMalformed, a.Kind, a.Params[0].Name)
		}
	} else {
		for _, p := range a.Params {
			allowed := false
			for _, al := range allow {
				if p.Name == al {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("%w: kind %q unexpected param %q", ErrMalformed, a.Kind, p.Name)
			}
		}
	}

	return nil
}

// DecodeAndValidate parses a raw action payload and validates it against the
// schema in one step, so the caller does not have to distinguish a decode
// failure from a schema failure. An undecodable payload, a payload with
// unknown JSON keys, trailing data, or a policy object that omits version is
// reported as ErrMalformed. This is the Go-side enforcement of
// additionalProperties: false and of required policy.version on the derived
// JSON Schema; encoding/json Unmarshal alone would drop stray keys and would
// treat a missing version as 0.
func (s *ActionSchema) DecodeAndValidate(raw []byte) (*Action, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil schema", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var a Action
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
		}
		return nil, fmt.Errorf("%w: trailing data: %v", ErrMalformed, err)
	}
	// schema.json marks policy.version required. encoding/json into int
	// cannot tell a missing key from an explicit 0, so a second pass with
	// *int rejects a present policy object that omitted version. An omitted
	// policy object is left to Validate (empty name).
	var wire struct {
		Policy *struct {
			Version *int `json:"version"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if wire.Policy != nil && wire.Policy.Version == nil {
		return nil, fmt.Errorf("%w: policy version missing", ErrMalformed)
	}
	if err := s.Validate(&a); err != nil {
		return nil, err
	}
	return &a, nil
}
