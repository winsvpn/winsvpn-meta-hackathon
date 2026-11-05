// Package agent evaluates agent-produced actions against authorization
// policies. An action that has passed the structural schema gate in
// actionschema.go is presented to the policy engine, which owns the decision:
// a rule registry maps each action kind to the rule that decides it, and
// Evaluate returns allow or deny. The registry defaults to deny so that any
// kind without a rule, and any kind the schema does not admit, is refused
// rather than guessed at.
//
// Evaluate does not run the schema gate. Callers that need both (production
// path) must use ContractRegistry.Admit or PolicyEngine.EvaluateValidated.
// Skipping that composition can Allow a structurally incomplete action.
//
// The schema record in actionschema.go is owned by a companion lane and is
// only referenced here, never redefined. This file adds the authorization
// layer on top of that structural record.
package agent

import (
	"context"
	"fmt"
)

// Decision is the outcome of evaluating an action against a rule.
type Decision int

const (
	// Deny refuses the action.
	Deny Decision = iota
	// Allow permits the action.
	Allow
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	default:
		return "deny"
	}
}

// rule decides a single action. It is pure with respect to the registry: the
// engine supplies the action it owns, and the rule returns the decision.
type rule func(ctx context.Context, a *Action) Decision

// PolicyEngine is a rule registry: one rule per action kind. Any kind with no
// registered rule resolves to the engine default, which is always deny, so an
// unguarded kind is refusable by construction.
type PolicyEngine struct {
	rules           map[ActionKind]rule
	defaultDecision Decision
}

// NewPolicyEngine returns an engine with no rules registered. Every kind is
// denied until a rule is registered for it.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		rules:           make(map[ActionKind]rule),
		defaultDecision: Deny,
	}
}

// Register binds a rule to an action kind. It refuses a nil engine, a nil
// rule, a kind that is not in the schema, and a kind that already has a rule,
// so the registry can never hold a rule for a kind the schema rejects and a
// rule can never be silently replaced or shadowed.
func (e *PolicyEngine) Register(k ActionKind, r rule) error {
	if e == nil || e.rules == nil {
		return fmt.Errorf("agent: register: nil engine")
	}
	if r == nil {
		return fmt.Errorf("agent: register: nil rule for kind %q", k)
	}
	if !IsValidKind(k) {
		return fmt.Errorf("agent: register: kind %q not in schema", k)
	}
	if _, present := e.rules[k]; present {
		return fmt.Errorf("agent: register: rule already registered for kind %q", k)
	}
	e.rules[k] = r
	return nil
}

// Evaluate returns the decision for an action. A nil engine, a nil action, a
// kind with no registered rule, and a kind not in the schema all resolve to
// deny. A registered rule decides its own kind. The explicit default branch
// ensures any schema-valid but not explicitly allowed kind is denied
// (deny-all). Evaluate does not validate params; use EvaluateValidated or
// ContractRegistry.Admit when the schema gate must run first.
func (e *PolicyEngine) Evaluate(ctx context.Context, a *Action) Decision {
	if e == nil || a == nil {
		return Deny
	}
	switch a.Kind {
	case ActionConnect, ActionRotateKey, ActionReport:
		r, ok := e.rules[a.Kind]
		if !ok {
			return Deny
		}
		return r(ctx, a)
	default:
		return Deny
	}
}

// EvaluateValidated runs ActionSchema.Validate and then Evaluate. A
// validation failure returns Deny and the validation error, so a caller that
// ignores the error still cannot proceed. A nil engine or nil schema returns
// Deny and ErrMalformed.
func (e *PolicyEngine) EvaluateValidated(ctx context.Context, s *ActionSchema, a *Action) (Decision, error) {
	if e == nil {
		return Deny, fmt.Errorf("%w: nil engine", ErrMalformed)
	}
	if s == nil {
		return Deny, fmt.Errorf("%w: nil schema", ErrMalformed)
	}
	if err := s.Validate(a); err != nil {
		return Deny, err
	}
	return e.Evaluate(ctx, a), nil
}

// DenyGateway returns a rule that denies a connect whose gateway_id is
// missing, empty, or in the banned set, and allows a connect whose
// gateway_id is present, non-empty, and not banned. A nil action is denied.
// It reads the gateway from the orderless Params list by name, never by
// position. Duplicate gateway_id values: any banned or empty value denies.
func DenyGateway(banned ...string) rule {
	blocked := make(map[string]struct{}, len(banned))
	for _, g := range banned {
		blocked[g] = struct{}{}
	}
	return func(ctx context.Context, a *Action) Decision {
		_ = ctx
		if a == nil {
			return Deny
		}
		found := false
		for _, p := range a.Params {
			if p.Name != "gateway_id" {
				continue
			}
			found = true
			if p.Value == "" {
				return Deny
			}
			if _, bad := blocked[p.Value]; bad {
				return Deny
			}
		}
		if !found {
			return Deny
		}
		return Allow
	}
}

// AllowRule returns a rule that allows every non-nil action it is asked to
// decide. A nil action is denied rather than allowed. It is the explicit
// positive bound a kind needs before Evaluate can return allow; without a
// registered rule a kind stays denied.
func AllowRule() rule {
	return func(ctx context.Context, a *Action) Decision {
		if a == nil {
			return Deny
		}
		return Allow
	}
}

// RequirePrincipal returns a rule that allows only when the action carries at
// least one param named principal, every principal value equals owner, and
// owner itself is non-empty. Any non-owner principal, missing principal,
// empty owner, nil action, or conflicting duplicate principal is denied. It
// reads principal by name, never by position. This models ownership for
// rotate_key: only the owner principal may rotate keys.
func RequirePrincipal(owner string) rule {
	return func(ctx context.Context, a *Action) Decision {
		_ = ctx
		if a == nil || owner == "" {
			return Deny
		}
		found := false
		for _, p := range a.Params {
			if p.Name != "principal" {
				continue
			}
			found = true
			if p.Value != owner {
				return Deny
			}
		}
		if !found {
			return Deny
		}
		return Allow
	}
}

// DenyRotateKeyUnlessOwner returns a rule that denies rotate_key for any
// principal that is not owner. It is a convenience alias for
// RequirePrincipal that names the rotate_key use case explicitly so the
// audit trace can register a policy that denies a non-owner principal and
// prove the Deny is recorded.
func DenyRotateKeyUnlessOwner(owner string) rule {
	return RequirePrincipal(owner)
}
