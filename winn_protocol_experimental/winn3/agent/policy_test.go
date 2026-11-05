package agent

import (
	"context"
	"testing"
)

// connectAction builds a connect action whose gateway_id param carries value.
func connectAction(value string) *Action {
	return &Action{
		Kind:   ActionConnect,
		Params: []Param{{Name: "gateway_id", Value: value}},
		Policy: PolicyRef{Name: "default", Version: 3},
	}
}

// TestControl_UnregisteredKindDefaultsToDeny is control one: with no rules
// registered the engine must refuse everything. If an unregistered kind were
// allowed, the registry would have no way to refuse a kind it does not know.
func TestControl_UnregisteredKindDefaultsToDeny(t *testing.T) {
	e := NewPolicyEngine()
	if got := e.Evaluate(context.Background(), connectAction("gx10")); got != Deny {
		t.Fatalf("unregistered kind decision = %v, want %v", got, Deny)
	}
}

// TestControl_OutOfSchemaKindDenied is control two: a kind the engine has a
// rule for, but which the schema does not admit, must still be denied. The
// denial must come from the registry, not from a rule, because no rule is
// registered for a kind that is not in the schema.
func TestControl_OutOfSchemaKindDenied(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, AllowRule()); err != nil {
		t.Fatalf("register: %v", err)
	}
	act := &Action{
		Kind:   ActionKind("wipe_disk"),
		Policy: PolicyRef{Name: "default", Version: 3},
	}
	if got := e.Evaluate(context.Background(), act); got != Deny {
		t.Fatalf("out-of-schema kind decision = %v, want %v", got, Deny)
	}
}

// TestControl_NilActionDenied is control three: the engine must refuse a nil
// action rather than panic or allow.
func TestControl_NilActionDenied(t *testing.T) {
	e := NewPolicyEngine()
	if got := e.Evaluate(context.Background(), nil); got != Deny {
		t.Fatalf("nil action decision = %v, want %v", got, Deny)
	}
}

// TestRegister_UnknownKindRejected checks that a rule cannot be registered for
// a kind the schema does not admit, so the registry can never hold a rule that
// the structural schema would reject.
func TestRegister_UnknownKindRejected(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionKind("wipe_disk"), AllowRule()); err == nil {
		t.Fatal("registering an out-of-schema kind did not fail")
	}
}

// TestRegister_DuplicateKindRejected checks that a rule cannot be silently
// replaced once a kind is registered, so no rule can be shadowed by mistake.
func TestRegister_DuplicateKindRejected(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, AllowRule()); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := e.Register(ActionConnect, AllowRule()); err == nil {
		t.Fatal("registering the same kind twice did not fail")
	}
}

// TestAllow_ConnectToAllowedGatewayPermitted is the positive boundary of the
// DenyGateway rule: a gateway that is not in the banned set must be allowed.
func TestAllow_ConnectToAllowedGatewayPermitted(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, DenyGateway("banned-gateway")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := e.Evaluate(context.Background(), connectAction("gx10")); got != Allow {
		t.Fatalf("allowed gateway decision = %v, want %v", got, Allow)
	}
}

// TestDeny_ConnectToBannedGatewayRefused is the deny path this suite pins. The
// DenyGateway rule must refuse a connect whose gateway_id is in the banned
// set. If the guard in DenyGateway is removed or inverted, this test goes red,
// so a mutation of the deny rule is visible to the suite.
func TestDeny_ConnectToBannedGatewayRefused(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, DenyGateway("banned-gateway")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := e.Evaluate(context.Background(), connectAction("banned-gateway")); got != Deny {
		t.Fatalf("banned gateway decision = %v, want %v", got, Deny)
	}
}

// TestAllow_RotateKeyPermittedWhenRuleRegistered exercises registering a rule
// for a second kind: the allow bound must come from an explicit rule, not from
// the default.
func TestAllow_RotateKeyPermittedWhenRuleRegistered(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionRotateKey, AllowRule()); err != nil {
		t.Fatalf("register: %v", err)
	}
	act := &Action{Kind: ActionRotateKey, Policy: PolicyRef{Name: "default", Version: 3}}
	if got := e.Evaluate(context.Background(), act); got != Allow {
		t.Fatalf("rotate_key decision = %v, want %v", got, Allow)
	}
}

// TestDenyAll_SchemaValidButNotAllowedIsDenied proves the explicit deny-all
// default: a schema-valid kind that has no registered rule must be denied.
// This is the load-bearing guard that prevents a future kind from falling
// through to allow. Mutating the default branch to return Allow must make
// this test fail.
func TestDenyAll_SchemaValidButNotAllowedIsDenied(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, AllowRule()); err != nil {
		t.Fatalf("register: %v", err)
	}
	// ActionReport is schema-valid (IsValidKind true) but has no rule
	// registered on this engine, so the explicit default must deny it.
	act := &Action{Kind: ActionReport, Policy: PolicyRef{Name: "default", Version: 3}}
	if !IsValidKind(act.Kind) {
		t.Fatalf("test setup: kind %q not in schema", act.Kind)
	}
	if got := e.Evaluate(context.Background(), act); got != Deny {
		t.Fatalf("unhandled schema-valid kind decision = %v, want %v", got, Deny)
	}
	// Also verify an unhandled ActionRotateKey is denied on a fresh engine.
	e2 := NewPolicyEngine()
	if err := e2.Register(ActionReport, AllowRule()); err != nil {
		t.Fatalf("register: %v", err)
	}
	act2 := &Action{Kind: ActionRotateKey, Policy: PolicyRef{Name: "default", Version: 3}}
	if got := e2.Evaluate(context.Background(), act2); got != Deny {
		t.Fatalf("unhandled schema-valid kind decision = %v, want %v", got, Deny)
	}
	// Default branch: an out-of-schema kind must also be denied via the
	// explicit default, not via a rule. This exercises the switch default.
	act3 := &Action{Kind: ActionKind("wipe_disk"), Policy: PolicyRef{Name: "default", Version: 3}}
	if got := e.Evaluate(context.Background(), act3); got != Deny {
		t.Fatalf("unhandled out-of-schema kind decision = %v, want %v", got, Deny)
	}
	// Fresh engine with no rules must deny even valid kinds via default path.
	e3 := NewPolicyEngine()
	act4 := &Action{Kind: ActionConnect, Policy: PolicyRef{Name: "default", Version: 3}}
	if got := e3.Evaluate(context.Background(), act4); got != Deny {
		t.Fatalf("unregistered valid kind decision = %v, want %v", got, Deny)
	}
}

// TestDecisionStringIsStable pins the string form of a decision so callers and
// audits agree on the vocabulary.
func TestDecisionStringIsStable(t *testing.T) {
	if got := Deny.String(); got != "deny" {
		t.Fatalf("Deny.String() = %q, want deny", got)
	}
	if got := Allow.String(); got != "allow" {
		t.Fatalf("Allow.String() = %q, want allow", got)
	}
}
