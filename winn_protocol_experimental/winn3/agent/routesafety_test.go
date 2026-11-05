package agent

import (
	"context"
	"testing"
)

// routeAction builds an action with the given kind and params.
func routeAction(kind ActionKind, params ...Param) *Action {
	return &Action{
		Kind:   kind,
		Params: params,
		Policy: PolicyRef{Name: "default", Version: 3},
	}
}

// TestRouteSafety_FrozenFleetAllowlistIsPublished asserts the published
// allowlist is non-empty and contains the frozen fleet members that the
// invariant protects. If spain-madrid or kansas were missing, a colliding
// register would not be denied and the fleet invariant would be open.
func TestRouteSafety_FrozenFleetAllowlistIsPublished(t *testing.T) {
	if len(FrozenFleetAllowlist) == 0 {
		t.Fatal("FrozenFleetAllowlist is empty; expected frozen fleet entries")
	}
	if len(PublishedRouteAllowlist) != len(FrozenFleetAllowlist) {
		t.Fatalf("PublishedRouteAllowlist length %d != FrozenFleetAllowlist %d", len(PublishedRouteAllowlist), len(FrozenFleetAllowlist))
	}
	need := map[string]bool{"spain-madrid": false, "kansas": false}
	for _, v := range FrozenFleetAllowlist {
		if _, ok := need[v]; ok {
			need[v] = true
		}
	}
	for k, found := range need {
		if !found {
			t.Fatalf("FrozenFleetAllowlist missing %q; must contain frozen fleet", k)
		}
	}
}

// TestRouteSafety_RegisterCollisionDenied is the deny path for register. A
// param named register whose value is exactly an allowlisted frozen entry must
// be denied. If the guard is removed or inverted this goes red.
func TestRouteSafety_RegisterCollisionDenied(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid", "kansas")
	act := routeAction(ActionConnect, Param{Name: "register", Value: "spain-madrid"})
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("register collision decision = %v, want %v", got, Deny)
	}
	act2 := routeAction(ActionConnect, Param{Name: "register", Value: "kansas"})
	if got := rule(context.Background(), act2); got != Deny {
		t.Fatalf("register collision decision = %v, want %v", got, Deny)
	}
}

// TestRouteSafety_SshHostCollisionDenied is the deny path for ssh_host. A param
// named ssh_host whose value collides against the allowlist must be denied.
func TestRouteSafety_SshHostCollisionDenied(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid", "kansas")
	act := routeAction(ActionConnect, Param{Name: "ssh_host", Value: "spain-madrid"})
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("ssh_host collision decision = %v, want %v", got, Deny)
	}
	act2 := routeAction(ActionReport, Param{Name: "ssh_host", Value: "kansas"})
	if got := rule(context.Background(), act2); got != Deny {
		t.Fatalf("ssh_host collision decision = %v, want %v", got, Deny)
	}
}

// TestRouteSafety_NonCollidingRegisterAllowed is the positive boundary: a
// register value not in the allowlist must be allowed.
func TestRouteSafety_NonCollidingRegisterAllowed(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid", "kansas")
	act := routeAction(ActionConnect, Param{Name: "register", Value: "new-node-1"})
	if got := rule(context.Background(), act); got != Allow {
		t.Fatalf("non-colliding register decision = %v, want %v", got, Allow)
	}
}

// TestRouteSafety_NonCollidingSshHostAllowed is the positive boundary for
// ssh_host.
func TestRouteSafety_NonCollidingSshHostAllowed(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid", "kansas")
	act := routeAction(ActionConnect, Param{Name: "ssh_host", Value: "10.0.0.5"})
	if got := rule(context.Background(), act); got != Allow {
		t.Fatalf("non-colliding ssh_host decision = %v, want %v", got, Allow)
	}
}

// TestRouteSafety_Orderless asserts params are read by name not position. Two
// actions with the same colliding register and ssh_host values in opposite
// order must both be denied. If the rule read position, one would diverge.
func TestRouteSafety_Orderless(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid")
	a := routeAction(ActionConnect,
		Param{Name: "register", Value: "spain-madrid"},
		Param{Name: "ssh_host", Value: "ok-host"},
	)
	b := routeAction(ActionConnect,
		Param{Name: "ssh_host", Value: "ok-host"},
		Param{Name: "register", Value: "spain-madrid"},
	)
	if got := rule(context.Background(), a); got != Deny {
		t.Fatalf("order A decision = %v, want %v", got, Deny)
	}
	if got := rule(context.Background(), b); got != Deny {
		t.Fatalf("order B decision = %v, want %v", got, Deny)
	}
	// Both orderings with no collision must allow.
	c := routeAction(ActionConnect,
		Param{Name: "register", Value: "new-node"},
		Param{Name: "ssh_host", Value: "10.0.0.5"},
	)
	d := routeAction(ActionConnect,
		Param{Name: "ssh_host", Value: "10.0.0.5"},
		Param{Name: "register", Value: "new-node"},
	)
	if got := rule(context.Background(), c); got != Allow {
		t.Fatalf("order C decision = %v, want %v", got, Allow)
	}
	if got := rule(context.Background(), d); got != Allow {
		t.Fatalf("order D decision = %v, want %v", got, Allow)
	}
}

// TestRouteSafety_MixedParamsAnyCollisionDenied asserts that if any param
// collides, the action is denied regardless of other params.
func TestRouteSafety_MixedParamsAnyCollisionDenied(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid", "kansas")
	act := routeAction(ActionConnect,
		Param{Name: "gateway_id", Value: "spain-madrid"},
		Param{Name: "register", Value: "kansas"},
		Param{Name: "host", Value: "ok"},
	)
	if got := rule(context.Background(), act); got != Deny {
		t.Fatalf("mixed params with one collision decision = %v, want %v", got, Deny)
	}
	act2 := routeAction(ActionConnect,
		Param{Name: "register", Value: "ok-node"},
		Param{Name: "ssh_host", Value: "spain-madrid"},
	)
	if got := rule(context.Background(), act2); got != Deny {
		t.Fatalf("mixed params ssh_host collision decision = %v, want %v", got, Deny)
	}
}

// TestRouteSafety_EmptyAllowlistAllowsEverything asserts an empty allowlist
// denies nothing, proving the rule defaults to allow when no fleet is
// published and that a mutation widening the allowlist is visible.
func TestRouteSafety_EmptyAllowlistAllowsEverything(t *testing.T) {
	rule := DenyRouteCollision()
	cases := []*Action{
		routeAction(ActionConnect, Param{Name: "register", Value: "spain-madrid"}),
		routeAction(ActionConnect, Param{Name: "ssh_host", Value: "kansas"}),
		routeAction(ActionConnect, Param{Name: "host", Value: "spain-madrid"}),
	}
	for i, act := range cases {
		if got := rule(context.Background(), act); got != Allow {
			t.Fatalf("case %d decision = %v, want %v for empty allowlist", i, got, Allow)
		}
	}
}

// TestRouteSafety_CaseSensitive asserts the collision check is exact and case
// sensitive. A homoglyph or case variant of a frozen entry must not be
// treated as a collision.
func TestRouteSafety_CaseSensitive(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid")
	act := routeAction(ActionConnect, Param{Name: "register", Value: "Spain-Madrid"})
	if got := rule(context.Background(), act); got != Allow {
		t.Fatalf("case variant decision = %v, want %v (exact match only)", got, Allow)
	}
	act2 := routeAction(ActionConnect, Param{Name: "ssh_host", Value: "SPAIN-MADRID"})
	if got := rule(context.Background(), act2); got != Allow {
		t.Fatalf("upper case decision = %v, want %v", got, Allow)
	}
}

// TestRouteSafety_UnrelatedParamNameIgnored asserts a param whose name is
// neither register nor ssh_host is ignored even if its value collides.
func TestRouteSafety_UnrelatedParamNameIgnored(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid")
	act := routeAction(ActionConnect,
		Param{Name: "gateway_id", Value: "spain-madrid"},
		Param{Name: "host", Value: "spain-madrid"},
	)
	if got := rule(context.Background(), act); got != Allow {
		t.Fatalf("unrelated param name decision = %v, want %v", got, Allow)
	}
}

// TestRouteSafety_NilActionDenied asserts a nil action is denied rather than
// panicking or allowing.
func TestRouteSafety_NilActionDenied(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid")
	if got := rule(context.Background(), nil); got != Deny {
		t.Fatalf("nil action decision = %v, want %v", got, Deny)
	}
}

// TestRouteSafety_NoParamsAllowed asserts an action with no params is allowed
// when the allowlist is non-empty, so the rule does not blanket deny.
func TestRouteSafety_NoParamsAllowed(t *testing.T) {
	rule := DenyRouteCollision("spain-madrid", "kansas")
	act := routeAction(ActionConnect)
	if got := rule(context.Background(), act); got != Allow {
		t.Fatalf("no params decision = %v, want %v", got, Allow)
	}
	act2 := routeAction(ActionReport)
	if got := rule(context.Background(), act2); got != Allow {
		t.Fatalf("report no params decision = %v, want %v", got, Allow)
	}
}

// TestRouteSafety_RouteSafetyRuleUsesFrozenFleet pins that RouteSafetyRule
// and FrozenFleetRule both use the published frozen fleet allowlist. A change
// that decouples them from the allowlist must be visible.
func TestRouteSafety_RouteSafetyRuleUsesFrozenFleet(t *testing.T) {
	for _, r := range []rule{RouteSafetyRule(), FrozenFleetRule()} {
		act := routeAction(ActionConnect, Param{Name: "register", Value: "spain-madrid"})
		if got := r(context.Background(), act); got != Deny {
			t.Fatalf("frozen fleet rule register collision decision = %v, want %v", got, Deny)
		}
		act2 := routeAction(ActionConnect, Param{Name: "ssh_host", Value: "kansas"})
		if got := r(context.Background(), act2); got != Deny {
			t.Fatalf("frozen fleet rule ssh_host collision decision = %v, want %v", got, Deny)
		}
		act3 := routeAction(ActionConnect, Param{Name: "register", Value: "new-node-ok"})
		if got := r(context.Background(), act3); got != Allow {
			t.Fatalf("frozen fleet rule non-colliding decision = %v, want %v", got, Allow)
		}
	}
}

// TestRouteSafety_IntegrationWithPolicyEngine exercises the rule through the
// policy engine registry, proving the correspondence rule: the schema is only
// referenced, never redefined, and the engine still denies by default.
func TestRouteSafety_IntegrationWithPolicyEngine(t *testing.T) {
	e := NewPolicyEngine()
	if err := e.Register(ActionConnect, DenyRouteCollision("spain-madrid", "kansas")); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Colliding register must be denied via engine.
	colliding := routeAction(ActionConnect, Param{Name: "register", Value: "spain-madrid"})
	if got := e.Evaluate(context.Background(), colliding); got != Deny {
		t.Fatalf("engine colliding register decision = %v, want %v", got, Deny)
	}
	// Colliding ssh_host must be denied via engine.
	colliding2 := routeAction(ActionConnect, Param{Name: "ssh_host", Value: "kansas"})
	if got := e.Evaluate(context.Background(), colliding2); got != Deny {
		t.Fatalf("engine colliding ssh_host decision = %v, want %v", got, Deny)
	}
	// Non-colliding must be allowed.
	ok := routeAction(ActionConnect, Param{Name: "register", Value: "new-node"}, Param{Name: "ssh_host", Value: "10.0.0.5"})
	if got := e.Evaluate(context.Background(), ok); got != Allow {
		t.Fatalf("engine non-colliding decision = %v, want %v", got, Allow)
	}
	// Unrelated param colliding on value must still allow, as rule checks name.
	unrelated := routeAction(ActionConnect, Param{Name: "gateway_id", Value: "spain-madrid"})
	if got := e.Evaluate(context.Background(), unrelated); got != Allow {
		t.Fatalf("engine unrelated param decision = %v, want %v", got, Allow)
	}
}

// TestRouteSafety_IntegrationWithMultipleKinds proves the same rule can guard
// multiple kinds when registered for each, and that an unregistered kind
// remains denied by the engine default regardless of the rule.
func TestRouteSafety_IntegrationWithMultipleKinds(t *testing.T) {
	e := NewPolicyEngine()
	shared := DenyRouteCollision("spain-madrid")
	if err := e.Register(ActionConnect, shared); err != nil {
		t.Fatalf("register connect: %v", err)
	}
	if err := e.Register(ActionRotateKey, shared); err != nil {
		t.Fatalf("register rotate_key: %v", err)
	}
	// Both kinds with colliding ssh_host must be denied.
	for _, kind := range []ActionKind{ActionConnect, ActionRotateKey} {
		act := routeAction(kind, Param{Name: "ssh_host", Value: "spain-madrid"})
		if got := e.Evaluate(context.Background(), act); got != Deny {
			t.Fatalf("kind %q colliding decision = %v, want %v", kind, got, Deny)
		}
	}
	// Unregistered ActionReport must be denied by engine default even with
	// non-colliding params.
	act := routeAction(ActionReport, Param{Name: "register", Value: "new-node"})
	if got := e.Evaluate(context.Background(), act); got != Deny {
		t.Fatalf("unregistered kind decision = %v, want %v", got, Deny)
	}
}
