// Package agent route safety extends the policy engine with a route-safety rule
// that reflects the frozen-fleet invariant: Kansas and Spain are FROZEN. Any
// /api/v1/nodes/register that collides on endpoint, public key or ssh_host can
// delete spain-madrid, the entire fleet. The rule denies any action whose
// params name a register or ssh_host collision against a published allowlist.
//
// The allowlist is published here as FrozenFleetAllowlist so the invariant is
// visible to tests, audits and any registry that wishes to wire it. The rule
// itself is orderless on Params, matching the schema contract that param order
// is meaningless. It references the Action record owned in actionschema.go and
// never redefines it.
package agent

import (
	"context"
)

// FrozenFleetAllowlist is the published allowlist of frozen fleet identifiers
// that must not be collided against. Kansas and Spain are FROZEN: any register
// that collides on endpoint, public key or ssh_host can delete spain-madrid.
// The list is authoritative for the route-safety rule and is the single
// correspondence point with the fleet inventory.
var FrozenFleetAllowlist = []string{
	"spain-madrid",
	"kansas",
	"spain-madrid:443",
	"kansas:443",
}

// PublishedRouteAllowlist is the published allowlist used by the route-safety
// rule. It aliases FrozenFleetAllowlist so callers that speak in route-safety
// terms and callers that speak in fleet terms see the same data.
var PublishedRouteAllowlist = FrozenFleetAllowlist

// DenyRouteCollision returns a rule that denies any action whose Params name a
// register or ssh_host collision against the given allowlist. It reads params
// by name, never by position, so param order is meaningless. A param whose
// Name is "register" or "ssh_host" and whose Value is exactly an entry in the
// allowlist is a collision and is denied. Any other param name, any value not
// in the allowlist, and an empty param list are allowed. A nil action is
// denied rather than allowed.
func DenyRouteCollision(allowlist ...string) rule {
	blocked := make(map[string]struct{}, len(allowlist))
	for _, v := range allowlist {
		blocked[v] = struct{}{}
	}
	return func(ctx context.Context, a *Action) Decision {
		_ = ctx
		if a == nil {
			return Deny
		}
		for _, p := range a.Params {
			if p.Name == "register" || p.Name == "ssh_host" {
				if _, bad := blocked[p.Value]; bad {
					return Deny
				}
			}
		}
		return Allow
	}
}

// RouteSafetyRule returns the frozen-fleet invariant rule using
// FrozenFleetAllowlist. It denies any register or ssh_host param that collides
// against the frozen fleet, reflecting that Kansas and Spain are frozen and
// must not be overwritten by a colliding register.
func RouteSafetyRule() rule {
	return DenyRouteCollision(FrozenFleetAllowlist...)
}

// FrozenFleetRule is an alias for RouteSafetyRule, naming the same invariant
// from the fleet side.
func FrozenFleetRule() rule {
	return RouteSafetyRule()
}
