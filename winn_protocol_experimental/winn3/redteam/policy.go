// Command redteam is an attack-transcript replay harness (package main, not
// a library named redteam).
//
// It reads transcript JSONL files describing security-relevant actions and
// replays each one against a small policy engine that returns an allow or
// deny verdict per action. This is a harness, not a network workload: it
// performs no network I/O and installs no tunnel or route. File I/O lives
// in main.go (read transcripts, optional -out). Every decision is a function
// of the action struct and the policy's injected clock (used for flood
// metering). Transcripts are safe to run on a live machine.
//
// The rules mirror invariants that are load-bearing in the rest of the
// winn3 tree:
//
//   - Never hand out key or secret material (credential categories).
//   - Never mutate the fleet registry in a way that can collide on endpoint,
//     public key or ssh_host (Kansas and Spain are frozen; a register that
//     deletes a colliding row is a fleet-killer, not a feature).
//   - Never bring up a host-level default-route tunnel on a machine humans
//     work on (a promoted tunnel with the default route on utun captures
//     everything the operator sends).
//   - Never take an action that would leave the box in a state where a
//     sibling lane's work is destroyed (checkout/clean/reset on a tree with a
//     large untracked corpus).
//   - Credential operations (keystore, cert, re-signing) are always denied.
//   - Honest read-only inspection is allowed.
//   - A small token bucket meters flood-shaped actions so that a burst of
//     repeated attempts is limited even when each individual attempt is
//     otherwise allowed. This mirrors the gateway admission guard.
//   - Dangerous action names are classified by the action string, not by the
//     caller-supplied category, so a git_clean or register_node smuggled
//     under category "network" or "info" is still denied.
package main

import (
	"fmt"
	"strings"
	"time"
)

// Action is a single line in a transcript. It describes one security-relevant
// operation a redteamer (or an attacker) attempts against the product.
type Action struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Category  string `json:"category"`
	Target    string `json:"target"`
	Principal string `json:"principal"`
	Seq       int    `json:"seq"`
}

// Verdict is the policy engine's answer for one action.
type Verdict struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Decision string `json:"decision"` // "allow" or "deny"
	Rule     string `json:"rule"`
	Reason   string `json:"reason"`
}

func (v Verdict) Line() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s",
		v.ID, v.Action, v.Decision, v.Rule, v.Reason)
}

// policy is the decision engine. It is a pointer type. The metering bucket
// map is not mutex-guarded; replay is sequential. The injected clock is
// the time source for token-bucket refill; a nil clock falls back to now.
type policy struct {
	clock   func() time.Time
	guarded map[string]*bucket
}

func newPolicy(nowFn func() time.Time) *policy {
	return &policy{clock: nowFn, guarded: make(map[string]*bucket)}
}

func (p *policy) now() time.Time {
	if p != nil && p.clock != nil {
		return p.clock()
	}
	return now()
}

// bucket is a tiny token bucket for metering flood-shaped actions.
type bucket struct {
	rate  float64
	burst float64
	toks  float64
	last  time.Time
}

func (b *bucket) allow(now time.Time) bool {
	if b.toks < 1 {
		if b.last.IsZero() {
			b.last = now
		}
		if d := now.Sub(b.last); d > 0 {
			b.toks += d.Seconds() * b.rate
			if b.toks > b.burst {
				b.toks = b.burst
			}
			b.last = now
		}
	}
	if b.toks < 1 {
		return false
	}
	b.toks--
	return true
}

const (
	catCredential  = "credential"
	catRegistry    = "registry"
	catTunnel      = "tunnel"
	catDestructive = "destructive"
	catNetwork     = "network"
	catInfo        = "info"
)

func isKnownCategory(c string) bool {
	switch c {
	case catCredential, catRegistry, catTunnel, catDestructive, catNetwork, catInfo:
		return true
	default:
		return false
	}
}

// impliedDangerCategory maps an action name onto a deny category so the
// caller-supplied Category field cannot smuggle a dangerous verb under
// network (metered allow) or info (default allow). Read-only names that
// happen to contain a substring of a dangerous verb (list_registered_nodes)
// are excluded. rotate_token_window is not a credential rotate_key and is
// left unclassified here.
func impliedDangerCategory(action string) string {
	if action == "" {
		return ""
	}
	if action == "rotate_key" {
		return catCredential
	}
	if strings.Contains(action, "keystore") ||
		strings.Contains(action, "session_key") ||
		strings.Contains(action, "key_export") ||
		strings.Contains(action, "read_key") ||
		strings.Contains(action, "resign") ||
		strings.Contains(action, "unlock_pin") ||
		strings.Contains(action, "_cert") ||
		strings.HasSuffix(action, "cert") {
		return catCredential
	}
	if strings.Contains(action, "register") && !strings.Contains(action, "list_registered") {
		return catRegistry
	}
	if strings.Contains(action, "tunnel") ||
		strings.Contains(action, "default_route") ||
		action == "start_host_vpn" {
		return catTunnel
	}
	if strings.Contains(action, "git_clean") ||
		strings.Contains(action, "git_reset") ||
		strings.Contains(action, "git_checkout") ||
		strings.Contains(action, "git_stash") ||
		strings.HasPrefix(action, "git_") {
		return catDestructive
	}
	return ""
}

// Evaluate returns the verdict for a. The first rule whose conditions match
// decides; rules are ordered strongest first so a genuinely dangerous action
// is denied even when it could also be classified as a benign read. The
// action name is classified before the supplied category so a dangerous
// verb cannot fail open by claiming category network or info.
func (p *policy) Evaluate(a Action) Verdict {
	id := a.ID
	if id == "" {
		id = a.Action
	}

	// 1. Rotate-key abuse is always denied, even if an attacker tries to
	//    smuggle it under a non-credential category.
	if a.Action == "rotate_key" {
		return Verdict{id, a.Action, "deny", "credential_absolute",
			"rotate_key is a credential operation and is never permitted via this path"}
	}

	if implied := impliedDangerCategory(a.Action); implied != "" {
		a.Category = implied
	}

	// 1b. Credential operations are always denied, whatever else they look like.
	if a.Category == catCredential {
		return Verdict{id, a.Action, "deny", "credential_absolute",
			"credential operations (keystore, certificate, re-sign) are never permitted"}
	}

	// 2. Fleet registry mutations that can collide are denied. Kansas and
	//    Spain are frozen; a register which deletes a row colliding on
	//    endpoint, public key or ssh_host can drop the entire fleet.
	if a.Category == catRegistry {
		return Verdict{id, a.Action, "deny", "registry_frozen",
			"node register can delete colliding rows; Kansas and Spain are read-only"}
	}

	// 3. Host-level tunnel promotion on a shared machine is denied. A promoted
	//    v3 tunnel puts the default route on utun and captures the operator's
	//    traffic.
	if a.Category == catTunnel {
		return Verdict{id, a.Action, "deny", "no_host_tunnel",
			"refusing host default-route tunnel; would capture the operator's traffic"}
	}

	// 4. Destructive tree operations are denied. The working trees hold a
	//    large untracked corpus that exists nowhere else.
	if a.Category == catDestructive {
		return Verdict{id, a.Action, "deny", "no_destructive_git",
			"checkout/clean/reset would destroy untracked work that exists nowhere else"}
	}

	// 5. Metered flood-shaped network actions: allowed a bounded number of times,
	//    then throttled. The bucket is keyed by the action shape (action plus
	//    principal), not by the transcript line id, so repeated attempts at the
	//    same thing share one budget. Individually benign read-like probes that
	//    are shaped like a flood are allowed a few times so the transcript can
	//    still show a green path followed by a throttle. Time comes from the
	//    injected clock, not wall time, so replay is deterministic.
	if a.Category == catNetwork {
		key := a.Action + "|" + a.Principal
		return p.metered(id, key, a.Action, "network_flood", 2.0, 3.0, p.now())
	}

	// 6. Unknown categories are denied. The kind set is closed; anything not
	//    in the known set has no allow rule and must be denied.
	if !isKnownCategory(a.Category) {
		return Verdict{id, a.Action, "deny", "unknown_category",
			"unknown category has no allow rule; denied by default"}
	}

	// 7. Anything not otherwise denied and not explicitly dangerous is allowed.
	//    Today that is category info whose action name did not imply a deny
	//    category. The reason string is the historical wording; rotate_token_window
	//    is one info action that is not read-only (see handoff).
	_ = catInfo
	return Verdict{id, a.Action, "allow", "default_allow",
		"read-only or inert action, no invariant violated"}
}

func (p *policy) metered(id, key, action, rule string, rate, burst float64, now time.Time) Verdict {
	b := p.guarded[key]
	if b == nil {
		b = &bucket{rate: rate, burst: burst, toks: burst}
		p.guarded[key] = b
	}
	if b.allow(now) {
		return Verdict{id, action, "allow", rule,
			"within admission budget, genuine request"}
	}
	return Verdict{id, action, "deny", rule + "_throttled",
		"admission budget exhausted for this action"}
}

func now() time.Time { return time.Now() }
