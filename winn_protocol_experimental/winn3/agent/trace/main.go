// Package main is a tiny audit trace harness for winn3/agent policy decisions.
// It registers representative rules for connect, rotate_key and report and
// admits each kind through ContractRegistry.Admit (schema then policy),
// printing Allow or Deny to agent_policy_trace.txt.
// The rotate_key case uses a policy that denies a non-owner principal, so
// that Deny is recorded in the trace. No VPN tunnel is brought up and no
// network I/O is performed.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

import (
	"winsvpn.local/winnprotocol/winn3/agent"
)

func agentDir() string {
	_, file, _, ok := runtime.Caller(0)
	if ok {
		return filepath.Dir(filepath.Dir(file))
	}
	return "winn3/agent"
}

func main() {
	ctx := context.Background()
	e := agent.NewPolicyEngine()

	// Representative policies after Register:
	// connect: allow unless gateway is banned (here none banned, so allow)
	// rotate_key: only owner principal may rotate
	// report: allow
	if err := e.Register(agent.ActionConnect, agent.DenyGateway()); err != nil {
		fmt.Fprintf(os.Stderr, "register connect: %v\n", err)
		os.Exit(1)
	}
	if err := e.Register(agent.ActionRotateKey, agent.DenyRotateKeyUnlessOwner("owner")); err != nil {
		fmt.Fprintf(os.Stderr, "register rotate_key: %v\n", err)
		os.Exit(1)
	}
	if err := e.Register(agent.ActionReport, agent.AllowRule()); err != nil {
		fmt.Fprintf(os.Stderr, "register report: %v\n", err)
		os.Exit(1)
	}

	owner := "owner"
	nonOwner := "attacker"

	cases := []struct {
		name      string
		action    *agent.Action
		wantLabel string
	}{
		{
			name: "connect_allowed",
			action: &agent.Action{
				Kind: agent.ActionConnect,
				Params: []agent.Param{
					{Name: "gateway_id", Value: "gx10"},
					{Name: "host", Value: "gx10:443"},
				},
				Policy: agent.PolicyRef{Name: "default", Version: 3},
			},
			wantLabel: "Allow",
		},
		{
			name: "rotate_key_owner_allowed",
			action: &agent.Action{
				Kind: agent.ActionRotateKey,
				Params: []agent.Param{
					{Name: "key_id", Value: "k-7"},
					{Name: "algorithm", Value: "x25519"},
					{Name: "principal", Value: owner},
				},
				Policy: agent.PolicyRef{Name: "default", Version: 3},
			},
			wantLabel: "Allow",
		},
		{
			name: "rotate_key_nonowner_denied",
			action: &agent.Action{
				Kind: agent.ActionRotateKey,
				Params: []agent.Param{
					{Name: "key_id", Value: "k-7"},
					{Name: "algorithm", Value: "x25519"},
					{Name: "principal", Value: nonOwner},
				},
				Policy: agent.PolicyRef{Name: "default", Version: 3},
			},
			wantLabel: "Deny",
		},
		{
			name: "rotate_key_no_principal_denied",
			action: &agent.Action{
				Kind: agent.ActionRotateKey,
				Params: []agent.Param{
					{Name: "key_id", Value: "k-7"},
					{Name: "algorithm", Value: "x25519"},
				},
				Policy: agent.PolicyRef{Name: "default", Version: 3},
			},
			wantLabel: "Deny",
		},
		{
			name: "report_allowed",
			action: &agent.Action{
				Kind:   agent.ActionReport,
				Params: nil,
				Policy: agent.PolicyRef{Name: "default", Version: 3},
			},
			wantLabel: "Allow",
		},
	}

	reg := agent.NewContractRegistry()

	lines := []string{}
	lines = append(lines, "# agent policy audit trace")
	lines = append(lines, "# Register: connect=DenyGateway(), rotate_key=DenyRotateKeyUnlessOwner(owner), report=AllowRule()")
	lines = append(lines, "# Decisions go through ContractRegistry.Admit (schema then policy)")
	lines = append(lines, "# Each line is kind principal decision rule")

	for _, c := range cases {
		dec, err := reg.Admit(ctx, e, c.action)
		if err != nil {
			dec = agent.Deny
		}
		principal := "n/a"
		for _, p := range c.action.Params {
			if p.Name == "principal" {
				principal = p.Value
				break
			}
		}
		line := fmt.Sprintf("kind=%s principal=%s decision=%s rule=%s case=%s", c.action.Kind, principal, dec.String(), ruleName(c.action.Kind), c.name)
		fmt.Println(line)
		lines = append(lines, line)
		// Verify expectation for non-owner case is Deny
		if c.name == "rotate_key_nonowner_denied" && dec != agent.Deny {
			fmt.Fprintf(os.Stderr, "expected Deny for non-owner rotate_key, got %s\n", dec.String())
			os.Exit(1)
		}
	}

	// Also show that an unregistered kind would be denied (deny-all).
	// Admit runs the schema gate first; wipe_disk is ErrUnknownKind -> Deny.
	unregisteredDec, unregErr := reg.Admit(ctx, e, &agent.Action{
		Kind:   agent.ActionKind("wipe_disk"),
		Policy: agent.PolicyRef{Name: "default", Version: 3},
	})
	if unregErr != nil {
		unregisteredDec = agent.Deny
	}
	line := fmt.Sprintf("kind=wipe_disk principal=n/a decision=%s rule=none case=unregistered_denied", unregisteredDec.String())
	fmt.Println(line)
	lines = append(lines, line)

	output := ""
	for _, l := range lines {
		output += l + "\n"
	}

	// Write to winn3/agent/agent_policy_trace.txt via absolute and via relative module path
	candidates := []string{
		filepath.Join(agentDir(), "agent_policy_trace.txt"),
		filepath.Join("winn3", "agent", "agent_policy_trace.txt"),
	}
	written := false
	for _, p := range candidates {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			continue
		}
		if err := os.WriteFile(p, []byte(output), 0644); err == nil {
			fmt.Printf("wrote trace to %s\n", p)
			written = true
		}
	}
	if !written {
		fmt.Fprint(os.Stderr, "failed to write trace to any candidate\n")
		os.Exit(1)
	}
}

func ruleName(k agent.ActionKind) string {
	switch k {
	case agent.ActionConnect:
		return "DenyGateway"
	case agent.ActionRotateKey:
		return "DenyRotateKeyUnlessOwner"
	case agent.ActionReport:
		return "AllowRule"
	default:
		return "none"
	}
}
