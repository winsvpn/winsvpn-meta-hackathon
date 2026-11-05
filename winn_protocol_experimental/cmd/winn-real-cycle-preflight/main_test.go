package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func TestRunRefusesExecutionBeforeEvidenceAccess(t *testing.T) {
	var output bytes.Buffer
	err := run(
		[]string{
			"-mode", "run", "-evidence", "/absent", "-trust", "/absent",
			"-topology", "/absent",
		},
		&output,
	)
	if err == nil || !strings.Contains(err.Error(), "execution is unsupported") {
		t.Fatalf("error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestRunRejectsUnknownAndPositionalArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{"-run"},
		{
			"-evidence", "/absent", "-trust", "/absent",
			"-topology", "/absent", "extra",
		},
	} {
		var output bytes.Buffer
		if err := run(arguments, &output); err == nil {
			t.Fatalf("arguments %q unexpectedly succeeded", arguments)
		}
		if output.Len() != 0 {
			t.Fatalf("arguments %q wrote output", arguments)
		}
	}
}

func TestRunProducesAllFalseNonAuthorizingOutput(t *testing.T) {
	validate := func(
		evidence, trust, topology string,
	) (realcycle.Result, error) {
		if evidence != "/evidence" || trust != "/accepted/trust.json" ||
			topology != "/accepted/e0" {
			t.Fatalf(
				"unexpected paths %q %q %q", evidence, trust, topology,
			)
		}
		return realcycle.Result{
			CycleID: "cycle", AttemptID: "attempt", TopologyID: "topology",
			BindingDigest:        strings.Repeat("1", 64),
			EvidenceBundleSHA256: strings.Repeat("2", 64),
			RuntimeCount:         4, TerminalCount: 1,
		}, nil
	}
	var first bytes.Buffer
	if err := runWithValidator(
		[]string{
			"-evidence", "/evidence", "-trust", "/accepted/trust.json",
			"-topology", "/accepted/e0",
		},
		&first, validate,
	); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := runWithValidator(
		[]string{
			"-mode", "preflight",
			"-evidence", "/evidence", "-trust", "/accepted/trust.json",
			"-topology", "/accepted/e0",
		},
		&second, validate,
	); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("nondeterministic output:\n%s\n%s", first.String(), second.String())
	}
	const wantJSON = `{"schema":"winn-real-cycle-preflight/v1","status":"evidence-contract-valid-nonauthorizing","mode":"preflight","cycle_id":"cycle","attempt_id":"attempt","topology_id":"topology","binding_digest":"1111111111111111111111111111111111111111111111111111111111111111","evidence_bundle_sha256":"2222222222222222222222222222222222222222222222222222222222222222","runtime_count":4,"terminal_count":1,"live_ready":false,"cloud_validation":false,"trust_acceptance":false,"credential_authority":false,"terminal_authority":false,"execution_authority":false,"replay_reservation":false,"provider_access":false,"credential_access":false,"mutation":"none","authority":false}` + "\n"
	if first.String() != wantJSON {
		t.Fatalf("output JSON:\n%s\nwant:\n%s", first.String(), wantJSON)
	}
	var status preflightOutput
	if err := json.Unmarshal(first.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Schema != outputSchema ||
		status.Status != "evidence-contract-valid-nonauthorizing" ||
		status.Mode != "preflight" ||
		status.CycleID != "cycle" || status.AttemptID != "attempt" ||
		status.TopologyID != "topology" ||
		status.BindingDigest != strings.Repeat("1", 64) ||
		status.EvidenceBundleSHA256 != strings.Repeat("2", 64) ||
		status.RuntimeCount != 4 || status.TerminalCount != 1 ||
		status.LiveReady ||
		status.CloudValidation || status.TrustAcceptance ||
		status.CredentialAuthority || status.TerminalAuthority ||
		status.ExecutionAuthority || status.ReplayReservation ||
		status.ProviderAccess || status.CredentialAccess ||
		status.Mutation != "none" || status.Authority {
		t.Fatalf("unsafe status: %+v", status)
	}
}

func TestRunRejectsMissingRequiredPaths(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{}, &output)
	if err == nil || !strings.Contains(
		err.Error(),
		"evidence, trust, and E0 topology paths are required",
	) {
		t.Fatalf("error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("unexpected output %q", output.String())
	}
}
