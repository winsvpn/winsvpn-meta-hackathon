package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func TestRunRejectsExecutionAndUnexpectedArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{
			"-mode", "run", "-admission", "/absent",
			"-trust", "/absent", "-topology", "/absent",
		},
		{"-run"},
		{
			"-admission", "/absent", "-trust", "/absent",
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

func TestRunRejectsMissingAdmissionTrustTopologyPaths(t *testing.T) {
	var output bytes.Buffer
	err := run(nil, &output)
	if err == nil {
		t.Fatal("missing paths unexpectedly succeeded")
	}
	if err.Error() != "admission, trust, and E0 topology paths are required" {
		t.Fatalf("error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("wrote output %q", output.Bytes())
	}
}

func TestRunPropagatesValidatorErrorWithoutOutput(t *testing.T) {
	validate := func(
		string, string, string,
	) (realcycle.AdmissionResult, error) {
		return realcycle.AdmissionResult{
			CycleID: "must-not-leak",
		}, errors.New("validator exploded")
	}
	var output bytes.Buffer
	err := runWithValidator(
		[]string{
			"-admission", "/admission", "-trust", "/trust",
			"-topology", "/e0",
		},
		&output, validate,
	)
	if err == nil || err.Error() != "validator exploded" {
		t.Fatalf("error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("wrote output %q", output.Bytes())
	}
}

func TestRunProducesOnlyAllFalseNonAuthorizingOutput(t *testing.T) {
	validate := func(
		admission, trust, topology string,
	) (realcycle.AdmissionResult, error) {
		if admission != "/admission" || trust != "/trust" ||
			topology != "/e0" {
			t.Fatalf("unexpected paths %q %q %q", admission, trust, topology)
		}
		return realcycle.AdmissionResult{
			CycleID: "cycle", AttemptID: "attempt", TopologyID: "topology",
			BindingDigest:           strings.Repeat("1", 64),
			AdmissionBundleSHA256:   strings.Repeat("2", 64),
			RuntimeCollectionDigest: strings.Repeat("3", 64),
			ReservationObjectDigest: strings.Repeat("4", 64),
			RuntimeCount:            4, ReservedTokenCount: 1,
			StartNotBefore: "2030-01-01T10:08:00Z",
			StartDeadline:  "2030-01-01T10:10:00Z",
			FinishDeadline: "2030-01-01T10:20:00Z",
		}, nil
	}
	var output bytes.Buffer
	if err := runWithValidator(
		[]string{
			"-admission", "/admission", "-trust", "/trust",
			"-topology", "/e0",
		},
		&output, validate,
	); err != nil {
		t.Fatal(err)
	}
	var status admissionOutput
	if err := json.Unmarshal(output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Schema != "winn-real-cycle-admission-preflight/v1" ||
		status.Status != "admission-contract-valid-nonauthorizing" ||
		status.Mode != "preflight" || status.LiveReady ||
		status.DispatchAuthorized || status.RuntimeAuthority ||
		status.ProviderAccess || status.CredentialAccess ||
		status.ReservationMutation || status.ExecutionAuthority ||
		status.CanonicalPublication || status.Mutation != "none" ||
		status.Authority {
		t.Fatalf("unsafe status: %+v", status)
	}
	if status.CycleID != "cycle" || status.AttemptID != "attempt" ||
		status.TopologyID != "topology" {
		t.Fatalf("identity: %+v", status)
	}
	if status.BindingDigest != strings.Repeat("1", 64) ||
		status.AdmissionBundleSHA256 != strings.Repeat("2", 64) ||
		status.RuntimeCollectionDigest != strings.Repeat("3", 64) ||
		status.ReservationObjectDigest != strings.Repeat("4", 64) {
		t.Fatalf("digests: %+v", status)
	}
	if status.RuntimeCount != 4 || status.ReservedTokenCount != 1 {
		t.Fatalf("counts: %+v", status)
	}
	if status.StartNotBefore != "2030-01-01T10:08:00Z" ||
		status.StartDeadline != "2030-01-01T10:10:00Z" ||
		status.FinishDeadline != "2030-01-01T10:20:00Z" {
		t.Fatalf("windows: %+v", status)
	}
}
