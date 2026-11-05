package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realtopology"
)

func TestRunRefusesExecutionBeforeBundleAccess(t *testing.T) {
	var output bytes.Buffer
	err := run(
		[]string{"-mode", "run", "-bundle", "/definitely/absent"},
		&output,
	)
	if err == nil || !strings.Contains(
		err.Error(), "execution is unsupported",
	) {
		t.Fatalf("error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestRunRejectsRunFlagAndPositionalArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{"-run"},
		{"-bundle", "/absent", "extra"},
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

func TestRunProducesDeterministicNonAuthorizingStatus(t *testing.T) {
	validate := func(path string) (realtopology.Result, error) {
		if path != "/retained/test-bundle" {
			t.Fatalf("unexpected bundle path %q", path)
		}
		return realtopology.Result{
			TopologyID:       "command-test",
			DescriptorSHA256: strings.Repeat("1", 64),
			BundleSHA256:     strings.Repeat("2", 64),
			PublicFileCount:  6,
		}, nil
	}
	var first bytes.Buffer
	if err := runWithValidator(
		[]string{
			"-mode", "preflight", "-bundle", "/retained/test-bundle",
		},
		&first, validate,
	); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := runWithValidator(
		[]string{"-bundle", "/retained/test-bundle"}, &second, validate,
	); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("output changed:\n%s\n%s", first.String(), second.String())
	}
	var status preflightOutput
	if err := json.Unmarshal(first.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != "structurally-valid-nonauthorizing" ||
		status.Mode != "preflight" || status.LiveReady ||
		status.ExercisedNodeCount != 0 || status.SignatureValidation ||
		status.TrustValidation || status.RuntimeValidation ||
		status.Mutation != "none" || status.Authority {
		t.Fatalf("unsafe or unexpected status: %+v", status)
	}
}
