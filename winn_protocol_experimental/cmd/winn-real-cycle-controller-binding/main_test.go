package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func TestRunRejectsExecutionAndMissingContract(t *testing.T) {
	for _, arguments := range [][]string{
		{"-mode", "run"},
		{"-mode", "preflight"},
		{"extra"},
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

func TestRunSuccessEmitsExactlyOneCanonicalBinding(t *testing.T) {
	digest := strings.Repeat("a", 64)
	input := realcycle.ControllerBindingInput{
		SoakRunID:           "soak-run-1",
		Sequence:            1,
		InstanceNonce:       "00112233445566778899aabbccddeeff",
		Readiness:           "warm",
		Profile:             "direct-primary",
		RunnerSHA256:        digest,
		MatrixRelativePath:  "scripts/aicore_phase1_auto_matrix.sh",
		MatrixSHA256:        digest,
		SnapshotSHA256:      digest,
		SnapshotFileCount:   102,
		SourceSHA256:        digest,
		ManifestSHA256:      digest,
		VerifierSHA256:      digest,
		ConfigurationSHA256: digest,
		ChildEnvironmentNames: []string{
			"READINESS",
			"WINN_SOAK_ADAPTER_MODE",
			"WINN_SOAK_CYCLE_SEQUENCE",
			"WINN_SOAK_INSTANCE_NONCE",
			"WINN_SOAK_MATRIX_RELATIVE_PATH",
			"WINN_SOAK_MATRIX_SHA256",
			"WINN_SOAK_PROFILE",
			"WINN_SOAK_RUN_ID",
		},
	}
	admission := realcycle.AdmissionResult{
		CycleID:                 "cycle-1",
		AttemptID:               "attempt-1",
		TopologyID:              "topology-1",
		BindingDigest:           digest,
		Nonce:                   "ffeeddccbbaa99887766554433221100",
		CounterDomain:           "counter-1",
		AcceptedCounter:         1,
		ExpectedTransport:       realcycle.TransportDirect,
		AdmissionBundleSHA256:   digest,
		RuntimeCollectionDigest: digest,
		ReservationObjectDigest: digest,
		StartNotBefore:          "2030-01-01T10:08:00Z",
		StartDeadline:           "2030-01-01T10:10:00Z",
		FinishDeadline:          "2030-01-01T10:20:00Z",
	}
	var output bytes.Buffer
	if err := runWith(
		[]string{
			"-admission", "/admission",
			"-trust", "/trust",
			"-topology", "/topology",
			"-controller-contract", "/contract",
		},
		&output,
		func(path string) (realcycle.ControllerBindingInput, error) {
			if path != "/contract" {
				t.Fatalf("unexpected contract path %q", path)
			}
			return input, nil
		},
		func(
			admissionPath, trustPath, topologyPath string,
		) (realcycle.AdmissionResult, error) {
			if admissionPath != "/admission" ||
				trustPath != "/trust" || topologyPath != "/topology" {
				t.Fatalf(
					"unexpected admission paths %q %q %q",
					admissionPath, trustPath, topologyPath,
				)
			}
			return admission, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := realcycle.ParseControllerCycleBinding(
		output.Bytes(),
	); err != nil {
		t.Fatalf(
			"CLI output is not one canonical binding: %v bytes=%q",
			err, output.String(),
		)
	}
	if bytes.HasSuffix(output.Bytes(), []byte("\n\n")) {
		t.Fatal("CLI appended a second newline")
	}
}

func TestRunRejectsNoncanonicalContractBeforeAdmission(t *testing.T) {
	directory := t.TempDir()
	noncanonical := filepath.Join(directory, "noncanonical.json")
	if err := os.WriteFile(
		noncanonical, []byte("{\"sequence\":1} \n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{
		"-admission", "/absent",
		"-trust", "/absent",
		"-topology", "/absent",
		"-controller-contract", noncanonical,
	}, &output)
	if err == nil {
		t.Fatal("noncanonical contract unexpectedly accepted")
	}
	if output.Len() != 0 {
		t.Fatal("failure wrote output")
	}
}
