package realcycle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControllerCycleBindingRoundTripAndNonAuthority(t *testing.T) {
	fixture := newAdmissionFixture(t, TransportH3)
	admission, err := ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	value, encoded, err := NewControllerCycleBinding(
		admission, validControllerBindingInput(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.Mutation != "none" || !validDigest(value.ObjectDigest) {
		t.Fatalf("binding unexpectedly conveys authority: %+v", value)
	}
	replayed, err := ParseControllerCycleBinding(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ObjectDigest != value.ObjectDigest ||
		replayed.AdmissionBundleSHA256 != admission.AdmissionBundleSHA256 ||
		replayed.AdmissionBindingDigest != admission.BindingDigest ||
		replayed.ExpectedTransport != TransportH3 {
		t.Fatalf("unexpected replay: %+v", replayed)
	}
	reencoded, err := marshalCanonical(replayed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("controller binding did not round-trip canonically")
	}
}

func TestControllerCycleBindingDeterministicAndInputSensitive(t *testing.T) {
	fixture := newAdmissionFixture(t, TransportDirect)
	admission, err := ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	input := validControllerBindingInput()
	first, firstBytes, err := NewControllerCycleBinding(admission, input)
	if err != nil {
		t.Fatal(err)
	}
	second, secondBytes, err := NewControllerCycleBinding(admission, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ObjectDigest != second.ObjectDigest ||
		!bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("binding is not deterministic")
	}
	input.Sequence++
	changed, _, err := NewControllerCycleBinding(admission, input)
	if err != nil {
		t.Fatal(err)
	}
	if changed.ObjectDigest == first.ObjectDigest {
		t.Fatal("sequence mutation did not change object digest")
	}
}

func TestControllerCycleBindingRejectsMalformedInputs(t *testing.T) {
	fixture := newAdmissionFixture(t, TransportH3)
	admission, err := ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ControllerBindingInput)
	}{
		{"zero-sequence", func(v *ControllerBindingInput) { v.Sequence = 0 }},
		{"bad-readiness", func(v *ControllerBindingInput) { v.Readiness = "both" }},
		{"absolute-matrix", func(v *ControllerBindingInput) {
			v.MatrixRelativePath = "/tmp/matrix"
		}},
		{"traversal-matrix", func(v *ControllerBindingInput) {
			v.MatrixRelativePath = "../matrix"
		}},
		{"unsorted-env", func(v *ControllerBindingInput) {
			v.ChildEnvironmentNames = []string{"ZED", "ALPHA"}
		}},
		{"duplicate-env", func(v *ControllerBindingInput) {
			v.ChildEnvironmentNames = []string{"ALPHA", "ALPHA"}
		}},
		{"bad-env", func(v *ControllerBindingInput) {
			v.ChildEnvironmentNames = []string{"lower"}
		}},
		{"extra-env", func(v *ControllerBindingInput) {
			v.ChildEnvironmentNames = append(
				v.ChildEnvironmentNames, "WINN_UNBOUND_EXTRA",
			)
		}},
		{"resume-without-predecessor", func(v *ControllerBindingInput) {
			v.ResumeCount = 1
		}},
		{"fresh-with-predecessor", func(v *ControllerBindingInput) {
			v.PredecessorNonce = "ffeeddccbbaa99887766554433221100"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validControllerBindingInput()
			test.mutate(&input)
			if _, _, err := NewControllerCycleBinding(admission, input); err == nil {
				t.Fatal("malformed binding input unexpectedly accepted")
			}
		})
	}
}

func TestParseControllerBindingInputRequiresExactCanonicalBytes(t *testing.T) {
	input := validControllerBindingInput()
	data, err := marshalCanonical(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseControllerBindingInput(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Sequence != input.Sequence ||
		parsed.MatrixRelativePath != input.MatrixRelativePath {
		t.Fatalf("unexpected parsed input: %+v", parsed)
	}
	if _, err := ParseControllerBindingInput(append(data, ' ')); err == nil {
		t.Fatal("noncanonical trailing byte unexpectedly accepted")
	}
}

func TestLoadControllerBindingInputRejectsUnsafePath(t *testing.T) {
	data, err := marshalCanonical(validControllerBindingInput())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "controller.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControllerBindingInput(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "controller-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControllerBindingInput(link); err == nil {
		t.Fatal("symlink controller contract unexpectedly accepted")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControllerBindingInput(path); err == nil {
		t.Fatal("group/world-writable controller contract unexpectedly accepted")
	}
}

func TestControllerCycleBindingRejectsAuthorityAndDigestMutation(t *testing.T) {
	fixture := newAdmissionFixture(t, TransportH3)
	admission, err := ValidateAdmission(
		fixture.directory, fixture.trustPath, fixture.topology,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, encoded, err := NewControllerCycleBinding(
		admission, validControllerBindingInput(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name  string
		field string
		value any
	}{
		{"dispatch", "dispatch_authorized", true},
		{"executed", "external_topology_executed", true},
		{"mutation", "mutation", "run"},
		{"digest", "runner_sha256", strings.Repeat("0", 64)},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			copyMap := make(map[string]any, len(raw))
			for key, value := range raw {
				copyMap[key] = value
			}
			copyMap[mutation.field] = mutation.value
			data, err := json.Marshal(copyMap)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseControllerCycleBinding(data); err == nil {
				t.Fatal("mutated binding unexpectedly accepted")
			}
		})
	}
}

func validControllerBindingInput() ControllerBindingInput {
	digest := strings.Repeat("a", 64)
	return ControllerBindingInput{
		SoakRunID:           "soak-run-1",
		Sequence:            1,
		InstanceNonce:       "00112233445566778899aabbccddeeff",
		PredecessorNonce:    "",
		ResumeCount:         0,
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
}
