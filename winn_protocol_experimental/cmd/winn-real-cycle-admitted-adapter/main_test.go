package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func TestRunAcceptsOnlyBoundPreflightAndReportsNoAuthority(t *testing.T) {
	binding, encoded := testBinding(t)
	var output bytes.Buffer
	if err := run(
		bytes.NewReader(encoded), testEnvironment(binding), &output,
	); err != nil {
		t.Fatal(err)
	}
	var status preflightOutput
	if err := json.Unmarshal(output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Schema != outputSchema ||
		status.ControllerBindingDigest != binding.ObjectDigest ||
		status.DispatchAuthorized || status.ExternalTopologyExecuted ||
		status.MatrixExecuted || status.ProviderAccess ||
		status.CredentialAccess || status.Mutation != "none" ||
		status.Authority {
		t.Fatalf("unsafe output: %+v", status)
	}
}

func TestRunRejectsEnvironmentAndBindingMutations(t *testing.T) {
	binding, encoded := testBinding(t)
	tests := []struct {
		name   string
		bytes  []byte
		mutate func([]string) []string
	}{
		{"run-mode", encoded, func(env []string) []string {
			return replaceEnvironment(env, "WINN_SOAK_ADAPTER_MODE", "run")
		}},
		{"wrong-sequence", encoded, func(env []string) []string {
			return replaceEnvironment(env, "WINN_SOAK_CYCLE_SEQUENCE", "2")
		}},
		{"extra-name", encoded, func(env []string) []string {
			return append(env, "EXTRA=value")
		}},
		{"missing-name", encoded, func(env []string) []string {
			return env[:len(env)-1]
		}},
		{"duplicate-name", encoded, func(env []string) []string {
			return append(env, env[0])
		}},
		{"trailing-binding-byte", append(encoded, ' '), func(env []string) []string {
			return env
		}},
		{"truncated-binding", encoded[:len(encoded)-1], func(env []string) []string {
			return env
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(
				bytes.NewReader(test.bytes),
				test.mutate(testEnvironment(binding)),
				&output,
			); err == nil {
				t.Fatal("mutated input unexpectedly accepted")
			}
			if output.Len() != 0 {
				t.Fatal("failure wrote output")
			}
		})
	}
}

func TestRunRejectsOversizeBinding(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, maxBindingBytes+1)
	if err := run(bytes.NewReader(data), nil, &bytes.Buffer{}); err == nil {
		t.Fatal("oversize binding unexpectedly accepted")
	}
}

func TestStableBindingDescriptorCustody(t *testing.T) {
	_, encoded := testBinding(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "binding.json")
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := readStableBindingFile(file); err != nil ||
		!bytes.Equal(data, encoded) {
		t.Fatalf("stable binding rejected: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	writable, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	if _, err := readStableBindingFile(writable); err == nil {
		t.Fatal("owner-writable binding unexpectedly accepted")
	}

	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "binding-alias.json")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	linked, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer linked.Close()
	if _, err := readStableBindingFile(linked); err == nil {
		t.Fatal("multiply-linked binding unexpectedly accepted")
	}
}

func TestStableBindingDescriptorRejectsSameInodeRewrite(t *testing.T) {
	_, encoded := testBinding(t)
	path := filepath.Join(t.TempDir(), "binding.json")
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	original := afterFirstBindingRead
	afterFirstBindingRead = func() {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		mutated := append([]byte(nil), encoded...)
		mutated[10] ^= 1
		if err := os.WriteFile(path, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		afterFirstBindingRead = original
	}
	t.Cleanup(func() { afterFirstBindingRead = original })
	if _, err := readStableBindingFile(file); err == nil {
		t.Fatal("same-inode binding rewrite unexpectedly accepted")
	}
}

func TestStableBindingDescriptorRejectsPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := readStableBindingFile(reader); err == nil {
		t.Fatal("pipe binding descriptor unexpectedly accepted")
	}
}

func TestStableBindingDescriptorRejectsNonzeroInitialOffset(t *testing.T) {
	_, encoded := testBinding(t)
	path := filepath.Join(t.TempDir(), "binding.json")
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableBindingFile(file); err == nil {
		t.Fatal("nonzero initial offset unexpectedly accepted")
	}
}

func TestRunInheritedClosesAllDescriptorsBeforeReturning(t *testing.T) {
	binding, encoded := testBinding(t)
	_, intentBytes, err := realcycle.NewControllerCycleIntent(encoded)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	runnerPath := filepath.Join(directory, "runner")
	bindingPath := filepath.Join(directory, "binding.json")
	intentPath := filepath.Join(directory, "intent.json")
	if err := os.WriteFile(runnerPath, []byte("not-an-executable"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, encoded, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(intentPath, intentBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	runner, err := os.Open(runnerPath)
	if err != nil {
		t.Fatal(err)
	}
	bindingFile, err := os.Open(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	intentFile, err := os.Open(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = runInherited(
		runner, bindingFile, intentFile, testEnvironment(binding), &output,
	)
	if err == nil {
		t.Fatal("non-executing runner descriptor unexpectedly accepted")
	}
	if output.Len() != 0 {
		t.Fatal("failure wrote output before descriptor closure")
	}
	if _, statErr := runner.Stat(); statErr == nil {
		t.Fatal("runner descriptor remains open")
	}
	if _, statErr := bindingFile.Stat(); statErr == nil {
		t.Fatal("binding descriptor remains open")
	}
	if _, statErr := intentFile.Stat(); statErr == nil {
		t.Fatal("intent descriptor remains open")
	}
}

func TestRunInheritedRejectsMismatchedIntentWithoutOutput(t *testing.T) {
	binding, encoded := testBinding(t)
	otherBinding, otherBytes := testBindingWithRunnerDigest(
		t, strings.Repeat("b", 64),
	)
	if otherBinding.ObjectDigest == binding.ObjectDigest {
		t.Fatal("test bindings unexpectedly equal")
	}
	_, intentBytes, err := realcycle.NewControllerCycleIntent(otherBytes)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	paths := []string{
		filepath.Join(directory, "runner"),
		filepath.Join(directory, "binding"),
		filepath.Join(directory, "intent"),
	}
	modes := []os.FileMode{0o500, 0o400, 0o400}
	data := [][]byte{[]byte("runner"), encoded, intentBytes}
	files := make([]*os.File, 3)
	for index := range paths {
		if err := os.WriteFile(paths[index], data[index], modes[index]); err != nil {
			t.Fatal(err)
		}
		files[index], err = os.Open(paths[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := runInherited(
		files[0], files[1], files[2], testEnvironment(binding), &output,
	); err == nil {
		t.Fatal("mismatched intent unexpectedly accepted")
	}
	if output.Len() != 0 {
		t.Fatal("mismatched intent wrote output")
	}
	for index, file := range files {
		if _, err := file.Stat(); err == nil {
			t.Fatalf("descriptor %d remains open", index+3)
		}
	}
}

func testBinding(t *testing.T) (realcycle.ControllerCycleBinding, []byte) {
	t.Helper()
	return testBindingWithRunnerDigest(t, strings.Repeat("a", 64))
}

func testBindingWithRunnerDigest(
	t *testing.T,
	runnerDigest string,
) (realcycle.ControllerCycleBinding, []byte) {
	t.Helper()
	digest := strings.Repeat("a", 64)
	admission := realcycle.AdmissionResult{
		CycleID:                 "cycle-1",
		AttemptID:               "attempt-1",
		TopologyID:              "topology-1",
		BindingDigest:           digest,
		Nonce:                   "00112233445566778899aabbccddeeff",
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
	binding, encoded, err := realcycle.NewControllerCycleBinding(
		admission,
		realcycle.ControllerBindingInput{
			SoakRunID:             "soak-run-1",
			Sequence:              1,
			InstanceNonce:         "ffeeddccbbaa99887766554433221100",
			Readiness:             "warm",
			Profile:               "direct-primary",
			RunnerSHA256:          runnerDigest,
			MatrixRelativePath:    "scripts/aicore_phase1_auto_matrix.sh",
			MatrixSHA256:          digest,
			SnapshotSHA256:        digest,
			SnapshotFileCount:     102,
			SourceSHA256:          digest,
			ManifestSHA256:        digest,
			VerifierSHA256:        digest,
			ConfigurationSHA256:   digest,
			ChildEnvironmentNames: slicesClone(exactEnvironmentNames),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding, encoded
}

func testEnvironment(binding realcycle.ControllerCycleBinding) []string {
	return []string{
		"READINESS=" + binding.Readiness,
		"WINN_SOAK_ADAPTER_MODE=preflight",
		"WINN_SOAK_CYCLE_SEQUENCE=" + strconv.FormatUint(binding.Sequence, 10),
		"WINN_SOAK_INSTANCE_NONCE=" + binding.InstanceNonce,
		"WINN_SOAK_MATRIX_RELATIVE_PATH=" + binding.MatrixRelativePath,
		"WINN_SOAK_MATRIX_SHA256=" + binding.MatrixSHA256,
		"WINN_SOAK_PROFILE=" + binding.Profile,
		"WINN_SOAK_RUN_ID=" + binding.SoakRunID,
	}
}

func replaceEnvironment(values []string, name, replacement string) []string {
	result := slicesClone(values)
	prefix := name + "="
	for index, value := range result {
		if strings.HasPrefix(value, prefix) {
			result[index] = prefix + replacement
			break
		}
	}
	return result
}

func slicesClone(values []string) []string {
	return append([]string(nil), values...)
}
