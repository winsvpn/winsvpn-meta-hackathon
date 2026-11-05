package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func TestAdmittedNonLinuxRefusesBeforeAttemptCreation(t *testing.T) {
	old := admittedPlatform
	admittedPlatform = "darwin"
	t.Cleanup(func() { admittedPlatform = old })
	root := filepath.Join(t.TempDir(), "must-not-exist")
	err := (AdmittedConfig{StateRoot: root}).Validate()
	if err == nil || !strings.Contains(err.Error(), "Linux-only") {
		t.Fatalf("non-Linux admitted mode was not refused: %v", err)
	}
	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("platform refusal created state: %v", statErr)
	}
}

func TestAdmittedCLINonLinuxRefusesBeforeAttemptCreation(t *testing.T) {
	old := admittedPlatform
	admittedPlatform = "darwin"
	t.Cleanup(func() { admittedPlatform = old })
	parent := t.TempDir()
	state := filepath.Join(parent, "state")
	evidence := filepath.Join(parent, "evidence")
	stdout, stderr := testOutputFiles(t)
	status := run([]string{
		"-admitted-e3-preflight", "-state-root", state,
		"-evidence-root", evidence,
	}, stdout, stderr, []string{})
	if status != exitPreflightRefusal {
		t.Fatalf("status=%d, want %d", status, exitPreflightRefusal)
	}
	for _, path := range []string{state, evidence} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("non-Linux CLI created %s: %v", path, err)
		}
	}
}

func TestAdmittedInventoryRejectsLegacyMixAndOrphans(t *testing.T) {
	state := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	if err := os.WriteFile(
		filepath.Join(state, "checkpoint.json"), []byte("{}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	stateDirectory := openTestSecureDirectory(t, state)
	evidenceDirectory := openTestSecureDirectory(t, evidence)
	if _, err := classifyAdmittedRoots(stateDirectory, evidenceDirectory); err == nil ||
		!strings.Contains(err.Error(), "legacy, mixed") {
		t.Fatalf("legacy state was accepted: %v", err)
	}

	state = privateTestDirectory(t)
	evidence = privateTestDirectory(t)
	writeTestModeRoots(t, state, evidence)
	for _, name := range []string{
		admittedCheckpointFile, admittedCheckpointKeyFile, admittedNonceFile,
	} {
		if err := os.WriteFile(filepath.Join(state, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(state, admittedAttemptsDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, admittedContractsDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(evidence, admittedReceiptFile), []byte{}, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	attempt := filepath.Join(state, admittedAttemptsDirectory, "00000000000000000001")
	if err := os.Mkdir(attempt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(attempt, "controller-intent.json"), []byte("{}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(state, admittedContractsDirectory,
			"00000000000000000001.json"), []byte("{}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	stateDirectory = openTestSecureDirectory(t, state)
	if _, _, err := inventoryAdmittedAttempts(stateDirectory); err == nil ||
		!strings.Contains(err.Error(), "orphaned") {
		t.Fatalf("orphan intent was accepted: %v", err)
	}
}

func TestLegacyModeRefusesAdmittedMarker(t *testing.T) {
	state := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	if err := os.WriteFile(
		filepath.Join(state, admittedModeFile), []byte("{}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := refuseAdmittedRootsForLegacy(state, evidence); err == nil {
		t.Fatal("legacy mode accepted an admitted state root")
	}
}

func TestAdmittedReceiptAndCheckpointRoundTripAndMismatch(t *testing.T) {
	state := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	writeTestModeRoots(t, state, evidence)
	log, err := openAdmittedReceiptLog(evidence, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	receipt := validAdmittedReceipt()
	if _, err := log.Append(receipt); err != nil {
		t.Fatal(err)
	}
	store, err := openAdmittedCheckpointStore(state, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	checkpoint, err := admittedCheckpointFrom(
		AdmittedConfig{RunID: "run-1"}, strings.Repeat("a", 64),
		strings.Repeat("1", 32), "", strings.Repeat("b", 64), log,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(checkpoint); err != nil {
		t.Fatal(err)
	}
	replayed, _, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := compareAdmittedCheckpoint(
		replayed, log, strings.Repeat("a", 64), strings.Repeat("b", 64),
	); err != nil {
		t.Fatal(err)
	}
	if err := compareAdmittedCheckpoint(
		replayed, log, strings.Repeat("a", 64), strings.Repeat("c", 64),
	); err == nil {
		t.Fatal("checkpoint accepted a different attempt inventory")
	}
}

func TestAdmittedReceiptRejectsAuthorityAndTornLine(t *testing.T) {
	root := privateTestDirectory(t)
	log, err := openAdmittedReceiptLog(root, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	receipt := validAdmittedReceipt()
	receipt.Result.Authority = true
	if _, err := log.Append(receipt); err == nil {
		t.Fatal("authority-bearing result was appended")
	}
	receipt = validAdmittedReceipt()
	receipt.Result.ControllerIntentDigest = strings.Repeat("b", 64)
	if _, err := log.Append(receipt); err == nil {
		t.Fatal("cross-binding mismatch was appended")
	}
	_ = log.Close()
	if err := os.WriteFile(
		filepath.Join(root, admittedReceiptFile), []byte(`{"schema":"torn"}`), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdmittedReceiptLog(root, "run-1"); err == nil {
		t.Fatal("torn receipt line was replayed")
	}
}

func TestAdmittedResultRequiresExactSingleLine(t *testing.T) {
	result := validAdmittedReceipt().Result
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAdmittedResult(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := parseAdmittedResult(data); err == nil {
		t.Fatal("result without newline was accepted")
	}
	result.MatrixExecuted = true
	data, _ = json.Marshal(result)
	if _, err := parseAdmittedResult(append(data, '\n')); err == nil {
		t.Fatal("matrix-executed result was accepted")
	}
}

func TestAdmittedAttemptArtifactsRequireAcceptedE3ImmutableMode(t *testing.T) {
	attempt := privateTestDirectory(t)
	directory, err := openAdmittedPrivateDirectory(attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if _, err := writeMockAdmittedArtifacts(
		directory.file, testAdmissionResult(), testControllerBindingInput(),
	); err != nil {
		t.Fatal(err)
	}
	names := []string{
		"controller-binding.json",
		"controller-intent.json",
		"adapter-preflight-result.json",
	}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(attempt, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Fatalf("%s mode=%04o, want 0400", name, info.Mode().Perm())
		}
	}
	if _, _, _, _, err := loadAttemptResult(directory); err != nil {
		t.Fatalf("accepted E3 artifact modes were rejected: %v", err)
	}
	if err := os.Chmod(filepath.Join(attempt, names[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadAttemptResult(directory); err == nil {
		t.Fatal("mutable E3 artifact mode was accepted")
	}
}

func TestAdmittedCrashBoundariesAreNotRepairable(t *testing.T) {
	for _, names := range [][]string{
		{},
		{"controller-binding.json"},
		{"controller-binding.json", "controller-intent.json"},
		{"controller-binding.json", "controller-intent.json",
			"adapter-preflight-result.json", "unexpected.tmp"},
	} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			state := privateTestDirectory(t)
			attempts := filepath.Join(state, admittedAttemptsDirectory)
			contracts := filepath.Join(state, admittedContractsDirectory)
			if err := os.Mkdir(attempts, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(contracts, 0o700); err != nil {
				t.Fatal(err)
			}
			attempt := filepath.Join(attempts, "00000000000000000001")
			if err := os.Mkdir(attempt, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(contracts, "00000000000000000001.json"),
				[]byte("{}"), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				if err := os.WriteFile(
					filepath.Join(attempt, name), []byte("{}"), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			}
			stateDirectory := openTestSecureDirectory(t, state)
			if _, _, err := inventoryAdmittedAttempts(stateDirectory); err == nil {
				t.Fatalf("partial boundary %v was accepted", names)
			}
		})
	}
}

func TestAdmittedReceiptWithoutCheckpointIsTerminalMismatch(t *testing.T) {
	state := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	log, err := openAdmittedReceiptLog(evidence, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(validAdmittedReceipt()); err != nil {
		t.Fatal(err)
	}
	_ = log.Close()
	store, err := openAdmittedCheckpointStore(state, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, _, err := store.Load(); !errors.Is(err, errNoCheckpoint) {
		t.Fatalf("receipt without checkpoint did not remain unmatched: %v", err)
	}
}

func TestAdmittedReceiptWriteFailureDoesNotAdvanceInMemoryHead(t *testing.T) {
	root := privateTestDirectory(t)
	log, err := openAdmittedReceiptLog(root, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	old := writeAllOperation
	writeAllOperation = func(io.Writer, []byte) error { return io.ErrShortWrite }
	t.Cleanup(func() { writeAllOperation = old })
	if _, err := log.Append(validAdmittedReceipt()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write fault was not propagated: %v", err)
	}
	if log.count != 0 || log.head != admittedGenesisDigest || log.last != nil {
		t.Fatalf("failed append advanced state: count=%d head=%s", log.count, log.head)
	}
}

func TestAdmittedConfigRejectsTraversalAndLongTimeout(t *testing.T) {
	old := admittedPlatform
	admittedPlatform = "linux"
	t.Cleanup(func() { admittedPlatform = old })
	cfg := minimallyShapedAdmittedConfig(t)
	cfg.MatrixRelativePath = "../matrix"
	if err := cfg.Validate(); err == nil {
		t.Fatal("matrix traversal was accepted")
	}
	cfg = minimallyShapedAdmittedConfig(t)
	cfg.Timeout = 5*time.Minute + time.Nanosecond
	if err := cfg.Validate(); err == nil {
		t.Fatal("unbounded admitted timeout was accepted")
	}
}

func TestAdmittedRootLockSerializesSharedEvidenceRoot(t *testing.T) {
	stateOne := privateTestDirectory(t)
	stateTwo := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	first, err := acquireAdmittedRootLock(stateOne, evidence)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if second, err := acquireAdmittedRootLock(stateTwo, evidence); err == nil {
		_ = second.Close()
		t.Fatal("shared evidence root admitted two concurrent state owners")
	}
}

func TestAdmittedRootAcquisitionRejectsPostOpenReplacement(t *testing.T) {
	state := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	old := admittedRootOpenedOperation
	swapped := false
	admittedRootOpenedOperation = func(path string) {
		if path != state || swapped {
			return
		}
		swapped = true
		if err := os.Rename(state, state+".retained"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { admittedRootOpenedOperation = old })
	lock, err := acquireAdmittedRootLock(state, evidence)
	if lock != nil {
		_ = lock.Close()
	}
	if err == nil || !swapped {
		t.Fatalf("post-open root replacement was accepted: swapped=%t err=%v", swapped, err)
	}
}

func TestAdmittedLockedRootRejectsPermissionDrift(t *testing.T) {
	state := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	lock, err := acquireAdmittedRootLock(state, evidence)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyAdmittedLockedRoots(lock); err == nil {
		t.Fatal("mode drift on retained state root was accepted")
	}
}

func TestAdmittedResumeRejectsUnsafeChildModes(t *testing.T) {
	state := privateTestDirectory(t)
	evidence := privateTestDirectory(t)
	writeTestModeRoots(t, state, evidence)
	if err := os.Chmod(filepath.Join(state, admittedModeFile), 0o644); err != nil {
		t.Fatal(err)
	}
	stateDirectory := openTestSecureDirectory(t, state)
	evidenceDirectory := openTestSecureDirectory(t, evidence)
	if _, err := classifyAdmittedRoots(
		stateDirectory, evidenceDirectory,
	); err == nil {
		t.Fatal("world-readable admitted marker was accepted")
	}

	state = privateTestDirectory(t)
	child := filepath.Join(state, admittedAttemptsDirectory)
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDirectory = openTestSecureDirectory(t, state)
	if directory, err := openAdmittedPrivateChildDirectory(
		stateDirectory, admittedAttemptsDirectory,
	); err == nil {
		_ = directory.Close()
		t.Fatal("non-private admitted child directory was accepted")
	}
}

func TestAdmittedControllerRejectsE2ChangeBeforeAnyWrite(t *testing.T) {
	oldPlatform := admittedPlatform
	oldVerify := verifyAdmittedInputsOperation
	oldValidate := validateAdmittedAdmission
	oldLaunch := runAdmittedLauncherOperation
	admittedPlatform = "linux"
	verifyAdmittedInputsOperation = func(AdmittedConfig) error { return nil }
	admission := testAdmissionResult()
	calls := 0
	validateAdmittedAdmission = func(
		string, string, string,
	) (realcycle.AdmissionResult, error) {
		calls++
		value := admission
		if calls == 2 {
			value.AcceptedCounter++
		}
		return value, nil
	}
	runAdmittedLauncherOperation = func(
		context.Context, AdmittedConfig, admittedLaunchRequest,
	) ([]byte, error) {
		t.Fatal("launcher ran after E2 changed")
		return nil, nil
	}
	t.Cleanup(func() {
		admittedPlatform = oldPlatform
		verifyAdmittedInputsOperation = oldVerify
		validateAdmittedAdmission = oldValidate
		runAdmittedLauncherOperation = oldLaunch
	})

	cfg := minimallyShapedAdmittedConfig(t)
	if _, err := runAdmittedPreflight(context.Background(), cfg); err == nil ||
		!strings.Contains(err.Error(), "E2 admission changed") {
		t.Fatalf("changed E2 was not rejected: %v", err)
	}
	for _, root := range []string{cfg.StateRoot, cfg.EvidenceRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("E2 rejection wrote %s: %v", root, entries)
		}
	}
}

func TestAdmittedControllerRejectsContractSwap(t *testing.T) {
	oldPlatform := admittedPlatform
	oldVerify := verifyAdmittedInputsOperation
	oldValidate := validateAdmittedAdmission
	oldLaunch := runAdmittedLauncherOperation
	admittedPlatform = "linux"
	verifyAdmittedInputsOperation = func(AdmittedConfig) error { return nil }
	admission := testAdmissionResult()
	validateAdmittedAdmission = func(
		string, string, string,
	) (realcycle.AdmissionResult, error) {
		return admission, nil
	}
	runAdmittedLauncherOperation = func(
		_ context.Context, _ AdmittedConfig, request admittedLaunchRequest,
	) ([]byte, error) {
		contract, err := readTestContract(request)
		if err != nil {
			return nil, err
		}
		input, err := realcycle.ParseControllerBindingInput(contract)
		if err != nil {
			return nil, err
		}
		input.SoakRunID = "swapped-run"
		return writeMockAdmittedArtifacts(request.StateDirectory, admission, input)
	}
	t.Cleanup(func() {
		admittedPlatform = oldPlatform
		verifyAdmittedInputsOperation = oldVerify
		validateAdmittedAdmission = oldValidate
		runAdmittedLauncherOperation = oldLaunch
	})

	cfg := minimallyShapedAdmittedConfig(t)
	if _, err := runAdmittedPreflight(context.Background(), cfg); err == nil ||
		!strings.Contains(err.Error(), "do not exactly cross-bind") {
		t.Fatalf("swapped contract was not rejected: %v", err)
	}
}

func TestAdmittedControllerRejectsRootReplacementWithoutReceipt(t *testing.T) {
	oldPlatform := admittedPlatform
	oldVerify := verifyAdmittedInputsOperation
	oldValidate := validateAdmittedAdmission
	oldLaunch := runAdmittedLauncherOperation
	admittedPlatform = "linux"
	verifyAdmittedInputsOperation = func(AdmittedConfig) error { return nil }
	admission := testAdmissionResult()
	validateAdmittedAdmission = func(
		string, string, string,
	) (realcycle.AdmissionResult, error) {
		return admission, nil
	}
	var movedEvidence string
	runAdmittedLauncherOperation = func(
		_ context.Context, cfg AdmittedConfig, request admittedLaunchRequest,
	) ([]byte, error) {
		contract, err := readTestContract(request)
		if err != nil {
			return nil, err
		}
		input, err := realcycle.ParseControllerBindingInput(contract)
		if err != nil {
			return nil, err
		}
		movedState := cfg.StateRoot + ".moved"
		movedEvidence = cfg.EvidenceRoot + ".moved"
		if err := os.Rename(cfg.StateRoot, movedState); err != nil {
			return nil, err
		}
		if err := os.Rename(cfg.EvidenceRoot, movedEvidence); err != nil {
			return nil, err
		}
		for _, path := range []string{cfg.StateRoot, cfg.EvidenceRoot} {
			if err := os.Mkdir(path, 0o700); err != nil {
				return nil, err
			}
		}
		return writeMockAdmittedArtifacts(
			request.StateDirectory, admission, input,
		)
	}
	t.Cleanup(func() {
		admittedPlatform = oldPlatform
		verifyAdmittedInputsOperation = oldVerify
		validateAdmittedAdmission = oldValidate
		runAdmittedLauncherOperation = oldLaunch
	})

	cfg := minimallyShapedAdmittedConfig(t)
	if _, err := runAdmittedPreflight(context.Background(), cfg); err == nil ||
		!strings.Contains(err.Error(), "root identity changed") {
		t.Fatalf("root replacement was not rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(movedEvidence, admittedReceiptFile)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(movedEvidence, admittedReceiptFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("root replacement appended a receipt: %q", data)
	}
	for _, root := range []string{cfg.StateRoot, cfg.EvidenceRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("replacement root was mutated: %s %v", root, entries)
		}
	}
}

func TestAdmittedArtifactCrossBindingRejectsEveryIdentityProjection(
	t *testing.T,
) {
	admission := testAdmissionResult()
	digest := strings.Repeat("a", 64)
	input := realcycle.ControllerBindingInput{
		SoakRunID: "run", Sequence: 1,
		InstanceNonce: strings.Repeat("1", 32), Readiness: "warm",
		Profile: "profile", RunnerSHA256: digest,
		MatrixRelativePath: "matrix.sh", MatrixSHA256: digest,
		SnapshotSHA256: digest, SnapshotFileCount: 1,
		SourceSHA256: digest, ManifestSHA256: digest,
		VerifierSHA256: digest, ConfigurationSHA256: digest,
		ChildEnvironmentNames: []string{
			"READINESS", "WINN_SOAK_ADAPTER_MODE",
			"WINN_SOAK_CYCLE_SEQUENCE", "WINN_SOAK_INSTANCE_NONCE",
			"WINN_SOAK_MATRIX_RELATIVE_PATH", "WINN_SOAK_MATRIX_SHA256",
			"WINN_SOAK_PROFILE", "WINN_SOAK_RUN_ID",
		},
	}
	binding, bindingBytes, err := realcycle.NewControllerCycleBinding(
		admission, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	intent, _, err := realcycle.NewControllerCycleIntent(bindingBytes)
	if err != nil {
		t.Fatal(err)
	}
	result := admittedAdapterResult{
		Schema: admittedResultSchema,
		Status: "controller-binding-valid-nonauthorizing",
		Mode:   "preflight", CycleID: binding.CycleID,
		AttemptID: binding.AttemptID, TopologyID: binding.TopologyID,
		ControllerBindingDigest: binding.ObjectDigest,
		ControllerIntentDigest:  intent.ObjectDigest,
		AdmissionBundleSHA256:   binding.AdmissionBundleSHA256,
		Mutation:                "none",
	}
	if err := validateAdmittedArtifactCrossBindings(
		bindingBytes, binding, intent, result, admission, input,
	); err != nil {
		t.Fatalf("valid artifact graph rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*realcycle.ControllerCycleIntent, *admittedAdapterResult)
	}{
		{"intent-cycle", func(i *realcycle.ControllerCycleIntent, _ *admittedAdapterResult) {
			i.CycleID = "other"
		}},
		{"intent-attempt", func(i *realcycle.ControllerCycleIntent, _ *admittedAdapterResult) {
			i.AttemptID = "other"
		}},
		{"intent-run", func(i *realcycle.ControllerCycleIntent, _ *admittedAdapterResult) {
			i.SoakRunID = "other"
		}},
		{"intent-sequence", func(i *realcycle.ControllerCycleIntent, _ *admittedAdapterResult) {
			i.Sequence++
		}},
		{"intent-nonce", func(i *realcycle.ControllerCycleIntent, _ *admittedAdapterResult) {
			i.InstanceNonce = strings.Repeat("2", 32)
		}},
		{"intent-admission", func(i *realcycle.ControllerCycleIntent, _ *admittedAdapterResult) {
			i.AdmissionBundleSHA256 = strings.Repeat("c", 64)
		}},
		{"result-cycle", func(_ *realcycle.ControllerCycleIntent, r *admittedAdapterResult) {
			r.CycleID = "other"
		}},
		{"result-attempt", func(_ *realcycle.ControllerCycleIntent, r *admittedAdapterResult) {
			r.AttemptID = "other"
		}},
		{"result-topology", func(_ *realcycle.ControllerCycleIntent, r *admittedAdapterResult) {
			r.TopologyID = "other"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedIntent := intent
			changedResult := result
			test.mutate(&changedIntent, &changedResult)
			if err := validateAdmittedArtifactCrossBindings(
				bindingBytes, binding, changedIntent, changedResult,
				admission, input,
			); err == nil {
				t.Fatal("divergent projection was accepted")
			}
		})
	}
}

func TestAdmittedControllerBuildsHomogeneousTwoReceiptChain(t *testing.T) {
	oldPlatform := admittedPlatform
	oldVerify := verifyAdmittedInputsOperation
	oldValidate := validateAdmittedAdmission
	oldLaunch := runAdmittedLauncherOperation
	admittedPlatform = "linux"
	verifyAdmittedInputsOperation = func(AdmittedConfig) error { return nil }
	admission := testAdmissionResult()
	validateAdmittedAdmission = func(string, string, string) (realcycle.AdmissionResult, error) {
		return admission, nil
	}
	runAdmittedLauncherOperation = func(
		_ context.Context, _ AdmittedConfig, request admittedLaunchRequest,
	) ([]byte, error) {
		contract, err := readTestContract(request)
		if err != nil {
			return nil, err
		}
		input, err := realcycle.ParseControllerBindingInput(contract)
		if err != nil {
			return nil, err
		}
		return writeMockAdmittedArtifacts(request.StateDirectory, admission, input)
	}
	t.Cleanup(func() {
		admittedPlatform = oldPlatform
		verifyAdmittedInputsOperation = oldVerify
		validateAdmittedAdmission = oldValidate
		runAdmittedLauncherOperation = oldLaunch
	})

	cfg := minimallyShapedAdmittedConfig(t)
	for sequence := uint64(1); sequence <= 2; sequence++ {
		summary, err := runAdmittedPreflight(context.Background(), cfg)
		if err != nil {
			t.Fatalf("sequence %d: %v", sequence, err)
		}
		if summary.Sequence != sequence || summary.MatrixExecuted ||
			summary.HandoffReady || summary.Authority {
			t.Fatalf("unsafe summary at sequence %d: %+v", sequence, summary)
		}
	}
	log, err := openAdmittedReceiptLog(cfg.EvidenceRoot, cfg.RunID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if log.count != 2 || log.last == nil ||
		log.last.PreviousDigest != log.digests[0] ||
		log.last.Result.MatrixExecuted || log.last.Authority {
		t.Fatalf("unexpected admitted chain: count=%d last=%+v", log.count, log.last)
	}
}

func writeMockAdmittedArtifacts(
	stateDirectory *os.File,
	admission realcycle.AdmissionResult,
	input realcycle.ControllerBindingInput,
) ([]byte, error) {
	binding, bindingBytes, err := realcycle.NewControllerCycleBinding(
		admission, input,
	)
	if err != nil {
		return nil, err
	}
	intent, intentBytes, err := realcycle.NewControllerCycleIntent(bindingBytes)
	if err != nil {
		return nil, err
	}
	result := admittedAdapterResult{
		Schema: admittedResultSchema,
		Status: "controller-binding-valid-nonauthorizing",
		Mode:   "preflight", CycleID: binding.CycleID,
		AttemptID: binding.AttemptID, TopologyID: binding.TopologyID,
		ControllerBindingDigest: binding.ObjectDigest,
		ControllerIntentDigest:  intent.ObjectDigest,
		AdmissionBundleSHA256:   binding.AdmissionBundleSHA256,
		Mutation:                "none",
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	resultBytes = append(resultBytes, '\n')
	for name, data := range map[string][]byte{
		"controller-binding.json":       bindingBytes,
		"controller-intent.json":        intentBytes,
		"adapter-preflight-result.json": resultBytes,
	} {
		directory := &secureDirectory{
			path: stateDirectory.Name(), file: stateDirectory,
		}
		file, err := directory.Open(
			name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400,
		)
		if err != nil {
			return nil, err
		}
		if err := writeAllOperation(file, data); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	directory := &secureDirectory{
		path: stateDirectory.Name(), file: stateDirectory,
	}
	if err := directory.Sync(); err != nil {
		return nil, err
	}
	return resultBytes, nil
}

func readTestFile(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	data := make([]byte, info.Size())
	_, err = file.ReadAt(data, 0)
	return data, err
}

func readTestContract(request admittedLaunchRequest) ([]byte, error) {
	directory := &secureDirectory{
		path: request.ContractDirectory.Name(),
		file: request.ContractDirectory,
	}
	file, err := directory.Open(request.ContractName, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readTestFile(file)
}

func validAdmittedReceipt() admittedReceipt {
	digest := strings.Repeat("a", 64)
	value := admittedReceipt{
		RunID: "run-1", InstanceNonce: strings.Repeat("1", 32),
		AdmissionBundleSHA256: digest, AdmissionBindingDigest: digest,
		RuntimeCollectionDigest: digest, ReservationObjectDigest: digest,
		BindingSHA256: digest, BindingObjectDigest: digest,
		IntentSHA256: digest, IntentObjectDigest: digest, IntentState: "pending",
		Result: admittedAdapterResult{
			Schema: admittedResultSchema,
			Status: "controller-binding-valid-nonauthorizing",
			Mode:   "preflight", CycleID: "cycle", AttemptID: "attempt",
			TopologyID: "topology", ControllerBindingDigest: digest,
			ControllerIntentDigest: digest, AdmissionBundleSHA256: digest,
			Mutation: "none",
		},
		LauncherSHA256: digest, AdapterSHA256: digest, MatrixSHA256: digest,
		SnapshotSHA256: digest, SourceSHA256: digest, ManifestSHA256: digest,
		VerifierSHA256: digest, ConfigurationSHA256: digest,
		ChildEnvironmentNames: []string{
			"READINESS", "WINN_SOAK_ADAPTER_MODE",
			"WINN_SOAK_CYCLE_SEQUENCE", "WINN_SOAK_INSTANCE_NONCE",
			"WINN_SOAK_MATRIX_RELATIVE_PATH", "WINN_SOAK_MATRIX_SHA256",
			"WINN_SOAK_PROFILE", "WINN_SOAK_RUN_ID",
		},
		AttemptDirectoryIdentity: "dev=1;ino=2;mode=0700", Mutation: "none",
	}
	resultBytes, _ := json.Marshal(value.Result)
	value.ResultSHA256 = admittedRawSHA(append(resultBytes, '\n'))
	return value
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func openTestSecureDirectory(t *testing.T, path string) *secureDirectory {
	t.Helper()
	directory, err := openSecureDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	return directory
}

func minimallyShapedAdmittedConfig(t *testing.T) AdmittedConfig {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	evidence := filepath.Join(root, "evidence")
	snapshot := filepath.Join(root, "snapshot")
	for _, path := range []string{state, evidence, snapshot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	digest := strings.Repeat("a", 64)
	return AdmittedConfig{
		RunID: "run", StateRoot: state, EvidenceRoot: evidence,
		SnapshotRoot: snapshot, AdmissionPath: filepath.Join(root, "admission"),
		TrustPath:    filepath.Join(root, "trust"),
		TopologyPath: filepath.Join(root, "topology"),
		LauncherPath: filepath.Join(root, "launcher"), LauncherSHA256: digest,
		AdapterPath: filepath.Join(root, "adapter"), AdapterSHA256: digest,
		ManifestPath: filepath.Join(root, "manifest"),
		VerifierPath: filepath.Join(root, "verifier"),
		Profile:      "profile", MatrixRelativePath: "matrix.sh",
		MatrixSHA256: digest, SnapshotSHA256: digest, SnapshotFileCount: 1,
		SourceSHA256: digest, ManifestSHA256: digest, VerifierSHA256: digest,
		ConfigurationSHA256: digest, Timeout: time.Second,
	}
}

func testAdmissionResult() realcycle.AdmissionResult {
	digest := strings.Repeat("b", 64)
	return realcycle.AdmissionResult{
		CycleID: "cycle", AttemptID: "attempt", TopologyID: "topology",
		BindingDigest: digest, Nonce: strings.Repeat("2", 32),
		CounterDomain: "counter", AcceptedCounter: 7,
		ExpectedTransport:     realcycle.TransportH3,
		AdmissionBundleSHA256: digest, RuntimeCollectionDigest: digest,
		ReservationObjectDigest: digest, RuntimeCount: 4,
		ReservedTokenCount: 4,
		StartNotBefore:     "2026-07-28T00:00:00Z",
		StartDeadline:      "2026-07-28T00:01:00Z",
		FinishDeadline:     "2026-07-28T00:02:00Z",
	}
}

func testControllerBindingInput() realcycle.ControllerBindingInput {
	digest := strings.Repeat("a", 64)
	return realcycle.ControllerBindingInput{
		SoakRunID: "run", Sequence: 1,
		InstanceNonce: strings.Repeat("1", 32), Readiness: "warm",
		Profile: "profile", RunnerSHA256: digest,
		MatrixRelativePath: "matrix.sh", MatrixSHA256: digest,
		SnapshotSHA256: digest, SnapshotFileCount: 1,
		SourceSHA256: digest, ManifestSHA256: digest,
		VerifierSHA256: digest, ConfigurationSHA256: digest,
		ChildEnvironmentNames: []string{
			"READINESS", "WINN_SOAK_ADAPTER_MODE",
			"WINN_SOAK_CYCLE_SEQUENCE", "WINN_SOAK_INSTANCE_NONCE",
			"WINN_SOAK_MATRIX_RELATIVE_PATH", "WINN_SOAK_MATRIX_SHA256",
			"WINN_SOAK_PROFILE", "WINN_SOAK_RUN_ID",
		},
	}
}

func writeTestModeRoots(t *testing.T, state, evidence string) {
	t.Helper()
	for _, root := range []string{state, evidence} {
		if err := os.WriteFile(
			filepath.Join(root, admittedModeFile), []byte("{}"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func testOutputFiles(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	stdout, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		_ = stdout.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdout.Close()
		_ = stderr.Close()
	})
	return stdout, stderr
}
