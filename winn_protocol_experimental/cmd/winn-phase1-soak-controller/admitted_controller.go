package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

type admittedSummary struct {
	Schema            string `json:"schema"`
	Mode              string `json:"mode"`
	RunID             string `json:"run_id"`
	Sequence          uint64 `json:"sequence"`
	ReceiptDigest     string `json:"receipt_digest"`
	CheckpointAddress string `json:"checkpoint_content_address"`
	InventoryDigest   string `json:"attempt_inventory_digest"`
	MatrixExecuted    bool   `json:"matrix_executed"`
	HandoffReady      bool   `json:"handoff_ready"`
	Authority         bool   `json:"authority"`
}

var (
	verifyAdmittedInputsOperation = verifyAdmittedInputs
	validateAdmittedAdmission     = realcycle.ValidateAdmission
	runAdmittedLauncherOperation  = runAdmittedLauncher
)

func runAdmittedPreflight(
	ctx context.Context, cfg AdmittedConfig,
) (summary admittedSummary, returnErr error) {
	if err := cfg.Validate(); err != nil {
		return summary, err
	}
	configDigest, err := cfg.digest()
	if err != nil {
		return summary, err
	}
	if err := verifyAdmittedInputsOperation(cfg); err != nil {
		return summary, err
	}
	admissionBeforeLock, err := validateAdmittedAdmission(
		cfg.AdmissionPath, cfg.TrustPath, cfg.TopologyPath,
	)
	if err != nil {
		return summary, fmt.Errorf("validate E2 admission before writes: %w", err)
	}

	lock, err := acquireAdmittedRootLock(cfg.StateRoot, cfg.EvidenceRoot)
	if err != nil {
		return summary, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if err := verifyAdmittedInputsOperation(cfg); err != nil {
		return summary, fmt.Errorf("reverify admitted inputs under lock: %w", err)
	}
	admissionUnderLock, err := validateAdmittedAdmission(
		cfg.AdmissionPath, cfg.TrustPath, cfg.TopologyPath,
	)
	if err != nil {
		return summary, fmt.Errorf("revalidate E2 admission under lock: %w", err)
	}
	if admissionUnderLock != admissionBeforeLock {
		return summary, errors.New("E2 admission changed before attempt creation")
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	fresh, err := classifyAdmittedRoots(lock.state, lock.evidence)
	if err != nil {
		return summary, err
	}

	var currentNonce, predecessorNonce string
	if fresh {
		currentNonce, err = mintAdmittedNonce()
		if err != nil {
			return summary, err
		}
		marker, markerBytes, err := newAdmittedModeMarker(
			cfg, configDigest, currentNonce,
		)
		if err != nil {
			return summary, err
		}
		if marker.ObjectDigest == "" {
			return summary, errors.New("empty admitted mode marker digest")
		}
		if err := publishFreshAdmittedRoots(
			lock.state, lock.evidence, markerBytes, []byte(currentNonce),
		); err != nil {
			return summary, err
		}
	} else {
		if _, err := verifyModeMarkers(
			lock.state, lock.evidence, cfg, configDigest,
		); err != nil {
			return summary, err
		}
	}

	_, inventoryDigest, err := inventoryAdmittedAttempts(lock.state)
	if err != nil {
		return summary, err
	}
	log, err := openAdmittedReceiptLogDirectory(lock.evidence, cfg.RunID)
	if err != nil {
		return summary, err
	}
	defer func() { returnErr = errors.Join(returnErr, log.Close()) }()
	store, err := openAdmittedCheckpointStoreDirectory(lock.state, fresh)
	if err != nil {
		return summary, err
	}
	defer func() { returnErr = errors.Join(returnErr, store.Close()) }()

	if fresh {
		if log.count != 0 {
			return summary, errors.New("fresh admitted root has receipts")
		}
	} else {
		stored, _, err := store.Load()
		if err != nil {
			return summary, fmt.Errorf("load admitted checkpoint: %w", err)
		}
		if err := compareAdmittedCheckpoint(
			stored, log, configDigest, inventoryDigest,
		); err != nil {
			return summary, err
		}
		nonceBytes, err := readExclusiveDirectoryFile(lock.state, admittedNonceFile)
		if err != nil || string(nonceBytes) != stored.InstanceNonce {
			return summary, errors.New("admitted instance nonce/checkpoint mismatch")
		}
		predecessorNonce = stored.InstanceNonce
		currentNonce, err = mintAdmittedNonce()
		if err != nil {
			return summary, err
		}
		if err := atomicWriteAdmittedDirectory(
			lock.state, admittedNonceFile, []byte(currentNonce),
		); err != nil {
			return summary, err
		}
	}
	sequence := log.count + 1
	contractDir, contractName, attemptDir, expectedInput, err := prepareAdmittedAttempt(
		lock.state, cfg, sequence, currentNonce, predecessorNonce, log.count,
	)
	if err != nil {
		return summary, err
	}
	defer func() {
		returnErr = errors.Join(
			returnErr, contractDir.Close(), attemptDir.Close(),
		)
	}()
	resultBytes, err := runAdmittedLauncherOperation(ctx, cfg, admittedLaunchRequest{
		AdmissionPath: cfg.AdmissionPath, TrustPath: cfg.TrustPath,
		TopologyPath: cfg.TopologyPath, ContractDirectory: contractDir.file,
		ContractName:   contractName,
		StateDirectory: attemptDir.file, AdapterPath: cfg.AdapterPath,
		Timeout: cfg.Timeout,
	})
	if err != nil {
		return summary, err
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	bindingBytes, intentBytes, durableResultBytes, result, err :=
		loadAttemptResult(attemptDir)
	if err != nil {
		return summary, err
	}
	if string(resultBytes) != string(durableResultBytes) {
		return summary, errors.New("launcher stdout and durable result differ")
	}
	binding, err := realcycle.ParseControllerCycleBinding(bindingBytes)
	if err != nil {
		return summary, err
	}
	intent, err := realcycle.ParseControllerCycleIntent(intentBytes)
	if err != nil {
		return summary, err
	}
	if err := validateAdmittedArtifactCrossBindings(
		bindingBytes, binding, intent, result, admissionUnderLock, expectedInput,
	); err != nil {
		return summary, err
	}
	attemptIdentity, err := admittedAttemptIdentity(attemptDir)
	if err != nil {
		return summary, err
	}
	receipt := admittedReceipt{
		RunID: cfg.RunID, InstanceNonce: currentNonce,
		PredecessorNonce:        predecessorNonce,
		AdmissionBundleSHA256:   binding.AdmissionBundleSHA256,
		AdmissionBindingDigest:  binding.AdmissionBindingDigest,
		RuntimeCollectionDigest: binding.RuntimeCollectionDigest,
		ReservationObjectDigest: binding.ReservationObjectDigest,
		BindingSHA256:           admittedRawSHA(bindingBytes),
		BindingObjectDigest:     binding.ObjectDigest,
		IntentSHA256:            admittedRawSHA(intentBytes),
		IntentObjectDigest:      intent.ObjectDigest, IntentState: intent.State,
		ResultSHA256: admittedRawSHA(durableResultBytes), Result: result,
		LauncherSHA256: cfg.LauncherSHA256, AdapterSHA256: cfg.AdapterSHA256,
		MatrixSHA256: cfg.MatrixSHA256, SnapshotSHA256: cfg.SnapshotSHA256,
		SourceSHA256: cfg.SourceSHA256, ManifestSHA256: cfg.ManifestSHA256,
		VerifierSHA256:           cfg.VerifierSHA256,
		ConfigurationSHA256:      cfg.ConfigurationSHA256,
		ChildEnvironmentNames:    append([]string(nil), binding.ChildEnvironmentNames...),
		AttemptDirectoryIdentity: attemptIdentity,
		DispatchAuthorized:       false, ExternalTopologyExecuted: false,
		MatrixExecuted: false, ProviderAccess: false, CredentialAccess: false,
		Mutation: "none", Authority: false,
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	receiptDigest, err := log.Append(receipt)
	if err != nil {
		return summary, err
	}
	_, inventoryDigest, err = inventoryAdmittedAttempts(lock.state)
	if err != nil {
		return summary, err
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	checkpoint, err := admittedCheckpointFrom(
		cfg, configDigest, currentNonce, predecessorNonce, inventoryDigest, log,
	)
	if err != nil {
		return summary, err
	}
	checkpointAddress, err := store.Save(checkpoint)
	if err != nil {
		return summary, err
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	return admittedSummary{
		Schema: "winn-phase1-admitted-preflight-summary/v1",
		Mode:   admittedMode, RunID: cfg.RunID, Sequence: sequence,
		ReceiptDigest: receiptDigest, CheckpointAddress: checkpointAddress,
		InventoryDigest: inventoryDigest, MatrixExecuted: false,
		HandoffReady: false, Authority: false,
	}, nil
}

func verifyAdmittedLockedRoots(lock *admittedRootLock) error {
	if lock == nil || lock.state == nil || lock.evidence == nil {
		return errors.New("admitted root capabilities are missing")
	}
	if err := verifyAdmittedDirectoryPath(lock.state); err != nil {
		return fmt.Errorf("state root identity changed: %w", err)
	}
	if err := verifyAdmittedDirectoryPath(lock.evidence); err != nil {
		return fmt.Errorf("evidence root identity changed: %w", err)
	}
	return nil
}

func validateAdmittedArtifactCrossBindings(
	bindingBytes []byte,
	binding realcycle.ControllerCycleBinding,
	intent realcycle.ControllerCycleIntent,
	result admittedAdapterResult,
	admission realcycle.AdmissionResult,
	expected realcycle.ControllerBindingInput,
) error {
	if binding.Sequence != expected.Sequence ||
		binding.CycleID != admission.CycleID ||
		binding.AttemptID != admission.AttemptID ||
		binding.TopologyID != admission.TopologyID ||
		binding.AdmissionBindingDigest != admission.BindingDigest ||
		binding.AdmissionBundleSHA256 != admission.AdmissionBundleSHA256 ||
		binding.RuntimeCollectionDigest != admission.RuntimeCollectionDigest ||
		binding.ReservationObjectDigest != admission.ReservationObjectDigest ||
		binding.AdmissionNonce != admission.Nonce ||
		binding.CounterDomain != admission.CounterDomain ||
		binding.AcceptedCounter != admission.AcceptedCounter ||
		binding.ExpectedTransport != admission.ExpectedTransport ||
		binding.StartNotBefore != admission.StartNotBefore ||
		binding.StartDeadline != admission.StartDeadline ||
		binding.FinishDeadline != admission.FinishDeadline ||
		binding.SoakRunID != expected.SoakRunID ||
		binding.InstanceNonce != expected.InstanceNonce ||
		binding.PredecessorNonce != expected.PredecessorNonce ||
		binding.ResumeCount != expected.ResumeCount ||
		binding.Readiness != expected.Readiness ||
		binding.Profile != expected.Profile ||
		binding.RunnerSHA256 != expected.RunnerSHA256 ||
		binding.MatrixRelativePath != expected.MatrixRelativePath ||
		binding.MatrixSHA256 != expected.MatrixSHA256 ||
		binding.SnapshotSHA256 != expected.SnapshotSHA256 ||
		binding.SnapshotFileCount != expected.SnapshotFileCount ||
		binding.SourceSHA256 != expected.SourceSHA256 ||
		binding.ManifestSHA256 != expected.ManifestSHA256 ||
		binding.VerifierSHA256 != expected.VerifierSHA256 ||
		binding.ConfigurationSHA256 != expected.ConfigurationSHA256 ||
		!slices.Equal(
			binding.ChildEnvironmentNames, expected.ChildEnvironmentNames,
		) ||
		intent.CycleID != binding.CycleID ||
		intent.AttemptID != binding.AttemptID ||
		intent.SoakRunID != binding.SoakRunID ||
		intent.Sequence != binding.Sequence ||
		intent.InstanceNonce != binding.InstanceNonce ||
		intent.ControllerBindingDigest != binding.ObjectDigest ||
		intent.ControllerBindingSHA256 != admittedRawSHA(bindingBytes) ||
		intent.AdmissionBundleSHA256 != binding.AdmissionBundleSHA256 ||
		result.CycleID != binding.CycleID ||
		result.AttemptID != binding.AttemptID ||
		result.TopologyID != binding.TopologyID ||
		result.ControllerBindingDigest != binding.ObjectDigest ||
		result.ControllerIntentDigest != intent.ObjectDigest ||
		result.AdmissionBundleSHA256 != binding.AdmissionBundleSHA256 {
		return errors.New("E3 durable artifacts do not exactly cross-bind")
	}
	return nil
}

func verifyAdmittedInputs(cfg AdmittedConfig) error {
	for label, pair := range map[string][2]string{
		"launcher": {cfg.LauncherPath, cfg.LauncherSHA256},
		"adapter":  {cfg.AdapterPath, cfg.AdapterSHA256},
		"manifest": {cfg.ManifestPath, cfg.ManifestSHA256},
		"verifier": {cfg.VerifierPath, cfg.VerifierSHA256},
	} {
		file, digest, err := openAndDigestPinnedFile(pair[0])
		if err == nil {
			err = file.Close()
		}
		if err != nil || digest != pair[1] {
			return fmt.Errorf("%s exact-file verification failed", label)
		}
	}
	snapshotDigest, count, err := treeDigest(cfg.SnapshotRoot)
	if err != nil || snapshotDigest != cfg.SnapshotSHA256 ||
		// #nosec G115 -- treeDigest rejects counts above 500,000 and never
		// returns a negative count.
		uint64(count) != cfg.SnapshotFileCount {
		return errors.New("snapshot digest or file count mismatch")
	}
	matrixPath := filepath.Join(cfg.SnapshotRoot, cfg.MatrixRelativePath)
	matrix, digest, err := openAndDigestPinnedFile(matrixPath)
	if err == nil {
		err = matrix.Close()
	}
	if err != nil || digest != cfg.MatrixSHA256 {
		return errors.New("matrix exact-file verification failed")
	}
	return nil
}

func mintAdmittedNonce() (string, error) {
	raw := make([]byte, instanceNonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func publishFreshAdmittedRoots(
	state, evidence *secureDirectory, marker, nonce []byte,
) error {
	if err := atomicWriteAdmittedDirectory(state, admittedModeFile, marker); err != nil {
		return err
	}
	if err := atomicWriteAdmittedDirectory(evidence, admittedModeFile, marker); err != nil {
		return err
	}
	if err := atomicWriteAdmittedDirectory(state, admittedNonceFile, nonce); err != nil {
		return err
	}
	for _, name := range []string{admittedAttemptsDirectory, admittedContractsDirectory} {
		if err := state.Mkdir(name, 0o700); err != nil {
			return err
		}
		child, err := openAdmittedPrivateChildDirectory(state, name)
		if err != nil {
			return err
		}
		if err := child.Close(); err != nil {
			return err
		}
	}
	return state.Sync()
}

func prepareAdmittedAttempt(
	state *secureDirectory,
	cfg AdmittedConfig,
	sequence uint64,
	nonce, predecessor string,
	resumeCount uint64,
) (
	*secureDirectory, string, *secureDirectory,
	realcycle.ControllerBindingInput, error,
) {
	name := fmt.Sprintf("%020d", sequence)
	contracts, err := openAdmittedPrivateChildDirectory(
		state, admittedContractsDirectory,
	)
	if err != nil {
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	attempts, err := openAdmittedPrivateChildDirectory(
		state, admittedAttemptsDirectory,
	)
	if err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	defer func() { _ = attempts.Close() }()
	input := realcycle.ControllerBindingInput{
		SoakRunID: cfg.RunID, Sequence: sequence, InstanceNonce: nonce,
		PredecessorNonce: predecessor, ResumeCount: resumeCount,
		Readiness: "warm", Profile: cfg.Profile,
		RunnerSHA256:       cfg.AdapterSHA256,
		MatrixRelativePath: cfg.MatrixRelativePath,
		MatrixSHA256:       cfg.MatrixSHA256, SnapshotSHA256: cfg.SnapshotSHA256,
		SnapshotFileCount: cfg.SnapshotFileCount, SourceSHA256: cfg.SourceSHA256,
		ManifestSHA256: cfg.ManifestSHA256, VerifierSHA256: cfg.VerifierSHA256,
		ConfigurationSHA256: cfg.ConfigurationSHA256,
		ChildEnvironmentNames: []string{
			"READINESS", "WINN_SOAK_ADAPTER_MODE",
			"WINN_SOAK_CYCLE_SEQUENCE", "WINN_SOAK_INSTANCE_NONCE",
			"WINN_SOAK_MATRIX_RELATIVE_PATH", "WINN_SOAK_MATRIX_SHA256",
			"WINN_SOAK_PROFILE", "WINN_SOAK_RUN_ID",
		},
	}
	contract, err := encodeAdmittedContract(input)
	if err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	if _, err := realcycle.ParseControllerBindingInput(contract); err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	file, err := openAdmittedPrivateFile(
		contracts,
		name+".json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	if err := writeAllOperation(file, contract); err != nil {
		_ = file.Close()
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	if err := file.Close(); err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	if err := contracts.Sync(); err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	if err := attempts.Mkdir(name, 0o700); err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	if err := attempts.Sync(); err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	attemptDirectory, err := openAdmittedPrivateChildDirectory(attempts, name)
	if err != nil {
		_ = contracts.Close()
		return nil, "", nil, realcycle.ControllerBindingInput{}, err
	}
	return contracts, name + ".json", attemptDirectory, input, nil
}

func admittedSummaryJSON(summary admittedSummary) ([]byte, error) {
	return json.MarshalIndent(summary, "", "  ")
}
