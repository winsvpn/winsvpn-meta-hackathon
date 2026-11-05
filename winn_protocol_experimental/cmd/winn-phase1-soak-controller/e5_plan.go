package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

var publishE5PlanOperation = publishE5Plan

func runAdmittedE5Plan(
	ctx context.Context, cfg AdmittedConfig, planRoot string,
) (summary e5PlanSummary, returnErr error) {
	_ = ctx // E5 performs no child launch or network operation.
	if err := cfg.Validate(); err != nil {
		return summary, err
	}
	if !filepath.IsAbs(planRoot) {
		return summary, errors.New("E5 plan root must be absolute")
	}
	for label, path := range map[string]string{
		"state root": cfg.StateRoot, "evidence root": cfg.EvidenceRoot,
		"snapshot root": cfg.SnapshotRoot, "admission": cfg.AdmissionPath,
		"trust": cfg.TrustPath, "topology": cfg.TopologyPath,
	} {
		if err := requireDisjoint(
			"-e5-plan-root", planRoot, label, path,
		); err != nil {
			return summary, err
		}
	}
	planDirectory, err := openAdmittedPrivateDirectory(planRoot)
	if err != nil {
		return summary, fmt.Errorf("open E5 plan root: %w", err)
	}
	if err := lockExclusiveNonBlocking(planDirectory.file); err != nil {
		_ = planDirectory.Close()
		return summary, fmt.Errorf("lock E5 plan root: %w", err)
	}
	defer func() {
		if planDirectory != nil && planDirectory.file != nil {
			file := planDirectory.file
			planDirectory.file = nil
			returnErr = errors.Join(returnErr, unlockAndClose(file))
		}
	}()
	entries, err := planDirectory.ReadDir()
	if err != nil || len(entries) != 0 {
		return summary, errors.New("E5 plan root must be empty")
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
		return summary, fmt.Errorf("validate E2 admission before E4 replay: %w", err)
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
		return summary, errors.New("E2 admission changed before E5 planning")
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	fresh, err := classifyAdmittedRoots(lock.state, lock.evidence)
	if err != nil {
		return summary, err
	}
	if fresh {
		return summary, errors.New("E5 requires an existing accepted E4 preflight")
	}
	if _, err := verifyModeMarkers(
		lock.state, lock.evidence, cfg, configDigest,
	); err != nil {
		return summary, err
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
	store, err := openAdmittedCheckpointStoreDirectory(lock.state, false)
	if err != nil {
		return summary, err
	}
	defer func() { returnErr = errors.Join(returnErr, store.Close()) }()
	checkpoint, checkpointAddress, err := store.Load()
	if err != nil {
		return summary, fmt.Errorf("load E4 checkpoint: %w", err)
	}
	if err := compareAdmittedCheckpoint(
		checkpoint, log, configDigest, inventoryDigest,
	); err != nil {
		return summary, err
	}
	nonce, err := readExclusiveDirectoryFile(lock.state, admittedNonceFile)
	if err != nil || string(nonce) != checkpoint.InstanceNonce {
		return summary, errors.New("E4 nonce/checkpoint mismatch")
	}
	if log.last == nil || log.count == 0 {
		return summary, errors.New("E5 requires at least one E4 receipt")
	}
	if err := validateE5ReceiptAdmission(*log.last, admissionUnderLock); err != nil {
		return summary, err
	}
	plan, encoded, err := buildE5Plan(
		cfg, configDigest, admissionUnderLock, *log.last, log.count,
		checkpointAddress, inventoryDigest,
	)
	if err != nil {
		return summary, err
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	if err := verifyAdmittedDirectoryPath(planDirectory); err != nil {
		return summary, err
	}
	if err := publishE5PlanOperation(planDirectory, encoded, plan); err != nil {
		return summary, err
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return summary, err
	}
	return e5PlanSummary{
		Schema: e5PlanSummaryV1, Mode: e5PlanMode, RunID: cfg.RunID,
		CycleID: plan.CycleID, AttemptID: plan.AttemptID,
		ExercisedNodeCount:         plan.ExercisedNodeCount,
		PlanSHA256:                 admittedRawSHA(encoded),
		PlanObjectDigest:           plan.ObjectDigest,
		E4LastReceiptDigest:        plan.E4LastReceiptDigest,
		E4CheckpointContentAddress: plan.E4CheckpointContentAddress,
	}, nil
}

func validateE5ReceiptAdmission(
	receipt admittedReceipt, admission realcycle.AdmissionResult,
) error {
	if receipt.AdmissionBundleSHA256 != admission.AdmissionBundleSHA256 ||
		receipt.AdmissionBindingDigest != admission.BindingDigest ||
		receipt.RuntimeCollectionDigest != admission.RuntimeCollectionDigest ||
		receipt.ReservationObjectDigest != admission.ReservationObjectDigest ||
		receipt.Result.CycleID != admission.CycleID ||
		receipt.Result.AttemptID != admission.AttemptID ||
		receipt.Result.TopologyID != admission.TopologyID {
		return errors.New("E4 receipt does not bind current E2 admission")
	}
	return nil
}

func buildE5Plan(
	cfg AdmittedConfig,
	configDigest string,
	admission realcycle.AdmissionResult,
	receipt admittedReceipt,
	receiptCount uint64,
	checkpointAddress, inventoryDigest string,
) (e5FourNodePlan, []byte, error) {
	if admission.RuntimeCount != e5PlanNodeCount ||
		admission.ExercisedNodeCount != e5PlanNodeCount {
		return e5FourNodePlan{}, nil, errors.New(
			"E5 requires exactly four exercised runtime nodes",
		)
	}
	var nodes [e5PlanNodeCount]e5PlanNode
	exercised := make(map[string]bool, e5PlanNodeCount)
	for _, nodeID := range admission.ExercisedNodes {
		if nodeID == "" || exercised[nodeID] {
			return e5FourNodePlan{}, nil, errors.New(
				"E5 exercised-node set is invalid",
			)
		}
		exercised[nodeID] = true
	}
	for index := range nodes {
		if admission.Deployments[index].Role != e5RequiredRoles[index] ||
			!exercised[admission.Deployments[index].NodeID] {
			return e5FourNodePlan{}, nil, fmt.Errorf(
				"E5 deployment %d is not the required exercised role", index,
			)
		}
		node, err := e5NodeFrom(
			admission.Deployments[index],
			admission.RuntimeAttestations[index],
			admission.RuntimeObjectDigests[index],
		)
		if err != nil {
			return e5FourNodePlan{}, nil, fmt.Errorf("E5 node %d: %w", index, err)
		}
		nodes[index] = node
	}
	return encodeE5Plan(e5FourNodePlan{
		RunID: cfg.RunID, CycleID: admission.CycleID,
		AttemptID: admission.AttemptID, TopologyID: admission.TopologyID,
		AdmissionBindingDigest:  admission.BindingDigest,
		AdmissionBundleSHA256:   admission.AdmissionBundleSHA256,
		RuntimeCollectionDigest: admission.RuntimeCollectionDigest,
		ReservationObjectDigest: admission.ReservationObjectDigest,
		AdmissionNonce:          admission.Nonce, CounterDomain: admission.CounterDomain,
		AcceptedCounter:            admission.AcceptedCounter,
		ExpectedTransport:          admission.ExpectedTransport,
		StartNotBefore:             admission.StartNotBefore,
		StartDeadline:              admission.StartDeadline,
		FinishDeadline:             admission.FinishDeadline,
		ControllerConfigSHA256:     configDigest,
		E4ReceiptCount:             receiptCount,
		E4LastReceiptDigest:        receipt.ObjectDigest,
		E4CheckpointContentAddress: checkpointAddress,
		E4AttemptInventoryDigest:   inventoryDigest,
		ExercisedNodeCount:         e5PlanNodeCount,
		ExercisedNodeOrder:         admission.ExercisedNodes,
		Nodes:                      nodes,
		RequiredFutureGates:        e5RequiredFutureGates,
		AuthorizationState:         "absent", Mutation: "none",
	})
}

func readE5Plan(directory *secureDirectory) (e5FourNodePlan, []byte, error) {
	file, err := openAdmittedPrivateFileMode(
		directory, e5PlanFile, os.O_RDONLY, 0, 0o400,
	)
	if err != nil {
		return e5FourNodePlan{}, nil, err
	}
	data, readErr := readBoundedE5File(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return e5FourNodePlan{}, nil, errors.Join(readErr, closeErr)
	}
	value, err := parseE5Plan(data)
	return value, data, err
}

func readBoundedE5File(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > e5PlanMaxBytes {
		return nil, errors.New("E5 plan file size is invalid")
	}
	data := make([]byte, int(info.Size()))
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := file.ReadAt(extra[:], info.Size()); n != 0 || err == nil {
		return nil, errors.New("E5 plan read did not terminate at exact EOF")
	}
	return data, nil
}
