//go:build linux && winn_incomplete_e8

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const e8ControllerNonceRootSuffix = ".winn-e8-controller-nonce-root-v1"

var runLocalFourNodeOperation = runLocalFourNode
var publishE8ReceiptOperation = publishE8Receipt
var e8CrashBoundaryOperation = func(string) error { return nil }

func runAdmittedE8Rehearsal(
	ctx context.Context,
	cfg AdmittedConfig,
	planRoot, e6Root, e7Root, grantRoot, outputRoot, workerPath, workerSHA string,
	prepared *e8PreparedWorkerSet,
) (summary e8Summary, returnErr error) {
	if err := cfg.Validate(); err != nil {
		return summary, err
	}
	for label, value := range map[string]string{
		"E5 plan root":    planRoot,
		"E6 receipt root": e6Root,
		"E7 receipt root": e7Root,
		"E8 grant root":   grantRoot,
		"E8 output root":  outputRoot,
		"E8 worker":       workerPath,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return summary, fmt.Errorf("%s must be an absolute canonical path", label)
		}
	}
	if !digestPattern.MatchString(workerSHA) {
		return summary, errors.New("E8 worker SHA-256 is malformed")
	}
	openLocked := func(label, path string) (*secureDirectory, error) {
		directory, err := openAdmittedPrivateDirectory(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", label, err)
		}
		if err := lockExclusiveNonBlocking(directory.file); err != nil {
			_ = directory.Close()
			return nil, fmt.Errorf("lock %s: %w", label, err)
		}
		return directory, nil
	}
	planDirectory, err := openLocked("E5 plan root", planRoot)
	if err != nil {
		return summary, err
	}
	defer func() {
		file := planDirectory.file
		planDirectory.file = nil
		returnErr = errors.Join(returnErr, unlockAndClose(file))
	}()
	e6Directory, err := openLocked("E6 receipt root", e6Root)
	if err != nil {
		return summary, err
	}
	defer func() {
		file := e6Directory.file
		e6Directory.file = nil
		returnErr = errors.Join(returnErr, unlockAndClose(file))
	}()
	e7Directory, err := openLocked("E7 receipt root", e7Root)
	if err != nil {
		return summary, err
	}
	defer func() {
		file := e7Directory.file
		e7Directory.file = nil
		returnErr = errors.Join(returnErr, unlockAndClose(file))
	}()
	output, err := openLocked("E8 output root", outputRoot)
	if err != nil {
		return summary, err
	}
	defer func() {
		file := output.file
		output.file = nil
		returnErr = errors.Join(returnErr, unlockAndClose(file))
	}()

	plan, planBytes, err := readE5Plan(planDirectory)
	if err != nil {
		return summary, err
	}
	e6, _, e6Bytes, err := readAuthenticatedE6Receipt(
		e6Directory,
		cfg.TrustPath,
	)
	if err != nil {
		return summary, err
	}
	planSHA := admittedRawSHA(planBytes)
	if e6.PlanSHA256 != planSHA || e6.PlanObjectDigest != plan.ObjectDigest ||
		e6.RunID != plan.RunID || e6.CycleID != plan.CycleID ||
		e6.AttemptID != plan.AttemptID || e6.TopologyID != plan.TopologyID {
		return summary, errors.New("E8 E5/E6 binding mismatch")
	}
	expected := e7Expectation(e6, admittedRawSHA(e6Bytes))
	e7, _, e7Bytes, err := readAuthenticatedE7Receipt(
		e7Directory,
		expected,
	)
	if err != nil {
		return summary, err
	}
	supervisor, err := verifyE8SupervisorIdentity(e6)
	if err != nil {
		return summary, err
	}
	defer func() { returnErr = errors.Join(returnErr, supervisor.Close()) }()
	grant, err := readAuthenticatedE8Grant(
		grantRoot,
		plan,
		e6,
		admittedRawSHA(e6Bytes),
		e7,
		admittedRawSHA(e7Bytes),
		workerPath,
		workerSHA,
	)
	if err != nil {
		return summary, err
	}
	transaction, err := openE8Transaction(grantRoot, grant, output)
	if err != nil {
		return summary, err
	}
	defer func() { returnErr = errors.Join(returnErr, transaction.Close()) }()
	nodeNonces, err := reserveE8ControllerNonces(
		cfg.StateRoot,
		grant,
		transaction,
	)
	if err != nil {
		return summary, err
	}

	// All downstream inputs, the actual process-image descriptor, the
	// grant/output reservation, and the controller-owned run/node nonces are
	// durable before E3 or any child can mutate state.
	e3, err := recoverOrRunE8E3(ctx, cfg, plan)
	if err != nil {
		return summary, fmt.Errorf("E8 recoverable E3 path: %w", err)
	}
	if e3.Authority || e3.MatrixExecuted || e3.HandoffReady {
		return summary, errors.New("E8 real E3 path returned unsafe authority")
	}
	e3Receipt, err := replayE8E3Lineage(cfg, plan, e3)
	if err != nil {
		return summary, err
	}
	if err := transaction.recordE3(e3.ReceiptDigest); err != nil {
		return summary, err
	}
	if err := e8CrashBoundaryOperation("after-e3-durable"); err != nil {
		return summary, err
	}
	if recovered, ok, err := recoverPublishedE8Receipt(
		output,
		transaction,
		plan,
		e6,
		e7,
		admittedRawSHA(e6Bytes),
		admittedRawSHA(e7Bytes),
		workerSHA,
		supervisor,
	); err != nil {
		return summary, err
	} else if ok {
		return recovered, nil
	}
	nodes, err := transaction.recoverChildrenEvidence(
		plan, e3.ReceiptDigest, workerSHA,
	)
	if errors.Is(err, os.ErrNotExist) {
		if transaction.phase() == "children-complete" {
			return summary, errors.New(
				"E8 transaction lost retained children evidence",
			)
		}
		nodes, err = runLocalFourNodeOperation(
			ctx,
			plan,
			e6,
			e7,
			grant,
			admittedRawSHA(e6Bytes),
			admittedRawSHA(e7Bytes),
			workerPath,
			workerSHA,
			nodeNonces,
			prepared,
		)
		if err == nil {
			err = transaction.persistChildrenEvidence(
				plan, e3.ReceiptDigest, workerSHA, nodes,
			)
		}
	}
	if err != nil {
		return summary, err
	}
	if err := transaction.recordChildren(e3.ReceiptDigest); err != nil {
		return summary, err
	}
	if err := e8CrashBoundaryOperation("after-children-complete"); err != nil {
		return summary, err
	}

	finalPlan, finalPlanBytes, err := readE5Plan(planDirectory)
	if err != nil || finalPlan != plan ||
		string(finalPlanBytes) != string(planBytes) {
		return summary, errors.New("E5 plan changed during E8 rehearsal")
	}
	finalE6, _, finalE6Bytes, err := readAuthenticatedE6Receipt(
		e6Directory,
		cfg.TrustPath,
	)
	if err != nil || finalE6 != e6 || string(finalE6Bytes) != string(e6Bytes) {
		return summary, errors.New("E6 receipt changed during E8 rehearsal")
	}
	finalE7, _, finalE7Bytes, err := readAuthenticatedE7Receipt(
		e7Directory,
		expected,
	)
	if err != nil || finalE7 != e7 ||
		string(finalE7Bytes) != string(e7Bytes) {
		return summary, errors.New("E7 receipt changed during E8 rehearsal")
	}
	finalGrant, err := readAuthenticatedE8Grant(
		grantRoot,
		plan,
		e6,
		admittedRawSHA(e6Bytes),
		e7,
		admittedRawSHA(e7Bytes),
		workerPath,
		workerSHA,
	)
	if err != nil || finalGrant != grant {
		return summary, errors.New("E8 rehearsal grant changed during execution")
	}
	if err := supervisor.Reverify(); err != nil {
		return summary, err
	}
	receipt, encoded, err := encodeE8Receipt(e8Receipt{
		RunID:                           plan.RunID,
		CycleID:                         plan.CycleID,
		AttemptID:                       plan.AttemptID,
		TopologyID:                      plan.TopologyID,
		E3RunID:                         e3Receipt.RunID,
		E3CycleID:                       e3Receipt.Result.CycleID,
		E3AttemptID:                     e3Receipt.Result.AttemptID,
		E3TopologyID:                    e3Receipt.Result.TopologyID,
		E3Sequence:                      e3Receipt.Sequence,
		E3ReceiptDigest:                 e3.ReceiptDigest,
		E3CheckpointAddress:             e3.CheckpointAddress,
		E3InventoryDigest:               e3.InventoryDigest,
		PlanSHA256:                      planSHA,
		PlanObjectDigest:                plan.ObjectDigest,
		E6ReceiptSHA256:                 admittedRawSHA(e6Bytes),
		E6ReceiptObjectDigest:           e6.ObjectDigest,
		E7ReceiptSHA256:                 admittedRawSHA(e7Bytes),
		E7ReceiptObjectDigest:           e7.ObjectDigest,
		RehearsalGrantSHA256:            grant.GrantSHA256,
		RehearsalGrantObjectDigest:      grant.GrantObjectDigest,
		RehearsalAcceptanceSHA256:       grant.AcceptanceSHA256,
		RehearsalAcceptanceObjectDigest: grant.AcceptanceObjectDigest,
		RehearsalGrantCollectionDigest:  grant.CollectionDigest,
		WorkerSHA256:                    workerSHA,
		SupervisorExecutableSHA256:      supervisor.SHA256,
		SupervisorExecutableDevice:      supervisor.Device,
		SupervisorExecutableInode:       supervisor.Inode,
		SupervisorExecutableSize:        supervisor.Size,
		SupervisorExecutableMode:        supervisor.Mode,
		SupervisorIdentityDigest:        supervisor.ObjectDigest,
		Nodes:                           nodes,
		RehearsalCompleted:              true,
		SandboxEnforced:                 true,
		Mutation:                        "local-evidence-only",
	})
	if err != nil {
		return summary, err
	}
	if err := publishE8ReceiptOperation(output, encoded, receipt); err != nil {
		return summary, err
	}
	if err := supervisor.Reverify(); err != nil {
		return summary, fmt.Errorf(
			"retained supervisor identity after publication: %w",
			err,
		)
	}
	if err := e8CrashBoundaryOperation("after-receipt-publication"); err != nil {
		return summary, err
	}
	if err := transaction.commit(
		e3.ReceiptDigest,
		receipt.ObjectDigest,
	); err != nil {
		return summary, err
	}
	return e8Summary{
		Schema:            "winn-local-sealed-four-node-rehearsal-summary/v1",
		Mode:              e8Mode,
		RunID:             plan.RunID,
		CycleID:           plan.CycleID,
		AttemptID:         plan.AttemptID,
		NodeCount:         4,
		ReceiptSHA256:     admittedRawSHA(encoded),
		ReceiptDigest:     receipt.ObjectDigest,
		RehearsalComplete: true,
	}, nil
}

func reserveE8ControllerNonces(
	stateRoot string,
	grant e8GrantResult,
	transaction *e8Transaction,
) (nonces [4]string, returnErr error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return nonces, errors.New("E8 controller state root is not canonical")
	}
	parentPath := filepath.Dir(stateRoot)
	parent, err := openSecureDirectory(parentPath)
	if err != nil {
		return nonces, err
	}
	defer func() { returnErr = errors.Join(returnErr, parent.Close()) }()
	if err := parent.VerifyPath(); err != nil {
		return nonces, err
	}
	rootName := filepath.Base(stateRoot) + e8ControllerNonceRootSuffix
	root, err := openE8DurableDirectory(
		parent, rootName, "controller-root",
	)
	if err != nil {
		return nonces, err
	}
	if err := lockExclusiveNonBlocking(root.file); err != nil {
		_ = root.Close()
		return nonces, err
	}
	defer func() {
		file := root.file
		root.file = nil
		returnErr = errors.Join(returnErr, unlockAndClose(file))
	}()
	binding, err := transaction.nonceBinding()
	if err != nil {
		return nonces, err
	}
	ledger, err := openE8NonceLedger(root, grant)
	if err != nil {
		return nonces, err
	}
	defer func() { returnErr = errors.Join(returnErr, ledger.Close()) }()
	return ledger.ReserveRun(grant.Grant.RehearsalNonce, binding)
}

func replayE8E3Lineage(
	cfg AdmittedConfig,
	plan e5FourNodePlan,
	summary admittedSummary,
) (receipt admittedReceipt, returnErr error) {
	if summary.RunID != plan.RunID {
		return receipt, errors.New("E8 E3 run does not bind E5 plan")
	}
	configDigest, err := cfg.digest()
	if err != nil || configDigest != plan.ControllerConfigSHA256 {
		return receipt, errors.New("E8 E3 controller configuration drift")
	}
	lock, err := acquireAdmittedRootLock(cfg.StateRoot, cfg.EvidenceRoot)
	if err != nil {
		return receipt, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		return receipt, err
	}
	log, err := openAdmittedReceiptLogDirectory(lock.evidence, cfg.RunID)
	if err != nil {
		return receipt, err
	}
	defer func() { returnErr = errors.Join(returnErr, log.Close()) }()
	store, err := openAdmittedCheckpointStoreDirectory(lock.state, false)
	if err != nil {
		return receipt, err
	}
	defer func() { returnErr = errors.Join(returnErr, store.Close()) }()
	checkpoint, checkpointAddress, err := store.Load()
	if err != nil {
		return receipt, err
	}
	_, inventoryDigest, err := inventoryAdmittedAttempts(lock.state)
	if err != nil {
		return receipt, err
	}
	if err := compareAdmittedCheckpoint(
		checkpoint,
		log,
		configDigest,
		inventoryDigest,
	); err != nil {
		return receipt, err
	}
	if log.last == nil || log.count != plan.E4ReceiptCount+1 ||
		log.last.PreviousDigest != plan.E4LastReceiptDigest ||
		log.last.ObjectDigest != summary.ReceiptDigest ||
		log.last.Sequence != plan.E4ReceiptCount+1 ||
		log.last.Result.CycleID != plan.CycleID ||
		log.last.Result.AttemptID != plan.AttemptID ||
		log.last.Result.TopologyID != plan.TopologyID ||
		log.last.AdmissionBindingDigest != plan.AdmissionBindingDigest ||
		log.last.AdmissionBundleSHA256 != plan.AdmissionBundleSHA256 ||
		log.last.RuntimeCollectionDigest != plan.RuntimeCollectionDigest ||
		log.last.ReservationObjectDigest != plan.ReservationObjectDigest ||
		checkpointAddress != summary.CheckpointAddress ||
		inventoryDigest != summary.InventoryDigest {
		return receipt, errors.New("E8 E3/E5 lineage replay mismatch")
	}
	return *log.last, nil
}
