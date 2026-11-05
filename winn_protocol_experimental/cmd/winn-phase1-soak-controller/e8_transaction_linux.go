//go:build linux && winn_incomplete_e8

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const (
	e8TransactionPrefix      = ".local-rehearsal-consumption."
	e8TransactionSchema      = "winn-e8-r4-rehearsal-consumption-event/v1"
	e8TransactionDomain      = "winn-e8-r4-rehearsal-consumption-event-object/v1"
	e8ChildrenEvidenceSchema = "winn-e8-retained-children-evidence/v1"
	e8ChildrenEvidenceDomain = "winn-e8-retained-children-evidence-object/v1"
)

type e8ChildrenEvidenceRecord struct {
	Schema           string            `json:"schema"`
	PlanObjectDigest string            `json:"plan_object_digest"`
	E3ReceiptDigest  string            `json:"e3_receipt_digest"`
	WorkerSHA256     string            `json:"worker_sha256"`
	Nodes            [4]e8NodeEvidence `json:"nodes"`
	ObjectDigest     string            `json:"object_digest"`
}

type e8TransactionEvent struct {
	Schema                string `json:"schema"`
	Sequence              uint64 `json:"sequence"`
	PreviousObjectDigest  string `json:"previous_object_digest"`
	Phase                 string `json:"phase"`
	GrantObjectDigest     string `json:"grant_object_digest"`
	GrantCollectionDigest string `json:"grant_collection_digest"`
	RehearsalNonce        string `json:"rehearsal_nonce"`
	OutputDevice          uint64 `json:"output_device"`
	OutputInode           uint64 `json:"output_inode"`
	E3ReceiptDigest       string `json:"e3_receipt_digest"`
	ReceiptObjectDigest   string `json:"receipt_object_digest"`
	Authority             bool   `json:"authority"`
	ObjectDigest          string `json:"object_digest"`
}

type e8Transaction struct {
	root   *secureDirectory
	grant  e8GrantResult
	output fileIdentity
	last   e8TransactionEvent
}

func validateE8NodesAgainstPlan(
	nodes [4]e8NodeEvidence,
	plan e5FourNodePlan,
	workerSHA string,
) error {
	androidPackageBindingDigest := nodes[0].AndroidPackageBindingDigest
	if androidPackageBindingDigest != "" &&
		!digestPattern.MatchString(androidPackageBindingDigest) {
		return errors.New("E8 Android package binding digest is malformed")
	}
	for index, node := range nodes {
		planned := plan.Nodes[index]
		if node.Contract.Role != planned.Role ||
			node.Contract.NodeID != planned.NodeID ||
			node.Contract.ServiceID != planned.ServiceID ||
			node.Contract.PlanObjectDigest != plan.ObjectDigest ||
			node.Contract.WorkerSHA256 != workerSHA ||
			node.Ready.ProcessID != planned.ProcessID ||
			node.Ready.ProcessStart != planned.ProcessStartTicks ||
			node.Start.ProcessID != planned.ProcessID ||
			node.Start.ProcessStart != planned.ProcessStartTicks ||
			node.Terminal.ProcessID != planned.ProcessID ||
			node.Terminal.ProcessStart != planned.ProcessStartTicks ||
			node.AndroidPackageBindingDigest != androidPackageBindingDigest {
			return fmt.Errorf(
				"E8 node %d evidence does not preserve E5 process identity", index,
			)
		}
	}
	return nil
}

func encodeE8ChildrenEvidence(
	plan e5FourNodePlan,
	e3Digest, workerSHA string,
	nodes [4]e8NodeEvidence,
) (e8ChildrenEvidenceRecord, []byte, error) {
	if err := validateE8NodesAgainstPlan(nodes, plan, workerSHA); err != nil {
		return e8ChildrenEvidenceRecord{}, nil, err
	}
	value := e8ChildrenEvidenceRecord{
		Schema:           e8ChildrenEvidenceSchema,
		PlanObjectDigest: plan.ObjectDigest,
		E3ReceiptDigest:  e3Digest,
		WorkerSHA256:     workerSHA,
		Nodes:            nodes,
	}
	digest, err := admittedDigest(e8ChildrenEvidenceDomain, value)
	if err != nil {
		return e8ChildrenEvidenceRecord{}, nil, err
	}
	value.ObjectDigest = digest
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > e8ReceiptMaxBytes {
		return e8ChildrenEvidenceRecord{}, nil,
			errors.New("E8 retained children evidence exceeds bound")
	}
	return value, encoded, nil
}

func validateE8ChildrenEvidence(
	value e8ChildrenEvidenceRecord,
	plan e5FourNodePlan,
	e3Digest, workerSHA string,
) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(e8ChildrenEvidenceDomain, value)
	value.ObjectDigest = digest
	if err != nil || digest != expected ||
		value.Schema != e8ChildrenEvidenceSchema ||
		value.PlanObjectDigest != plan.ObjectDigest ||
		value.E3ReceiptDigest != e3Digest ||
		value.WorkerSHA256 != workerSHA {
		return errors.New("E8 retained children evidence identity mismatch")
	}
	return validateE8NodesAgainstPlan(value.Nodes, plan, workerSHA)
}

func (t *e8Transaction) persistChildrenEvidence(
	plan e5FourNodePlan,
	e3Digest, workerSHA string,
	nodes [4]e8NodeEvidence,
) error {
	value, encoded, err := encodeE8ChildrenEvidence(
		plan, e3Digest, workerSHA, nodes,
	)
	if err != nil {
		return err
	}
	file, err := openAdmittedPrivateFile(
		t.root, e8ChildrenEvidenceFile,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if errors.Is(err, os.ErrExist) {
		recovered, recoverErr := t.recoverChildrenEvidence(
			plan, e3Digest, workerSHA,
		)
		if recoverErr != nil || recovered != value.Nodes {
			return errors.New("E8 retained children evidence already differs")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err := writeAllOperation(file, encoded); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := t.root.Sync(); err != nil {
		return err
	}
	recovered, err := t.recoverChildrenEvidence(plan, e3Digest, workerSHA)
	if err != nil || recovered != value.Nodes {
		return errors.New("E8 retained children evidence readback differs")
	}
	return nil
}

func (t *e8Transaction) recoverChildrenEvidence(
	plan e5FourNodePlan,
	e3Digest, workerSHA string,
) ([4]e8NodeEvidence, error) {
	var absent [4]e8NodeEvidence
	file, err := openAdmittedPrivateFileMode(
		t.root, e8ChildrenEvidenceFile, os.O_RDONLY, 0, 0o600,
	)
	if err != nil {
		return absent, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, e8ReceiptMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 ||
		len(data) > e8ReceiptMaxBytes {
		return absent, errors.New("E8 retained children evidence is torn")
	}
	var value e8ChildrenEvidenceRecord
	if err := decodeStrictObject(data, &value); err != nil {
		return absent, err
	}
	if err := validateE8ChildrenEvidence(
		value, plan, e3Digest, workerSHA,
	); err != nil {
		return absent, err
	}
	return value.Nodes, nil
}

func openE8Transaction(
	rootPath string, grant e8GrantResult, output *secureDirectory,
) (*e8Transaction, error) {
	root, err := openAdmittedPrivateDirectory(rootPath)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*e8Transaction, error) {
		_ = root.Close()
		return nil, cause
	}
	if err := lockExclusiveNonBlocking(root.file); err != nil {
		return fail(fmt.Errorf("lock E8 one-shot grant root: %w", err))
	}
	outputInfo, err := output.file.Stat()
	if err != nil {
		return fail(err)
	}
	outputIdentity, err := identityFromInfo(outputInfo)
	if err != nil {
		return fail(err)
	}
	transaction := &e8Transaction{
		root: root, grant: grant, output: outputIdentity,
	}
	if err := transaction.replay(); err != nil {
		_ = transaction.Close()
		return nil, err
	}
	if transaction.last.Sequence == 0 {
		if err := transaction.append("reserved", "", ""); err != nil {
			_ = transaction.Close()
			return nil, err
		}
	}
	return transaction, nil
}

func (t *e8Transaction) replay() error {
	previous := admittedGenesisDigest
	lastPhase := ""
	for sequence := uint64(1); sequence <= 4; sequence++ {
		name := fmt.Sprintf("%s%02d.json", e8TransactionPrefix, sequence)
		file, err := openAdmittedPrivateFileMode(t.root, name, os.O_RDWR, 0, 0o600)
		if errors.Is(err, os.ErrNotExist) {
			for later := sequence + 1; later <= 4; later++ {
				laterName := fmt.Sprintf("%s%02d.json", e8TransactionPrefix, later)
				if probe, probeErr := openAdmittedPrivateFile(t.root, laterName, os.O_RDONLY, 0); probeErr == nil {
					_ = probe.Close()
					return errors.New("E8 transaction has a noncontiguous immutable record")
				} else if !errors.Is(probeErr, os.ErrNotExist) {
					return probeErr
				}
			}
			break
		}
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		if readErr != nil || len(data) == 0 || len(data) > 64<<10 {
			_ = file.Close()
			if err := t.root.Remove(name); err != nil {
				return errors.Join(readErr, err)
			}
			return t.root.Sync()
		}
		var event e8TransactionEvent
		eventErr := decodeStrictObject(data, &event)
		if eventErr == nil {
			eventErr = validateE8TransactionEvent(
				event, t.grant, t.output, sequence, previous, lastPhase,
			)
		}
		if eventErr != nil {
			_ = file.Close()
			if decodeStrictObject(data, &event) == nil {
				return eventErr
			}
			if err := t.root.Remove(name); err != nil {
				return errors.Join(eventErr, err)
			}
			if err := t.root.Sync(); err != nil {
				return err
			}
			break
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		previous = event.ObjectDigest
		lastPhase = event.Phase
		t.last = event
	}
	return t.root.Sync()
}

func (t *e8Transaction) append(
	phase, e3Digest, receiptDigest string,
) error {
	event := e8TransactionEvent{
		Schema: e8TransactionSchema, Sequence: t.last.Sequence + 1,
		PreviousObjectDigest: admittedGenesisDigest,
		Phase:                phase, GrantObjectDigest: t.grant.GrantObjectDigest,
		GrantCollectionDigest: t.grant.CollectionDigest,
		RehearsalNonce:        t.grant.Grant.RehearsalNonce,
		OutputDevice:          t.output.device, OutputInode: t.output.inode,
		E3ReceiptDigest: e3Digest, ReceiptObjectDigest: receiptDigest,
		Authority: false,
	}
	if t.last.Sequence > 0 {
		event.PreviousObjectDigest = t.last.ObjectDigest
	}
	event.ObjectDigest = ""
	digest, err := admittedDigest(e8TransactionDomain, event)
	if err != nil {
		return err
	}
	event.ObjectDigest = digest
	if err := validateE8TransactionEvent(
		event, t.grant, t.output, event.Sequence,
		event.PreviousObjectDigest, t.last.Phase,
	); err != nil {
		return err
	}
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) > 64<<10 {
		return errors.New("E8 transaction event exceeds bound")
	}
	name := fmt.Sprintf("%s%02d.json", e8TransactionPrefix, event.Sequence)
	file, err := openAdmittedPrivateFile(
		t.root, name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		return err
	}
	if err := writeAllOperation(file, encoded); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := t.root.Sync(); err != nil {
		return err
	}
	readback, err := readExclusiveDirectoryFileMode(t.root, name, 0o600)
	if err != nil || string(readback) != string(encoded) {
		return errors.New("E8 immutable transaction record readback failed")
	}
	t.last = event
	return nil
}

func validateE8TransactionEvent(
	event e8TransactionEvent,
	grant e8GrantResult,
	output fileIdentity,
	sequence uint64,
	previous, priorPhase string,
) error {
	digest := event.ObjectDigest
	event.ObjectDigest = ""
	expected, err := admittedDigest(e8TransactionDomain, event)
	event.ObjectDigest = digest
	if err != nil || digest != expected ||
		event.Schema != e8TransactionSchema || event.Sequence != sequence ||
		event.PreviousObjectDigest != previous ||
		event.GrantObjectDigest != grant.GrantObjectDigest ||
		event.GrantCollectionDigest != grant.CollectionDigest ||
		event.RehearsalNonce != grant.Grant.RehearsalNonce ||
		event.OutputDevice != output.device || event.OutputInode != output.inode ||
		event.Authority {
		return errors.New("E8 transaction event binding is invalid")
	}
	expectedPrior := map[string]string{
		"reserved": "", "e3-durable": "reserved",
		"children-complete": "e3-durable",
		"receipt-committed": "children-complete",
	}
	requiredPrior, knownPhase := expectedPrior[event.Phase]
	if !knownPhase || requiredPrior != priorPhase {
		return errors.New("E8 transaction phase order is invalid")
	}
	if event.Phase == "reserved" &&
		(event.E3ReceiptDigest != "" || event.ReceiptObjectDigest != "") {
		return errors.New("E8 reservation predicts future evidence")
	}
	if event.Phase != "reserved" &&
		!digestPattern.MatchString(event.E3ReceiptDigest) {
		return errors.New("E8 transaction lacks durable E3 digest")
	}
	if event.Phase == "receipt-committed" {
		if !digestPattern.MatchString(event.ReceiptObjectDigest) {
			return errors.New("E8 transaction lacks committed receipt digest")
		}
	} else if event.ReceiptObjectDigest != "" {
		return errors.New("E8 transaction predicts a receipt digest")
	}
	return nil
}

func (t *e8Transaction) phase() string { return t.last.Phase }

func (t *e8Transaction) nonceBinding() (e8NonceLedgerBinding, error) {
	if t == nil || t.root == nil || t.root.file == nil {
		return e8NonceLedgerBinding{}, errors.New(
			"E8 transaction grant root is unavailable",
		)
	}
	info, err := t.root.file.Stat()
	if err != nil {
		return e8NonceLedgerBinding{}, err
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return e8NonceLedgerBinding{}, err
	}
	if identity.device == 0 || identity.inode == 0 ||
		t.output.device == 0 || t.output.inode == 0 {
		return e8NonceLedgerBinding{}, errors.New(
			"E8 transaction nonce binding is incomplete",
		)
	}
	return e8NonceLedgerBinding{
		GrantRootDevice: identity.device,
		GrantRootInode:  identity.inode,
		OutputDevice:    t.output.device,
		OutputInode:     t.output.inode,
	}, nil
}

func (t *e8Transaction) recordE3(digest string) error {
	if t.last.Phase == "e3-durable" || t.last.Phase == "children-complete" ||
		t.last.Phase == "receipt-committed" {
		if t.last.E3ReceiptDigest != digest {
			return errors.New("E8 resumed E3 digest changed")
		}
		return nil
	}
	return t.append("e3-durable", digest, "")
}

func (t *e8Transaction) recordChildren(e3Digest string) error {
	if t.last.Phase == "children-complete" || t.last.Phase == "receipt-committed" {
		return nil
	}
	return t.append("children-complete", e3Digest, "")
}

func (t *e8Transaction) commit(e3Digest, receiptDigest string) error {
	if t.last.Phase == "receipt-committed" {
		if t.last.ReceiptObjectDigest != receiptDigest {
			return errors.New("E8 committed receipt digest changed")
		}
		return nil
	}
	return t.append("receipt-committed", e3Digest, receiptDigest)
}

func (t *e8Transaction) Close() error {
	if t == nil {
		return nil
	}
	var result error
	if t.root != nil {
		file := t.root.file
		t.root.file = nil
		result = errors.Join(result, unlockAndClose(file))
		t.root = nil
	}
	return result
}

func recoverOrRunE8E3(
	ctx context.Context, cfg AdmittedConfig, plan e5FourNodePlan,
) (admittedSummary, error) {
	lock, err := acquireAdmittedRootLock(cfg.StateRoot, cfg.EvidenceRoot)
	if err != nil {
		return admittedSummary{}, err
	}
	if err := verifyAdmittedLockedRoots(lock); err != nil {
		_ = lock.Close()
		return admittedSummary{}, err
	}
	if err := repairE8PartialAttempt(lock, cfg, plan); err != nil {
		_ = lock.Close()
		return admittedSummary{}, err
	}
	configDigest, err := cfg.digest()
	if err != nil {
		_ = lock.Close()
		return admittedSummary{}, err
	}
	log, err := openAdmittedReceiptLogDirectory(lock.evidence, cfg.RunID)
	if err != nil {
		_ = lock.Close()
		return admittedSummary{}, err
	}
	inventoryRows, inventoryDigest, err := inventoryAdmittedAttempts(lock.state)
	if err != nil {
		_ = log.Close()
		_ = lock.Close()
		return admittedSummary{}, err
	}
	if log.count == plan.E4ReceiptCount {
		_ = log.Close()
		_ = lock.Close()
		return runAdmittedPreflight(ctx, cfg)
	}
	if log.count != plan.E4ReceiptCount+1 || log.last == nil ||
		log.last.PreviousDigest != plan.E4LastReceiptDigest ||
		log.last.RunID != plan.RunID ||
		log.last.Result.CycleID != plan.CycleID ||
		log.last.Result.AttemptID != plan.AttemptID ||
		log.last.Result.TopologyID != plan.TopologyID ||
		log.last.AdmissionBindingDigest != plan.AdmissionBindingDigest ||
		log.last.AdmissionBundleSHA256 != plan.AdmissionBundleSHA256 ||
		log.last.RuntimeCollectionDigest != plan.RuntimeCollectionDigest ||
		log.last.ReservationObjectDigest != plan.ReservationObjectDigest {
		_ = log.Close()
		_ = lock.Close()
		return admittedSummary{}, errors.New(
			"E8 cannot recover a foreign or incomplete E3 transition",
		)
	}
	if log.count > uint64(len(inventoryRows)) ||
		// #nosec G115 -- len is nonnegative and representable by uint64.
		uint64(len(inventoryRows)) != 4*log.count {
		_ = log.Close()
		_ = lock.Close()
		return admittedSummary{}, errors.New("E8 E3 inventory is not complete")
	}
	store, err := openAdmittedCheckpointStoreDirectory(lock.state, false)
	if err != nil {
		_ = log.Close()
		_ = lock.Close()
		return admittedSummary{}, err
	}
	checkpoint, checkpointAddress, loadErr := store.Load()
	if loadErr != nil || compareAdmittedCheckpoint(
		checkpoint, log, configDigest, inventoryDigest,
	) != nil {
		checkpoint, err = admittedCheckpointFrom(
			cfg, configDigest, log.last.InstanceNonce,
			log.last.PredecessorNonce, inventoryDigest, log,
		)
		if err == nil {
			checkpointAddress, err = store.Save(checkpoint)
		}
		if err != nil {
			_ = store.Close()
			_ = log.Close()
			_ = lock.Close()
			return admittedSummary{}, fmt.Errorf(
				"recover E8 E3 checkpoint: %w", err,
			)
		}
	}
	summary := admittedSummary{
		Schema: "winn-phase1-admitted-preflight-summary/v1",
		Mode:   admittedMode, RunID: cfg.RunID, Sequence: log.last.Sequence,
		ReceiptDigest:     log.last.ObjectDigest,
		CheckpointAddress: checkpointAddress,
		InventoryDigest:   inventoryDigest,
		MatrixExecuted:    false, HandoffReady: false, Authority: false,
	}
	closeErr := errors.Join(store.Close(), log.Close(), lock.Close())
	if closeErr != nil {
		return admittedSummary{}, closeErr
	}
	return summary, nil
}

// repairE8PartialAttempt rolls back only the single next E3 attempt when no
// complete receipt exists. Every removed byte is reached through retained root
// descriptors, has a closed name/type census, and is followed by parent fsync.
func repairE8PartialAttempt(
	lock *admittedRootLock, cfg AdmittedConfig, plan e5FourNodePlan,
) error {
	file, err := openAdmittedPrivateFile(
		lock.evidence, admittedReceiptFile, os.O_RDWR, 0,
	)
	if err != nil {
		return err
	}
	reader := bufio.NewReaderSize(file, admittedMaximumObjectBytes)
	var count, offset uint64
	previous := admittedGenesisDigest
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		if len(line) > admittedMaximumObjectBytes || line[len(line)-1] != '\n' {
			break
		}
		var receipt admittedReceipt
		raw := line[:len(line)-1]
		if err := decodeStrictObject(raw, &receipt); err != nil {
			_ = file.Close()
			return errors.New("E8 complete receipt suffix is not canonical")
		}
		if err := validateAdmittedReceipt(
			receipt, cfg.RunID, count+1, previous,
		); err != nil {
			_ = file.Close()
			return errors.New("E8 complete receipt suffix is unauthenticated")
		}
		count++
		offset += uint64(len(line))
		previous = receipt.ObjectDigest
		if count > plan.E4ReceiptCount+1 {
			_ = file.Close()
			return errors.New("E8 E3 receipt log advanced beyond reserved attempt")
		}
		if readErr != nil {
			break
		}
	}
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return statErr
	}
	if count < plan.E4ReceiptCount {
		_ = file.Close()
		return errors.New("E8 cannot repair receipt bytes before E4 boundary")
	}
	expectedSize, err := boundedUint64ToInt64(offset, "E8 receipt log offset")
	if err != nil || info.Size() < 0 {
		_ = file.Close()
		return errors.New("E8 receipt log size is outside the supported range")
	}
	if info.Size() != expectedSize {
		if err := file.Truncate(expectedSize); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := lock.evidence.Sync(); err != nil {
		return err
	}
	if count == plan.E4ReceiptCount+1 {
		return nil
	}
	sequence := fmt.Sprintf("%020d", plan.E4ReceiptCount+1)
	attempts, err := openAdmittedPrivateChildDirectory(
		lock.state, admittedAttemptsDirectory,
	)
	if err != nil {
		return err
	}
	contracts, err := openAdmittedPrivateChildDirectory(
		lock.state, admittedContractsDirectory,
	)
	if err != nil {
		_ = attempts.Close()
		return err
	}
	attempt, err := openAdmittedPrivateChildDirectory(attempts, sequence)
	if err == nil {
		entries, readErr := attempt.ReadDir()
		if readErr != nil || len(entries) > 3 {
			_ = attempt.Close()
			_ = attempts.Close()
			_ = contracts.Close()
			return errors.New("E8 partial attempt census is ambiguous")
		}
		allowed := map[string]bool{
			"controller-binding.json": true, "controller-intent.json": true,
			"adapter-preflight-result.json": true,
		}
		for _, entry := range entries {
			if entry.IsDir() || !allowed[entry.Name()] {
				_ = attempt.Close()
				_ = attempts.Close()
				_ = contracts.Close()
				return errors.New("E8 partial attempt contains unknown bytes")
			}
			if err := attempt.Remove(entry.Name()); err != nil {
				return err
			}
		}
		if err := attempt.Sync(); err != nil {
			return err
		}
		if err := attempt.Close(); err != nil {
			return err
		}
		if err := unix.Unlinkat(
			// #nosec G115 -- secureDirectory owns a live Linux descriptor.
			int(attempts.file.Fd()), sequence, unix.AT_REMOVEDIR,
		); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := attempts.Sync(); err != nil {
		return err
	}
	if err := contracts.Remove(sequence + ".json"); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := contracts.Sync(); err != nil {
		return err
	}
	_ = attempts.Close()
	_ = contracts.Close()
	store, err := openAdmittedCheckpointStoreDirectory(lock.state, false)
	if err != nil {
		return err
	}
	checkpoint, _, err := store.Load()
	closeErr := store.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return atomicWriteAdmittedDirectory(
		lock.state, admittedNonceFile, []byte(checkpoint.InstanceNonce),
	)
}

func recoverPublishedE8Receipt(
	output *secureDirectory,
	transaction *e8Transaction,
	plan e5FourNodePlan,
	e6 e6VerificationReceipt,
	e7 e7VerificationReceipt,
	e6SHA, e7SHA, workerSHA string,
	supervisor *e8SupervisorIdentity,
) (e8Summary, bool, error) {
	if transaction.phase() != "children-complete" &&
		transaction.phase() != "receipt-committed" {
		return e8Summary{}, false, nil
	}
	if _, err := output.file.Seek(0, io.SeekStart); err != nil {
		return e8Summary{}, false, err
	}
	entries, err := output.ReadDir()
	if err != nil {
		return e8Summary{}, false, err
	}
	if len(entries) == 0 {
		return e8Summary{}, false, nil
	}
	if len(entries) != 1 || entries[0].IsDir() {
		return e8Summary{}, false, errors.New(
			"E8 recovery output census is invalid",
		)
	}
	name := entries[0].Name()
	if name != e8ReceiptFile && name != "."+e8ReceiptFile+".pending" {
		return e8Summary{}, false, errors.New(
			"E8 recovery output contains an unknown artifact",
		)
	}
	file, err := openAdmittedPrivateFileMode(output, name, os.O_RDONLY, 0, 0o400)
	if err != nil {
		return e8Summary{}, false, err
	}
	data, err := io.ReadAll(io.LimitReader(file, e8ReceiptMaxBytes+1))
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil || len(data) == 0 || len(data) > e8ReceiptMaxBytes {
		return e8Summary{}, false, errors.New(
			"E8 recovery receipt is unreadable",
		)
	}
	var receipt e8Receipt
	if err := decodeStrictObject(data, &receipt); err != nil ||
		validateE8Receipt(receipt) != nil ||
		validateE8NodesAgainstPlan(receipt.Nodes, plan, workerSHA) != nil ||
		receipt.RunID != plan.RunID || receipt.CycleID != plan.CycleID ||
		receipt.AttemptID != plan.AttemptID ||
		receipt.TopologyID != plan.TopologyID ||
		receipt.E3ReceiptDigest != transaction.last.E3ReceiptDigest ||
		receipt.PlanObjectDigest != plan.ObjectDigest ||
		receipt.E6ReceiptSHA256 != e6SHA ||
		receipt.E6ReceiptObjectDigest != e6.ObjectDigest ||
		receipt.E7ReceiptSHA256 != e7SHA ||
		receipt.E7ReceiptObjectDigest != e7.ObjectDigest ||
		receipt.RehearsalGrantObjectDigest !=
			transaction.grant.GrantObjectDigest ||
		receipt.RehearsalGrantCollectionDigest !=
			transaction.grant.CollectionDigest ||
		receipt.WorkerSHA256 != workerSHA ||
		receipt.SupervisorIdentityDigest != supervisor.ObjectDigest {
		return e8Summary{}, false, errors.New(
			"E8 recovery receipt does not bind the reserved transaction",
		)
	}
	if transaction.phase() == "receipt-committed" &&
		receipt.ObjectDigest != transaction.last.ReceiptObjectDigest {
		return e8Summary{}, false, errors.New(
			"E8 committed transaction receipt digest changed",
		)
	}
	if name != e8ReceiptFile {
		if err := publishE8Receipt(output, data, receipt); err != nil {
			return e8Summary{}, false, err
		}
	}
	if err := transaction.commit(
		receipt.E3ReceiptDigest, receipt.ObjectDigest,
	); err != nil {
		return e8Summary{}, false, err
	}
	return e8Summary{
		Schema: "winn-local-sealed-four-node-rehearsal-summary/v1",
		Mode:   e8Mode, RunID: receipt.RunID, CycleID: receipt.CycleID,
		AttemptID: receipt.AttemptID, NodeCount: 4,
		ReceiptSHA256: admittedRawSHA(data),
		ReceiptDigest: receipt.ObjectDigest, RehearsalComplete: true,
	}, true, nil
}
