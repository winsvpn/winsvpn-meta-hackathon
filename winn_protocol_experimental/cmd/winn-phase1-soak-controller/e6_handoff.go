package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

var validateSealedHandoffOperation = realcycle.ValidateSealedHandoff
var replaySealedHandoffOperation = realcycle.VerifySealedHandoffObjects
var publishE6ReceiptOperation = publishE6Receipt

func runAdmittedE6Handoff(
	ctx context.Context, cfg AdmittedConfig,
	planRoot, handoffRoot, receiptRoot string,
) (summary e6Summary, returnErr error) {
	_ = ctx
	if err := cfg.Validate(); err != nil {
		return summary, err
	}
	for label, path := range map[string]string{
		"E5 plan root": planRoot, "E6 handoff input root": handoffRoot,
		"E6 receipt root": receiptRoot,
	} {
		if !filepath.IsAbs(path) {
			return summary, fmt.Errorf("%s must be absolute", label)
		}
	}
	paths := []struct{ label, path string }{
		{"state root", cfg.StateRoot}, {"evidence root", cfg.EvidenceRoot},
		{"snapshot root", cfg.SnapshotRoot}, {"admission", cfg.AdmissionPath},
		{"trust", cfg.TrustPath}, {"topology", cfg.TopologyPath},
		{"E5 plan root", planRoot}, {"E6 handoff input root", handoffRoot},
		{"E6 receipt root", receiptRoot},
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if err := requireDisjoint(
				paths[i].label, paths[i].path, paths[j].label, paths[j].path,
			); err != nil {
				return summary, err
			}
		}
	}
	output, err := openAdmittedPrivateDirectory(receiptRoot)
	if err != nil {
		return summary, fmt.Errorf("open E6 receipt root: %w", err)
	}
	if err := lockExclusiveNonBlocking(output.file); err != nil {
		_ = output.Close()
		return summary, fmt.Errorf("lock E6 receipt root: %w", err)
	}
	defer func() {
		if output != nil && output.file != nil {
			file := output.file
			output.file = nil
			returnErr = errors.Join(returnErr, unlockAndClose(file))
		}
	}()
	if entries, err := output.ReadDir(); err != nil || len(entries) != 0 {
		return summary, errors.New("E6 receipt root must be empty")
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
	if err := verifyAdmittedInputsOperation(cfg); err != nil {
		return summary, err
	}
	admissionBefore, err := validateAdmittedAdmission(
		cfg.AdmissionPath, cfg.TrustPath, cfg.TopologyPath,
	)
	if err != nil {
		return summary, fmt.Errorf("validate E2 admission before E6: %w", err)
	}
	plan, planBytes, err := readE5Plan(planDirectory)
	if err != nil {
		return summary, fmt.Errorf("read E5 plan: %w", err)
	}
	if err := validateE6PlanAdmission(plan, admissionBefore, cfg.RunID); err != nil {
		return summary, err
	}
	planSHA := admittedRawSHA(planBytes)
	expectation := realcycle.HandoffExpectation{
		RunID: plan.RunID, CycleID: plan.CycleID,
		AttemptID: plan.AttemptID, TopologyID: plan.TopologyID,
		PlanSHA256: planSHA, PlanObjectDigest: plan.ObjectDigest,
		TrustSHA256:             admissionBefore.TrustSHA256,
		AdmissionBindingDigest:  plan.AdmissionBindingDigest,
		AdmissionBundleSHA256:   plan.AdmissionBundleSHA256,
		RuntimeCollectionDigest: plan.RuntimeCollectionDigest,
		ReservationObjectDigest: plan.ReservationObjectDigest,
		AdmissionNonce:          plan.AdmissionNonce, CounterDomain: plan.CounterDomain,
		AcceptedCounter:     plan.AcceptedCounter,
		LastObservedCounter: admissionBefore.LastObservedCounter,
		ExpectedTransport:   plan.ExpectedTransport,
		StartNotBefore:      plan.StartNotBefore, StartDeadline: plan.StartDeadline,
		FinishDeadline: plan.FinishDeadline,
	}
	result, err := validateSealedHandoffOperation(
		handoffRoot, cfg.TrustPath, expectation,
	)
	if err != nil {
		return summary, fmt.Errorf("validate sealed handoff: %w", err)
	}
	if err := verifyAdmittedInputsOperation(cfg); err != nil {
		return summary, fmt.Errorf("reverify admitted inputs before E6 publication: %w", err)
	}
	admissionAfter, err := validateAdmittedAdmission(
		cfg.AdmissionPath, cfg.TrustPath, cfg.TopologyPath,
	)
	if err != nil || admissionAfter != admissionBefore {
		return summary, errors.New("E2 admission changed during E6 verification")
	}
	replayedPlan, replayedBytes, err := readE5Plan(planDirectory)
	if err != nil || replayedPlan != plan || string(replayedBytes) != string(planBytes) {
		return summary, errors.New("E5 plan changed during E6 verification")
	}
	receipt, encoded, err := buildE6Receipt(plan, planSHA, result)
	if err != nil {
		return summary, err
	}
	precommitResult, err := verifyE6ReceiptProjection(receipt, cfg.TrustPath)
	if err != nil || precommitResult != result {
		return summary, errors.New("E6 prepublication cryptographic replay mismatch")
	}
	if err := verifyAdmittedDirectoryPath(output); err != nil {
		return summary, err
	}
	if err := publishE6ReceiptOperation(
		output, encoded, receipt, cfg.TrustPath, result,
	); err != nil {
		return summary, err
	}
	replayedResult, err := verifyE6ReceiptProjection(receipt, cfg.TrustPath)
	if err != nil || replayedResult != result {
		return summary, indeterminateE6Publication(
			"postpublication-cryptographic-replay", true, true,
			errors.New("E6 durable receipt cryptographic replay mismatch"),
		)
	}
	return e6Summary{
		Schema: e6SummarySchema, Mode: e6Mode, RunID: plan.RunID,
		CycleID: plan.CycleID, AttemptID: plan.AttemptID,
		PlanSHA256: planSHA, ReceiptSHA256: admittedRawSHA(encoded),
		ReceiptObjectDigest:     receipt.ObjectDigest,
		HandoffCollectionDigest: receipt.HandoffCollectionDigest,
		VerificationState:       receipt.VerificationState,
	}, nil
}

func validateE6PlanAdmission(
	plan e5FourNodePlan, admission realcycle.AdmissionResult, runID string,
) error {
	if plan.RunID != runID || plan.CycleID != admission.CycleID ||
		plan.AttemptID != admission.AttemptID ||
		plan.TopologyID != admission.TopologyID ||
		plan.AdmissionBindingDigest != admission.BindingDigest ||
		plan.AdmissionBundleSHA256 != admission.AdmissionBundleSHA256 ||
		plan.RuntimeCollectionDigest != admission.RuntimeCollectionDigest ||
		plan.ReservationObjectDigest != admission.ReservationObjectDigest ||
		plan.AdmissionNonce != admission.Nonce ||
		plan.CounterDomain != admission.CounterDomain ||
		plan.AcceptedCounter != admission.AcceptedCounter ||
		plan.ExpectedTransport != admission.ExpectedTransport ||
		plan.StartNotBefore != admission.StartNotBefore ||
		plan.StartDeadline != admission.StartDeadline ||
		plan.FinishDeadline != admission.FinishDeadline {
		return errors.New("E5 plan does not bind current E2 admission")
	}
	for index := range plan.Nodes {
		if plan.Nodes[index].RuntimeObjectDigest !=
			admission.RuntimeObjectDigests[index] {
			return errors.New("E5 runtime projection does not bind E2 admission")
		}
	}
	return nil
}

func readE6ReceiptStructure(directory *secureDirectory) (
	e6VerificationReceipt, []byte, error,
) {
	file, err := openAdmittedPrivateFileMode(
		directory, e6ReceiptFile, os.O_RDONLY, 0, 0o400,
	)
	if err != nil {
		return e6VerificationReceipt{}, nil, err
	}
	data, readErr := readBoundedE6File(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return e6VerificationReceipt{}, nil, errors.Join(readErr, closeErr)
	}
	value, err := parseE6ReceiptStructure(data)
	return value, data, err
}

func readAuthenticatedE6Receipt(
	directory *secureDirectory, trustPath string,
) (
	e6VerificationReceipt, realcycle.SealedHandoffResult, []byte, error,
) {
	value, raw, err := readE6ReceiptStructure(directory)
	if err != nil {
		return e6VerificationReceipt{}, realcycle.SealedHandoffResult{},
			nil, err
	}
	authenticated, result, err := parseAuthenticatedE6Receipt(raw, trustPath)
	if err != nil || authenticated != value {
		return e6VerificationReceipt{}, realcycle.SealedHandoffResult{},
			nil, errors.New("E6 durable receipt authentication failed")
	}
	return authenticated, result, raw, nil
}

func readBoundedE6File(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > e6ReceiptMaxBytes {
		return nil, errors.New("E6 receipt file size is invalid")
	}
	data := make([]byte, int(info.Size()))
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := file.ReadAt(extra[:], info.Size()); n != 0 || err == nil {
		return nil, errors.New("E6 receipt read did not terminate at exact EOF")
	}
	return data, nil
}
