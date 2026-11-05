package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

var validateExecutionAuthorizationOperation = realcycle.ValidateExecutionAuthorization
var publishE7ReceiptOperation = publishE7Receipt
var readE7SourceE6ReceiptOperation = readAuthenticatedE6Receipt

func runAdmittedE7Authorization(
	ctx context.Context,
	cfg AdmittedConfig,
	e6ReceiptRoot, authorizationRoot, receiptRoot string,
) (summary e7Summary, returnErr error) {
	_ = ctx
	if err := cfg.Validate(); err != nil {
		return summary, err
	}
	for label, path := range map[string]string{
		"E6 receipt root":             e6ReceiptRoot,
		"E7 authorization input root": authorizationRoot,
		"E7 receipt root":             receiptRoot,
	} {
		if !filepath.IsAbs(path) {
			return summary, fmt.Errorf("%s must be absolute", label)
		}
	}
	paths := []struct{ label, path string }{
		{"state root", cfg.StateRoot}, {"evidence root", cfg.EvidenceRoot},
		{"snapshot root", cfg.SnapshotRoot}, {"admission", cfg.AdmissionPath},
		{"trust", cfg.TrustPath}, {"topology", cfg.TopologyPath},
		{"E6 receipt root", e6ReceiptRoot},
		{"E7 authorization input root", authorizationRoot},
		{"E7 receipt root", receiptRoot},
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if err := requireDisjoint(
				paths[i].label, paths[i].path,
				paths[j].label, paths[j].path,
			); err != nil {
				return summary, err
			}
		}
	}
	e6Directory, err := openAdmittedPrivateDirectory(e6ReceiptRoot)
	if err != nil {
		return summary, fmt.Errorf("open E6 receipt root: %w", err)
	}
	if err := lockExclusiveNonBlocking(e6Directory.file); err != nil {
		_ = e6Directory.Close()
		return summary, fmt.Errorf("lock E6 receipt root: %w", err)
	}
	defer func() {
		if e6Directory != nil && e6Directory.file != nil {
			file := e6Directory.file
			e6Directory.file = nil
			returnErr = errors.Join(returnErr, unlockAndClose(file))
		}
	}()
	e6, _, e6Bytes, err := readE7SourceE6ReceiptOperation(
		e6Directory, cfg.TrustPath,
	)
	if err != nil {
		return summary, fmt.Errorf("authenticate E6 receipt: %w", err)
	}
	if e6.RunID != cfg.RunID {
		return summary, errors.New("E6 receipt run_id does not match E7 run")
	}
	e6SHA := admittedRawSHA(e6Bytes)
	expected := e7Expectation(e6, e6SHA)
	output, err := openAdmittedPrivateDirectory(receiptRoot)
	if err != nil {
		return summary, fmt.Errorf("open E7 receipt root: %w", err)
	}
	if err := lockExclusiveNonBlocking(output.file); err != nil {
		_ = output.Close()
		return summary, fmt.Errorf("lock E7 receipt root: %w", err)
	}
	defer func() {
		if output != nil && output.file != nil {
			file := output.file
			output.file = nil
			returnErr = errors.Join(returnErr, unlockAndClose(file))
		}
	}()
	if entries, err := output.ReadDir(); err != nil || len(entries) != 0 {
		return summary, errors.New("E7 receipt root must be empty")
	}
	result, err := validateExecutionAuthorizationOperation(
		authorizationRoot, expected,
	)
	if err != nil {
		return summary, fmt.Errorf("validate E7 authorization input: %w", err)
	}
	replayedE6, _, replayedE6Bytes, err := readE7SourceE6ReceiptOperation(
		e6Directory, cfg.TrustPath,
	)
	if err != nil || replayedE6 != e6 ||
		string(replayedE6Bytes) != string(e6Bytes) {
		return summary, errors.New("E6 receipt changed during E7 verification")
	}
	receipt, encoded, err := buildE7Receipt(
		e6, e6SHA, result.Decision, result.Acceptance, result,
	)
	if err != nil {
		return summary, err
	}
	replayed, err := verifyE7ReceiptProjection(receipt, expected)
	if err != nil || replayed != result {
		return summary, errors.New("E7 prepublication signed replay mismatch")
	}
	if err := verifyAdmittedDirectoryPath(output); err != nil {
		return summary, err
	}
	if err := publishE7ReceiptOperation(
		output, encoded, receipt, expected, result,
	); err != nil {
		return summary, err
	}
	finalE6, _, finalE6Bytes, err := readE7SourceE6ReceiptOperation(
		e6Directory, cfg.TrustPath,
	)
	if err != nil || finalE6 != e6 ||
		string(finalE6Bytes) != string(e6Bytes) {
		return summary, indeterminateE6Publication(
			"E7-postpublication-E6-authenticated-replay",
			true, true,
			errors.New("E6 receipt changed after E7 publication"),
		)
	}
	return e7Summary{
		Schema: e7SummarySchema, Mode: e7Mode,
		RunID: e6.RunID, CycleID: e6.CycleID, AttemptID: e6.AttemptID,
		DecisionID:                    result.DecisionID,
		E6ReceiptSHA256:               e6SHA,
		ReceiptSHA256:                 admittedRawSHA(encoded),
		ReceiptObjectDigest:           receipt.ObjectDigest,
		AuthorizationCollectionDigest: result.CollectionDigest,
		VerificationState:             receipt.VerificationState,
	}, nil
}

func e7Expectation(
	e6 e6VerificationReceipt, e6SHA string,
) realcycle.ExecutionAuthorizationExpectation {
	return realcycle.ExecutionAuthorizationExpectation{
		RunID: e6.RunID, CycleID: e6.CycleID,
		AttemptID: e6.AttemptID, TopologyID: e6.TopologyID,
		PlanSHA256: e6.PlanSHA256, PlanObjectDigest: e6.PlanObjectDigest,
		TrustSHA256:     e6.TrustSHA256,
		E6ReceiptSHA256: e6SHA, E6ReceiptObjectDigest: e6.ObjectDigest,
		HandoffCollectionDigest:  e6.HandoffCollectionDigest,
		OneTimeNonce:             e6.OneTimeNonce,
		MinimumActivationCounter: e6.MinimumActivationCounter,
		LastObservedCounter:      e6.LastObservedCounter,
		ValidNotBefore:           e6.ValidNotBefore, ValidNotAfter: e6.ValidNotAfter,
		MaxExecutionSeconds:        e6.MaxExecutionSeconds,
		SupervisorExecutablePath:   e6.SupervisorExecutablePath,
		SupervisorExecutableSHA256: e6.SupervisorExecutableSHA256,
		SupervisorConfigPath:       e6.SupervisorConfigPath,
		SupervisorConfigSHA256:     e6.SupervisorConfigSHA256,
		RoleKeys:                   e6.RoleExtensionKeys,
	}
}

//lint:ignore U1000 used by Linux E7 publication and replay.
func readE7ReceiptStructure(
	directory *secureDirectory,
) (e7VerificationReceipt, []byte, error) {
	file, err := openAdmittedPrivateFileMode(
		directory, e7ReceiptFile, os.O_RDONLY, 0, 0o400,
	)
	if err != nil {
		return e7VerificationReceipt{}, nil, err
	}
	data, readErr := readBoundedE7File(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return e7VerificationReceipt{}, nil, errors.Join(readErr, closeErr)
	}
	value, err := parseE7ReceiptStructure(data)
	return value, data, err
}

//lint:ignore U1000 used by Linux E7 publication and replay.
func readAuthenticatedE7Receipt(
	directory *secureDirectory,
	expected realcycle.ExecutionAuthorizationExpectation,
) (
	e7VerificationReceipt, realcycle.ExecutionAuthorizationResult,
	[]byte, error,
) {
	value, raw, err := readE7ReceiptStructure(directory)
	if err != nil {
		return e7VerificationReceipt{},
			realcycle.ExecutionAuthorizationResult{}, nil, err
	}
	result, err := verifyE7ReceiptProjection(value, expected)
	if err != nil {
		return e7VerificationReceipt{},
			realcycle.ExecutionAuthorizationResult{}, nil, err
	}
	return value, result, raw, nil
}

//lint:ignore U1000 used by Linux E7 publication and replay.
func readBoundedE7File(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > e7ReceiptMaxBytes {
		return nil, errors.New("E7 receipt file size is invalid")
	}
	data := make([]byte, int(info.Size()))
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := file.ReadAt(extra[:], info.Size()); n != 0 || err == nil {
		return nil, errors.New("E7 receipt read did not terminate at exact EOF")
	}
	return data, nil
}
