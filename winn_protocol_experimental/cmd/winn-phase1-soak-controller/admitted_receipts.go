package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type admittedReceiptLog struct {
	directory     *secureDirectory
	file          *os.File
	count         uint64
	head          string
	digests       []string
	last          *admittedReceipt
	ownsDirectory bool
}

func openAdmittedReceiptLog(root, runID string) (*admittedReceiptLog, error) {
	directory, err := openAdmittedPrivateDirectory(root)
	if err != nil {
		return nil, err
	}
	if err := verifyAdmittedDirectoryPath(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	log, err := openAdmittedReceiptLogDirectory(directory, runID)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	log.ownsDirectory = true
	return log, nil
}

func openAdmittedReceiptLogDirectory(
	directory *secureDirectory, runID string,
) (*admittedReceiptLog, error) {
	file, err := openAdmittedPrivateFile(
		directory,
		admittedReceiptFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600,
	)
	if err != nil {
		return nil, err
	}
	log := &admittedReceiptLog{
		directory: directory, file: file, head: admittedGenesisDigest,
	}
	if err := log.replay(runID); err != nil {
		_ = file.Close()
		return nil, err
	}
	return log, nil
}

func (l *admittedReceiptLog) Close() error {
	if l == nil {
		return nil
	}
	var err error
	if l.file != nil {
		err = l.file.Close()
		l.file = nil
	}
	if l.directory != nil && l.ownsDirectory {
		err = errors.Join(err, l.directory.Close())
	}
	l.directory = nil
	return err
}

func (l *admittedReceiptLog) replay(runID string) error {
	if _, err := l.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(l.file)
	scanner.Buffer(make([]byte, 64<<10), admittedMaximumObjectBytes)
	for scanner.Scan() {
		if l.count >= admittedMaximumReceipts {
			return errors.New("admitted receipt count exceeds bound")
		}
		line := append([]byte(nil), scanner.Bytes()...)
		var receipt admittedReceipt
		if err := decodeStrictObject(line, &receipt); err != nil {
			return fmt.Errorf("decode admitted receipt %d: %w", l.count+1, err)
		}
		if err := validateAdmittedReceipt(
			receipt, runID, l.count+1, l.head,
		); err != nil {
			return err
		}
		l.count++
		l.head = receipt.ObjectDigest
		l.digests = append(l.digests, receipt.ObjectDigest)
		copyOf := receipt
		l.last = &copyOf
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	info, err := l.file.Stat()
	if err != nil {
		return err
	}
	identity, err := identityFromInfo(info)
	if err != nil || identity.nlink != 1 {
		return errors.New("admitted receipt log lacks exclusive identity")
	}
	if info.Size() > 0 {
		var last [1]byte
		if _, err := l.file.ReadAt(last[:], info.Size()-1); err != nil ||
			last[0] != '\n' {
			return errors.New("admitted receipt log has torn final line")
		}
	}
	_, err = l.file.Seek(0, io.SeekEnd)
	return err
}

func validateAdmittedReceipt(
	value admittedReceipt, runID string, sequence uint64, previous string,
) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(admittedReceiptDomain, value)
	if err != nil || digest != expected {
		return errors.New("admitted receipt object digest mismatch")
	}
	if value.Schema != admittedReceiptSchema || value.RunID != runID ||
		value.Sequence != sequence || value.PreviousDigest != previous ||
		!noncePattern.MatchString(value.InstanceNonce) ||
		(value.PredecessorNonce != "" &&
			!noncePattern.MatchString(value.PredecessorNonce)) ||
		value.IntentState != "pending" ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.MatrixExecuted || value.ProviderAccess ||
		value.CredentialAccess || value.Mutation != "none" ||
		value.Authority {
		return errors.New("admitted receipt fields are invalid")
	}
	resultBytes, err := json.Marshal(value.Result)
	if err != nil {
		return err
	}
	resultBytes = append(resultBytes, '\n')
	if value.Result.ControllerBindingDigest != value.BindingObjectDigest ||
		value.Result.ControllerIntentDigest != value.IntentObjectDigest ||
		value.Result.AdmissionBundleSHA256 != value.AdmissionBundleSHA256 ||
		value.ResultSHA256 != admittedRawSHA(resultBytes) ||
		len(value.ChildEnvironmentNames) != 8 ||
		value.ChildEnvironmentNames[0] != "READINESS" ||
		value.ChildEnvironmentNames[1] != "WINN_SOAK_ADAPTER_MODE" ||
		value.ChildEnvironmentNames[2] != "WINN_SOAK_CYCLE_SEQUENCE" ||
		value.ChildEnvironmentNames[3] != "WINN_SOAK_INSTANCE_NONCE" ||
		value.ChildEnvironmentNames[4] != "WINN_SOAK_MATRIX_RELATIVE_PATH" ||
		value.ChildEnvironmentNames[5] != "WINN_SOAK_MATRIX_SHA256" ||
		value.ChildEnvironmentNames[6] != "WINN_SOAK_PROFILE" ||
		value.ChildEnvironmentNames[7] != "WINN_SOAK_RUN_ID" {
		return errors.New("admitted receipt cross-binding is invalid")
	}
	for _, digest := range []string{
		value.AdmissionBundleSHA256, value.AdmissionBindingDigest,
		value.RuntimeCollectionDigest, value.ReservationObjectDigest,
		value.BindingSHA256, value.BindingObjectDigest, value.IntentSHA256,
		value.IntentObjectDigest, value.ResultSHA256, value.LauncherSHA256,
		value.AdapterSHA256, value.MatrixSHA256, value.SnapshotSHA256,
		value.SourceSHA256, value.ManifestSHA256, value.VerifierSHA256,
		value.ConfigurationSHA256, digest,
	} {
		if !digestPattern.MatchString(digest) {
			return errors.New("admitted receipt contains malformed digest")
		}
	}
	return validateAdmittedAdapterResult(value.Result)
}

func validateAdmittedAdapterResult(value admittedAdapterResult) error {
	if value.Schema != admittedResultSchema ||
		value.Status != "controller-binding-valid-nonauthorizing" ||
		value.Mode != "preflight" ||
		value.CycleID == "" || value.AttemptID == "" ||
		value.TopologyID == "" ||
		!digestPattern.MatchString(value.ControllerBindingDigest) ||
		!digestPattern.MatchString(value.ControllerIntentDigest) ||
		!digestPattern.MatchString(value.AdmissionBundleSHA256) ||
		value.DispatchAuthorized || value.ExternalTopologyExecuted ||
		value.MatrixExecuted || value.ProviderAccess ||
		value.CredentialAccess || value.Mutation != "none" ||
		value.Authority {
		return errors.New("adapter result is not exact nonauthorizing preflight")
	}
	return nil
}

func (l *admittedReceiptLog) Append(value admittedReceipt) (string, error) {
	if l.count >= admittedMaximumReceipts {
		return "", errors.New("admitted receipt count bound reached")
	}
	value.Schema = admittedReceiptSchema
	value.Sequence = l.count + 1
	value.PreviousDigest = l.head
	value.ObjectDigest = ""
	digest, err := admittedDigest(admittedReceiptDomain, value)
	if err != nil {
		return "", err
	}
	value.ObjectDigest = digest
	if err := validateAdmittedReceipt(
		value, value.RunID, value.Sequence, value.PreviousDigest,
	); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > admittedMaximumObjectBytes {
		return "", errors.New("admitted receipt encoding exceeds bound")
	}
	encoded = append(encoded, '\n')
	if err := verifyAdmittedDirectoryPath(l.directory); err != nil {
		return "", err
	}
	if err := writeAllOperation(l.file, encoded); err != nil {
		return "", err
	}
	if err := l.file.Sync(); err != nil {
		return "", err
	}
	if err := l.directory.Sync(); err != nil {
		return "", err
	}
	if err := verifyAdmittedDirectoryPath(l.directory); err != nil {
		return "", err
	}
	l.count++
	l.head = digest
	l.digests = append(l.digests, digest)
	copyOf := value
	l.last = &copyOf
	return digest, nil
}
