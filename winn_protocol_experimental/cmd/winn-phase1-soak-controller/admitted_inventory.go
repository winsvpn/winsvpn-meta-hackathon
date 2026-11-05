package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type admittedRootLock struct {
	state    *secureDirectory
	evidence *secureDirectory
}

var admittedRootOpenedOperation = func(string) {}

func acquireAdmittedRootLock(
	statePath, evidencePath string,
) (*admittedRootLock, error) {
	type root struct {
		path string
		kind string
	}
	roots := []root{
		{path: statePath, kind: "state"},
		{path: evidencePath, kind: "evidence"},
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].path < roots[j].path
	})
	opened := make(map[string]*secureDirectory, len(roots))
	for _, candidate := range roots {
		directory, err := openAdmittedPrivateDirectory(candidate.path)
		if err != nil {
			for _, prior := range opened {
				_ = prior.Close()
			}
			return nil, err
		}
		admittedRootOpenedOperation(candidate.path)
		if err := lockExclusiveNonBlocking(directory.file); err != nil {
			_ = directory.Close()
			for _, prior := range opened {
				_ = unlockAndClose(prior.file)
			}
			return nil, err
		}
		if err := verifyAdmittedDirectoryPath(directory); err != nil {
			_ = unlockAndClose(directory.file)
			directory.file = nil
			for _, prior := range opened {
				_ = unlockAndClose(prior.file)
				prior.file = nil
			}
			return nil, err
		}
		opened[candidate.kind] = directory
	}
	return &admittedRootLock{
		state: opened["state"], evidence: opened["evidence"],
	}, nil
}

func (l *admittedRootLock) Close() error {
	if l == nil {
		return nil
	}
	var result error
	for _, directory := range []*secureDirectory{l.evidence, l.state} {
		if directory == nil || directory.file == nil {
			continue
		}
		file := directory.file
		directory.file = nil
		result = errors.Join(result, unlockAndClose(file))
	}
	l.evidence = nil
	l.state = nil
	return result
}

func validateAdmittedPrivateDirectoryInfo(info os.FileInfo, path string) error {
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s must be a mode 0700 directory", path)
	}
	if !admittedOwnedByCurrentUser(info) {
		return fmt.Errorf("%s is not owned by the current effective user", path)
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return err
	}
	if identity.nlink < 1 {
		return fmt.Errorf("%s has invalid directory link count", path)
	}
	return nil
}

func validateAdmittedPrivateFileInfo(
	info os.FileInfo, path string, expectedMode os.FileMode,
) error {
	if !info.Mode().IsRegular() || info.Mode().Perm() != expectedMode.Perm() {
		return fmt.Errorf(
			"%s must be a mode %04o regular file", path, expectedMode.Perm(),
		)
	}
	if !admittedOwnedByCurrentUser(info) {
		return fmt.Errorf("%s is not owned by the current effective user", path)
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return err
	}
	if identity.nlink != 1 {
		return fmt.Errorf("%s has %d hard links, expected one", path, identity.nlink)
	}
	return nil
}

func openAdmittedPrivateDirectory(path string) (*secureDirectory, error) {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return nil, err
	}
	info, err := directory.file.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := validateAdmittedPrivateDirectoryInfo(info, path); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func openAdmittedPrivateChildDirectory(
	parent *secureDirectory, name string,
) (*secureDirectory, error) {
	directory, err := parent.OpenDirectory(name)
	if err != nil {
		return nil, err
	}
	info, err := directory.file.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := validateAdmittedPrivateDirectoryInfo(info, directory.path); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func verifyAdmittedDirectoryPath(directory *secureDirectory) error {
	retained, err := directory.file.Stat()
	if err != nil {
		return err
	}
	if err := validateAdmittedPrivateDirectoryInfo(retained, directory.path); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(directory.path)
	if err != nil {
		return err
	}
	if err := validateAdmittedPrivateDirectoryInfo(pathInfo, directory.path); err != nil {
		return err
	}
	retainedID, err := identityFromInfo(retained)
	if err != nil {
		return err
	}
	pathID, err := identityFromInfo(pathInfo)
	if err != nil {
		return err
	}
	if retainedID != pathID {
		return fmt.Errorf("directory %s changed retained identity", directory.path)
	}
	return nil
}

func openAdmittedPrivateFile(
	directory *secureDirectory, name string, flags int, permission os.FileMode,
) (*os.File, error) {
	return openAdmittedPrivateFileMode(
		directory, name, flags, permission, 0o600,
	)
}

func openAdmittedPrivateFileMode(
	directory *secureDirectory, name string, flags int,
	permission, expectedMode os.FileMode,
) (*os.File, error) {
	file, err := directory.Open(name, flags, permission)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateAdmittedPrivateFileInfo(
		info, filepath.Join(directory.path, name), expectedMode,
	); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func atomicWriteAdmittedDirectory(
	directory *secureDirectory, name string, data []byte,
) error {
	if err := atomicWriteDirectory(directory, name, data, 0o600); err != nil {
		return err
	}
	file, err := openAdmittedPrivateFile(directory, name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return verifyAdmittedDirectoryPath(directory)
}

func classifyAdmittedRoots(
	stateRoot, evidenceRoot *secureDirectory,
) (fresh bool, err error) {
	stateEntries, err := stateRoot.ReadDir()
	if err != nil {
		return false, err
	}
	evidenceEntries, err := evidenceRoot.ReadDir()
	if err != nil {
		return false, err
	}
	if len(stateEntries) == 0 && len(evidenceEntries) == 0 {
		return true, nil
	}
	allowedState := map[string]bool{
		admittedModeFile: true, admittedCheckpointFile: true,
		admittedCheckpointKeyFile: true, admittedNonceFile: true,
		admittedAttemptsDirectory: true, admittedContractsDirectory: true,
	}
	allowedEvidence := map[string]bool{
		admittedModeFile: true, admittedReceiptFile: true,
	}
	for _, entry := range stateEntries {
		if !allowedState[entry.Name()] {
			return false, fmt.Errorf(
				"state root contains legacy, mixed, or unknown entry %q",
				entry.Name(),
			)
		}
		if (entry.Name() == admittedAttemptsDirectory ||
			entry.Name() == admittedContractsDirectory) != entry.IsDir() {
			return false, fmt.Errorf("state entry %q has the wrong type", entry.Name())
		}
		if entry.IsDir() {
			directory, err := openAdmittedPrivateChildDirectory(
				stateRoot, entry.Name(),
			)
			if err != nil {
				return false, err
			}
			if err := directory.Close(); err != nil {
				return false, err
			}
		} else {
			file, err := openAdmittedPrivateFile(
				stateRoot, entry.Name(), os.O_RDONLY, 0,
			)
			if err != nil {
				return false, err
			}
			if err := file.Close(); err != nil {
				return false, err
			}
		}
	}
	for _, entry := range evidenceEntries {
		if !allowedEvidence[entry.Name()] {
			return false, fmt.Errorf(
				"evidence root contains legacy, mixed, or unknown entry %q",
				entry.Name(),
			)
		}
		if entry.IsDir() {
			return false, fmt.Errorf("evidence entry %q has the wrong type", entry.Name())
		}
		file, err := openAdmittedPrivateFile(
			evidenceRoot, entry.Name(), os.O_RDONLY, 0,
		)
		if err != nil {
			return false, err
		}
		if err := file.Close(); err != nil {
			return false, err
		}
	}
	if !containsEntry(stateEntries, admittedModeFile) ||
		!containsEntry(evidenceEntries, admittedModeFile) {
		return false, errors.New("admitted mode markers are incomplete")
	}
	for _, name := range []string{
		admittedCheckpointFile, admittedCheckpointKeyFile, admittedNonceFile,
		admittedAttemptsDirectory, admittedContractsDirectory,
	} {
		if !containsEntry(stateEntries, name) {
			return false, fmt.Errorf("admitted state is incomplete: missing %s", name)
		}
	}
	if !containsEntry(evidenceEntries, admittedReceiptFile) {
		return false, errors.New("admitted evidence is incomplete: missing receipt log")
	}
	return false, nil
}

func containsEntry(entries []os.DirEntry, name string) bool {
	for _, entry := range entries {
		if entry.Name() == name {
			return true
		}
	}
	return false
}

func refuseAdmittedRootsForLegacy(stateRoot, evidenceRoot string) error {
	for _, root := range []string{stateRoot, evidenceRoot} {
		_, err := os.Lstat(filepath.Join(root, admittedModeFile))
		if err == nil {
			return fmt.Errorf(
				"legacy controller mode refuses admitted E3 root %s", root,
			)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect controller mode marker: %w", err)
		}
	}
	return nil
}

func newAdmittedModeMarker(
	cfg AdmittedConfig, configDigest, nonce string,
) (admittedModeMarker, []byte, error) {
	value := admittedModeMarker{
		Schema: admittedModeSchema, Mode: admittedMode, RunID: cfg.RunID,
		ControllerConfigSHA256: configDigest,
		LauncherSHA256:         cfg.LauncherSHA256,
		AdapterSHA256:          cfg.AdapterSHA256,
		CreatedInstanceNonce:   nonce, Authority: false,
	}
	digest, err := admittedDigest(admittedModeDomain, value)
	if err != nil {
		return admittedModeMarker{}, nil, err
	}
	value.ObjectDigest = digest
	encoded, err := json.Marshal(value)
	return value, encoded, err
}

func parseAdmittedModeMarker(data []byte) (admittedModeMarker, error) {
	var value admittedModeMarker
	if len(data) == 0 || len(data) > admittedMaximumObjectBytes {
		return value, errors.New("mode marker size is invalid")
	}
	if err := decodeStrictObject(data, &value); err != nil {
		return value, err
	}
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(admittedModeDomain, value)
	value.ObjectDigest = digest
	if err != nil || digest != expected || value.Schema != admittedModeSchema ||
		value.Mode != admittedMode || value.Authority ||
		!noncePattern.MatchString(value.CreatedInstanceNonce) ||
		!digestPattern.MatchString(value.ControllerConfigSHA256) ||
		!digestPattern.MatchString(value.LauncherSHA256) ||
		!digestPattern.MatchString(value.AdapterSHA256) ||
		!digestPattern.MatchString(value.ObjectDigest) {
		return admittedModeMarker{}, errors.New("mode marker is invalid")
	}
	return value, nil
}

func verifyModeMarkers(
	stateRoot, evidenceRoot *secureDirectory,
	cfg AdmittedConfig,
	configDigest string,
) (admittedModeMarker, error) {
	stateBytes, err := readExclusiveDirectoryFile(stateRoot, admittedModeFile)
	if err != nil {
		return admittedModeMarker{}, err
	}
	evidenceBytes, err := readExclusiveDirectoryFile(evidenceRoot, admittedModeFile)
	if err != nil {
		return admittedModeMarker{}, err
	}
	if string(stateBytes) != string(evidenceBytes) {
		return admittedModeMarker{}, errors.New("state and evidence mode markers differ")
	}
	marker, err := parseAdmittedModeMarker(stateBytes)
	if err != nil {
		return admittedModeMarker{}, err
	}
	if marker.RunID != cfg.RunID ||
		marker.ControllerConfigSHA256 != configDigest ||
		marker.LauncherSHA256 != cfg.LauncherSHA256 ||
		marker.AdapterSHA256 != cfg.AdapterSHA256 {
		return admittedModeMarker{}, errors.New(
			"admitted mode marker does not match this invocation",
		)
	}
	return marker, nil
}

func readExclusiveDirectoryFile(
	directory *secureDirectory, name string,
) ([]byte, error) {
	return readExclusiveDirectoryFileMode(directory, name, 0o600)
}

func readExclusiveDirectoryFileMode(
	directory *secureDirectory, name string, expectedMode os.FileMode,
) ([]byte, error) {
	file, err := openAdmittedPrivateFileMode(
		directory, name, os.O_RDONLY, 0, expectedMode,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	identity, err := identityFromInfo(before)
	if err != nil || identity.nlink != 1 {
		return nil, fmt.Errorf("%s lacks exclusive identity", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, admittedMaximumObjectBytes+1))
	if err != nil || len(data) == 0 || len(data) > admittedMaximumObjectBytes {
		return nil, fmt.Errorf("%s is unreadable or unbounded", name)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	afterIdentity, err := identityFromInfo(after)
	if err != nil || afterIdentity != identity || after.Size() != before.Size() {
		return nil, fmt.Errorf("%s changed while reading", name)
	}
	return data, nil
}

func inventoryAdmittedAttempts(
	stateRoot *secureDirectory,
) ([]string, string, error) {
	attemptsRoot, attemptErr := openAdmittedPrivateChildDirectory(
		stateRoot, admittedAttemptsDirectory,
	)
	contractsRoot, contractErr := openAdmittedPrivateChildDirectory(
		stateRoot, admittedContractsDirectory,
	)
	if errors.Is(attemptErr, os.ErrNotExist) &&
		errors.Is(contractErr, os.ErrNotExist) {
		digest, err := admittedDigest("winn-phase1-admitted-attempt-inventory/v1", []string{})
		return []string{}, digest, err
	}
	if attemptErr != nil || contractErr != nil {
		if attemptsRoot != nil {
			_ = attemptsRoot.Close()
		}
		if contractsRoot != nil {
			_ = contractsRoot.Close()
		}
		return nil, "", errors.New("attempt and contract directories are incomplete")
	}
	defer func() {
		_ = attemptsRoot.Close()
		_ = contractsRoot.Close()
	}()
	attemptEntries, attemptErr := attemptsRoot.ReadDir()
	contractEntries, contractErr := contractsRoot.ReadDir()
	if attemptErr != nil || contractErr != nil {
		return nil, "", errors.New("read attempt and contract directories")
	}
	sort.Slice(attemptEntries, func(i, j int) bool {
		return attemptEntries[i].Name() < attemptEntries[j].Name()
	})
	sort.Slice(contractEntries, func(i, j int) bool {
		return contractEntries[i].Name() < contractEntries[j].Name()
	})
	if len(attemptEntries) != len(contractEntries) {
		return nil, "", errors.New("attempt/contract cardinality mismatch")
	}
	rows := make([]string, 0, len(attemptEntries))
	for index, attempt := range attemptEntries {
		expected := fmt.Sprintf("%020d", index+1)
		if attempt.Name() != expected || !attempt.IsDir() {
			return nil, "", fmt.Errorf("attempt sequence is not contiguous at %q", attempt.Name())
		}
		contractName := expected + ".json"
		if contractEntries[index].Name() != contractName ||
			contractEntries[index].IsDir() {
			return nil, "", errors.New("contract sequence is not contiguous")
		}
		attemptDirectory, err := openAdmittedPrivateChildDirectory(
			attemptsRoot, expected,
		)
		if err != nil {
			return nil, "", err
		}
		files, err := attemptDirectory.ReadDir()
		if err != nil {
			_ = attemptDirectory.Close()
			return nil, "", err
		}
		names := make([]string, 0, len(files))
		for _, file := range files {
			names = append(names, file.Name())
		}
		sort.Strings(names)
		if strings.Join(names, ",") !=
			"adapter-preflight-result.json,controller-binding.json,controller-intent.json" {
			return nil, "", fmt.Errorf(
				"attempt %s is orphaned or contains unexpected files: %v",
				expected, names,
			)
		}
		for _, name := range names {
			data, err := readExclusiveDirectoryFileMode(
				attemptDirectory, name, 0o400,
			)
			if err != nil {
				_ = attemptDirectory.Close()
				return nil, "", fmt.Errorf("attempt file %s/%s: %w", expected, name, err)
			}
			rows = append(rows, expected+"/"+name+"\x00"+admittedRawSHA(data))
		}
		if err := attemptDirectory.Close(); err != nil {
			return nil, "", err
		}
		contract, err := readExclusiveDirectoryFile(contractsRoot, contractName)
		if err != nil {
			return nil, "", fmt.Errorf("contract %s is unreadable or unbounded", contractName)
		}
		rows = append(rows, contractName+"\x00"+admittedRawSHA(contract))
	}
	digest, err := admittedDigest("winn-phase1-admitted-attempt-inventory/v1", rows)
	return rows, digest, err
}

func decodeStrictObject(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil || string(canonical) != string(data) {
		return errors.New("JSON is not exact canonical encoding")
	}
	return nil
}
