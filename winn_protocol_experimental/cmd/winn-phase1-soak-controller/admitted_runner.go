package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type admittedLaunchRequest struct {
	AdmissionPath     string
	TrustPath         string
	TopologyPath      string
	ContractDirectory *os.File
	ContractName      string
	StateDirectory    *os.File
	AdapterPath       string
	Timeout           time.Duration
}

func runAdmittedLauncher(
	ctx context.Context,
	cfg AdmittedConfig,
	request admittedLaunchRequest,
) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("admitted launcher execution is Linux-only")
	}
	if request.ContractDirectory == nil || request.StateDirectory == nil ||
		request.ContractName == "" ||
		request.ContractName != filepath.Base(request.ContractName) {
		return nil, errors.New("admitted launcher capabilities are missing")
	}
	launcher, digest, err := openAndDigestPinnedFile(cfg.LauncherPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = launcher.Close() }()
	if digest != cfg.LauncherSHA256 {
		return nil, fmt.Errorf(
			"launcher hashes to %s, expected %s", digest, cfg.LauncherSHA256,
		)
	}
	adapter, adapterDigest, err := openAndDigestPinnedFile(cfg.AdapterPath)
	if err != nil {
		return nil, err
	}
	if adapterDigest != cfg.AdapterSHA256 {
		_ = adapter.Close()
		return nil, fmt.Errorf(
			"adapter hashes to %s, expected %s",
			adapterDigest, cfg.AdapterSHA256,
		)
	}
	adapterInfo, err := adapter.Stat()
	_ = adapter.Close()
	if err != nil || adapterInfo.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("adapter is not an executable regular file")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	arguments := []string{
		"-admission", request.AdmissionPath,
		"-trust", request.TrustPath,
		"-topology", request.TopologyPath,
		"-controller-contract", "/proc/self/fd/4/" + request.ContractName,
		"-state-dir", "/proc/self/fd/5/.",
		"-adapter", request.AdapterPath,
		"-mode", "preflight",
		"-timeout", request.Timeout.String(),
	}
	return runAdmittedCommand(
		timeoutCtx, launcher, []*os.File{
			request.ContractDirectory, request.StateDirectory,
		}, cfg.LauncherPath, arguments,
	)
}

func parseAdmittedResult(data []byte) (admittedAdapterResult, error) {
	var result admittedAdapterResult
	if len(data) == 0 || len(data) > admittedMaximumObjectBytes ||
		data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return result, errors.New("admitted result framing is invalid")
	}
	withoutLF := data[:len(data)-1]
	if err := decodeStrictObject(withoutLF, &result); err != nil {
		return result, err
	}
	if err := validateAdmittedAdapterResult(result); err != nil {
		return result, err
	}
	return result, nil
}

func loadAttemptResult(
	directory *secureDirectory,
) (
	bindingBytes, intentBytes, resultBytes []byte,
	result admittedAdapterResult,
	err error,
) {
	read := func(name string) ([]byte, error) {
		file, err := openAdmittedPrivateFileMode(
			directory, name, os.O_RDONLY, 0, 0o400,
		)
		if err != nil {
			return nil, fmt.Errorf("attempt artifact %s is not regular", name)
		}
		defer func() { _ = file.Close() }()
		before, err := file.Stat()
		if err != nil {
			return nil, err
		}
		beforeIdentity, err := identityFromInfo(before)
		if err != nil || beforeIdentity.nlink != 1 {
			return nil, fmt.Errorf("attempt artifact %s lacks exclusive identity", name)
		}
		data, err := io.ReadAll(io.LimitReader(file, admittedMaximumObjectBytes+1))
		if err != nil || len(data) == 0 || len(data) > admittedMaximumObjectBytes {
			return nil, fmt.Errorf("attempt artifact %s is unreadable or unbounded", name)
		}
		after, err := file.Stat()
		if err != nil {
			return nil, err
		}
		afterIdentity, err := identityFromInfo(after)
		if err != nil || afterIdentity != beforeIdentity ||
			after.Size() != before.Size() {
			return nil, fmt.Errorf("attempt artifact %s changed while reading", name)
		}
		return data, nil
	}
	if bindingBytes, err = read("controller-binding.json"); err != nil {
		return
	}
	if intentBytes, err = read("controller-intent.json"); err != nil {
		return
	}
	if resultBytes, err = read("adapter-preflight-result.json"); err != nil {
		return
	}
	result, err = parseAdmittedResult(resultBytes)
	return
}

func admittedAttemptIdentity(directory *secureDirectory) (string, error) {
	info, err := directory.file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", errors.New("attempt directory identity is invalid")
	}
	if !admittedOwnedByCurrentUser(info) {
		return "", errors.New("attempt directory owner is invalid")
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"dev=%d;ino=%d;mode=0700", identity.device, identity.inode,
	), nil
}

func encodeAdmittedContract(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	encoded = append(encoded, '\n')
	if err != nil || len(encoded) > admittedMaximumObjectBytes {
		return nil, errors.New("controller contract exceeds bound")
	}
	return encoded, nil
}
