package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// afterEvidenceInputsSealed is a deterministic test seam. Production leaves
// it nil. Tests use it to replace the caller-owned paths after the immutable
// copies exist, proving every later read is from the sealed set.
var afterEvidenceInputsSealed func()

func sealVerificationInputs(cfg options) (options, func(), error) {
	directory, err := os.MkdirTemp("", "winn-ios-evidenceverify-inputs-")
	if err != nil {
		return options{}, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }

	sealed := cfg
	sealed.evidence, err = sealOneInput(
		directory, "evidence.jsonl", cfg.evidence, 64<<20, 0o400,
	)
	if err == nil {
		sealed.startReceipt, err = sealOneInput(
			directory,
			"start-receipt.json",
			cfg.startReceipt,
			64<<10,
			0o400,
		)
	}
	if err == nil && cfg.stopReceipt != "" {
		sealed.stopReceipt, err = sealOneInput(
			directory,
			"stop-receipt.json",
			cfg.stopReceipt,
			64<<10,
			0o400,
		)
	}
	if err != nil {
		cleanup()
		return options{}, func() {}, err
	}
	if err := syncSealedDirectory(directory); err != nil {
		cleanup()
		return options{}, func() {}, fmt.Errorf(
			"sync sealed-input directory: %w", err,
		)
	}
	if afterEvidenceInputsSealed != nil {
		afterEvidenceInputsSealed()
	}
	return sealed, cleanup, nil
}

func sealOneInput(
	directory string,
	name string,
	source string,
	maximum int64,
	mode os.FileMode,
) (string, error) {
	if source == "" {
		return "", errors.New("cannot seal an empty input path")
	}
	input, err := openSecureRegular(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	if err := requireBoundedFile(input, maximum); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	output, err := root.OpenFile(
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(output, io.LimitReader(input, maximum+1))
	if copyErr == nil {
		var info os.FileInfo
		info, copyErr = output.Stat()
		if copyErr == nil && info.Size() > maximum {
			copyErr = fmt.Errorf("%s exceeds %d bytes", source, maximum)
		}
	}
	if copyErr == nil {
		copyErr = output.Chmod(mode)
	}
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = root.Remove(name)
		return "", copyErr
	}
	return filepath.Join(directory, name), nil
}

func syncSealedDirectory(directory string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	parent, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return err
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		_ = root.Close()
		return err
	}
	if err := parent.Close(); err != nil {
		_ = root.Close()
		return err
	}
	return root.Close()
}
