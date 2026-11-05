package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// afterMatrixInputsSealed is a deterministic test seam. Production leaves it
// nil. Tests replace the caller-owned files here to prove verification uses
// only the immutable O_EXCL-created copies.
var afterMatrixInputsSealed func()

func sealMatrixInputs(
	base string,
	manifest matrixManifest,
	manifestContent []byte,
) (string, matrixManifest, func(), error) {
	directory, err := os.MkdirTemp("", "winn-ios-matrixverify-inputs-")
	if err != nil {
		return "", matrixManifest{}, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	if err := publishSealedBytes(
		directory, "matrix.json", manifestContent, 0o400,
	); err != nil {
		cleanup()
		return "", matrixManifest{}, func() {}, err
	}

	sealed := manifest
	sealed.Runs = append([]manifestRun(nil), manifest.Runs...)
	for index := range sealed.Runs {
		run := &sealed.Runs[index]
		run.originalEvidenceFileName = filepath.Base(run.Evidence)
		runDirectory := fmt.Sprintf("run-%03d", index)
		if err := os.Mkdir(filepath.Join(directory, runDirectory), 0o700); err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}
		evidence, err := readRegularWithin(
			base, filepath.Clean(run.Evidence), maxEvidenceBytes,
		)
		if err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}
		if err := requireDigest(evidence, run.EvidenceSHA256, "evidence"); err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}
		run.Evidence = filepath.Join(
			runDirectory, run.originalEvidenceFileName,
		)
		if err := publishSealedBytes(
			directory, run.Evidence, evidence, 0o400,
		); err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}

		start, err := readRegularWithin(
			base, filepath.Clean(run.StartReceipt), 64<<10,
		)
		if err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}
		if err := requireDigest(
			start, run.StartReceiptSHA256, "start receipt",
		); err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}
		run.StartReceipt = filepath.Join(runDirectory, "start-receipt.json")
		if err := publishSealedBytes(
			directory, run.StartReceipt, start, 0o400,
		); err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}

		if run.StopReceipt != "" {
			stop, err := readRegularWithin(
				base, filepath.Clean(run.StopReceipt), 64<<10,
			)
			if err != nil {
				cleanup()
				return "", matrixManifest{}, func() {}, err
			}
			if err := requireDigest(
				stop, run.StopReceiptSHA256, "stop receipt",
			); err != nil {
				cleanup()
				return "", matrixManifest{}, func() {}, err
			}
			run.StopReceipt = filepath.Join(runDirectory, "stop-receipt.json")
			if err := publishSealedBytes(
				directory, run.StopReceipt, stop, 0o400,
			); err != nil {
				cleanup()
				return "", matrixManifest{}, func() {}, err
			}
		}
		if err := syncDirectoryWithin(directory, runDirectory); err != nil {
			cleanup()
			return "", matrixManifest{}, func() {}, err
		}
	}
	if err := syncDirectoryWithin(directory, "."); err != nil {
		cleanup()
		return "", matrixManifest{}, func() {}, err
	}
	if afterMatrixInputsSealed != nil {
		afterMatrixInputsSealed()
	}
	return directory, sealed, cleanup, nil
}

func publishSealedBytes(
	root string,
	relative string,
	content []byte,
	mode os.FileMode,
) error {
	directory, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	output, err := directory.OpenFile(
		relative,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return err
	}
	written := 0
	for written < len(content) {
		count, writeErr := output.Write(content[written:])
		if writeErr != nil {
			err = writeErr
			break
		}
		if count == 0 {
			err = errors.New("sealed-input write made no progress")
			break
		}
		written += count
	}
	if err == nil {
		err = output.Chmod(mode)
	}
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = directory.Remove(relative)
	}
	return err
}

func syncDirectoryWithin(rootPath string, relative string) error {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	directory, err := root.Open(relative)
	if err != nil {
		_ = root.Close()
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		_ = root.Close()
		return err
	}
	if err := directory.Close(); err != nil {
		_ = root.Close()
		return err
	}
	return root.Close()
}

func requireDigest(content []byte, expected string, name string) error {
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expected {
		return fmt.Errorf("%s SHA-256 mismatch while sealing", name)
	}
	return nil
}
