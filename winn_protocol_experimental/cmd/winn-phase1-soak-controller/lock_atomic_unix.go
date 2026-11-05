//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

var (
	atomicCreateTemp = os.CreateTemp
	atomicRename     = os.Rename
)

// atomicWrite is retained for the Unix durability fault-injection contract.
// Production checkpoint and receipt publication uses descriptor-relative
// atomicWriteDirectory; non-Unix platforms do not have that descriptor
// backend and must not compile this path-based compatibility seam.
func atomicWrite(path string, data []byte, permission os.FileMode) error {
	directory := filepath.Dir(path)
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	temporary, err := atomicCreateTemp(directory, ".winn-soak-*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", directory, err)
	}
	temporaryPath := temporary.Name()
	abandon := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(permission); err != nil {
		abandon()
		return fmt.Errorf("restrict temporary file: %w", err)
	}
	if err := writeAllOperation(temporary, data); err != nil {
		abandon()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := syncFileOperation(temporary); err != nil {
		abandon()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := atomicRename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}
