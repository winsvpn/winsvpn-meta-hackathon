package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// openExclusivePrivateFile creates one regular file inside an existing private
// directory. OpenRoot keeps the final path resolution relative to an already
// opened directory, so a caller-controlled path cannot be swapped to a target
// outside that directory between validation and creation.
func openExclusivePrivateFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("output path must be absolute and clean")
	}
	base := filepath.Base(path)
	if base == "." || base == ".." || base == string(os.PathSeparator) {
		return nil, errors.New("output path must name a file")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("output parent must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("output parent must deny group and other access")
	}

	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open output directory root: %w", err)
	}
	file, openErr := root.OpenFile(
		base,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	closeErr := root.Close()
	if openErr != nil {
		return nil, fmt.Errorf("create private output: %w", openErr)
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("close output directory root: %w", closeErr)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set private output mode: %w", err)
	}
	return file, nil
}
