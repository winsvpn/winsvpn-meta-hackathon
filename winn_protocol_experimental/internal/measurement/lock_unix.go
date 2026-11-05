//go:build !windows

package measurement

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"winsvpn.local/winnprotocol/internal/securefile"
)

type fileLock struct {
	file *os.File
}

func acquireFileLock(path string) (*fileLock, error) {
	if err := securefile.EnsurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	existing, err := os.Lstat(path)
	if err == nil && !existing.Mode().IsRegular() {
		return nil, errors.New("measurement lock path is not a regular file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// #nosec G304 -- path is administrator configuration; its private parent
	// and any existing target were validated immediately above.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() ||
		(existing != nil && !os.SameFile(existing, opened)) {
		_ = file.Close()
		return nil, errors.New(
			"measurement lock target changed or is not regular",
		)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := flock(file, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf(
			"another process owns %s: %w", path, err,
		)
	}
	return &fileLock{file: file}, nil
}

func (lock *fileLock) release() error {
	unlockErr := flock(lock.file, unix.LOCK_UN)
	closeErr := lock.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func flock(file *os.File, operation int) error {
	descriptor := file.Fd()
	if descriptor > uintptr(^uint(0)>>1) {
		return errors.New("file descriptor exceeds the platform int range")
	}
	// #nosec G115 -- descriptor was bounded to native int maximum.
	return unix.Flock(int(descriptor), operation)
}
