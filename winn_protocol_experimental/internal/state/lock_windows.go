//go:build windows

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"winsvpn.local/winnprotocol/internal/securefile"
)

type fileLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireFileLock(path string) (*fileLock, error) {
	directory := filepath.Dir(path)
	if err := securefile.EnsurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	existing, err := os.Lstat(path)
	if err == nil && !existing.Mode().IsRegular() {
		return nil, errors.New("state lock path is not a regular file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := securefile.OpenFileWithinParent(
		path, os.O_CREATE|os.O_RDWR, 0o600,
	)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() ||
		(existing != nil && !os.SameFile(existing, opened)) {
		_ = file.Close()
		return nil, errors.New("state lock target changed or is not a regular file")
	}
	lock := &fileLock{file: file}
	err = windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&lock.overlapped,
	)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another process owns %s: %w", path, err)
	}
	return lock, nil
}

func (l *fileLock) release() error {
	unlockErr := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
