//go:build !windows

package replaystore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readWALName(dir *walDirectory, name string) (Record, error) {
	path := filepath.Join(dir.path, name)
	fd, err := unix.Openat(int(dir.handle.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Record{}, fmt.Errorf("replay WAL record %s: openat: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return Record{}, fmt.Errorf("replay WAL record %s: bind descriptor", path)
	}
	defer f.Close()
	var openedRaw unix.Stat_t
	if err := unix.Fstat(fd, &openedRaw); err != nil {
		return Record{}, fmt.Errorf("replay WAL record %s: fstat: %w", path, err)
	}
	opened, err := f.Stat()
	if err != nil {
		return Record{}, fmt.Errorf("replay WAL record %s: stat: %w", path, err)
	}
	if err := checkJournalFile(path, opened); err != nil {
		return Record{}, err
	}
	if opened.Size() != RecordSize {
		return Record{}, &RefusedError{Path: path, Why: fmt.Sprintf(
			"is %d bytes, not one complete %d-byte WAL record", opened.Size(), RecordSize)}
	}
	raw, err := io.ReadAll(io.LimitReader(f, RecordSize+1))
	if err != nil {
		return Record{}, fmt.Errorf("replay WAL record %s: read: %w", path, err)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(dir.handle.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return Record{}, &RefusedError{Path: path, Why: "changed while its immutable WAL record was being read"}
	}
	if openedRaw.Dev != named.Dev || openedRaw.Ino != named.Ino {
		return Record{}, &RefusedError{Path: path, Why: "changed while its immutable WAL record was being read"}
	}
	if len(raw) != RecordSize {
		return Record{}, &RefusedError{Path: path, Why: "does not contain exactly one complete WAL record"}
	}
	return decodeRecord(raw), nil
}

func removeWALName(dir *walDirectory, name string) error {
	return unix.Unlinkat(int(dir.handle.Fd()), name, 0)
}

func syncWALDir(dir *walDirectory) error {
	return unix.Fsync(int(dir.handle.Fd()))
}

func commitWALName(dir *walDirectory, name string, record Record) error {
	path := filepath.Join(dir.path, name)
	if existing, err := readWALName(dir, name); err == nil {
		if existing != record {
			return &RefusedError{Path: path, Why: "conflicts with the deterministic WAL identity"}
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	temp := fmt.Sprintf(".tmp-%d-%d", os.Getpid(), walTempSequence.Add(1))
	fd, err := unix.Openat(
		int(dir.handle.Fd()),
		temp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o640,
	)
	if err != nil {
		return fmt.Errorf("replay WAL %s: create temp: %w", path, err)
	}
	tempPath := filepath.Join(dir.path, temp)
	f := os.NewFile(uintptr(fd), tempPath)
	if f == nil {
		_ = unix.Close(fd)
		_ = removeWALName(dir, temp)
		return fmt.Errorf("replay WAL %s: bind temp descriptor", path)
	}
	published := false
	defer func() {
		_ = f.Close()
		if !published {
			_ = removeWALName(dir, temp)
		}
	}()
	if err := f.Chmod(0o640); err != nil {
		return fmt.Errorf("replay WAL %s: chmod temp: %w", path, err)
	}
	atWALPublishStage(1)
	want := encodeRecord(record)
	if err := walRecordWrite(f, want[:]); err != nil {
		return fmt.Errorf("replay WAL %s: write complete temp: %w", path, err)
	}
	atWALPublishStage(2)
	if err := f.Sync(); err != nil {
		return fmt.Errorf("replay WAL %s: sync temp: %w", path, err)
	}
	if err := verifyCompleteRecordFile(tempPath, f); err != nil {
		return fmt.Errorf("replay WAL %s: verify temp metadata: %w", path, err)
	}
	atWALPublishStage(3)
	if err := verifyCompleteRecordFile(tempPath, f); err != nil {
		return fmt.Errorf("replay WAL %s: reverify temp metadata before publication: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("replay WAL %s: close temp: %w", path, err)
	}
	if err := renameNoReplaceAt(int(dir.handle.Fd()), temp, int(dir.handle.Fd()), name); err != nil {
		if errors.Is(err, unix.EEXIST) {
			existing, readErr := readWALName(dir, name)
			if readErr != nil || existing != record {
				return &RefusedError{Path: path, Why: "was concurrently published with conflicting WAL contents"}
			}
			if removeErr := removeWALName(dir, temp); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return fmt.Errorf("replay WAL %s: remove redundant temp: %w", path, removeErr)
			}
			if err := syncWALDir(dir); err != nil {
				return fmt.Errorf("replay WAL %s: sync redundant-temp cleanup: %w", path, err)
			}
			return nil
		}
		return fmt.Errorf("replay WAL %s: atomically publish immutable record: %w", path, err)
	}
	published = true
	atWALPublishStage(4)
	if err := syncWALDir(dir); err != nil {
		return fmt.Errorf("replay WAL %s: sync committed record: %w", path, err)
	}
	atWALPublishStage(5)
	got, err := readWALName(dir, name)
	if err != nil || got != record {
		return &RefusedError{Path: path, Why: "did not retain the exact committed WAL record"}
	}
	encoded := encodeRecord(got)
	if !bytes.Equal(encoded[:], want[:]) {
		return &RefusedError{Path: path, Why: "did not retain the exact committed WAL bytes"}
	}
	atWALPublishStage(6)
	return nil
}
