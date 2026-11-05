//go:build windows

package replaystore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func readWALName(dir *walDirectory, name string) (Record, error) {
	path := filepath.Join(dir.path, name)
	f, err := os.Open(path)
	if err != nil {
		return Record{}, fmt.Errorf("replay WAL record %s: open: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Record{}, err
	}
	if err := checkJournalFile(path, info); err != nil {
		return Record{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, RecordSize+1))
	if err != nil || len(raw) != RecordSize {
		return Record{}, &RefusedError{Path: path, Why: "does not contain exactly one complete WAL record"}
	}
	return decodeRecord(raw), nil
}

func removeWALName(dir *walDirectory, name string) error {
	return os.Remove(filepath.Join(dir.path, name))
}

func syncWALDir(dir *walDirectory) error {
	return dir.handle.Sync()
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
	want := encodeRecord(record)
	temp := filepath.Join(dir.path, fmt.Sprintf(".tmp-%d-%d", os.Getpid(), walTempSequence.Add(1)))
	f, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		_ = f.Close()
		if !published {
			_ = os.Remove(temp)
		}
	}()
	atWALPublishStage(1)
	if err := walRecordWrite(f, want[:]); err != nil {
		return fmt.Errorf("replay WAL %s: write complete temp: %w", path, err)
	}
	atWALPublishStage(2)
	if err := f.Sync(); err != nil {
		return err
	}
	if err := verifyCompleteRecordFile(temp, f); err != nil {
		return fmt.Errorf("replay WAL %s: verify temp metadata: %w", path, err)
	}
	atWALPublishStage(3)
	if err := verifyCompleteRecordFile(temp, f); err != nil {
		return fmt.Errorf("replay WAL %s: reverify temp metadata before publication: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := renameNoReplace(temp, path); err != nil {
		if existing, readErr := readWALName(dir, name); readErr == nil && existing == record {
			_ = os.Remove(temp)
			return syncWALDir(dir)
		}
		return fmt.Errorf("replay WAL %s: atomically publish immutable record: %w", path, err)
	}
	published = true
	atWALPublishStage(4)
	if err := syncWALDir(dir); err != nil {
		return err
	}
	atWALPublishStage(5)
	got, err := readWALName(dir, name)
	if err != nil || got != record {
		return &RefusedError{Path: path, Why: "did not retain the exact committed WAL record"}
	}
	atWALPublishStage(6)
	return nil
}
