package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// AnonymousSnapshot returns an open descriptor on a private, unnamed copy of
// content.
//
// WHY A DESCRIPTOR ON A NAMED FILE IS NOT ENOUGH.
//
// Holding a read-only descriptor open on /path/to/provider-one.ed25519.pub
// looks like it freezes the bytes. It does not. The descriptor refers to that
// inode, and any process with write access to the same inode can modify its
// contents IN PLACE afterwards; the next read through the descriptor sees the
// new bytes. Re-hashing the path before each use does not help either — that
// checks what the file was at the moment of the check, and an in-place write
// can land between the check and the read, or between the parent's check and a
// child's open.
//
// The fix is to stop referring to a name at all. The verified bytes are written
// to a fresh 0600 temporary file, fsynced, rewound, and then UNLINKED while the
// descriptor is still held. On Linux and Darwin the inode survives as long as
// the descriptor does, but it now has no path anywhere in the filesystem — so
// there is nothing left for anyone to open, replace, or write through. The only
// route to those bytes is this descriptor and whatever children inherit it.
//
// The caller must Seek to 0 before each reuse: a descriptor read to EOF once
// yields nothing on a second read.
func AnonymousSnapshot(content []byte) (*os.File, error) {
	if len(content) == 0 {
		return nil, errors.New("refusing to snapshot empty content")
	}
	directory := os.TempDir()
	file, err := os.CreateTemp(directory, ".winn-snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("create snapshot: %w", err)
	}
	path := file.Name()
	fail := func(err error) (*os.File, error) {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("secure snapshot: %w", err))
	}
	if _, err := file.Write(content); err != nil {
		return fail(fmt.Errorf("write snapshot: %w", err))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("sync snapshot: %w", err))
	}
	// Unlink while the descriptor is open. From here the bytes have no name.
	if err := os.Remove(path); err != nil {
		return fail(fmt.Errorf("unlink snapshot: %w", err))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("rewind snapshot: %w", err)
	}
	return file, nil
}

// RewindSnapshot prepares a snapshot descriptor for another read, and confirms
// its bytes still equal what was snapshotted.
//
// The confirmation is cheap and worth doing: it turns "this descriptor should
// be immutable" into an assertion the code actually makes, and it catches a
// caller that handed the wrong descriptor along.
func RewindSnapshot(file *os.File, expected []byte) error {
	if file == nil {
		return errors.New("nil snapshot descriptor")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind snapshot: %w", err)
	}
	actual, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	if len(actual) != len(expected) {
		return fmt.Errorf(
			"snapshot holds %d bytes, want %d", len(actual), len(expected),
		)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return errors.New("snapshot contents changed")
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind snapshot: %w", err)
	}
	return nil
}
