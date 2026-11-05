package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// errRenameNoReplaceUnsupported reports that this platform has no atomic
// no-replace directory rename.
var errRenameNoReplaceUnsupported = errors.New(
	"no atomic no-replace directory rename on this platform",
)

// PublishDirectoryNoReplace moves a prepared directory into its final location
// atomically, refusing to replace an existing destination, and makes the
// result durable.
//
// WHY NOT os.Rename.
//
// POSIX requires rename(2) to replace an existing EMPTY directory. A committed
// anchor slot is created by moving a pending directory into place, and an empty
// or partially-cleaned committed slot is exactly what an interrupted earlier
// attempt leaves behind — so a plain kernel rename silently replaces it and a
// second set of provider receipts overwrites the first for the same ordinal.
//
// Go's os.Rename appears to refuse that, but only because it Lstats the
// destination first and returns EEXIST before issuing the syscall
// (src/os/file_unix.go). That pre-check is not the guarantee it looks like: it
// leaves the destination free to appear between the check and the rename. The
// refusal has to be requested of the kernel, which is what the platform
// primitives below do.
//
// Linux uses renameat2(RENAME_NOREPLACE); Darwin uses renamex_np(RENAME_EXCL).
// Both are single atomic operations, so the destination path either does not
// exist or holds the complete directory — there is no instant at which an
// observer can see a partial one.
//
// Platforms with neither primitive refuse to publish. An earlier version fell
// back to claiming the destination with mkdir and moving entries in one by one;
// that exposes the real path while it is still incomplete, so a crash mid-move
// leaves a directory that looks committed and is not. Failing to publish is
// recoverable; publishing something indistinguishable from a committed slot is
// not.
//
// Durability is the destination's parent fsync. Without it the new directory
// entry may not survive a crash, and a slot could be reported as committed and
// then not exist.
func PublishDirectoryNoReplace(preparedPath, destinationPath string) error {
	info, err := os.Lstat(preparedPath)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("prepared path is not a real directory")
	}
	// Lstat, not Stat: a dangling symlink at the destination is an existing
	// entry that rename and mkdir both trip over, and a plain existence test
	// would call it absent.
	if _, err := os.Lstat(destinationPath); err == nil {
		return fmt.Errorf("%s already exists: %w", destinationPath, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	switch err := renameNoReplace(preparedPath, destinationPath); {
	case err == nil:
		return syncParent(destinationPath)
	case errors.Is(err, os.ErrExist):
		return fmt.Errorf("%s already exists: %w", destinationPath, os.ErrExist)
	case errors.Is(err, errRenameNoReplaceUnsupported):
		// Fail closed. There is no visible-partial fallback: see
		// renamenoreplace_other.go for why the claim-and-move approach was
		// removed rather than kept as a degraded mode.
		return fmt.Errorf(
			"cannot publish %s atomically: %w. Publishing by claiming the "+
				"destination and moving entries into it would expose an "+
				"incomplete directory at the real path, which every observer "+
				"would read as a committed one",
			destinationPath, err,
		)
	default:
		return err
	}
}

// syncParent fsyncs the directory that now holds the published entry. Without
// it the new directory entry may not survive a crash, so a slot could be
// reported as committed and then not exist. Mandatory regardless of which
// rename primitive published it.
func syncParent(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory := filepath.Dir(path)
	// #nosec G304 -- directory is the parent of a caller-selected destination
	// that has already been resolved and validated above.
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("sync directory: %w", err)
	}
	return handle.Close()
}
