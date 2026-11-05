//go:build linux

package securefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace publishes a directory atomically and refuses to replace an
// existing destination.
//
// On Linux this is renameat2 with RENAME_NOREPLACE, which the kernel resolves
// atomically. Plain rename(2) is NOT a substitute: the kernel will replace an
// existing EMPTY directory, so a rename onto a committed anchor slot left empty
// by an interrupted attempt succeeds silently. That is demonstrated directly by
// TestRawKernelRenameReplacesAnEmptyDirectory, which performs the raw call.
//
// Go's os.Rename is not a substitute either. It Lstats the destination first
// and returns EEXIST for directory-onto-different-directory before issuing the
// syscall (src/os/file_unix.go), so it MASKS the kernel behaviour in ordinary
// tests while leaving the underlying race open: the destination can appear
// after that pre-check and before the rename lands. A source-level invariant in
// renamenoreplace_source_test.go keeps this file from drifting back to it,
// because that regression is not reliably observable from behaviour.
//
// A kernel or filesystem without renameat2 support reports ENOSYS or EINVAL;
// callers fall back to the portable claim path rather than silently degrading
// to replacing rename.
func renameNoReplace(oldPath, newPath string) error {
	err := unix.Renameat2(
		unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE,
	)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST), errors.Is(err, unix.ENOTEMPTY):
		return os.ErrExist
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return errRenameNoReplaceUnsupported
	default:
		return err
	}
}
