//go:build darwin

package securefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace publishes a directory atomically and refuses to replace an
// existing destination.
//
// On Darwin this is renamex_np with RENAME_EXCL, the native atomic no-replace
// rename. Plain rename(2) is not a substitute: POSIX requires it to replace an
// existing EMPTY directory, and an empty or partially-cleaned committed slot is
// exactly what an interrupted earlier attempt leaves behind.
//
// Go's os.Rename is not a substitute either, and for a reason that is easy to
// misread. It performs its own Lstat of the destination and returns EEXIST for
// directory-onto-different-directory before issuing the syscall at all
// (src/os/file_unix.go). That makes a plain-rename mutant look refused in
// ordinary tests on every platform — an earlier comment here wrongly credited
// APFS for that, when it was Go's pre-check. The pre-check is a convenience in
// front of a syscall that will replace, and it does not cover the race it
// appears to: the destination can appear after the check and before the rename.
// The guarantee has to come from the flag, requested of the kernel.
func renameNoReplace(oldPath, newPath string) error {
	err := unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST), errors.Is(err, unix.ENOTEMPTY):
		return os.ErrExist
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENOTSUP),
		errors.Is(err, unix.EINVAL):
		return errRenameNoReplaceUnsupported
	default:
		return err
	}
}
