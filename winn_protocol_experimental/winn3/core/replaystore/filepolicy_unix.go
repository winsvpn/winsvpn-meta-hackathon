//go:build !windows

package replaystore

import (
	"fmt"
	"os"
	"syscall"
)

// checkJournalOwnerMode applies the existing-journal ownership policy of
// Open: the file must be owned by the process's effective uid and carry
// exactly mode 0600 or 0640, mirroring the gateway installer's
// require_root_private_keyfile policy (which dies on any keyfile that is a
// symlink, carried a wider mode, or was not root-owned). A journal that the
// operator cannot vouch for is refused at startup, not read.
func checkJournalOwnerMode(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return &RefusedError{Path: path, Why: "has unreadable ownership metadata; refusing rather than assuming it is private"}
	}
	if err := journalOwnerModeAllowed(int(st.Uid), fi.Mode().Perm(), os.Geteuid()); err != nil {
		return &RefusedError{Path: path, Why: err.Error()}
	}
	return nil
}

func checkWALDirOwnerMode(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil || int(st.Uid) != os.Geteuid() || fi.Mode().Perm() != 0o700 {
		return &RefusedError{Path: path, Why: "must be owned by this process and have mode 0700"}
	}
	return nil
}

// journalOwnerModeAllowed is the pure policy over one stat result, kept
// separate so the tests can exercise every refusal without chown privileges.
func journalOwnerModeAllowed(uid int, mode os.FileMode, euid int) error {
	if uid != euid {
		return fmt.Errorf("is owned by uid %d, not this process's euid %d; fix the ownership rather than widening the mode",
			uid, euid)
	}
	if mode != 0o600 && mode != 0o640 {
		return fmt.Errorf("has mode %#o; only 0600 and 0640 are allowed (the journal is refused rather than widened, exactly like an installer keyfile)",
			mode)
	}
	return nil
}
