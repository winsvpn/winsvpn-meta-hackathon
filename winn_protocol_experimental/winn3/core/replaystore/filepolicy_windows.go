//go:build windows

package replaystore

import "os"

// checkJournalOwnerMode is a no-op on Windows: there is no shipped Windows
// deployment of the replay journal, Windows file modes are ACL-backed rather
// than POSIX 0600/0640, and there is no meaningful euid to compare the owner
// against. The regular-file and size bounds of Open still apply.
func checkJournalOwnerMode(path string, fi os.FileInfo) error {
	return nil
}

func checkWALDirOwnerMode(path string, fi os.FileInfo) error {
	return nil
}
