//go:build windows

package replaystore

import (
	"fmt"
)

var rewriteRecordWrite = writeFull
var rewriteStage func(stage int)

func atRewriteStage(stage int) {
	if rewriteStage != nil {
		rewriteStage(stage)
	}
}

// replace refuses the replay journal on Windows. The Go file handle does not
// grant FILE_SHARE_DELETE, so deleting or replacing the live path requires
// closing the only descriptor that binds its identity. A close-then-remove
// sequence can delete a concurrently substituted victim and can lose both the
// old journal and its complete temp if rename fails. The gateway journal is
// not shipped on Windows; fail startup closed instead of claiming durability
// this platform implementation cannot provide.
func (w *Writer) replace(records []Record) error {
	return fmt.Errorf("replay journal %s: crash-atomic rewrite is unsupported on Windows", w.path)
}

// Windows does not provide the Unix directory-fsync durability primitive used
// by the deployed journal. Keep the pending-record ordering explicit while
// preserving the platform's already-documented weaker rewrite guarantee.
func syncDir(string) error { return nil }
