//go:build !windows

package replaystore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// rewriteStage, when non-nil, is called at the named instants inside replace.
// It exists for the crash-safety test, which sets it in a subprocess and
// kills itself at the exact dangerous instant; production code leaves it nil.
var rewriteStage func(stage int)
var rewriteRecordWrite = writeFull

func atRewriteStage(stage int) {
	if rewriteStage != nil {
		rewriteStage(stage)
	}
}

// replace performs the crash-atomic prune/cap rewrite. The old journal is
// never modified in place: the new bytes are written to .journal.tmp.<pid> in
// the SAME directory, fsynced, and renamed over the journal, then the
// directory is fsynced so the rename itself is durable. Whatever the crash
// point, the path holds either the old whole journal or the new whole one:
// never an empty or torn file. The writer's fd is then rebound to the new
// inode so later appends land in the renamed file.
func (w *Writer) replace(records []Record) error {
	tmp := filepath.Join(w.dir, fmt.Sprintf(".journal.tmp.%d", os.Getpid()))
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if errors.Is(err, os.ErrExist) {
		// A stale temp from a crashed sibling in the same pid namespace: the
		// journal directory is provisioned for this process alone, so it is
		// removed and recreated rather than trusted.
		if rm := os.Remove(tmp); rm != nil {
			return fmt.Errorf("replay journal rewrite: stale temp %s exists and cannot be removed: %w", tmp, rm)
		}
		tf, err = os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	}
	if err != nil {
		return fmt.Errorf("replay journal rewrite: creating temp %s: %w", tmp, err)
	}
	// The temp becomes the journal at the rename, so pin its mode to exactly
	// 0640 rather than trust the umask: the replaced file must reload.
	if err := tf.Chmod(0o640); err != nil {
		tf.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("replay journal rewrite: chmod 0640 on temp %s: %w", tmp, err)
	}
	defer func() {
		tf.Close()
		_ = os.Remove(tmp) // a no-op after the rename below succeeds
	}()
	var rec [RecordSize]byte
	for _, r := range records {
		copy(rec[:32], r.Key[:])
		binary.BigEndian.PutUint64(rec[32:], uint64(r.Expiry))
		if err := rewriteRecordWrite(tf, rec[:]); err != nil {
			return fmt.Errorf("replay journal rewrite: writing temp %s: %w", tmp, err)
		}
	}
	if err := tf.Sync(); err != nil {
		return fmt.Errorf("replay journal rewrite: syncing temp %s: %w", tmp, err)
	}
	tempInfo, err := tf.Stat()
	if err != nil {
		return fmt.Errorf("replay journal rewrite: stat complete temp %s: %w", tmp, err)
	}
	if err := checkJournalFile(tmp, tempInfo); err != nil {
		return fmt.Errorf("replay journal rewrite: verify temp metadata: %w", err)
	}
	if want := int64(len(records) * RecordSize); tempInfo.Size() != want {
		return &RefusedError{Path: tmp, Why: fmt.Sprintf(
			"is %d bytes before publication, not the complete %d-byte snapshot",
			tempInfo.Size(), want)}
	}
	atRewriteStage(1) // temp complete and fsynced; the journal still holds the old bytes
	if err := w.verifyPathIdentity(); err != nil {
		return fmt.Errorf("replay journal rewrite: pre-rename pathname identity: %w", err)
	}
	published := tempInfo
	if err := tf.Close(); err != nil {
		return fmt.Errorf("replay journal rewrite: closing temp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, w.path); err != nil {
		return fmt.Errorf("replay journal rewrite: renaming %s over %s: %w", tmp, w.path, err)
	}
	atRewriteStage(2) // the journal now holds the new bytes; the rename is not durable yet
	if err := syncDir(w.dir); err != nil {
		return fmt.Errorf("replay journal rewrite: syncing directory %s: %w", w.dir, err)
	}
	atRewriteStage(3) // the rename is durable; the writer fd has not been rebound yet
	atRewriteStage(4) // deterministic pathname-swap seam immediately before reopen
	fd, err := unix.Open(w.path, unix.O_RDWR|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("replay journal rewrite: reopening %s: %w", w.path, err)
	}
	nf := os.NewFile(uintptr(fd), w.path)
	if nf == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("replay journal rewrite: adopting reopened descriptor for %s", w.path)
	}
	reopened, statErr := nf.Stat()
	named, nameErr := os.Lstat(w.path)
	if statErr != nil || nameErr != nil || !os.SameFile(published, reopened) || !os.SameFile(reopened, named) {
		_ = nf.Close()
		if statErr != nil {
			return fmt.Errorf("replay journal rewrite: stat reopened %s: %w", w.path, statErr)
		}
		if nameErr != nil {
			return fmt.Errorf("replay journal rewrite: lstat published %s: %w", w.path, nameErr)
		}
		return &RefusedError{Path: w.path, Why: "did not remain bound to the exact fsynced rewrite inode"}
	}
	if err := checkJournalFile(w.path, reopened); err != nil {
		_ = nf.Close()
		return err
	}
	old := w.f
	w.f = nf
	if err := old.Close(); err != nil {
		return fmt.Errorf("replay journal rewrite: closing the replaced file handle: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
