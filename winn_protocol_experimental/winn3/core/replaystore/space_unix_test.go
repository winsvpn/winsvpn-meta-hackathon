//go:build !windows

package replaystore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTransientWALSpaceErrorDoesNotLatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.journal")
	_, w, err := OpenWithLimit(path, testJournalNow, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	original := walRecordWrite
	walRecordWrite = func(*os.File, []byte) error { return unix.ENOSPC }
	t.Cleanup(func() { walRecordWrite = original })

	record := testRecords("enospc-wal", 1, testJournalNow.Unix()+3600)[0]
	err = w.Append(record, testJournalNow.Unix())
	if err == nil || !isTransientSpace(err) {
		t.Fatalf("ENOSPC WAL append = %v, want a transient space error", err)
	}
	if w.Err() != nil {
		t.Fatalf("transient ENOSPC latched persist health: %v", w.Err())
	}
	if _, err := os.Lstat(filepath.Join(path+walSuffix, walRecordName(record))); !os.IsNotExist(err) {
		t.Fatalf("ENOSPC published a canonical WAL record: %v", err)
	}

	walRecordWrite = original
	if err := w.Append(record, testJournalNow.Unix()); err != nil {
		t.Fatalf("append after transient ENOSPC: %v", err)
	}
	if w.Err() != nil {
		t.Fatalf("recovered writer reported persist health: %v", w.Err())
	}
}

func TestTransientRewriteSpaceErrorDoesNotLatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.journal")
	_, w, err := OpenWithLimit(path, testJournalNow, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	seed := testRecords("enospc-rewrite", 1, testJournalNow.Unix()+3600)[0]
	if err := w.Append(seed, testJournalNow.Unix()); err != nil {
		t.Fatal(err)
	}

	original := rewriteRecordWrite
	rewriteRecordWrite = func(*os.File, []byte) error { return unix.ENOSPC }
	t.Cleanup(func() { rewriteRecordWrite = original })

	err = w.Rewrite([]Record{seed}, testJournalNow.Unix())
	if err == nil || !isTransientSpace(err) {
		t.Fatalf("ENOSPC rewrite = %v, want a transient space error", err)
	}
	if w.Err() != nil {
		t.Fatalf("transient rewrite ENOSPC latched persist health: %v", w.Err())
	}

	rewriteRecordWrite = original
	later := testJournalNow.Add(time.Hour)
	if err := w.Rewrite([]Record{seed}, later.Unix()); err != nil {
		t.Fatalf("rewrite after transient ENOSPC: %v", err)
	}
	if w.Err() != nil {
		t.Fatalf("recovered rewrite reported persist health: %v", w.Err())
	}
}
