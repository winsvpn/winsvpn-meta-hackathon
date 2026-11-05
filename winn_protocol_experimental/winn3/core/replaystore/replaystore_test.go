package replaystore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testJournalNow = time.Unix(1_700_000_000, 0)

func writeJournal(t *testing.T, dir, name string, raw []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRecords(tag string, n int, expiry int64) []Record {
	rs := make([]Record, n)
	for i := range rs {
		rs[i] = Record{Key: sha256.Sum256([]byte(fmt.Sprintf("%s-%d", tag, i))), Expiry: expiry}
	}
	return rs
}

func testRecordBytes(rs []Record) []byte {
	out := make([]byte, 0, len(rs)*RecordSize)
	for _, r := range rs {
		var rec [RecordSize]byte
		copy(rec[:32], r.Key[:])
		binary.BigEndian.PutUint64(rec[32:], uint64(r.Expiry))
		out = append(out, rec[:]...)
	}
	return out
}

func testFileSize(info os.FileInfo) int64 {
	if info == nil {
		return -1
	}
	return info.Size()
}

// TestOpenRefusesASymlink is the auditor's truncate/overwrite scenario done
// safely end to end: the journal path is a symlink, Open must refuse with the
// named refusal, and the victim file must be byte-identical afterwards. With
// the old open-following code the prune rewrite would have truncated the
// victim to whatever the live set became.
func TestOpenRefusesASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on windows needs privileges this suite does not assume")
	}
	t.Run("a symlink to an existing file", func(t *testing.T) {
		dir := t.TempDir()
		victim := filepath.Join(dir, "victim")
		victimBytes := bytes.Repeat([]byte{0x41}, 2*RecordSize)
		if err := os.WriteFile(victim, victimBytes, 0o640); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "replay.journal")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		_, _, err := Open(link, testJournalNow)
		var refused *RefusedError
		if !errors.As(err, &refused) {
			t.Fatalf("a symlinked journal was opened (err %v); want a RefusedError", err)
		}
		if !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("the refusal does not name the symlink: %v", err)
		}
		after, err := os.ReadFile(victim)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, victimBytes) {
			t.Fatalf("the symlink victim was modified: %d bytes before, %d after", len(victimBytes), len(after))
		}
	})
	t.Run("a dangling symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "replay.journal")
		if err := os.Symlink(filepath.Join(t.TempDir(), "never-created"), link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(link, testJournalNow); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("a dangling symlink must be refused as a symlink, got %v", err)
		}
	})
}

// TestOpenModePolicy pins the 0600/0640 allowlist: modes the installer would
// refuse on a keyfile are refused here too, and only the two allowed modes
// load. The modes are set with Chmod after the write so no umask can mask the
// value under test.
func TestOpenModePolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes do not exist on windows")
	}
	refused := []os.FileMode{0o644, 0o777, 0o660, 0o222, 0o400, 0o000}
	allowed := []os.FileMode{0o600, 0o640}

	for _, mode := range refused {
		path := writeJournal(t, t.TempDir(), "replay.journal", nil, mode)
		if _, _, err := Open(path, testJournalNow); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("journal mode %#o was not refused with a mode-naming error (got %v)", mode, err)
		}
	}
	for _, mode := range allowed {
		path := writeJournal(t, t.TempDir(), "replay.journal", nil, mode)
		if _, _, err := Open(path, testJournalNow); err != nil {
			t.Errorf("journal mode %#o must load, got %v", mode, err)
		}
	}
}

func TestWALCustodyAndExpiryPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX WAL custody modes do not exist on windows")
	}
	t.Run("directory and records use exact owner-only modes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := Open(path, testJournalNow)
		if err != nil {
			t.Fatal(err)
		}
		record := testRecords("wal-mode", 1, testJournalNow.Unix()+3600)[0]
		if err := w.Append(record, testJournalNow.Unix()); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		walDir := path + walSuffix
		info, err := os.Stat(walDir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("WAL directory mode = %#o, want 0700", info.Mode().Perm())
		}
		walPath := filepath.Join(walDir, walRecordName(record))
		info, err = os.Stat(walPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("WAL record mode = %#o, want 0640", info.Mode().Perm())
		}
		if err := os.Chmod(walPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(path, testJournalNow); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Fatalf("widened WAL record was not refused with a mode error: %v", err)
		}
	})

	t.Run("noncanonical entry refuses startup", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := Open(path, testJournalNow)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path+walSuffix, "unexpected.tmp"), []byte("partial"), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Open(path, testJournalNow); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Fatalf("noncanonical WAL entry was not refused: %v", err)
		}
	})

	t.Run("garbage collection removes only expired records", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := Open(path, testJournalNow)
		if err != nil {
			t.Fatal(err)
		}
		expired := testRecords("wal-expired", 1, testJournalNow.Unix()-1)[0]
		liveRecord := testRecords("wal-live", 1, testJournalNow.Unix()+3600)[0]
		if err := commitWAL(w.wal, expired, testJournalNow.Unix(), MaxRecords); err != nil {
			t.Fatal(err)
		}
		if err := commitWAL(w.wal, liveRecord, testJournalNow.Unix(), MaxRecords); err != nil {
			t.Fatal(err)
		}
		bounded, err := loadWAL(w.wal, testJournalNow.Unix(), 1)
		if err != nil {
			t.Fatalf("expired physical entries were counted before GC: %v", err)
		}
		if len(bounded) != 1 || bounded[0] != liveRecord {
			t.Fatalf("bounded WAL GC loaded %#v, want only %#v", bounded, liveRecord)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		live, reopened, err := Open(path, testJournalNow)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if len(live) != 1 || live[0] != liveRecord {
			t.Fatalf("WAL GC loaded %#v, want only %#v", live, liveRecord)
		}
		if _, err := os.Stat(filepath.Join(path+walSuffix, walRecordName(expired))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired WAL record remained after GC: %v", err)
		}
		if _, err := os.Stat(filepath.Join(path+walSuffix, walRecordName(liveRecord))); err != nil {
			t.Fatalf("live WAL record was removed: %v", err)
		}
	})
}

func TestFirstWALDirectoryCreationFsyncsItsParentExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.journal")
	original := walParentSync
	var synced []string
	walParentSync = func(dir string) error {
		synced = append(synced, dir)
		return original(dir)
	}
	t.Cleanup(func() { walParentSync = original })
	_, first, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != filepath.Dir(path) {
		t.Fatalf("first WAL directory creation parent fsyncs = %v, want [%s]", synced, filepath.Dir(path))
	}
	_, second, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 {
		t.Fatalf("existing WAL directory repeated parent-creation fsync: %v", synced)
	}
}

func TestPhysicalWALCapacityUsesAppendClockAndIsSticky(t *testing.T) {
	t.Run("expired physical records are collected before capacity", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := OpenWithLimit(path, testJournalNow, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		short := testRecords("short-lived", 1, testJournalNow.Unix()+1)[0]
		long := testRecords("long-lived", 1, testJournalNow.Unix()+3600)[0]
		replacement := testRecords("after-expiry", 1, testJournalNow.Unix()+3600)[0]
		if err := w.Append(short, testJournalNow.Unix()); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(long, testJournalNow.Unix()); err != nil {
			t.Fatal(err)
		}
		advanced := testJournalNow.Add(2 * time.Second).Unix()
		if err := w.Append(replacement, advanced); err != nil {
			t.Fatalf("append after runtime-clock expiry: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(path+walSuffix, walRecordName(short))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired physical WAL record remains after append-time GC: %v", err)
		}
		live, err := loadWAL(w.wal, advanced, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(live) != 2 {
			t.Fatalf("physical WAL has %d live records after GC, want 2", len(live))
		}
	})

	t.Run("live physical capacity recovers after expiry", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := OpenWithLimit(path, testJournalNow, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		records := testRecords("physical-cap", 4, testJournalNow.Unix()+3600)
		for i := 0; i < 2; i++ {
			if err := w.Append(records[i], testJournalNow.Unix()); err != nil {
				t.Fatalf("append %d below cap: %v", i, err)
			}
		}
		firstErr := w.Append(records[2], testJournalNow.Unix())
		if firstErr == nil || !errors.Is(firstErr, ErrCapacity) {
			t.Fatalf("third live physical record = %v, want ErrCapacity", firstErr)
		}
		if w.Err() != nil {
			t.Fatalf("capacity refusal became a sticky persist latch: %v", w.Err())
		}
		if got := w.Append(records[3], testJournalNow.Unix()); got == nil || !errors.Is(got, ErrCapacity) {
			t.Fatalf("same-clock append after capacity = %v, want another ErrCapacity", got)
		}
		if w.Err() != nil {
			t.Fatalf("repeated capacity refusal latched persist health: %v", w.Err())
		}
		if _, err := os.Lstat(filepath.Join(path+walSuffix, walRecordName(records[2]))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("capacity-refused canonical WAL record exists: %v", err)
		}
		if _, err := os.Lstat(path + pendingSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("capacity refusal published a pending sidecar: %v", err)
		}
		later := testJournalNow.Add(24 * time.Hour)
		replacement := testRecords("physical-cap-after-expiry", 1, later.Unix()+3600)[0]
		if err := w.Append(replacement, later.Unix()); err != nil {
			t.Fatalf("append after expiry freed capacity: %v", err)
		}
		if w.Err() != nil {
			t.Fatalf("recovered writer reported persist health: %v", w.Err())
		}
		if _, err := os.Lstat(filepath.Join(path+walSuffix, walRecordName(replacement))); err != nil {
			t.Fatalf("recovered WAL record missing: %v", err)
		}
	})
}

func TestRecordPublicationShortWritesNeverPublishMalformedCanonicalFiles(t *testing.T) {
	t.Run("WAL record", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := OpenWithLimit(path, testJournalNow, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		record := testRecords("short-wal-write", 1, testJournalNow.Unix()+3600)[0]
		original := walRecordWrite
		walRecordWrite = func(f *os.File, raw []byte) error {
			if _, err := f.Write(raw[:7]); err != nil {
				return err
			}
			return io.ErrShortWrite
		}
		t.Cleanup(func() { walRecordWrite = original })
		if err := w.Append(record, testJournalNow.Unix()); err == nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short WAL write = %v, want io.ErrShortWrite", err)
		}
		if _, err := os.Lstat(filepath.Join(path+walSuffix, walRecordName(record))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("short write published a canonical WAL record: %v", err)
		}
		entries, err := os.ReadDir(path + walSuffix)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("short WAL write left files behind: %v", entries)
		}
	})

	t.Run("pending sidecar", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := OpenWithLimit(path, testJournalNow, 2)
		if err != nil {
			t.Fatal(err)
		}
		record := testRecords("short-pending-write", 1, testJournalNow.Unix()+3600)[0]
		original := pendingRecordWrite
		pendingRecordWrite = func(f *os.File, raw []byte) error {
			if _, err := f.Write(raw[:9]); err != nil {
				return err
			}
			return io.ErrShortWrite
		}
		if err := w.Append(record, testJournalNow.Unix()); err == nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short pending write = %v, want io.ErrShortWrite", err)
		}
		pendingRecordWrite = original
		t.Cleanup(func() { pendingRecordWrite = original })
		if _, err := os.Lstat(path + pendingSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("short write published a canonical pending sidecar: %v", err)
		}
		if _, err := os.Lstat(pendingTempPath(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("short pending write left its hidden temp behind: %v", err)
		}
		if info, err := os.Stat(filepath.Join(path+walSuffix, walRecordName(record))); err != nil || info.Size() != RecordSize {
			t.Fatalf("authoritative WAL after pending short write = size %v err %v", testFileSize(info), err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		live, recovered, err := OpenWithLimit(path, testJournalNow, 2)
		if err != nil {
			t.Fatalf("restart after pending short write: %v", err)
		}
		defer recovered.Close()
		if len(live) != 1 || live[0] != record {
			t.Fatalf("restart recovered %#v, want %#v", live, record)
		}
	})
}

func TestAtomicPublicationNeverOverwritesRacedCanonicalRecord(t *testing.T) {
	t.Run("WAL record", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := OpenWithLimit(path, testJournalNow, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		record := testRecords("wal-race-target", 1, testJournalNow.Unix()+3600)[0]
		other := testRecords("wal-race-other", 1, testJournalNow.Unix()+3600)[0]
		canonical := filepath.Join(path+walSuffix, walRecordName(record))
		originalHook := walPublishStage
		var hookErr error
		walPublishStage = func(stage int) {
			if stage != 3 {
				return
			}
			walPublishStage = nil
			raw := encodeRecord(other)
			hookErr = os.WriteFile(canonical, raw[:], 0o640)
			if hookErr == nil {
				hookErr = os.Chmod(canonical, 0o640)
			}
		}
		t.Cleanup(func() { walPublishStage = originalHook })
		if err := w.Append(record, testJournalNow.Unix()); err == nil || !strings.Contains(err.Error(), "conflicting") {
			t.Fatalf("WAL target race = %v, want conflicting-publication refusal", err)
		}
		if hookErr != nil {
			t.Fatal(hookErr)
		}
		want := encodeRecord(other)
		if got, err := os.ReadFile(canonical); err != nil || !bytes.Equal(got, want[:]) {
			t.Fatalf("atomic WAL publication overwrote raced canonical: got=%x err=%v want=%x", got, err, want)
		}
	})

	t.Run("pending sidecar", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replay.journal")
		_, w, err := OpenWithLimit(path, testJournalNow, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		record := testRecords("pending-race-target", 1, testJournalNow.Unix()+3600)[0]
		other := testRecords("pending-race-other", 1, testJournalNow.Unix()+3600)[0]
		originalHook := pendingPublishStage
		var hookErr error
		pendingPublishStage = func(stage int) {
			if stage != 3 {
				return
			}
			pendingPublishStage = nil
			raw := encodeRecord(other)
			hookErr = os.WriteFile(path+pendingSuffix, raw[:], 0o640)
			if hookErr == nil {
				hookErr = os.Chmod(path+pendingSuffix, 0o640)
			}
		}
		t.Cleanup(func() { pendingPublishStage = originalHook })
		if err := w.Append(record, testJournalNow.Unix()); err == nil || !strings.Contains(err.Error(), "atomically publish pending") {
			t.Fatalf("pending target race = %v, want atomic no-replace refusal", err)
		}
		if hookErr != nil {
			t.Fatal(hookErr)
		}
		want := encodeRecord(other)
		if got, err := os.ReadFile(path + pendingSuffix); err != nil || !bytes.Equal(got, want[:]) {
			t.Fatalf("atomic pending publication overwrote raced canonical: got=%x err=%v want=%x", got, err, want)
		}
	})
}

func TestWALDirectorySwapDuringPublicationUsesHeldDescriptorAndFailsSticky(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix held-directory publication")
	}
	path := filepath.Join(t.TempDir(), "replay.journal")
	_, w, err := OpenWithLimit(path, testJournalNow, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	originalDir := path + walSuffix
	movedDir := originalDir + ".moved"
	var hookErr error
	originalHook := walPublishStage
	walPublishStage = func(stage int) {
		if stage != 3 || hookErr != nil {
			return
		}
		walPublishStage = nil
		if err := os.Rename(originalDir, movedDir); err != nil {
			hookErr = err
			return
		}
		hookErr = os.Mkdir(originalDir, 0o700)
	}
	t.Cleanup(func() { walPublishStage = originalHook })
	record := testRecords("mid-publish-dir-swap", 1, testJournalNow.Unix()+3600)[0]
	err = w.Append(record, testJournalNow.Unix())
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if err == nil || !strings.Contains(err.Error(), "WAL directory") {
		t.Fatalf("append across mid-publication WAL directory swap = %v, want custody refusal", err)
	}
	if w.Err() == nil {
		t.Fatal("mid-publication WAL directory swap did not become sticky")
	}
	if entries, err := os.ReadDir(originalDir); err != nil || len(entries) != 0 {
		t.Fatalf("replacement WAL directory was mutated: entries=%v err=%v", entries, err)
	}
	info, err := os.Stat(filepath.Join(movedDir, walRecordName(record)))
	if err != nil || info.Size() != RecordSize {
		t.Fatalf("held WAL directory lacks the complete published record: size=%v err=%v", testFileSize(info), err)
	}
}

func TestLegacyJournalMigratesEveryLiveRecordIntoAuthoritativeWAL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.journal")
	records := testRecords("legacy-migration", 3, testJournalNow.Unix()+3600)
	writeJournal(t, dir, "replay.journal", testRecordBytes(records), 0o640)
	live, w, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != len(records) {
		t.Fatalf("migration loaded %d records, want %d", len(live), len(records))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if _, err := os.Stat(filepath.Join(path+walSuffix, walRecordName(record))); err != nil {
			t.Fatalf("legacy record was not imported into WAL: %v", err)
		}
	}
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	live, reopened, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(live) != len(records) {
		t.Fatalf("WAL recovery after snapshot loss loaded %d records, want %d", len(live), len(records))
	}
}

// TestOpenBoundsTheJournal processes the bound after the bound: the exactly-
// bounded file loads, one byte over refuses, and a record-count overflow
// refuses even while still under the byte bound.
func TestOpenBoundsTheJournal(t *testing.T) {
	dir := t.TempDir()
	t.Run("exactly the record count and byte bound loads", func(t *testing.T) {
		raw := make([]byte, MaxRecords*RecordSize) // every record all-zero: expired, so live is empty
		path := writeJournal(t, dir, "bound.journal", raw, 0o640)
		live, _, err := Open(path, testJournalNow)
		if err != nil {
			t.Fatalf("a journal exactly at the bound must load: %v", err)
		}
		if len(live) != 0 {
			t.Fatalf("%d live records parsed from an all-expired journal, want 0", len(live))
		}
	})
	t.Run("one byte over the bound refuses before being read", func(t *testing.T) {
		path := writeJournal(t, dir, "oversize.journal", make([]byte, MaxFileBytes+1), 0o640)
		if _, _, err := Open(path, testJournalNow); err == nil ||
			(!strings.Contains(err.Error(), "bound") && !strings.Contains(err.Error(), "records")) {
			t.Fatalf("a journal above the size bound was not refused as oversize: %v", err)
		}
	})
	t.Run("one record over the cap refuses even under the byte bound", func(t *testing.T) {
		// (MaxRecords+1)*RecordSize = 5,242,920, which is still under
		// MaxFileBytes: this is the belt-and-braces record cap firing.
		path := writeJournal(t, dir, "toomany.journal", make([]byte, (MaxRecords+1)*RecordSize), 0o640)
		if _, _, err := Open(path, testJournalNow); err == nil || !strings.Contains(err.Error(), "records") {
			t.Fatalf("a journal above the record cap was not refused: %v", err)
		}
	})
}

// TestAppendsAfterARewriteLandInTheReplacedFile pins the fd rebind: the
// crash-atomic rewrite replaces the inode, so appends made after it must land
// in the renamed file, not in the orphaned pre-rewrite inode.
func TestAppendsAfterARewriteLandInTheReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.journal")
	nowUnix := testJournalNow.Unix()
	_, w, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range testRecords("old", 3, nowUnix+3600) {
		if err := w.Append(r, nowUnix); err != nil {
			t.Fatal(err)
		}
	}
	repl := testRecords("new", 5, nowUnix+3600)
	if err := w.Rewrite(repl, nowUnix); err != nil {
		t.Fatal(err)
	}
	if err := w.VerifyPath(); err != nil {
		t.Fatalf("writer rejected its own crash-atomic rewrite: %v", err)
	}
	extra := testRecords("post", 1, nowUnix+3600)[0]
	if err := w.Append(extra, nowUnix); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	extraBytes := encodeRecord(extra)
	if len(raw) != (3+len(repl)+1)*RecordSize || !bytes.Equal(raw[len(raw)-RecordSize:], extraBytes[:]) {
		t.Fatalf("journal on disk is %d bytes and does not end in the post-rewrite append", len(raw))
	}
	if st, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o640 {
		t.Fatalf("the rewritten journal has mode %#o, want 0640", st.Mode().Perm())
	}
	live, _, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 3+len(repl)+1 {
		t.Fatalf("a fresh load sees %d live records, want %d", len(live), 3+len(repl)+1)
	}
}

func TestAppendPathReplacementFailsAndRetainsRecoverablePendingRecord(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix rename permits deterministic replacement of an open journal")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.journal")
	_, w, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	record := testRecords("raced", 1, testJournalNow.Unix()+3600)[0]
	replaced := false
	appendStage = func(stage int) {
		if stage != 1 || replaced {
			return
		}
		replaced = true
		moved := path + ".old"
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { appendStage = nil })
	err = w.Append(record, testJournalNow.Unix())
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("append across pathname replacement = %v, want a replacement refusal", err)
	}
	if w.Err() == nil {
		t.Fatal("pathname replacement did not become a sticky writer error")
	}
	if _, err := os.Stat(path + pendingSuffix); err != nil {
		t.Fatalf("durable pending record was not retained: %v", err)
	}
	_ = w.Close()
	appendStage = nil
	live, recovered, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatalf("restart did not recover the pending record into the replacement path: %v", err)
	}
	defer recovered.Close()
	if len(live) != 1 || live[0] != record {
		t.Fatalf("restart recovered %#v, want only %#v", live, record)
	}
	if _, err := os.Stat(path + pendingSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending record remained after recovery: %v", err)
	}
}

func TestAppendPathReplacementImmediatelyBeforePendingClearRetainsRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix rename permits deterministic replacement of an open journal")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.journal")
	_, w, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	record := testRecords("pre-clear-race", 1, testJournalNow.Unix()+3600)[0]
	appendStage = func(stage int) {
		if stage != 3 {
			return
		}
		appendStage = nil
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { appendStage = nil })
	if err := w.Append(record, testJournalNow.Unix()); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("append across pre-clear replacement = %v, want replacement refusal", err)
	}
	if w.Err() == nil {
		t.Fatal("pre-clear replacement did not become a sticky writer error")
	}
	info, err := os.Stat(path + pendingSuffix)
	if err != nil {
		t.Fatalf("durable pending record was not retained: %v", err)
	}
	if info.Size() != RecordSize {
		t.Fatalf("pending record size = %d, want %d", info.Size(), RecordSize)
	}
	walPath := filepath.Join(path+walSuffix, walRecordName(record))
	if info, err := os.Stat(walPath); err != nil || info.Size() != RecordSize {
		t.Fatalf("immutable WAL record = size %v err %v, want %d bytes", func() int64 {
			if info == nil {
				return -1
			}
			return info.Size()
		}(), err, RecordSize)
	}
	_ = w.Close()
	appendStage = nil
	// Simulate loss of the legacy pending sidecar. The WAL, not pending or the
	// replaced compact journal, is the durable authority after commit.
	if err := os.Remove(path + pendingSuffix); err != nil {
		t.Fatal(err)
	}
	live, recovered, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatalf("restart did not recover the pre-clear pending record: %v", err)
	}
	defer recovered.Close()
	if len(live) != 1 || live[0] != record {
		t.Fatalf("restart recovered %#v, want only %#v", live, record)
	}
}

func TestAppendRefusesWALDirectoryPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix keeps the opened WAL directory descriptor stable across rename")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.journal")
	_, w, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	original := path + walSuffix
	moved := original + ".moved"
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	record := testRecords("wal-dir-swap", 1, testJournalNow.Unix()+3600)[0]
	if err := w.Append(record, testJournalNow.Unix()); err == nil || !strings.Contains(err.Error(), "WAL directory") {
		t.Fatalf("append across WAL-directory replacement = %v, want custody refusal", err)
	}
	if w.Err() == nil {
		t.Fatal("WAL-directory replacement did not become a sticky writer error")
	}
	entries, err := os.ReadDir(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement WAL directory was mutated: %v", entries)
	}
}

func TestRewriteRefusesPathSwapBeforeReopen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix rename permits deterministic replacement of the published rewrite")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.journal")
	_, w, err := Open(path, testJournalNow)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rewriteStage = func(stage int) {
		if stage != 4 {
			return
		}
		rewriteStage = nil
		if err := os.Rename(path, path+".published"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { rewriteStage = nil })
	err = w.Rewrite(testRecords("rewrite-race", 2, testJournalNow.Unix()+3600), testJournalNow.Unix())
	if err == nil || !strings.Contains(err.Error(), "rewrite inode") {
		t.Fatalf("rewrite across pathname swap = %v, want exact-inode refusal", err)
	}
	if w.Err() == nil {
		t.Fatal("rewrite pathname swap did not become a sticky writer error")
	}
}
