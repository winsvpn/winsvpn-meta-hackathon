// Package replaystore is the on-disk half of the Winn3 handshake replay
// journal (F-02).
//
// It lives in its own package because the winn3/core layer is structurally
// forbidden from touching the environment: core holds no timer and no socket
// (pinned by TestCoreHasNoTimersOrSockets), and a file is environment access
// just as much as a socket is. core owns the POLICY of the replay window: the
// lifetime, the cap, the fail-closed load decision, and imports this
// package for the bytes; this package owns nothing but the file.
//
// File format: an append-only sequence of 40-byte records,
//
//	initiation-hash  [32 bytes: SHA-256 over the handshake body]
//	expiry           [ 8 bytes: big-endian unix seconds]
//
// written with O_APPEND and fsync'd on every append. Before the compact journal
// is touched, each accepted record is committed as an immutable file in the
// owner-only <journal>.wal directory. Those WAL files remain authoritative
// until expiry. The journal is only a compact snapshot, so replacing its path
// after a WAL commit cannot erase a live replay key. The legacy
// <journal>.pending sidecar still makes a short snapshot append recoverable,
// including its matching prefix. A torn journal without that exact recovery
// record must not silently weaken the replay gate, so Open refuses it.
//
// Open also refuses a path it cannot vouch for, for the same reason the
// gateway installer refuses insecure keyfiles:
//
//   - a symbolic link or anything else that is not a regular file is refused
//     before it is opened, checked again against what was opened, and refused
//     again on a mismatch: a journal path that gets swapped for a victim file
//     must never read, truncate or overwrite the victim;
//   - an existing file must be owned by the opening process's euid and carry
//     exactly mode 0600 or 0640 (nothing group/other-writable, nothing
//     widened past 0640), so a world-readable or attacker-provisioned journal
//     is a startup error, not a data source;
//   - a file above the bounded size (MaxFileBytes) is refused before any
//     bytes are read, and the record count is capped independently, so a
//     hostile or corrupt journal cannot drive an unbounded allocation.
//
// New files are created 0640. The WAL directory is exactly 0700, every WAL
// record is exactly 0640, and the crash-atomic snapshot rewrite below retains
// the journal's 0640 mode.
package replaystore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// RecordSize is one journal record in bytes: 32-byte initiation hash plus
// 8-byte big-endian unix expiry.
const RecordSize = 32 + 8

// MaxRecords caps how many records a load will accept, even after the size
// bound has passed. It agrees with core's maxReplayEntries, which is the
// policy source this package merely enforces at load time.
const MaxRecords = 1 << 17

// MaxFileBytes is the load-time size bound: MaxRecords records plus slack for
// a bounded margin. Open stats the file and refuses anything larger before
// calling io.ReadAll, so a hostile journal cannot drive an unbounded read.
const MaxFileBytes = MaxRecords*RecordSize + 4096

const pendingSuffix = ".pending"

// Record is one journal entry.
type Record struct {
	// Key is the SHA-256 initiation hash the replay cache answers seen() on.
	Key [32]byte
	// Expiry is the unix second after which the record may be pruned.
	Expiry int64
}

// RefusedError reports why Open refused a journal: a symbolic link or
// non-regular file, an insecure mode, a foreign owner, or an oversize file.
// All of these are fail-closed startup refusals, like TornError.
type RefusedError struct {
	Path string
	Why  string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("replay journal %s %s; the gateway refuses to start on it rather "+
		"than open a file it cannot vouch for", e.Path, e.Why)
}

// Writer appends records to one journal file. It is not safe for concurrent
// use; the owning core replay cache serialises through its own mutex.
type Writer struct {
	f       *os.File
	path    string
	dir     string
	pending string
	wal     *walDirectory
	maxWAL  int
	broken  error
}

// appendStage is a deterministic race seam for replaystore package tests.
// Production leaves it nil.
var appendStage func(stage int)
var pendingRecordWrite = writeFull
var pendingPublishStage func(stage int)

func atAppendStage(stage int) {
	if appendStage != nil {
		appendStage(stage)
	}
}

func atPendingPublishStage(stage int) {
	if pendingPublishStage != nil {
		pendingPublishStage(stage)
	}
}

// Open loads path, refuses a torn, insecure or oversize file, and returns the
// records whose expiry is still in the future of now (unix second) together
// with a Writer primed for appends. An absent file is created 0640; an empty
// file is a valid empty journal.
func Open(path string, now time.Time) (live []Record, w *Writer, err error) {
	return OpenWithLimit(path, now, MaxRecords)
}

// OpenWithLimit is Open with an explicit physical WAL record ceiling. Core
// uses the same value for its in-memory and on-disk limits; tests use a small
// ceiling to exercise capacity and expiry deterministically.
func OpenWithLimit(path string, now time.Time, maxWAL int) (live []Record, w *Writer, err error) {
	if !atomicNoReplaceSupported() {
		return nil, nil, fmt.Errorf("replay journal %s: atomic no-replace publication is unsupported on this platform", path)
	}
	if maxWAL < 1 || maxWAL > MaxRecords {
		return nil, nil, fmt.Errorf("replay journal %s: invalid physical WAL cap %d", path, maxWAL)
	}
	f, err := openJournalFile(path)
	if err != nil {
		return nil, nil, err
	}
	closeOnErr := func(e error) ([]Record, *Writer, error) {
		f.Close()
		return nil, nil, e
	}
	fi, err := f.Stat()
	if err != nil {
		return closeOnErr(fmt.Errorf("replay journal %s: stat after open: %w", path, err))
	}
	if err := checkJournalFile(path, fi); err != nil {
		return closeOnErr(err)
	}
	if fi.Size() > MaxFileBytes {
		return closeOnErr(oversizeRefusal(path, fi.Size()))
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return closeOnErr(fmt.Errorf("replay journal %s: read: %w", path, err))
	}
	if int64(len(raw)) > MaxFileBytes {
		return closeOnErr(oversizeRefusal(path, int64(len(raw))))
	}
	pendingPath := path + pendingSuffix
	if err := removeStalePendingTemp(path); err != nil {
		return closeOnErr(err)
	}
	pending, hasPending, err := readPending(pendingPath)
	if err != nil {
		return closeOnErr(err)
	}
	if len(raw)%RecordSize != 0 {
		// A failed append may have written a prefix of the staged record. The
		// pending record was fsynced before the journal write began, so that
		// exact prefix is recoverable without guessing. Any other fragment is
		// still a torn journal and refuses startup.
		fragment := len(raw) % RecordSize
		encodedPending := encodeRecord(pending)
		if !hasPending || !bytes.Equal(raw[len(raw)-fragment:], encodedPending[:fragment]) {
			return closeOnErr(&TornError{Path: path, Bytes: len(raw)})
		}
		raw = raw[:len(raw)-fragment]
	}
	if records := len(raw) / RecordSize; records > MaxRecords {
		return closeOnErr(&RefusedError{Path: path, Why: fmt.Sprintf(
			"holds %d records, above the %d-record cap; refusing rather than parsing past the bound",
			records, MaxRecords)})
	}
	nowUnix := now.Unix()
	live = make([]Record, 0, len(raw)/RecordSize)
	for i := 0; i < len(raw); i += RecordSize {
		r := decodeRecord(raw[i : i+RecordSize])
		expiry := r.Expiry
		if expiry <= nowUnix {
			continue
		}
		live = append(live, r)
	}
	if hasPending && pending.Expiry > nowUnix {
		live = appendOrReplaceRecord(live, pending)
	}
	walDir, err := openWALDir(path)
	if err != nil {
		return closeOnErr(err)
	}
	closeWALOnErr := true
	defer func() {
		if closeWALOnErr {
			_ = walDir.close()
		}
	}()
	walLive, err := loadWAL(walDir, nowUnix, maxWAL)
	if err != nil {
		return closeOnErr(err)
	}
	for _, record := range walLive {
		live = appendOrReplaceRecord(live, record)
	}
	if len(live) > maxWAL {
		return closeOnErr(&RefusedError{Path: walDir.path, Why: fmt.Sprintf(
			"expands the live replay set to %d records, above the %d-record cap", len(live), maxWAL)})
	}
	w = &Writer{f: f, path: path, dir: filepath.Dir(path), pending: pendingPath, wal: walDir, maxWAL: maxWAL}
	// Migration and rewrite custody: every live legacy journal/pending record is
	// committed to the immutable WAL before startup can become ready. The compact
	// journal is thereafter a snapshot, never the sole authority for a replay key.
	for _, record := range live {
		if err := commitWAL(w.wal, record, nowUnix, w.maxWAL); err != nil {
			_ = w.f.Close()
			return nil, nil, fmt.Errorf("replay journal %s: importing live record into WAL: %w", path, err)
		}
	}
	if hasPending {
		// Complete an interrupted append before returning the writer. Rewrite
		// keeps the recovery crash-atomic: until its rename is durable, the
		// pending record remains the authority that makes a restart fail closed.
		if err := w.replace(live); err != nil {
			_ = w.f.Close()
			return nil, nil, fmt.Errorf("replay journal %s: recovering pending record: %w", path, err)
		}
		if err := w.clearPending(); err != nil {
			_ = w.f.Close()
			return nil, nil, fmt.Errorf("replay journal %s: completing pending-record recovery: %w", path, err)
		}
	}
	closeWALOnErr = false
	return live, w, nil
}

func encodeRecord(r Record) [RecordSize]byte {
	var rec [RecordSize]byte
	copy(rec[:32], r.Key[:])
	binary.BigEndian.PutUint64(rec[32:], uint64(r.Expiry))
	return rec
}

func decodeRecord(raw []byte) Record {
	var r Record
	copy(r.Key[:], raw[:32])
	r.Expiry = int64(binary.BigEndian.Uint64(raw[32:40]))
	return r
}

func appendOrReplaceRecord(records []Record, pending Record) []Record {
	for i := range records {
		if records[i].Key == pending.Key {
			if records[i].Expiry < pending.Expiry {
				records[i] = pending
			}
			return records
		}
	}
	return append(records, pending)
}

func readPending(path string) (Record, bool, error) {
	li, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("replay journal pending record %s: lstat: %w", path, err)
	}
	if err := checkJournalFile(path, li); err != nil {
		return Record{}, false, err
	}
	if li.Size() != RecordSize {
		return Record{}, false, &RefusedError{Path: path, Why: fmt.Sprintf(
			"is %d bytes, not one complete %d-byte pending record", li.Size(), RecordSize)}
	}
	f, err := os.Open(path)
	if err != nil {
		return Record{}, false, fmt.Errorf("replay journal pending record %s: open: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Record{}, false, fmt.Errorf("replay journal pending record %s: stat after open: %w", path, err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(fi, after) {
		return Record{}, false, &RefusedError{Path: path, Why: "was changed while it was being opened; refusing rather than trusting a raced pending record"}
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return Record{}, false, fmt.Errorf("replay journal pending record %s: read: %w", path, err)
	}
	if len(raw) != RecordSize {
		return Record{}, false, &RefusedError{Path: path, Why: fmt.Sprintf(
			"changed size while being read (%d bytes, want %d)", len(raw), RecordSize)}
	}
	return decodeRecord(raw), true, nil
}

func oversizeRefusal(path string, size int64) error {
	return &RefusedError{Path: path, Why: fmt.Sprintf(
		"is %d bytes, above the %d-byte bound (%d records plus slack); the journal is "+
			"refused before any of it is read", size, MaxFileBytes, MaxRecords)}
}

// openJournalFile returns the journal fd, following nothing.
//
// The path is Lstat'd first and refused unless it is a regular file. Between
// that check and the open an attacker can still swap the name, so the opened
// fd is bound back to the name afterwards and refused on any identity
// mismatch. On the create path O_EXCL refuses to follow anything that appears
// concurrently instead of creating the file.
func openJournalFile(path string) (*os.File, error) {
	if li, err := os.Lstat(path); err == nil {
		if err := checkJournalFile(path, li); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
		if err != nil {
			return nil, err
		}
		ff, ferr := f.Stat()
		after, aerr := os.Lstat(path)
		switch {
		case ferr != nil:
			f.Close()
			return nil, ferr
		case aerr != nil:
			f.Close()
			return nil, &RefusedError{Path: path, Why: "could not be re-verified after it was opened; refusing rather than trusting an open followed from a raced path"}
		case !os.SameFile(ff, after):
			f.Close()
			return nil, &RefusedError{Path: path, Why: "was swapped between the check and the open; refusing rather than following whatever was put in its place"}
		}
		return f, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0o640)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, &RefusedError{Path: path, Why: "appeared concurrently with creation; refusing rather than opening whatever was put in its place"}
		}
		return nil, err
	}
	// Pin the mode to exactly 0640 rather than trust the umask to yield one
	// of the two allowed modes: a fresh journal must always be loadable.
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return nil, fmt.Errorf("replay journal %s: chmod 0640 after create: %w", path, err)
	}
	return f, nil
}

// checkJournalFile applies the whole trust policy to one stat result: regular
// file, euid owner, and exactly mode 0600 or 0640.
func checkJournalFile(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return &RefusedError{Path: path, Why: "is a symbolic link; the journal must be the file itself, because a prune or cap rewrite would truncate and overwrite whatever the link points at"}
	}
	if !fi.Mode().IsRegular() {
		return &RefusedError{Path: path, Why: fmt.Sprintf("is not a regular file (mode %v)", fi.Mode())}
	}
	return checkJournalOwnerMode(path, fi)
}

// TornError reports a journal whose length is not a whole number of records.
type TornError struct {
	Path  string
	Bytes int
}

func (e *TornError) Error() string {
	return fmt.Sprintf("replay journal %s is %d bytes, not a whole number of %d-byte records; "+
		"a torn journal must not silently weaken the replay window, so the gateway refuses "+
		"to start on it (truncate or restore the file)", e.Path, e.Bytes, RecordSize)
}

// Append writes one record and fsyncs.
func (w *Writer) Append(r Record, nowUnix int64) error {
	if w.broken != nil {
		return w.broken
	}
	if err := commitWAL(w.wal, r, nowUnix, w.maxWAL); err != nil {
		return w.admitFailure(fmt.Errorf("replay journal %s: commit immutable WAL record: %w", w.path, err))
	}
	if err := w.stagePending(r); err != nil {
		return w.admitFailure(err)
	}
	atAppendStage(1)
	if err := w.verifyPathIdentity(); err != nil {
		return w.fail(err)
	}
	rec := encodeRecord(r)
	n, err := w.f.Write(rec[:])
	if err != nil {
		return w.fail(fmt.Errorf("replay journal %s: append: %w", w.path, err))
	}
	if n != len(rec) {
		return w.fail(fmt.Errorf("replay journal %s: short append: wrote %d of %d bytes", w.path, n, len(rec)))
	}
	if err := w.f.Sync(); err != nil {
		return w.fail(fmt.Errorf("replay journal %s: sync appended record: %w", w.path, err))
	}
	atAppendStage(2)
	// Rebind the pathname after the durable append and before clearing the
	// pending recovery record. If the name was replaced during the append, the
	// pending record remains durable and admission fails. A restart can then
	// recover the record into the current path instead of answering a handshake
	// whose replay key exists only on an unlinked descriptor.
	if err := w.verifyPathIdentity(); err != nil {
		return w.fail(err)
	}
	atAppendStage(3)
	// Keep the pending record authoritative through the last observable stage
	// before removal. A pathname change at that boundary fails sticky and leaves
	// the complete record for restart recovery.
	if err := w.verifyPathIdentity(); err != nil {
		return w.fail(err)
	}
	if err := w.clearPending(); err != nil {
		return w.fail(err)
	}
	return nil
}

func (w *Writer) verifyPathIdentity() error {
	opened, err := w.f.Stat()
	if err != nil {
		return fmt.Errorf("replay journal %s: stat open writer: %w", w.path, err)
	}
	current, err := os.Lstat(w.path)
	if err != nil {
		return fmt.Errorf("replay journal %s: revalidate pathname: %w", w.path, err)
	}
	if err := checkJournalFile(w.path, current); err != nil {
		return err
	}
	if !os.SameFile(opened, current) {
		return &RefusedError{Path: w.path, Why: "was replaced while a proven initiation was being recorded; the durable pending record is retained and admission is refused"}
	}
	return nil
}

// VerifyPath confirms that both live pathnames still name the exact journal
// file and WAL directory descriptors owned by this writer. It accepts the
// writer's own crash-atomic Rewrite replacement because replace adopts the
// newly published journal descriptor before this check can run.
func (w *Writer) VerifyPath() error {
	if w == nil {
		return nil
	}
	if w.broken != nil {
		return w.broken
	}
	if err := verifyWALDirPath(w.wal); err != nil {
		return w.fail(err)
	}
	if err := w.verifyPathIdentity(); err != nil {
		return w.fail(err)
	}
	return nil
}

// Close releases the journal descriptor. A closed Writer cannot be reused;
// any later Append fails and leaves its already-durable pending record for
// restart recovery.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	var first error
	if w.f != nil {
		first = w.f.Close()
	}
	if err := w.wal.close(); first == nil {
		first = err
	}
	return first
}

func (w *Writer) stagePending(r Record) error {
	if _, err := os.Lstat(w.pending); err == nil {
		return fmt.Errorf("replay journal %s: canonical pending record already exists", w.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replay journal %s: inspect pending record: %w", w.path, err)
	}
	temp := pendingTempPath(w.path)
	pf, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("replay journal %s: create hidden pending temp: %w", w.path, err)
	}
	published := false
	defer func() {
		_ = pf.Close()
		if !published {
			_ = os.Remove(temp)
		}
	}()
	if err := pf.Chmod(0o640); err != nil {
		return fmt.Errorf("replay journal %s: chmod hidden pending temp: %w", w.path, err)
	}
	atPendingPublishStage(1)
	rec := encodeRecord(r)
	if err := pendingRecordWrite(pf, rec[:]); err != nil {
		return fmt.Errorf("replay journal %s: write complete hidden pending temp: %w", w.path, err)
	}
	atPendingPublishStage(2)
	if err := pf.Sync(); err != nil {
		return fmt.Errorf("replay journal %s: sync hidden pending temp: %w", w.path, err)
	}
	if err := verifyCompleteRecordFile(temp, pf); err != nil {
		return fmt.Errorf("replay journal %s: verify hidden pending temp metadata: %w", w.path, err)
	}
	atPendingPublishStage(3)
	if err := verifyCompleteRecordFile(temp, pf); err != nil {
		return fmt.Errorf("replay journal %s: reverify hidden pending temp metadata before publication: %w", w.path, err)
	}
	if err := pf.Close(); err != nil {
		return fmt.Errorf("replay journal %s: close hidden pending temp: %w", w.path, err)
	}
	if err := renameNoReplace(temp, w.pending); err != nil {
		return fmt.Errorf("replay journal %s: atomically publish pending record: %w", w.path, err)
	}
	published = true
	atPendingPublishStage(4)
	if err := syncDir(w.dir); err != nil {
		return fmt.Errorf("replay journal %s: sync directory after publishing pending record: %w", w.path, err)
	}
	atPendingPublishStage(5)
	got, ok, err := readPending(w.pending)
	if err != nil || !ok || got != r {
		if err != nil {
			return fmt.Errorf("replay journal %s: verify published pending record: %w", w.path, err)
		}
		return &RefusedError{Path: w.pending, Why: "did not retain the exact published pending record"}
	}
	atPendingPublishStage(6)
	return nil
}

func pendingTempPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+pendingSuffix+".tmp")
}

func removeStalePendingTemp(path string) error {
	temp := pendingTempPath(path)
	info, err := os.Lstat(temp)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("replay journal %s: inspect stale hidden pending temp: %w", path, err)
	}
	if err := checkJournalFile(temp, info); err != nil {
		return err
	}
	if err := os.Remove(temp); err != nil {
		return fmt.Errorf("replay journal %s: remove stale hidden pending temp: %w", path, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("replay journal %s: sync stale pending-temp cleanup: %w", path, err)
	}
	return nil
}

func (w *Writer) clearPending() error {
	if err := os.Remove(w.pending); err != nil {
		return fmt.Errorf("replay journal %s: remove committed pending record: %w", w.path, err)
	}
	if err := syncDir(w.dir); err != nil {
		return fmt.Errorf("replay journal %s: sync directory after clearing pending record: %w", w.path, err)
	}
	return nil
}

func (w *Writer) fail(err error) error {
	if w.broken == nil {
		w.broken = err
	}
	return w.broken
}

// admitFailure records integrity-compromising persist errors as sticky, and
// returns live-set capacity or pre-mutation ENOSPC without latching. Compact
// journal write/sync failures must keep using fail(): those can tear the
// snapshot, so new-handshake admission stays closed on that Writer.
func (w *Writer) admitFailure(err error) error {
	if isRetryableAdmissionError(err) {
		return err
	}
	return w.fail(err)
}

// Rewrite replaces the journal with exactly the given records. It is the
// prune-on-load and max-entries cap rewrite, and it is crash-safe: the new
// bytes go to a temp file in the SAME directory, are fsynced, and are renamed
// over the journal atomically, with the directory fsynced afterwards. A crash
// mid-rewrite leaves either the old whole journal or the new whole journal,
// never an empty or torn one.
func (w *Writer) Rewrite(records []Record, nowUnix int64) error {
	if w.broken != nil {
		return w.broken
	}
	for _, record := range records {
		if err := commitWAL(w.wal, record, nowUnix, w.maxWAL); err != nil {
			return w.admitFailure(fmt.Errorf("replay journal %s: commit rewrite record to WAL: %w", w.path, err))
		}
	}
	walRecords, err := loadWAL(w.wal, nowUnix, w.maxWAL)
	if err != nil {
		return w.fail(fmt.Errorf("replay journal %s: load authoritative WAL for rewrite: %w", w.path, err))
	}
	merged := append([]Record(nil), records...)
	for _, record := range walRecords {
		merged = appendOrReplaceRecord(merged, record)
	}
	if len(merged) > w.maxWAL {
		return w.fail(&RefusedError{Path: w.wal.path, Why: fmt.Sprintf(
			"requires %d live records, above the %d-record cap", len(merged), w.maxWAL)})
	}
	if err := w.replace(merged); err != nil {
		return w.admitFailure(err)
	}
	return nil
}

// Err reports the first sticky append/rewrite failure, or nil. Live-set
// capacity and transient pre-mutation space errors are returned from
// Append/Rewrite without being stored here.
func (w *Writer) Err() error {
	if w == nil {
		return nil
	}
	return w.broken
}
