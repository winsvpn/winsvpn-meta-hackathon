package replaystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

const walSuffix = ".wal"

type walDirectory struct {
	path   string
	handle *os.File
	// live is the in-memory index of the records on disk, keyed by replay
	// key with their expiry, as loadWAL last scanned the directory plus every
	// commit since. commitWAL consults it instead of rescanning the directory
	// for every accepted handshake, so one handshake costs O(1) file work
	// whatever the live set holds. nil until the first loadWAL.
	live map[[32]byte]int64
	// nextGC is the unix second at or after which commitWAL rescans the
	// directory (loadWAL) to remove expired records before it checks
	// capacity. Expired records therefore stay on disk for at most
	// walGCInterval past their expiry; they are never consulted as replay
	// authority after it.
	nextGC int64
}

// walGCInterval bounds how long commitWAL goes between directory rescans. A
// rescan is also forced whenever the index reports the live set at capacity,
// so expiry can always free a slot before an admission is refused.
const walGCInterval = 60

// walScans counts directory rescans (loadWAL). It is a test seam only: the
// regression test for the per-handshake scan pins that a run of appends
// costs a bounded number of scans, not one per append.
var walScans atomic.Uint64

// walRecordWrite and walPublishStage are deterministic fault seams for this
// package's tests. Production keeps the default writer and a nil stage hook.
var walRecordWrite = writeFull
var walPublishStage func(stage int)
var walTempSequence atomic.Uint64
var walParentSync = syncDir

func atWALPublishStage(stage int) {
	if walPublishStage != nil {
		walPublishStage(stage)
	}
}

func walRecordName(r Record) string {
	return fmt.Sprintf("v1-%016x-%x.rec", uint64(r.Expiry), r.Key)
}

func openWALDir(path string) (*walDirectory, error) {
	dir := path + walSuffix
	created := false
	if err := os.Mkdir(dir, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("replay WAL %s: create directory: %w", dir, err)
		}
	} else {
		created = true
	}
	if created {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("replay WAL %s: chmod 0700: %w", dir, err)
		}
		if err := walParentSync(filepath.Dir(dir)); err != nil {
			return nil, fmt.Errorf("replay WAL %s: sync parent after create: %w", dir, err)
		}
	}
	before, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("replay WAL %s: lstat: %w", dir, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, &RefusedError{Path: dir, Why: "is not the owner-only WAL directory"}
	}
	if err := checkWALDirOwnerMode(dir, before); err != nil {
		return nil, err
	}
	handle, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("replay WAL %s: open directory: %w", dir, err)
	}
	opened, statErr := handle.Stat()
	after, nameErr := os.Lstat(dir)
	if statErr != nil || nameErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		_ = handle.Close()
		return nil, &RefusedError{Path: dir, Why: "changed while its stable directory descriptor was opened"}
	}
	return &walDirectory{path: dir, handle: handle}, nil
}

func (dir *walDirectory) close() error {
	if dir == nil || dir.handle == nil {
		return nil
	}
	return dir.handle.Close()
}

func verifyWALDirPath(dir *walDirectory) error {
	opened, err := dir.handle.Stat()
	if err != nil {
		return fmt.Errorf("replay WAL %s: stat stable directory: %w", dir.path, err)
	}
	current, err := os.Lstat(dir.path)
	if err != nil {
		return fmt.Errorf("replay WAL %s: revalidate pathname: %w", dir.path, err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(opened, current) {
		return &RefusedError{Path: dir.path, Why: "was replaced while the stable WAL directory was active"}
	}
	return checkWALDirOwnerMode(dir.path, current)
}

func loadWAL(dir *walDirectory, nowUnix int64, maxLive int) ([]Record, error) {
	if maxLive < 1 || maxLive > MaxRecords {
		return nil, fmt.Errorf("replay WAL %s: invalid physical record cap %d", dir.path, maxLive)
	}
	if err := verifyWALDirPath(dir); err != nil {
		return nil, err
	}
	if _, err := dir.handle.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("replay WAL %s: rewind directory: %w", dir.path, err)
	}
	entries, err := dir.handle.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("replay WAL %s: read stable directory: %w", dir.path, err)
	}
	walScans.Add(1)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	type namedRecord struct {
		name   string
		record Record
	}
	// Keep exactly one physical record per replay key. A duplicate with a
	// shorter expiry is not useful replay authority, but it would otherwise
	// consume physical capacity forever. Expired and superseded records are
	// collected before the cap is enforced.
	best := make(map[[32]byte]namedRecord, min(len(entries), maxLive))
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".tmp-") {
			if err := removeWALName(dir, name); err != nil {
				return nil, fmt.Errorf("replay WAL %s: remove uncommitted temp: %w", filepath.Join(dir.path, name), err)
			}
			removed = true
			continue
		}
		if strings.Contains(name, "/") || !strings.HasPrefix(name, "v1-") || !strings.HasSuffix(name, ".rec") {
			return nil, &RefusedError{Path: filepath.Join(dir.path, name), Why: "is not a canonical immutable WAL record"}
		}
		record, err := readWALName(dir, name)
		if err != nil {
			return nil, err
		}
		if name != walRecordName(record) {
			return nil, &RefusedError{Path: filepath.Join(dir.path, name), Why: "filename does not bind its record key and expiry"}
		}
		if record.Expiry <= nowUnix {
			if err := removeWALName(dir, name); err != nil {
				return nil, fmt.Errorf("replay WAL %s: remove expired record: %w", filepath.Join(dir.path, name), err)
			}
			removed = true
			continue
		}
		if prior, ok := best[record.Key]; ok {
			remove := name
			if record.Expiry > prior.record.Expiry {
				remove = prior.name
				best[record.Key] = namedRecord{name: name, record: record}
			}
			if err := removeWALName(dir, remove); err != nil {
				return nil, fmt.Errorf("replay WAL %s: remove superseded record: %w", filepath.Join(dir.path, remove), err)
			}
			removed = true
			continue
		}
		best[record.Key] = namedRecord{name: name, record: record}
	}
	if removed {
		if err := syncWALDir(dir); err != nil {
			return nil, fmt.Errorf("replay WAL %s: sync after GC: %w", dir.path, err)
		}
	}
	if len(best) > maxLive {
		return nil, &RefusedError{Path: dir.path, Why: fmt.Sprintf(
			"holds %d live physical records after expired-record GC, above the %d-record cap",
			len(best), maxLive)}
	}
	live := make([]Record, 0, len(best))
	index := make(map[[32]byte]int64, len(best))
	for key, named := range best {
		live = append(live, named.record)
		index[key] = named.record.Expiry
	}
	sort.Slice(live, func(i, j int) bool { return walRecordName(live[i]) < walRecordName(live[j]) })
	dir.live = index
	dir.nextGC = nowUnix + walGCInterval
	return live, nil
}

func commitWAL(dir *walDirectory, record Record, nowUnix int64, maxLive int) error {
	if err := verifyWALDirPath(dir); err != nil {
		return err
	}
	// Rescan the directory only when the index is cold, when the GC interval
	// has elapsed, or when the index says the live set is full and this key
	// needs a new slot (so that expired records are removed before capacity
	// is refused). Every other commit is answered from the index.
	scanned := false
	if dir.live == nil || nowUnix >= dir.nextGC {
		if _, err := loadWAL(dir, nowUnix, maxLive); err != nil {
			return err
		}
		scanned = true
	}
	expiry, held := dir.live[record.Key]
	if !held && !scanned && len(dir.live) >= maxLive {
		// A key the index already holds never needs a slot, so it never pays
		// for this rescan: Rewrite and Open commit every live record, all of
		// them held, and a rescan per held key made both O(N^2) in record
		// reads whenever the live set sat at the cap.
		if _, err := loadWAL(dir, nowUnix, maxLive); err != nil {
			return err
		}
		expiry, held = dir.live[record.Key]
	}
	var superseded *Record
	if held {
		if expiry >= record.Expiry {
			return nil
		}
		old := Record{Key: record.Key, Expiry: expiry}
		superseded = &old
	}
	if superseded == nil && len(dir.live) >= maxLive {
		return fmt.Errorf("replay journal %s: reached the %d-record physical WAL capacity after expired-record GC: %w",
			dir.path, maxLive, ErrCapacity)
	}
	if err := commitWALName(dir, walRecordName(record), record); err != nil {
		return err
	}
	dir.live[record.Key] = record.Expiry
	if superseded != nil {
		if err := removeWALName(dir, walRecordName(*superseded)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("replay WAL %s: remove superseded committed record: %w", dir.path, err)
		}
		if err := syncWALDir(dir); err != nil {
			return fmt.Errorf("replay WAL %s: sync superseded-record cleanup: %w", dir.path, err)
		}
	}
	return verifyWALDirPath(dir)
}
