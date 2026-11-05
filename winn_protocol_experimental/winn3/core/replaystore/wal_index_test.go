package replaystore

import (
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"
)

func indexKey(i int) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return sha256.Sum256(b[:])
}

// A run of accepted handshakes must not rescan the WAL directory per append:
// with the live set indexed in memory, N appends inside one GC interval cost
// a bounded number of scans, and a gateway start with N live records costs
// O(N) record reads, not O(N^2).
func TestCommitWALDoesNotRescanPerAppend(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := filepath.Join(t.TempDir(), "replay.journal")
	_, w, err := OpenWithLimit(path, now, MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	const n = 500
	before := walScans.Load()
	for i := 0; i < n; i++ {
		if err := w.Append(Record{Key: indexKey(i), Expiry: now.Unix() + 130}, now.Unix()); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if scans := walScans.Load() - before; scans > 2 {
		t.Fatalf("%d appends inside one GC interval performed %d directory scans, want at most 2", n, scans)
	}
	// The index must still refuse a duplicate key's shorter expiry and accept
	// a longer one, exactly as a rescan would.
	if err := w.Append(Record{Key: indexKey(0), Expiry: now.Unix() + 100}, now.Unix()); err != nil {
		t.Fatalf("shorter duplicate: %v", err)
	}
	if err := w.Append(Record{Key: indexKey(0), Expiry: now.Unix() + 200}, now.Unix()); err != nil {
		t.Fatalf("longer duplicate: %v", err)
	}
	live, err := loadWAL(w.wal, now.Unix(), MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != n {
		t.Fatalf("live WAL holds %d records, want %d", len(live), n)
	}
	for _, r := range live {
		if r.Key == indexKey(0) && r.Expiry != now.Unix()+200 {
			t.Fatalf("superseded record kept expiry %d, want %d", r.Expiry, now.Unix()+200)
		}
	}
	_ = w.Close()

	// Gateway start with n live records: one scan at Open, one for the
	// prune-on-load rewrite core performs, never one per imported record.
	before = walScans.Load()
	start := time.Now()
	live, w2, err := OpenWithLimit(path, now, MaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	// The compact journal keeps every appended record (the two duplicate
	// appends above included) and core collapses them by key; count keys.
	keys := make(map[[32]byte]bool, len(live))
	for _, r := range live {
		keys[r.Key] = true
	}
	if len(keys) != n {
		t.Fatalf("reopened live set holds %d keys, want %d", len(keys), n)
	}
	if scans := walScans.Load() - before; scans > 2 {
		t.Fatalf("open with %d live records performed %d directory scans, want at most 2", n, scans)
	}
	t.Logf("open with %d live records took %v", n, time.Since(start))
}

// Capacity is still enforced from the index, and expiry still frees a slot:
// at the cap, commitWAL rescans so expired records are removed before the
// admission is refused.
func TestCommitWALCapacityStillUsesExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := filepath.Join(t.TempDir(), "replay.journal")
	const cap = 8
	_, w, err := OpenWithLimit(path, now, cap)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < cap; i++ {
		if err := w.Append(Record{Key: indexKey(i), Expiry: now.Unix() + 10 + int64(i)}, now.Unix()); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	err = w.Append(Record{Key: indexKey(cap), Expiry: now.Unix() + 100}, now.Unix())
	if !isRetryableAdmissionError(err) {
		t.Fatalf("append at capacity: got %v, want a retryable ErrCapacity", err)
	}
	if w.Err() != nil {
		t.Fatalf("capacity refusal latched the writer: %v", w.Err())
	}
	// The records expiring at now+10, now+11 and now+12 are expired at
	// now+12 (expiry <= now); a later append must see the freed slots
	// through the capacity rescan.
	later := now.Unix() + 12
	if err := w.Append(Record{Key: indexKey(cap), Expiry: later + 100}, later); err != nil {
		t.Fatalf("append after expiry: %v", err)
	}
	live, err := loadWAL(w.wal, later, cap)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != cap-2 {
		t.Fatalf("live WAL holds %d records after expiry GC, want %d", len(live), cap-2)
	}
}
