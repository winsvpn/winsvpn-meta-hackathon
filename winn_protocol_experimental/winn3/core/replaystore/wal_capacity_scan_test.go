package replaystore

import (
	"path/filepath"
	"testing"
)

// At the physical cap, commitWAL forces a directory rescan so expired records
// can free a slot before an admission is refused. That rescan is only useful
// for a key the index does not already hold: a commit of a held key never
// needs a slot. Rewrite (core's compaction and prune-on-load) and Open's
// import loop commit every live record, all of them already held, so with the
// live set at the cap a rescan per held key made both O(N^2) in record-file
// reads. Gemini L06 F-2 / Muse L06 F-7 residual after Mythos L06 F-1.
func TestCommitWALAtCapacitySkipsRescanForHeldKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.journal")
	nowUnix := testJournalNow.Unix()
	const n = 64
	records := testRecords("cap-held", n, nowUnix+3600)

	before := walScans.Load()
	_, w, err := OpenWithLimit(path, testJournalNow, n)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range records {
		if err := w.Append(r, nowUnix); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	afterAppends := walScans.Load() - before
	if err := w.Rewrite(records, nowUnix); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	afterRewrite := walScans.Load() - before
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	live, reopened, err := OpenWithLimit(path, testJournalNow, n)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if len(live) != n {
		t.Fatalf("reopened %d live records, want %d", len(live), n)
	}
	total := walScans.Load() - before
	t.Logf("scans: open+appends=%d, +rewrite=%d, +reopen=%d", afterAppends, afterRewrite, total)
	// Open 1, one capacity rescan at most during the appends, Rewrite's
	// authoritative reload 1, reopen 1.
	if total > 4 {
		t.Fatalf("Open + %d appends + Rewrite + reopen at the cap performed %d directory scans, want at most 4", n, total)
	}
	// A new key at the cap is still refused after the forced rescan, and the
	// refusal is the retryable capacity error.
	extra := testRecords("cap-new", 1, nowUnix+3600)[0]
	if err := reopened.Append(extra, nowUnix); !isRetryableAdmissionError(err) {
		t.Fatalf("append of a new key at the cap: got %v, want retryable ErrCapacity", err)
	}
}
