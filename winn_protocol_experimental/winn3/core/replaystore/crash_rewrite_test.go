//go:build !windows

package replaystore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRewriteCrashMidFlightNeverEmptiesTheJournal is the auditor's scenario
// turned into a deterministic regression pin. The old prune/cap code truncated
// the journal in place and rewrote it, so a kill between the truncate and the
// first write left an empty journal that the next start loaded silently as a
// wiped replay window. The new code writes a same-directory temp, fsyncs it,
// renames it over the journal and fsyncs the directory; the rewriteStage hook
// lets a subprocess kill itself at each of the three exact instants along
// that path, and the parent proves the journal afterwards is a whole file:
// the old records before the rename, the new records after it, nonzero in
// every case, and always loadable.
func TestRewriteCrashMidFlightNeverEmptiesTheJournal(t *testing.T) {
	nowUnix := int64(1_700_000_000)
	aRecs := testRecords("old", 3, nowUnix+3600)
	bRecs := testRecords("new", 7, nowUnix+3600)
	walOld := append([]Record(nil), aRecs...)
	sort.Slice(walOld, func(i, j int) bool {
		return walRecordName(walOld[i]) < walRecordName(walOld[j])
	})
	committedUnion := append(append([]Record(nil), bRecs...), walOld...)

	for stage := 1; stage <= 3; stage++ {
		t.Run(fmt.Sprintf("stage-%d", stage), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "replay.journal")
			_, w, err := Open(path, time.Unix(nowUnix, 0))
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range aRecs {
				if err := w.Append(r, nowUnix); err != nil {
					t.Fatal(err)
				}
			}
			seed := testRecordBytes(aRecs)
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, seed) {
				t.Fatalf("seed journal is not the exact nonzero set (err %v, %d bytes)", err, len(got))
			}

			cmd := exec.Command(os.Args[0], "-test.run=^TestRewriteCrashChild$")
			cmd.Env = append(os.Environ(),
				"WINN3_CRASH_CHILD=1",
				"WINN3_CRASH_STAGE="+strconv.Itoa(stage),
				"WINN3_CRASH_JOURNAL="+path,
				"WINN3_CRASH_NOW="+strconv.FormatInt(nowUnix, 10),
			)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			childPID := cmd.Process.Pid
			tempName := filepath.Join(dir, fmt.Sprintf(".journal.tmp.%d", childPID))
			waitErr := cmd.Wait()
			if ee, ok := waitErr.(*exec.ExitError); !ok || ee.ExitCode() != -1 {
				t.Fatalf("the crash child did not die by a signal (err %v, stderr %q); its kill landed outside the rewrite", waitErr, stderr.String())
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("after the simulated crash the journal cannot be read: %v", err)
			}
			if len(raw) == 0 {
				t.Fatalf("after the simulated crash the journal is EMPTY while %d records were on disk before it; that empty file is the silently weakened gate this rewrite exists to kill", len(aRecs))
			}
			if len(raw)%RecordSize != 0 {
				t.Fatalf("after the simulated crash the journal is %d bytes, not a whole number of records", len(raw))
			}
			want := seed
			if stage >= 2 {
				want = testRecordBytes(committedUnion)
			}
			if !bytes.Equal(raw, want) {
				t.Fatalf("after the simulated crash the journal is %d bytes and neither the whole old set (%d bytes) nor the committed union (%d bytes)",
					len(raw), len(seed), len(testRecordBytes(committedUnion)))
			}

			if stage == 1 {
				// The kill landed exactly where the hook says: the complete
				// new set sits in the finished temp, and the journal has not
				// been renamed over yet.
				tf, err := os.ReadFile(tempName)
				if err != nil {
					t.Fatalf("a stage-1 kill must leave the finished temp file behind: %v", err)
				}
				if !bytes.Equal(tf, testRecordBytes(committedUnion)) {
					t.Fatalf("the stage-1 temp file is %d bytes, want the complete %d-byte committed union", len(tf), len(testRecordBytes(committedUnion)))
				}
			} else if _, err := os.Lstat(tempName); err == nil {
				t.Fatalf("after the stage-%d kill the temp file still exists; the rename should have consumed it", stage)
			}

			// The crash survivor must load, and a post-crash append must land
			// in the surviving file.
			now := time.Unix(nowUnix, 0)
			_, w2, err := Open(path, now)
			if err != nil {
				t.Fatalf("the journal that survived the crash does not load: %v", err)
			}
			post := testRecords("post", 1, nowUnix+3600)[0]
			if err := w2.Append(post, nowUnix); err != nil {
				t.Fatal(err)
			}
			wantPlusPost := append(append([]byte(nil), want...), testRecordBytes([]Record{post})...)
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, wantPlusPost) {
				t.Fatalf("the post-crash append did not land in the surviving journal file (%d bytes, want %d)", len(got), len(wantPlusPost))
			}
		})
	}
}

// TestRewriteCrashChild is the killed subprocess: it opens the seeded
// journal, points the stage hook at a SIGKILL and rewrites a new record set.
// It is reached only through the -test.run filter above, so a normal test run
// skips it.
func TestRewriteCrashChild(t *testing.T) {
	if os.Getenv("WINN3_CRASH_CHILD") != "1" {
		t.Skip("spawned only by TestRewriteCrashMidFlightNeverEmptiesTheJournal")
	}
	stage, err := strconv.Atoi(os.Getenv("WINN3_CRASH_STAGE"))
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("WINN3_CRASH_JOURNAL")
	nowUnix, err := strconv.ParseInt(os.Getenv("WINN3_CRASH_NOW"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	rewriteStage = func(s int) {
		if s == stage {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	_, w, err := Open(path, time.Unix(nowUnix, 0))
	if err != nil {
		t.Fatal(err) // a non-signal exit is refused by the parent
	}
	if err := w.Rewrite(testRecords("new", 7, nowUnix+3600), nowUnix); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("the stage-%d hook never fired; the rewrite completed without dying", stage)
}

func TestRecordPublicationCrashStagesNeverLeaveMalformedCanonicalRecord(t *testing.T) {
	nowUnix := int64(1_700_000_000)
	record := testRecords("publication-crash", 1, nowUnix+3600)[0]
	for _, kind := range []string{"wal", "pending"} {
		for stage := 1; stage <= 5; stage++ {
			t.Run(fmt.Sprintf("%s-stage-%d", kind, stage), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "replay.journal")
				_, seed, err := OpenWithLimit(path, time.Unix(nowUnix, 0), 2)
				if err != nil {
					t.Fatal(err)
				}
				if err := seed.Close(); err != nil {
					t.Fatal(err)
				}

				cmd := exec.Command(os.Args[0], "-test.run=^TestRecordPublicationCrashChild$")
				cmd.Env = append(os.Environ(),
					"WINN3_RECORD_CRASH_CHILD=1",
					"WINN3_RECORD_CRASH_KIND="+kind,
					"WINN3_RECORD_CRASH_STAGE="+strconv.Itoa(stage),
					"WINN3_RECORD_CRASH_JOURNAL="+path,
					"WINN3_RECORD_CRASH_NOW="+strconv.FormatInt(nowUnix, 10),
				)
				var stderr strings.Builder
				cmd.Stderr = &stderr
				if err := cmd.Run(); err == nil {
					t.Fatalf("crash child completed at %s stage %d", kind, stage)
				} else if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != -1 {
					t.Fatalf("crash child did not die by signal: err=%v stderr=%q", err, stderr.String())
				}

				canonical := filepath.Join(path+walSuffix, walRecordName(record))
				if kind == "pending" {
					canonical = path + pendingSuffix
				}
				if info, err := os.Lstat(canonical); err == nil {
					if !info.Mode().IsRegular() || info.Size() != RecordSize {
						t.Fatalf("%s crash stage %d left malformed canonical %s: mode=%v size=%d",
							kind, stage, canonical, info.Mode(), info.Size())
					}
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}

				live, recovered, err := OpenWithLimit(path, time.Unix(nowUnix, 0), 2)
				if err != nil {
					t.Fatalf("restart after %s crash stage %d: %v", kind, stage, err)
				}
				if err := recovered.Close(); err != nil {
					t.Fatal(err)
				}
				wantLive := 0
				if kind == "pending" || stage >= 4 {
					wantLive = 1
				}
				if len(live) != wantLive {
					t.Fatalf("restart after %s crash stage %d loaded %d records, want %d", kind, stage, len(live), wantLive)
				}
				if wantLive == 1 && live[0] != record {
					t.Fatalf("restart after %s crash stage %d loaded %#v, want %#v", kind, stage, live, record)
				}
				if _, err := os.Lstat(pendingTempPath(path)); !os.IsNotExist(err) {
					t.Fatalf("restart left hidden pending temp after %s crash stage %d: %v", kind, stage, err)
				}
				entries, err := os.ReadDir(path + walSuffix)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".tmp-") {
						t.Fatalf("restart left hidden WAL temp %q after %s crash stage %d", entry.Name(), kind, stage)
					}
				}
			})
		}
	}
}

func TestRecordPublicationCrashChild(t *testing.T) {
	if os.Getenv("WINN3_RECORD_CRASH_CHILD") != "1" {
		t.Skip("spawned only by TestRecordPublicationCrashStagesNeverLeaveMalformedCanonicalRecord")
	}
	stage, err := strconv.Atoi(os.Getenv("WINN3_RECORD_CRASH_STAGE"))
	if err != nil {
		t.Fatal(err)
	}
	nowUnix, err := strconv.ParseInt(os.Getenv("WINN3_RECORD_CRASH_NOW"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	killAt := func(s int) {
		if s == stage {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	switch os.Getenv("WINN3_RECORD_CRASH_KIND") {
	case "wal":
		walPublishStage = killAt
	case "pending":
		pendingPublishStage = killAt
	default:
		t.Fatal("unknown crash kind")
	}
	path := os.Getenv("WINN3_RECORD_CRASH_JOURNAL")
	_, w, err := OpenWithLimit(path, time.Unix(nowUnix, 0), 2)
	if err != nil {
		t.Fatal(err)
	}
	record := testRecords("publication-crash", 1, nowUnix+3600)[0]
	if err := w.Append(record, nowUnix); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("the %s stage-%d hook never fired", os.Getenv("WINN3_RECORD_CRASH_KIND"), stage)
}
