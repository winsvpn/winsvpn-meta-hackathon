//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRemediationRunnerExecutesVerifiedDescriptorAfterPathSwap(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runner.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf old\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	opened, _, err := openAndDigestPinnedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	sealedPath, sealedFile, cleanup, err := sealRunnerCopy(root, opened, mustDigest(t, path))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer func() { _ = sealedFile.Close() }()
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(
		replacement, []byte("#!/bin/sh\nprintf new\n"), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	runner := &execRunner{
		runnerPath: sealedPath, procRoot: "/proc",
		sampleInterval: time.Millisecond, childLog: io.Discard,
		killGrace: 10 * time.Second,
	}
	// The cycle timeout and kill grace are deliberately far beyond what the
	// instant printf needs: under a full-suite load the child's spawn, the
	// pipe drain and the reap can all be scheduled late, and none of them is
	// the property this test exists to prove.
	result, err := runner.RunCycle(context.Background(), CycleRequest{
		Sequence: 1, Readiness: ReadinessWarm, Timeout: 30 * time.Second,
		OutputLimit: 1024, WorkingDirectory: root, Environment: []string{"PATH=/usr/bin:/bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.StdoutTail) != "old" {
		t.Fatalf("executed %q, want verified descriptor bytes old", result.StdoutTail)
	}
}

func TestRemediationSealedRunnerPathABAIsBoundOrRefused(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "runner")
	if err := os.WriteFile(original, []byte("#!/bin/sh\nprintf sealed-old\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	opened, digest, err := openAndDigestPinnedFile(original)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	sealedPath, sealedFile, cleanup, err := sealRunnerCopy(root, opened, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer func() { _ = sealedFile.Close() }()
	if err := os.Chmod(filepath.Dir(sealedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(filepath.Dir(sealedPath), "replacement")
	if err := os.WriteFile(
		replacement, []byte("#!/bin/sh\nprintf sealed-new\n"), 0o500,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, sealedPath); err != nil {
		t.Fatal(err)
	}
	runner := &execRunner{
		runnerPath: sealedPath, runnerFile: sealedFile, procRoot: "/proc",
		sampleInterval: time.Millisecond, childLog: io.Discard,
		killGrace: 10 * time.Second,
	}
	if runtime.GOOS == "linux" {
		oldPrepare := cycleContainmentPreparer
		cycleContainmentPreparer = func(
			_, _ string, _ int64, _ bool,
		) (cycleContainment, error) {
			return supportedTestContainment{}, nil
		}
		defer func() { cycleContainmentPreparer = oldPrepare }()
	}
	result, err := runner.RunCycle(context.Background(), CycleRequest{
		Sequence: 1, Readiness: ReadinessWarm, Timeout: 30 * time.Second,
		OutputLimit: 1024, WorkingDirectory: root,
		Environment: []string{"PATH=/usr/bin:/bin"},
	})
	if runtime.GOOS != "linux" {
		if err == nil || !strings.Contains(err.Error(), "refusing pathname fallback") {
			t.Fatalf("non-Linux sealed pathname ABA was not refused: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(result.StdoutTail) != "sealed-old" {
		t.Fatalf("executed %q, want exact opened sealed inode", result.StdoutTail)
	}
}

type supportedTestContainment struct{}

func (supportedTestContainment) Configure(*exec.Cmd) error { return nil }
func (supportedTestContainment) Sample(string) (
	int64, int64, int64, bool, error,
) {
	return 1, 1, 1, true, nil
}
func (supportedTestContainment) TerminateAll() error { return nil }
func (supportedTestContainment) KillAll() error      { return nil }
func (supportedTestContainment) Finish() (CycleContainmentCleanup, error) {
	return nonApplicableContainmentCleanup(), nil
}

func mustDigest(t *testing.T, path string) string {
	t.Helper()
	digest, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestRemediationReplacingLockMarkerCannotAdmitSecondController(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	first, err := AcquireInstanceLock(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()
	marker := filepath.Join(state, "soak.lock")
	if err := os.Rename(marker, marker+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireInstanceLock(state)
	if second != nil {
		_ = second.Release()
	}
	if !errors.Is(err, errLockHeld) {
		t.Fatalf("replacement admitted second controller: %v", err)
	}
}

func TestRemediationReceiptRequiresLFAndExactDuplicateFreeMembers(t *testing.T) {
	build := func(t *testing.T) (string, []byte) {
		t.Helper()
		root := t.TempDir()
		log, err := OpenReceiptLog(root, "strict")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(validTestReceipt("strict", OutcomeSucceeded)); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "cycle-receipts.jsonl")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return path, raw
	}
	t.Run("missing LF", func(t *testing.T) {
		path, raw := build(t)
		if err := os.WriteFile(path, raw[:len(raw)-1], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReceiptLog(filepath.Dir(path), "strict"); err == nil ||
			!strings.Contains(err.Error(), "newline-terminated") {
			t.Fatalf("missing LF accepted: %v", err)
		}
	})
	t.Run("unknown member", func(t *testing.T) {
		path, raw := build(t)
		edited := strings.Replace(string(raw), `{"schema":`, `{"unknown":1,"schema":`, 1)
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReceiptLog(filepath.Dir(path), "strict"); err == nil ||
			!strings.Contains(err.Error(), "unknown JSON member") {
			t.Fatalf("unknown member accepted: %v", err)
		}
	})
	t.Run("duplicate member", func(t *testing.T) {
		path, raw := build(t)
		edited := strings.Replace(
			string(raw), `{"schema":`, `{"schema":"other","schema":`, 1,
		)
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReceiptLog(filepath.Dir(path), "strict"); err == nil ||
			!strings.Contains(err.Error(), "duplicate JSON member") {
			t.Fatalf("duplicate member accepted: %v", err)
		}
	})
}

func TestRemediationReceiptRejectsBrokenNonceLineage(t *testing.T) {
	root := t.TempDir()
	log, err := OpenReceiptLog(root, "lineage")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := log.Append(validTestReceipt("lineage", OutcomeSucceeded)); err != nil {
			t.Fatal(err)
		}
	}
	_ = log.Close()
	path := filepath.Join(root, "cycle-receipts.jsonl")
	lines := strings.Split(strings.TrimSpace(string(mustRead(t, path))), "\n")
	lines[1] = strings.Replace(
		lines[1], receiptTestNonce, "abcdefabcdefabcdefabcdefabcdefab", 1,
	)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiptLog(root, "lineage"); err == nil ||
		!strings.Contains(err.Error(), "nonce lineage changed") {
		t.Fatalf("broken nonce lineage accepted: %v", err)
	}
}

func TestRemediationCheckpointRequiresExactDuplicateFreePresence(t *testing.T) {
	build := func(t *testing.T) (*CheckpointStore, string, []byte) {
		t.Helper()
		state := filepath.Join(t.TempDir(), "state")
		store, err := OpenCheckpointStore(state)
		if err != nil {
			t.Fatal(err)
		}
		cfg := testConfig(t, t.TempDir())
		if _, err := store.Save(storedCheckpoint(cfg, testProvenance())); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(state, "checkpoint.json")
		return store, path, mustRead(t, path)
	}
	t.Run("duplicate envelope member", func(t *testing.T) {
		store, path, raw := build(t)
		edited := strings.Replace(
			string(raw), `{"schema":`, `{"schema":"other","schema":`, 1,
		)
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Load(); err == nil ||
			!strings.Contains(err.Error(), "duplicate JSON member") {
			t.Fatalf("duplicate checkpoint member accepted: %v", err)
		}
	})
	t.Run("missing body member with valid MAC", func(t *testing.T) {
		store, path, raw := build(t)
		var envelope checkpointEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(envelope.Body, &body); err != nil {
			t.Fatal(err)
		}
		delete(body, "resume_count")
		rewritten, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(rewritten)
		envelope.Body = rewritten
		envelope.ContentAddress = hex.EncodeToString(sum[:])
		envelope.MAC = hex.EncodeToString(
			store.authenticator(envelope.ContentAddress),
		)
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Load(); err == nil ||
			!strings.Contains(err.Error(), `required JSON member "resume_count"`) {
			t.Fatalf("missing checkpoint member accepted: %v", err)
		}
	})
}

func TestRemediationWriteAndDirectoryDurabilityFailuresPropagate(t *testing.T) {
	t.Run("short write", func(t *testing.T) {
		old := writeAllOperation
		writeAllOperation = func(writer io.Writer, data []byte) error {
			if len(data) > 0 {
				_, _ = writer.Write(data[:1])
			}
			return io.ErrShortWrite
		}
		defer func() { writeAllOperation = old }()
		path := filepath.Join(t.TempDir(), "state", "checkpoint")
		if err := atomicWrite(path, []byte("complete"), 0o600); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write was not propagated: %v", err)
		}
	})
	t.Run("receipt file sync", func(t *testing.T) {
		root := t.TempDir()
		log, err := OpenReceiptLog(root, "sync-fault")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = log.Close() }()
		old := syncFileOperation
		syncFileOperation = func(*os.File) error {
			return errors.New("injected receipt sync failure")
		}
		defer func() { syncFileOperation = old }()
		if _, err := log.Append(
			validTestReceipt("sync-fault", OutcomeSucceeded),
		); err == nil || !strings.Contains(err.Error(), "injected receipt sync failure") {
			t.Fatalf("receipt sync failure was ignored: %v", err)
		}
		if log.Count() != 0 {
			t.Fatal("receipt state advanced after sync failure")
		}
	})
	t.Run("secure checkpoint directory sync", func(t *testing.T) {
		state := filepath.Join(t.TempDir(), "state")
		store, err := OpenCheckpointStore(state)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		old := secureDirectorySyncOperation
		secureDirectorySyncOperation = func(*secureDirectory) error {
			return errors.New("injected secure directory sync failure")
		}
		defer func() { secureDirectorySyncOperation = old }()
		cfg := testConfig(t, t.TempDir())
		if _, err := store.Save(
			storedCheckpoint(cfg, testProvenance()),
		); err == nil || !strings.Contains(
			err.Error(), "injected secure directory sync failure",
		) {
			t.Fatalf("secure directory sync failure was ignored: %v", err)
		}
	})
	t.Run("directory sync open", func(t *testing.T) {
		old := atomicOpenDir
		atomicOpenDir = func(string) (*os.File, error) {
			return nil, errors.New("injected directory open failure")
		}
		defer func() { atomicOpenDir = old }()
		path := filepath.Join(t.TempDir(), "state", "checkpoint")
		if err := atomicWrite(path, []byte("complete"), 0o600); err == nil ||
			!strings.Contains(err.Error(), "injected directory open failure") {
			t.Fatalf("directory durability failure was ignored: %v", err)
		}
	})
}

func TestRemediationHardlinkedInputsAndLogsAreRefused(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "snapshot-file")
	link := filepath.Join(root, "snapshot-link")
	if err := os.WriteFile(original, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, link); err != nil {
		t.Fatal(err)
	}
	if _, err := fileDigest(original); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hardlinked snapshot input accepted: %v", err)
	}

	logDir := filepath.Join(root, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(logDir, "cycle.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := newRotatingLog(logDir, "cycle.log", 1024, 2); err == nil ||
		!strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hardlinked log accepted: %v", err)
	}
	if string(mustRead(t, outside)) != "sentinel" {
		t.Fatal("outside hardlink target was modified")
	}
}

func TestRemediationDirectoryReplacementIsRefusedByStableDescriptors(t *testing.T) {
	t.Run("checkpoint", func(t *testing.T) {
		root := t.TempDir()
		state := filepath.Join(root, "state")
		store, err := OpenCheckpointStore(state)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		if err := os.Rename(state, state+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := testConfig(t, t.TempDir())
		if _, err := store.Save(storedCheckpoint(cfg, testProvenance())); err == nil ||
			!strings.Contains(err.Error(), "changed device/inode identity") {
			t.Fatalf("replacement checkpoint directory accepted: %v", err)
		}
	})
	t.Run("receipt", func(t *testing.T) {
		root := t.TempDir()
		evidence := filepath.Join(root, "evidence")
		log, err := OpenReceiptLog(evidence, "replacement")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = log.Close() }()
		if err := os.Rename(evidence, evidence+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(evidence, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(
			validTestReceipt("replacement", OutcomeSucceeded),
		); err == nil || !strings.Contains(err.Error(), "changed device/inode identity") {
			t.Fatalf("replacement receipt directory accepted: %v", err)
		}
	})
	t.Run("rotating log", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "logs")
		log, err := newRotatingLog(directory, "cycle.log", 1024, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = log.Close() }()
		if err := os.Rename(directory, directory+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Write([]byte("must-not-write")); err == nil ||
			!strings.Contains(err.Error(), "changed device/inode identity") {
			t.Fatalf("replacement log directory accepted: %v", err)
		}
	})
}

func TestRemediationTailRetainsTerminalError(t *testing.T) {
	buffer := newBoundedBuffer(16)
	_, _ = buffer.Write([]byte(strings.Repeat("noise", 100)))
	_, _ = buffer.Write([]byte("TERMINAL-ERROR!!"))
	if got := string(buffer.Bytes()); got != "TERMINAL-ERROR!!" {
		t.Fatalf("tail retained %q", got)
	}
}

func TestRemediationProcessGroupAccountingIncludesDescendantOnlyViolation(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, 101, 101, 1, 2, 1024)
	writeProcFixture(t, root, 102, 101, 9, 11, 8192)
	if err := os.WriteFile(
		filepath.Join(root, "102", "stat"),
		[]byte("102 (descendant) S 101 101 0 0 0\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	threads, files, rss, supported := procGroupSample(root, 101)
	if !supported || threads != 10 || files != 13 || rss != 9*1024*1024 {
		t.Fatalf("group sample supported=%t threads=%d files=%d rss=%d",
			supported, threads, files, rss)
	}
	sample := ResourceSample{}
	sample.merge(threads, files, rss)
	broken := (ResourceBounds{
		MaxRSSBytes: 4096, MaxThreads: 5, MaxOpenFiles: 5,
	}).check(sample, 0, 0)
	if len(broken) != 3 {
		t.Fatalf("descendant-only violations not all detected: %+v", broken)
	}
	_, _, _, supported = procGroupSample(filepath.Join(root, "absent"), 101)
	if supported {
		t.Fatal("absent procfs was reported as supported")
	}

	writeProcFixture(t, root, 103, 103, 1, 1, 64)
	if err := os.WriteFile(
		filepath.Join(root, "103", "stat"),
		[]byte("103 (escaped) S 102 103 0 0 0\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	escaped, supported := detectEscapedDescendant(root, 101, 101)
	if !supported || !escaped {
		t.Fatalf("setsid-style descendant escape not detected: supported=%t escaped=%t",
			supported, escaped)
	}
	if err := escapedContainmentError(escaped); err == nil ||
		!strings.Contains(err.Error(), "cgroup-v2 containment is required") {
		t.Fatalf("detected escape was not refused: %v", err)
	}
	escaped, supported = detectEscapedDescendant(
		filepath.Join(root, "absent"), 101, 101,
	)
	if supported || escaped {
		t.Fatal("unsupported containment surface was reported as measured")
	}
}

func writeProcFixture(
	t *testing.T, root string, pid, pgid int, threads, files, rssKB int,
) {
	t.Helper()
	base := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (fixture) S 1 %d 0 0 0\n", pid, pgid)
	if err := os.WriteFile(filepath.Join(base, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Threads:\t%d\nVmRSS:\t%d kB\n", threads, rssKB)
	if err := os.WriteFile(filepath.Join(base, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < files; index++ {
		if err := os.WriteFile(
			filepath.Join(base, "fd", strconv.Itoa(index)), []byte{}, 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
