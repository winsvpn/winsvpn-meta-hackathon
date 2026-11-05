package core

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core/replaystore"
)

// The persisted replay journal (F-02): the replay window used to empty on
// restart, so one captured initiation earned a fresh response from a restarted
// gateway — the one restart-sensitive fingerprint the fleet still had. The
// tests here pin the journal contract from the header of replay.go: survive
// restart, prune by expiry, refuse torn files, and stay bounded at the cap.

func journalPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "replay.journal")
}

// TestReplayJournalSurvivesRestartAndStillRejects is the core of F-02: capture
// → remember → "restart" (a fresh cache on the same journal) → the captured
// initiation is still refused.
func TestReplayJournalSurvivesRestartAndStillRejects(t *testing.T) {
	path := journalPath(t)
	lifetime := 10 * time.Minute
	now := fixedNow

	c1, err := newReplayCacheWithJournal(lifetime, path, now)
	if err != nil {
		t.Fatalf("first cache: %v", err)
	}
	k := sha256Of(t, "captured-initiation-body")
	if err := c1.remember(k, now); err != nil {
		t.Fatalf("remember: %v", err)
	}
	if st, err := os.Stat(path); err != nil || st.Size() != replayJournalRecordSize {
		t.Fatalf("journal is %d bytes after one remember (err %v), want one %d-byte record",
			fileSizeOr(t, path, st, err), err, replayJournalRecordSize)
	}

	// Restart: a brand-new cache on the same journal must refuse the capture.
	c2, err := newReplayCacheWithJournal(lifetime, path, now.Add(time.Second))
	if err != nil {
		t.Fatalf("restarted cache: %v", err)
	}
	if !c2.seen(k, now.Add(time.Second)) {
		t.Fatal("the captured initiation is not seen after the restart; the journal did not survive")
	}
	if c2.seen(sha256Of(t, "some-other-body"), now.Add(time.Second)) {
		t.Fatal("a body that was never accepted is reported seen")
	}
	if c2.journalError() != nil {
		t.Fatalf("journal error on a clean journal: %v", c2.journalError())
	}

	// The live record must still be on disk after the prune-on-load rewrite.
	if st, err := os.Stat(path); err != nil || st.Size() != replayJournalRecordSize {
		t.Fatalf("journal is %d bytes after restart (err %v), want the one live record kept",
			fileSizeOr(t, path, st, err), err)
	}

	// Past expiry, a further restart prunes it and the file empties.
	c3, err := newReplayCacheWithJournal(lifetime, path, now.Add(lifetime+time.Minute))
	if err != nil {
		t.Fatalf("expired cache: %v", err)
	}
	if c3.seen(k, now.Add(lifetime+time.Minute)) {
		t.Fatal("the expired initiation is still seen; prune-on-load did not run")
	}
	if st, err := os.Stat(path); err != nil || st.Size() != 0 {
		t.Fatalf("journal is %d bytes after expiry (err %v), want the pruned file to be empty",
			fileSizeOr(t, path, st, err), err)
	}
}

// TestReplayJournalRefusesATornFile pins the fail-closed load: a file that is
// not a whole number of records must refuse the gateway start, because a torn
// journal must not silently weaken the gate.
func TestReplayJournalRefusesATornFile(t *testing.T) {
	lifetime := time.Minute
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"half a record", make([]byte, replayJournalRecordSize/2)},
		{"record plus a fragment", append(bytesOfRecord(sha256Of(t, "x"), 1234567890), 0xde, 0xad)},
		{"one stray byte", []byte{0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := journalPath(t)
			if err := os.WriteFile(path, tc.data, 0o640); err != nil {
				t.Fatal(err)
			}
			_, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
			if err == nil {
				t.Fatalf("a torn journal of %d bytes was accepted; the load must refuse", len(tc.data))
			}
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("torn journal refused with %v, want an ErrConfig", err)
			}
		})
	}

	// The control: an empty file is a valid empty journal. It is written 0640
	// because the load-time ownership policy now refuses anything else; a
	// journal that nothing provisioned is no different from a journal that
	// was provisioned wrong.
	path := journalPath(t)
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := newReplayCacheWithJournal(lifetime, path, fixedNow); err != nil {
		t.Fatalf("an empty journal must load: %v", err)
	}
}

// TestReplayJournalRefusesAFileItCannotVouchFor pins the load-time trust
// policy at the core boundary, where every refusal surfaces as ErrConfig to
// the gateway start: a symlinked journal, a world-widened mode and an oversize
// file all refuse, matching the installer's keyfile policy, while a correctly
// provisioned 0600 journal still loads.
func TestReplayJournalRefusesAFileItCannotVouchFor(t *testing.T) {
	lifetime := time.Minute

	t.Run("a symbolic link", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("creating a symlink on windows needs privileges this suite does not assume")
		}
		dir := t.TempDir()
		victim := filepath.Join(dir, "victim")
		if err := os.WriteFile(victim, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "replay.journal")
		if err := os.Symlink(victim, path); err != nil {
			t.Fatal(err)
		}
		_, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
		if err == nil || !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("a symlinked journal must refuse the gateway start with ErrConfig naming the symlink, got %v", err)
		}
		if st, err := os.Stat(victim); err != nil || st.Size() != 0 {
			t.Fatalf("the symlink victim was modified (size %d, err %v)", fileSizeOr(t, victim, st, err), err)
		}
	})

	t.Run("a symbolic-link pending record", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("creating a symlink on windows needs privileges this suite does not assume")
		}
		path := journalPath(t)
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(filepath.Dir(path), "pending-victim")
		if err := os.WriteFile(victim, bytesOfRecord(sha256Of(t, "pending"), fixedNow.Add(time.Hour).Unix()), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, path+".pending"); err != nil {
			t.Fatal(err)
		}
		_, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
		if err == nil || !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("a symlinked pending record must refuse startup with ErrConfig, got %v", err)
		}
		if st, err := os.Stat(victim); err != nil || st.Size() != replayJournalRecordSize {
			t.Fatalf("the pending symlink victim was modified (size %d, err %v)", fileSizeOr(t, victim, st, err), err)
		}
	})

	t.Run("a malformed pending record", func(t *testing.T) {
		path := journalPath(t)
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".pending", []byte{0x01}, 0o640); err != nil {
			t.Fatal(err)
		}
		_, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
		if err == nil || !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "pending") {
			t.Fatalf("a malformed pending record must refuse startup with ErrConfig, got %v", err)
		}
	})

	t.Run("a world-widened mode", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX modes do not exist on windows")
		}
		path := journalPath(t)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
		if err == nil || !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "mode") {
			t.Fatalf("a 0644 journal must refuse the gateway start with ErrConfig naming the mode, got %v", err)
		}
	})

	t.Run("above the load size bound", func(t *testing.T) {
		path := journalPath(t)
		if err := os.WriteFile(path, make([]byte, replaystore.MaxFileBytes+1), 0o640); err != nil {
			t.Fatal(err)
		}
		_, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
		if err == nil || !errors.Is(err, ErrConfig) {
			t.Fatalf("an oversize journal must refuse the gateway start with ErrConfig, got %v", err)
		}
	})

	t.Run("a correctly provisioned 0600 journal still loads", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX modes do not exist on windows")
		}
		path := journalPath(t)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := newReplayCacheWithJournal(lifetime, path, fixedNow); err != nil {
			t.Fatalf("an installer-provisioned 0600 journal must load: %v", err)
		}
	})
}

// TestReplayJournalStaysBoundedAtTheCap pins fail-closed capacity: an
// unexpired replay key is never evicted merely to admit another handshake.
func TestReplayJournalStaysBoundedAtTheCap(t *testing.T) {
	path := journalPath(t)
	lifetime := time.Hour
	const testCap = 8
	c, err := newReplayCacheWithJournalLimit(lifetime, path, fixedNow, testCap)
	if err != nil {
		t.Fatal(err)
	}

	keys := make([][32]byte, 32)
	for i := range keys {
		keys[i] = sha256Of(t, "initiation-body-"+string(rune('a'+i)))
	}
	for i := range keys {
		err := c.remember(keys[i], fixedNow)
		if i < c.journal.cap {
			if err != nil {
				t.Fatalf("remember key %d below cap: %v", i, err)
			}
		} else if !errors.Is(err, ErrReplayJournal) {
			t.Fatalf("remember key %d above cap = %v, want ErrReplayJournal", i, err)
		}
	}
	if got := c.size(); got != c.journal.cap {
		t.Fatalf("in-memory window holds %d records, want cap %d", got, c.journal.cap)
	}
	if err := c.journal.journalError(); err != nil {
		t.Fatalf("live-set capacity latched persist health: %v", err)
	}
	if c.journal.records > c.journal.cap {
		t.Fatalf("journal holds %d records, above the cap %d", c.journal.records, c.journal.cap)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(c.journal.cap) * replayJournalRecordSize; st.Size() > want {
		t.Fatalf("journal is %d bytes, above the capped %d", st.Size(), want)
	}

	// The journal reloads every accepted key and none of the refused keys.
	c2, err := newReplayCacheWithJournalLimit(lifetime, path, fixedNow, testCap)
	if err != nil {
		t.Fatalf("reload after the cap rewrite: %v", err)
	}
	for i, k := range keys {
		seen := c2.seen(k, fixedNow)
		if i < c.journal.cap && !seen {
			t.Fatalf("accepted key %d was lost at restart", i)
		}
		if i >= c.journal.cap && seen {
			t.Fatalf("capacity-refused key %d appeared in the replay set", i)
		}
	}
}

func TestReplayJournalCapRechecksStaggeredExpiryBeforeStickyFailure(t *testing.T) {
	path := journalPath(t)
	const testCap = 2
	lifetime := 10 * time.Second
	c, err := newReplayCacheWithJournalLimit(lifetime, path, fixedNow, testCap)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := c.journal.w.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	first := sha256Of(t, "staggered-expiry-first")
	second := sha256Of(t, "staggered-expiry-second")
	replacement := sha256Of(t, "staggered-expiry-replacement")
	third := sha256Of(t, "staggered-expiry-third")
	if err := c.remember(first, fixedNow); err != nil {
		t.Fatal(err)
	}
	if err := c.remember(second, fixedNow.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	if c.seen(first, fixedNow.Add(10*time.Second)) {
		t.Fatal("first key remained live at its expiry boundary")
	}
	if err := c.remember(replacement, fixedNow.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.remember(third, fixedNow.Add(19*time.Second)); err != nil {
		t.Fatalf("expired staggered key caused a false sticky capacity refusal: %v", err)
	}
	if err := c.journalError(); err != nil {
		t.Fatalf("healthy journal became sticky after staggered expiry: %v", err)
	}
	if got := c.size(); got != testCap {
		t.Fatalf("cache contains %d entries after staggered expiry, want replacement plus new key", got)
	}
	if !c.seen(third, fixedNow.Add(19*time.Second)) {
		t.Fatal("new key was not retained after expired-cap reclamation")
	}
}

func TestPhysicalWALCapacityRecoversAfterExpiryThroughCore(t *testing.T) {
	path := journalPath(t)
	const physicalCap = 2
	_, writer, err := replaystore.OpenWithLimit(path, fixedNow, physicalCap)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	c, err := newReplayCache(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the policy cap one entry above the store cap so the third key reaches
	// the physical WAL check instead of being stopped by the in-memory ceiling.
	c.journal = &replayJournal{
		w:       writer,
		cap:     physicalCap + 1,
		entries: make(map[[32]byte]time.Time),
	}
	keys := [4][32]byte{
		sha256Of(t, "physical-core-0"),
		sha256Of(t, "physical-core-1"),
		sha256Of(t, "physical-core-2"),
		sha256Of(t, "physical-core-3"),
	}
	for i := 0; i < physicalCap; i++ {
		if err := c.remember(keys[i], fixedNow); err != nil {
			t.Fatalf("remember %d below physical cap: %v", i, err)
		}
	}
	firstErr := c.remember(keys[2], fixedNow)
	if !errors.Is(firstErr, ErrReplayJournal) || !errors.Is(firstErr, replaystore.ErrCapacity) {
		t.Fatalf("physical-cap admission = %v, want ErrReplayJournal wrapping ErrCapacity", firstErr)
	}
	if health := c.journalError(); health != nil {
		t.Fatalf("physical capacity latched persist health: %v", health)
	}
	if got := c.remember(keys[3], fixedNow); !errors.Is(got, ErrReplayJournal) {
		t.Fatalf("same-clock admission while WAL is full = %v, want ErrReplayJournal", got)
	}
	if got := c.remember(keys[3], fixedNow.Add(24*time.Hour)); got != nil {
		t.Fatalf("admission after expiry freed physical capacity: %v", got)
	}
	if health := c.journalError(); health != nil {
		t.Fatalf("recovered journal reported persist health: %v", health)
	}
}

func TestReplayJournalRecoversAfterExpiryFreesCapacity(t *testing.T) {
	path := journalPath(t)
	const testCap = 2
	lifetime := 10 * time.Second
	c, err := newReplayCacheWithJournalLimit(lifetime, path, fixedNow, testCap)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := c.journal.w.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	first := sha256Of(t, "cap-recover-first")
	second := sha256Of(t, "cap-recover-second")
	overflow := sha256Of(t, "cap-recover-overflow")
	later := sha256Of(t, "cap-recover-later")
	if err := c.remember(first, fixedNow); err != nil {
		t.Fatal(err)
	}
	if err := c.remember(second, fixedNow); err != nil {
		t.Fatal(err)
	}
	if err := c.remember(overflow, fixedNow); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("overflow at cap = %v, want ErrReplayJournal", err)
	}
	if err := c.journalError(); err != nil {
		t.Fatalf("capacity refusal latched persist health: %v", err)
	}
	if err := c.remember(overflow, fixedNow.Add(time.Second)); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("still-full admission = %v, want ErrReplayJournal", err)
	}
	freed := fixedNow.Add(lifetime)
	if err := c.remember(later, freed); err != nil {
		t.Fatalf("admission after expiry freed capacity: %v", err)
	}
	if err := c.journalError(); err != nil {
		t.Fatalf("recovered journal reported persist health: %v", err)
	}
	if !c.seen(later, freed) {
		t.Fatal("recovered admission was not retained")
	}
	if c.seen(first, freed) || c.seen(overflow, freed) {
		t.Fatal("expired or capacity-refused key remained live after recovery")
	}
}

func TestReplayJournalPersistFailureStaysStickyAfterExpiry(t *testing.T) {
	h := newHarness(t)
	syncErr := errors.New("sync appended replay record: injected I/O error")
	h.resp.replay.journal = &replayJournal{
		w:       &failingReplayJournalWriter{failure: syncErr},
		cap:     maxReplayEntries,
		entries: make(map[[32]byte]time.Time),
	}

	first := h.initiator(t)
	firstMsg, err := first.WriteInitiation([]byte("sticky-sync-failure"), PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(firstMsg); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("sync failure admission: want ErrReplayJournal, got %v", err)
	}
	if got := h.resp.replay.size(); got != 0 {
		t.Fatalf("failed durable append left %d in-memory entries", got)
	}

	h.now = h.now.Add(24 * time.Hour)
	later := h.initiator(t)
	laterMsg, err := later.WriteInitiation([]byte("after-expiry-sync-failure"), PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(laterMsg); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("new initiation after expiry with sticky persist failure: want ErrReplayJournal, got %v", err)
	}
	if !errors.Is(h.resp.ReplayJournalError(), syncErr) {
		t.Fatalf("sticky persist health was lost after expiry: %v", h.resp.ReplayJournalError())
	}
}

func TestExpectedRuntimeCompactionUpdatesIdentityWithoutTrustingHostileReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("runtime inode replacement is a Unix monitor contract")
	}
	path := journalPath(t)
	const cap = 2
	lifetime := 2 * time.Second
	c, err := newReplayCacheWithJournalLimit(lifetime, path, fixedNow, cap)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := c.journal.w.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	for i := 0; i < cap; i++ {
		if err := c.remember(sha256Of(t, fmt.Sprintf("pre-compact-%d", i)), fixedNow); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	advanced := fixedNow.Add(3 * time.Second)
	if err := c.remember(sha256Of(t, "post-expiry"), advanced); err != nil {
		t.Fatalf("remember that triggers runtime compaction: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("runtime compaction did not replace the compact-journal inode")
	}
	if err := c.verifyJournalPath(); err != nil {
		t.Fatalf("monitor rejected the writer's legitimate runtime compaction: %v", err)
	}

	moved := path + ".legitimate"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := c.verifyJournalPath(); err == nil {
		t.Fatal("monitor accepted a hostile pathname replacement after legitimate compaction")
	}
	if c.journalError() == nil {
		t.Fatal("hostile replacement did not become sticky journal health")
	}
	if err := c.remember(sha256Of(t, "after-hostile-replacement"), advanced); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("admission after hostile replacement = %v, want ErrReplayJournal", err)
	}
}

// TestReplayJournalLoadUsesTheCallersClock pins the prune instant: a fixed
// injected clock must not expire a journal written at the same fixed clock,
// which is what the gateway restart test depends on.
func TestReplayJournalLoadUsesTheCallersClock(t *testing.T) {
	path := journalPath(t)
	lifetime := 3 * time.Second
	c1, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	k := sha256Of(t, "fixed-clock-initiation")
	if err := c1.remember(k, fixedNow); err != nil {
		t.Fatalf("remember: %v", err)
	}

	// Load again at the SAME fixed instant: nothing may have expired.
	c2, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if !c2.seen(k, fixedNow) {
		t.Fatal("a journal written and loaded at the same injected clock instant lost its record")
	}
}

// TestReplayJournalClosedWriterRejectsBeforeDurableCommit is the original
// fail-open adversary: close the live journal descriptor, deliver a valid new
// initiation, then restart on the same path. Admission must report the storage
// failure, every later new initiation on that Responder must fail closed, and
// restart may accept the initiation once because the failed responder never
// crossed the authoritative WAL commit point and never answered it.
func TestReplayJournalClosedWriterRejectsBeforeDurableCommit(t *testing.T) {
	path := journalPath(t)
	withJournal := func(h *harness) { h.gwCf.ReplayJournal = path }
	h := newHarness(t, withJournal)

	w, ok := h.resp.replay.journal.w.(*replaystore.Writer)
	if !ok {
		t.Fatalf("journal writer type is %T, want *replaystore.Writer", h.resp.replay.journal.w)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close live journal: %v", err)
	}

	first := h.initiator(t)
	firstMsg, err := first.WriteInitiation([]byte("closed-journal"), PadAuto)
	if err != nil {
		t.Fatalf("write first initiation: %v", err)
	}
	if _, err := h.resp.ReadInitiation(firstMsg); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("closed journal admission: want ErrReplayJournal, got %v", err)
	}
	if got := h.resp.replay.size(); got != 0 {
		t.Fatalf("failed durable append left %d in-memory entries", got)
	}
	if h.resp.ReplayJournalError() == nil {
		t.Fatal("closed journal failure was not retained for operator health")
	}
	if _, err := os.Stat(path + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-commit failure unexpectedly staged a pending record: %v", err)
	}

	second := h.initiator(t)
	secondMsg, err := second.WriteInitiation([]byte("sticky-broken"), PadAuto)
	if err != nil {
		t.Fatalf("write second initiation: %v", err)
	}
	if _, err := h.resp.ReadInitiation(secondMsg); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("new initiation after sticky failure: want ErrReplayJournal, got %v", err)
	}

	restarted := newHarness(t, withJournal)
	if _, err := restarted.resp.ReadInitiation(firstMsg); err != nil {
		t.Fatalf("restart refused an initiation that never crossed durable commit: %v", err)
	}
	if _, err := restarted.resp.ReadInitiation(firstMsg); !errors.Is(err, ErrReplay) {
		t.Fatalf("restart did not remember its accepted initiation: want ErrReplay, got %v", err)
	}
}

// TestReplayJournalRewriteFailureRejectsButRestartStillSeesTheKey forces an
// explicit snapshot rewrite to fail after a new record was accepted. The WAL
// remains authoritative, operator health becomes sticky, and restart refuses
// the accepted initiation.
func TestReplayJournalRewriteFailureRejectsButRestartStillSeesTheKey(t *testing.T) {
	path := journalPath(t)
	withJournal := func(h *harness) { h.gwCf.ReplayJournal = path }
	h := newHarness(t, withJournal)

	first := h.initiator(t)
	firstMsg, err := first.WriteInitiation([]byte("rewrite-seed"), PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(firstMsg); err != nil {
		t.Fatalf("seed admission: %v", err)
	}

	blocker := filepath.Join(filepath.Dir(path), fmt.Sprintf(".journal.tmp.%d", os.Getpid()))
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatalf("create rewrite blocker: %v", err)
	}
	blockerChild := filepath.Join(blocker, "keep-nonempty")
	if err := os.WriteFile(blockerChild, []byte("x"), 0o600); err != nil {
		t.Fatalf("populate rewrite blocker: %v", err)
	}

	second := h.initiator(t)
	secondMsg, err := second.WriteInitiation([]byte("rewrite-failure"), PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(secondMsg); err != nil {
		t.Fatalf("second admission before forced rewrite: %v", err)
	}
	if err := h.resp.replay.journal.rewrite(
		h.resp.replay.entries,
		h.resp.replay.lifetime,
		fixedNow,
		nil,
	); err == nil {
		t.Fatal("forced snapshot rewrite unexpectedly succeeded")
	}
	if h.resp.ReplayJournalError() == nil {
		t.Fatal("rewrite failure was not retained for operator health")
	}

	if err := os.Remove(blockerChild); err != nil {
		t.Fatalf("remove rewrite blocker child: %v", err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatalf("remove rewrite blocker: %v", err)
	}
	restarted := newHarness(t, withJournal)
	if _, err := restarted.resp.ReadInitiation(secondMsg); !errors.Is(err, ErrReplay) {
		t.Fatalf("restart forgot the key after rewrite failure: want ErrReplay, got %v", err)
	}
}

type failingReplayJournalWriter struct {
	failure error
	broken  error
}

func (w *failingReplayJournalWriter) Append(replaystore.Record, int64) error {
	w.broken = w.failure
	return w.failure
}

func (w *failingReplayJournalWriter) Rewrite([]replaystore.Record, int64) error {
	w.broken = w.failure
	return w.failure
}

func (w *failingReplayJournalWriter) VerifyPath() error { return w.broken }

func (w *failingReplayJournalWriter) Err() error { return w.broken }

// TestReplayJournalSyncFailurePropagatesToResponder pins the responder seam
// independently of filesystem-specific error injection. A writer reporting an
// fsync failure must make ReadInitiation return ErrReplayJournal and keep the
// responder sticky-broken for every later new handshake.
func TestReplayJournalSyncFailurePropagatesToResponder(t *testing.T) {
	h := newHarness(t)
	syncErr := errors.New("sync appended replay record: injected I/O error")
	h.resp.replay.journal = &replayJournal{
		w:       &failingReplayJournalWriter{failure: syncErr},
		cap:     maxReplayEntries,
		entries: make(map[[32]byte]time.Time),
	}

	first := h.initiator(t)
	firstMsg, err := first.WriteInitiation([]byte("sync-failure"), PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(firstMsg); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("sync failure admission: want ErrReplayJournal, got %v", err)
	}
	if got := h.resp.replay.size(); got != 0 {
		t.Fatalf("failed durable append left %d in-memory entries", got)
	}
	if !errors.Is(h.resp.ReplayJournalError(), syncErr) {
		t.Fatalf("responder health lost sync failure: %v", h.resp.ReplayJournalError())
	}

	second := h.initiator(t)
	secondMsg, err := second.WriteInitiation([]byte("after-sync-failure"), PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(secondMsg); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("new initiation after sync failure: want ErrReplayJournal, got %v", err)
	}
}

func cacheWithJournalWriter(t *testing.T, lifetime time.Duration, w replayJournalWriter, cap int) *replayCache {
	t.Helper()
	c, err := newReplayCache(lifetime)
	if err != nil {
		t.Fatal(err)
	}
	if cap <= 0 {
		cap = maxReplayEntries
	}
	c.journal = &replayJournal{
		w:       w,
		cap:     cap,
		entries: make(map[[32]byte]time.Time),
	}
	return c
}

type transientReplayJournalWriter struct {
	remaining int
	failure   error
}

func (w *transientReplayJournalWriter) Append(replaystore.Record, int64) error {
	if w.remaining > 0 {
		w.remaining--
		return w.failure
	}
	return nil
}

func (w *transientReplayJournalWriter) Rewrite([]replaystore.Record, int64) error { return nil }

func (w *transientReplayJournalWriter) VerifyPath() error { return nil }

func (w *transientReplayJournalWriter) Err() error { return nil }

type recordingReplayJournalWriter struct {
	mu      sync.Mutex
	appends int
	broken  error
}

func (w *recordingReplayJournalWriter) Append(replaystore.Record, int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broken != nil {
		return w.broken
	}
	w.appends++
	return nil
}

func (w *recordingReplayJournalWriter) Rewrite([]replaystore.Record, int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.broken
}

func (w *recordingReplayJournalWriter) VerifyPath() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.broken
}

func (w *recordingReplayJournalWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.broken
}

// TestReplayRememberAppendFailureLeavesNoCommittedMemoryEntry is the
// fail-closed ordering adversary: remember must not install c.entries[key]
// unless the durable append succeeded. A refused initiation that exists only
// in memory reports ErrReplay as if it had been admitted, then vanishes on
// restart and becomes admissible again.
func TestReplayRememberAppendFailureLeavesNoCommittedMemoryEntry(t *testing.T) {
	syncErr := errors.New("sync appended replay record: injected I/O error")
	c := cacheWithJournalWriter(t, time.Hour, &failingReplayJournalWriter{failure: syncErr}, 0)
	k := sha256Of(t, "append-failure-no-memory")

	if err := c.remember(k, fixedNow); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("failed append admission = %v, want ErrReplayJournal", err)
	}
	if c.seen(k, fixedNow) {
		t.Fatal("failed durable append left a committed-looking in-memory entry")
	}
	if got := c.size(); got != 0 {
		t.Fatalf("failed durable append retained %d in-memory entries", got)
	}
	if !errors.Is(c.journalError(), syncErr) {
		t.Fatalf("sticky persist health = %v, want injected sync error", c.journalError())
	}

	retry := c.remember(k, fixedNow)
	if !errors.Is(retry, ErrReplayJournal) {
		t.Fatalf("retry after sticky append failure = %v, want ErrReplayJournal", retry)
	}
	if errors.Is(retry, ErrReplay) {
		t.Fatal("retry after failed append reported ErrReplay; that treats a refused initiation as committed")
	}
	if c.seen(k, fixedNow) {
		t.Fatal("retry installed a committed-looking in-memory entry")
	}
}

func TestReplayRememberAppendFailureRestartEquivalentHasNoDurableKey(t *testing.T) {
	path := journalPath(t)
	lifetime := time.Hour
	c1, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	w, ok := c1.journal.w.(*replaystore.Writer)
	if !ok {
		t.Fatalf("journal writer type is %T, want *replaystore.Writer", c1.journal.w)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	k := sha256Of(t, "closed-writer-no-memory")
	if err := c1.remember(k, fixedNow); !errors.Is(err, ErrReplayJournal) {
		t.Fatalf("closed-writer admission = %v, want ErrReplayJournal", err)
	}
	if c1.seen(k, fixedNow) {
		t.Fatal("closed-writer append failure left a committed-looking in-memory entry")
	}
	if _, err := os.Stat(path + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-commit failure unexpectedly staged a pending record: %v", err)
	}

	c2, err := newReplayCacheWithJournal(lifetime, path, fixedNow)
	if err != nil {
		t.Fatalf("restart-equivalent cache: %v", err)
	}
	if c2.seen(k, fixedNow) {
		t.Fatal("restart loaded a replay key that never crossed durable commit")
	}
	if err := c2.remember(k, fixedNow); err != nil {
		t.Fatalf("restart-equivalent refused an initiation that was never admitted or journaled: %v", err)
	}
	if !c2.seen(k, fixedNow) {
		t.Fatal("restart-equivalent did not retain its own successful admission")
	}
	if err := c2.remember(k, fixedNow); !errors.Is(err, ErrReplay) {
		t.Fatalf("restart-equivalent lost duplicate detection: %v", err)
	}
}

func TestReplayRememberTransientAppendFailureAllowsRetryWithoutPhantomCommit(t *testing.T) {
	transient := errors.New("ENOSPC before compact journal mutation")
	w := &transientReplayJournalWriter{remaining: 1, failure: transient}
	c := cacheWithJournalWriter(t, time.Hour, w, 0)
	k := sha256Of(t, "transient-append-retry")

	first := c.remember(k, fixedNow)
	if !errors.Is(first, ErrReplayJournal) {
		t.Fatalf("transient append admission = %v, want ErrReplayJournal", first)
	}
	if errors.Is(first, ErrReplay) {
		t.Fatal("transient append failure reported ErrReplay")
	}
	if c.seen(k, fixedNow) {
		t.Fatal("transient append failure left a committed-looking in-memory entry")
	}
	if err := c.journalError(); err != nil {
		t.Fatalf("transient append latched persist health: %v", err)
	}

	if err := c.remember(k, fixedNow); err != nil {
		t.Fatalf("retry after transient append failure: %v", err)
	}
	if !c.seen(k, fixedNow) {
		t.Fatal("successful retry was not retained in memory")
	}
	if err := c.remember(k, fixedNow); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate after successful retry = %v, want ErrReplay", err)
	}
}

func TestReplayRememberConcurrentDuplicatesOneDurableWinner(t *testing.T) {
	w := &recordingReplayJournalWriter{}
	c := cacheWithJournalWriter(t, time.Hour, w, 0)
	k := sha256Of(t, "concurrent-duplicate-winner")

	const n = 64
	start := make(chan struct{})
	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			runtime.Gosched()
			results <- c.remember(k, fixedNow)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
			continue
		}
		if !errors.Is(err, ErrReplay) {
			t.Fatalf("concurrent duplicate = %v, want ErrReplay for losers", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("exactly one concurrent remember must succeed, got %d", accepted)
	}
	if !c.seen(k, fixedNow) {
		t.Fatal("winning admission was not retained")
	}
	if w.appends != 1 {
		t.Fatalf("durable append ran %d times, want 1", w.appends)
	}
	if err := c.journalError(); err != nil {
		t.Fatalf("healthy concurrent admission latched persist health: %v", err)
	}
}

func TestReplayRememberConcurrentDuplicatesAppendFailureCommitsNothing(t *testing.T) {
	syncErr := errors.New("sync appended replay record: injected I/O error")
	c := cacheWithJournalWriter(t, time.Hour, &failingReplayJournalWriter{failure: syncErr}, 0)
	k := sha256Of(t, "concurrent-duplicate-append-failure")

	const n = 64
	start := make(chan struct{})
	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			runtime.Gosched()
			results <- c.remember(k, fixedNow)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	for err := range results {
		if err == nil {
			t.Fatal("concurrent remember succeeded after durable append failure")
		}
		if !errors.Is(err, ErrReplayJournal) {
			t.Fatalf("concurrent append failure = %v, want ErrReplayJournal", err)
		}
		if errors.Is(err, ErrReplay) {
			t.Fatal("concurrent append failure reported ErrReplay; that treats a refused initiation as committed")
		}
	}
	if c.seen(k, fixedNow) {
		t.Fatal("concurrent append failure left a committed-looking in-memory entry")
	}
	if got := c.size(); got != 0 {
		t.Fatalf("concurrent append failure retained %d in-memory entries", got)
	}
	if !errors.Is(c.journalError(), syncErr) {
		t.Fatalf("sticky persist health = %v, want injected sync error", c.journalError())
	}
}

func sha256Of(t *testing.T, s string) [32]byte {
	t.Helper()
	return sha256.Sum256([]byte(s))
}

func fileSizeOr(t *testing.T, path string, st os.FileInfo, err error) int64 {
	t.Helper()
	if err != nil {
		return -1
	}
	return st.Size()
}

func bytesOfRecord(k [32]byte, expiry int64) []byte {
	rec := make([]byte, replayJournalRecordSize)
	copy(rec[:32], k[:])
	binary.BigEndian.PutUint64(rec[32:], uint64(expiry))
	return rec
}
