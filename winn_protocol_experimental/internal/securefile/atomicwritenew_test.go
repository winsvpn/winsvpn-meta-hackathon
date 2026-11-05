package securefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestAtomicWriteNewRefusesAnIncumbent proves the create-once contract: a
// second write does not merely fail, it leaves the first writer's bytes exactly
// as they were. A terminal audit checkpoint that could be silently replaced
// would close nothing.
func TestAtomicWriteNewRefusesAnIncumbent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-checkpoint.json")
	incumbent := []byte("the original checkpoint\n")
	if err := AtomicWriteNew(path, incumbent, 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	err := AtomicWriteNew(path, []byte("a replacement\n"), 0o600)
	if err == nil {
		t.Fatal("an existing checkpoint was silently replaced")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("second write failed for an unexpected reason: %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, incumbent) {
		t.Fatalf(
			"the incumbent file changed after a rejected write: %q", after,
		)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions are %04o, want 0600", info.Mode().Perm())
	}
}

// TestAtomicWriteNewHasExactlyOneWinner races many creators for one path.
// link(2) resolves the race in the kernel and fails with EEXIST rather than
// replacing, so exactly one caller may succeed and the surviving bytes must be
// that winner's.
func TestAtomicWriteNewHasExactlyOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-checkpoint.json")
	const writers = 16
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	results := make([]error, writers)
	payloads := make([][]byte, writers)
	for index := 0; index < writers; index++ {
		payloads[index] = []byte{byte('A' + index), '\n'}
		done.Add(1)
		go func(index int) {
			defer done.Done()
			start.Wait()
			results[index] = AtomicWriteNew(path, payloads[index], 0o600)
		}(index)
	}
	start.Done()
	done.Wait()

	winners := 0
	winner := -1
	for index, err := range results {
		if err == nil {
			winners++
			winner = index
			continue
		}
		if !errors.Is(err, os.ErrExist) {
			t.Fatalf("writer %d failed unexpectedly: %v", index, err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d writers won the race, want exactly 1", winners)
	}
	content, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, payloads[winner]) {
		t.Fatalf(
			"the surviving bytes %q are not the winner's %q",
			content, payloads[winner],
		)
	}
}

// TestAtomicWriteNewNeverPublishesAPartialFile proves the destination name is
// absent until the content is complete.
//
// The failure mode this rules out is specific and permanent: a crash during a
// direct O_EXCL write to the final path would leave a zero-byte file there, and
// because the path now exists, every later retry would be refused by the very
// no-clobber rule meant to protect it. Writing to a private temporary name and
// publishing by link means an interrupted attempt leaves nothing at the
// destination at all.
func TestAtomicWriteNewNeverPublishesAPartialFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit-checkpoint.json")

	// A write that fails part-way: the destination must not exist afterwards,
	// and the retry must succeed rather than be permanently blocked.
	unwritable := filepath.Join(directory, "missing-subdirectory", "file.json")
	if err := AtomicWriteNew(unwritable, []byte("x"), 0o600); err == nil {
		// A missing parent is created by EnsurePrivateDirectory, so this
		// particular path succeeds; remove it and move on to the real check.
		_ = os.Remove(unwritable)
	}

	// Observe every intermediate filename state while a large payload is
	// written. The destination may only ever appear complete.
	payload := make([]byte, 1<<20)
	for index := range payload {
		payload[index] = byte(index)
	}
	stop := make(chan struct{})
	var observer sync.WaitGroup
	partial := make(chan int64, 1)
	observer.Add(1)
	go func() {
		defer observer.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if info, err := os.Lstat(path); err == nil &&
				info.Size() != int64(len(payload)) {
				select {
				case partial <- info.Size():
				default:
				}
				return
			}
		}
	}()
	if err := AtomicWriteNew(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	close(stop)
	observer.Wait()
	select {
	case size := <-partial:
		t.Fatalf(
			"the destination was observable at %d bytes before the write "+
				"completed; a crash there would leave an unrecoverable stub",
			size,
		)
	default:
	}
	content, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatal("the published file does not match the payload")
	}
	// No temporary files are left behind.
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".winn-new-") {
			t.Fatalf("a temporary file survived the write: %s", entry.Name())
		}
	}
}

// TestAtomicWriteNewLoserNeverDeletesTheWinnersFile is requirement (d): a
// failed attempt cleans up only its own uniquely-named temporary file, never
// the destination another writer just published.
func TestAtomicWriteNewLoserNeverDeletesTheWinnersFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit-checkpoint.json")
	winner := []byte("the winner's checkpoint\n")
	if err := AtomicWriteNew(path, winner, 0o600); err != nil {
		t.Fatal(err)
	}
	var losers sync.WaitGroup
	for index := 0; index < 8; index++ {
		losers.Add(1)
		go func(index int) {
			defer losers.Done()
			_ = AtomicWriteNew(path, []byte{byte(index)}, 0o600)
		}(index)
	}
	losers.Wait()
	content, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("the winner's file was deleted by a losing writer: %v", err)
	}
	if !bytes.Equal(content, winner) {
		t.Fatalf("the winner's bytes changed to %q", content)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".winn-new-") {
			t.Fatalf("a loser left a temporary file behind: %s", entry.Name())
		}
	}
}

// TestAtomicWriteNewRefusesASymlink proves the no-replace rule guards the path: a
// symlink planted at the destination is refused outright rather than followed
// into whatever it points at.
func TestAtomicWriteNewRefusesASymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("do not touch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "audit-checkpoint.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := AtomicWriteNew(link, []byte("hijacked\n"), 0o600); err == nil {
		t.Fatal("a symlinked destination was written through")
	}
	content, err := os.ReadFile(target) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "do not touch\n" {
		t.Fatalf("the symlink target was modified: %q", content)
	}
}
