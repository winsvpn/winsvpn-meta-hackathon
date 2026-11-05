// Atomic no-replace directory publication.
//
// The property under test is not "the second attempt is refused" — that is a
// weaker statement that a visibly-partial publication also satisfies. It is
// that the destination path is NEVER observable in an incomplete state: at
// every instant it either does not exist or holds the complete directory.
//
// These run on whatever platform the suite runs on. Linux uses renameat2
// (RENAME_NOREPLACE); Darwin uses renamex_np (RENAME_EXCL). Both are asserted
// here by behaviour rather than by inspecting which primitive was chosen, so
// the same file proves the guarantee on either.
package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func preparedDirectory(t *testing.T, entries map[string]string) string {
	t.Helper()
	prepared := filepath.Join(t.TempDir(), "pending")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range entries {
		if err := os.WriteFile(
			filepath.Join(prepared, name), []byte(content), 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	return prepared
}

func slotEntries() map[string]string {
	return map[string]string{
		"provider-config.json":             "{}\n",
		"provider-one.receipt.json":        "{\"one\":1}\n",
		"provider-one.receipt.json.sha256": "aa\n",
		"provider-two.receipt.json":        "{\"two\":2}\n",
		"provider-two.receipt.json.sha256": "bb\n",
		"request.json":                     "{\"r\":1}\n",
		"request.json.sha256":              "cc\n",
	}
}

func TestPublishDirectoryNoReplacePublishesCompletely(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "000001-batch")
	prepared := preparedDirectory(t, slotEntries())
	if err := PublishDirectoryNoReplace(prepared, destination); err != nil {
		t.Fatalf("publication failed: %v", err)
	}
	published, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(published) != len(slotEntries()) {
		t.Fatalf(
			"the destination holds %d entries, want %d",
			len(published), len(slotEntries()),
		)
	}
	if _, err := os.Lstat(prepared); !os.IsNotExist(err) {
		t.Fatal("the prepared directory survived publication")
	}
}

// TestPublishDirectoryNeverReplacesAnIncumbent covers every destination shape a
// prior attempt can leave, including the EMPTY directory that plain rename(2)
// is required by POSIX to replace.
func TestPublishDirectoryNeverReplacesAnIncumbent(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, destination string)
		verify  func(t *testing.T, destination string)
	}{
		{
			name: "empty_directory",
			prepare: func(t *testing.T, destination string) {
				t.Helper()
				// The case that matters. rename(2) replaces this on Linux.
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, destination string) {
				t.Helper()
				entries, err := os.ReadDir(destination)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatal("the empty incumbent was replaced")
				}
			},
		},
		{
			name: "populated_directory",
			prepare: func(t *testing.T, destination string) {
				t.Helper()
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(
					filepath.Join(destination, "incumbent.json"),
					[]byte("first attempt\n"), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, destination string) {
				t.Helper()
				content, err := os.ReadFile( // #nosec G304 -- test temp path
					filepath.Join(destination, "incumbent.json"))
				if err != nil {
					t.Fatal("the incumbent's contents were removed")
				}
				if string(content) != "first attempt\n" {
					t.Fatal("the incumbent's contents changed")
				}
			},
		},
		{
			name: "regular_file",
			prepare: func(t *testing.T, destination string) {
				t.Helper()
				if err := os.WriteFile(
					destination, []byte("not a slot\n"), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, destination string) {
				t.Helper()
				content, err := os.ReadFile(destination) // #nosec G304 -- temp
				if err != nil || string(content) != "not a slot\n" {
					t.Fatal("the incumbent file was replaced")
				}
			},
		},
		{
			name: "dangling_symlink",
			prepare: func(t *testing.T, destination string) {
				t.Helper()
				// [ -e ] and os.Stat both call this absent.
				if err := os.Symlink(
					filepath.Join(filepath.Dir(destination), "gone"),
					destination,
				); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			verify: func(t *testing.T, destination string) {
				t.Helper()
				info, err := os.Lstat(destination)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("the dangling symlink was replaced")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "000001-batch")
			test.prepare(t, destination)
			prepared := preparedDirectory(t, slotEntries())

			err := PublishDirectoryNoReplace(prepared, destination)
			if err == nil {
				t.Fatal(
					"publication replaced an existing destination; a second " +
						"set of provider receipts would overwrite the first " +
						"for the same ordinal",
				)
			}
			if !errors.Is(err, os.ErrExist) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			test.verify(t, destination)
		})
	}
}

// TestPublishDirectoryIsNeverObservablyPartial is the requirement stated
// directly. An observer polling the destination throughout a publication must
// see it either absent or complete, never in between.
func TestPublishDirectoryIsNeverObservablyPartial(t *testing.T) {
	const rounds = 40
	entries := slotEntries()
	for round := 0; round < rounds; round++ {
		directory := t.TempDir()
		destination := filepath.Join(directory, "000001-batch")
		prepared := preparedDirectory(t, entries)

		stop := make(chan struct{})
		partial := make(chan int, 1)
		var observer sync.WaitGroup
		observer.Add(1)
		go func() {
			defer observer.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				found, err := os.ReadDir(destination)
				if err != nil {
					// Absent is fine; it is the only other legal state.
					continue
				}
				if len(found) != len(entries) {
					select {
					case partial <- len(found):
					default:
					}
					return
				}
			}
		}()

		if err := PublishDirectoryNoReplace(prepared, destination); err != nil {
			close(stop)
			observer.Wait()
			t.Fatalf("publication failed: %v", err)
		}
		close(stop)
		observer.Wait()
		select {
		case count := <-partial:
			t.Fatalf(
				"the destination was observable holding %d of %d entries; a "+
					"crash at that instant would leave a directory every "+
					"observer reads as a committed slot",
				count, len(entries),
			)
		default:
		}
	}
}

// TestPublishDirectoryHasExactlyOneWinner races concurrent publishers for one
// destination.
func TestPublishDirectoryHasExactlyOneWinner(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "000001-batch")
	const publishers = 8
	prepared := make([]string, publishers)
	for index := range prepared {
		prepared[index] = preparedDirectory(t, map[string]string{
			"request.json": "{\"publisher\":" + string(rune('0'+index)) + "}\n",
		})
	}
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	results := make([]error, publishers)
	for index := 0; index < publishers; index++ {
		done.Add(1)
		go func(index int) {
			defer done.Done()
			start.Wait()
			results[index] = PublishDirectoryNoReplace(
				prepared[index], destination)
		}(index)
	}
	start.Done()
	done.Wait()

	winners := 0
	for index, err := range results {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, os.ErrExist) {
			t.Fatalf("publisher %d failed unexpectedly: %v", index, err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d publishers won the race, want exactly 1", winners)
	}
	published, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(published) != 1 {
		t.Fatalf("the destination holds %d entries, want 1", len(published))
	}
}

// TestPublishDirectoryRejectsAnUnusablePreparedPath keeps the input side
// honest.
func TestPublishDirectoryRejectsAnUnusablePreparedPath(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "000001-batch")

	if err := PublishDirectoryNoReplace(
		filepath.Join(directory, "absent"), destination,
	); err == nil {
		t.Fatal("an absent prepared directory was published")
	}
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PublishDirectoryNoReplace(regular, destination); err == nil {
		t.Fatal("a regular file was published as a directory")
	}
}

// TestRenameNoReplacePrimitiveRefusesAnEmptyIncumbent exercises the platform
// primitive directly, bypassing PublishDirectoryNoReplace's Lstat pre-check.
//
// That pre-check is a convenience, not the guarantee: it is inherently
// TOCTOU-prone, and a destination created between the check and the rename is
// exactly the race the atomic flag exists for. A test that goes through the
// wrapper is satisfied by the pre-check alone — swapping the primitive for
// plain os.Rename leaves such a test passing, which is precisely how the
// original defect survived on a Darwin-only suite.
//
// The empty-directory case is the one that matters. POSIX REQUIRES rename(2) to
// replace an existing empty directory, and an empty or partially-cleaned
// committed slot is what an interrupted attempt leaves behind.
func TestRenameNoReplacePrimitiveRefusesAnEmptyIncumbent(t *testing.T) {
	directory := t.TempDir()
	prepared := filepath.Join(directory, "pending")
	if err := os.Mkdir(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(prepared, "request.json"), []byte("{}\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "committed")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}

	err := renameNoReplace(prepared, destination)
	if errors.Is(err, errRenameNoReplaceUnsupported) {
		t.Skip("no atomic no-replace rename on this platform")
	}
	if err == nil {
		t.Fatal(
			"the rename primitive replaced an existing empty directory. " +
				"POSIX requires plain rename(2) to do exactly that, so this " +
				"is the case an atomic no-replace flag exists to prevent — a " +
				"second set of provider receipts would overwrite the first " +
				"for the same ordinal",
		)
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("the primitive failed for an unexpected reason: %v", err)
	}
	// The incumbent is untouched and the prepared directory still exists, so
	// the caller can retry or report without having lost anything.
	if entries, readErr := os.ReadDir(destination); readErr != nil ||
		len(entries) != 0 {
		t.Fatal("the empty incumbent was modified")
	}
	if _, statErr := os.Lstat(
		filepath.Join(prepared, "request.json"),
	); statErr != nil {
		t.Fatal("the prepared directory was consumed by a failed rename")
	}
}

// TestRenameNoReplacePrimitivePublishesOntoAFreeName is the positive control
// for the primitive: it must still succeed when the destination is free.
func TestRenameNoReplacePrimitivePublishesOntoAFreeName(t *testing.T) {
	directory := t.TempDir()
	prepared := filepath.Join(directory, "pending")
	if err := os.Mkdir(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(prepared, "request.json"), []byte("{}\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "committed")
	err := renameNoReplace(prepared, destination)
	if errors.Is(err, errRenameNoReplaceUnsupported) {
		t.Skip("no atomic no-replace rename on this platform")
	}
	if err != nil {
		t.Fatalf("the primitive refused a free destination: %v", err)
	}
	if _, statErr := os.Lstat(
		filepath.Join(destination, "request.json"),
	); statErr != nil {
		t.Fatalf("the published directory is incomplete: %v", statErr)
	}
}
