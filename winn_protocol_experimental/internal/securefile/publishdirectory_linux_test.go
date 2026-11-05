//go:build linux

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRawKernelRenameReplacesAnEmptyDirectory is the "unsafe control": it
// proves the KERNEL is replace-capable, which is the entire reason production
// must request RENAME_NOREPLACE explicitly.
//
// It uses the raw syscall, and that choice is the whole point of this test.
//
// An earlier version used os.Rename and asserted that it replaced an empty
// incumbent. That assertion is false on every platform, and Codex caught it by
// actually running it in a Linux container. Go's os.Rename (src/os/file_unix.go)
// begins with its own Lstat of the destination: if the destination is a
// directory and is not SameFile as the source, it returns syscall.EEXIST
// BEFORE issuing syscall.Rename at all. So os.Rename never exposes kernel
// rename semantics for directory-onto-directory, and a test built on it cannot
// distinguish a correct RENAME_NOREPLACE implementation from an incorrect
// os.Rename one — it fails against both.
//
// That also corrects an earlier claim in this package's own comments: the
// reason a plain-rename mutant appeared to be refused on macOS was Go's
// pre-check, not anything APFS does. The pre-check is a Go-level convenience on
// a path that production must not depend on, because it does not cover the race
// it looks like it covers — the destination appearing after the pre-check and
// before the rename.
func TestRawKernelRenameReplacesAnEmptyDirectory(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(source, "marker")
	if err := os.WriteFile(
		marker, []byte("second attempt\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "destination")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}

	// flags = 0 is plain rename(2) at the kernel level, with none of Go's
	// pre-checking in front of it.
	err := unix.Renameat2(
		unix.AT_FDCWD, source, unix.AT_FDCWD, destination, 0,
	)
	if errors.Is(err, unix.ENOSYS) {
		t.Skip("renameat2 is unavailable on this kernel")
	}
	if err != nil {
		t.Fatalf(
			"the raw kernel rename refused to replace an empty directory "+
				"(%v). If this becomes the kernel's behaviour, the reasoning "+
				"behind requesting RENAME_NOREPLACE should be revisited — but "+
				"production should keep requesting it regardless, because "+
				"relying on an implicit refusal is what this whole design "+
				"avoids", err,
		)
	}
	// The incumbent is gone and the source's contents took its place.
	if _, err := os.Lstat(filepath.Join(destination, "marker")); err != nil {
		t.Fatal("the raw kernel rename did not actually replace the incumbent")
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatal("the source survived a successful rename")
	}
}

// TestRenameat2NoReplaceRefusesAnEmptyDirectory is the production primitive,
// exercised directly against the same scenario the raw call above replaces.
func TestRenameat2NoReplaceRefusesAnEmptyDirectory(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(source, "marker"), []byte("second attempt\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "destination")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}

	err := unix.Renameat2(
		unix.AT_FDCWD, source, unix.AT_FDCWD, destination,
		unix.RENAME_NOREPLACE,
	)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
		t.Skip("renameat2(RENAME_NOREPLACE) is unavailable on this filesystem")
	}
	if err == nil {
		t.Fatal(
			"renameat2(RENAME_NOREPLACE) replaced an existing empty " +
				"directory; the no-replace guarantee does not hold here",
		)
	}
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("renameat2 failed for an unexpected reason: %v", err)
	}
	// Nothing moved: the incumbent is untouched and the source survives, so the
	// caller can retry or report without having lost anything.
	entries, readErr := os.ReadDir(destination)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("the empty incumbent was modified")
	}
	if _, statErr := os.Lstat(filepath.Join(source, "marker")); statErr != nil {
		t.Fatal("the source was consumed by a refused rename")
	}
}

// TestPublishDirectoryNoReplaceHoldsOnLinux exercises the wrapper against the
// empty-incumbent case on the platform where production runs.
func TestPublishDirectoryNoReplaceHoldsOnLinux(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "000001-batch")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	prepared := preparedDirectory(t, slotEntries())
	err := PublishDirectoryNoReplace(prepared, destination)
	if err == nil {
		t.Fatal("an existing empty committed slot was replaced")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("the empty incumbent was modified")
	}
}
