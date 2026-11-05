package securefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestAnonymousSnapshotHasNoPath is the property the whole design rests on: the
// bytes exist, and nothing in the filesystem names them.
func TestAnonymousSnapshotHasNoPath(t *testing.T) {
	content := []byte("PROVIDER KEY BYTES\n")
	snapshot, err := AnonymousSnapshot(content)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()

	read, err := io.ReadAll(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(content) {
		t.Fatalf("snapshot holds %q, want %q", read, content)
	}

	// File.Name retains the exact path originally assigned by CreateTemp even
	// after unlink. Check that path, rather than scanning the shared process
	// temp directory for every snapshot created by concurrent tests or tools.
	if _, err := os.Lstat(snapshot.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"the snapshot left its exact path %s named in the filesystem "+
				"(lstat=%v); anything with a name can be opened, replaced, "+
				"or written through",
			snapshot.Name(), err,
		)
	}
}

// TestAnonymousSnapshotIsImmuneToInPlaceMutation is the specific failure a
// descriptor on a NAMED file does not prevent.
func TestAnonymousSnapshotIsImmuneToInPlaceMutation(t *testing.T) {
	directory := t.TempDir()
	named := filepath.Join(directory, "provider-one.ed25519.pub")
	original := []byte("ORIGINAL KEY BYTES\n")
	if err := os.WriteFile(named, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// The pattern that does NOT work, shown failing, so the reason the
	// snapshot exists is executable rather than asserted in a comment.
	namedDescriptor, err := os.Open(named) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	defer namedDescriptor.Close()

	// The pattern that does work.
	content, err := os.ReadFile(named) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := AnonymousSnapshot(content)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()

	// In-place mutation of the same inode: not a rename, not a replace.
	writable, err := os.OpenFile(named, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writable.WriteAt([]byte("SWAPPED KEY BYTES!"), 0); err != nil {
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}

	// Diagnostic only. Whether this filesystem reflects an in-place write
	// through an already-open descriptor is interesting context, but it must
	// NOT gate the assertion below — an earlier version skipped here, which
	// meant the test could report success without ever checking the property
	// it is named for.
	throughName := make([]byte, len(original))
	if _, err := namedDescriptor.ReadAt(throughName, 0); err != nil {
		t.Fatal(err)
	}
	if string(throughName) == string(original) {
		t.Logf(
			"this filesystem did not reflect the in-place write through the " +
				"existing named descriptor; the snapshot assertion still runs",
		)
	} else {
		t.Logf(
			"the named descriptor now reads %q — which is exactly why holding "+
				"a descriptor on a named file is not enough", throughName,
		)
	}

	// Always executed, never skipped.
	if err := RewindSnapshot(snapshot, content); err != nil {
		t.Fatalf(
			"the anonymous snapshot changed after an in-place write to the "+
				"original file (%v); it is not actually private", err,
		)
	}
	throughSnapshot, err := io.ReadAll(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if string(throughSnapshot) != string(original) {
		t.Fatalf(
			"the snapshot read %q after the original was mutated in place; "+
				"want the original %q", throughSnapshot, original,
		)
	}
}

// TestRewindSnapshotSupportsRepeatedReads covers sequential reuse: an fd read
// to EOF once yields nothing on a second read unless it is rewound.
func TestRewindSnapshotSupportsRepeatedReads(t *testing.T) {
	content := []byte("PROVIDER KEY BYTES\n")
	snapshot, err := AnonymousSnapshot(content)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()

	for round := 0; round < 5; round++ {
		if err := RewindSnapshot(snapshot, content); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		read, err := io.ReadAll(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if string(read) != string(content) {
			t.Fatalf(
				"round %d read %q, want %q; a descriptor reused without "+
					"rewinding yields nothing after the first pass",
				round, read, content,
			)
		}
	}
}

func TestRewindSnapshotDetectsWrongContent(t *testing.T) {
	snapshot, err := AnonymousSnapshot([]byte("one\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if err := RewindSnapshot(snapshot, []byte("two\n")); err == nil {
		t.Fatal("a snapshot holding different bytes was accepted")
	}
	if err := RewindSnapshot(snapshot, []byte("longer content\n")); err == nil {
		t.Fatal("a snapshot of the wrong length was accepted")
	}
}

func TestAnonymousSnapshotRefusesEmptyContent(t *testing.T) {
	if _, err := AnonymousSnapshot(nil); err == nil {
		t.Fatal("an empty snapshot was created")
	}
}
