package main

import "fmt"

// mountFacts is what the controller needs to know about the filesystem a path
// lives on. Every field has an explicit "we could not tell" representation,
// because a probe that reports zero free bytes when it actually failed would
// stop a healthy soak, and one that reports plenty would let a full disk
// through. Available says which of those two mistakes is being avoided.
type mountFacts struct {
	// FilesystemType is a lowercase name where the platform can supply one,
	// or "unknown-0x..." where only a magic number is available.
	FilesystemType string
	ReadOnly       bool
	FreeBytes      int64
	TotalBytes     int64
	// Available is false when this platform cannot answer at all. It is
	// never false merely because a particular field was unsurprising.
	Available bool
}

// disallowedSnapshotFilesystems are refused outright as snapshot roots.
//
// overlay and aufs are union mounts: the bytes a read returns are assembled
// from a lower layer plus a writable upper layer, and a digest taken over the
// merged view says nothing about what either layer contains. The point of
// pinning a snapshot is that its contents are fixed and attributable; a union
// mount can have its upper layer altered underneath a running process, and the
// re-verification this controller performs would then be re-verifying the
// alteration.
//
// ecryptfs and fuse are refused for a narrower reason: both interpose a
// userspace process between the read and the bytes, so "the tree did not
// change" becomes "the helper returned the same answer twice", which is a
// claim about a process rather than about storage.
var disallowedSnapshotFilesystems = map[string]string{
	"overlay":  "a union mount's merged view is not attributable to fixed bytes",
	"overlay2": "a union mount's merged view is not attributable to fixed bytes",
	"aufs":     "a union mount's merged view is not attributable to fixed bytes",
	"ecryptfs": "an interposing userspace layer can vary its answers between reads",
	"fuse":     "an interposing userspace layer can vary its answers between reads",
	"fuseblk":  "an interposing userspace layer can vary its answers between reads",
}

func (m mountFacts) refusalReason() (string, bool) {
	if !m.Available {
		return "", false
	}
	if reason, bad := disallowedSnapshotFilesystems[m.FilesystemType]; bad {
		return fmt.Sprintf(
			"snapshot root is on %s: %s", m.FilesystemType, reason,
		), true
	}
	return "", false
}
