//go:build darwin

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDescriptorChainContainment(t *testing.T) {
	root, rc, err := openPinnedAbsolute("/private/tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	child, cc, err := openPinnedAbsolute("/private/tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	if !chainsOverlapAtOrBelow(cc, rc) {
		t.Fatal("equal descriptor ancestry was not detected")
	}
	aliasChain := []identity{
		{Dev: 900, Ino: 1, Type: 0040000, Mode: 0755},
		rc[len(rc)-1],
	}
	if !chainsOverlapAtOrBelow(aliasChain, rc) {
		t.Fatal("alternate mount ancestry of protected root was not detected")
	}
	dev, dc, err := openPinnedAbsolute("/dev")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.close()
	if root.id.Dev == dev.id.Dev {
		t.Skip("host maps /dev to the same filesystem")
	}
	if chainsOverlapAtOrBelow(dc, rc) {
		t.Fatal("cross-filesystem sibling falsely treated as contained")
	}
	if err := requireSameFilesystem(root, dev); err == nil {
		t.Fatal("cross-filesystem directory was not refused")
	}
}

func TestSafeRelativePath(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../x", "/x", "a/../b", "a//b", "a/"} {
		if safeRel(bad) {
			t.Fatalf("accepted unsafe relative path %q", bad)
		}
	}
	if !safeRel("cmd/winn/file.go") {
		t.Fatal("rejected safe relative path")
	}
}

func TestDirectoryOwnerAndModeDriftRejected(t *testing.T) {
	base := identity{Dev: 1, Ino: 2, Type: 0040000, Mode: 0755, UID: 501, GID: 20}
	owner := base
	owner.UID++
	group := base
	group.GID++
	mode := base
	mode.Mode = 0775
	if sameDir(base, owner) || sameDir(base, group) || sameDir(base, mode) {
		t.Fatal("directory owner/group/mode drift was accepted")
	}
}

func TestRecoverRefusesRollbackAfterCommitDecided(t *testing.T) {
	// The guard must fire from the ledger snapshot alone, before any
	// filesystem rollback step is attempted.
	tr := &transaction{
		log: &ledger{events: []event{{Seq: 1, Phase: "decision", Op: "commit-decided"}}},
	}
	err := tr.recover(errors.New("cleanup failed"))
	if err == nil || !strings.Contains(err.Error(), "commit-decided") {
		t.Fatalf("recover after commit-decided = %v, want a refusal naming the decision", err)
	}
	if !strings.Contains(err.Error(), "rollback refused") {
		t.Fatalf("recover after commit-decided = %v, want rollback refused", err)
	}
}
