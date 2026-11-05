//go:build !windows

package replaystore

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestJournalOwnerModeAllowed is the pure policy over one stat result, so
// every refusal is exercised deterministically without needing root to chown
// fixtures in the unprivileged case.
func TestJournalOwnerModeAllowed(t *testing.T) {
	euid := os.Geteuid()
	other := euid + 1
	if other == 0 {
		other = 2
	}
	refused := []struct {
		uid    int
		mode   os.FileMode
		needle string
	}{
		{other, 0o640, "uid"},
		{euid, 0o644, "mode"},
		{euid, 0o777, "mode"},
		{euid, 0o660, "mode"},
		{euid, 0o222, "mode"},
		{euid, 0o400, "mode"},
	}
	for _, tc := range refused {
		err := journalOwnerModeAllowed(tc.uid, tc.mode, euid)
		if err == nil || !strings.Contains(err.Error(), tc.needle) {
			t.Errorf("uid %d mode %#o: got %v, want a refusal naming %q", tc.uid, tc.mode, err, tc.needle)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o640} {
		if err := journalOwnerModeAllowed(euid, mode, euid); err != nil {
			t.Errorf("uid %d mode %#o must pass, got %v", euid, mode, err)
		}
	}
}

// TestOpenRefusesAForeignOwner is the integration half of the ownership
// policy, runnable only where chown works: as root the file can genuinely
// change hands and Open must refuse it.
func TestOpenRefusesAForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Logf("running unprivileged (euid %d); the chown integration case needs root and the pure policy is pinned by TestJournalOwnerModeAllowed", os.Geteuid())
		return
	}
	path := writeJournal(t, t.TempDir(), "replay.journal", nil, 0o600)
	if err := os.Chown(path, 12345, -1); err != nil {
		t.Fatal(err)
	}
	_, _, err := Open(path, time.Unix(1_700_000_000, 0))
	if err == nil || !strings.Contains(err.Error(), "uid") {
		t.Fatalf("a journal owned by uid 12345 was not refused as foreign-owned: %v", err)
	}
}
