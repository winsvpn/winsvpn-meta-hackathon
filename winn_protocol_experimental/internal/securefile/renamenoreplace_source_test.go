package securefile

import (
	"os"
	"strings"
	"testing"
)

// Source-level invariants on the no-replace rename implementations.
//
// These exist because a behavioural test cannot reliably catch the regression
// they guard against.
//
// Go's os.Rename begins with its own Lstat of the destination and returns
// EEXIST for directory-onto-different-directory before issuing the syscall
// (src/os/file_unix.go). So a mutant that replaced unix.Renameat2 with
// os.Rename would still refuse in every easily constructed test — the symptom
// is masked by Go's pre-check. The failure it introduces is a RACE: the
// destination appearing after that pre-check and before the rename lands, which
// is not deterministically triggerable from a test.
//
// The pre-check is also not a substitute for the flag. It is a convenience in
// front of a syscall that will happily replace, whereas RENAME_NOREPLACE makes
// the kernel itself refuse atomically. Production must request the flag; these
// tests make silently dropping it a build-visible failure rather than a
// latent race.

func requireImplementation(t *testing.T, path string, checks func(string)) {
	t.Helper()
	source, err := os.ReadFile(path) // #nosec G304 -- repository source file
	if err != nil {
		t.Skipf("%s is not present on this platform: %v", path, err)
	}
	var code []string
	for _, line := range strings.Split(string(source), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code = append(code, line)
	}
	checks(strings.Join(code, "\n"))
}

func TestLinuxNoReplaceUsesRenameat2WithTheFlag(t *testing.T) {
	requireImplementation(t, "renamenoreplace_linux.go", func(code string) {
		if !strings.Contains(code, "unix.Renameat2(") {
			t.Fatal(
				"renamenoreplace_linux.go no longer calls unix.Renameat2; " +
					"the atomic no-replace guarantee comes from that syscall",
			)
		}
		if !strings.Contains(code, "unix.RENAME_NOREPLACE") {
			t.Fatal(
				"renamenoreplace_linux.go no longer passes " +
					"unix.RENAME_NOREPLACE; without the flag renameat2 is a " +
					"plain replacing rename",
			)
		}
		for _, forbidden := range []string{
			"os.Rename(", "syscall.Rename(",
		} {
			if strings.Contains(code, forbidden) {
				t.Fatalf(
					"renamenoreplace_linux.go uses %s. Go's os.Rename has its "+
						"own Lstat pre-check that masks this in ordinary "+
						"tests, so the regression would surface only as a "+
						"race: the destination appearing between that "+
						"pre-check and the rename", forbidden,
				)
			}
		}
	})
}

func TestDarwinNoReplaceUsesRenamexNpWithTheFlag(t *testing.T) {
	requireImplementation(t, "renamenoreplace_darwin.go", func(code string) {
		if !strings.Contains(code, "unix.RenamexNp(") {
			t.Fatal(
				"renamenoreplace_darwin.go no longer calls unix.RenamexNp",
			)
		}
		if !strings.Contains(code, "unix.RENAME_EXCL") {
			t.Fatal(
				"renamenoreplace_darwin.go no longer passes unix.RENAME_EXCL",
			)
		}
		for _, forbidden := range []string{
			"os.Rename(", "syscall.Rename(",
		} {
			if strings.Contains(code, forbidden) {
				t.Fatalf(
					"renamenoreplace_darwin.go uses %s rather than the raw "+
						"no-replace primitive", forbidden,
				)
			}
		}
	})
}

// TestUnsupportedPlatformsFailClosed pins that a platform without a native
// primitive refuses rather than degrading to a replacing rename.
func TestUnsupportedPlatformsFailClosed(t *testing.T) {
	requireImplementation(t, "renamenoreplace_other.go", func(code string) {
		if strings.Contains(code, "os.Rename(") ||
			strings.Contains(code, "syscall.Rename(") {
			t.Fatal(
				"the unsupported-platform fallback performs a rename; it must " +
					"refuse, because a replacing rename there would silently " +
					"overwrite a committed slot",
			)
		}
		if !strings.Contains(code, "errRenameNoReplaceUnsupported") {
			t.Fatal(
				"the unsupported-platform fallback no longer reports that it " +
					"is unsupported",
			)
		}
	})
}
