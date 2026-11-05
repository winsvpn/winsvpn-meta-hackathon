package auditcheckpoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the known-leak scan for what it is and, just as
// importantly, pin what it is NOT.
//
// The security boundary is that the seed is never provisioned to the producing
// host and that the controller is a separate identity. The scan is a secondary
// check for the obvious deployment mistakes. TestLeakScanCannotProveAbsence
// below states that limit as an executable fact, so nobody reads a clean scan
// as proof of custody.

func TestLeakScanFindsNothingInACleanRegion(t *testing.T) {
	runRoot := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(runRoot, "carrier-audit.jsonl"), []byte("{}\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(runRoot, "audit.key"), make([]byte, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	// The audit HMAC writer key is SUPPOSED to be here. Only finalizer material
	// is forbidden, and a probe that confused the two would make every run fail.
	if err := DetectKnownFinalizerLeaks(
		[]string{runRoot}, []string{"PATH=/usr/bin", "RUN_ID=batch-1"},
	); err != nil {
		t.Fatalf("a region with no known leak shapes was refused: %v", err)
	}
}

func TestLeakScanFindsPlantedFinalizerMaterial(t *testing.T) {
	for _, test := range []struct {
		name    string
		plant   func(t *testing.T, root string)
		environ []string
		want    string
	}{
		{
			name: "seed_named_as_a_finalizer",
			plant: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(root, "finalizer.seed"),
					make([]byte, seedSize), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
			want: "finalizer.seed",
		},
		{
			name: "seed_hidden_under_a_neutral_name",
			plant: func(t *testing.T, root string) {
				t.Helper()
				nested := filepath.Join(root, "pki")
				if err := os.MkdirAll(nested, 0o700); err != nil {
					t.Fatal(err)
				}
				// Renaming is the obvious way to hide one, so the shape is
				// checked as well as the name.
				if err := os.WriteFile(
					filepath.Join(nested, "spare.seed"),
					make([]byte, seedSize), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
			want: "spare.seed",
		},
		{
			name:  "environment_points_at_a_credential",
			plant: func(t *testing.T, root string) { _ = root },
			environ: []string{
				"AUDIT_FINALIZER_SEED=/opt/winn-lab/pki/x.bin",
			},
			want: "AUDIT_FINALIZER_SEED",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.plant(t, root)
			environ := test.environ
			if environ == nil {
				environ = []string{"PATH=/usr/bin"}
			}
			err := DetectKnownFinalizerLeaks([]string{root}, environ)
			if err == nil {
				t.Fatal(
					"the producing host accepted finalizer material it could " +
						"read; the checkpoint would be signed by a credential " +
						"the audited party holds",
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf(
					"refusal did not name the material at fault (%s): %v",
					test.want, err,
				)
			}
		})
	}
}

// TestLeakScanIgnoresPermissionBits states, as an executable assertion, why
// permission bits are not the boundary: a 0600 seed owned by the same identity
// the writer runs as is not protection, so the scan must report it exactly as
// loudly as a world-readable one.
func TestLeakScanIgnoresPermissionBits(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "finalizer.seed")
	if err := os.WriteFile(private, make([]byte, seedSize), 0o600); err != nil {
		t.Fatal(err)
	}
	strict := DetectKnownFinalizerLeaks([]string{root}, nil)
	if strict == nil {
		t.Fatal("a 0600 finalizer seed on the producing host was accepted")
	}
	if err := os.Chmod(private, 0o644); err != nil {
		t.Fatal(err)
	}
	loose := DetectKnownFinalizerLeaks([]string{root}, nil)
	if loose == nil {
		t.Fatal("a world-readable finalizer seed was accepted")
	}
	// Same verdict either way: the permission bits were never the boundary.
	if strict.Error() != loose.Error() {
		t.Fatalf(
			"the scan treated permission bits as the boundary:\n0600: %v\n0644: %v",
			strict, loose,
		)
	}
}

// TestLeakScanCannotProveAbsence pins the limit of this check so no caller can
// mistake a clean result for custody.
//
// A seed renamed to something innocuous, or referenced through a variable whose
// name says nothing, passes unnoticed — by construction, because the scan
// matches on names and shapes it knows. This test asserts that miss on purpose.
// If it ever starts failing, the scan grew a stronger claim and the
// documentation around it has to grow with it.
func TestLeakScanCannotProveAbsence(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "neutral.bin"), make([]byte, seedSize), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	err := DetectKnownFinalizerLeaks(
		[]string{root}, []string{"KEY_PATH=" + filepath.Join(root, "neutral.bin")},
	)
	if err != nil {
		t.Fatalf(
			"the scan grew a stronger claim than it is documented to make "+
				"(%v); update the package note and this test together", err,
		)
	}
	// Stated plainly for any reader of this file: the run above is a MISS. The
	// credential is right there. Nothing about a nil return means the host is
	// clean; only never provisioning the seed here does.
}

// TestLeakScanFailsClosedOnAnUnreadableRegion proves the honest failure mode. A
// directory the scan cannot enter is unexamined, and reporting "no leaks found"
// over unexamined ground would be a false statement rather than a conservative
// one.
func TestLeakScanFailsClosedOnAnUnreadableRegion(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(blocked, "finalizer.seed"), make([]byte, seedSize), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	err := DetectKnownFinalizerLeaks([]string{root}, nil)
	if err == nil {
		t.Fatal(
			"an unreadable subtree was silently skipped and the host reported " +
				"clean; an unexamined region is not a clean one",
		)
	}
	if !strings.Contains(err.Error(), "cannot be scanned") {
		t.Fatalf("unreadable subtree rejected for the wrong reason: %v", err)
	}
}

// TestLeakScanFailsClosedOnAMisconfiguredRoot covers the two ways a caller can
// believe a region is being examined when it is not: a root that does not exist
// and a root that is not a directory. Continuing past either would report "no
// leaks found" over ground nobody looked at.
func TestLeakScanFailsClosedOnAMisconfiguredRoot(t *testing.T) {
	directory := t.TempDir()

	t.Run("absent_root", func(t *testing.T) {
		err := DetectKnownFinalizerLeaks(
			[]string{filepath.Join(directory, "not-here")}, nil,
		)
		if err == nil {
			t.Fatal("a scan root that does not exist was silently skipped")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})

	t.Run("root_is_a_regular_file", func(t *testing.T) {
		path := filepath.Join(directory, "not-a-directory")
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := DetectKnownFinalizerLeaks([]string{path}, nil)
		if err == nil {
			t.Fatal("a non-directory scan root was silently skipped")
		}
		if !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})

	t.Run("empty_root", func(t *testing.T) {
		err := DetectKnownFinalizerLeaks([]string{""}, nil)
		if err == nil {
			t.Fatal("an empty scan root was silently skipped and the host reported clean")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Fatalf("unexpected rejection: %v", err)
		}
	})
}

// TestLeakScanReportsASymlinkNamedFinalizer covers the name detector on a
// dirent that is not a regular file. WalkDir visits the symlink; skipping it
// because Type() is not regular reported the host clean while a marker name
// sat in the scanned root.
func TestLeakScanReportsASymlinkNamedFinalizer(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "hidden.bin")
	if err := os.WriteFile(target, make([]byte, seedSize), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "finalizer.seed")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := DetectKnownFinalizerLeaks([]string{root}, nil)
	if err == nil {
		t.Fatal(
			"a symlink named finalizer.seed was silently skipped and the " +
				"host reported clean",
		)
	}
	if !strings.Contains(err.Error(), "finalizer.seed") {
		t.Fatalf("refusal did not name the symlink: %v", err)
	}
}
