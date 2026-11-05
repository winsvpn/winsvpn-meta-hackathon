// LinuxExecAllowList, tested against what it actually claims.
//
// The point of these tests is as much to PIN THE LIMITS as to confirm the
// refusals. The type's earlier comment described it as making "this process
// only ever runs these binaries" an enforced property, and a test suite that
// only exercised the happy refusals would have left that reading standing.
// Several cases below assert acceptance of things a content or identity pin
// would reject — because this is not one, and a future reader should find that
// written down as a deliberate, tested boundary rather than discover it.
package directawg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLinuxExecAllowListRejectsUnusableConfiguration(t *testing.T) {
	t.Run("no_entries", func(t *testing.T) {
		if _, err := NewLinuxExecAllowList(); err == nil {
			t.Fatal("an empty allow-list was accepted")
		}
	})
	t.Run("only_empty_entries", func(t *testing.T) {
		// Empty strings are skipped so a harness with an optional binary does
		// not have to special-case it, but skipping every entry leaves a list
		// that refuses everything. That is a configuration error, not a very
		// strict policy, and it must be reported at construction.
		if _, err := NewLinuxExecAllowList("", "", ""); err == nil {
			t.Fatal("an allow-list of only empty entries was accepted")
		}
	})
	t.Run("relative_path", func(t *testing.T) {
		// A relative name is resolved against PATH at exec time, so the set it
		// denotes is not fixed and the whole exercise would be pointless.
		if _, err := NewLinuxExecAllowList("/bin/ip", "nft"); err == nil {
			t.Fatal("a relative executable name was accepted")
		}
	})
	t.Run("bare_name", func(t *testing.T) {
		if _, err := NewLinuxExecAllowList("ip"); err == nil {
			t.Fatal("a bare command name was accepted")
		}
	})
}

func TestLinuxExecAllowListRequire(t *testing.T) {
	list, err := NewLinuxExecAllowList("/usr/sbin/nft", "/usr/bin/ip", "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil_receiver_refuses", func(t *testing.T) {
		var absent *LinuxExecAllowList
		if err := absent.Require("/usr/bin/ip"); err == nil {
			t.Fatal(
				"a runner with no allow-list accepted a command; forgetting " +
					"to wire one up must not be indistinguishable from being " +
					"configured with everything",
			)
		}
	})

	t.Run("exact_member_accepted", func(t *testing.T) {
		for _, path := range []string{"/usr/sbin/nft", "/usr/bin/ip"} {
			if err := list.Require(path); err != nil {
				t.Fatalf("a configured executable %q was refused: %v", path, err)
			}
		}
	})

	t.Run("empty_path_refused", func(t *testing.T) {
		if err := list.Require(""); err == nil {
			t.Fatal("the empty path was accepted")
		}
	})

	// Aliases. Every one of these denotes the same file on a real filesystem,
	// and every one is refused, because the rule is string membership and
	// normalising would admit paths the operator never named.
	t.Run("aliases_refused", func(t *testing.T) {
		for _, alias := range []string{
			"/usr/bin/./ip",
			"/usr/bin//ip",
			"/usr/bin/../bin/ip",
			"/usr/bin/ip/",
			"/USR/BIN/IP",
			"ip",
			"./ip",
			"/usr/local/bin/ip",
		} {
			if err := list.Require(alias); err == nil {
				t.Fatalf(
					"the alias %q was accepted; membership must be exact "+
						"string equality against what the operator named",
					alias,
				)
			}
		}
	})

	t.Run("refusal_names_the_configured_set", func(t *testing.T) {
		err := list.Require("/bin/sh")
		if err == nil {
			t.Fatal("/bin/sh was accepted")
		}
		for _, expected := range []string{"/bin/sh", "/usr/bin/ip", "/usr/sbin/nft"} {
			if !strings.Contains(err.Error(), expected) {
				t.Fatalf("refusal %q does not mention %s", err, expected)
			}
		}
	})

	t.Run("paths_are_stable_and_drop_empties", func(t *testing.T) {
		paths := list.Paths()
		if len(paths) != 2 ||
			paths[0] != "/usr/bin/ip" || paths[1] != "/usr/sbin/nft" {
			t.Fatalf("Paths() = %v", paths)
		}
		var absent *LinuxExecAllowList
		if absent.Paths() != nil {
			t.Fatal("a nil list reported paths")
		}
	})
}

// TestLinuxExecAllowListDoesNotPinTheExecutableObject is the LIMIT test, and it
// asserts ACCEPTANCE on purpose.
//
// Replacing the file at a configured path with entirely different content is
// still allowed, because nothing here binds an inode or a digest. This is the
// exact overclaim being corrected: a reader must not take this list for a
// content control. If a future change does start pinning identity, this test
// fails and forces the type comment to be rewritten with it.
func TestLinuxExecAllowListDoesNotPinTheExecutableObject(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	list, err := NewLinuxExecAllowList(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Require(path); err != nil {
		t.Fatal(err)
	}

	// Same path, different bytes, different inode.
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(
		replacement, []byte("#!/bin/sh\nexit 1\n"), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := list.Require(path); err != nil {
		t.Fatalf(
			"same-path replacement was refused (%v). That would be a stronger "+
				"control than this type provides, and if it is now real the "+
				"type comment must stop saying it pins names rather than "+
				"objects", err,
		)
	}

	// And a symbolic link to the allowed path is refused even though it
	// resolves to the very same file — the mirror image of the case above, and
	// together they show precisely what the rule is: the string, nothing else.
	link := filepath.Join(directory, "alias")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := list.Require(link); err == nil {
		t.Fatal("a symbolic link to the configured path was accepted")
	}
}

// TestUncoveredExecBoundariesAreStillUncovered pins the second half of the
// narrowed claim: this package has exec paths the allow-list does not reach,
// and the type comment names them. A structural check keeps that statement true
// rather than letting it rot into another stale comment.
func TestUncoveredExecBoundariesAreStillUncovered(t *testing.T) {
	for _, uncovered := range []struct {
		file    string
		symbol  string
		context string
	}{
		{"linux_exec.go", "func (execLinuxRunner) Run(", "Core default runner"},
		{"linux_exec.go", "func (execLinuxRunner) Start(", "Core default runner"},
		{"status_cli.go", "func runBoundedStatusCommand(", "CLIStatusSource"},
	} {
		source, err := os.ReadFile(uncovered.file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		at := strings.Index(text, uncovered.symbol)
		if at < 0 {
			t.Fatalf(
				"%s no longer contains %s; the allow-list's scope note names "+
					"it as an uncovered exec boundary and must be updated "+
					"together with the code",
				uncovered.file, uncovered.symbol,
			)
		}
		// If one of these ever DOES gain allow-list enforcement, that is good
		// news and the type comment stops being accurate, so this fails.
		end := strings.Index(text[at:], "\n}\n")
		if end < 0 {
			t.Fatalf("could not delimit %s in %s",
				uncovered.symbol, uncovered.file)
		}
		body := text[at : at+end]
		if strings.Contains(body, "Require(") {
			t.Fatalf(
				"%s (%s) now enforces an allow-list. That is an improvement, "+
					"and LinuxExecAllowList's type comment must stop listing "+
					"it as an uncovered exec boundary",
				uncovered.symbol, uncovered.context,
			)
		}
	}

	// The scope note itself has to still name them, or the honest narrowing
	// has been silently dropped.
	note, err := os.ReadFile("exec_allowlist.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"execLinuxRunner",
		"runBoundedStatusCommand",
		"SELECTED HARNESS RUNNERS REFUSE PATH NAMES",
	} {
		if !strings.Contains(string(note), required) {
			t.Fatalf(
				"exec_allowlist.go no longer states %q; the narrowed claim is "+
					"the correction this file exists to hold", required,
			)
		}
	}
}
