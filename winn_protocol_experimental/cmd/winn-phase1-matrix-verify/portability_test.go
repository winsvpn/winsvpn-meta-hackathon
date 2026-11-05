// The verifier's platform boundary.
//
// Sealed evidence is meant to be independently re-verifiable by any third party
// on any platform, and the canonical-path work in main.go exists to make the
// verifier's ACCEPTED SET identical everywhere. That claim was empty while this
// binary could not be compiled for Windows at all: internal/phase1anchor held
// the provider's POSIX append-only ledger — flock(2), open(2) with O_NOFOLLOW —
// in the same package as the request/receipt protocol types, with no build
// constraint, so `GOOS=windows go build ./cmd/winn-phase1-matrix-verify` failed
// on syscalls this binary never calls.
//
// The ledger now sits behind `//go:build unix`. There is deliberately no
// non-unix ledger: a stub returning success would claim provider support that
// does not exist. The narrow claim is that the VERIFIER is portable, not that
// the anchor server is.
//
// A test that merely built the binary would pass for the wrong reason the day
// someone adds a Unix-only import that Go happens to satisfy through a
// different path. So the invariant asserted here is structural: under
// GOOS=windows, golang.org/x/sys/unix must not appear anywhere in this
// binary's transitive dependency set.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// unixSyscallPackage is the package that carries the ledger's flock/O_NOFOLLOW
// primitives. Reaching it from the verifier means the boundary has been broken.
const unixSyscallPackage = "golang.org/x/sys/unix"

// goToolPath locates the toolchain that runs these tests.
//
// PATH, not runtime.GOROOT: that function is deprecated because the value it
// reports is the root the test BINARY was built against, which says nothing
// about the machine actually running it.
func goToolPath(t *testing.T) string {
	t.Helper()
	found, err := exec.LookPath("go")
	if err != nil {
		t.Skipf(
			"no go toolchain is on PATH, so the platform boundary cannot be "+
				"checked here: %v", err,
		)
	}
	return found
}

// TestVerifierDependencySurfaceExcludesUnixLedgerSyscalls is the structural
// half of the boundary.
func TestVerifierDependencySurfaceExcludesUnixLedgerSyscalls(t *testing.T) {
	command := exec.Command( // #nosec G204 -- the toolchain running this test
		goToolPath(t), "list", "-deps",
		"winsvpn.local/winnprotocol/cmd/winn-phase1-matrix-verify",
	)
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"the verifier's dependency graph could not be resolved for "+
				"windows/amd64, which by itself means it is not portable: "+
				"%v\n%s", err, output,
		)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == unixSyscallPackage {
			t.Fatalf(
				"the verifier reaches %s on windows/amd64. The provider's "+
					"POSIX ledger has leaked back into the portable surface, "+
					"and a third-party auditor on a non-POSIX host cannot "+
					"build the binary that checks the evidence.\n%s",
				unixSyscallPackage, output,
			)
		}
	}
}

// TestVerifierBuildsForWindows is the end-to-end half: the boundary holding in
// the import graph is necessary, and actually producing an executable is what
// an auditor needs.
func TestVerifierBuildsForWindows(t *testing.T) {
	output := filepath.Join(t.TempDir(), "winn-phase1-matrix-verify.exe")
	command := exec.Command( // #nosec G204 -- the toolchain running this test
		goToolPath(t), "build", "-o", output,
		"winsvpn.local/winnprotocol/cmd/winn-phase1-matrix-verify",
	)
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf(
			"the formal verifier does not build for windows/amd64: %v\n%s",
			err, combined,
		)
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() == 0 {
		t.Fatalf("no windows executable was produced: %v", err)
	}
}

// buildConstraint returns the //go:build directive a file declares, if any.
//
// A directive is a LINE of its own above the package clause, so this scans
// lines rather than substring-matching the whole file — otherwise the comment
// in rejection.go that explains where the constraint lives would itself read as
// a constraint, and the invariant would report the opposite of the truth.
func buildConstraint(source string) (string, bool) {
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			return "", false
		}
		if strings.HasPrefix(trimmed, "//go:build") {
			return trimmed, true
		}
	}
	return "", false
}

// TestPOSIXOnlyComponentsStateTheirConstraint pins the other direction. The
// boundary is only truthful if the POSIX side says so in source, rather than
// being discovered at link time on somebody else's machine.
func TestPOSIXOnlyComponentsStateTheirConstraint(t *testing.T) {
	for _, file := range []string{
		"../../internal/phase1anchor/ledger.go",
		"../../cmd/winn-phase1-anchor-server/main.go",
	} {
		t.Run(filepath.Base(filepath.Dir(file)), func(t *testing.T) {
			source, err := os.ReadFile(file) // #nosec G304 -- fixed repo path
			if err != nil {
				t.Fatal(err)
			}
			constraint, ok := buildConstraint(string(source))
			if !ok || !strings.Contains(constraint, "unix") {
				t.Fatalf(
					"%s carries POSIX-only primitives but declares no unix "+
						"build constraint (found %q), so it is compiled into "+
						"every platform's build and breaks it there",
					file, constraint,
				)
			}
		})
	}
	// And the portable half must stay portable.
	source, err := os.ReadFile("../../internal/phase1anchor/rejection.go")
	if err != nil {
		t.Fatal(err)
	}
	if constraint, ok := buildConstraint(string(source)); ok {
		t.Fatalf(
			"rejection.go has acquired the build constraint %q; it holds the "+
				"protocol types the verifier needs on every platform",
			constraint,
		)
	}
}
