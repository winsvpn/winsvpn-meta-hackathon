// Canonicality of RECORDED protocol paths in the formal verifier.
//
// Evidence is sealed once and is meant to be independently re-verifiable by any
// third party on any platform. That only holds if the names recorded inside it
// are treated as protocol strings rather than as local pathnames. `filepath` is
// the host's pathname package: on Windows it cleans "a/b" to "a\\b", it strips a
// "C:" volume prefix in Base, and it reports IsAbs("/opt/x") as FALSE. Every one
// of those makes the verifier's ACCEPTED SET depend on the auditor's operating
// system, which is the one thing a verifier must never do.
//
// On Linux and macOS the two packages return identical strings for these
// inputs, so no behavioural test on this workstation can distinguish them by
// output alone — which is exactly why the defect survived. The tests here
// therefore combine three things: pinned behaviour over the inputs that matter
// (including the nested and backslash cases the old code got wrong), an
// explicit statement of the divergence, and per-function source invariants that
// fail the moment `filepath` is reintroduced into a protocol-path decision.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeEvidenceTree materialises an evidence directory holding the given
// members and a real sha256 manifest over them, in the exact `sha256sum`
// two-space format the sealer emits.
func writeEvidenceTree(
	t *testing.T, members map[string]string, extraLines []string,
) string {
	t.Helper()
	directory := t.TempDir()
	var lines []string
	for name, content := range members {
		full := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		lines = append(lines, hex.EncodeToString(sum[:])+"  ./"+name)
	}
	lines = append(lines, extraLines...)
	if err := os.WriteFile(
		filepath.Join(directory, "evidence-manifest.sha256"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	return directory
}

// TestEvidenceManifestAcceptsNestedRecordedPaths pins the accepted set.
//
// The sealer builds the manifest with `find . -type f`, so nested members are
// the normal case, not an exotic one. Under the old filepath-based check every
// one of these entries was rejected on Windows — filepath.Clean("a/b") returns
// "a\\b" there, which never equals the recorded value — while the identical
// evidence passed on Linux and macOS.
func TestEvidenceManifestAcceptsNestedRecordedPaths(t *testing.T) {
	directory := writeEvidenceTree(t, map[string]string{
		"result.txt":                    "PASS\n",
		"diagnostics/client/root.txt":   "client\n",
		"diagnostics/server/qdisc.json": "{}\n",
		"a/b/c/deep.txt":                "deep\n",
	}, nil)
	if err := verifyEvidenceManifest(directory); err != nil {
		t.Fatalf(
			"a manifest of canonical nested protocol paths was refused on %s: %v",
			runtime.GOOS, err,
		)
	}
}

// TestEvidenceManifestRefusesNonProtocolPaths covers the rejected set, and the
// backslash case is a genuine behavioural change rather than a portability
// nicety.
//
// A backslash is a legal filename byte on Linux and macOS and a DIRECTORY
// SEPARATOR on Windows. The old check ran filepath.Clean, which on this
// platform leaves "outer\\inner" untouched — so a file literally named
// "outer\inner" was accepted here and would have been read as "outer/inner"
// there. One sealed manifest, two different sets of bytes hashed, depending on
// who verifies it. The protocol has exactly one separator; anything else is an
// illegal character and is refused identically everywhere.
func TestEvidenceManifestRefusesNonProtocolPaths(t *testing.T) {
	// A real file whose NAME contains a backslash. This is what makes the case
	// behavioural rather than hypothetical: the target exists, its digest is
	// correct, and the only reason to refuse it is the character itself.
	backslash := "outer\\inner"
	sum := sha256.Sum256([]byte("planted\n"))
	directory := writeEvidenceTree(t, map[string]string{
		"result.txt": "PASS\n",
	}, []string{hex.EncodeToString(sum[:]) + "  ./" + backslash})
	if err := os.WriteFile(
		filepath.Join(directory, backslash), []byte("planted\n"), 0o600,
	); err != nil {
		t.Skipf("this filesystem cannot hold a backslash in a name: %v", err)
	}
	err := verifyEvidenceManifest(directory)
	if err == nil {
		t.Fatal(
			"a manifest entry containing a backslash was accepted; the same " +
				"sealed manifest would name a different file on Windows",
		)
	}
	if !strings.Contains(err.Error(), "path is invalid") {
		t.Fatalf(
			"backslash entry was refused for the wrong reason: %v", err,
		)
	}

	for _, recorded := range []string{
		"../escape.txt",
		"a/../b.txt",
		"a//b.txt",
		"a/./b.txt",
		"/etc/passwd",
		"..",
	} {
		t.Run(recorded, func(t *testing.T) {
			sum := sha256.Sum256([]byte("x\n"))
			directory := writeEvidenceTree(t, map[string]string{
				"result.txt": "PASS\n",
			}, []string{hex.EncodeToString(sum[:]) + "  " + recorded})
			if err := verifyEvidenceManifest(directory); err == nil {
				t.Fatalf("manifest entry %q was accepted", recorded)
			}
		})
	}
}

// TestSHA256ManifestLineSetAcceptsRecordedPOSIXAbsolutePaths states the second
// half of the same defect.
//
// The execution inventory records the lab's own Linux pathnames, and this
// verifier never opens one: the whole line is the map key and the only
// operation is byte equality. filepath.IsAbs is nonetheless host-dependent —
// on Windows it demands a drive letter or UNC prefix and reports FALSE for
// "/opt/winn-lab/bin/…" — so a Windows auditor rejected every honest line in
// the corpus as malformed.
func TestSHA256ManifestLineSetAcceptsRecordedPOSIXAbsolutePaths(t *testing.T) {
	digest := strings.Repeat("a", sha256.Size*2)
	content := digest + "  /opt/winn-lab/bin/winn-auto-e2e\n" +
		strings.Repeat("b", sha256.Size*2) +
		"  /opt/winn-lab/bin/amneziawg-go-winn-v3-abc\n"
	set, err := sha256ManifestLineSet([]byte(content))
	if err != nil || len(set) != 2 {
		t.Fatalf(
			"recorded POSIX absolute inventory paths were refused on %s: "+
				"set=%d error=%v", runtime.GOOS, len(set), err,
		)
	}
	// Relative recorded names remain refused: an inventory line that does not
	// name an absolute location says nothing about which binary ran.
	if _, err := sha256ManifestLineSet(
		[]byte(digest + "  opt/winn-lab/bin/winn-auto-e2e\n"),
	); err == nil {
		t.Fatal("a relative inventory path was accepted")
	}
}

// TestProtocolPathValidatorsDivergeFromFilepathOnWindows states the property
// directly rather than relying on an output comparison this platform cannot
// make.
func TestProtocolPathValidatorsDivergeFromFilepathOnWindows(t *testing.T) {
	nested := "diagnostics/client/root.txt"
	if filepath.Separator == '/' {
		if filepath.Clean(nested) != nested {
			t.Fatalf("filepath.Clean(%q) = %q on %s", nested,
				filepath.Clean(nested), runtime.GOOS)
		}
		t.Logf(
			"on %s filepath and path agree on %q, which is why this platform "+
				"cannot catch the divergence by output alone; the pinned "+
				"behaviour above and the source invariants below are what "+
				"enforce it", runtime.GOOS, nested,
		)
		return
	}
	if filepath.Clean(nested) == nested {
		t.Fatalf(
			"on %s filepath.Clean left %q unchanged; this test's premise is "+
				"wrong for this platform", runtime.GOOS, nested,
		)
	}
	// On a native-separator platform the verifier must still accept the
	// slash-separated recorded form.
	directory := writeEvidenceTree(t, map[string]string{nested: "client\n"}, nil)
	if err := verifyEvidenceManifest(directory); err != nil {
		t.Fatalf("nested recorded path refused on %s: %v", runtime.GOOS, err)
	}
}

// TestProtocolPathValidatorsUsePathNotFilepath is a source-level invariant, and
// it exists because no behavioural test on this workstation can replace it.
//
// filepath.Clean, filepath.Base and filepath.IsAbs return exactly what path.*
// returns for these inputs on Linux and macOS. Swapping one for the other
// therefore leaves every behavioural assertion above green while silently
// restoring a verifier whose verdict depends on the auditor's operating
// system. Pinning the choice per function is the only check available here that
// actually fails when the mistake is reintroduced.
func TestProtocolPathValidatorsUsePathNotFilepath(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, function := range []string{
		"func sha256ManifestLineSet(",
		"func verifyEvidenceManifest(",
		"func evidenceRelativeDirectoryName(",
		"func validArchiveFileName(",
	} {
		t.Run(strings.TrimSuffix(strings.TrimPrefix(function, "func "), "("),
			func(t *testing.T) {
				body, ok := protocolFunctionBody(string(source), function)
				if !ok {
					t.Fatalf(
						"%s is no longer present in main.go; this invariant "+
							"must move with it", function,
					)
				}
				requireWholeFunctionBody(t, function, body)
				code := stripProtocolComments(body)
				for _, forbidden := range []string{
					"filepath.Clean", "filepath.IsAbs", "filepath.Base",
				} {
					if strings.Contains(code, forbidden) {
						t.Fatalf(
							"%s decides the canonicality of a RECORDED "+
								"protocol path with %s, which is "+
								"host-dependent and changes the accepted set "+
								"by operating system:\n%s",
							function, forbidden, body,
						)
					}
				}
			})
	}
}

// TestEvidenceManifestConvertsOnlyAtTheFilesystemBoundary pins the other half
// of the rule: a native separator is correct exactly once, where a file is
// actually opened.
func TestEvidenceManifestConvertsOnlyAtTheFilesystemBoundary(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := protocolFunctionBody(string(source), "func verifyEvidenceManifest(")
	if !ok {
		t.Fatal("verifyEvidenceManifest is no longer present in main.go")
	}
	requireWholeFunctionBody(t, "verifyEvidenceManifest", body)
	code := stripProtocolComments(body)
	if !strings.Contains(code, "filepath.FromSlash(") {
		t.Fatalf(
			"verifyEvidenceManifest no longer converts the recorded protocol "+
				"path to a native one before opening it:\n%s", body,
		)
	}
}

// stripProtocolComments removes comment lines so an invariant scanning for a
// forbidden call is not tripped by the comment explaining why it is forbidden.
func stripProtocolComments(source string) string {
	var kept []string
	for _, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// protocolFunctionBody returns the source text of the function beginning with
// prefix.
//
// Brace counting must not start at the first "{" in the declaration. A result
// list such as (map[string]struct{}, error) opens and closes a brace pair
// inside the SIGNATURE, so a naive counter returns the signature as the whole
// "body" — and every invariant scanning that text then reports health over code
// it never looked at. That is not hypothetical: the first version of this file
// did exactly that, and a mutation restoring filepath.IsAbs to
// sha256ManifestLineSet passed unnoticed.
//
// The body's opening brace is the only one followed by a newline, because gofmt
// puts it at the end of the declaration line; struct{} and interface{} are
// always written closed. So the scan starts there.
func protocolFunctionBody(source, prefix string) (string, bool) {
	start := strings.Index(source, prefix)
	if start < 0 {
		return "", false
	}
	open := strings.Index(source[start:], "{\n")
	if open < 0 {
		return "", false
	}
	depth := 0
	for index := start + open; index < len(source); index++ {
		switch source[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[start : index+1], true
			}
		}
	}
	return "", false
}

// requireWholeFunctionBody fails unless the extracted text really is a complete
// function body rather than a truncated declaration.
//
// Every invariant in this file is an ABSENCE check: it passes when a forbidden
// call is not found. An extractor that silently returns too little therefore
// makes all of them pass, which is the worst possible failure for a test whose
// job is to notice a regression. This asserts the extraction itself.
func requireWholeFunctionBody(t *testing.T, function, body string) {
	t.Helper()
	if !strings.HasSuffix(body, "\n}") {
		t.Fatalf(
			"the extracted text for %s does not end at a function's closing "+
				"brace, so the invariants below scanned a fragment:\n%s",
			function, body,
		)
	}
	if !strings.Contains(body, "return ") {
		t.Fatalf(
			"the extracted text for %s contains no return statement, so it "+
				"is not a whole body:\n%s", function, body,
		)
	}
}
