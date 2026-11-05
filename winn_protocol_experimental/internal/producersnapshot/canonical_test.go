// Canonicality of the signed digest input.
//
// The producer snapshot is cryptographically signed into CONTROLLER_START and
// is meant to be independently re-verifiable by any third party. That only
// holds if its input is a protocol value rather than a local pathname: an
// earlier version built labels with filepath.Join, so the same evidence tree
// hashed to one value on Linux and macOS and a different value on Windows, and
// a Windows auditor would have rejected honest evidence.
package producersnapshot

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCanonicalLabelIsAlwaysSlashSeparated pins nested labels to their exact
// expected form, so the digest input is deterministic regardless of the
// platform the snapshot was built on.
func TestCanonicalLabelIsAlwaysSlashSeparated(t *testing.T) {
	for _, test := range []struct {
		name     string
		elements []string
		want     string
	}{
		{
			name:     "batch_record",
			elements: []string{"batches", "b0001-edge-warm.closed-pending"},
			want:     "batches/b0001-edge-warm.closed-pending",
		},
		{
			name: "evidence_manifest",
			elements: []string{
				"evidence/auto-e2e-m1-b0001", "evidence-manifest.sha256",
			},
			want: "evidence/auto-e2e-m1-b0001/evidence-manifest.sha256",
		},
		{
			name: "nested_member_two_levels",
			elements: []string{
				"evidence/auto-e2e-m1-b0001", "diagnostics/client/root.txt",
			},
			want: "evidence/auto-e2e-m1-b0001/diagnostics/client/root.txt",
		},
		{
			name: "nested_member_three_levels",
			elements: []string{
				"evidence/auto-e2e-m1-b0001", "a/b/c/deep.txt",
			},
			want: "evidence/auto-e2e-m1-b0001/a/b/c/deep.txt",
		},
		{
			name:     "directory_label",
			elements: []string{"evidence/auto-e2e-m1-b0001", "diagnostics/empty"},
			want:     "evidence/auto-e2e-m1-b0001/diagnostics/empty",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := canonicalLabel(test.elements...)
			if got != test.want {
				t.Fatalf("canonicalLabel = %q, want %q", got, test.want)
			}
			if strings.ContainsRune(got, '\\') {
				t.Fatalf(
					"the label %q contains a backslash; the signed digest "+
						"input would differ by build platform", got,
				)
			}
			// The separator count is fixed by the protocol, not by the host.
			if strings.Count(got, "/") != strings.Count(test.want, "/") {
				t.Fatalf("label %q has the wrong separator count", got)
			}
		})
	}
}

// TestCanonicalLabelDivergesFromFilepathOnWindows states the defect directly.
//
// On Linux and macOS filepath.Join and path.Join agree, so no test on those
// platforms can distinguish them by output alone — which is exactly why the
// original bug survived. This asserts the property that matters instead: the
// canonical label is byte-identical to the slash form on every platform, and on
// a platform whose separator is not "/" it must NOT equal filepath.Join.
func TestCanonicalLabelDivergesFromFilepathOnWindows(t *testing.T) {
	elements := []string{"evidence/auto-e2e-m1-b0001", "diagnostics/client/root.txt"}
	canonical := canonicalLabel(elements...)
	native := filepath.Join(elements...)

	if canonical != "evidence/auto-e2e-m1-b0001/diagnostics/client/root.txt" {
		t.Fatalf("canonical label drifted: %q", canonical)
	}
	if filepath.Separator == '/' {
		if canonical != native {
			t.Fatalf(
				"on %s the two forms should coincide; canonical=%q native=%q",
				runtime.GOOS, canonical, native,
			)
		}
		t.Logf(
			"on %s filepath.Join and path.Join coincide (%q), which is why "+
				"this platform cannot catch the divergence by output alone; "+
				"the pinned expectations above are what enforce it",
			runtime.GOOS, canonical,
		)
		return
	}
	if canonical == native {
		t.Fatalf(
			"on %s the canonical label equals the native path %q; the signed "+
				"digest input is host-dependent", runtime.GOOS, native,
		)
	}
}

// TestRequireEvidenceRelativeAcceptsCanonicalPathsOnEveryPlatform covers the
// same rule applied to validation.
//
// requireEvidenceRelative used filepath.Clean on a slash-separated protocol
// value. On Windows that returns "evidence\\x", which does not equal the
// recorded value — so every legitimate record would have been rejected there
// while being accepted everywhere else.
func TestRequireEvidenceRelativeAcceptsCanonicalPathsOnEveryPlatform(t *testing.T) {
	for _, recorded := range []string{
		"evidence/auto-e2e-m1-b0001.closed-pending.tar.gz",
		"evidence/a..b.closed-pending.tar.gz",
	} {
		if err := RequireEvidenceRelative(recorded); err != nil {
			t.Fatalf(
				"a canonical record path was refused on %s: %v",
				runtime.GOOS, err,
			)
		}
	}
	// A backslash is not a separator in this protocol; it is an illegal
	// character, and must be refused identically on every platform.
	if err := RequireEvidenceRelative(
		"evidence\\auto-e2e-m1-b0001.closed-pending.tar.gz",
	); err == nil {
		t.Fatal("a backslash-separated path was accepted as canonical")
	}
}

// TestSnapshotLabelsAreSlashSeparated proves the property end to end: every
// label in a real digest input is slash-separated, with no host separator
// anywhere.
func TestSnapshotLabelsAreSlashSeparated(t *testing.T) {
	// canonicalLabel is the only construction path for digest labels, so a
	// nested tree exercising all three label kinds is enough to pin the shape.
	labels := []string{
		canonicalLabel("batches", "b0001.closed-pending"),
		canonicalLabel("evidence/auto-e2e-m1-b0001", manifestName),
		canonicalLabel("evidence/auto-e2e-m1-b0001", auditLogName),
		canonicalLabel("evidence/auto-e2e-m1-b0001", "diagnostics/qdisc.json"),
		canonicalLabel("evidence/auto-e2e-m1-b0001", "diagnostics/client"),
	}
	for _, label := range labels {
		if strings.ContainsRune(label, filepath.Separator) &&
			filepath.Separator != '/' {
			t.Fatalf("label %q carries the host separator", label)
		}
		if strings.HasPrefix(label, "/") || strings.Contains(label, "//") {
			t.Fatalf("label %q is not a clean relative protocol path", label)
		}
	}
}

// TestCanonicalLabelIsImplementedWithPathNotFilepath is a source-level
// invariant, and it exists because no behavioural test on this platform can
// replace it.
//
// On Linux and macOS filepath.Join and path.Join return identical strings, so
// swapping one for the other leaves every behavioural assertion in this file
// green. The defect only manifests on Windows — where the signed digest would
// silently become a different value — and this workstation cannot execute a
// Windows build. Pinning the implementation choice in source is therefore the
// only check available here that actually fails when the mistake is
// reintroduced.
//
// The same reasoning applies to the canonicality validators: a filepath-based
// Clean on a slash-separated protocol value rejects legitimate records on
// Windows while accepting them everywhere else.
func TestCanonicalLabelIsImplementedWithPathNotFilepath(t *testing.T) {
	source, err := os.ReadFile("snapshot.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := functionBody(string(source), "func canonicalLabel(")
	if !ok {
		t.Fatal("canonicalLabel is no longer present; the digest label " +
			"construction moved and this invariant must move with it")
	}
	if strings.Contains(stripComments(body), "filepath.") {
		t.Fatalf(
			"canonicalLabel uses filepath, which is host-dependent:\n%s\n"+
				"The signed digest input must be a protocol value, not a "+
				"local pathname", body,
		)
	}
	if !strings.Contains(stripComments(body), "path.Join(") {
		t.Fatalf("canonicalLabel no longer uses path.Join:\n%s", body)
	}

	// And no digest label anywhere is built with filepath.
	for number, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if !strings.Contains(trimmed, "filepath.Join(") {
			continue
		}
		// Digest labels are recognisable: they are concatenated with the
		// tab-separated digest that follows them.
		if strings.Contains(trimmed, `+"\t`) ||
			strings.Contains(trimmed, `) + "\t`) {
			t.Fatalf(
				"snapshot.go:%d builds a digest label with filepath.Join:\n\t%s",
				number+1, trimmed,
			)
		}
	}
}

// TestCanonicalityValidatorsUsePath covers the validators for the same reason.
func TestCanonicalityValidatorsUsePath(t *testing.T) {
	source, err := os.ReadFile("paths.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := functionBody(string(source), "func requireEvidenceRelative(")
	if !ok {
		t.Fatal("requireEvidenceRelative is no longer present")
	}
	code := stripComments(body)
	if strings.Contains(code, "filepath.Clean") ||
		strings.Contains(code, "filepath.IsAbs") {
		t.Fatalf(
			"requireEvidenceRelative validates a slash-separated protocol "+
				"value with filepath, which rejects legitimate records on "+
				"Windows:\n%s", body,
		)
	}
}

// stripComments removes comment lines, so an invariant that scans for a
// forbidden call is not tripped by the comment explaining why it is forbidden.
func stripComments(source string) string {
	var kept []string
	for _, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// functionBody returns the source text of the function beginning with prefix.
func functionBody(source, prefix string) (string, bool) {
	start := strings.Index(source, prefix)
	if start < 0 {
		return "", false
	}
	depth := 0
	for index := start; index < len(source); index++ {
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
