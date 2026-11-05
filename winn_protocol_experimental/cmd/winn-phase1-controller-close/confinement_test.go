// Archive-path confinement, and the decompression bounds.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/producersnapshot"
)

// TestArchiveRelativeConfinementIsEnforcedBeforeAnyAnchor is the zero-anchor
// requirement: an escaping path must be refused while the record is being read,
// not by the verifier after the providers have already signed.
func TestArchiveRelativeConfinementIsEnforcedBeforeAnyAnchor(t *testing.T) {
	for _, recorded := range []string{
		"../outside/auto-e2e-x.closed-pending.tar.gz",
		"evidence/../../etc/auto-e2e-x.closed-pending.tar.gz",
		"/absolute/auto-e2e-x.closed-pending.tar.gz",
		"evidence/nested/auto-e2e-x.closed-pending.tar.gz",
		"other/auto-e2e-x.closed-pending.tar.gz",
		"evidence/./auto-e2e-x.closed-pending.tar.gz",
		"auto-e2e-x.closed-pending.tar.gz",
		"evidence/auto-e2e-x.tar.gz",
	} {
		t.Run(strings.ReplaceAll(recorded, "/", "_"), func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			path := filepath.Join(
				fixture.root, "batches", fixture.keys[0]+pendingSuffix)
			content, err := os.ReadFile(path) // #nosec G304 -- test temp path
			if err != nil {
				t.Fatal(err)
			}
			var rebuilt []string
			for _, line := range strings.Split(
				strings.TrimSuffix(string(content), "\n"), "\n",
			) {
				if strings.HasPrefix(line, "archive_relative=") {
					line = "archive_relative=" + recorded
				}
				rebuilt = append(rebuilt, line)
			}
			writeFixtureFile(t, path, strings.Join(rebuilt, "\n")+"\n")

			err = fixture.controller().Run()
			if err == nil {
				t.Fatalf("the escaping path %q was accepted", recorded)
			}
			if !strings.Contains(err.Error(), "unusable producer archive") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			// The whole point: not one anchor was attempted.
			if len(fixture.anchor.previous) != 0 ||
				fixture.anchor.counter != 0 {
				t.Fatalf(
					"%d anchors were requested before the path was refused; "+
						"each is an irreversible provider signature spent to "+
						"learn something decidable from a string",
					len(fixture.anchor.previous),
				)
			}
			assertNoTerminalArtifacts(t, fixture.root)
		})
	}
}

// TestRequireEvidenceRelativeAcceptsLegitimatePaths is the positive control. A
// confinement rule that rejected everything would pass every case above.
func TestRequireEvidenceRelativeAcceptsLegitimatePaths(t *testing.T) {
	for _, recorded := range []string{
		"evidence/auto-e2e-phase1-auto-v1-b0001.closed-pending.tar.gz",
		"evidence/a..b.closed-pending.tar.gz",
		"evidence/x.closed-pending.tar.gz",
	} {
		if err := producersnapshot.RequireEvidenceRelative(recorded); err != nil {
			t.Fatalf("a legitimate path %q was refused: %v", recorded, err)
		}
	}
}
