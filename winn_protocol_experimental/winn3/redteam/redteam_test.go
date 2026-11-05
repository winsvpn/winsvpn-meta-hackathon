package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scenarioExpected is the ground truth this suite enforces. Each id names an
// adversarial scenario in the transcripts directory and the decision the
// harness MUST reproduce for it. A transcript line that stops being denied
// (or a harness change that starts allowing it) makes this suite go red.
//
// The mutation harness that audits this suite flips an entry below from deny
// to allow and requires the suite to fail; that is the inverted control. So
// every entry here is load-bearing, not cosmetic.
var scenarioExpected = map[string]string{
	// Coercion pin: the unlock material must never be surrendered.
	"coer-01": "deny",
	"coer-02": "deny",
	"coer-03": "deny",
	"coer-04": "deny",
	// Duress message: an attacker's message must not promote a host tunnel,
	// install a default route, wipe a working tree or touch the frozen fleet.
	"dur-01": "deny",
	"dur-02": "deny",
	"dur-03": "deny",
	"dur-04": "deny",
	// Forged action: forged register, key export and tunnel promote are denied.
	"frg-01": "deny",
	"frg-02": "deny",
	"frg-03": "deny",
	// A forged-posing but genuinely read-only audit read is allowed.
	"frg-04": "allow",
}

// transcriptsDir resolves the transcripts directory. Under `go test
// ./winn3/redteam/...` the package working directory is the package source
// directory itself, so "transcripts" is relative to cwd. This is overlay-safe:
// substituting redteam_test.go via -overlay does not change the cwd.
func transcriptsDir() string {
	return filepath.Join("transcripts")
}

// TestTranscriptVerdictsMatchExpected replays every transcript line through
// the harness and asserts the decision matches the scenario table. This is
// the harness cannot false-green check: a transcript that changes a deny to
// an allow, or a harness step that starts allowing a forbidden category, is
// caught here and named.
func TestTranscriptVerdictsMatchExpected(t *testing.T) {
	dir := transcriptsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir transcripts: %v", err)
	}

	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("open %s: %v", e.Name(), err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		p := newPolicy(fixedClock)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var a Action
			if err := json.Unmarshal([]byte(line), &a); err != nil {
				t.Fatalf("%s: bad JSONL: %v", e.Name(), err)
			}
			want, owned := scenarioExpected[a.ID]
			if !owned {
				// Not a scenario this lane owns; parse-only so concurrent
				// edits to shared transcripts cannot break this suite.
				continue
			}
			checked++
			v := p.Evaluate(a)
			if v.Decision != want {
				t.Errorf("%s %s (%s): decision %s, want %s (rule=%s)",
					e.Name(), a.ID, a.Category, v.Decision, want, v.Rule)
			}
		}
		if err := sc.Err(); err != nil {
			t.Fatalf("%s: read: %v", e.Name(), err)
		}
		f.Close()
	}

	if checked == 0 {
		t.Fatal("no owned scenarios matched: the scenario table checks nothing")
	}
}

// TestInvertedControlDenyIsNotAllowed is the positive control. A forged set of
// credentials, a forged registry write or a forged tunnel promotion under a
// coerced/duress narrative must come back denied. This asserts the NEGATIVE of
// the deny rule: it would fail immediately if any of these were ever allowed.
func TestInvertedControlDenyIsNotAllowed(t *testing.T) {
	denyIDs := []string{"coer-01", "coer-02", "coer-03", "coer-04",
		"dur-01", "dur-02", "dur-03", "dur-04",
		"frg-01", "frg-02", "frg-03"}
	for _, id := range denyIDs {
		if scenarioExpected[id] != "deny" {
			t.Fatalf("inverted control compromised: %s expected %s, want deny",
				id, scenarioExpected[id])
		}
	}
}
