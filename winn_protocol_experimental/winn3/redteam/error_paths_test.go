package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBadJSONLFailsClosed is the expensive error path: a malformed transcript
// line used to be logged and skipped (continue) while the process still
// exited 0. That is fail-open for an attack-replay harness. A bad line must
// return exit 1 and must not emit a summary that looks like a complete run.
func TestBadJSONLFailsClosed(t *testing.T) {
	dir := t.TempDir()
	good := mustJSON(t, Action{ID: "ok-01", Category: catInfo, Action: "read_log", Principal: "auditor", Seq: 1})
	path := writeFixture(t, dir, "bad.jsonl", []string{good, "{not json", good})
	var stdout, stderr bytes.Buffer
	code := run(path, "", "", &stdout, &stderr)
	if code == 0 {
		t.Fatalf("bad JSONL must not exit 0; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if code != 1 {
		t.Fatalf("bad JSONL exit %d want 1; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "bad JSONL") {
		t.Fatalf("stderr must name bad JSONL, got %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "# total=") {
		t.Fatalf("must not print a success summary after parse failure: %q", stdout.String())
	}
	// The first valid line may already have been written; the second valid
	// line after the break must not appear (fail closed, stop).
	if strings.Count(stdout.String(), "ok-01") > 1 {
		t.Fatalf("replay continued past bad JSONL: %q", stdout.String())
	}
}

// TestEmptyDirFailsClosed: a directory with no .jsonl used to exit 0 with
// total=0. That is a vacuous pass. It must be exit 2.
func TestEmptyDirFailsClosed(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(dir, "", "", &stdout, &stderr)
	if code == 0 {
		t.Fatalf("empty dir must not exit 0; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if code != 2 {
		t.Fatalf("empty dir exit %d want 2; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no .jsonl transcripts") {
		t.Fatalf("stderr must name missing jsonl, got %q", stderr.String())
	}
}

// TestEmptyJSONLFileFailsClosed: a .jsonl with only blank lines used to
// print # total=0 and exit 0. That is a vacuous pass.
func TestEmptyJSONLFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "empty.jsonl", []string{"", "  ", ""})
	var stdout, stderr bytes.Buffer
	code := run(path, "", "", &stdout, &stderr)
	if code == 0 {
		t.Fatalf("empty jsonl must not exit 0; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "no actions") && !strings.Contains(stderr.String(), "no .jsonl") {
		t.Fatalf("stderr must name the empty replay, got %q", stderr.String())
	}
}

// TestDirWithOnlyNonJSONLFailsClosed: non-jsonl files are skipped; if that
// leaves zero transcripts the run must not look like a pass.
func TestDirWithOnlyNonJSONLFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a transcript\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(dir, "", "", &stdout, &stderr)
	if code == 0 {
		t.Fatalf("dir with no jsonl must not exit 0; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestCategorySmuggleDenied asserts the NEGATIVE of the category rules:
// a dangerous action name under network (metered allow) or info (default
// allow) must still be denied. Before impliedDangerCategory, git_clean
// with category network was allowed three times.
func TestCategorySmuggleDenied(t *testing.T) {
	pol := newPolicy(fixedClock)
	cases := []struct {
		id, category, action, wantRule string
	}{
		{"smuggle-git-net", catNetwork, "git_clean", "no_destructive_git"},
		{"smuggle-git-info", catInfo, "git_reset_hard", "no_destructive_git"},
		{"smuggle-reg-net", catNetwork, "register_node", "registry_frozen"},
		{"smuggle-reg-info", catInfo, "register_node_spain", "registry_frozen"},
		{"smuggle-tun-net", catNetwork, "promote_host_tunnel", "no_host_tunnel"},
		{"smuggle-tun-info", catInfo, "install_default_route", "no_host_tunnel"},
		{"smuggle-cred-net", catNetwork, "export_apple_cert", "credential_absolute"},
		{"smuggle-cred-info", catInfo, "read_key", "credential_absolute"},
		{"smuggle-keyexp-info", catInfo, "forged_key_export", "credential_absolute"},
	}
	for _, c := range cases {
		v := pol.Evaluate(Action{ID: c.id, Category: c.category, Action: c.action, Principal: "attacker", Seq: 1})
		if v.Decision != "deny" {
			t.Errorf("%s: category %s action %s decision %s want deny (rule=%s)",
				c.id, c.category, c.action, v.Decision, v.Rule)
		}
		if v.Rule != c.wantRule {
			t.Errorf("%s: rule %s want %s", c.id, v.Rule, c.wantRule)
		}
	}
}

// TestCategorySmuggleDoesNotFalsePositive keeps the allow path honest:
// list_registered_nodes contains "register" but is a read; rotate_token_window
// is not rotate_key; handshake_flood stays metered network.
func TestCategorySmuggleDoesNotFalsePositive(t *testing.T) {
	pol := newPolicy(fixedClock)
	allows := []Action{
		{ID: "keep-list", Category: catInfo, Action: "list_registered_nodes", Principal: "auditor", Seq: 1},
		{ID: "keep-rotate-window", Category: catInfo, Action: "rotate_token_window", Principal: "sre", Seq: 2},
		{ID: "keep-read", Category: catInfo, Action: "read_config", Principal: "sre", Seq: 3},
		{ID: "keep-flood", Category: catNetwork, Action: "handshake_flood", Principal: "probe", Seq: 4},
	}
	for _, a := range allows {
		v := pol.Evaluate(a)
		if v.Decision != "allow" {
			t.Errorf("%s action %s decision %s want allow rule=%s", a.ID, a.Action, v.Decision, v.Rule)
		}
	}
}

// TestInjectedClockDrivesMetering: Evaluate used wall-clock now() and ignored
// p.clock, so refill could not be tested and replay was not deterministic
// under a slow clock. Frozen clock must not refill; advancing clock must.
func TestInjectedClockDrivesMetering(t *testing.T) {
	t0 := time.Unix(1000, 0)
	current := t0
	pol := newPolicy(func() time.Time { return current })
	act := func(id string) Action {
		return Action{ID: id, Category: catNetwork, Action: "handshake_flood", Principal: "probe"}
	}
	for i := 1; i <= 3; i++ {
		v := pol.Evaluate(act("clk-a"))
		if v.Decision != "allow" {
			t.Fatalf("burst %d: %s want allow", i, v.Decision)
		}
	}
	v := pol.Evaluate(act("clk-deny"))
	if v.Decision != "deny" || v.Rule != "network_flood_throttled" {
		t.Fatalf("frozen clock 4th: %s %s want deny network_flood_throttled", v.Decision, v.Rule)
	}
	// 500ms at rate 2.0/s -> 1 token.
	current = t0.Add(500 * time.Millisecond)
	v = pol.Evaluate(act("clk-refill"))
	if v.Decision != "allow" {
		t.Fatalf("after 500ms refill: %s %s want allow", v.Decision, v.Rule)
	}
	v = pol.Evaluate(act("clk-empty"))
	if v.Decision != "deny" {
		t.Fatalf("immediately after refill spend: %s want deny", v.Decision)
	}
}

// TestTokenBucketBurstCap: a long pause must not accumulate above burst.
func TestTokenBucketBurstCap(t *testing.T) {
	t0 := time.Unix(2000, 0)
	current := t0
	pol := newPolicy(func() time.Time { return current })
	act := Action{ID: "cap", Category: catNetwork, Action: "admission_scan", Principal: "probe"}
	for i := 0; i < 3; i++ {
		if pol.Evaluate(act).Decision != "allow" {
			t.Fatalf("initial burst %d want allow", i)
		}
	}
	if pol.Evaluate(act).Decision != "deny" {
		t.Fatal("burst exhausted want deny")
	}
	current = t0.Add(60 * time.Second)
	allowed := 0
	for i := 0; i < 5; i++ {
		if pol.Evaluate(act).Decision == "allow" {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("after 60s pause allowed %d want burst 3 (cap)", allowed)
	}
}

// TestFlagValidationFailsClosed covers CLI error returns that used to be
// untested (go test -cover of main() was near-zero because E2E execs a
// separate binary). Each case must be non-zero.
func TestFlagValidationFailsClosed(t *testing.T) {
	dir := t.TempDir()
	fixture := writeFixture(t, dir, "one.jsonl", []string{
		mustJSON(t, Action{ID: "f-01", Category: catInfo, Action: "read_log", Principal: "auditor"}),
	})
	cases := []struct {
		name, transcripts, out, ver string
		want                        int
		stderrHas                   string
	}{
		{"empty transcripts", "", "", "", 2, "-transcripts flag must not be empty"},
		{"whitespace transcripts", "   ", "", "", 2, "-transcripts flag must not be empty"},
		{"whitespace out", fixture, "   ", "", 2, "-out flag must not be empty or whitespace"},
		{"out is directory", fixture, dir, "", 2, "is a directory"},
		{"out parent missing", fixture, filepath.Join(dir, "no-such-dir", "out.txt"), "", 2, "parent directory does not exist"},
		{"policy whitespace", fixture, "", "   ", 2, "-policy-version flag must not be whitespace"},
		{"policy too long", fixture, "", strings.Repeat("a", 65), 2, "too long"},
		{"policy bad char", fixture, "", "v1/x", 2, "invalid character"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(c.transcripts, c.out, c.ver, &stdout, &stderr)
			if code != c.want {
				t.Fatalf("exit %d want %d stderr=%q", code, c.want, stderr.String())
			}
			if !strings.Contains(stderr.String(), c.stderrHas) {
				t.Fatalf("stderr %q want substring %q", stderr.String(), c.stderrHas)
			}
		})
	}
}

// TestRunHappyPathInProcess exercises run() without the e2e binary so
// coverage of main.go is a real measurement, not an exec of a sibling build.
func TestRunHappyPathInProcess(t *testing.T) {
	dir := t.TempDir()
	fixture := writeFixture(t, dir, "ok.jsonl", []string{
		mustJSON(t, Action{ID: "h-01", Category: catInfo, Action: "read_log", Principal: "auditor"}),
		mustJSON(t, Action{ID: "h-02", Category: catCredential, Action: "read_key", Principal: "attacker"}),
	})
	outFile := filepath.Join(dir, "out.txt")
	var stdout, stderr bytes.Buffer
	code := run(fixture, outFile, "vTest", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d want 0 stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "# total=2") || !strings.Contains(content, "policy-version=vTest") {
		t.Fatalf("summary missing: %s", content)
	}
	m := parseVerdicts(t, content)
	assertVerdict(t, m, "h-01", "allow", "default_allow")
	assertVerdict(t, m, "h-02", "deny", "credential_absolute")
}

// TestMissingTranscriptsPathFailsClosed: stat failure is exit 1, not 0.
func TestMissingTranscriptsPathFailsClosed(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.jsonl")
	var stdout, stderr bytes.Buffer
	code := run(missing, "", "", &stdout, &stderr)
	if code == 0 {
		t.Fatal("missing transcripts path must not exit 0")
	}
	if code != 1 {
		t.Fatalf("exit %d want 1 stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing transcripts dir") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

// TestImpliedDangerCategoryClosedSet is the negative control for the
// classifier itself: empty and benign names must not imply a deny category.
func TestImpliedDangerCategoryClosedSet(t *testing.T) {
	if impliedDangerCategory("") != "" {
		t.Fatal("empty action must not imply a category")
	}
	if impliedDangerCategory("read_config") != "" {
		t.Fatal("read_config must not imply a deny category")
	}
	if impliedDangerCategory("list_registered_nodes") != "" {
		t.Fatal("list_registered_nodes must not imply registry")
	}
	if impliedDangerCategory("rotate_token_window") != "" {
		t.Fatal("rotate_token_window must not imply credential")
	}
	if impliedDangerCategory("git_clean") != catDestructive {
		t.Fatal("git_clean must imply destructive")
	}
}
