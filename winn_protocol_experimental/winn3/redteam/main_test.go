package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// transcriptsDirForMainTest resolves the transcripts directory for this harness.
// The harness is invoked as `go run . -transcripts winn3/redteam/transcripts`
// from source/wins_vpn/winn_protocol_experimental/winn3/redteam, which needs
// the nested path, and as `go run . -transcripts transcripts` from the same
// directory. Both must resolve, and the canonical on-disk location is
// transcripts/. This helper prefers the flat path and falls back to the nested
// one so the test remains valid regardless of how the caller was invoked.
func transcriptsDirForMainTest(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("transcripts"),
		filepath.Join("winn3", "redteam", "transcripts"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	t.Fatalf("transcripts directory not found (tried %v) cwd=%s", candidates, mustGetwd())
	return ""
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return err.Error()
	}
	return wd
}

// collectReplay replays every transcript line through a fresh policy with a
// deterministic clock and returns the verdict lines. It is the same replay
// logic as main.go's replay closure, intentionally duplicated so the test
// does not import main's unexported replay function but still verifies the
// policy produces deterministic allow/deny decisions over the exact same
// transcript corpus that the binary writes to redteam_verdicts.txt.
func collectReplay(t *testing.T, dir string, clock func() string) []Verdict {
	t.Helper()
	_ = clock
	pol := newPolicy(fixedClock)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var verdicts []Verdict
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		// Skip backup files that other lanes leave beside the transcripts.
		if strings.Contains(e.Name(), ".bak_") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("open %s: %v", e.Name(), err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var a Action
			if err := json.Unmarshal([]byte(line), &a); err != nil {
				f.Close()
				t.Fatalf("%s: bad JSONL %q: %v", e.Name(), line, err)
			}
			v := pol.Evaluate(a)
			verdicts = append(verdicts, v)
		}
		if err := sc.Err(); err != nil {
			f.Close()
			t.Fatalf("%s: read: %v", e.Name(), err)
		}
		f.Close()
	}
	return verdicts
}

// TestReplayEveryLineIsAllowOrDeny invokes the replay over the same
// transcripts that `go run . -transcripts winn3/redteam/transcripts -out
// redteam_verdicts.txt` uses and asserts every emitted verdict line is
// exactly "allow" or "deny" in its decision field. This is the deterministic
// verdict invariant: the harness must never emit an empty, unknown, or
// third-valued decision, even under flood metering or unknown categories.
func TestReplayEveryLineIsAllowOrDeny(t *testing.T) {
	dir := transcriptsDirForMainTest(t)
	verdicts := collectReplay(t, dir, nil)

	if len(verdicts) == 0 {
		t.Fatal("no verdicts produced: transcripts empty or not found; harness would be vacuous")
	}

	// Count transcript lines independently so we can assert one verdict per line.
	transcriptLines := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") || strings.Contains(e.Name(), ".bak_") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("open %s: %v", e.Name(), err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "" {
				continue
			}
			transcriptLines++
		}
		f.Close()
	}
	if len(verdicts) != transcriptLines {
		t.Fatalf("verdict count %d != transcript line count %d: missing or extra verdicts", len(verdicts), transcriptLines)
	}

	for i, v := range verdicts {
		if v.Decision != "allow" && v.Decision != "deny" {
			t.Fatalf("verdict %d id=%s action=%s decision=%q want exactly allow or deny (rule=%s)", i, v.ID, v.Action, v.Decision, v.Rule)
		}
		// The tab-separated Line() must carry the decision as its third field
		// and it must be exactly allow or deny, no whitespace, no other token.
		parts := strings.Split(v.Line(), "\t")
		if len(parts) < 3 {
			t.Fatalf("verdict %d Line() malformed: %q", i, v.Line())
		}
		if parts[2] != "allow" && parts[2] != "deny" {
			t.Fatalf("verdict %d Line() decision field %q not allow/deny: %q", i, parts[2], v.Line())
		}
		if parts[2] != v.Decision {
			t.Fatalf("verdict %d Line() field mismatch: parts[2]=%q vs Decision=%q", i, parts[2], v.Decision)
		}
	}
	t.Logf("replay verified: %d transcript lines -> %d verdicts, all allow/deny", transcriptLines, len(verdicts))
}

// TestReplayDeterministic replays twice with the same fixed clock and asserts
// the verdict streams are byte-identical. A non-deterministic harness (e.g. one
// that reads time.Now without injection or that shuffles transcript order)
// would fail this test.
func TestReplayDeterministic(t *testing.T) {
	dir := transcriptsDirForMainTest(t)
	a := collectReplay(t, dir, nil)
	b := collectReplay(t, dir, nil)
	if len(a) != len(b) {
		t.Fatalf("determinism: first run %d verdicts, second %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Line() != b[i].Line() {
			t.Fatalf("determinism: verdict %d differs between runs\n first: %q\nsecond: %q", i, a[i].Line(), b[i].Line())
		}
	}
	t.Logf("determinism proven: %d verdicts identical across two replays", len(a))
}

// TestBuildVerdictsFileExistsAndMatchesReplay verifies the on-disk verdict
// file produced by `go run . -transcripts winn3/redteam/transcripts -out
// redteam_verdicts.txt` exists, has one verdict per transcript line
// (plus an optional summary line), and every verdict line is exactly allow
// or deny. This closes the loop between the binary's file output and the
// in-process replay the previous tests cover.
func TestBuildVerdictsFileExistsAndMatchesReplay(t *testing.T) {
	dir := transcriptsDirForMainTest(t)
	verdicts := collectReplay(t, dir, nil)

	// The deliverable is redteam_verdicts.txt beside the package sources. It
	// used to live in a directory named build/, which the release source
	// freeze refuses under a source-bearing root, so the harness is now run as
	// `go run . -transcripts winn3/redteam/transcripts -out redteam_verdicts.txt`.
	candidatePaths := []string{
		"redteam_verdicts.txt",
		filepath.Join("winn3", "redteam", "redteam_verdicts.txt"),
	}
	var path string
	var data []byte
	for _, p := range candidatePaths {
		if b, err := os.ReadFile(p); err == nil {
			path = p
			data = b
			break
		}
	}
	if path == "" {
		t.Fatalf("verdict file not found (tried %v) cwd=%s; run `go run . -transcripts winn3/redteam/transcripts -out redteam_verdicts.txt` from winn3/redteam", candidatePaths, mustGetwd())
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// Separate verdict lines from the trailing summary line starting with "#".
	var fileVerdicts []string
	var summary string
	for _, l := range lines {
		trim := strings.TrimSpace(l)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "#") {
			summary = trim
			continue
		}
		fileVerdicts = append(fileVerdicts, trim)
	}

	if len(fileVerdicts) == 0 {
		t.Fatalf("%s: no verdict lines found (summary=%q)", path, summary)
	}
	if len(fileVerdicts) != len(verdicts) {
		t.Fatalf("%s: verdict line count %d != replay %d; file not one-per-line", path, len(fileVerdicts), len(verdicts))
	}

	for i, l := range fileVerdicts {
		parts := strings.Split(l, "\t")
		if len(parts) < 3 {
			t.Fatalf("%s line %d malformed: %q", path, i, l)
		}
		if parts[2] != "allow" && parts[2] != "deny" {
			t.Fatalf("%s line %d decision %q not allow/deny: %q", path, i, parts[2], l)
		}
		// Compare to in-process replay; order must match because both walk
		// the same directory in the same sorted order.
		if l != verdicts[i].Line() {
			t.Fatalf("%s line %d mismatch vs replay\n file: %q\nreplay: %q", path, i, l, verdicts[i].Line())
		}
	}

	if summary == "" {
		t.Fatalf("%s: missing summary line starting with # total=", path)
	}
	if !strings.Contains(summary, "total=") {
		t.Fatalf("%s: summary missing total=: %q", path, summary)
	}
	t.Logf("build file %s verified: %d verdicts, all allow/deny, summary %q", path, len(fileVerdicts), summary)
}

// TestHarnessIsOffline asserts the harness performs no network I/O and
// installs no tunnel. It does this by inspecting the source text of
// main.go and policy.go: they must not import net, net/http, or reference
// syscall tun/utun setup, and policy must deny tunnel/registry categories.
// This is a static check that the replay is pure offline and that Kansas
// and Spain remain frozen and read-only via registry_frozen.
func TestHarnessIsOffline(t *testing.T) {
	policyPath := filepath.Join("policy.go")
	mainPath := filepath.Join("main.go")
	for _, p := range []string{policyPath, mainPath} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		text := string(data)
		forbidden := []string{
			"\"net/\"", "\"net/http\"", "\"golang.org/x/net\"",
			"\"syscall\"", "\"net\"",
			"VpnService",
			"scutil", "NEProvider", "NetworkExtension",
		}
		for _, f := range forbidden {
			if strings.Contains(text, f) {
				t.Fatalf("%s contains forbidden offline-violating token %q", p, f)
			}
		}
		// No direct tunnel device manipulation.
		if strings.Contains(text, "tun1") && strings.Contains(text, "os.Open") {
			t.Fatalf("%s appears to open a tun device", p)
		}
	}
	// Functional check: tunnel and registry categories must be denied.
	pol := newPolicy(fixedClock)
	checks := []struct {
		action   Action
		wantRule string
	}{
		{Action{ID: "offline-tun", Category: "tunnel", Action: "promote_host_tunnel"}, "no_host_tunnel"},
		{Action{ID: "offline-reg", Category: "registry", Action: "register_node"}, "registry_frozen"},
	}
	for _, c := range checks {
		v := pol.Evaluate(c.action)
		if v.Decision != "deny" {
			t.Fatalf("offline invariant: %s should be deny, got %s", c.action.Category, v.Decision)
		}
		if v.Rule != c.wantRule {
			t.Fatalf("offline invariant: %s rule %q want %q", c.action.Category, v.Rule, c.wantRule)
		}
	}
}
