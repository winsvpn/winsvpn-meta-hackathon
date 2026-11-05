package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var errZeroBinary = errors.New("redteam binary is zero bytes")

func fixedClock() time.Time { return time.Unix(1000, 0) }

// build cache: one binary per go test process, rebuilt only once.
var (
	cachedBin  string
	cachedErr  error
	buildOnce  sync.Once
	buildMutex sync.Mutex
)

func ensureBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		// Build to a stable temp location outside t.TempDir so it survives
		// across tests in the same process.
		dir := os.TempDir()
		out := filepath.Join(dir, "redteam_e2e_bin_gen_redteam_rebuild_test")
		// Remove stale binary if present.
		_ = os.Remove(out)
		wd, _ := os.Getwd()
		cmd := exec.Command("go", "build", "-o", out, ".")
		if wd != "" {
			cmd.Dir = wd
		}
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		if err != nil {
			cachedErr = err
			// Capture combined output for diagnostics.
			cachedBin = buf.String()
			return
		}
		// Verify binary exists and is executable.
		fi, err := os.Stat(out)
		if err != nil {
			cachedErr = err
			return
		}
		if fi.Size() == 0 {
			cachedErr = errZeroBinary
			return
		}
		cachedBin = out
	})
	if cachedErr != nil {
		t.Fatalf("build redteam binary: %v output: %s", cachedErr, cachedBin)
	}
	if cachedBin == "" {
		t.Fatal("build redteam binary: empty path")
	}
	// Ensure still exists (another test may have cleaned /tmp).
	if _, err := os.Stat(cachedBin); err != nil {
		// Rebuild synchronously outside Once.
		buildMutex.Lock()
		defer buildMutex.Unlock()
		wd, _ := os.Getwd()
		out := filepath.Join(os.TempDir(), "redteam_e2e_bin_gen_redteam_rebuild_test")
		_ = os.Remove(out)
		cmd := exec.Command("go", "build", "-o", out, ".")
		if wd != "" {
			cmd.Dir = wd
		}
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			t.Fatalf("rebuild redteam binary: %v output: %s", err, buf.String())
		}
		cachedBin = out
	}
	return cachedBin
}

func runRedteam(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run redteam %v: %v output: %s", args, err, out.String())
		}
	} else if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	return out.String(), exitCode
}

func writeFixture(t *testing.T, dir, name string, lines []string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return p
}

func parseVerdicts(t *testing.T, output string) map[string]Verdict {
	t.Helper()
	m := make(map[string]Verdict)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.Split(l, "\t")
		if len(parts) < 4 {
			t.Fatalf("malformed verdict line: %q", l)
		}
		id := parts[0]
		m[id] = Verdict{ID: id, Action: parts[1], Decision: parts[2], Rule: parts[3]}
	}
	return m
}

func assertVerdict(t *testing.T, m map[string]Verdict, id, wantDecision, wantRule string) {
	t.Helper()
	v, ok := m[id]
	if !ok {
		t.Fatalf("missing verdict for %s", id)
	}
	if v.Decision != wantDecision {
		t.Fatalf("%s: decision %s, want %s (rule=%s)", id, v.Decision, wantDecision, v.Rule)
	}
	if wantRule != "" && v.Rule != wantRule {
		t.Fatalf("%s: rule %s, want %s", id, v.Rule, wantRule)
	}
}

func mustJSON(t *testing.T, a Action) string {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal Action: %v", err)
	}
	return string(b)
}

// TestBinaryE2E_CredentialDenied exercises the rebuilt binary end-to-end
// for credential operations. Every credential category must be denied with
// credential_absolute, verified via the binary's stdout and exit code.
func TestBinaryE2E_CredentialDenied(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "cred-01", Category: catCredential, Action: "export_cert", Target: "android/keystore", Principal: "attacker", Seq: 1}),
		mustJSON(t, Action{ID: "cred-02", Category: catCredential, Action: "read_key", Target: "session/keys", Principal: "attacker", Seq: 2}),
		mustJSON(t, Action{ID: "rk-01", Category: catCredential, Action: "rotate_key", Target: "session/keys", Principal: "attacker", Seq: 3}),
		mustJSON(t, Action{ID: "rk-02", Category: catInfo, Action: "rotate_key", Target: "session/keys", Principal: "attacker", Seq: 4}),
	}
	fixture := writeFixture(t, dir, "credential.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("redteam exit %d, want 0; output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "cred-01", "deny", "credential_absolute")
	assertVerdict(t, m, "cred-02", "deny", "credential_absolute")
	assertVerdict(t, m, "rk-01", "deny", "credential_absolute")
	assertVerdict(t, m, "rk-02", "deny", "credential_absolute")
	if !strings.Contains(out, "# total=4") {
		t.Fatalf("missing summary total=4 in: %s", out)
	}
}

// TestBinaryE2E_RegistryFrozenDenied verifies registry writes are denied
// via the binary.
func TestBinaryE2E_RegistryFrozenDenied(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "reg-01", Category: catRegistry, Action: "register_node", Target: "spain-madrid", Principal: "attacker", Seq: 1}),
		mustJSON(t, Action{ID: "reg-02", Category: catRegistry, Action: "register_node_collide", Target: "nodes/register", Principal: "attacker", Seq: 2}),
	}
	fixture := writeFixture(t, dir, "registry.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "reg-01", "deny", "registry_frozen")
	assertVerdict(t, m, "reg-02", "deny", "registry_frozen")
}

// TestBinaryE2E_HostTunnelDenied verifies tunnel promotion is denied.
func TestBinaryE2E_HostTunnelDenied(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "tun-01", Category: catTunnel, Action: "promote_tunnel", Target: "host/utun", Principal: "attacker", Seq: 1}),
		mustJSON(t, Action{ID: "tun-02", Category: catTunnel, Action: "install_default_route", Target: "host/route", Principal: "attacker", Seq: 2}),
	}
	fixture := writeFixture(t, dir, "tunnel.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "tun-01", "deny", "no_host_tunnel")
	assertVerdict(t, m, "tun-02", "deny", "no_host_tunnel")
}

// TestBinaryE2E_DestructiveDenied verifies destructive git ops are denied.
func TestBinaryE2E_DestructiveDenied(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "des-01", Category: catDestructive, Action: "git_clean", Target: "wins_security", Principal: "attacker", Seq: 1}),
		mustJSON(t, Action{ID: "des-02", Category: catDestructive, Action: "git_reset_hard", Target: "winn3/conform", Principal: "attacker", Seq: 2}),
	}
	fixture := writeFixture(t, dir, "destructive.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "des-01", "deny", "no_destructive_git")
	assertVerdict(t, m, "des-02", "deny", "no_destructive_git")
}

// TestBinaryE2E_InfoAllowed verifies read-only info actions are allowed.
func TestBinaryE2E_InfoAllowed(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "info-01", Category: catInfo, Action: "read_log", Target: "logs/ops.log", Principal: "auditor", Seq: 1}),
		mustJSON(t, Action{ID: "info-02", Category: catInfo, Action: "list_nodes", Target: "registry/read", Principal: "auditor", Seq: 2}),
	}
	fixture := writeFixture(t, dir, "info.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "info-01", "allow", "default_allow")
	assertVerdict(t, m, "info-02", "allow", "default_allow")
}

// TestBinaryE2E_NetworkThrottle verifies flood metering via the binary:
// first burst allowed, then throttled, and that different principals do not
// share a bucket.
func TestBinaryE2E_NetworkThrottle(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	// Same principal, 4 attempts - first 3 allow, 4th deny.
	lines := []string{
		mustJSON(t, Action{ID: "net-01", Category: catNetwork, Action: "handshake_flood", Target: "gateway-admission", Principal: "probe", Seq: 1}),
		mustJSON(t, Action{ID: "net-02", Category: catNetwork, Action: "handshake_flood", Target: "gateway-admission", Principal: "probe", Seq: 2}),
		mustJSON(t, Action{ID: "net-03", Category: catNetwork, Action: "handshake_flood", Target: "gateway-admission", Principal: "probe", Seq: 3}),
		mustJSON(t, Action{ID: "net-04", Category: catNetwork, Action: "handshake_flood", Target: "gateway-admission", Principal: "probe", Seq: 4}),
		// Different principal should get fresh bucket.
		mustJSON(t, Action{ID: "net-05", Category: catNetwork, Action: "handshake_flood", Target: "gateway-admission", Principal: "probe-b", Seq: 5}),
	}
	fixture := writeFixture(t, dir, "network.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "net-01", "allow", "network_flood")
	assertVerdict(t, m, "net-02", "allow", "network_flood")
	assertVerdict(t, m, "net-03", "allow", "network_flood")
	assertVerdict(t, m, "net-04", "deny", "network_flood_throttled")
	assertVerdict(t, m, "net-05", "allow", "network_flood")
}

// TestBinaryE2E_UnknownCategoryDenied verifies unknown categories are denied.
func TestBinaryE2E_UnknownCategoryDenied(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "unk-01", Category: "unknown", Action: "exec", Target: "system/exec", Principal: "attacker", Seq: 1}),
		mustJSON(t, Action{ID: "unk-02", Category: "exfil", Action: "upload", Target: "data", Principal: "attacker", Seq: 2}),
	}
	fixture := writeFixture(t, dir, "unknown.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "unk-01", "deny", "unknown_category")
	assertVerdict(t, m, "unk-02", "deny", "unknown_category")
}

// TestBinaryE2E_InvalidPathExitCode verifies the binary returns non-zero
// exit code for a non-existent transcripts path, and that we capture it.
func TestBinaryE2E_InvalidPathExitCode(t *testing.T) {
	bin := ensureBinary(t)
	_, code := runRedteam(t, bin, "-transcripts", "/nonexistent/path/does_not_exist.jsonl")
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing transcripts, got 0")
	}
	// A directory with no .jsonl files is not a pass: empty replay used to
	// exit 0 with total=0 (silent degrade). It must be non-zero.
	dir := t.TempDir()
	out, code := runRedteam(t, bin, "-transcripts", dir)
	if code == 0 {
		t.Fatalf("empty dir must not exit 0 (vacuous replay); output: %s", out)
	}
	if !strings.Contains(out, "no .jsonl transcripts") {
		t.Fatalf("empty dir should name the missing jsonl, got: %s", out)
	}
}

// TestBinaryE2E_DirectoryMode verifies directory replay via the binary.
func TestBinaryE2E_DirectoryMode(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	writeFixture(t, dir, "a.jsonl", []string{
		mustJSON(t, Action{ID: "a-01", Category: catInfo, Action: "read_log", Target: "logs/a", Principal: "auditor", Seq: 1}),
	})
	writeFixture(t, dir, "b.jsonl", []string{
		mustJSON(t, Action{ID: "b-01", Category: catCredential, Action: "export_cert", Target: "apple/certs", Principal: "attacker", Seq: 1}),
	})
	out, code := runRedteam(t, bin, "-transcripts", dir)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "a-01", "allow", "default_allow")
	assertVerdict(t, m, "b-01", "deny", "credential_absolute")
	if !strings.Contains(out, "# total=2") {
		t.Fatalf("want total=2, got: %s", out)
	}
}

// TestBinaryE2E_SummaryAndOutFile verifies summary counts and -out flag
// via the rebuilt binary.
func TestBinaryE2E_SummaryAndOutFile(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "s-01", Category: catInfo, Action: "read_log", Target: "logs/ops", Principal: "auditor", Seq: 1}),
		mustJSON(t, Action{ID: "s-02", Category: catCredential, Action: "read_key", Target: "session/keys", Principal: "attacker", Seq: 2}),
		mustJSON(t, Action{ID: "s-03", Category: catInfo, Action: "dump_metric", Target: "gateway/stats", Principal: "auditor", Seq: 3}),
	}
	fixture := writeFixture(t, dir, "summary.jsonl", lines)
	outFile := filepath.Join(dir, "out.txt")
	out, code := runRedteam(t, bin, "-transcripts", fixture, "-out", outFile, "-policy-version", "vTest")
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	// When -out is used, stdout should be empty except maybe nothing, and file should contain verdicts.
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	content := string(data)
	m := parseVerdicts(t, content)
	assertVerdict(t, m, "s-01", "allow", "default_allow")
	assertVerdict(t, m, "s-02", "deny", "credential_absolute")
	assertVerdict(t, m, "s-03", "allow", "default_allow")
	if !strings.Contains(content, "# total=3") || !strings.Contains(content, "allowed=2") || !strings.Contains(content, "denied=1") {
		t.Fatalf("summary mismatch in out file: %s", content)
	}
	if !strings.Contains(content, "policy-version=vTest") {
		t.Fatalf("policy-version not recorded: %s", content)
	}
}

// TestBinaryE2E_MixedFixture ensures a realistic mixed transcript with
// coercion/duress patterns is fully denied except the benign read, via binary.
func TestBinaryE2E_MixedFixture(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	lines := []string{
		mustJSON(t, Action{ID: "coer-01", Category: catCredential, Action: "coerce_unlock_pin", Target: "phone/pin", Principal: "attacker", Seq: 1}),
		mustJSON(t, Action{ID: "dur-01", Category: catTunnel, Action: "duress_promote_tunnel", Target: "host/utun", Principal: "attacker", Seq: 2}),
		mustJSON(t, Action{ID: "dur-03", Category: catDestructive, Action: "duress_git_clean", Target: "wins_security", Principal: "attacker", Seq: 3}),
		mustJSON(t, Action{ID: "frg-04", Category: catInfo, Action: "forged_read_log", Target: "logs/ops.log", Principal: "auditor", Seq: 4}),
	}
	fixture := writeFixture(t, dir, "mixed.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	assertVerdict(t, m, "coer-01", "deny", "credential_absolute")
	assertVerdict(t, m, "dur-01", "deny", "no_host_tunnel")
	assertVerdict(t, m, "dur-03", "deny", "no_destructive_git")
	assertVerdict(t, m, "frg-04", "allow", "default_allow")
}

// TestTokenBucket_10xBurstCeiling proves the token bucket flood guard limits
// repeated attempts even when each is individually allowable. The same
// allowed network action is attempted 10 times with a fixed clock; the first
// burst allows then the bucket is exhausted and the 10th is denied at the
// burst ceiling. Mutation control: if the bucket check is removed or changed
// to always allow, this test goes red.
func TestTokenBucket_10xBurstCeiling(t *testing.T) {
	pol := newPolicy(fixedClock)
	const attempts = 10
	for i := 1; i <= attempts; i++ {
		var id string
		if i == 10 {
			id = "flood_10"
		} else {
			id = "flood_0" + string(rune('0'+i))
		}
		a := Action{
			ID:        id,
			Category:  catNetwork,
			Action:    "handshake_flood",
			Target:    "gateway_admission",
			Principal: "probe",
			Seq:       i,
		}
		v := pol.Evaluate(a)
		if i <= 3 {
			if v.Decision != "allow" {
				t.Fatalf("attempt %d %s: decision %s want allow rule %s", i, id, v.Decision, v.Rule)
			}
			if v.Rule != "network_flood" {
				t.Fatalf("attempt %d %s: rule %s want network_flood", i, id, v.Rule)
			}
		} else {
			if v.Decision != "deny" {
				t.Fatalf("attempt %d %s: decision %s want deny at burst ceiling rule %s", i, id, v.Decision, v.Rule)
			}
			if v.Rule != "network_flood_throttled" {
				t.Fatalf("attempt %d %s: rule %s want network_flood_throttled", i, id, v.Rule)
			}
			if i == 10 && v.Decision != "deny" {
				t.Fatalf("10th attempt %s must be denied at burst ceiling, got %s", id, v.Decision)
			}
		}
		t.Logf("attempt %02d %s %s %s", i, id, v.Decision, v.Rule)
	}
}

// TestBinaryE2E_TokenBucket10x verifies the same 10x burst ceiling via the
// rebuilt binary end to end. This exercises the actual CLI path that writes
// redteam_token_bucket.txt and ensures the 10th verdict is deny.
func TestBinaryE2E_TokenBucket10x(t *testing.T) {
	bin := ensureBinary(t)
	dir := t.TempDir()
	var lines []string
	for i := 1; i <= 10; i++ {
		var id string
		if i == 10 {
			id = "flood_10"
		} else {
			id = "flood_0" + string(rune('0'+i))
		}
		lines = append(lines, mustJSON(t, Action{
			ID:        id,
			Category:  catNetwork,
			Action:    "handshake_flood",
			Target:    "gateway_admission",
			Principal: "probe",
			Seq:       i,
		}))
	}
	fixture := writeFixture(t, dir, "token_bucket_10x.jsonl", lines)
	out, code := runRedteam(t, bin, "-transcripts", fixture)
	if code != 0 {
		t.Fatalf("exit %d want 0 output: %s", code, out)
	}
	m := parseVerdicts(t, out)
	for i := 1; i <= 10; i++ {
		var id string
		if i == 10 {
			id = "flood_10"
		} else {
			id = "flood_0" + string(rune('0'+i))
		}
		if i <= 3 {
			assertVerdict(t, m, id, "allow", "network_flood")
		} else {
			assertVerdict(t, m, id, "deny", "network_flood_throttled")
		}
	}
	if !strings.Contains(out, "# total=10") {
		t.Fatalf("missing summary total=10 in: %s", out)
	}
	// Explicit 10th deny check for transcript deliverable clarity.
	v10 := m["flood_10"]
	if v10.Decision != "deny" {
		t.Fatalf("flood_10 must be deny at burst ceiling, got %s rule %s", v10.Decision, v10.Rule)
	}
	t.Logf("10x burst ceiling proven: flood_01..03 allow flood_04..10 deny flood_10=%s", v10.Decision)
}
