package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildBinary compiles the real CLI. Driving the compiled binary, rather than
// calling emit/fail in-process, is the point: those helpers os.Exit, and a host
// launching this the way Android launches a staged Go engine only ever sees
// stdout plus the process exit code.
func buildBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go tool not on PATH: %v", err)
	}
	name := "winn-clientinfo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	output := filepath.Join(t.TempDir(), name)
	args := []string{"build", "-o", output, "."}
	// go test -overlay does not apply to a child go build. Tests that drive
	// the compiled CLI must forward the overlay or they compile the live
	// tree and report a green against a mutant they never linked.
	if overlay := os.Getenv("GOTEST_OVERLAY"); overlay != "" {
		args = []string{"build", "-overlay", overlay, "-o", output, "."}
	}
	command := exec.Command("go", args...)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build winn-clientinfo: %v\n%s", err, combined)
	}
	return output
}

type cliResult struct {
	stdout string
	stderr string
	exit   int
}

func runCLI(t *testing.T, binary string, stdin string, args ...string) cliResult {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := cliResult{stdout: stdout.String(), stderr: stderr.String(), exit: 0}
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		result.exit = exitErr.ExitCode()
	}
	return result
}

func decodeJSON(t *testing.T, raw string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &value); err != nil {
		t.Fatalf("stdout is not a JSON object: %q: %v", raw, err)
	}
	return value
}

func TestCLI(t *testing.T) {
	binary := buildBinary(t)

	t.Run("noArgsExitsOneWithUsage", func(t *testing.T) {
		got := runCLI(t, binary, "")
		if got.exit != 1 {
			t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", got.exit, got.stdout, got.stderr)
		}
		if got.stderr != "" {
			t.Fatalf("stderr must be empty, got %q", got.stderr)
		}
		doc := decodeJSON(t, got.stdout)
		errText, _ := doc["error"].(string)
		if !strings.Contains(errText, "usage:") {
			t.Fatalf("error = %q, want usage", errText)
		}
	})

	t.Run("unknownSubcommandExitsOne", func(t *testing.T) {
		got := runCLI(t, binary, "", "connect")
		if got.exit != 1 {
			t.Fatalf("exit = %d, want 1; stdout=%q", got.exit, got.stdout)
		}
		doc := decodeJSON(t, got.stdout)
		errText, _ := doc["error"].(string)
		if errText != "unknown subcommand connect" {
			t.Fatalf("error = %q", errText)
		}
	})

	t.Run("backendRefusesToAdvertise", func(t *testing.T) {
		got := runCLI(t, binary, "", "backend")
		if got.exit != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", got.exit, got.stdout, got.stderr)
		}
		if got.stderr != "" {
			t.Fatalf("stderr must be empty, got %q", got.stderr)
		}
		doc := decodeJSON(t, got.stdout)
		if doc["safe_to_advertise_protocol"] != false {
			t.Fatalf("safe_to_advertise_protocol = %v, want false", doc["safe_to_advertise_protocol"])
		}
		if doc["tunnel_supported"] != false {
			t.Fatalf("tunnel_supported = %v, want false without WINS_WINN3_ENGINE", doc["tunnel_supported"])
		}
		if doc["protocol_version"] != "winn/3" {
			t.Fatalf("protocol_version = %v, want winn/3", doc["protocol_version"])
		}
		if doc["rekey_protocol_version"] != "winn/2" {
			t.Fatalf("rekey_protocol_version = %v, want winn/2", doc["rekey_protocol_version"])
		}
	})

	t.Run("suitesAndModesAreJSONArrays", func(t *testing.T) {
		suites := runCLI(t, binary, "", "suites")
		if suites.exit != 0 {
			t.Fatalf("suites exit = %d stdout=%q", suites.exit, suites.stdout)
		}
		var suiteList []string
		if err := json.Unmarshal([]byte(strings.TrimSpace(suites.stdout)), &suiteList); err != nil {
			t.Fatalf("suites stdout not a JSON array: %q: %v", suites.stdout, err)
		}
		if len(suiteList) == 0 {
			t.Fatal("suites must not be empty")
		}
		modes := runCLI(t, binary, "", "modes")
		if modes.exit != 0 {
			t.Fatalf("modes exit = %d stdout=%q", modes.exit, modes.stdout)
		}
		var modeList []string
		if err := json.Unmarshal([]byte(strings.TrimSpace(modes.stdout)), &modeList); err != nil {
			t.Fatalf("modes stdout not a JSON array: %q: %v", modes.stdout, err)
		}
		joined := strings.Join(modeList, ",")
		if !strings.Contains(joined, "stealth") || strings.Contains(joined, "turbo") {
			t.Fatalf("modes = %v", modeList)
		}
	})

	t.Run("unsupportedSuiteAndModeExitOne", func(t *testing.T) {
		got := runCLI(t, binary, "", "capabilities", "rsa2048")
		if got.exit != 1 {
			t.Fatalf("capabilities rsa2048 exit = %d, want 1; stdout=%q", got.exit, got.stdout)
		}
		if decodeJSON(t, got.stdout)["error"] != "unsupported cryptographic suite" {
			t.Fatalf("capabilities error = %q", got.stdout)
		}
		got = runCLI(t, binary, "", "auth-algorithm", "rsa2048")
		if got.exit != 1 {
			t.Fatalf("auth-algorithm rsa2048 exit = %d, want 1", got.exit)
		}
		got = runCLI(t, binary, "", "carriers", "turbo")
		if got.exit != 1 {
			t.Fatalf("carriers turbo exit = %d, want 1; stdout=%q", got.exit, got.stdout)
		}
		if decodeJSON(t, got.stdout)["error"] != "unsupported connection mode" {
			t.Fatalf("carriers error = %q", got.stdout)
		}
	})

	t.Run("supportedSuiteAndFastCarriers", func(t *testing.T) {
		got := runCLI(t, binary, "", "auth-algorithm", "x25519-mlkem768")
		if got.exit != 0 {
			t.Fatalf("auth-algorithm exit = %d stdout=%q", got.exit, got.stdout)
		}
		var algorithm string
		if err := json.Unmarshal([]byte(strings.TrimSpace(got.stdout)), &algorithm); err != nil {
			t.Fatalf("auth-algorithm stdout not a JSON string: %q: %v", got.stdout, err)
		}
		if algorithm != "mldsa65" {
			t.Fatalf("algorithm = %q, want mldsa65", algorithm)
		}
		got = runCLI(t, binary, "", "carriers", "fast")
		if got.exit != 0 {
			t.Fatalf("carriers fast exit = %d stdout=%q", got.exit, got.stdout)
		}
		if strings.TrimSpace(got.stdout) != `["direct-awg"]` {
			t.Fatalf("fast carriers = %s", got.stdout)
		}
		got = runCLI(t, binary, "", "carriers", "stealth")
		if got.exit != 0 {
			t.Fatalf("carriers stealth exit = %d stdout=%q", got.exit, got.stdout)
		}
		if strings.Contains(got.stdout, "direct-awg") {
			t.Fatalf("stealth must not permit direct-awg: %s", got.stdout)
		}
	})

	t.Run("validateDeviceIDRejectsInvalidWithExitOne", func(t *testing.T) {
		got := runCLI(t, binary, "", "validate-device-id", "bad id with spaces")
		if got.exit != 1 {
			t.Fatalf("exit = %d, want 1 (invalid must not look like success); stdout=%q", got.exit, got.stdout)
		}
		doc := decodeJSON(t, got.stdout)
		if doc["valid"] != false {
			t.Fatalf("valid = %v, want false", doc["valid"])
		}
		errText, _ := doc["error"].(string)
		if errText == "" {
			t.Fatal("invalid device id must name the error, not go silent")
		}
	})

	t.Run("validateDeviceIDAcceptsWellFormed", func(t *testing.T) {
		got := runCLI(t, binary, "", "validate-device-id", "device-01")
		if got.exit != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q", got.exit, got.stdout)
		}
		doc := decodeJSON(t, got.stdout)
		if doc["valid"] != true {
			t.Fatalf("valid = %v, want true", doc["valid"])
		}
	})

	t.Run("validatePeerKeyRejectsAllZeroWithExitOne", func(t *testing.T) {
		got := runCLI(t, binary, "", "validate-peer-key", strings.Repeat("A", 42)+"=")
		if got.exit != 1 {
			t.Fatalf("exit = %d, want 1; stdout=%q", got.exit, got.stdout)
		}
		doc := decodeJSON(t, got.stdout)
		if doc["valid"] != false {
			t.Fatalf("valid = %v, want false", doc["valid"])
		}
	})

	t.Run("validatePeerKeyAcceptsNonZero", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		got := runCLI(t, binary, "", "validate-peer-key", key)
		if got.exit != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q", got.exit, got.stdout)
		}
		if decodeJSON(t, got.stdout)["valid"] != true {
			t.Fatalf("stdout = %q", got.stdout)
		}
	})

	t.Run("validateReadinessRejectsGarbageWithExitOne", func(t *testing.T) {
		got := runCLI(t, binary, "", "validate-readiness", "not json")
		if got.exit != 1 {
			t.Fatalf("exit = %d, want 1; stdout=%q", got.exit, got.stdout)
		}
		if decodeJSON(t, got.stdout)["valid"] != false {
			t.Fatalf("stdout = %q", got.stdout)
		}
	})

	t.Run("validateBindingAcceptsWellFormedAndStdinDash", func(t *testing.T) {
		document := map[string]any{
			"AttemptID":      strings.Repeat("a", 32),
			"Profile":        "default",
			"Mode":           "auto",
			"ManifestDigest": strings.Repeat("0", 64),
			"CandidateID":    "candidate-1",
			"NodeID":         "node-1",
			"SessionID":      strings.Repeat("b", 32),
			"PSKGeneration":  1,
			"SequenceEpoch":  1,
			"Nonce":          strings.Repeat("c", 32),
			"ExpiresAt":      time.Now().Add(time.Minute).Format(time.RFC3339Nano),
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		got := runCLI(t, binary, "", "validate-binding", string(encoded))
		if got.exit != 0 {
			t.Fatalf("argv document exit = %d stdout=%q", got.exit, got.stdout)
		}
		if decodeJSON(t, got.stdout)["valid"] != true {
			t.Fatalf("argv document stdout = %q", got.stdout)
		}
		got = runCLI(t, binary, string(encoded), "validate-binding", "-")
		if got.exit != 0 {
			t.Fatalf("stdin dash exit = %d stdout=%q stderr=%q", got.exit, got.stdout, got.stderr)
		}
		if decodeJSON(t, got.stdout)["valid"] != true {
			t.Fatalf("stdin dash stdout = %q", got.stdout)
		}
	})
}

func TestReadInputDoesNotUseDevStdin(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(src, []byte(`os.ReadFile("/dev/stdin")`)) {
		t.Fatal(`os.ReadFile("/dev/stdin") does not exist on windows-amd64, which is a build_winn_protocol_engine.sh target`)
	}
	if !bytes.Contains(src, []byte("io.ReadAll(os.Stdin)")) {
		t.Fatal("readInput must consume os.Stdin so '-' works on every GOOS")
	}
}
