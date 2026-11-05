//go:build !linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNonLinuxInvocationExitsNonZero builds THIS package and runs the binary.
// A stub that prints "Linux-only" and exits 0 is a false green: any script
// checking status would treat the proof as having run. Sibling harness
// winn-auto-e2e already refuses with stderr + exit 1.
func TestNonLinuxInvocationExitsNonZero(t *testing.T) {
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot, err := findRepoRoot(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(repoRoot, ".spark_lanes", "scratch", "prodpkg_cmd_winn_teardown_e2e")
	gotmp := filepath.Join(scratch, "gotmp")
	if err := os.MkdirAll(gotmp, 0o755); err != nil {
		t.Fatal(err)
	}
	outbin := filepath.Join(scratch, "winn-teardown-e2e.under-test")

	args := []string{"build", "-o", outbin}
	if overlay := os.Getenv("WINN_TEARDOWN_E2E_TEST_OVERLAY"); overlay != "" {
		args = append(args, "-overlay", overlay)
	}
	args = append(args, ".")
	build := exec.Command("go", args...)
	build.Dir = pkgDir
	build.Env = append(os.Environ(), "GOTMPDIR="+gotmp)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	run := exec.Command(outbin)
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	err = run.Run()
	if err == nil {
		t.Fatalf("unsupported-platform binary exited 0 (false green); stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run error is not ExitError: %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("want exit 1, got %d; stdout=%q stderr=%q",
			exitErr.ExitCode(), stdout.String(), stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("Linux-only")) {
		t.Fatalf("stderr %q does not name Linux-only", stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("FAIL:")) {
		t.Fatalf("stderr %q does not start a FAIL: line", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty on refusal, got %q", stdout.String())
	}
}

func findRepoRoot(start string) (string, error) {
	dir := start
	for {
		if st, err := os.Stat(filepath.Join(dir, ".spark_lanes")); err == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
