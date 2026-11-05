package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/conform"
)

func mustUnproven(t *testing.T, err error, needles ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an unprovenError (exit 2), got nil")
	}
	if exitCodeFor(err) != 2 {
		t.Fatalf("expected exit 2 for unproven, got %d (%T: %v)", exitCodeFor(err), err, err)
	}
	msg := err.Error()
	for _, n := range needles {
		if !strings.Contains(msg, n) {
			t.Fatalf("unproven message %q does not name %q", msg, n)
		}
	}
}

func TestExitCodeForWrappedUnprovenStaysTwo(t *testing.T) {
	wrapped := fmt.Errorf("load: %w", unproven("nothing was checked"))
	if got := exitCodeFor(wrapped); got != 2 {
		t.Fatalf("a wrapped unprovenError must still exit 2, got %d: a %%w wrap used to silently "+
			"degrade exit 2 into exit 1 (late-validation sweep §3.11)", got)
	}
	if got := exitCodeFor(fmt.Errorf("load: %w", wrongAnswerErr{})); got != 1 {
		t.Fatalf("a wrapped concrete disagreement must still exit 1, got %d", got)
	}
}

func TestNothingToDoMessageNamesTheFourActionFlags(t *testing.T) {
	var out strings.Builder
	err := run(nil, &out)
	mustUnproven(t, err, "-emit", "-emit-tasks", "-verify", "-matrix")
}

func TestPositionalReportPathNamesVerify(t *testing.T) {
	var out strings.Builder
	err := run([]string{"report.json"}, &out)
	mustUnproven(t, err, "-verify", "report.json")
}

func TestSpaceSeparatedVerifyPathsNameTheCommaFix(t *testing.T) {
	// THE accept-transit-shaped pair: -verify a.json b.json used to verify a.json,
	// drop b.json, and exit 0.
	var out strings.Builder
	err := run([]string{"-verify", "a.json", "b.json"}, &out)
	mustUnproven(t, err, "-verify", "a.json,b.json", "comma-separated")
}

func TestMatrixWithLeftoverReportPathIsUnproven(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-matrix", "report.json"}, &out)
	mustUnproven(t, err, "-verify", "report.json")
	if strings.Contains(out.String(), "plan-floor matrix") {
		t.Fatal("a leftover report path must be refused before -matrix prints; printing then "+
			"exiting 0 is the unit that started without -accept-transit")
	}
}

func TestVerifyEmptyListNamesTheFlag(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-verify", ","}, &out)
	mustUnproven(t, err, "-verify")
}

func TestVerifyStdinDashNamesTheFix(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-verify", "-"}, &out)
	mustUnproven(t, err, "-verify", "-emit -")
}

func TestVerifyDuplicatePathsNamesTheFlag(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-verify", "go.json,go.json,go.json"}, &out)
	mustUnproven(t, err, "-verify", "go.json")
}

func TestUnknownFlagIsNotSuccess(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-accept-transit=true"}, &out)
	if err == nil {
		t.Fatal("an unknown flag must not succeed; this binary has no -accept-transit")
	}
	if !strings.Contains(err.Error(), "accept-transit") {
		t.Fatalf("unknown-flag error must name the flag, got %v", err)
	}
	if exitCodeFor(err) != 1 {
		t.Fatalf("flag-parse errors are exit 1 (not unproven), got %d", exitCodeFor(err))
	}
}

func TestMissingVectorsFileNamesTheFlag(t *testing.T) {
	_, err := loadVectors(filepath.Join(t.TempDir(), "no-such-vectors.json"))
	mustUnproven(t, err, "-vectors")
}

func TestLoadVectorsRefusesTrailingJSON(t *testing.T) {
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v.JSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(path, append(raw, []byte("\n{\"sneaky\":true}")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVectors(path); err == nil {
		t.Fatal("a vector file with trailing JSON loaded cleanly; the second object would never be compared")
	} else if !strings.Contains(err.Error(), "trailing JSON") && !strings.Contains(err.Error(), "-vectors") {
		t.Fatalf("trailing-JSON refusal must name the cause, got %v", err)
	}
}

func TestVectorsSourceLineIsPrinted(t *testing.T) {
	_, vpath := writeVectorsFile(t)
	var out strings.Builder
	if err := run([]string{"-vectors", vpath, "-matrix"}, &out); err != nil {
		t.Fatalf("matrix with -vectors failed: %v", err)
	}
	if !strings.Contains(out.String(), "vectors loaded from "+vpath) {
		t.Fatalf("using -vectors must record that the vectors came from a file, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "not computed from this tree") {
		t.Fatalf("the source line must say the vectors were not computed, got:\n%s", out.String())
	}
}

func TestHostThatDeclaredEverythingNotDerivedIsUnproven(t *testing.T) {
	dir, vpath := writeVectorsFile(t)
	report := filepath.Join(dir, "skip.json")
	body := `{"host":"skip","language":"go","not_derived":["gateway_id_hex","admission_key_hex","tag_size","path_mtu","carrier_classes","message_size","inner_mtu","inner_ipv6","floors","overheads","transport_observed_both_ways"]}`
	if err := os.WriteFile(report, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	err := run([]string{"-vectors", vpath, "-verify", report}, &out)
	mustUnproven(t, err, "not_derived", "compared nothing")
	if !strings.Contains(out.String(), "COMPARED NOTHING") {
		t.Fatalf("table must say COMPARED NOTHING, got:\n%s", out.String())
	}
	if strings.Contains(out.String(), "AGREES") {
		t.Fatalf("a host that compared nothing must not print AGREES, got:\n%s", out.String())
	}
}

func TestAdmissionOnlyHostStillAgreesThroughRun(t *testing.T) {
	// CONTROL_GREEN for the compared-nothing guard: a host that actually
	// compared admission-tag inputs must still exit 0.
	v, err := conform.BuildVectors(conform.Reference())
	if err != nil {
		t.Fatal(err)
	}
	r := focusedReport(t, v, v.Admission.GatewayIDHex, v.Admission.AdmissionKeyHex)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	dir, vpath := writeVectorsFile(t)
	report := filepath.Join(dir, "ok.json")
	if err := os.WriteFile(report, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := run([]string{"-vectors", vpath, "-verify", report}, &out); err != nil {
		t.Fatalf("an admission-only host that matches the reference must agree: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "AGREES") {
		t.Fatalf("expected AGREES, got:\n%s", out.String())
	}
}

func TestCheckVerifyPathsTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantErr string
	}{
		{in: ",", wantErr: "-verify"},
		{in: "   ", wantErr: "-verify"},
		{in: "-", wantErr: "-verify"},
		{in: "a.json,a.json", wantErr: "a.json"},
		{in: "a.json, b.json, a.json", wantErr: "a.json"},
	}
	for _, tc := range cases {
		_, err := checkVerifyPaths(tc.in)
		if err == nil {
			t.Fatalf("checkVerifyPaths(%q) succeeded; must refuse", tc.in)
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("checkVerifyPaths(%q) = %v, want it to name %q", tc.in, err, tc.wantErr)
		}
		if exitCodeFor(err) != 2 {
			t.Fatalf("checkVerifyPaths(%q) must be unproven (exit 2), got %d", tc.in, exitCodeFor(err))
		}
	}
	paths, err := checkVerifyPaths(" a.json , b.json ")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "a.json" || paths[1] != "b.json" {
		t.Fatalf("checkVerifyPaths accepted list = %v", paths)
	}
}

func TestVectorsAloneNamesVectorsIsNotAnAction(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-vectors", "vec.json"}, &out)
	mustUnproven(t, err, "-vectors", "-emit", "-emit-tasks", "-verify", "-matrix")
	if !strings.Contains(err.Error(), "not an action") {
		t.Fatalf("a lone -vectors must say it is not an action, got %v", err)
	}
}

func TestVectorsDashNamesTheFix(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-vectors", "-", "-matrix"}, &out)
	mustUnproven(t, err, "-vectors", "-emit -")
}

func TestEmitAndEmitTasksSamePathNamesBothFlags(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-emit", "same.json", "-emit-tasks", "same.json"}, &out)
	mustUnproven(t, err, "-emit", "-emit-tasks", "same.json", "two different paths")
}

func TestEmitAndEmitTasksDotSlashIsTheSamePath(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-emit", "./out.json", "-emit-tasks", "out.json"}, &out)
	mustUnproven(t, err, "-emit", "-emit-tasks", "two different paths")
}

func TestEmitAndEmitTasksBothStdoutNamesTheFix(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-emit", "-", "-emit-tasks", "-"}, &out)
	mustUnproven(t, err, "-emit -", "-emit-tasks -", "stdout")
	if strings.Contains(out.String(), "operator_gateway_id_hex") || strings.Contains(out.String(), `"generator"`) {
		t.Fatal("colliding stdout writers must be refused before either writes")
	}
}

func TestVerifyPathEqualsEmitPathNamesTheCollision(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-emit", "vec.json", "-verify", "vec.json"}, &out)
	mustUnproven(t, err, "-verify", "-emit", "vec.json", "host-report")
}

func TestVerifyPathEqualsVectorsPathNamesTheCollision(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-vectors", "vec.json", "-verify", "vec.json"}, &out)
	mustUnproven(t, err, "-verify", "-vectors", "vec.json", "host-report")
}

func TestEmitAndEmitTasksDifferentPathsBothWritten(t *testing.T) {
	// CONTROL_GREEN for refuseIOCollisions: the CI invocation
	// (verify_winn3_conformance.sh) passes two different paths and must still
	// succeed.
	dir := t.TempDir()
	vec := filepath.Join(dir, "vectors.json")
	tasks := filepath.Join(dir, "tasks.txt")
	var out strings.Builder
	if err := run([]string{"-emit", vec, "-emit-tasks", tasks}, &out); err != nil {
		t.Fatalf("emit + emit-tasks to different paths must succeed: %v\n%s", err, out.String())
	}
	stVec, err := os.Stat(vec)
	if err != nil || stVec.Size() == 0 {
		t.Fatalf("vectors file missing or empty: %v", err)
	}
	stTasks, err := os.Stat(tasks)
	if err != nil || stTasks.Size() == 0 {
		t.Fatalf("task list missing or empty: %v", err)
	}
	if !strings.Contains(out.String(), "wrote") {
		t.Fatalf("expected write receipts, got:\n%s", out.String())
	}
}

func TestEmitWriteErrorNamesTheFlag(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	err := run([]string{"-emit", dir}, &out)
	if err == nil {
		t.Fatal("-emit to a directory must fail")
	}
	if !strings.Contains(err.Error(), "-emit") {
		t.Fatalf("write failure must name -emit, got %v", err)
	}
	if exitCodeFor(err) != 1 {
		t.Fatalf("a write failure is exit 1, got %d (%T: %v)", exitCodeFor(err), err, err)
	}
}

func TestHelpIsNotASuccessfulRun(t *testing.T) {
	var out strings.Builder
	err := run([]string{"-h"}, &out)
	if err == nil {
		t.Fatal("-h must not be reported as a successful conformance run")
	}
	if exitCodeFor(err) != 1 {
		t.Fatalf("-h is a flag-parse error (exit 1), got %d", exitCodeFor(err))
	}
}
