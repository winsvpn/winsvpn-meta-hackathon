package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// frozenCExports is the C ABI this package claims. Adding or removing an
// //export without updating this list is an ABI change the test must see.
var frozenCExports = []string{
	"WinnFreeString",
	"WinnFacadeVersion",
	"WinnProtocolVersion",
	"WinnRekeyProtocolVersion",
	"WinnTunnelSupported",
	"WinnTunnelBackendJSON",
	"WinnSupportedSuitesJSON",
	"WinnSupportedModesJSON",
	"WinnCapabilitiesJSON",
	"WinnRequiredAuthAlgorithm",
	"WinnCarriersForModeJSON",
	"WinnValidateReadinessJSON",
	"WinnValidateBindingJSON",
	"WinnValidateDeviceID",
	"WinnValidatePeerPublicKey",
	"WinnConnect",
	"WinnStatusJSON",
	"WinnDisconnect",
}

func TestExportDirectivesMatchFrozenABI(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "winn_clientbinding.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse winn_clientbinding.go: %v", err)
	}
	var got []string
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			name, ok := strings.CutPrefix(c.Text, "//export ")
			if !ok {
				continue
			}
			got = append(got, strings.TrimSpace(name))
		}
	}
	if strings.Join(got, ",") != strings.Join(frozenCExports, ",") {
		t.Fatalf("C ABI //export list changed.\ngot:  %v\nwant: %v", got, frozenCExports)
	}
}

func TestCABIProbe(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("C ABI probe needs cc + c-shared on %s", runtime.GOOS)
	}
	probeSrc, err := filepath.Abs(filepath.Join("testdata", "cabi_probe.c"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(probeSrc); err != nil {
		t.Fatalf("probe source missing: %v", err)
	}

	buildDir, err := os.MkdirTemp(".", "cabi-out-")
	if err != nil {
		t.Fatalf("mkdir build dir in package (not /tmp): %v", err)
	}
	buildDir, err = filepath.Abs(buildDir)
	if err != nil {
		t.Fatalf("abs build dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(buildDir) })

	libName := "libwinn_clientbinding.dylib"
	if runtime.GOOS == "linux" {
		libName = "libwinn_clientbinding.so"
	}
	libPath := filepath.Join(buildDir, libName)
	headerPath := filepath.Join(buildDir, "libwinn_clientbinding.h")

	// The C probe links a c-shared dylib built by a child `go build`.
	// `go test -overlay` applies only to the test compile, not to that child,
	// so mutation runs must set CSHARED_OVERLAY to the same JSON.
	buildArgs := []string{"build", "-buildmode=c-shared", "-o", libPath, "."}
	if overlay := os.Getenv("CSHARED_OVERLAY"); overlay != "" {
		buildArgs = []string{"build", "-overlay", overlay, "-buildmode=c-shared", "-o", libPath, "."}
	}
	build := exec.Command("go", buildArgs...)
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build -buildmode=c-shared: %v\n%s", err, out)
	}
	st, err := os.Stat(libPath)
	if err != nil {
		t.Fatalf("c-shared output missing: %v", err)
	}
	if st.Size() == 0 {
		t.Fatal("c-shared output is zero bytes")
	}
	if _, err := os.Stat(headerPath); err != nil {
		t.Fatalf("c-shared did not write a header: %v", err)
	}

	probePath := filepath.Join(buildDir, "cabi_probe")
	cc := exec.Command("cc", "-o", probePath, probeSrc, libPath)
	if runtime.GOOS == "darwin" {
		cc.Args = append(cc.Args, "-Wl,-rpath,@executable_path")
	}
	if out, err := cc.CombinedOutput(); err != nil {
		t.Fatalf("cc probe: %v\n%s", err, out)
	}

	run := exec.Command(probePath)
	run.Dir = buildDir
	run.Env = append(os.Environ(),
		"WINS_WINN3_ENGINE=",
		"DYLD_LIBRARY_PATH="+buildDir,
		"LD_LIBRARY_PATH="+buildDir,
	)
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	err = run.Run()
	t.Logf("probe stdout:\n%s", stdout.String())
	if stderr.Len() > 0 {
		t.Logf("probe stderr:\n%s", stderr.String())
	}
	if err != nil {
		t.Fatalf("C ABI probe failed: %v\nstderr:\n%s\nstdout:\n%s", err, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "ALL_PASS") {
		t.Fatalf("probe exit 0 but no ALL_PASS marker\nstdout:\n%s", stdout.String())
	}
}
