package datapath

import (
	"go/parser"
	"go/token"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// datapathTarget is one GOOS/GOARCH pair together with the cgo setting
// tools/build_winn_protocol_engine.sh builds that pair with. Both matter: the
// dependency closure of a package changes with GOOS and with cgo, so a closure
// checked under the wrong pair is not the closure that ships.
type datapathTarget struct {
	goos, goarch string
	cgo          bool
}

// archiveEngineTargets are the pairs tools/build_winn_protocol_engine.sh builds
// the cdatapath c-archive for. Read off the target case arms that call
// select_datapath_archive (PACKAGE="./cdatapath"): datapath-ios-arm64,
// datapath-iossimulator-{arm64,amd64} (GOOS=ios), and
// datapath-archive-darwin-{arm64,amd64} (GOOS=darwin). All of them cgo-on,
// because the c-archive surface lives behind `import "C"`.
//
// This is the darwin/iOS family and ONLY the darwin/iOS family, which is why
// every cdatapath/*.go file carries //go:build darwin. Android is deliberately
// absent: it ships the cmd/winn-datapath subprocess engine instead.
//
// THE DAY the build script grows a datapath-android-* arm that calls
// select_datapath_archive, add that pair here and the closure re-enters the
// matrix. That is the whole reason this is a list and not a GOOS=="darwin"
// test: the path stays expressible instead of being deleted.
var archiveEngineTargets = []datapathTarget{
	{"ios", "arm64", true},
	{"ios", "amd64", true},
	{"darwin", "arm64", true},
	{"darwin", "amd64", true},
}

// subprocessEngineTargets are the pairs the same script builds
// cmd/winn-datapath for, read off the arms that call select_datapath_engine.
//
// iOS is absent on purpose and not by oversight: iOS forbids subprocesses
// outright, which is the reason cdatapath exists at all. Android is built
// through the NDK clang wrapper with cgo on, matching the xray engine; every
// other pair is a plain static executable with cgo off.
var subprocessEngineTargets = []datapathTarget{
	{"windows", "amd64", false},
	{"windows", "arm64", false},
	{"darwin", "amd64", false},
	{"darwin", "arm64", false},
	{"linux", "amd64", false},
	{"linux", "arm64", false},
	{"android", "arm64", true},
	{"android", "amd64", true},
}

// The packages that make up the shippable datapath surface, each paired with
// the exact targets it is built for. Every one of them runs on a device with no
// shell, so none may reach os/exec.
//
// datapath and datapath/duplex are libraries that never ship on their own —
// they ship inside the two engines, so their target set is the union of both
// engines'. Checking them directly as well is not redundant: it localises a
// violation to the library rather than to whichever engine happened to be
// listed first.
var datapathPackages = []struct {
	path    string
	targets []datapathTarget
}{
	{"winsvpn.local/winnprotocol/datapath", append(
		append([]datapathTarget{}, archiveEngineTargets...), subprocessEngineTargets...)},
	{"winsvpn.local/winnprotocol/datapath/duplex", append(
		append([]datapathTarget{}, archiveEngineTargets...), subprocessEngineTargets...)},
	{"winsvpn.local/winnprotocol/cdatapath", archiveEngineTargets},
	{"winsvpn.local/winnprotocol/cmd/winn-datapath", subprocessEngineTargets},
}

var forbiddenDependencies = []string{"os/exec"}

// forbiddenIdentifiers catches the process-creation calls that live in
// packages the datapath legitimately imports, so an import-path check alone
// would not see them.
var forbiddenIdentifiers = []string{
	"os.StartProcess",
	"syscall.ForkExec",
	"syscall.StartProcess",
	"syscall.CreateProcess",
}

// TestDatapathSourceImportsNoSubprocessPackage parses the datapath sources
// directly. It needs no toolchain and no network, so it always runs, and it
// covers files that a build-tagged compile might exclude.
func TestDatapathSourceImportsNoSubprocessPackage(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	directories := []string{
		filepath.Join(root, "datapath"),
		filepath.Join(root, "datapath", "duplex"),
		filepath.Join(root, "cdatapath"),
		filepath.Join(root, "cmd", "winn-datapath"),
	}
	inspected := 0
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read %s: %v", directory, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
				strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(directory, name)
			file, err := parser.ParseFile(
				token.NewFileSet(), path, nil, parser.ImportsOnly,
			)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			inspected++
			for _, imported := range file.Imports {
				value := strings.Trim(imported.Path.Value, `"`)
				if slices.Contains(forbiddenDependencies, value) {
					t.Errorf("%s imports %q; the datapath must never "+
						"spawn a subprocess", path, value)
				}
			}
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, identifier := range forbiddenIdentifiers {
				// The identifiers are only ever named in this list and in
				// prose, so a match in real code is unambiguous.
				if strings.Contains(string(source), identifier+"(") {
					t.Errorf("%s calls %s; the datapath must never spawn a "+
						"subprocess", path, identifier)
				}
			}
		}
	}
	if inspected < 8 {
		t.Fatalf("only %d datapath source files were inspected; the guard "+
			"is not covering the package", inspected)
	}
}

// TestDatapathDependencyClosureHasNoSubprocessPackage is the transitive form:
// it asks the toolchain for the full dependency closure of each shipped
// package, for the platforms that forbid subprocesses outright. A direct-import
// scan cannot see a forbidden package pulled in three levels down; this can.
func TestDatapathDependencyClosureHasNoSubprocessPackage(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go tool not on PATH, transitive closure unchecked: %v", err)
	}
	// Each package is listed exactly the way
	// tools/build_winn_protocol_engine.sh builds it — its real targets, with
	// its real cgo setting — so the closure under test is the closure that
	// ships.
	closuresChecked := 0
	for _, pkg := range datapathPackages {
		for _, target := range pkg.targets {
			cgo := "CGO_ENABLED=0"
			if target.cgo {
				cgo = "CGO_ENABLED=1"
			}
			command := exec.Command("go", "list", "-deps", pkg.path)
			command.Dir = moduleDir(t)
			command.Env = append(os.Environ(),
				"GOOS="+target.goos,
				"GOARCH="+target.goarch,
				cgo,
				"GOTOOLCHAIN=local",
				"GOFLAGS=-mod=mod",
			)
			output, err := command.CombinedOutput()
			if err != nil {
				// Errorf and CARRY ON, never Fatalf. Until 2026-08-12 this was
				// a Fatalf, and because cdatapath is darwin-only while the loop
				// asked for it on android/arm64, `go list` returned "build
				// constraints exclude all Go files" and aborted the whole
				// function on the second target. Everything after it — windows,
				// darwin, linux/amd64, and the platform actually being deployed
				// — was never checked at all. The gate reported one red line
				// while silently verifying nothing, which is worse than red.
				// One unbuildable target must cost exactly that one target.
				t.Errorf("go list -deps %s for %s/%s (%s): %v\n%s",
					pkg.path, target.goos, target.goarch, cgo, err, output)
				continue
			}
			closuresChecked++
			for _, line := range strings.Split(string(output), "\n") {
				dependency := strings.TrimSpace(line)
				if slices.Contains(forbiddenDependencies, dependency) {
					// The cgo setting is named because darwin is checked under
					// BOTH — it ships as the cgo-on c-archive and as the cgo-off
					// subprocess executable — and a violation that appears under
					// only one of them is a different bug from one that appears
					// under both.
					t.Errorf("%s on %s/%s (%s) transitively depends on %q",
						pkg.path, target.goos, target.goarch, cgo, dependency)
				}
			}
		}
	}

	// The coverage floor, for the same reason TestDatapathSourceImportsNo-
	// SubprocessPackage counts the files it inspected: a sweep that checked
	// nothing passes every assertion inside it. This is the assertion that the
	// sweep happened. It must equal the number of (package, target) pairs
	// declared above, so trimming the matrix without noticing is caught here.
	wantClosures := 0
	for _, pkg := range datapathPackages {
		wantClosures += len(pkg.targets)
	}
	if closuresChecked != wantClosures {
		t.Errorf("only %d of %d declared datapath closures were checked; a "+
			"target the toolchain cannot list is a target this gate is blind "+
			"on, not a target that passed", closuresChecked, wantClosures)
	}
}

func moduleDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	return root
}

// withSocketOpenerGuard replaces the package's only socket-creation seam with
// one that records the attempt and refuses. Any code path that tried to open a
// socket would both fail and be counted.
func withSocketOpenerGuard(t *testing.T) *atomic.Int64 {
	t.Helper()
	var attempts atomic.Int64
	original := socketOpener
	socketOpener = func(network, address string) (net.PacketConn, error) {
		attempts.Add(1)
		t.Errorf("engine opened its own UDP socket (%s %s) although one "+
			"was supplied", network, address)
		return nil, os.ErrPermission
	}
	t.Cleanup(func() { socketOpener = original })
	return &attempts
}

// TestSuppliedConnectionMeansNoSocketIsOpened covers the whole lifetime, not
// just construction: create, carry traffic in both directions, read status,
// close. None of it may create a socket.
func TestSuppliedConnectionMeansNoSocketIsOpened(t *testing.T) {
	attempts := withSocketOpenerGuard(t)
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	if _, err := engine.WriteInbound([]byte("carry me")); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	count, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	if _, err := gateway.WriteToUDP(buffer[:count], from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound: %v", err)
	}
	_ = engine.StatusJSON()
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("%d socket-creation attempts with a supplied connection", got)
	}
}
