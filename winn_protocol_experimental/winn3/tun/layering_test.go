package tun

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The layering guards. The core enforces the same rule on itself by grepping
// its own source for banned substrings; these are the stricter version, because
// a substring grep cannot see through an alias — `import n "net"` followed by
// `n.Dial` contains neither `"net/` nor `net.Dial` and would sail past it.
// Everything here parses the real syntax tree instead.

// allowedImports is the whole of what this package may depend on, with the
// reason each one is safe. Anything else is either I/O, a host call, or a
// dependency that drags one in.
var allowedImports = map[string]string{
	"context":         "cancellation signalling; performs no I/O",
	"encoding/binary": "byte order; pure",
	"errors":          "sentinel errors",
	"fmt":             "Sprintf only, and TestFmtIsOnlyUsedForStrings enforces that",
	"net/netip":       "address values: parsing and comparison, no dialer, no resolver, no syscall",
	"sync":            "locks",
	"sync/atomic":     "counters",
	"time":            "Time and Duration values; TestNoTimersAndNoAmbientClock forbids the rest",

	"winsvpn.local/winnprotocol/winn3/core": "the protocol core, which is itself socket-free and timer-free",
}

func packageFiles(t *testing.T) (*token.FileSet, []*ast.File, []string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	var names []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		files = append(files, f)
		names = append(names, name)
	}
	if len(files) == 0 {
		t.Fatal("no source files found; the guard would pass vacuously")
	}
	return fset, files, names
}

// TestPackageOpensNothing is the portability guarantee and half of the
// fail-closed one.
//
// Portability: the same code has to be correct on utun, /dev/net/tun, WinTun,
// an Android VpnService descriptor and NEPacketTunnelFlow. It can only be that
// if it never names any of them.
//
// Fail-closed: the property is "no inner packet reaches the host's real
// interface". That is only provable if the set of ways this package can emit a
// byte is small enough to enumerate — the FrameSink and the Device, and nothing
// else. An import that can open a socket makes the claim unfalsifiable.
func TestPackageOpensNothing(t *testing.T) {
	_, files, names := packageFiles(t)
	for i, f := range files {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := allowedImports[path]; !ok {
				t.Errorf("%s imports %q, which is not on the allowlist; this package must open nothing", names[i], path)
			}
		}
	}
}

// TestNoTimersAndNoAmbientClock. A timer here would put the timing policy in
// two layers at once — and the measured failure this protocol replaces was a
// 25.000-second zero-jitter keepalive, which is a timer in the wrong layer.
// time.Now would make the rate limiter untestable and non-deterministic; the
// injected Clock is the only time source.
func TestNoTimersAndNoAmbientClock(t *testing.T) {
	banned := map[string]string{
		"Now":       "use the injected Clock",
		"Since":     "use the injected Clock",
		"Until":     "use the injected Clock",
		"Sleep":     "this package must not block on time",
		"After":     "this package holds no timer",
		"Tick":      "this package holds no timer",
		"NewTicker": "this package holds no timer",
		"NewTimer":  "this package holds no timer",
		"AfterFunc": "this package holds no timer",
	}
	fset, files, _ := packageFiles(t)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "time" {
				return true
			}
			if why, bad := banned[sel.Sel.Name]; bad {
				t.Errorf("%s: time.%s is forbidden — %s", fset.Position(sel.Pos()), sel.Sel.Name, why)
			}
			return true
		})
	}
}

// TestFmtIsOnlyUsedForStrings. fmt.Fprintf and fmt.Print write somewhere;
// Sprintf and Errorf do not. Keeping to the second pair is what lets fmt sit on
// the import allowlist at all.
func TestFmtIsOnlyUsedForStrings(t *testing.T) {
	allowed := map[string]bool{"Sprintf": true, "Errorf": true, "Sprint": true}
	fset, files, _ := packageFiles(t)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "fmt" {
				return true
			}
			if !allowed[sel.Sel.Name] {
				t.Errorf("%s: fmt.%s writes somewhere; only string formatting is allowed here",
					fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}

// countCalls counts calls of the form <something>.<name>(...).
func countCalls(t *testing.T, name string) (int, []string) {
	t.Helper()
	fset, files, _ := packageFiles(t)
	var n int
	var where []string
	for _, f := range files {
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != name {
				return true
			}
			n++
			where = append(where, fset.Position(call.Pos()).String())
			return true
		})
	}
	return n, where
}

// TestDeviceHasExactlyOneWriteSite. The invariant "everything written to the
// host passed the inbound address rules" is worth exactly as much as the number
// of places that can violate it. One place is auditable; two is a claim.
//
// The synthesised path-MTU packet goes through the same door as every other
// delivered packet for this reason: it makes the no-forwarding property an
// instance of the rule rather than an exception to it.
func TestDeviceHasExactlyOneWriteSite(t *testing.T) {
	n, where := countCalls(t, "WritePacket")
	if n != 1 {
		t.Fatalf("WritePacket is called from %d sites (%v); exactly one, inside deliver, may write to the host", n, where)
	}
	if !strings.Contains(where[0], "tun.go") {
		t.Fatalf("the single WritePacket call site is at %s; it belongs in tun.go's deliver", where[0])
	}
}

// TestSessionHasExactlyOneSendSite is the same argument on the other side: one
// door out to the wire, and it is behind the gate.
func TestSessionHasExactlyOneSendSite(t *testing.T) {
	n, where := countCalls(t, "SendData")
	if n != 1 {
		t.Fatalf("SendData is called from %d sites (%v); exactly one may hand a packet to the session", n, where)
	}
}

// TestNoHiddenGoroutines. Every loop in this package runs on a goroutine the
// caller supplied and can therefore stop. A package that starts its own has
// lifetimes the host cannot see, and a packet loop that outlives a teardown is
// the fail-closed property leaking out the side.
func TestNoHiddenGoroutines(t *testing.T) {
	fset, files, _ := packageFiles(t)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if g, ok := n.(*ast.GoStmt); ok {
				t.Errorf("%s: this package must not start goroutines", fset.Position(g.Pos()))
			}
			return true
		})
	}
}

// TestNoPanicsOnThePacketPath. A panic in the packet loop takes the tunnel
// down, and on a hostile network the input to that loop is attacker-influenced.
func TestNoPanicsOnThePacketPath(t *testing.T) {
	fset, files, _ := packageFiles(t)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
				t.Errorf("%s: panic on the packet path", fset.Position(call.Pos()))
			}
			return true
		})
	}
}

// TestLayeringGuardHasTeeth feeds the import checker a file that imports
// something forbidden and requires it to object.
//
// A passing invariant test that could never fail is worse than no test: it
// turns an unverified claim into a verified-looking one. The core makes the
// same argument for its uniformity detector; the same argument applies here.
func TestLayeringGuardHasTeeth(t *testing.T) {
	src := `package tun
import (
	n "net"
	"os/exec"
)
func leak() { _, _ = n.Dial("udp", "x"); _ = exec.Command("x") }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "leak.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var flagged []string
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := allowedImports[path]; !ok {
			flagged = append(flagged, path)
		}
	}
	if len(flagged) != 2 {
		t.Fatalf("the guard flagged %v; it must object to both the aliased net import and os/exec", flagged)
	}
}
