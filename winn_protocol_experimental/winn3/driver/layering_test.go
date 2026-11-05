package driver

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

// The guards below parse this package's own AST rather than grepping it.
//
// A text grep cannot see through an alias — `import d "…/datapath"` followed by
// `d.Evaluate` contains neither "winnprotocol/datapath" as a selector nor
// "datapath." as a call — and it flags the doc comments that explain why these
// things are banned, which is how a structural guard becomes noise and then
// becomes disabled. Every instrument here is also fed a file that does the
// banned thing and required to object; a structural test is exactly the shape
// that passes silently when the instrument is broken.

func parseSelf(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) < 4 {
		t.Fatalf("parsed %d source files; the guard is looking in the wrong place", len(files))
	}
	return fset, files
}

// bannedImports is the dependency edge winn3/ may not acquire.
//
// winn3/ is standalone. datapath/ is the v1/v2 world plus the committed
// escalation decision; importing it here would give the standalone protocol the
// dependency graph the ruling removed, and winn3/carrier already holds the same
// guard. The escalation adapter lives in driver/dpbridge, which is a leaf
// package a host opts into.
var bannedImports = map[string]string{
	"winsvpn.local/winnprotocol/datapath":         "winn3 is standalone; the adapter is driver/dpbridge",
	"winsvpn.local/winnprotocol/internal/carrier": "the v1/v2 carrier manager is not this protocol's",
	"winsvpn.local/winnprotocol/internal/awg":     "nothing here is solved with AmneziaWG",
	"github.com/xtls/xray-core":                   "nothing here is solved with Xray",
	"winsvpn.local/winnprotocol/winn3/gateway":    "the gateway lane owns dispatch; this loop drives one session",
}

func importsOf(files []*ast.File) []string {
	var out []string
	for _, f := range files {
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

func TestDriverIsStandalone(t *testing.T) {
	_, files := parseSelf(t)
	for _, p := range importsOf(files) {
		for banned, why := range bannedImports {
			if p == banned || strings.HasPrefix(p, banned+"/") {
				t.Fatalf("package driver imports %q: %s", p, why)
			}
		}
	}
}

// selectorUses counts references to pkg.Name across the package, resolving the
// local name of each import so that an alias cannot hide one.
func selectorUses(files []*ast.File, path, name string) int {
	n := 0
	for _, f := range files {
		local := ""
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil || p != path {
				continue
			}
			if imp.Name != nil {
				local = imp.Name.Name
			} else {
				local = p[strings.LastIndex(p, "/")+1:]
			}
		}
		if local == "" {
			continue
		}
		ast.Inspect(f, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != name {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local {
				n++
			}
			return true
		})
	}
	return n
}

const sessionPath = "winsvpn.local/winnprotocol/winn3/session"

// TestDriverNeverNamesTheDefaultMessageSize is the ban the carrier lane holds in
// its own package, applied here because this is the package that could reach
// around it.
//
// session.DefaultMaxMessageSize is 1280-48: correct for UDP over IPv6 and for
// nothing else. A loop that fell back to it would be 84 bytes wide of the floor
// on the first migration to a stream carrier, which is the black hole the whole
// Sizing type exists to close. The loop always sets the size explicitly, so the
// default is unreachable rather than merely unused.
func TestDriverNeverNamesTheDefaultMessageSize(t *testing.T) {
	_, files := parseSelf(t)
	if n := selectorUses(files, sessionPath, "DefaultMaxMessageSize"); n != 0 {
		t.Fatalf("package driver references session.DefaultMaxMessageSize %d times; "+
			"the size must come from Sizing, which is the floor over the migration plan", n)
	}
}

// TestExactlyOneSiteSetsTheMessageSize counts assignments to MaxMessageSize.
//
// One site is auditable; two is a claim. The invariant "the session's ceiling is
// the plan floor" is worth exactly as much as the number of places that can
// violate it, which is the argument the tun lane makes about its single device
// write site.
func TestExactlyOneSiteSetsTheMessageSize(t *testing.T) {
	_, files := parseSelf(t)
	n := 0
	for _, f := range files {
		ast.Inspect(f, func(node ast.Node) bool {
			as, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "MaxMessageSize" {
					n++
				}
			}
			return true
		})
	}
	if n != 1 {
		t.Fatalf("%d sites assign MaxMessageSize; want exactly one", n)
	}
}

// TestSessionHasExactlyTwoEnqueueSites is the same argument on the other seam,
// widened on 2026-08-12 from "exactly one" to a named, closed set of two.
//
// Everything that reaches the session's send queue either passed the tun
// layer's inbound rules (frameSink.SendData) or passed Loop.SendInner's own
// narrower fail-closed check in place of them (a caller outside the tun layer
// entirely, for a gateway session with no tun.Tunnel — see SendInner's doc for
// why winn3/tun cannot be that caller). That is a second way in, added
// deliberately, and the risk this test now guards against is a THIRD one
// appearing by accident: it still fails on any count other than the two named
// sites below, and it names them so a new one cannot hide by matching the
// count.
func TestSessionHasExactlyTwoEnqueueSites(t *testing.T) {
	_, files := parseSelf(t)
	var sites []string
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			found := false
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Enqueue" {
					found = true
				}
				return true
			})
			if !found {
				continue
			}
			name := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				name = exprTypeName(fn.Recv.List[0].Type) + "." + name
			}
			sites = append(sites, name)
		}
	}
	want := map[string]bool{"frameSink.SendData": true, "Loop.SendInner": true}
	if len(sites) != len(want) {
		t.Fatalf("%d call site(s) reach session.Enqueue (%v); want exactly %v", len(sites), sites, want)
	}
	for _, s := range sites {
		if !want[s] {
			t.Fatalf("unexpected call site %q reaches session.Enqueue; want exactly %v", s, want)
		}
	}
}

// exprTypeName renders a (possibly pointer) receiver type's bare name, so a
// method on *Loop and a method on Loop are reported identically.
func exprTypeName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

// TestTheFloorIsComputedInOnePlace requires the plan floor to be derived once,
// by delegation, and never re-derived with local arithmetic on a path MTU.
func TestTheFloorIsComputedInOnePlace(t *testing.T) {
	_, files := parseSelf(t)
	const carrierPath = "winsvpn.local/winnprotocol/winn3/carrier"
	if n := selectorUses(files, carrierPath, "NewPlanFloor"); n != 1 {
		t.Fatalf("%d references to carrier.NewPlanFloor; want exactly one", n)
	}
	if n := selectorUses(files, carrierPath, "Floor"); n != 0 {
		t.Fatalf("%d direct references to carrier.Floor; NewPlanFloor is the one entry point", n)
	}
}

// TestPackageHasNoAmbientClock forbids the standard library's clock by selector.
//
// The loop owns the only timer in v3, and it takes it from Config.Clock so that
// every schedule is deterministic under test. A direct time.Now or time.Sleep
// here would put part of the schedule beyond a test's reach, which is how the
// 25.000-second metronome survived long enough to be measured in the field.
// time.Duration, time.Time and time.NewTimer inside SystemClock are the
// exceptions, and SystemClock is the one place a real clock is read.
func TestPackageHasNoAmbientClock(t *testing.T) {
	_, files := parseSelf(t)
	banned := []string{"Now", "Since", "Until", "Sleep", "After", "Tick", "NewTicker", "AfterFunc"}
	for _, name := range banned {
		uses := selectorUses(files, "time", name)
		if name == "Now" {
			// SystemClock.Now is the single production reading of the wall clock.
			if uses > 1 {
				t.Fatalf("%d references to time.Now; only SystemClock.Now may read the wall clock", uses)
			}
			continue
		}
		if uses != 0 {
			t.Fatalf("%d references to time.%s; the loop's schedule must come from Config.Clock", uses, name)
		}
	}
	if n := selectorUses(files, "time", "NewTimer"); n != 1 {
		t.Fatalf("%d references to time.NewTimer; only SystemClock may build one", n)
	}
}

// TestGuardsHaveTeeth feeds every instrument above a file that does the banned
// thing and requires each to object.
//
// A structural test is exactly the shape that passes when the instrument is
// broken, and a passing invariant test that could never fail is worse than no
// test: it turns an unverified claim into a verified-looking one.
func TestGuardsHaveTeeth(t *testing.T) {
	const bad = `package driver

import (
	dp "winsvpn.local/winnprotocol/datapath"
	s "winsvpn.local/winnprotocol/winn3/session"
	"time"
)

func offend(cfg *s.Config) {
	cfg.MaxMessageSize = s.DefaultMaxMessageSize
	_ = dp.VerdictBlocked
	_ = time.Now()
	go func() { time.Sleep(time.Second) }()
}

func alsoOffend(d *s.Driver, p []byte) { _ = d.Enqueue(p) }
`
	dir := t.TempDir()
	path := filepath.Join(dir, "offender.go")
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	files := []*ast.File{f}

	// The import guard must see the ALIASED datapath import.
	found := false
	for _, p := range importsOf(files) {
		if _, banned := bannedImports[p]; banned {
			found = true
		}
	}
	if !found {
		t.Fatal("the import guard did not object to an aliased datapath import")
	}

	// The default-size guard must see the aliased session import.
	if n := selectorUses(files, sessionPath, "DefaultMaxMessageSize"); n != 1 {
		t.Fatalf("the default-size guard saw %d aliased references, want 1", n)
	}

	// The clock guard.
	if n := selectorUses(files, "time", "Now"); n != 1 {
		t.Fatalf("the clock guard saw %d references to time.Now, want 1", n)
	}
	if n := selectorUses(files, "time", "Sleep"); n != 1 {
		t.Fatalf("the clock guard saw %d references to time.Sleep, want 1", n)
	}

	// The single-site guards.
	assigns := 0
	enqueues := 0
	ast.Inspect(f, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "MaxMessageSize" {
					assigns++
				}
			}
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Enqueue" {
				enqueues++
			}
		}
		return true
	})
	if assigns != 1 || enqueues != 1 {
		t.Fatalf("the single-site guards saw %d assignments and %d enqueues, want 1 and 1",
			assigns, enqueues)
	}
}
