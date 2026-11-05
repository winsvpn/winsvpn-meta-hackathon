package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The forward direction runs once per client packet, and its diagnostics go to
// stderr, which the unit sends to the journal and, on a node where rsyslog is
// still running, to /var/log/syslog. Measured 2026-09-24 (lane L25): 13,333
// lines in one node's syslog read
//
//	forward validatePeerSource failed: peer=<static key> src=<inner> dst=<destination>
//
// which ties a client's long-term identity key, which the hub maps to an
// account, to every internet address it tried to reach. The inner address is
// itself a stable per-user identifier: the peer registry binds each static key
// to exactly one inner_v4. These tests pin that no forward-direction
// diagnostic carries the peer key, the inner source, the owned address or the
// destination, and that no stderr or stdout print anywhere in this package
// names a peer's static key.

// captureStderr runs fn with os.Stderr redirected and returns what was written.
// The forward diagnostics use fmt.Fprintf(os.Stderr, ...), which reads the
// variable at call time, so swapping it is enough. Not parallel-safe; the
// tests using it do not call t.Parallel.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stderr = saved }()
	fn()
	os.Stderr = saved
	_ = w.Close()
	return <-done
}

func TestForwardDiagnosticsCarryNoClientAddresses(t *testing.T) {
	// Addresses used by no other test in this package, so a stray line from an
	// unrelated goroutine cannot make the absence check pass or fail.
	const inner1, inner2, dest = "10.64.77.2", "10.64.77.3", "198.51.100.77"
	out := captureStderr(t, func() {
		// 1. source changed: one session, two inner sources.
		dev := newGatewayForwardDevice(&fakeInnerWriter{}, newForwardTable(), 1400)
		dev.bind(fakeLoop())
		if _, err := dev.WritePacket(ipv4Packet(t, inner1, dest)); err != nil {
			t.Fatalf("first packet: %v", err)
		}
		if _, err := dev.WritePacket(ipv4Packet(t, inner2, dest)); !errors.Is(err, errGatewayInnerSourceChanged) {
			t.Fatalf("second source error = %v, want %v", err, errGatewayInnerSourceChanged)
		}
		// 2. table.learn failed: a second session claims an owned inner address.
		tbl := newForwardTable()
		a := newGatewayForwardDevice(&fakeInnerWriter{}, tbl, 1400)
		a.bind(fakeLoop())
		if _, err := a.WritePacket(ipv4Packet(t, inner1, dest)); err != nil {
			t.Fatalf("owner packet: %v", err)
		}
		b := newGatewayForwardDevice(&fakeInnerWriter{}, tbl, 1400)
		b.bind(fakeLoop())
		if _, err := b.WritePacket(ipv4Packet(t, inner1, dest)); !errors.Is(err, errGatewayInnerSourceOwned) {
			t.Fatalf("collision error = %v, want %v", err, errGatewayInnerSourceOwned)
		}
		// 3. shared.write failed.
		c := newGatewayForwardDevice(&fakeInnerWriter{err: errors.New("tun write refused")}, newForwardTable(), 1400)
		c.bind(fakeLoop())
		if _, err := c.WritePacket(ipv4Packet(t, inner2, dest)); err == nil {
			t.Fatal("write through a failing writer reported success")
		}
	})
	// Anti-vacuity: each diagnostic must actually have been written, or the
	// absence checks below would pass on an empty capture.
	for _, want := range []string{"forward source changed", "forward table.learn failed", "shared.write failed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("diagnostic %q was not logged; captured:\n%s", want, out)
		}
	}
	for _, addr := range []string{inner1, inner2, dest} {
		if strings.Contains(out, addr) {
			t.Errorf("forward diagnostic leaked %s:\n%s", addr, out)
		}
	}
}

// TestForwardValidatePeerSourceDiagnosticCarriesNoIdentity drives the line
// the 2026-09-24 fleet probe measured, through a real authenticated session
// (newAuthorityFixture), for both refusal classes validatePeerSource returns.
func TestForwardValidatePeerSourceDiagnosticCarriesNoIdentity(t *testing.T) {
	// 10.10.0.2 is the fixture's authorized inner address. The spoofed source
	// and the destinations are used by no other test in this package.
	const authorized, spoofed = "10.10.0.2", "10.10.0.77"
	const dest1, dest2 = "198.51.100.78", "198.51.100.79"
	f := newAuthorityFixture(t, 0)
	out := captureStderr(t, func() {
		// Class 1: the authenticated peer claims an inner source that is not
		// the one its registry entry binds.
		if _, err := f.device.WritePacket(ipv4Packet(t, spoofed, dest1)); !errors.Is(err, errGatewayInnerSourceMismatch) {
			t.Fatalf("spoofed source error = %v, want %v", err, errGatewayInnerSourceMismatch)
		}
		// Class 2: the peer's registry entry is withdrawn while the session is
		// live.
		replaceAuthority(t, f.registry.path, `{"version":1,"peers":[]}`)
		dueAuthorityRefresh(f.registry)
		if _, err := f.device.WritePacket(ipv4Packet(t, authorized, dest2)); !errors.Is(err, errGatewayPeerUnauthorized) {
			t.Fatalf("revoked peer error = %v, want %v", err, errGatewayPeerUnauthorized)
		}
	})
	if !strings.Contains(out, "forward validatePeerSource failed") {
		t.Fatalf("validatePeerSource diagnostic was not logged; captured:\n%s", out)
	}
	for _, class := range []error{errGatewayInnerSourceMismatch, errGatewayPeerUnauthorized} {
		if !strings.Contains(out, class.Error()) {
			t.Errorf("the refusal class %q is the operator signal and must stay visible; captured:\n%s", class, out)
		}
	}
	forbidden := []string{
		hex.EncodeToString(f.key),
		strings.ToUpper(hex.EncodeToString(f.key)),
		base64.StdEncoding.EncodeToString(f.key),
		base64.RawURLEncoding.EncodeToString(f.key),
		authorized, spoofed, dest1, dest2,
	}
	for _, needle := range forbidden {
		if strings.Contains(out, needle) {
			t.Errorf("forward diagnostic leaked %q:\n%s", needle, out)
		}
	}
	// A prefix of the key is still a stable identifier.
	if prefix := hex.EncodeToString(f.key[:6]); strings.Contains(strings.ToLower(out), prefix) {
		t.Errorf("forward diagnostic leaked a key prefix %q:\n%s", prefix, out)
	}
}

// TestForwardDiagnosticArgumentsCarryNoPeerData is the source-level half: it
// rejects any stderr print in WritePacket whose arguments name the packet
// addresses, the owned address or the peer's static key, so a future edit
// cannot add one back on a path the behavioural tests do not drive.
func TestForwardDiagnosticArgumentsCarryNoPeerData(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "forward.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"src": true, "dst": true, "owned": true, "PeerStatic": true}
	var prints, sentinelPrints int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "WritePacket" || fn.Recv == nil {
			continue
		}
		// err may be printed only where it is validatePeerSource's result,
		// which is one of two fixed sentinel errors. Anywhere else err is an
		// unrestricted error (innerWriter.write returns whatever the writer
		// chose) and may name the packet's addresses.
		var sentinelScopes []*ast.BlockStmt
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			stmt, ok := n.(*ast.IfStmt)
			if !ok || stmt.Init == nil {
				return true
			}
			ast.Inspect(stmt.Init, func(m ast.Node) bool {
				if sel, ok := m.(*ast.SelectorExpr); ok && sel.Sel.Name == "validatePeerSource" {
					sentinelScopes = append(sentinelScopes, stmt.Body)
				}
				return true
			})
			return true
		})
		inSentinelScope := func(pos token.Pos) bool {
			for _, b := range sentinelScopes {
				if pos >= b.Pos() && pos < b.End() {
					return true
				}
			}
			return false
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(sel.Sel.Name, "Fprint") {
				return true
			}
			prints++
			for _, arg := range call.Args[1:] {
				ast.Inspect(arg, func(m ast.Node) bool {
					id, ok := m.(*ast.Ident)
					if !ok {
						return true
					}
					if forbidden[id.Name] {
						t.Errorf("%s: stderr diagnostic prints %q", fset.Position(call.Pos()), id.Name)
					}
					if id.Name == "err" {
						if inSentinelScope(call.Pos()) {
							sentinelPrints++
						} else {
							t.Errorf("%s: stderr diagnostic prints an unrestricted err; log its class or a count, "+
								"not its text", fset.Position(call.Pos()))
						}
					}
					return true
				})
			}
			return true
		})
	}
	// Anti-vacuity: WritePacket must still exist and still carry its prints,
	// and the sentinel-scope detection must have found the one legitimate
	// err print.
	if prints < 6 {
		t.Fatalf("found %d Fprint calls in WritePacket, want at least 6; the scan is not looking at the right code", prints)
	}
	if sentinelPrints != 1 {
		t.Fatalf("found %d err prints inside the validatePeerSource branch, want 1; "+
			"the sentinel-scope detection is not looking at the right code", sentinelPrints)
	}
}

// TestForwardWriteFailureLogsNoErrorText pins OI-U2 (Round U): the error a
// writer returns is unrestricted, so its text never reaches the process log,
// and the caller still receives it unchanged.
func TestForwardWriteFailureLogsNoErrorText(t *testing.T) {
	const inner, dest = "10.64.77.3", "198.51.100.77"
	writeErr := errors.New("write " + inner + " to " + dest + " failed")
	var got error
	out := captureStderr(t, func() {
		dev := newGatewayForwardDevice(&fakeInnerWriter{err: writeErr}, newForwardTable(), 1400)
		dev.bind(fakeLoop())
		_, got = dev.WritePacket(ipv4Packet(t, inner, dest))
	})
	if got != writeErr {
		t.Fatalf("WritePacket returned %v, want the writer's own error value", got)
	}
	// Anti-vacuity: the failure was described.
	if !strings.Contains(out, "shared.write failed") {
		t.Fatalf("write failure was not logged; captured:\n%s", out)
	}
	for _, addr := range []string{inner, dest} {
		if strings.Contains(out, addr) {
			t.Errorf("write-failure diagnostic leaked %s from the writer's error text:\n%s", addr, out)
		}
	}
}

// TestNoProcessLogNamesAPeerStaticKey scans every non-test file of this
// package for a print to os.Stderr or os.Stdout, or a call through a logf
// sink, whose arguments reach a peer's static key. The key is the account
// identity; no operational line needs it.
func TestNoProcessLogNamesAPeerStaticKey(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"PeerStatic": true, "InitiatorStatic": true, "peerStatic": true, "innerForPeer": true}
	var scanned, sinks int
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isProcessLogSink(call) {
				return true
			}
			sinks++
			for _, arg := range call.Args {
				ast.Inspect(arg, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok && forbidden[id.Name] {
						t.Errorf("%s: process log line reaches %q", fset.Position(call.Pos()), id.Name)
					}
					return true
				})
			}
			return true
		})
	}
	if scanned < 20 || sinks < 30 {
		t.Fatalf("scanned %d files and %d log sinks; the scan is not looking at this package", scanned, sinks)
	}
}

// isProcessLogSink reports fmt.Fprint*(os.Stderr|os.Stdout, ...) and calls of
// a function value named logf.
func isProcessLogSink(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == "logf"
	case *ast.SelectorExpr:
		pkg, ok := fun.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" || !strings.HasPrefix(fun.Sel.Name, "Fprint") || len(call.Args) == 0 {
			return false
		}
		w, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok {
			return false
		}
		recv, ok := w.X.(*ast.Ident)
		return ok && recv.Name == "os" && (w.Sel.Name == "Stderr" || w.Sel.Name == "Stdout")
	}
	return false
}

// TestEveryHTTPServerRedactsItsErrorLog pins: every http.Server literal in
// this package declares an ErrorLogger. With ErrorLog nil, net/http writes
// lines such as
//
//	http: panic serving 10.64.0.5:43210: ...
//
// to the process's standard logger with the client's address interpolated.
// On the speedtest ingest listener that address is the client's inner
// address, which the peer registry binds to one account.
//
// The redaction itself is observability.ErrorLogger's, pinned by that
// package's own tests; this test pins only that the servers here use it.
func TestEveryHTTPServerRedactsItsErrorLog(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var servers int
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isHTTPServerType(lit.Type) {
				return true
			}
			servers++
			if !declaresErrorLogger(lit) {
				t.Errorf("%s: http.Server without ErrorLog: observability.ErrorLogger(...); "+
					"net/http would log client addresses unredacted", fset.Position(lit.Pos()))
			}
			return true
		})
	}
	// Anti-vacuity: the cover listener and the speedtest ingest listener.
	if servers < 2 {
		t.Fatalf("found %d http.Server literals, want at least 2", servers)
	}
}

// TestSpeedtestIngestServesTheConfiguredServer traces, inside
// startSpeedtestIngest, the one variable bound to the http.Server literal to
// the server.Serve(listener) call, so the server that serves is the one whose
// ErrorLog was configured: no second server, no reassignment, no other Serve.
func TestSpeedtestIngestServesTheConfiguredServer(t *testing.T) {
	fset := token.NewFileSet()
	// Object resolution is on (mode 0), so each *ast.Ident that names a local
	// variable carries the *ast.Object of its declaration.
	file, err := parser.ParseFile(fset, "speedtest_ingest.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "startSpeedtestIngest" && d.Recv == nil {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("startSpeedtestIngest not found in speedtest_ingest.go")
	}
	var configured *ast.Object
	var literals, bindings int
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok && isHTTPServerType(lit.Type) {
			literals++
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range assign.Rhs {
			unary, ok := rhs.(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				continue
			}
			lit, ok := unary.X.(*ast.CompositeLit)
			if !ok || !isHTTPServerType(lit.Type) || i >= len(assign.Lhs) {
				continue
			}
			id, ok := assign.Lhs[i].(*ast.Ident)
			if !ok || id.Obj == nil {
				t.Fatalf("%s: the http.Server literal is not bound to a local variable", fset.Position(lit.Pos()))
			}
			if !declaresErrorLogger(lit) {
				t.Fatalf("%s: the speedtest http.Server does not declare an ErrorLogger", fset.Position(lit.Pos()))
			}
			configured = id.Obj
			bindings++
		}
		return true
	})
	if literals != 1 || bindings != 1 || configured == nil {
		t.Fatalf("startSpeedtestIngest has %d http.Server literals and %d bindings, want exactly 1 of each",
			literals, bindings)
	}
	var assignments, serves, servesListener int
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Obj == configured {
					assignments++
				}
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(sel.Sel.Name, "Serve") && !strings.HasPrefix(sel.Sel.Name, "ListenAndServe") {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Obj != configured {
				t.Errorf("%s: %s is called on something other than the configured server",
					fset.Position(node.Pos()), sel.Sel.Name)
				return true
			}
			serves++
			if sel.Sel.Name == "Serve" && len(node.Args) == 1 {
				if arg, ok := node.Args[0].(*ast.Ident); ok && arg.Name == "listener" {
					servesListener++
				}
			}
		}
		return true
	})
	if assignments != 1 {
		t.Errorf("the configured server variable is assigned %d times, want exactly 1 (its declaration)", assignments)
	}
	if serves != 1 || servesListener != 1 {
		t.Errorf("found %d Serve calls on the configured server, %d of them Serve(listener); want exactly 1 of each",
			serves, servesListener)
	}
}

func isHTTPServerType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Server" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "http"
}

func declaresErrorLogger(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "ErrorLog" {
			continue
		}
		call, ok := kv.Value.(*ast.CallExpr)
		if !ok {
			continue
		}
		if fn, ok := call.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "ErrorLogger" {
			return true
		}
	}
	return false
}
