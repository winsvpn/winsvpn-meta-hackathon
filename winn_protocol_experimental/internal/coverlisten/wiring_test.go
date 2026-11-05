package coverlisten_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file is the regression test for the bug that produced the cover
// certificate release blocker, and the bug is not "the cover profile does not
// work". The cover profile worked. internal/tlsconfig/cover_test.go proved it
// worked, against a real prober, on the day it was written.
//
// The bug is that it was wired to one listener out of three. winn-server and
// winn-token-issuer both bind 0.0.0.0 in the shipped systemd unit templates,
// both request a client certificate unconditionally, and neither applied the
// cover profile - so each of them handed every prober a CertificateRequest
// naming the Winn CA and a leaf certificate issued by it, while the tree
// contained a tested, working defence against exactly that.
//
// A test that the mechanism works in isolation cannot catch that, and did not.
// These tests check the wiring instead: that every command which serves TLS
// where a censor can reach it builds its listener configuration through
// coverlisten.Apply, verifies it through coverlisten.Verify, and serves the
// identifier it verified. A future listener that skips any of the three fails
// here rather than in Yangon.

// exemptCommands are commands that construct a TLS server which no external
// prober can reach. Each entry needs a reason, and the reason has to be
// something a reader can check.
//
// Adding to this map is the way to make these tests pass without wiring up a
// cover profile, which is deliberate: it is a visible, reviewable act in a
// file whose whole subject is that omission, rather than a silent absence in
// somebody else's main().
var exemptCommands = map[string]string{
	"winn-phase1-conservation-smoke": "in-process evidence harness; its H2 " +
		"listener binds 127.0.0.1:0 and its H3 listener is a local packet " +
		"conn, both created and torn down inside a single run to drive the " +
		"real carrier handlers. It is never deployed and never reachable.",
	"winn3-labrig": "one-session lab rig; its own package doc says it is not " +
		"a gateway, has no admission policy, and is never deployed.",
	"winn-carrier-client": "client; it dials, it does not serve a reachable listener.",
	"winn-datapath": "shipping client; ListenUDP in winn3_device_loopback.go " +
		"is a 127.0.0.1 inner-packet seam, not a public cover port.",
	"winn-aicore-directawg-e2e": "in-process e2e harness, never deployed.",
	"winn-h3-e2e": "Linux e2e harness; ListenUDP is a local DNS/canary socket, never deployed.",
	"winn-teardown-e2e": "Linux e2e harness, never deployed.",
}

const (
	coverPackage = "coverlisten"
	applyFunc    = "Apply"
	verifyFunc   = "Verify"
)

// tlsServerFields are the struct fields through which a *tls.Config becomes a
// listening server's configuration. Client-side fields (TLSClientConfig) are
// deliberately absent: a client config discloses nothing to a prober.
var tlsServerFields = map[string]bool{
	"TLSConfig": true,
}

type commandFacts struct {
	name          string
	dir           string
	servedConfigs []servedConfig
	verified      map[string]bool
	callsApply    bool
	listensUDP    bool
}

type servedConfig struct {
	expression string
	position   string
}

// TestEveryReachableTLSListenerIsBuiltThroughCoverlisten fails if any command
// can be started with a TLS listener that did not come from coverlisten.Apply.
func TestEveryReachableTLSListenerIsBuiltThroughCoverlisten(t *testing.T) {
	commands := scanCommands(t)
	if len(commands) == 0 {
		t.Fatal("scanned no commands; the scanner is broken, not the tree")
	}

	var servers int
	for _, command := range commands {
		reachable := len(command.servedConfigs) > 0 || command.listensUDP
		if !reachable {
			continue
		}
		if reason, exempt := exemptCommands[command.name]; exempt {
			t.Logf("%s: exempt (%s)", command.name, reason)
			continue
		}
		servers++
		t.Run(command.name, func(t *testing.T) {
			if !command.callsApply {
				t.Fatalf(
					"%s serves TLS or binds UDP but never calls %s.%s.\n"+
						"Every listener a prober can reach must present the cover "+
						"profile: no CertificateRequest, no pinned group or version "+
						"set, and a certificate whose issuer does not name the Winn "+
						"CA. A UDP-only bind that never answers is the probe-resistant-"+
						"proxy fingerprint this check exists to refuse. Build the "+
						"listener with %s.%s, or add %s to exemptCommands with a "+
						"reason a reader can check.",
					command.name, coverPackage, applyFunc,
					coverPackage, applyFunc, command.name,
				)
			}
			for _, served := range command.servedConfigs {
				if !command.verified[served.expression] {
					t.Errorf(
						"%s: serves TLSConfig %q at %s, which is never passed to "+
							"%s.%s.\n"+
							"Serve the configuration that was verified, so the "+
							"runtime gate covers the configuration actually on the "+
							"wire.",
						command.name, served.expression, served.position,
						coverPackage, verifyFunc,
					)
				}
			}
		})
	}
	if servers < 4 {
		t.Fatalf(
			"found only %d command(s) serving TLS or binding a non-exempt UDP "+
				"socket; winn-server, winn-token-issuer, winn-carrier-server and "+
				"winn3-gateway are all expected, so the scanner has stopped seeing "+
				"them and this test has stopped protecting anything",
			servers,
		)
	}
}

// TestKnownReachableCommandsAreNotExempt pins the three listeners this work
// was about. Exempting one of them later would silently disable the check
// above for it; this test makes that a failure rather than a green run.
func TestKnownReachableCommandsAreNotExempt(t *testing.T) {
	for _, name := range []string{
		"winn-server", "winn-token-issuer", "winn-carrier-server", "winn3-gateway",
	} {
		if reason, exempt := exemptCommands[name]; exempt {
			t.Errorf(
				"%s is exempt (%q), but it binds a public address in "+
					"deploy/systemd and is exactly the listener a prober reaches",
				name, reason,
			)
		}
	}
}

// TestWinn3GatewayCannotSkipCoverlisten is the regression for the bug that
// shipped this binary uncovered: the scanner keyed only on a TLSConfig struct
// field, so a UDP-only listener was invisible and the suite stayed green.
func TestWinn3GatewayCannotSkipCoverlisten(t *testing.T) {
	var gw *commandFacts
	commands := scanCommands(t)
	for i := range commands {
		if commands[i].name == "winn3-gateway" {
			gw = &commands[i]
			break
		}
	}
	if gw == nil {
		t.Fatal("scanner did not see cmd/winn3-gateway; it cannot protect it")
	}
	if !gw.listensUDP {
		t.Fatal("scanner does not see net.ListenUDP in winn3-gateway; a UDP-only " +
			"listener would stay green the way this binary originally shipped")
	}
	if !gw.callsApply {
		t.Fatal("winn3-gateway does not call coverlisten.Apply")
	}
	if len(gw.servedConfigs) == 0 {
		t.Fatal("winn3-gateway serves no TLSConfig; the cover listener is missing")
	}
}

// TestAUDPOnlyCommandWithoutApplyIsAScannerFailure is the deliberate break:
// a command that only binds UDP and never calls Apply must be a failure
// predicate, or the ListenUDP extension has no teeth.
func TestAUDPOnlyCommandWithoutApplyIsAScannerFailure(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n" +
		"import \"net\"\n" +
		"func main() { _, _ = net.ListenUDP(\"udp4\", nil) }\n"
	if err := os.WriteFile(dir+"/main.go", []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	facts := scanCommand(t, "synthetic-udp-gateway", dir)
	if !facts.listensUDP {
		t.Fatal("scanner missed net.ListenUDP; the UDP-only extension is a zero-clause")
	}
	if facts.callsApply {
		t.Fatal("synthetic command must not call Apply")
	}
	if len(facts.servedConfigs) != 0 {
		t.Fatalf("synthetic command has TLSConfig fields %v; it must be UDP-only", facts.servedConfigs)
	}
	// This is the predicate TestEveryReachableTLSListenerIsBuiltThroughCoverlisten
	// uses. If it is not true here, a UDP-only listener still ships green.
	if facts.callsApply || !facts.listensUDP {
		t.Fatal("failure predicate did not fire for a UDP-only command with no Apply")
	}
}


func scanCommands(t *testing.T) []commandFacts {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "cmd"))
	if err != nil {
		t.Fatalf("resolve cmd directory: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read cmd directory: %v", err)
	}
	var commands []commandFacts
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		commands = append(commands, scanCommand(t, entry.Name(), filepath.Join(root, entry.Name())))
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].name < commands[j].name })
	return commands
}

func scanCommand(t *testing.T, name, dir string) commandFacts {
	t.Helper()
	facts := commandFacts{name: name, dir: dir, verified: map[string]bool{}}
	fileSet := token.NewFileSet()
	packages, err := parser.ParseDir(fileSet, dir, func(info os.FileInfo) bool {
		// Test files are not part of what ships. Names beginning with "." or
		// "_" are ignored by the go tool itself, which is what makes the
		// AppleDouble "._main.go" resource forks littered through this tree
		// invisible to a build and unparseable here.
		name := info.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return false
		}
		return !strings.HasSuffix(name, "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.CompositeLit:
					for _, element := range typed.Elts {
						pair, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := pair.Key.(*ast.Ident)
						if !ok || !tlsServerFields[key.Name] {
							continue
						}
						facts.servedConfigs = append(facts.servedConfigs, servedConfig{
							expression: exprString(pair.Value),
							position:   fileSet.Position(pair.Pos()).String(),
						})
					}
				case *ast.CallExpr:
					function, ok := typed.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					receiver, ok := function.X.(*ast.Ident)
					if !ok {
						return true
					}
					if receiver.Name == "net" && function.Sel.Name == "ListenUDP" {
						facts.listensUDP = true
						return true
					}
					if receiver.Name != coverPackage {
						return true
					}
					switch function.Sel.Name {
					case applyFunc:
						facts.callsApply = true
					case verifyFunc:
						for _, argument := range typed.Args {
							facts.verified[exprString(argument)] = true
						}
					}
				}
				return true
			})
		}
	}
	return facts
}

// exprString renders the expressions this scanner cares about - plain
// identifiers and simple selectors - and refuses anything else, so a listener
// configuration built by an expression too complicated to match cannot pass by
// being unrecognised.
func exprString(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return exprString(typed.X) + "." + typed.Sel.Name
	default:
		return "<unrecognised expression>"
	}
}
