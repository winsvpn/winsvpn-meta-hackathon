package decoy_test

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

// This file is the regression test for the wiring, and the wiring is where this
// bug lived. site.go can generate a million distinct cover sites and none of
// that reaches a single user if a command builds its origin without telling it
// which deployment it is.
//
// The old signature was NewOrigin(target string). Every command passed its
// -decoy-origin flag and nothing else, so every command that did not set that
// flag - which is the default, and the configuration the shipped systemd unit
// templates come up in - served the same compiled-in page as every other Winn
// gateway on the internet. Fetch "/" from one, hash it, ask any scan corpus
// which other hosts return that hash, and the answer is the fleet.
//
// So what is checked here is not that the generator varies. It is that no
// command can build a cover origin that is not seeded from its own listener:
// NewOrigin is called with a Config, the Config carries the CoverTLS the
// command actually serves, and it carries the PrivateServerName that must be
// kept out of the seed. A future listener that forgets any of that fails here
// rather than in Yangon.
//
// It follows internal/coverlisten/wiring_test.go, which exists for the same
// reason one layer down: the cover profile worked and was wired to one listener
// out of three.

// exemptCommands are commands that build a decoy origin no external prober can
// reach. Each entry needs a reason a reader can check.
//
// Adding to this map is the way to make these tests pass without seeding the
// origin, which is deliberate: it is a visible, reviewable act in a file whose
// whole subject is that omission.
var exemptCommands = map[string]string{}

const (
	decoyPackage = "decoy"
	originFunc   = "NewOrigin"
	coverPackage = "coverlisten"
	verifyFunc   = "Verify"

	coverField   = "CoverTLS"
	privateField = "PrivateServerName"
)

type originCall struct {
	position string
	fields   map[string]string
}

type commandFacts struct {
	name     string
	calls    []originCall
	verified map[string]bool
}

// TestEveryCoverOriginIsSeededFromItsOwnListener fails if any command can build
// a decoy origin that is not derived from the deployment it is running on.
func TestEveryCoverOriginIsSeededFromItsOwnListener(t *testing.T) {
	commands := scanCommands(t)
	if len(commands) == 0 {
		t.Fatal("scanned no commands; the scanner is broken, not the tree")
	}

	var builders int
	for _, command := range commands {
		if len(command.calls) == 0 {
			continue
		}
		builders++
		if reason, exempt := exemptCommands[command.name]; exempt {
			t.Logf("%s: exempt (%s)", command.name, reason)
			continue
		}
		t.Run(command.name, func(t *testing.T) {
			for _, call := range command.calls {
				cover, ok := call.fields[coverField]
				switch {
				case !ok || cover == "" || cover == "nil":
					t.Errorf(
						"%s: %s.%s at %s sets no %s.\n"+
							"Without it the built-in cover site is the same bytes on "+
							"every deployment that does not pass -decoy-origin, and one "+
							"body hash enumerates the fleet. Pass the listener "+
							"configuration this command serves.",
						command.name, decoyPackage, originFunc, call.position, coverField,
					)
				case !command.verified[cover]:
					t.Errorf(
						"%s: %s.%s at %s seeds from %q, which is never passed to "+
							"%s.%s.\n"+
							"Seed from the configuration actually on the wire, so the "+
							"page a prober gets is derived from the certificate that "+
							"same prober was handed.",
						command.name, decoyPackage, originFunc, call.position, cover,
						coverPackage, verifyFunc,
					)
				}
				if private, ok := call.fields[privateField]; !ok || private == "" ||
					private == `""` {
					t.Errorf(
						"%s: %s.%s at %s sets no %s.\n"+
							"It is the exclusion that keeps the derivation safe: on the "+
							"lab path the cover profile serves the Winn leaf, whose DNS "+
							"name is the private ECH-inner name, and seeding the public "+
							"page from it would put a function of that name on the wire.",
						command.name, decoyPackage, originFunc, call.position, privateField,
					)
				}
			}
		})
	}
	if builders < 3 {
		t.Fatalf(
			"found only %d command(s) building a cover origin; winn-server, "+
				"winn-token-issuer and winn-carrier-server are all expected, so the "+
				"scanner has stopped seeing them and this test has stopped protecting "+
				"anything",
			builders,
		)
	}
}

// TestKnownReachableCommandsAreNotExempt pins the three listeners this work was
// about. Exempting one later would silently disable the check above for it.
func TestKnownReachableCommandsAreNotExempt(t *testing.T) {
	for _, name := range []string{
		"winn-server", "winn-token-issuer", "winn-carrier-server",
	} {
		if reason, exempt := exemptCommands[name]; exempt {
			t.Errorf(
				"%s is exempt (%q), but it binds a public address in deploy/systemd "+
					"and is exactly the endpoint a prober fetches a page from",
				name, reason,
			)
		}
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
	facts := commandFacts{name: name, verified: map[string]bool{}}
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
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				function, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				receiver, ok := function.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch {
				case receiver.Name == decoyPackage && function.Sel.Name == originFunc:
					facts.calls = append(facts.calls, originCall{
						position: fileSet.Position(call.Pos()).String(),
						fields:   configFields(call.Args),
					})
				case receiver.Name == coverPackage && function.Sel.Name == verifyFunc:
					for _, argument := range call.Args {
						facts.verified[exprString(argument)] = true
					}
				}
				return true
			})
		}
	}
	return facts
}

// configFields reads the decoy.Config literal a NewOrigin call was given. A
// call whose argument is anything other than a literal - a variable built
// elsewhere, a helper's return value - yields no fields and therefore fails,
// which is the intended behaviour: this test can only certify wiring it can
// see.
func configFields(arguments []ast.Expr) map[string]string {
	fields := map[string]string{}
	if len(arguments) != 1 {
		return fields
	}
	literal, ok := arguments[0].(*ast.CompositeLit)
	if !ok {
		return fields
	}
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := pair.Key.(*ast.Ident)
		if !ok {
			continue
		}
		fields[key.Name] = exprString(pair.Value)
	}
	return fields
}

// exprString renders the expressions this scanner cares about - plain
// identifiers and simple selectors - and refuses anything else, so a value
// built by an expression too complicated to match cannot pass by being
// unrecognised.
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
