package realcycle

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestE3OfflineBoundaryHasNoNetworkProviderProcessOrWriteImports(t *testing.T) {
	files := []string{
		"controllerlink.go",
		"controllerintent.go",
		filepath.Join(
			"..", "..", "cmd",
			"winn-real-cycle-controller-binding", "main.go",
		),
		filepath.Join(
			"..", "..", "cmd",
			"winn-real-cycle-admitted-adapter", "main.go",
		),
	}
	for _, name := range files {
		t.Run(filepath.Base(name), func(t *testing.T) {
			parsed, err := parser.ParseFile(
				token.NewFileSet(), name, nil, 0,
			)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range parsed.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if importPath == "os/exec" ||
					importPath == "syscall" ||
					importPath == "net" ||
					strings.HasPrefix(importPath, "net/") ||
					strings.Contains(importPath, "cloud") ||
					strings.Contains(importPath, "provider") ||
					strings.Contains(importPath, "credential") {
					t.Fatalf("forbidden E3 import %q", importPath)
				}
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if !ok || identifier.Name != "os" {
					return true
				}
				switch selector.Sel.Name {
				case "WriteFile", "Create", "CreateTemp", "OpenFile",
					"Mkdir", "MkdirAll", "Remove", "RemoveAll", "Rename":
					fallthrough
				case "Chmod", "Chtimes", "Truncate":
					t.Fatalf(
						"forbidden E3 filesystem mutation call os.%s",
						selector.Sel.Name,
					)
				}
				return true
			})
		})
	}
}

func TestE3LauncherIsTheOnlyNarrowWriteExecBoundary(t *testing.T) {
	directory := filepath.Join(
		"..", "..", "cmd", "winn-real-cycle-admitted-launcher",
	)
	files := []string{
		filepath.Join(directory, "main.go"),
		filepath.Join(directory, "runtime_linux.go"),
		filepath.Join(directory, "runtime_linux_helpers.go"),
		filepath.Join(directory, "runtime_unsupported.go"),
	}
	for _, name := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if importPath == "net" ||
				strings.HasPrefix(importPath, "net/") ||
				strings.Contains(importPath, "cloud") ||
				strings.Contains(importPath, "provider") ||
				strings.Contains(importPath, "credential") {
				t.Fatalf("%s imports forbidden package %q", name, importPath)
			}
			if importPath == "os/exec" &&
				filepath.Base(name) != "runtime_linux.go" {
				t.Fatalf("%s imports os/exec outside Linux boundary", name)
			}
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(source, []byte("aicore_phase1_auto_matrix.sh")) ||
			bytes.Contains(source, []byte("WINN_SOAK_ADAPTER_MODE=run")) {
			t.Fatalf("%s contains a forbidden matrix/run-mode path", name)
		}
	}
}
