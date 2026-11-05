package main

import (
	_ "embed"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

//go:embed main_other.go
var unsupportedPlatformSource []byte

func TestUnsupportedPlatformProductionMainWiringIsExact(t *testing.T) {
	t.Parallel()
	file, err := parser.ParseFile(
		token.NewFileSet(), "main_other.go", unsupportedPlatformSource, 0,
	)
	if err != nil {
		t.Fatalf("parse embedded non-Unix production source: %v", err)
	}
	if !importsStandardOSAsOS(file) {
		t.Fatal("non-Unix production source must import the standard os package as os")
	}

	var mainDecl *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "main" {
			continue
		}
		if mainDecl != nil {
			t.Fatal("non-Unix production source contains multiple main functions")
		}
		mainDecl = function
	}
	if mainDecl == nil || mainDecl.Recv != nil ||
		len(mainDecl.Type.Params.List) != 0 ||
		(mainDecl.Type.Results != nil && len(mainDecl.Type.Results.List) != 0) ||
		mainDecl.Body == nil || len(mainDecl.Body.List) != 1 {
		t.Fatal("non-Unix production main must have no parameters or results and one statement")
	}

	statement, ok := mainDecl.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatal("non-Unix production main statement must be an expression")
	}
	exitCall, ok := statement.X.(*ast.CallExpr)
	if !ok || exitCall.Ellipsis.IsValid() || len(exitCall.Args) != 1 ||
		!isSelector(exitCall.Fun, "os", "Exit") {
		t.Fatal("non-Unix production main must call os.Exit with one argument")
	}
	runCall, ok := exitCall.Args[0].(*ast.CallExpr)
	if !ok || runCall.Ellipsis.IsValid() || len(runCall.Args) != 1 ||
		!isIdentifier(runCall.Fun, "runUnsupportedPlatform") ||
		!isSelector(runCall.Args[0], "os", "Stderr") {
		t.Fatal(
			"non-Unix production main must call " +
				"os.Exit(runUnsupportedPlatform(os.Stderr))",
		)
	}
}

func isIdentifier(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func isSelector(expression ast.Expr, receiver, name string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && isIdentifier(selector.X, receiver) && selector.Sel.Name == name
}

func importsStandardOSAsOS(file *ast.File) bool {
	found := false
	for _, specification := range file.Imports {
		path, err := strconv.Unquote(specification.Path.Value)
		if err != nil {
			return false
		}
		name := ""
		if specification.Name != nil {
			name = specification.Name.Name
		}
		if name == "os" && path != "os" {
			return false
		}
		if path == "os" {
			if name != "" && name != "os" {
				return false
			}
			found = true
		}
	}
	return found
}
