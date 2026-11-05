package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAugmentBOMAddsEmbeddedForkAndDependencyEdges(t *testing.T) {
	sourceRoot := makeForkFixture(t)
	input := []byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {"bom-ref": "root"}},
	  "components": [
	    {"bom-ref": "httpsfv", "name": "github.com/dunglas/httpsfv"},
	    {"bom-ref": "quic-go", "name": "github.com/quic-go/quic-go"},
	    {"bom-ref": "uritemplate", "name": "github.com/yosida95/uritemplate/v3"}
	  ],
	  "dependencies": [{"ref": "root", "dependsOn": ["quic-go"]}]
	}`)

	output, err := augmentBOM(input, sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]any
	if err := json.Unmarshal(output, &bom); err != nil {
		t.Fatal(err)
	}
	components, err := objectArray(bom, "components")
	if err != nil {
		t.Fatal(err)
	}
	foundFork := false
	for _, component := range components {
		if component["bom-ref"] == forkReference {
			foundFork = true
		}
	}
	if !foundFork {
		t.Fatal("embedded MASQUE fork component is absent")
	}
	dependencies, err := objectArray(bom, "dependencies")
	if err != nil {
		t.Fatal(err)
	}
	for _, dependency := range dependencies {
		dependsOn, err := stringArray(dependency, "dependsOn")
		if err != nil {
			t.Fatal(err)
		}
		switch dependency["ref"] {
		case "root":
			if !slices.Contains(dependsOn, forkReference) {
				t.Fatal("root does not depend on embedded MASQUE fork")
			}
		case forkReference:
			want := []string{"httpsfv", "quic-go", "uritemplate"}
			if !slices.Equal(dependsOn, want) {
				t.Fatalf("fork dependencies = %v, want %v", dependsOn, want)
			}
		}
	}
}

func TestAugmentBOMRejectsDuplicateFork(t *testing.T) {
	sourceRoot := makeForkFixture(t)
	input := []byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {"bom-ref": "root"}},
	  "components": [{"bom-ref": "` + forkReference + `", "name": "masque-go"}],
	  "dependencies": [{"ref": "root"}]
	}`)
	if _, err := augmentBOM(input, sourceRoot); err == nil {
		t.Fatal("duplicate embedded fork was accepted")
	}
}

func TestForkSourceDigestIgnoresAppleDoubleGoFiles(t *testing.T) {
	sourceRoot := makeForkFixture(t)
	digestWithout, countWithout, err := forkSourceDigest(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	apple := filepath.Join(sourceRoot, "internal", "masque", "._conn.go")
	if err := os.WriteFile(apple, []byte("NOT SOURCE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digestWith, countWith, err := forkSourceDigest(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if countWith != countWithout {
		t.Fatalf("source-file-count with AppleDouble = %d, without = %d", countWith, countWithout)
	}
	if digestWith != digestWithout {
		t.Fatal("digest changed when AppleDouble ._conn.go was added")
	}
}

func TestAugmentBOMRejectsEmptyDependencyBomRef(t *testing.T) {
	sourceRoot := makeForkFixture(t)
	input := []byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {"bom-ref": "root"}},
	  "components": [
	    {"name": "github.com/dunglas/httpsfv"},
	    {"bom-ref": "quic-go", "name": "github.com/quic-go/quic-go"},
	    {"bom-ref": "uritemplate", "name": "github.com/yosida95/uritemplate/v3"}
	  ],
	  "dependencies": [{"ref": "root"}]
	}`)
	if _, err := augmentBOM(input, sourceRoot); err == nil {
		t.Fatal("empty bom-ref on required fork dependency was accepted")
	} else if !strings.Contains(err.Error(), "empty bom-ref") {
		t.Fatalf("error = %q, want substring %q", err.Error(), "empty bom-ref")
	}
}

func TestAugmentFileRewritesBOMInPlace(t *testing.T) {
	sourceRoot := makeForkFixture(t)
	dir := t.TempDir()
	bomPath := filepath.Join(dir, "bom.json")
	input := []byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {"bom-ref": "root"}},
	  "components": [
	    {"bom-ref": "httpsfv", "name": "github.com/dunglas/httpsfv"},
	    {"bom-ref": "quic-go", "name": "github.com/quic-go/quic-go"},
	    {"bom-ref": "uritemplate", "name": "github.com/yosida95/uritemplate/v3"}
	  ],
	  "dependencies": [{"ref": "root", "dependsOn": ["quic-go"]}]
	}`)
	if err := os.WriteFile(bomPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := augmentFile(bomPath, sourceRoot); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(bomPath)
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]any
	if err := json.Unmarshal(output, &bom); err != nil {
		t.Fatal(err)
	}
	components, err := objectArray(bom, "components")
	if err != nil {
		t.Fatal(err)
	}
	foundFork := false
	for _, component := range components {
		if component["bom-ref"] == forkReference {
			foundFork = true
		}
	}
	if !foundFork {
		t.Fatal("embedded MASQUE fork component is absent after augmentFile")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".winn-sbom-augment-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func makeForkFixture(t *testing.T) string {
	t.Helper()
	sourceRoot := t.TempDir()
	forkRoot := filepath.Join(sourceRoot, "internal", "masque")
	if err := os.MkdirAll(forkRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"conn.go":            "package masque\n",
		"LICENSE":            "MIT\n",
		"UPSTREAM.md":        "provenance\n",
		"UPSTREAM_README.md": "upstream\n",
	} {
		if err := os.WriteFile(filepath.Join(forkRoot, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return sourceRoot
}
