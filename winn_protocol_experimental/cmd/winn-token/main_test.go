package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTokenOutputPathsPreserveSingleOutputCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	paths, err := tokenOutputPaths(path, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != path {
		t.Fatalf("single token outputs = %#v", paths)
	}
}

func TestTokenOutputPathsCreateDeterministicBatch(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "tokens")
	paths, err := tokenOutputPaths("", directory, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(directory, "token-000001.json"),
		filepath.Join(directory, "token-000002.json"),
		filepath.Join(directory, "token-000003.json"),
	}
	for index := range want {
		if paths[index] != want[index] {
			t.Fatalf("batch outputs = %#v, want %#v", paths, want)
		}
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("batch directory mode = %04o", info.Mode().Perm())
	}
}

func TestTokenOutputPathsRejectUnsafeBatchShapes(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		output string
		dir    string
		count  int
	}{
		{"", "", 1},
		{"token.json", directory, 1},
		{"token.json", "", 2},
		{"", directory, 0},
		{"", directory, 8193},
	} {
		if _, err := tokenOutputPaths(
			test.output, test.dir, test.count,
		); err == nil {
			t.Fatalf("unsafe output shape accepted: %#v", test)
		}
	}
	existing := filepath.Join(directory, "existing.json")
	if err := os.WriteFile(existing, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tokenOutputPaths(existing, "", 1); err == nil {
		t.Fatal("existing token output was accepted")
	}
}
