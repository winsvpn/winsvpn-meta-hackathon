//go:build !unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireUnsupported(t *testing.T, operation string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		t.Fatalf("%s error = %v, want explicit unsupported error", operation, err)
	}
}

func TestSecureDirectoryNonUnixOperationsRefuseWithoutMutation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustNotExist := filepath.Join(root, "must-not-exist")
	directory, err := openSecureDirectory(mustNotExist)
	requireUnsupported(t, "openSecureDirectory", err)
	if directory != nil {
		t.Fatal("openSecureDirectory returned a capability on an unsupported platform")
	}

	stub := &secureDirectory{path: mustNotExist}
	_, err = stub.Open("file", os.O_CREATE|os.O_WRONLY, 0o600)
	requireUnsupported(t, "Open", err)
	_, err = stub.OpenDirectory("child")
	requireUnsupported(t, "OpenDirectory", err)
	requireUnsupported(t, "Mkdir", stub.Mkdir("child", 0o700))
	temporary, name, err := stub.Temp(0o600)
	requireUnsupported(t, "Temp", err)
	if temporary != nil || name != "" {
		t.Fatalf("Temp returned capability %v or name %q", temporary, name)
	}
	requireUnsupported(t, "Rename", stub.Rename("from", "to"))
	requireUnsupported(t, "Remove", stub.Remove("file"))
	requireUnsupported(t, "Sync", stub.Sync())
	if free, err := stub.FreeBytes(); err == nil || free != 0 {
		t.Fatalf("FreeBytes = (%d, %v), want (0, unsupported error)", free, err)
	} else {
		requireUnsupported(t, "FreeBytes", err)
	}
	if entries, err := stub.ReadDir(); err == nil || entries != nil {
		t.Fatalf("ReadDir = (%v, %v), want (nil, unsupported error)", entries, err)
	} else {
		requireUnsupported(t, "ReadDir", err)
	}
	requireUnsupported(t, "VerifyPath", stub.VerifyPath())
	requireUnsupported(
		t, "atomicWriteDirectory",
		atomicWriteDirectory(stub, "file", []byte("must not be written"), 0o600),
	)
	if err := stub.Close(); err != nil {
		t.Fatalf("cleanup-only Close returned %v", err)
	}
	if _, err := os.Lstat(mustNotExist); !os.IsNotExist(err) {
		t.Fatalf("unsupported operations mutated %s: %v", mustNotExist, err)
	}
}
