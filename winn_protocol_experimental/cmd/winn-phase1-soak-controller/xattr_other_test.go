//go:build !unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDescriptorXattrsNonUnixRefuse(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "held-file")
	if err := os.WriteFile(path, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if names, err := listExtendedAttributesDescriptor(file); err == nil || names != nil {
		t.Fatalf(
			"listExtendedAttributesDescriptor = (%v, %v), want (nil, error)",
			names, err,
		)
	}
	if present, err := hasExtendedAttributeDescriptor(file, "quarantine"); err == nil ||
		present {
		t.Fatalf(
			"hasExtendedAttributeDescriptor = (%v, %v), want (false, error)",
			present, err,
		)
	}
	if isExtendedAttributeUnsupported(errors.New("synthetic unsupported")) {
		t.Fatal("non-Unix xattr classifier converted an arbitrary error to success")
	}
}
