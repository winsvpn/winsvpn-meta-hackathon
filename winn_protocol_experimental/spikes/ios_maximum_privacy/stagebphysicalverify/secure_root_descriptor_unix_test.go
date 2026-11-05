//go:build darwin || linux

package main

import "testing"

func TestUnixDescriptorConversionsRejectInvalidValues(t *testing.T) {
	if descriptor, err := unixDescriptor(0); err != nil || descriptor != 0 {
		t.Fatalf("zero descriptor = %d, %v", descriptor, err)
	}
	if _, err := unixDescriptor(^uintptr(0)); err == nil {
		t.Fatal("out-of-range descriptor was accepted")
	}
	if file, err := ownUnixDescriptor(-1, "invalid"); err == nil || file != nil {
		t.Fatalf("negative descriptor ownership = %v, %v", file, err)
	}
}
