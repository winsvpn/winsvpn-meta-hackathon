//go:build !linux

package main

import (
	"strings"
	"testing"
	"time"
)

func TestNewProductionRuntimeRefusesNonLinux(t *testing.T) {
	runtime, err := newProductionRuntime(
		t.TempDir(), "adapter", strings.Repeat("a", 64), time.Second,
	)
	if runtime != nil || err == nil {
		t.Fatalf("runtime=%v err=%v", runtime, err)
	}
	if !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("unexpected error: %v", err)
	}
}
