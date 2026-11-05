//go:build !linux

package h3candidate

import (
	"errors"
	"testing"
)

func TestLinuxProtectedUnderlayConstructorIsGated(t *testing.T) {
	_, err := NewLinuxProtectedUnderlayFactory(
		LinuxProtectedUnderlayConfig{},
	)
	if !errors.Is(err, ErrLinuxAdaptersUnsupported) {
		t.Fatalf("constructor error = %v, want unsupported", err)
	}
}
