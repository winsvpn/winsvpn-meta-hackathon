//go:build !linux

package directawg

import (
	"context"
	"errors"
	"testing"
)

func TestLinuxUnderlayPolicyAnchorUnsupportedOffLinux(t *testing.T) {
	factory := &LinuxNftResolvedPolicyFactory{}
	_, err := factory.PrepareUnderlayPolicyAnchor(
		context.Background(),
		LinuxUnderlayPolicyAnchorSpec{},
	)
	if !errors.Is(err, ErrLinuxPolicyAnchorUnsupported) {
		t.Fatalf("unsupported anchor error = %v", err)
	}
}
