//go:build !linux && winn_incomplete_e8

package main

import (
	"strings"
	"testing"
)

func TestE8SupervisorIdentityFailsClosedWithoutProcessImageProof(
	t *testing.T,
) {
	identity, err := verifyE8SupervisorIdentity(e6VerificationReceipt{
		SupervisorExecutablePath:   "/absolute/but-unproved",
		SupervisorExecutableSHA256: strings.Repeat("a", 64),
	})
	if err == nil || identity != nil {
		if identity != nil {
			_ = identity.Close()
		}
		t.Fatal("non-Linux supervisor identity was admitted")
	}
}
