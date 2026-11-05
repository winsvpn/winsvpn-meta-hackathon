//go:build !linux && winn_incomplete_e8

package main

import (
	"errors"
	"os"
)

func e8FileObjectIdentity(os.FileInfo) (uint64, uint64, bool) {
	return 0, 0, false
}

// verifyE8SupervisorIdentity is unavailable off Linux: the kernel
// process-image descriptor binding required by E8 has no equivalent proved by
// this tranche, so every other platform fails closed.
func verifyE8SupervisorIdentity(
	e6VerificationReceipt,
) (*e8SupervisorIdentity, error) {
	return nil, errors.New(
		"E8 supervisor identity verification requires Linux process-image proof",
	)
}
