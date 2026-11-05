//go:build !unix

package main

import (
	"errors"
	"os"
)

var errLockUnsupported = errors.New(
	"exclusive instance locking requires a unix platform",
)

// lockExclusiveNonBlocking refuses rather than succeeding vacuously.
//
// Returning nil here would give a platform with no lock a controller that
// believes it is the only instance. The duplicate-instance guard would then be
// a comment.
func lockExclusiveNonBlocking(*os.File) error {
	return errLockUnsupported
}

func unlockAndClose(descriptor *os.File) error {
	return descriptor.Close()
}
