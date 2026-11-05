//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockExclusiveNonBlocking takes an exclusive advisory lock on an open
// descriptor.
//
// flock on a descriptor, rather than a pid file: the kernel releases it when
// the process dies, however it dies. A pid-file lock survives a SIGKILL and
// then has to be reasoned about -- is that pid still alive, was it recycled --
// and that reasoning is exactly what makes a duplicate-instance guard fail
// open after a crash, on the one occasion it was needed.
func lockExclusiveNonBlocking(descriptor *os.File) error {
	// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
	err := syscall.Flock(int(descriptor.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return errLockHeld
	}
	return fmt.Errorf("lock %s: %w", descriptor.Name(), err)
}

func unlockAndClose(descriptor *os.File) error {
	// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
	unlockErr := syscall.Flock(int(descriptor.Fd()), syscall.LOCK_UN)
	closeErr := descriptor.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close lock: %w", closeErr)
	}
	return nil
}
