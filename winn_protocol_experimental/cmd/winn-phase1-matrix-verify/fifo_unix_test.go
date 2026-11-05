//go:build unix

package main

import "golang.org/x/sys/unix"

// makeFIFO creates a named pipe, so a test can put a non-regular file where a
// slot member belongs. A FIFO is the useful case: os.Open on one BLOCKS until a
// writer appears, so a verifier that opened it without checking its type would
// not merely read the wrong thing — it would hang.
func makeFIFO(path string) error {
	return unix.Mkfifo(path, 0o600)
}
