//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func requireRunnerSeals(file *os.File) error {
	const required = unix.F_SEAL_WRITE |
		unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW |
		unix.F_SEAL_EXEC |
		unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&required != required {
		return errors.New("runner memfd seals are incomplete")
	}
	return nil
}
