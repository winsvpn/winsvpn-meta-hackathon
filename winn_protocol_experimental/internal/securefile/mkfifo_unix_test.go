//go:build unix

package securefile

import "syscall"

func makeTestFIFO(path string, mode uint32) error {
	return syscall.Mkfifo(path, mode)
}
