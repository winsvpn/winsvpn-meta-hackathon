//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

func openRegularNoFollow(path string, flags int, permission os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(
		path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, uint32(permission.Perm()),
	)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- syscall.Open returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("adopt descriptor for %s", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	identity, err := identityFromInfo(info)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if identity.nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf(
			"%s has %d hard links; exclusive file identity requires exactly one",
			path, identity.nlink,
		)
	}
	return file, nil
}
