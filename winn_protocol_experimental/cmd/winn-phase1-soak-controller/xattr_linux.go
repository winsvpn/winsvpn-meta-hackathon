//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func listExtendedAttributesDescriptor(file *os.File) ([]string, error) {
	return listDescriptorXattrs(
		file,
		func(fd int, destination []byte) (int, error) {
			return unix.Flistxattr(fd, destination)
		},
	)
}

func hasExtendedAttributeDescriptor(
	file *os.File, attribute string,
) (bool, error) {
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in every syscall API used here.
	_, err := unix.Fgetxattr(int(file.Fd()), attribute, nil)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.ENODATA) {
		return false, nil
	}
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return false, fmt.Errorf(
			"descriptor extended-attribute inspection is unsupported: %w", err,
		)
	}
	return false, fmt.Errorf(
		"fgetxattr %s %s: %w", file.Name(), attribute, err,
	)
}
