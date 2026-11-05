//go:build darwin

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
	// #nosec G115 -- os.File owns a live Darwin kernel descriptor represented
	// by int; Fd widens that descriptor to uintptr.
	_, err := unix.Fgetxattr(int(file.Fd()), attribute, nil)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.ENOATTR) {
		return false, nil
	}
	if errors.Is(err, unix.ENOTSUP) {
		return false, fmt.Errorf(
			"descriptor extended-attribute inspection is unsupported: %w", err,
		)
	}
	return false, fmt.Errorf(
		"fgetxattr %s %s: %w", file.Name(), attribute, err,
	)
}
