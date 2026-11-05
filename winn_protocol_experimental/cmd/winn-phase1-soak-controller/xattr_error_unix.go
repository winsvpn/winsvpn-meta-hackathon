//go:build unix

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isExtendedAttributeUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP)
}
