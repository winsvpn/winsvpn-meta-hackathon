//go:build !windows

package replaystore

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isTransientSpace(err error) bool {
	return errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT)
}
