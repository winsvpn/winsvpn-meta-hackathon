//go:build windows

package replaystore

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isTransientSpace(err error) bool {
	return errors.Is(err, windows.ERROR_DISK_FULL)
}
