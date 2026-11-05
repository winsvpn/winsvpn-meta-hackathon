//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

func demuxPayloadTruncated(flags int, err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE) || err == nil && flags&windows.MSG_TRUNC != 0
}
