//go:build !windows

package main

import "syscall"

func demuxPayloadTruncated(flags int, err error) bool {
	return err == nil && flags&syscall.MSG_TRUNC != 0
}
