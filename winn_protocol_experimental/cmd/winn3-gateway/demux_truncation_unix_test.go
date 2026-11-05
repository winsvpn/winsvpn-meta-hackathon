//go:build !windows

package main

import (
	"net"
	"syscall"
	"testing"
)

func TestDemuxPayloadTruncatedUnixMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags int
		err   error
		want  bool
	}{
		{"ordinary", 0, nil, false},
		{"payload", syscall.MSG_TRUNC, nil, true},
		{"control-only", syscall.MSG_CTRUNC, nil, false},
		{"both-flags", syscall.MSG_TRUNC | syscall.MSG_CTRUNC, nil, true},
		{"closed-with-flag", syscall.MSG_TRUNC, net.ErrClosed, false},
		{"unrelated-error-with-flag", syscall.MSG_TRUNC, syscall.EIO, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := demuxPayloadTruncated(tc.flags, tc.err); got != tc.want {
				t.Fatalf("truncated=%v, want %v", got, tc.want)
			}
		})
	}
}
