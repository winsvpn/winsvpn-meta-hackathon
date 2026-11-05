//go:build windows

package main

import (
	"fmt"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDemuxPayloadTruncatedWindowsMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags int
		err   error
		want  bool
	}{
		{"ordinary", 0, nil, false},
		{"payload-flag", windows.MSG_TRUNC, nil, true},
		{"control-only", windows.MSG_CTRUNC, nil, false},
		{"message-size", 0, windows.WSAEMSGSIZE, true},
		{"wrapped-message-size", 0, fmt.Errorf("read: %w", windows.WSAEMSGSIZE), true},
		{"closed-with-flag", windows.MSG_TRUNC, net.ErrClosed, false},
		{"unrelated-error-with-flag", windows.MSG_TRUNC, windows.WSAEINVAL, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := demuxPayloadTruncated(tc.flags, tc.err); got != tc.want {
				t.Fatalf("truncated=%v, want %v", got, tc.want)
			}
		})
	}
}
