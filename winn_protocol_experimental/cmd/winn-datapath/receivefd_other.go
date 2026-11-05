//go:build !unix

package main

import (
	"errors"
	"net"
)

// receiveDescriptor is unavailable off unix. SCM_RIGHTS is a unix-domain
// mechanism; Windows has no equivalent on this socket type.
//
// This is not a gap in the Windows path. The plan's socket rule assigns Windows
// route-based or split-tunnel exclusion rather than descriptor protection, so a
// Windows host runs this binary with -transport stdio and lets the engine open
// its own socket via allow_own_socket, or inherits one and names it with
// -udp-fd.
func receiveDescriptor(*net.UnixConn) (int, error) {
	return -1, errors.New(
		"receiving a UDP descriptor over a control socket needs SCM_RIGHTS, " +
			"which is unix-only; on this platform use -udp-fd, or set " +
			"allow_own_socket in the datapath configuration",
	)
}

func receiveV3Descriptors(*net.UnixConn) (int, int, int, error) {
	return -1, -1, -1, errors.New("v3 descriptor handoff needs a unix control socket")
}
