//go:build unix

package main

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// receiveDescriptor reads exactly one UDP descriptor from the control socket's
// ancillary data.
//
// This is the Android hand-off: VpnTunnelService opens the outer socket, calls
// VpnService.protect(fd) on it — without which the carrier's own traffic is
// routed back into the tunnel and loops forever — and sends the descriptor here
// over a LocalSocket with setFileDescriptorsForSend. The descriptor arrives as
// an SCM_RIGHTS control message alongside one data byte, because a control
// message cannot be sent on its own.
//
// Exactly one descriptor is accepted. More than one is refused rather than
// picked from, because silently choosing the first would leak the rest and
// would hide a host bug that matters: a second unprotected socket is precisely
// the failure this hand-off exists to prevent.
func receiveDescriptor(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("access control socket: %w", err)
	}
	data := make([]byte, 1)
	// unix.CmsgSpace(4) is the space one SCM_RIGHTS descriptor needs; room for
	// four makes an over-sending host visible instead of truncating it into
	// looking correct.
	oob := make([]byte, unix.CmsgSpace(4*4))
	var (
		dataCount int
		oobCount  int
		innerErr  error
	)
	controlErr := raw.Read(func(fd uintptr) bool {
		// #nosec G115 -- RawConn.Read hands back a live descriptor, which is
		// nonnegative and inside int range on every platform Go builds for.
		descriptor := int(fd)
		dataCount, oobCount, _, _, innerErr = unix.Recvmsg(
			descriptor, data, oob, 0,
		)
		// Returning false parks the goroutine until the socket is readable and
		// retries, which is what makes this work on a non-blocking socket.
		return !errors.Is(innerErr, unix.EAGAIN)
	})
	if controlErr != nil {
		return -1, fmt.Errorf("read control socket: %w", controlErr)
	}
	if innerErr != nil {
		return -1, fmt.Errorf("receive UDP descriptor: %w", innerErr)
	}
	if dataCount < 1 {
		return -1, errors.New(
			"control socket closed before the UDP descriptor arrived",
		)
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobCount])
	if err != nil {
		return -1, fmt.Errorf("parse control message: %w", err)
	}
	descriptors := make([]int, 0, 1)
	for _, message := range messages {
		received, err := unix.ParseUnixRights(&message)
		if err != nil {
			// Not an SCM_RIGHTS message; other control messages are not an
			// error, they are simply not what is being collected here.
			continue
		}
		descriptors = append(descriptors, received...)
	}
	if len(descriptors) == 0 {
		return -1, errors.New(
			"the control socket carried no SCM_RIGHTS descriptor; the host " +
				"must send the protected UDP socket with the first byte",
		)
	}
	if len(descriptors) > 1 {
		for _, extra := range descriptors {
			_ = unix.Close(extra)
		}
		return -1, fmt.Errorf(
			"the control socket carried %d descriptors; exactly one protected "+
				"UDP socket is expected", len(descriptors),
		)
	}
	unix.CloseOnExec(descriptors[0])
	return descriptors[0], nil
}
