//go:build unix

package main

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Marker 1 carries UDP plus a separate request channel. The engine requests a
// freshly protected TCP socket on that channel for every dial.
func receiveV3Descriptors(conn *net.UnixConn) (udp, tcp, channel int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, -1, -1, fmt.Errorf("access control socket: %w", err)
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4*4))
	var dataCount, oobCount, flags int
	var innerErr error
	err = raw.Read(func(fd uintptr) bool {
		dataCount, oobCount, flags, _, innerErr = unix.Recvmsg(int(fd), data, oob, 0)
		return !errors.Is(innerErr, unix.EAGAIN)
	})
	if err != nil {
		return -1, -1, -1, fmt.Errorf("read control socket: %w", err)
	}
	if innerErr != nil {
		return -1, -1, -1, fmt.Errorf("receive v3 descriptors: %w", innerErr)
	}
	if dataCount != 1 {
		return -1, -1, -1, errors.New("control socket closed before the v3 descriptors arrived")
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobCount])
	if err != nil {
		return -1, -1, -1, fmt.Errorf("parse v3 control message: %w", err)
	}
	var fds []int
	for _, message := range messages {
		rights, parseErr := unix.ParseUnixRights(&message)
		if parseErr == nil {
			fds = append(fds, rights...)
		}
	}
	if flags&unix.MSG_CTRUNC != 0 || len(fds) < 1 || len(fds) > 2 || (data[0] != 0 && data[0] != 1) || (data[0] == 1 && len(fds) != 2) {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return -1, -1, -1, fmt.Errorf("invalid v3 descriptor handoff marker %d with %d descriptors", data[0], len(fds))
	}
	unix.CloseOnExec(fds[0])
	if len(fds) == 1 {
		return fds[0], -1, -1, nil
	}
	unix.CloseOnExec(fds[1])
	if data[0] == 1 {
		return fds[0], -1, fds[1], nil
	}
	return fds[0], fds[1], -1, nil
}
