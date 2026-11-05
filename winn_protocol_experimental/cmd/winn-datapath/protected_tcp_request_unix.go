//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// requestTCPDescriptor uses a separate Unix socket so the frame reader never
// races an SCM_RIGHTS receive. One request obtains one new protected socket.
func (s *winn3FrameServer) requestTCPDescriptor(ctx context.Context) (int, error) {
	s.tcpRequestMu.Lock()
	defer s.tcpRequestMu.Unlock()
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	if s.tcpChannel == nil {
		return -1, errors.New("protected TCP request channel is unavailable")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return -1, errors.New("protected TCP request needs a deadline")
	}
	if err := s.tcpChannel.SetDeadline(deadline); err != nil {
		return -1, err
	}
	defer s.tcpChannel.SetDeadline(time.Time{})
	if _, err := s.tcpChannel.Write([]byte{1}); err != nil {
		_ = s.tcpChannel.Close()
		return -1, fmt.Errorf("request protected TCP socket: %w", err)
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, err := s.tcpChannel.ReadMsgUnix(data, oob)
	if err != nil {
		// A late reply must never be consumed as the next dial's descriptor.
		_ = s.tcpChannel.Close()
		return -1, fmt.Errorf("receive protected TCP socket: %w", err)
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		_ = s.tcpChannel.Close()
		return -1, fmt.Errorf("parse protected TCP socket: %w", err)
	}
	var fds []int
	for _, message := range messages {
		rights, parseErr := unix.ParseUnixRights(&message)
		if parseErr == nil {
			fds = append(fds, rights...)
		}
	}
	if n != 1 || data[0] != 1 || flags&unix.MSG_CTRUNC != 0 || len(fds) != 1 {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		_ = s.tcpChannel.Close()
		return -1, errors.New("host did not supply exactly one protected TCP socket")
	}
	kind, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_STREAM {
		_ = unix.Close(fds[0])
		_ = s.tcpChannel.Close()
		return -1, errors.New("host supplied a non-stream protected TCP descriptor")
	}
	addr, addrErr := unix.Getsockname(fds[0])
	_, isIPv4 := addr.(*unix.SockaddrInet4)
	if addrErr != nil || !isIPv4 {
		_ = unix.Close(fds[0])
		_ = s.tcpChannel.Close()
		return -1, errors.New("host supplied a non-IPv4 protected TCP descriptor")
	}
	unix.CloseOnExec(fds[0])
	return fds[0], nil
}
