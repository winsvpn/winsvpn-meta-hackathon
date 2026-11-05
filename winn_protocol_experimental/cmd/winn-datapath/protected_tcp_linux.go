//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// connectProtectedTCP consumes a host-protected, unconnected TCP descriptor.
// It never creates a replacement socket, since that socket would lack the
// Android VPN exclusion carried by this descriptor.
func connectProtectedTCP(ctx context.Context, fd int, remote *net.UDPAddr) (net.Conn, error) {
	file := os.NewFile(uintptr(fd), "winn3-protected-tcp")
	defer file.Close()
	if remote == nil || remote.IP.To4() == nil || remote.Port < 1 {
		return nil, errors.New("protected TCP needs an IPv4 gateway endpoint")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	var addr [4]byte
	copy(addr[:], remote.IP.To4())
	err := unix.Connect(fd, &unix.SockaddrInet4{Port: remote.Port, Addr: addr})
	if err != nil && !errors.Is(err, unix.EINPROGRESS) {
		return nil, err
	}
	if err != nil {
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("protected TCP connect needs a deadline")
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, context.DeadlineExceeded
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
			n, pollErr := unix.Poll(poll, int((remaining+time.Millisecond-1)/time.Millisecond))
			if errors.Is(pollErr, unix.EINTR) {
				continue
			}
			if pollErr != nil {
				return nil, pollErr
			}
			if n == 0 {
				return nil, context.DeadlineExceeded
			}
			result, sockErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if sockErr != nil {
				return nil, sockErr
			}
			if result != 0 {
				return nil, fmt.Errorf("protected TCP connect: %w", unix.Errno(result))
			}
			break
		}
	}
	return net.FileConn(file)
}
