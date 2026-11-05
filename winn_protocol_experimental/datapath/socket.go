package datapath

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// ErrDeadlineExceeded is what ReadOutboundTimeout returns on expiry. It IS
// os.ErrDeadlineExceeded, so errors.Is against either sentinel matches; it is
// re-exported so a caller does not have to import os to classify a timeout.
var ErrDeadlineExceeded = os.ErrDeadlineExceeded

// descriptorAdopted counts successful adoptions. It exists so a test can prove
// which branch Open took without reaching into unexported connection state.
var descriptorAdopted = func() {}

// adoptUDPDescriptor takes ownership of a caller-supplied UDP descriptor and
// returns a net.PacketConn over it.
//
// OWNERSHIP. os.NewFile takes the descriptor; net.FilePacketConn then
// duplicates it and returns a connection over the duplicate. Closing the
// os.File therefore closes the ORIGINAL descriptor, completing the transfer,
// while the returned connection keeps its own duplicate. That is the whole
// ownership story, and it is why Close on the Engine is sufficient to release
// the host's descriptor: the host must not close it again.
//
// PLATFORMS. This is net.FilePacketConn, not a syscall of ours, so it is
// available wherever the standard library implements it: unix (linux, darwin,
// ios, android) via dup(2), and windows via WSADuplicateSocket. There is no
// build tag here and no per-platform code, which is the point.
func adoptUDPDescriptor(fd int) (net.PacketConn, error) {
	if fd < 0 {
		return nil, errors.New("winn datapath UDP descriptor is negative")
	}
	file := os.NewFile(uintptr(fd), "winn-datapath-udp")
	if file == nil {
		return nil, fmt.Errorf(
			"winn datapath UDP descriptor %d is not a valid file descriptor",
			fd,
		)
	}
	conn, err := net.FilePacketConn(file)
	// The duplicate inside conn is what the engine uses from here on, so the
	// original is closed either way: on success to complete the ownership
	// transfer, on failure so a rejected descriptor is not leaked.
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf(
			"winn datapath adopt UDP descriptor %d: %w", fd, err,
		)
	}
	if closeErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf(
			"winn datapath release adopted UDP descriptor %d: %w",
			fd, closeErr,
		)
	}
	if _, ok := conn.(*net.UDPConn); !ok {
		_ = conn.Close()
		return nil, fmt.Errorf(
			"winn datapath descriptor %d is not a UDP socket (%T)", fd, conn,
		)
	}
	descriptorAdopted()
	return conn, nil
}

// adoptStreamDescriptor is adoptUDPDescriptor for a CONNECTED TCP socket, which
// is what the HTTP/2 carrier rides. Everything about ownership, the dup inside
// net.FileConn, and platform coverage is identical; see adoptUDPDescriptor.
//
// The socket must already be connected. On Android the host connects it before
// calling VpnService.protect and before the handoff, because connecting it
// afterwards would be a route lookup this process cannot influence.
func adoptStreamDescriptor(fd int) (net.Conn, error) {
	if fd < 0 {
		return nil, errors.New("winn datapath TCP descriptor is negative")
	}
	file := os.NewFile(uintptr(fd), "winn-datapath-tcp")
	if file == nil {
		return nil, fmt.Errorf(
			"winn datapath TCP descriptor %d is not a valid file descriptor",
			fd,
		)
	}
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf(
			"winn datapath adopt TCP descriptor %d: %w", fd, err,
		)
	}
	if closeErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf(
			"winn datapath release adopted TCP descriptor %d: %w",
			fd, closeErr,
		)
	}
	if _, ok := conn.(*net.TCPConn); !ok {
		_ = conn.Close()
		return nil, fmt.Errorf(
			"winn datapath descriptor %d is not a TCP socket (%T)", fd, conn,
		)
	}
	if conn.RemoteAddr() == nil {
		_ = conn.Close()
		return nil, fmt.Errorf(
			"winn datapath TCP descriptor %d is not connected; the host must "+
				"connect and protect the socket before handing it over", fd,
		)
	}
	descriptorAdopted()
	return conn, nil
}
