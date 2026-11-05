//go:build unix

package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProtectedTCPRequestSuppliesFreshDescriptorEachTime(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostFile := os.NewFile(uintptr(fds[0]), "host-requests")
	hostConn, err := net.FileConn(hostFile)
	_ = hostFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	host := hostConn.(*net.UnixConn)
	defer host.Close()
	engineFile := os.NewFile(uintptr(fds[1]), "engine-requests")
	engineConn, err := net.FileConn(engineFile)
	_ = engineFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	engine := engineConn.(*net.UnixConn)
	defer engine.Close()
	s := &winn3FrameServer{tcpChannel: engine}
	hostDone := make(chan error, 1)
	go func() {
		for range 2 {
			var request [1]byte
			if _, err := host.Read(request[:]); err != nil {
				hostDone <- err
				return
			}
			if request[0] != 1 {
				hostDone <- context.Canceled
				return
			}
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
			if err != nil {
				hostDone <- err
				return
			}
			_, _, err = host.WriteMsgUnix([]byte{1}, unix.UnixRights(fd), nil)
			_ = unix.Close(fd)
			if err != nil {
				hostDone <- err
				return
			}
		}
		hostDone <- nil
	}()
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		fd, err := s.requestTCPDescriptor(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		typeID, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		_ = unix.Close(fd)
		if err != nil || typeID != unix.SOCK_STREAM {
			t.Fatalf("received descriptor is not a TCP socket: type=%d err=%v", typeID, err)
		}
	}
	if err := <-hostDone; err != nil {
		t.Fatal(err)
	}
}

func TestV3DescriptorHandoffUsesSeparateRequestChannel(t *testing.T) {
	control, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostFile := os.NewFile(uintptr(control[0]), "host-control")
	defer hostFile.Close()
	engineFile := os.NewFile(uintptr(control[1]), "engine-control")
	engineConn, err := net.FileConn(engineFile)
	_ = engineFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	engine := engineConn.(*net.UnixConn)
	defer engine.Close()
	udpFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(udpFD)
	channel, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(channel[0])
	defer unix.Close(channel[1])
	if _, err := unix.SendmsgN(int(hostFile.Fd()), []byte{1}, unix.UnixRights(udpFD, channel[1]), nil, 0); err != nil {
		t.Fatal(err)
	}
	udp, tcp, requests, err := receiveV3Descriptors(engine)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(udp)
	defer unix.Close(requests)
	if tcp != -1 || requests < 0 {
		t.Fatalf("handoff assigned tcp=%d requests=%d", tcp, requests)
	}
	if kind, err := unix.GetsockoptInt(udp, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || kind != unix.SOCK_DGRAM {
		t.Fatalf("UDP descriptor has type=%d err=%v", kind, err)
	}
}

func TestProtectedTCPRequestTimeoutCannotConsumeLateReply(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	engineFile := os.NewFile(uintptr(fds[1]), "engine-requests")
	engineConn, err := net.FileConn(engineFile)
	_ = engineFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	engine := engineConn.(*net.UnixConn)
	defer engine.Close()
	s := &winn3FrameServer{tcpChannel: engine}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if fd, err := s.requestTCPDescriptor(ctx); err == nil || fd >= 0 {
		t.Fatalf("unanswered TCP request returned fd=%d err=%v", fd, err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if fd, err := s.requestTCPDescriptor(ctx2); err == nil || fd >= 0 {
		t.Fatalf("closed request channel returned fd=%d err=%v", fd, err)
	}
}
