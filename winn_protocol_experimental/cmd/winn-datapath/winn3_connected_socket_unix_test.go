//go:build unix

package main

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestOuterSocketRetainsConnectedPeerAndPort(t *testing.T) {
	gateway, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	peer := gateway.LocalAddr().(*net.UDPAddr)
	client, err := net.DialUDP("udp4", nil, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	local := client.LocalAddr().String()
	file, err := client.File()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	// outerSocket consumes fd and gives its duplicate to the network poller.
	s := &winn3FrameServer{descriptor: fd}
	adopted, err := s.outerSocket(context.Background(), winn3CreatePlan{remote: peer})
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()
	if adopted.RemoteAddr() == nil || adopted.RemoteAddr().String() != peer.String() {
		t.Fatalf("adopted peer = %v, want %v", adopted.RemoteAddr(), peer)
	}
	if adopted.LocalAddr().String() != local {
		t.Fatalf("adopted local address = %v, want %s", adopted.LocalAddr(), local)
	}
	deadline := time.Now().Add(2 * time.Second)
	if err := gateway.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := adopted.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	for attempt := byte(0); attempt < 5; attempt++ {
		if _, err := adopted.Write([]byte{attempt}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32)
		n, from, err := gateway.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if from.String() != local || n != 1 || buf[0] != attempt {
			t.Fatalf("request %d: source=%v bytes=%d payload=%x", attempt, from, n, buf[:n])
		}
		if _, err := gateway.WriteToUDP(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		n, from, err = adopted.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if from.String() != peer.String() || n != 1 || buf[0] != attempt {
			t.Fatalf("response %d: source=%v bytes=%d payload=%x", attempt, from, n, buf[:n])
		}
	}
}
