//go:build linux

package h3candidate

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestLinuxQUICDialErrorLeavesSocketForOuterOwner(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socket := &linuxCloseCountingPacketConn{PacketConn: raw}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = dialLinuxQUICPath(
		ctx,
		socket,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9},
		&tls.Config{
			ServerName: "cover.example",
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
		&quic.Config{EnableDatagrams: true},
	)
	if err == nil {
		t.Fatal("canceled Linux QUIC dial unexpectedly succeeded")
	}
	if closes := socket.closes.Load(); closes != 0 {
		t.Fatalf("inner Linux dial closed outer-owned socket %d times", closes)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if closes := socket.closes.Load(); closes != 1 {
		t.Fatalf("outer Linux socket closes = %d, want 1", closes)
	}
}

type linuxCloseCountingPacketConn struct {
	net.PacketConn
	closes atomic.Int32
}

func (socket *linuxCloseCountingPacketConn) Close() error {
	socket.closes.Add(1)
	return socket.PacketConn.Close()
}
