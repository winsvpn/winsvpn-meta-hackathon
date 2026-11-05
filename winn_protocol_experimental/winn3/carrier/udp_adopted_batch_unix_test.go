//go:build unix

package carrier

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// Exercise the descriptor adoption used by the Android host, with a raw UDP
// peer so a second buggy batch carrier cannot hide lost or duplicate packets.
func TestUDPAdoptedBatchDeliversExactlyOnce(t *testing.T) {
	for _, mode := range []string{"unconnected-ipv4", "unconnected-dual-stack", "connected-ipv4"} {
		for _, direction := range []string{"receive", "send"} {
			t.Run(mode+"/"+direction, func(t *testing.T) {
				server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = server.Close() })
				peer := server.LocalAddr().(*net.UDPAddr)
				var original *net.UDPConn
				switch mode {
				case "connected-ipv4":
					original, err = net.DialUDP("udp4", nil, peer)
				case "unconnected-dual-stack":
					original, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
				default:
					original, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = original.Close() })
				file, err := original.File()
				if err != nil {
					t.Fatal(err)
				}
				packetConn, adoptErr := net.FilePacketConn(file)
				closeErr := file.Close()
				if adoptErr != nil {
					t.Fatal(adoptErr)
				}
				t.Cleanup(func() { _ = packetConn.Close() })
				if closeErr != nil {
					t.Fatal(closeErr)
				}
				if err := original.Close(); err != nil {
					t.Fatal(err)
				}
				conn := packetConn.(*net.UDPConn)
				cfg := UDPConfig{Conn: conn, Peer: peer}
				u, err := NewUDP(cfg)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				payload := []byte("one handshake datagram")
				if direction == "receive" {
					destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: conn.LocalAddr().(*net.UDPAddr).Port}
					if _, err := server.WriteToUDP(payload, destination); err != nil {
						t.Fatal(err)
					}
					msgs := []BatchMsg{{Payload: make([]byte, u.MaxMessageSize())}}
					n, err := u.RecvBatch(ctx, msgs)
					if err != nil || n != 1 {
						t.Fatalf("RecvBatch consumed one datagram but returned count=%d err=%v", n, err)
					}
					if !bytes.Equal(msgs[0].Payload[:msgs[0].N], payload) {
						t.Fatal("received payload changed")
					}
					if got := u.Stats().Delivered; got != 1 {
						t.Fatalf("Delivered=%d, want 1", got)
					}
					return
				}
				msgs := []BatchMsg{{Payload: payload, N: len(payload)}}
				if n, err := u.SendBatch(ctx, msgs); err != nil || n != 1 {
					t.Fatalf("SendBatch count=%d err=%v", n, err)
				}
				if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 1500)
				n, _, err := server.ReadFromUDP(buf)
				if err != nil || !bytes.Equal(buf[:n], payload) {
					t.Fatalf("raw peer did not receive the original datagram: %v", err)
				}
				if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				if _, _, err := server.ReadFromUDP(buf); err == nil {
					t.Fatal("SendBatch sent a duplicate datagram")
				} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
					t.Fatalf("checking for duplicate: %v", err)
				}
				if got := u.Stats(); got.Sent != 1 || got.LastSend.IsZero() {
					t.Fatalf("Sent=%d LastSend zero=%v, want 1 and false", got.Sent, got.LastSend.IsZero())
				}
			})
		}
	}
}
