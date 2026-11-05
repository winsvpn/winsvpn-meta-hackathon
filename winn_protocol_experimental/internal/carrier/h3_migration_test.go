package carrier

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestCloseOwnedQUICTransportClosesSuppliedPacketConn(t *testing.T) {
	socket := &closeCountingPacketConn{}
	transport := &quic.Transport{
		Conn:               socket,
		ConnectionIDLength: 8,
	}
	if err := closeOwnedQUICTransport(transport); err != nil {
		t.Fatal(err)
	}
	if count := socket.closes.Load(); count != 1 {
		t.Fatalf("supplied PacketConn close count = %d, want 1", count)
	}
}

func TestClosedMigratableH3ConsumesRejectedSocket(t *testing.T) {
	carrier := &migratableH3PacketConn{closed: true}
	socket := &closeCountingPacketConn{}
	if err := carrier.MigratePath(
		context.Background(),
		socket,
	); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("MigratePath error = %v, want closed", err)
	}
	if count := socket.closes.Load(); count != 1 {
		t.Fatalf("rejected migration socket closes = %d, want 1", count)
	}
}

type closeCountingPacketConn struct {
	closes atomic.Int32
}

func (*closeCountingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (*closeCountingPacketConn) WriteTo(
	packet []byte,
	_ net.Addr,
) (int, error) {
	return len(packet), nil
}

func (socket *closeCountingPacketConn) Close() error {
	socket.closes.Add(1)
	return nil
}

func (*closeCountingPacketConn) LocalAddr() net.Addr {
	return fixedAddr("owned-quic")
}

func (*closeCountingPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (*closeCountingPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*closeCountingPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}
