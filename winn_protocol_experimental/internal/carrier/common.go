package carrier

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultMaxDatagram  = 1350
	AbsoluteMaxDatagram = 1500
)

var ErrDatagramTooLarge = errors.New("winn carrier datagram exceeds configured MTU")

type packetConn struct {
	net.PacketConn
	maxDatagram int
	closed      atomic.Bool
	readMu      sync.Mutex
	readBuffer  []byte
}

func limitPacketConn(conn net.PacketConn, maxDatagram int) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("packet connection is nil")
	}
	if maxDatagram <= 0 {
		maxDatagram = DefaultMaxDatagram
	}
	if maxDatagram > AbsoluteMaxDatagram {
		return nil, errors.New("carrier datagram limit exceeds 1500 bytes")
	}
	return &packetConn{
		PacketConn:  conn,
		maxDatagram: maxDatagram,
		readBuffer:  make([]byte, maxDatagram+1),
	}, nil
}

func (c *packetConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	count, address, err := c.PacketConn.ReadFrom(c.readBuffer)
	if err != nil {
		return 0, nil, err
	}
	if count > c.maxDatagram {
		clear(c.readBuffer[:count])
		return 0, address, ErrDatagramTooLarge
	}
	copied := copy(buffer, c.readBuffer[:count])
	clear(c.readBuffer[:count])
	return copied, address, nil
}

func (c *packetConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(packet) > c.maxDatagram {
		return 0, ErrDatagramTooLarge
	}
	return c.PacketConn.WriteTo(packet, address)
}

func (c *packetConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return c.PacketConn.Close()
}

func (c *packetConn) SetDeadline(deadline time.Time) error {
	if c.closed.Load() {
		return os.ErrClosed
	}
	return c.PacketConn.SetDeadline(deadline)
}

type fixedAddr string

func (address fixedAddr) Network() string { return "winn-carrier" }
func (address fixedAddr) String() string  { return string(address) }
