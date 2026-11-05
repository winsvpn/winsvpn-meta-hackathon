package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

const tcpClassificationTimeout = 5 * time.Second

// tcpIngress retains every byte read during classification. A rejected stream
// reaches the existing decoy listener with exactly those bytes restored.
type tcpIngress struct {
	raw       net.Listener
	secret    []byte
	cfg       session.Config
	sizing    driver.Sizing
	cover     chan net.Conn
	accepted  chan *tcpAccepted
	done      chan struct{}
	once      sync.Once
	admission atomic.Pointer[tcpAdmission]
}

type tcpAdmission struct{ allows func() bool }

func (i *tcpIngress) setAdmissionGate(allows func() bool) {
	i.admission.Store(&tcpAdmission{allows: allows})
}

type tcpAccepted struct {
	stream   *carrier.Stream
	driver   *session.Driver
	remote   net.Addr
	fallback func()
}

type tcpCaptureConn struct {
	net.Conn
	read []byte
	// stopped ends capture once classification has read the first flight.
	// The admitted stream keeps reading through this wrapper for its whole
	// life, and the cover replay needs only the classification bytes. Set on
	// the classify goroutine before the stream is handed off.
	stopped bool
}

func (c *tcpCaptureConn) Read(dst []byte) (int, error) {
	n, err := c.Conn.Read(dst)
	if !c.stopped {
		c.read = append(c.read, dst[:n]...)
	}
	return n, err
}

// retireUnowned ends a classified driver that no loop will own, so its
// session state and its copies of the gateway's dual-auth signing keys are
// wiped (session.Driver.terminate) instead of left for the collector.
func retireUnowned(d *session.Driver) {
	if d != nil {
		d.RetireIfQuiet(d.ReclaimView().Seq)
	}
}

type tcpReplayConn struct {
	net.Conn
	prefix      *bytes.Reader
	expireReads bool
}

func (c *tcpReplayConn) Read(dst []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(dst)
	}
	return c.Conn.Read(dst)
}

func (c *tcpReplayConn) SetReadDeadline(deadline time.Time) error {
	if c.expireReads {
		deadline = time.Now().Add(-time.Second)
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *tcpReplayConn) SetDeadline(deadline time.Time) error {
	if !c.expireReads {
		return c.Conn.SetDeadline(deadline)
	}
	if err := c.Conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return c.SetReadDeadline(deadline)
}

func newTCPIngress(raw net.Listener, secret []byte, cfg session.Config, sizing driver.Sizing) *tcpIngress {
	i := &tcpIngress{
		raw: raw, secret: append([]byte(nil), secret...), cfg: cfg, sizing: sizing,
		cover: make(chan net.Conn), accepted: make(chan *tcpAccepted), done: make(chan struct{}),
	}
	go i.pump()
	return i
}

func (i *tcpIngress) pump() {
	for {
		conn, err := i.raw.Accept()
		if err != nil {
			i.Close()
			return
		}
		go i.classify(conn)
	}
}

func (i *tcpIngress) classify(raw net.Conn) {
	captured := &tcpCaptureConn{Conn: raw}
	expireCoverReads := false
	fallback := func() {
		replayed := &tcpReplayConn{Conn: raw, prefix: bytes.NewReader(captured.read), expireReads: expireCoverReads}
		select {
		case i.cover <- replayed:
		case <-i.done:
			_ = raw.Close()
		}
	}
	_ = raw.SetReadDeadline(time.Now().Add(tcpClassificationTimeout))
	var firstByte [1]byte
	_, peekErr := io.ReadFull(captured, firstByte[:])
	_ = raw.SetReadDeadline(time.Time{})
	if peekErr != nil || firstByte[0] != 0x16 {
		fallback()
		return
	}
	replayed := &tcpReplayConn{Conn: captured, prefix: bytes.NewReader(captured.read)}
	stream, err := carrier.NewStream(carrier.StreamConfig{
		Conn: replayed, Secret: i.secret, Role: carrier.RoleGateway,
		MaxMessageSize: i.sizing.MessageSize, PathMTU: i.sizing.PathMTU, TCPFirstFlight: true,
	})
	if err != nil {
		fallback()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), tcpClassificationTimeout)
	first, err := stream.Recv(ctx)
	cancel()
	captured.stopped = true
	if err != nil {
		var timeout net.Error
		expireCoverReads = errors.Is(err, context.DeadlineExceeded) ||
			(errors.As(err, &timeout) && timeout.Timeout())
		fallback()
		return
	}
	gate := i.admission.Load()
	if gate == nil || !gate.allows() {
		fallback()
		return
	}
	cfg := i.cfg
	cfg.MaxMessageSize = i.sizing.MessageSize
	cfg.PathMTU = i.sizing.PathMTU
	cfg.Clock = driver.SessionClock{Clock: driver.SystemClock{}}
	authenticated, err := session.NewGateway(cfg)
	if err != nil {
		fallback()
		return
	}
	_, err = authenticated.Deliver(first)
	if err != nil || len(authenticated.PeerStatic()) == 0 || authenticated.State().Terminal() {
		retireUnowned(authenticated)
		fallback()
		return
	}
	rejected := func() {
		retireUnowned(authenticated)
		fallback()
	}
	select {
	case i.accepted <- &tcpAccepted{stream: stream, driver: authenticated, remote: raw.RemoteAddr(), fallback: rejected}:
	case <-i.done:
		retireUnowned(authenticated)
		_ = raw.Close()
	}
}

func (i *tcpIngress) Accept() (net.Conn, error) {
	select {
	case conn := <-i.cover:
		return conn, nil
	case <-i.done:
		return nil, net.ErrClosed
	}
}

func (i *tcpIngress) Close() error {
	i.once.Do(func() { close(i.done) })
	return i.raw.Close()
}

func (i *tcpIngress) Addr() net.Addr { return i.raw.Addr() }
