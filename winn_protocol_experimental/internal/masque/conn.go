package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	StreamID() quic.StreamID
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type Conn struct {
	str        http3Stream
	localAddr  net.Addr
	remoteAddr net.Addr
	closeConn  func() error

	closed   atomic.Bool // set when Close is called
	readDone chan struct{}

	deadlineMx              sync.Mutex
	readCtx                 context.Context
	readCtxCancel           context.CancelFunc
	deadline                time.Time
	readDeadlineTimer       *time.Timer
	deadlineGeneration      uint64
	deadlineCallbackStarted func()
}

var _ net.PacketConn = &Conn{}

// closeConn is only used for QUIC connections dialed by [Transport.Dial].
// It is nil for connections created through [Transport.NewClientConn]; callers close those QUIC connections themselves.
func newProxiedConn(str http3Stream, local, remote net.Addr, closeConn func() error) *Conn {
	c := &Conn{
		str:        str,
		localAddr:  local,
		remoteAddr: remote,
		closeConn:  closeConn,
		readDone:   make(chan struct{}),
	}
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(quicvarint.NewReader(str)); err != io.EOF && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		// The peer has ended its response direction. CancelWrite is
		// idempotent and cannot surface quic-go's benign "close called for
		// canceled stream" race when the server already sent STOP_SENDING.
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	}()
	return c
}

func (c *Conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
start:
	c.deadlineMx.Lock()
	ctx := c.readCtx
	c.deadlineMx.Unlock()
	data, err := c.str.ReceiveDatagram(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			return 0, nil, err
		}
		// The context is cancelled asynchronously (in a Go routine spawned from time.AfterFunc).
		// We need to check if a new deadline has already been set.
		c.deadlineMx.Lock()
		restart := time.Now().Before(c.deadline)
		c.deadlineMx.Unlock()
		if restart {
			goto start
		}
		return 0, nil, os.ErrDeadlineExceeded
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return 0, nil, fmt.Errorf("masque: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of UDP payloads.
		goto start
	}
	// If b is too small, additional bytes are discarded.
	// This mirrors the behavior of large UDP datagrams received on a UDP socket (on Linux).
	return copy(b, data[n:]), c.remoteAddr, nil
}

// capacityQuerySize is larger than any UDP payload can ever be (65,507 bytes),
// and therefore larger than any QUIC DATAGRAM frame. SendDatagram compares the
// length against its current limit and returns DatagramTooLargeError *before*
// it copies or queues anything, so asking with an impossible size reads the
// limit out of quic-go without putting a byte on the wire.
//
// The impossibility is the safety property: if this constant were ever small
// enough to be accepted, the query would emit a stray datagram. Do not lower it.
const capacityQuerySize = 1 << 16

// DatagramCapacity reports the largest UDP payload WriteTo can carry on this
// proxied connection right now. It sends nothing.
//
// The number comes from the QUIC connection that is already up: quic-go derives
// it from the packet size the handshake was conducted at and from the peer's
// max_datagram_frame_size transport parameter. Both were settled before this
// call, so reading them costs no packets and reveals nothing to an observer.
//
// This exists so a caller can fail closed on a path that cannot carry its
// datagrams without first *demonstrating* the fact with a distinctive burst of
// same-size datagrams. See internal/carrier.(*envelopePacketConn).
// ConfirmDatagramCapacity for what the carrier does with it.
func (c *Conn) DatagramCapacity() (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	err := c.str.SendDatagram(make([]byte, capacityQuerySize))
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		if err == nil {
			// Unreachable unless capacityQuerySize stops being impossible, in
			// which case a datagram just went out and the caller must be told.
			return 0, errors.New(
				"masque: datagram capacity query was accepted; the query size is no longer impossible",
			)
		}
		return 0, fmt.Errorf("masque: read datagram capacity: %w", err)
	}
	// MaxDatagramPayloadSize is the budget for everything the layers below
	// WriteTo put in the QUIC DATAGRAM frame: the quarter stream ID varint that
	// http3 prepends (RFC 9297) and the context ID that WriteTo prepends
	// (RFC 9298). What is left is what a caller's UDP payload may use.
	framing := quicvarint.Len(uint64(c.str.StreamID()/4)) + len(contextIDZero)
	capacity := int(tooLarge.MaxDatagramPayloadSize) - framing
	if capacity <= 0 {
		return 0, errors.New(
			"masque: HTTP datagram framing leaves no room for a UDP payload",
		)
	}
	return capacity, nil
}

// WriteTo sends a UDP datagram to the target.
// The net.Addr parameter is ignored.
func (c *Conn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	data := make([]byte, 0, len(contextIDZero)+len(p))
	data = append(data, contextIDZero...)
	data = append(data, p...)
	if err := c.str.SendDatagram(data); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	<-c.readDone
	c.deadlineMx.Lock()
	c.deadlineGeneration++
	c.deadline = time.Time{}
	if c.readDeadlineTimer != nil {
		c.readDeadlineTimer.Stop()
		c.readDeadlineTimer = nil
	}
	c.readCtxCancel()
	c.deadlineMx.Unlock()
	if c.closeConn != nil {
		return c.closeConn()
	}
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.SetReadDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMx.Lock()
	defer c.deadlineMx.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}

	c.deadlineGeneration++
	generation := c.deadlineGeneration
	c.deadline = t
	if c.readDeadlineTimer != nil {
		// Timers created by time.AfterFunc have a nil C field. Never wait on
		// that channel when Stop reports that the callback has started.
		// The generation check below makes an already queued callback stale.
		c.readDeadlineTimer.Stop()
		c.readDeadlineTimer = nil
	}

	// A previously expired deadline canceled readCtx. Clearing or extending
	// the deadline must install a live context for subsequent reads.
	renewReadContext := func() {
		if c.readCtx.Err() != nil {
			c.readCtxCancel()
			c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
		}
	}
	if t.IsZero() {
		renewReadContext()
		return nil
	}

	now := time.Now()
	if !t.After(now) {
		c.readCtxCancel()
		return nil
	}
	renewReadContext()

	c.readDeadlineTimer = time.AfterFunc(t.Sub(now), func() {
		if c.deadlineCallbackStarted != nil {
			c.deadlineCallbackStarted()
		}
		c.deadlineMx.Lock()
		defer c.deadlineMx.Unlock()
		if c.deadlineGeneration != generation {
			return
		}
		if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
			c.readCtxCancel()
		}
	})
	return nil
}

func (c *Conn) SetWriteDeadline(time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	// TODO(#22): This is currently blocked on a change in quic-go's API.
	return nil
}

func skipCapsules(str io.Reader) error {
	parser := http3.NewCapsuleParser(str)
	for {
		ct, r, err := parser.Next()
		if err != nil {
			return err
		}
		log.Printf("skipping capsule of type %d", ct)
		if err := r.Discard(); err != nil {
			return err
		}
	}
}
