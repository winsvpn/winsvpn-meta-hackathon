//go:build !linux && !android

package carrier

import (
	"errors"
	"net"
)

// SendErrorOptions is defined here too so the field names are stable across
// platforms; on non-Linux nothing sets either.
type SendErrorOptions struct {
	IPv4 bool
	IPv6 bool
}

func (o SendErrorOptions) Any() bool { return o.IPv4 || o.IPv6 }

// EnableSendErrorReporting is Linux-only. Elsewhere it returns
// errors.ErrUnsupported and the socket keeps its platform behaviour.
func EnableSendErrorReporting(conn *net.UDPConn) (SendErrorOptions, error) {
	return SendErrorOptions{}, errors.ErrUnsupported
}

// IsAsyncSocketError is false where there is no IP_RECVERR error queue.
func IsAsyncSocketError(err error) bool { return false }

// IsPermanentSocketError is false here; the pump's closure check still applies.
func IsPermanentSocketError(err error) bool { return false }

// SocketErrorQueue has nothing to drain on this platform. Every method is a
// no-op, safe on a nil receiver.
type SocketErrorQueue struct{}

// NewSocketErrorQueue returns errors.ErrUnsupported on this platform.
func NewSocketErrorQueue(conn *net.UDPConn) (*SocketErrorQueue, error) {
	return nil, errors.ErrUnsupported
}

func (q *SocketErrorQueue) SetHandler(fn func(QueuedSocketError)) {}

func (q *SocketErrorQueue) Stats() SocketErrorStats { return SocketErrorStats{} }

func (q *SocketErrorQueue) Drain() int { return 0 }

func (q *SocketErrorQueue) AbsorbAsync(err error, attempt int) bool { return false }

func (q *SocketErrorQueue) noteScalarRefused() {}

func (q *SocketErrorQueue) noteScalarDropped() {}

// ErrorQueue is nil on this platform.
func (c *RawBatchConn) ErrorQueue() *SocketErrorQueue { return nil }

// NoteMatchingRetry is a no-op without an error queue.
func (q *SocketErrorQueue) NoteMatchingRetry(err error) {}

// Draining is always false without an error queue.
func (q *SocketErrorQueue) Draining() bool { return false }

// SendScalarRetain on a platform without an error queue simply runs the write.
func (q *SocketErrorQueue) SendScalarRetain(write func() (int, error)) (int, error) {
	return write()
}

// SendCoverScalar on a platform without an error queue simply runs the write.
func (q *SocketErrorQueue) SendCoverScalar(payloadLen int, write func() (int, error)) (int, error) {
	return write()
}
