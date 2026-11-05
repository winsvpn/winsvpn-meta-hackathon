//go:build !linux && !android

package carrier

import (
	"context"
	"errors"
	"net/netip"
)

// There is no portable recvmmsg/sendmmsg. On every platform without them the
// carrier keeps its per-datagram socket loop, which is the same filtering and
// error contract with a different syscall count.
type batchState struct{}

func (u *UDP) recvBatchKernel(
	ctx context.Context,
	msgs []BatchMsg,
	ceiling int,
) (int, error, bool) {
	return 0, nil, false
}

func (u *UDP) sendBatchKernel(ctx context.Context, msgs []BatchMsg) (int, error, bool) {
	return 0, nil, false
}

type RawBatchConn struct{}

func NewRawBatchConn(conn any) (*RawBatchConn, error) {
	return nil, errors.New("raw batch not supported on this platform")
}

func (c *RawBatchConn) WriteBatchTo(msgs []BatchMsg, to netip.AddrPort) (int, error) {
	return 0, errors.New("raw batch not supported on this platform")
}

func (c *RawBatchConn) ReadBatchFrom(msgs []BatchMsg) (int, error) {
	return 0, errors.New("raw batch not supported on this platform")
}
