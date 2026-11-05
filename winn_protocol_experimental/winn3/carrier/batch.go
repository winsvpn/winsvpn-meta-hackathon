package carrier

import (
	"context"
	"net/netip"
)

// BatchMsg describes one packet in a batched carrier read or write.
type BatchMsg struct {
	// Payload is the packet data slice. For reads, it must point to a buffer
	// with sufficient capacity (at least MaxMessageSize). For writes, it contains
	// the bytes to be transmitted.
	Payload []byte

	// Addr is the remote peer address for this datagram.
	Addr netip.AddrPort

	// N is the number of bytes read or written.
	N int

	// Err is any per-message error encountered during processing.
	Err error
}

// BatchCarrier is an optional extension to Carrier for exchanging groups of
// complete datagrams. It specifies partial-result semantics, not a syscall
// count. UDP currently uses portable per-datagram socket operations; a native
// vector implementation must preserve the same filtering and error contract.
type BatchCarrier interface {
	Carrier

	// RecvBatch reads up to len(msgs) datagrams into the provided slices.
	// Returns the number of successfully read messages.
	RecvBatch(ctx context.Context, msgs []BatchMsg) (int, error)

	// SendBatch writes up to len(msgs) datagrams from the provided slices.
	// Returns the number of successfully written messages.
	SendBatch(ctx context.Context, msgs []BatchMsg) (int, error)
}

// RecvBatchFallback emulates RecvBatch over an ordinary Carrier by calling
// Recv/RecvInto repeatedly until msgs is full or a read fails.
func RecvBatchFallback(ctx context.Context, c Carrier, msgs []BatchMsg) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	type receiverInto interface {
		RecvInto(context.Context, []byte) ([]byte, error)
	}
	into, hasInto := c.(receiverInto)

	n := 0
	for i := range msgs {
		if hasInto && len(msgs[i].Payload) > 0 {
			buf, err := into.RecvInto(ctx, msgs[i].Payload)
			if err != nil {
				if n > 0 {
					return n, nil
				}
				return 0, err
			}
			msgs[i].N = len(buf)
			n++
		} else {
			data, err := c.Recv(ctx)
			if err != nil {
				if n > 0 {
					return n, nil
				}
				return 0, err
			}
			msgs[i].Payload = data
			msgs[i].N = len(data)
			n++
		}
	}
	return n, nil
}

// SendBatchFallback emulates SendBatch over an ordinary Carrier by calling
// Send for each message.
func SendBatchFallback(ctx context.Context, c Carrier, msgs []BatchMsg) (int, error) {
	for i := range msgs {
		if msgs[i].N < 0 || msgs[i].N > len(msgs[i].Payload) {
			return 0, wrap(ErrConfig, "invalid batch payload length")
		}
	}
	for i := range msgs {
		if err := c.Send(ctx, msgs[i].Payload[:msgs[i].N]); err != nil {
			return i, err
		}
	}
	return len(msgs), nil
}
