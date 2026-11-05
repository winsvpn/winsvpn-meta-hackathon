package carrier

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// DefaultRelayBatchSize bounds each recvmmsg/sendmmsg operation while
	// amortizing syscall cost at line rate.
	DefaultRelayBatchSize = 64
	// MaxRelayBatchSize keeps the relay's preallocated packet memory bounded.
	MaxRelayBatchSize = 128
	// MaxRelaySocketBufferBytes bounds each kernel UDP send/receive buffer
	// request. Linux may account additional bookkeeping beyond this value.
	MaxRelaySocketBufferBytes = 16 << 20
)

var errRelayBatchUnsupported = errors.New("relay batch I/O is unsupported")

// relayBatchConn deliberately uses ipv4.Message for both address families.
// ipv4.Message and ipv6.Message are aliases of the same socket.Message type.
type relayBatchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

type ipv4RelayBatchConn struct {
	connection *ipv4.PacketConn
}

func (connection ipv4RelayBatchConn) ReadBatch(
	messages []ipv4.Message,
	flags int,
) (int, error) {
	return connection.connection.ReadBatch(messages, flags)
}

func (connection ipv4RelayBatchConn) WriteBatch(
	messages []ipv4.Message,
	flags int,
) (int, error) {
	return connection.connection.WriteBatch(messages, flags)
}

type ipv6RelayBatchConn struct {
	connection *ipv6.PacketConn
}

func (connection ipv6RelayBatchConn) ReadBatch(
	messages []ipv4.Message,
	flags int,
) (int, error) {
	return connection.connection.ReadBatch(messages, flags)
}

func (connection ipv6RelayBatchConn) WriteBatch(
	messages []ipv4.Message,
	flags int,
) (int, error) {
	return connection.connection.WriteBatch(messages, flags)
}

type relayBatchFactory func(net.PacketConn, *net.UDPAddr) relayBatchConn

type relaySocketBufferSetter interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func configureRelaySocketBuffers(
	local relaySocketBufferSetter,
	remote net.PacketConn,
	bytes int,
) error {
	if bytes == 0 {
		return nil
	}
	if bytes < 0 || bytes > MaxRelaySocketBufferBytes {
		return errors.New("relay UDP socket buffer size is invalid")
	}
	setter, ok := remote.(relaySocketBufferSetter)
	if !ok {
		return errors.New(
			"configured relay UDP socket buffers require a compatible carrier",
		)
	}
	if err := local.SetReadBuffer(bytes); err != nil {
		return fmt.Errorf("configure local relay UDP read buffer: %w", err)
	}
	if err := local.SetWriteBuffer(bytes); err != nil {
		return fmt.Errorf("configure local relay UDP write buffer: %w", err)
	}
	if err := setter.SetReadBuffer(bytes); err != nil {
		return fmt.Errorf("configure carrier UDP read buffer: %w", err)
	}
	if err := setter.SetWriteBuffer(bytes); err != nil {
		return fmt.Errorf("configure carrier UDP write buffer: %w", err)
	}
	return nil
}

func newRelayBatchConn(
	connection net.PacketConn,
	expectedPeer *net.UDPAddr,
) relayBatchConn {
	if _, ok := connection.(syscall.Conn); !ok {
		return nil
	}
	// Prefer the known peer family. A wildcard local bind does not otherwise
	// reveal whether a dual-stack socket will receive an IPv4 or IPv6 peer.
	address := expectedPeer
	if address == nil {
		if remote, ok := connection.(interface{ RemoteAddr() net.Addr }); ok {
			address, _ = remote.RemoteAddr().(*net.UDPAddr)
		}
	}
	if address == nil {
		address, _ = connection.LocalAddr().(*net.UDPAddr)
	}
	if address != nil && address.IP != nil && address.IP.To4() == nil {
		return ipv6RelayBatchConn{connection: ipv6.NewPacketConn(connection)}
	}
	return ipv4RelayBatchConn{connection: ipv4.NewPacketConn(connection)}
}

// relayPacketIO falls back independently for reads and writes. A partial
// successful batch is never retried: callers continue at the returned count,
// which prevents both duplication and reordering.
type relayPacketIO struct {
	connection net.PacketConn
	batch      relayBatchConn

	readBatchOK  atomic.Bool
	writeBatchOK atomic.Bool
}

func newRelayPacketIO(
	connection net.PacketConn,
	expectedPeer *net.UDPAddr,
	factory relayBatchFactory,
) *relayPacketIO {
	batch := factory(connection, expectedPeer)
	packets := &relayPacketIO{connection: connection, batch: batch}
	packets.readBatchOK.Store(batch != nil)
	packets.writeBatchOK.Store(batch != nil)
	return packets
}

func (packets *relayPacketIO) readBatch(
	messages []ipv4.Message,
) (int, error) {
	if packets.readBatchOK.Load() {
		count, err := packets.batch.ReadBatch(messages, 0)
		if !isRelayBatchUnsupported(err) {
			return count, err
		}
		packets.readBatchOK.Store(false)
		if count > 0 {
			return count, nil
		}
	}
	count, sender, err := packets.connection.ReadFrom(messages[0].Buffers[0])
	if err != nil {
		return 0, err
	}
	messages[0].N = count
	messages[0].Addr = sender
	return 1, nil
}

func (packets *relayPacketIO) writeBatch(
	messages []ipv4.Message,
) (int, error) {
	if packets.writeBatchOK.Load() {
		count, err := packets.batch.WriteBatch(messages, 0)
		if !isRelayBatchUnsupported(err) {
			return count, err
		}
		packets.writeBatchOK.Store(false)
		if count > 0 {
			return count, nil
		}
	}
	message := messages[0]
	count, err := packets.connection.WriteTo(message.Buffers[0], message.Addr)
	if err != nil {
		return 0, err
	}
	message.N = count
	return 1, nil
}

func writeAllRelayMessages(
	packets *relayPacketIO,
	messages []ipv4.Message,
) error {
	for written := 0; written < len(messages); {
		count, err := packets.writeBatch(messages[written:])
		if count < 0 || count > len(messages)-written {
			return errors.New("relay batch write returned an invalid count")
		}
		written += count
		if err != nil {
			return err
		}
		if count == 0 {
			return errors.New("relay batch write made no progress")
		}
	}
	return nil
}

func isRelayBatchUnsupported(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errRelayBatchUnsupported) ||
		errors.Is(err, errors.ErrUnsupported) {
		return true
	}
	// x/net's platform stubs return private sentinel errors. They are commonly
	// wrapped by net.OpError, so inspect the unwrapped text as a final portable
	// compatibility check.
	for current := err; current != nil; current = errors.Unwrap(current) {
		message := strings.ToLower(current.Error())
		if strings.Contains(message, "not implemented") ||
			strings.Contains(message, "operation not supported") {
			return true
		}
	}
	return false
}
