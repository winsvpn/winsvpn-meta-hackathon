package carrier

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

// PathMigrator is implemented by an HTTP/3 carrier that can validate and
// switch the existing QUIC connection to a new local network socket. It
// consumes socket on every outcome and closes it on failure or when the
// carrier later closes. This is RFC 9000 connection migration, not
// simultaneous draft multipath scheduling.
type PathMigrator interface {
	MigratePath(context.Context, net.PacketConn) error
}

type migratableH3PacketConn struct {
	net.PacketConn
	connection *quic.Conn

	mu         sync.Mutex
	migration  sync.Mutex
	transports []*quic.Transport
	closed     bool
}

func newMigratableH3PacketConn(packet net.PacketConn, connection *quic.Conn, initial *quic.Transport) *migratableH3PacketConn {
	result := &migratableH3PacketConn{PacketConn: packet, connection: connection}
	if initial != nil {
		result.transports = append(result.transports, initial)
	}
	return result
}

// DatagramCapacity forwards the MASQUE underlay's zero-packet report of how
// large a datagram the established QUIC connection will carry. It sends
// nothing: the number was settled by the handshake and by the peer's transport
// parameters before this connection was handed back.
func (c *migratableH3PacketConn) DatagramCapacity() (int, error) {
	reporter, ok := c.PacketConn.(DatagramCapacityReporter)
	if !ok {
		return 0, errors.New(
			"HTTP/3 carrier underlay cannot report its established datagram capacity",
		)
	}
	return reporter.DatagramCapacity()
}

func (c *migratableH3PacketConn) MigratePath(ctx context.Context, socket net.PacketConn) error {
	if ctx == nil || socket == nil {
		if socket != nil {
			_ = socket.Close()
		}
		return errors.New("QUIC migration context and socket are required")
	}
	c.migration.Lock()
	defer c.migration.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = socket.Close()
		return net.ErrClosed
	}
	c.mu.Unlock()

	transport := &quic.Transport{
		Conn:               socket,
		ConnectionIDLength: 8,
	}
	path, err := c.connection.AddPath(transport)
	if err != nil {
		_ = closeOwnedQUICTransport(transport)
		return err
	}
	if err := path.Probe(ctx); err != nil {
		_ = path.Close()
		_ = closeOwnedQUICTransport(transport)
		return err
	}
	if err := path.Switch(); err != nil {
		_ = path.Close()
		_ = closeOwnedQUICTransport(transport)
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = c.connection.CloseWithError(0, "carrier closed during migration")
		_ = closeOwnedQUICTransport(transport)
		return net.ErrClosed
	}
	// The active path's Transport must remain alive for the lifetime of the
	// QUIC connection. Closing the connection first makes later cleanup safe.
	c.transports = append(c.transports, transport)
	c.mu.Unlock()
	return nil
}

// listenUDPSocket is the ONE place this package opens a UDP socket for itself.
// It is a package variable for a single reason: a test can replace it with a
// recorder and prove that the caller-supplied-socket path never reaches it. If
// you add another way to create a transport socket, route it through here or
// that proof silently stops meaning anything.
//
// Production never replaces it.
var listenUDPSocket = func(
	network string,
	local *net.UDPAddr,
) (net.PacketConn, error) {
	return net.ListenUDP(network, local)
}

// dialSuppliedQUIC builds a QUIC transport around a socket the CALLER opened
// and protected. It is the HTTP/3 and MASQUE half of the Android contract.
//
// It never resolves a hostname. On the supplied-socket path the host has
// already resolved the endpoint over the physical underlay; doing it again here
// would put a DNS lookup on the unprotected path before the tunnel exists.
//
// Ownership transfers to the returned transport: closeOwnedQUICTransport closes
// Transport.Conn, so a carrier close closes the supplied socket exactly once.
func dialSuppliedQUIC(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
	supplied *SuppliedPacketSocket,
) (*quic.Conn, *quic.Transport, error) {
	endpoint, err := requireIPLiteralEndpoint(address)
	if err != nil {
		return nil, nil, err
	}
	socket, err := supplied.take()
	if err != nil {
		return nil, nil, err
	}
	transport := &quic.Transport{
		Conn:               socket,
		ConnectionIDLength: 8,
	}
	connection, err := transport.Dial(
		ctx, net.UDPAddrFromAddrPort(endpoint), tlsConfig, quicConfig,
	)
	if err != nil {
		_ = closeOwnedQUICTransport(transport)
		return nil, nil, err
	}
	return connection, transport, nil
}

func dialMigratableQUIC(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, *quic.Transport, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, nil, err
	}
	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, nil, err
	}
	network := "udp4"
	localIP := net.IPv4zero
	if resolved.IP.To4() == nil {
		network = "udp6"
		localIP = net.IPv6unspecified
	}
	socket, err := listenUDPSocket(network, &net.UDPAddr{IP: localIP})
	if err != nil {
		return nil, nil, err
	}
	transport := &quic.Transport{
		Conn:               socket,
		ConnectionIDLength: 8,
	}
	connection, err := transport.Dial(
		ctx, resolved, tlsConfig, quicConfig,
	)
	if err != nil {
		_ = closeOwnedQUICTransport(transport)
		return nil, nil, err
	}
	return connection, transport, nil
}

func (c *migratableH3PacketConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closed = true
	transports := append([]*quic.Transport(nil), c.transports...)
	c.mu.Unlock()

	streamErr := c.PacketConn.Close()
	connectionErr := c.connection.CloseWithError(0, "Winn carrier closed")
	var transportErrors []error
	for _, transport := range transports {
		transportErrors = append(
			transportErrors,
			closeOwnedQUICTransport(transport),
		)
	}
	return errors.Join(append([]error{streamErr, connectionErr}, transportErrors...)...)
}

// closeOwnedQUICTransport closes both quic-go's transport state and the
// application-supplied PacketConn. quic.Transport.Close intentionally does
// not close a Conn supplied by its caller, so every Winn-created transport
// transfers ownership of Transport.Conn to this explicit close path.
func closeOwnedQUICTransport(transport *quic.Transport) error {
	if transport == nil {
		return nil
	}
	socket := transport.Conn
	transportErr := transport.Close()
	var socketErr error
	if socket != nil {
		socketErr = socket.Close()
	}
	if errors.Is(transportErr, net.ErrClosed) {
		transportErr = nil
	}
	if errors.Is(socketErr, net.ErrClosed) {
		socketErr = nil
	}
	return errors.Join(transportErr, socketErr)
}
