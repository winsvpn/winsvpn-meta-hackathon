package carrier

// Caller-supplied transport sockets.
//
// # Why this exists
//
// On Android the outer transport socket must be opened by the HOST and passed
// through VpnService.protect(fd) before any byte leaves the device.
// protect() marks the kernel socket — netd sets the bypass-VPN SO_MARK on the
// struct sock — not the descriptor number. dup(2) and SCM_RIGHTS both create a
// new descriptor onto the same open file description and the same struct sock,
// so the mark travels with a descriptor handed across a process boundary. That
// is what makes the Android handoff sound.
//
// A socket a carrier opens for itself carries no mark. Its packets match the
// routes the VpnService just installed, are written back into the tunnel, are
// encapsulated again, and loop with nothing leaving the device. A raw integer
// fd means nothing in another process, so a subprocess cannot protect its own
// socket after the fact. The order is fixed and not negotiable:
//
//	host opens -> host protects -> host hands over
//
// # What this does not change
//
// Everything here is additive. A dialer with no supplied socket takes exactly
// the path it took before: H3Dialer.dialH3QUIC still calls dialMigratableQUIC,
// and H2Dialer still lets net/http dial its own TCP connection. That path is
// correct on desktop, Linux and Apple, where the outer traffic is excluded by
// route or by NEPacketTunnelProvider, and it is untouched.
//
// # Fail closed, never fall back
//
// A supplied socket is single-use. Once a dial has consumed it, a second dial
// returns ErrSuppliedSocketConsumed rather than opening a replacement, because
// a replacement would be unprotected. Likewise a dialer that has both a
// supplied socket and a custom dial hook returns ErrSuppliedSocketConflict
// instead of guessing. Silently opening a socket is the one failure mode this
// file exists to make impossible.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

// SocketKind names the kind of socket a carrier needs when the caller supplies
// one. It lets a host that holds only a descriptor decide what to adopt it as
// before it ever constructs a dialer.
type SocketKind string

const (
	// SocketKindPacket is an UNCONNECTED UDP socket handed over as a
	// net.PacketConn. QUIC needs this, so the HTTP/3 CONNECT-UDP carrier — the
	// MASQUE carrier; internal/carrier has one dialer for both — takes it.
	//
	// The socket must be unconnected: quic-go drives it with WriteTo, and Go's
	// net package refuses WriteTo on a connected UDPConn.
	SocketKindPacket SocketKind = "packet"

	// SocketKindStream is a CONNECTED, plaintext TCP socket handed over as a
	// net.Conn. The HTTP/2 carrier takes it and layers TLS on top itself, so
	// the caller must not hand over an already-negotiated TLS connection.
	SocketKindStream SocketKind = "stream"
)

var (
	// ErrSuppliedSocketRequired means a nil socket was offered.
	ErrSuppliedSocketRequired = errors.New(
		"winn carrier supplied socket is required",
	)

	// ErrSuppliedSocketConsumed means the single-use socket has already been
	// taken by a dial. The carrier refuses rather than opening an unprotected
	// replacement.
	ErrSuppliedSocketConsumed = errors.New(
		"winn carrier supplied socket has already been consumed: a carrier " +
			"built around a caller-supplied socket is single-use and must fail " +
			"rather than open an unprotected socket of its own",
	)

	// ErrSuppliedSocketConflict means the dialer holds both a supplied socket
	// and a custom dial hook.
	ErrSuppliedSocketConflict = errors.New(
		"winn carrier has both a caller-supplied socket and a custom dial " +
			"hook: refusing rather than guessing which one owns the transport",
	)

	// ErrSuppliedSocketEndpoint means the carrier endpoint is not an IP
	// literal. Resolving a hostname on the supplied-socket path would leak a
	// DNS lookup outside the tunnel before the protected resolver exists. It is
	// the same rule internal/directawg and datapath.validateIPLiteralEndpoint
	// already enforce.
	ErrSuppliedSocketEndpoint = errors.New(
		"winn carrier endpoint must be an IP literal when a socket is supplied",
	)

	// ErrSuppliedSocketPeer means the supplied stream socket is connected to a
	// different peer than the carrier is about to speak to. Handing the carrier
	// a socket pointed somewhere else would tunnel authenticated traffic to an
	// address nobody chose.
	ErrSuppliedSocketPeer = errors.New(
		"winn carrier supplied socket peer does not match the carrier endpoint",
	)

	// ErrSuppliedSocketWrongKind means the carrier asked for a network the
	// supplied socket cannot serve, or the socket is in the wrong state.
	ErrSuppliedSocketWrongKind = errors.New(
		"winn carrier supplied socket is the wrong kind for this carrier",
	)
)

// Dialer is implemented by every carrier. SuppliedSocketDialer narrows it to
// the carriers that can be built around a socket the caller already opened and
// protected.
//
// It is a sibling of Dialer rather than a replacement: Manager keeps consuming
// plain Dialers, and a carrier that has not been converted simply does not
// implement this.
type SuppliedSocketDialer interface {
	Dialer

	// SuppliedSocketKind reports what the caller must hand over.
	SuppliedSocketKind() SocketKind

	// HasSuppliedSocket reports whether one has been supplied. False means the
	// next Dial will open its own socket.
	HasSuppliedSocket() bool
}

// PacketSocketDialer is a SuppliedSocketDialer whose transport is a UDP socket.
type PacketSocketDialer interface {
	SuppliedSocketDialer

	// UseSuppliedSocket adopts an unconnected UDP socket. The carrier takes
	// ownership: closing the carrier closes the socket, and the caller must not
	// close it again.
	UseSuppliedSocket(net.PacketConn) error
}

// StreamSocketDialer is a SuppliedSocketDialer whose transport is a TCP
// connection.
type StreamSocketDialer interface {
	SuppliedSocketDialer

	// UseSuppliedSocket adopts a connected, plaintext TCP connection. The
	// carrier takes ownership.
	UseSuppliedSocket(net.Conn) error
}

// Which carriers have actually been converted. A carrier that is not on this
// list has not been converted, and the datapath must keep refusing it.
//
// HTTP/3 CONNECT-UDP and MASQUE are the SAME dialer here: H3Dialer performs RFC
// 9298 CONNECT-UDP through internal/masque over one QUIC connection. There is
// no separate MASQUE dialer in this module, so converting H3Dialer converts
// both. reality-xhttp, websocket-tls, native-two-hop and privacy-two-hop are
// named in internal/connectivity but have no dialer in this package at all.
var (
	_ PacketSocketDialer = (*H3Dialer)(nil)
	_ StreamSocketDialer = (*H2Dialer)(nil)
)

// SuppliedPacketSocket holds one caller-supplied UDP socket until a dial takes
// it. It is safe for concurrent use.
type SuppliedPacketSocket struct {
	mu    sync.Mutex
	conn  net.PacketConn
	taken bool
}

// NewSuppliedPacketSocket validates and wraps an unconnected UDP socket.
func NewSuppliedPacketSocket(conn net.PacketConn) (*SuppliedPacketSocket, error) {
	if conn == nil {
		return nil, ErrSuppliedSocketRequired
	}
	// quic-go drives the socket with WriteTo, which Go refuses on a connected
	// UDPConn. Catching that here turns a confusing runtime write failure into
	// a configuration error the host can act on.
	if peered, ok := conn.(interface{ RemoteAddr() net.Addr }); ok {
		if remote := peered.RemoteAddr(); remote != nil {
			return nil, fmt.Errorf(
				"%w: UDP socket is already connected to %s; QUIC needs an "+
					"unconnected socket",
				ErrSuppliedSocketWrongKind, remote,
			)
		}
	}
	return &SuppliedPacketSocket{conn: conn}, nil
}

// Taken reports whether a dial has consumed the socket.
func (s *SuppliedPacketSocket) Taken() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.taken
}

// take hands the socket to exactly one dial.
func (s *SuppliedPacketSocket) take() (net.PacketConn, error) {
	if s == nil {
		return nil, ErrSuppliedSocketRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taken {
		return nil, ErrSuppliedSocketConsumed
	}
	s.taken = true
	return s.conn, nil
}

// Close releases the socket only if no dial ever consumed it. After a
// successful dial the carrier owns the socket and closing the carrier is what
// closes it, so Close here is a no-op — calling it is safe on every path.
func (s *SuppliedPacketSocket) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taken || s.conn == nil {
		return nil
	}
	s.taken = true
	err := s.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// SuppliedStreamSocket holds one caller-supplied TCP connection until a dial
// takes it. It is safe for concurrent use.
type SuppliedStreamSocket struct {
	mu    sync.Mutex
	conn  net.Conn
	taken bool
}

// NewSuppliedStreamSocket validates and wraps a connected TCP connection.
func NewSuppliedStreamSocket(conn net.Conn) (*SuppliedStreamSocket, error) {
	if conn == nil {
		return nil, ErrSuppliedSocketRequired
	}
	if conn.RemoteAddr() == nil {
		return nil, fmt.Errorf(
			"%w: TCP connection reports no peer; the host must connect the "+
				"socket before handing it over",
			ErrSuppliedSocketWrongKind,
		)
	}
	return &SuppliedStreamSocket{conn: conn}, nil
}

// Taken reports whether a dial has consumed the connection.
func (s *SuppliedStreamSocket) Taken() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.taken
}

// take hands the connection to exactly one dial, after proving that the address
// net/http asked for is the address the socket is actually connected to.
func (s *SuppliedStreamSocket) take(network, address string) (net.Conn, error) {
	if s == nil {
		return nil, ErrSuppliedSocketRequired
	}
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf(
			"%w: carrier asked for network %q, supplied socket is TCP",
			ErrSuppliedSocketWrongKind, network,
		)
	}
	endpoint, err := requireIPLiteralEndpoint(address)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taken {
		return nil, ErrSuppliedSocketConsumed
	}
	if err := matchesPeer(s.conn.RemoteAddr(), endpoint); err != nil {
		return nil, err
	}
	s.taken = true
	return s.conn, nil
}

// Close releases the connection only if no dial ever consumed it. See
// SuppliedPacketSocket.Close.
func (s *SuppliedStreamSocket) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taken || s.conn == nil {
		return nil
	}
	s.taken = true
	err := s.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// requireIPLiteralEndpoint parses "ip:port" and refuses a hostname.
func requireIPLiteralEndpoint(address string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf(
			"%w: %q does not parse as an IP literal with a port (%v)",
			ErrSuppliedSocketEndpoint, address, err,
		)
	}
	if endpoint.Port() == 0 || !endpoint.Addr().IsValid() ||
		endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return netip.AddrPort{}, fmt.Errorf(
			"%w: %q is not a routable unicast endpoint",
			ErrSuppliedSocketEndpoint, address,
		)
	}
	return endpoint, nil
}

// matchesPeer compares a socket's peer with the endpoint the carrier intends to
// speak to. IPv4-mapped IPv6 peers are unmapped first so a dual-stack socket
// reporting ::ffff:127.0.0.1 still matches 127.0.0.1.
func matchesPeer(remote net.Addr, endpoint netip.AddrPort) error {
	if remote == nil {
		return fmt.Errorf("%w: socket reports no peer", ErrSuppliedSocketPeer)
	}
	peer, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return fmt.Errorf(
			"%w: peer %q does not parse (%v)",
			ErrSuppliedSocketPeer, remote.String(), err,
		)
	}
	if peer.Port() != endpoint.Port() ||
		peer.Addr().Unmap() != endpoint.Addr().Unmap() {
		return fmt.Errorf(
			"%w: socket peer is %s, carrier endpoint is %s",
			ErrSuppliedSocketPeer, peer, endpoint,
		)
	}
	return nil
}
