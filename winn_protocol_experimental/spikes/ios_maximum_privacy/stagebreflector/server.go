package stagebreflector

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Reflector composes the pure request verifier, bounded replay cache, and
// response encoder. It does not perform network I/O.
type Reflector struct {
	key   [KeyLength]byte
	cache *ReplayCache
}

func NewReflector(key []byte, cacheCapacity int) (*Reflector, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	cache, err := NewReplayCache(cacheCapacity)
	if err != nil {
		return nil, err
	}
	reflector := &Reflector{cache: cache}
	copy(reflector.key[:], key)
	return reflector, nil
}

func (reflector *Reflector) Process(
	datagram []byte,
	nowUnixMilliseconds uint64,
	receivedUnixMilliseconds uint64,
	sentUnixMilliseconds uint64,
) ([]byte, error) {
	if reflector == nil || reflector.cache == nil {
		return nil, ErrClosed
	}
	verified, err := VerifyRequest(datagram, reflector.key[:], nowUnixMilliseconds)
	if err != nil {
		return nil, err
	}
	response, err := EncodeResponse(
		reflector.key[:],
		verified,
		receivedUnixMilliseconds,
		sentUnixMilliseconds,
	)
	if err != nil {
		return nil, err
	}
	if err := reflector.cache.Use(
		verified.Tag,
		verified.Request.ExpiresAtUnixMilliseconds,
		nowUnixMilliseconds,
	); err != nil {
		return nil, err
	}
	return response, nil
}

// ParseLoopbackUDPAddress accepts only numeric literal 127.0.0.1 or ::1 UDP
// endpoints. Host names, zones, wildcard, unspecified, and other addresses are
// rejected without DNS resolution.
func ParseLoopbackUDPAddress(address string) (*net.UDPAddr, error) {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, ErrLoopbackAddress
	}
	addressPart := addrPort.Addr()
	if addressPart != netip.MustParseAddr("127.0.0.1") &&
		addressPart != netip.IPv6Loopback() {
		return nil, ErrLoopbackAddress
	}
	return net.UDPAddrFromAddrPort(addrPort), nil
}

// UnixMillisecondClock supplies an injected reflector wall clock.
type UnixMillisecondClock func() uint64

// UDPServer is a one-datagram-at-a-time loopback reference server.
type UDPServer struct {
	connection *net.UDPConn
	reflector  *Reflector
	clock      UnixMillisecondClock
	admission  chan struct{}
}

func ListenLoopbackUDP(
	address string,
	key []byte,
	cacheCapacity int,
	clock UnixMillisecondClock,
) (*UDPServer, error) {
	if clock == nil {
		return nil, ErrClock
	}
	udpAddress, err := ParseLoopbackUDPAddress(address)
	if err != nil {
		return nil, err
	}
	reflector, err := NewReflector(key, cacheCapacity)
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return nil, ErrRead
	}
	server := &UDPServer{
		connection: connection,
		reflector:  reflector,
		clock:      clock,
		admission:  make(chan struct{}, 1),
	}
	server.admission <- struct{}{}
	return server, nil
}

// LocalAddr returns the numeric loopback endpoint selected by the OS.
func (server *UDPServer) LocalAddr() netip.AddrPort {
	if server == nil || server.connection == nil {
		return netip.AddrPort{}
	}
	return server.connection.LocalAddr().(*net.UDPAddr).AddrPort()
}

// ServeOne reads and handles exactly one UDP datagram. Invalid datagrams get
// no response. Errors never incorporate the source address or packet bytes.
func (server *UDPServer) ServeOne(ctx context.Context) error {
	if server == nil || server.connection == nil || server.reflector == nil {
		return ErrClosed
	}
	if ctx == nil {
		return ErrCancelled
	}
	select {
	case <-ctx.Done():
		return ErrCancelled
	case <-server.admission:
	}
	defer func() { server.admission <- struct{}{} }()

	if err := server.connection.SetReadDeadline(time.Time{}); err != nil {
		return ErrRead
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := server.connection.SetReadDeadline(deadline); err != nil {
			return ErrRead
		}
	}
	cancelDeadlineSet := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = server.connection.SetReadDeadline(time.Now())
		close(cancelDeadlineSet)
	})
	buffer := make([]byte, 65_535)
	n, source, err := server.connection.ReadFromUDP(buffer)
	if !stopCancellation() {
		<-cancelDeadlineSet
	}
	if clearErr := server.connection.SetReadDeadline(time.Time{}); clearErr != nil {
		return ErrRead
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if err != nil {
		return ErrRead
	}
	received := server.clock()
	sent := server.clock()
	response, err := server.reflector.Process(buffer[:n], received, received, sent)
	if err != nil {
		return err
	}
	if _, err := server.connection.WriteToUDP(response, source); err != nil {
		return ErrWrite
	}
	return nil
}

func (server *UDPServer) Close() error {
	if server == nil || server.connection == nil {
		return nil
	}
	if err := server.connection.Close(); err != nil {
		return ErrClosed
	}
	return nil
}
