package stagebreflector

import (
	"context"
	"crypto/hmac"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

var (
	ErrPrivateAddress   = errors.New("private bind address")
	ErrPrivateInterface = errors.New("private bind interface")
	ErrPrivateClient    = errors.New("private client allowlist")
	ErrPrivateBusy      = errors.New("private server busy")
	ErrPrivateWindow    = errors.New("private request window")
)

// ResolvedInterface freezes a kernel interface index and its numeric addresses.
type ResolvedInterface struct {
	Index     int
	Addresses []netip.Addr
}

type InterfaceAddressResolver func(interfaceName string) (ResolvedInterface, error)

// PrivateUnixMillisecondClock reports trusted wall time or a local clock
// failure. The server calls it only after source and request authentication.
type PrivateUnixMillisecondClock func() (uint64, error)

// SystemInterfaceAddressResolver resolves only an exact interface name. It
// performs no hostname or DNS lookup.
func SystemInterfaceAddressResolver(interfaceName string) (ResolvedInterface, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil || iface.Index <= 0 {
		return ResolvedInterface{}, ErrPrivateInterface
	}
	rawAddresses, err := iface.Addrs()
	if err != nil {
		return ResolvedInterface{}, ErrPrivateInterface
	}
	addresses := make([]netip.Addr, 0, len(rawAddresses))
	for _, rawAddress := range rawAddresses {
		addressText := rawAddress.String()
		if slash := strings.LastIndexByte(addressText, '/'); slash >= 0 {
			addressText = addressText[:slash]
		}
		address, parseErr := netip.ParseAddr(addressText)
		if parseErr != nil {
			return ResolvedInterface{}, ErrPrivateInterface
		}
		addresses = append(addresses, address)
	}
	return ResolvedInterface{Index: iface.Index, Addresses: addresses}, nil
}

type privateUDPConnection interface {
	ReadMsgUDPAddrPort(
		payload []byte,
		outOfBand []byte,
	) (payloadLength int, outOfBandLength int, flags int, source netip.AddrPort, err error)
	WriteMsgUDPAddrPort(
		payload []byte,
		outOfBand []byte,
		destination netip.AddrPort,
	) (payloadLength int, outOfBandLength int, err error)
	SetReadDeadline(deadline time.Time) error
	Close() error
}

type privateUDPListenFunc func(
	network string,
	address *net.UDPAddr,
) (privateUDPConnection, error)

type privateInterfaceController interface {
	Configure(
		connection privateUDPConnection,
		network string,
		bindAddress netip.Addr,
		interfaceIndex int,
	) error
	ControlMessageSize(network string) int
	InboundInterfaceIndex(network string, control []byte) (int, error)
	WriteResponse(
		connection privateUDPConnection,
		network string,
		payload []byte,
		destination netip.AddrPort,
		bindAddress netip.Addr,
		interfaceIndex int,
	) (int, error)
}

// PrivateUDPServer is a one-datagram-at-a-time private-interface server. It
// neither forwards traffic nor retains client identifiers. Packet rejection is
// silent; only local transport, interface, and clock failures are returned.
type PrivateUDPServer struct {
	initialized    bool
	connection     privateUDPConnection
	reflector      *Reflector
	clock          PrivateUnixMillisecondClock
	controller     privateInterfaceController
	network        string
	interfaceIndex int
	bindAddress    netip.AddrPort
	allowedClient  netip.Addr
	admitted       atomic.Bool
	closed         atomic.Bool
}

// ParsePrivateInterfaceUDPBinding validates a private numeric endpoint, an
// exact interface name/index, and one private /32 or /128 client prefix.
func ParsePrivateInterfaceUDPBinding(
	address string,
	interfaceName string,
	allowedClientPrefix string,
	resolver InterfaceAddressResolver,
) (netip.AddrPort, netip.Addr, int, error) {
	var zeroAddress netip.AddrPort
	var zeroClient netip.Addr

	if interfaceName == "" ||
		strings.TrimSpace(interfaceName) != interfaceName ||
		strings.ContainsRune(interfaceName, '\x00') ||
		resolver == nil {
		return zeroAddress, zeroClient, 0, ErrPrivateInterface
	}
	bindAddress, err := netip.ParseAddrPort(address)
	if err != nil ||
		bindAddress.Port() == 0 ||
		!isPrivateUnicast(bindAddress.Addr()) {
		return zeroAddress, zeroClient, 0, ErrPrivateAddress
	}
	clientPrefix, err := netip.ParsePrefix(allowedClientPrefix)
	if err != nil ||
		clientPrefix.Bits() != clientPrefix.Addr().BitLen() ||
		!isPrivateUnicast(clientPrefix.Addr()) ||
		clientPrefix.Addr() == bindAddress.Addr() ||
		clientPrefix.Addr().Is4() != bindAddress.Addr().Is4() {
		return zeroAddress, zeroClient, 0, ErrPrivateClient
	}
	identity, err := resolver(interfaceName)
	if err != nil ||
		identity.Index <= 0 ||
		!resolvedInterfaceContains(identity, bindAddress.Addr()) {
		return zeroAddress, zeroClient, 0, ErrPrivateInterface
	}
	return bindAddress, clientPrefix.Addr(), identity.Index, nil
}

func resolvedInterfaceContains(identity ResolvedInterface, wanted netip.Addr) bool {
	for _, address := range identity.Addresses {
		if address.IsValid() &&
			address.Zone() == "" &&
			!address.Is4In6() &&
			address == wanted {
			return true
		}
	}
	return false
}

// ListenPrivateInterfaceUDP opens a private-interface reflector socket. It
// fails closed on platforms where ingress and egress interface confinement
// cannot be enforced.
func ListenPrivateInterfaceUDP(
	address string,
	interfaceName string,
	allowedClientPrefix string,
	key []byte,
	cacheCapacity int,
	clock PrivateUnixMillisecondClock,
	resolver InterfaceAddressResolver,
) (*PrivateUDPServer, error) {
	return listenPrivateInterfaceUDP(
		address,
		interfaceName,
		allowedClientPrefix,
		key,
		cacheCapacity,
		clock,
		resolver,
		func(network string, address *net.UDPAddr) (privateUDPConnection, error) {
			return net.ListenUDP(network, address)
		},
		systemPrivateInterfaceController(),
	)
}

func listenPrivateInterfaceUDP(
	address string,
	interfaceName string,
	allowedClientPrefix string,
	key []byte,
	cacheCapacity int,
	clock PrivateUnixMillisecondClock,
	resolver InterfaceAddressResolver,
	listen privateUDPListenFunc,
	controller privateInterfaceController,
) (*PrivateUDPServer, error) {
	if clock == nil {
		return nil, ErrClock
	}
	if listen == nil {
		return nil, ErrClosed
	}
	if controller == nil {
		return nil, ErrPrivateInterface
	}
	bindAddress, allowedClient, interfaceIndex, err :=
		ParsePrivateInterfaceUDPBinding(
			address,
			interfaceName,
			allowedClientPrefix,
			resolver,
		)
	if err != nil {
		return nil, err
	}
	reflector, err := NewReflector(key, cacheCapacity)
	if err != nil {
		return nil, err
	}
	network := "udp6"
	if bindAddress.Addr().Is4() {
		network = "udp4"
	}
	connection, err := listen(network, net.UDPAddrFromAddrPort(bindAddress))
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, ErrRead
	}

	// Re-resolve after bind so an address or interface replacement between
	// validation and socket creation cannot silently change the confinement.
	postBind, resolveErr := resolver(interfaceName)
	if resolveErr != nil ||
		postBind.Index != interfaceIndex ||
		!resolvedInterfaceContains(postBind, bindAddress.Addr()) {
		_ = connection.Close()
		return nil, ErrPrivateInterface
	}
	if err := controller.Configure(
		connection,
		network,
		bindAddress.Addr(),
		interfaceIndex,
	); err != nil {
		_ = connection.Close()
		return nil, ErrPrivateInterface
	}
	server, err := newPrivateUDPServer(
		connection,
		reflector,
		clock,
		controller,
		network,
		interfaceIndex,
		bindAddress,
		allowedClient,
	)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return server, nil
}

func newPrivateUDPServer(
	connection privateUDPConnection,
	reflector *Reflector,
	clock PrivateUnixMillisecondClock,
	controller privateInterfaceController,
	network string,
	interfaceIndex int,
	bindAddress netip.AddrPort,
	allowedClient netip.Addr,
) (*PrivateUDPServer, error) {
	if connection == nil ||
		reflector == nil ||
		reflector.cache == nil ||
		clock == nil ||
		controller == nil ||
		(network != "udp4" && network != "udp6") ||
		interfaceIndex <= 0 ||
		controller.ControlMessageSize(network) <= 0 ||
		controller.ControlMessageSize(network) > 256 ||
		bindAddress.Port() == 0 ||
		!isPrivateUnicast(bindAddress.Addr()) ||
		!isPrivateUnicast(allowedClient) ||
		allowedClient == bindAddress.Addr() ||
		allowedClient.Is4() != bindAddress.Addr().Is4() ||
		(network == "udp4") != bindAddress.Addr().Is4() {
		return nil, ErrClosed
	}
	return &PrivateUDPServer{
		initialized:    true,
		connection:     connection,
		reflector:      reflector,
		clock:          clock,
		controller:     controller,
		network:        network,
		interfaceIndex: interfaceIndex,
		bindAddress:    bindAddress,
		allowedClient:  allowedClient,
	}, nil
}

func isPrivateUnicast(address netip.Addr) bool {
	return address.IsValid() &&
		address.Zone() == "" &&
		!address.Is4In6() &&
		address.IsPrivate() &&
		!address.IsUnspecified() &&
		!address.IsMulticast()
}

func (server *PrivateUDPServer) LocalAddr() netip.AddrPort {
	if !server.valid() {
		return netip.AddrPort{}
	}
	return server.bindAddress
}

// ServeOne reads at most one datagram. Source/interface, framing,
// authentication, request-window, replay, and capacity failures are silent.
func (server *PrivateUDPServer) ServeOne(ctx context.Context) error {
	if !server.valid() {
		return ErrClosed
	}
	if ctx == nil {
		return ErrCancelled
	}
	select {
	case <-ctx.Done():
		return ErrCancelled
	default:
	}
	if !server.admitted.CompareAndSwap(false, true) {
		return ErrPrivateBusy
	}
	defer server.admitted.Store(false)

	if err := server.connection.SetReadDeadline(time.Time{}); err != nil {
		if server.closed.Load() {
			return ErrClosed
		}
		return ErrRead
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if err := server.connection.SetReadDeadline(deadline); err != nil {
			if server.closed.Load() {
				return ErrClosed
			}
			return ErrRead
		}
	}
	cancelDeadlineSet := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = server.connection.SetReadDeadline(time.Now())
		close(cancelDeadlineSet)
	})

	var datagram [RequestLength]byte
	control := make([]byte, server.controller.ControlMessageSize(server.network))
	n, controlLength, flags, source, readErr :=
		server.connection.ReadMsgUDPAddrPort(datagram[:], control)
	if !stopCancellation() {
		<-cancelDeadlineSet
	}
	if server.closed.Load() {
		return ErrClosed
	}
	if err := server.connection.SetReadDeadline(time.Time{}); err != nil {
		if server.closed.Load() {
			return ErrClosed
		}
		return ErrRead
	}
	if server.closed.Load() {
		return ErrClosed
	}
	if ctx.Err() != nil ||
		(hasDeadline && !deadline.After(time.Now())) {
		return ErrCancelled
	}
	if readErr != nil {
		return ErrRead
	}

	if flags != 0 ||
		n != RequestLength ||
		controlLength <= 0 ||
		controlLength > len(control) ||
		!source.IsValid() ||
		source.Addr().Zone() != "" ||
		source.Addr().Is4In6() ||
		source.Addr() != server.allowedClient {
		return nil
	}
	inboundIndex, err := server.controller.InboundInterfaceIndex(
		server.network,
		control[:controlLength],
	)
	if err != nil || inboundIndex != server.interfaceIndex {
		return nil
	}

	// Authenticate before consulting wall time. An attacker-controlled stale or
	// future unauthenticated packet therefore cannot manufacture ErrClock.
	verified, err := verifyPrivateRequest(datagram[:n], server.reflector.key[:])
	if err != nil {
		if isSilentPrivatePacketError(err) {
			return nil
		}
		return err
	}
	if err := server.stopError(ctx); err != nil {
		return err
	}
	received, clockErr := server.clock()
	if err := server.stopError(ctx); err != nil {
		return err
	}
	if clockErr != nil {
		return ErrClock
	}
	sent, clockErr := server.clock()
	if err := server.stopError(ctx); err != nil {
		return err
	}
	if clockErr != nil {
		return ErrClock
	}
	response, err := server.reflector.encodePrivateVerified(
		verified,
		received,
		sent,
	)
	if err != nil {
		if isSilentPrivatePacketError(err) {
			return nil
		}
		return err
	}
	if err := server.stopError(ctx); err != nil {
		return err
	}
	if err := server.reflector.cache.Use(
		verified.Tag,
		verified.Request.ExpiresAtUnixMilliseconds,
		received,
	); err != nil {
		if isSilentPrivatePacketError(err) {
			return nil
		}
		return err
	}
	if err := server.stopError(ctx); err != nil {
		return err
	}
	written, err := server.controller.WriteResponse(
		server.connection,
		server.network,
		response,
		source,
		server.bindAddress.Addr(),
		server.interfaceIndex,
	)
	if err != nil || written != len(response) {
		return ErrWrite
	}
	return nil
}

func verifyPrivateRequest(datagram, key []byte) (VerifiedRequest, error) {
	var verified VerifiedRequest
	if err := validateKey(key); err != nil {
		return verified, err
	}
	if len(datagram) != RequestLength {
		return verified, ErrDatagramLength
	}
	request, body, err := decodeAndValidateBody(datagram[:CommonBodyLength], 1)
	if err != nil {
		return verified, err
	}
	expected := authenticate(key, requestDomain, datagram[:CommonBodyLength])
	if !hmac.Equal(expected[:], datagram[CommonBodyLength:RequestLength]) {
		return verified, ErrAuthentication
	}
	verified.Request = request
	verified.Body = body
	copy(verified.Tag[:], datagram[CommonBodyLength:RequestLength])
	return verified, nil
}

func (reflector *Reflector) encodePrivateVerified(
	verified VerifiedRequest,
	receivedUnixMilliseconds uint64,
	sentUnixMilliseconds uint64,
) ([]byte, error) {
	if reflector == nil || reflector.cache == nil {
		return nil, ErrClosed
	}
	if receivedUnixMilliseconds < verified.Request.IssuedAtUnixMilliseconds ||
		receivedUnixMilliseconds > verified.Request.ExpiresAtUnixMilliseconds {
		return nil, ErrPrivateWindow
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
	return response, nil
}

// stopError classifies a local Close ahead of context cancellation when both
// are observable at one checkpoint. A cancellation or Close can still race
// with the immediately following cache or socket operation; no userspace
// checkpoint can make those independent operations atomic.
func (server *PrivateUDPServer) stopError(ctx context.Context) error {
	if server.closed.Load() {
		return ErrClosed
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

func isSilentPrivatePacketError(err error) bool {
	return errors.Is(err, ErrDatagramLength) ||
		errors.Is(err, ErrFixedField) ||
		errors.Is(err, ErrRequiredField) ||
		errors.Is(err, ErrLifetime) ||
		errors.Is(err, ErrAuthentication) ||
		errors.Is(err, ErrPrivateWindow) ||
		errors.Is(err, ErrReplay) ||
		errors.Is(err, ErrCacheFull)
}

func (server *PrivateUDPServer) valid() bool {
	if server == nil ||
		!server.initialized ||
		server.closed.Load() ||
		server.connection == nil ||
		server.reflector == nil ||
		server.reflector.cache == nil ||
		server.clock == nil ||
		server.controller == nil ||
		(server.network != "udp4" && server.network != "udp6") ||
		server.interfaceIndex <= 0 ||
		server.bindAddress.Port() == 0 ||
		!isPrivateUnicast(server.bindAddress.Addr()) ||
		!isPrivateUnicast(server.allowedClient) ||
		server.allowedClient == server.bindAddress.Addr() ||
		server.allowedClient.Is4() != server.bindAddress.Addr().Is4() ||
		(server.network == "udp4") != server.bindAddress.Addr().Is4() {
		return false
	}
	size := server.controller.ControlMessageSize(server.network)
	return size > 0 && size <= 256
}

func (server *PrivateUDPServer) Close() error {
	if server == nil || !server.initialized {
		return nil
	}
	if !server.closed.CompareAndSwap(false, true) {
		return nil
	}
	if server.connection == nil {
		return ErrClosed
	}
	if err := server.connection.Close(); err != nil {
		return ErrClosed
	}
	return nil
}
