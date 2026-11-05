package stagebreflector

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const privateTestInterfaceIndex = 7

type privateTestPacket struct {
	payload        []byte
	flags          int
	source         netip.AddrPort
	interfaceIndex int
	err            error
}

type privateTestWrite struct {
	payload        []byte
	destination    netip.AddrPort
	interfaceIndex int
}

type privateTestConnection struct {
	mu          sync.Mutex
	packet      privateTestPacket
	writes      []privateTestWrite
	readStarted chan struct{}
	readRelease chan struct{}
	releaseOnce sync.Once
	writeErr    error
	shortWrite  bool
	deadlineErr error
	closeErr    error
	closed      atomic.Bool
}

type privateTestController struct {
	configureErr error
	configured   atomic.Int32
}

func (controller *privateTestController) Configure(
	_ privateUDPConnection,
	_ string,
	_ netip.Addr,
	interfaceIndex int,
) error {
	controller.configured.Store(int32(interfaceIndex))
	return controller.configureErr
}

func (*privateTestController) ControlMessageSize(string) int { return 4 }

func (*privateTestController) InboundInterfaceIndex(
	_ string,
	control []byte,
) (int, error) {
	if len(control) != 4 {
		return 0, ErrPrivateInterface
	}
	return int(binary.BigEndian.Uint32(control)), nil
}

func (*privateTestController) WriteResponse(
	connection privateUDPConnection,
	_ string,
	payload []byte,
	destination netip.AddrPort,
	_ netip.Addr,
	interfaceIndex int,
) (int, error) {
	control := make([]byte, 4)
	binary.BigEndian.PutUint32(control, uint32(interfaceIndex))
	n, controlN, err := connection.WriteMsgUDPAddrPort(
		payload,
		control,
		destination,
	)
	if err != nil || controlN != len(control) {
		return n, ErrWrite
	}
	return n, nil
}

func (connection *privateTestConnection) ReadMsgUDPAddrPort(
	payload []byte,
	control []byte,
) (int, int, int, netip.AddrPort, error) {
	if connection.readStarted != nil {
		select {
		case connection.readStarted <- struct{}{}:
		default:
		}
	}
	if connection.readRelease != nil {
		<-connection.readRelease
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	n := copy(payload, connection.packet.payload)
	controlN := 0
	if connection.packet.interfaceIndex > 0 && len(control) >= 4 {
		binary.BigEndian.PutUint32(control, uint32(connection.packet.interfaceIndex))
		controlN = 4
	}
	return n, controlN, connection.packet.flags,
		connection.packet.source, connection.packet.err
}

func (connection *privateTestConnection) WriteMsgUDPAddrPort(
	payload []byte,
	control []byte,
	destination netip.AddrPort,
) (int, int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.writeErr != nil {
		return 0, 0, connection.writeErr
	}
	interfaceIndex := 0
	if len(control) == 4 {
		interfaceIndex = int(binary.BigEndian.Uint32(control))
	}
	connection.writes = append(connection.writes, privateTestWrite{
		payload:        append([]byte{}, payload...),
		destination:    destination,
		interfaceIndex: interfaceIndex,
	})
	if connection.shortWrite {
		return len(payload) - 1, len(control), nil
	}
	return len(payload), len(control), nil
}

func (connection *privateTestConnection) SetReadDeadline(deadline time.Time) error {
	if connection.deadlineErr != nil {
		return connection.deadlineErr
	}
	if connection.readRelease != nil &&
		!deadline.IsZero() &&
		!deadline.After(time.Now()) {
		connection.releaseOnce.Do(func() { close(connection.readRelease) })
	}
	return nil
}

func (connection *privateTestConnection) Close() error {
	connection.closed.Store(true)
	if connection.readRelease != nil {
		connection.releaseOnce.Do(func() { close(connection.readRelease) })
	}
	return connection.closeErr
}

func privateResolver(addresses ...string) InterfaceAddressResolver {
	return func(string) (ResolvedInterface, error) {
		resolved := make([]netip.Addr, 0, len(addresses))
		for _, address := range addresses {
			resolved = append(resolved, netip.MustParseAddr(address))
		}
		return ResolvedInterface{
			Index:     privateTestInterfaceIndex,
			Addresses: resolved,
		}, nil
	}
}

func privateClock(value uint64) PrivateUnixMillisecondClock {
	return func() (uint64, error) { return value, nil }
}

func privateSequenceClock(values ...uint64) PrivateUnixMillisecondClock {
	var index atomic.Int32
	return func() (uint64, error) {
		next := int(index.Add(1)) - 1
		if next >= len(values) {
			return values[len(values)-1], nil
		}
		return values[next], nil
	}
}

func privateServerForPacket(
	t *testing.T,
	bindAddress string,
	allowedClient string,
	packet privateTestPacket,
	clock PrivateUnixMillisecondClock,
) (*PrivateUDPServer, *privateTestConnection) {
	t.Helper()
	if packet.interfaceIndex == 0 {
		packet.interfaceIndex = privateTestInterfaceIndex
	}
	reflector, err := NewReflector(publicKey(), 4)
	if err != nil {
		t.Fatal(err)
	}
	connection := &privateTestConnection{packet: packet}
	network := "udp6"
	if netip.MustParseAddrPort(bindAddress).Addr().Is4() {
		network = "udp4"
	}
	server, err := newPrivateUDPServer(
		connection,
		reflector,
		clock,
		&privateTestController{},
		network,
		privateTestInterfaceIndex,
		netip.MustParseAddrPort(bindAddress),
		netip.MustParseAddr(allowedClient),
	)
	if err != nil {
		t.Fatal(err)
	}
	return server, connection
}

func TestPrivateBindingAcceptsExactIPv4AndIPv6(t *testing.T) {
	tests := []struct {
		bind, client, ifaceAddr string
	}{
		{"10.203.1.1:9999", "10.203.1.16/32", "10.203.1.1"},
		{"[fd00:203::1]:9999", "fd00:203::16/128", "fd00:203::1"},
	}
	for _, test := range tests {
		bind, client, index, err := ParsePrivateInterfaceUDPBinding(
			test.bind, "winn-gw0", test.client, privateResolver(test.ifaceAddr),
		)
		if err != nil {
			t.Fatal(err)
		}
		if bind != netip.MustParseAddrPort(test.bind) ||
			client != netip.MustParsePrefix(test.client).Addr() ||
			index != privateTestInterfaceIndex {
			t.Fatalf("binding = %s client = %s index = %d", bind, client, index)
		}
	}
}

func TestPrivateBindingRejectsUnsafeInputs(t *testing.T) {
	for _, address := range []string{
		"gateway.internal:9999", "0.0.0.0:9999", "[::]:9999",
		"127.0.0.1:9999", "192.0.2.1:9999", "10.203.1.1:0",
		"[fe80::1]:9999", "[fd00:203::1%winn-gw0]:9999",
		"[::ffff:10.203.1.1]:9999", "",
	} {
		if _, _, _, err := ParsePrivateInterfaceUDPBinding(
			address, "winn-gw0", "10.203.1.16/32",
			privateResolver("10.203.1.1"),
		); !errors.Is(err, ErrPrivateAddress) {
			t.Fatalf("%q accepted or wrong error: %v", address, err)
		}
	}
	for _, interfaceName := range []string{"", " winn-gw0", "winn-gw0 ", "winn\x00gw0"} {
		if _, _, _, err := ParsePrivateInterfaceUDPBinding(
			"10.203.1.1:9999", interfaceName, "10.203.1.16/32",
			privateResolver("10.203.1.1"),
		); !errors.Is(err, ErrPrivateInterface) {
			t.Fatalf("interface %q: %v", interfaceName, err)
		}
	}
	for _, client := range []string{
		"10.203.1.16", "10.203.1.16/28", "127.0.0.1/32",
		"192.0.2.1/32", "10.203.1.1/32", "fd00:203::16/128", "",
	} {
		if _, _, _, err := ParsePrivateInterfaceUDPBinding(
			"10.203.1.1:9999", "winn-gw0", client,
			privateResolver("10.203.1.1"),
		); !errors.Is(err, ErrPrivateClient) {
			t.Fatalf("client %q: %v", client, err)
		}
	}
}

func TestPrivateBindingRejectsInvalidInterfaceIdentity(t *testing.T) {
	resolvers := []InterfaceAddressResolver{
		privateResolver("10.203.1.2"),
		func(string) (ResolvedInterface, error) {
			return ResolvedInterface{
				Index:     0,
				Addresses: []netip.Addr{netip.MustParseAddr("10.203.1.1")},
			}, nil
		},
		func(string) (ResolvedInterface, error) {
			return ResolvedInterface{}, errors.New("sensitive")
		},
	}
	for _, resolver := range resolvers {
		if _, _, _, err := ParsePrivateInterfaceUDPBinding(
			"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32", resolver,
		); !errors.Is(err, ErrPrivateInterface) ||
			err.Error() != ErrPrivateInterface.Error() {
			t.Fatalf("resolver failure leaked or accepted: %v", err)
		}
	}
}

func TestPrivateListenerFreezesAndRechecksInterfaceIdentity(t *testing.T) {
	var calls atomic.Int32
	resolver := func(string) (ResolvedInterface, error) {
		call := calls.Add(1)
		index := privateTestInterfaceIndex
		if call == 2 {
			index++
		}
		return ResolvedInterface{
			Index:     index,
			Addresses: []netip.Addr{netip.MustParseAddr("10.203.1.1")},
		}, nil
	}
	connection := &privateTestConnection{}
	_, err := listenPrivateInterfaceUDP(
		"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32",
		publicKey(), 4, privateClock(deterministicRequest().IssuedAtUnixMilliseconds),
		resolver,
		func(string, *net.UDPAddr) (privateUDPConnection, error) {
			return connection, nil
		},
		&privateTestController{},
	)
	if !errors.Is(err, ErrPrivateInterface) || !connection.closed.Load() {
		t.Fatalf("swap was not rejected/closed: err=%v closed=%v", err, connection.closed.Load())
	}
}

func TestPrivateListenerUsesExactFamilyAndCleansPartialFailure(t *testing.T) {
	controller := &privateTestController{}
	connection := &privateTestConnection{}
	var family string
	server, err := listenPrivateInterfaceUDP(
		"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32",
		publicKey(), 4, privateClock(deterministicRequest().IssuedAtUnixMilliseconds),
		privateResolver("10.203.1.1"),
		func(network string, address *net.UDPAddr) (privateUDPConnection, error) {
			family = network
			if address.AddrPort() != netip.MustParseAddrPort("10.203.1.1:9999") {
				t.Fatalf("address = %s", address)
			}
			return connection, nil
		},
		controller,
	)
	if err != nil {
		t.Fatal(err)
	}
	if family != "udp4" ||
		controller.configured.Load() != privateTestInterfaceIndex {
		t.Fatalf("family=%q configured=%d", family, controller.configured.Load())
	}
	_ = server.Close()

	partial := &privateTestConnection{}
	_, err = listenPrivateInterfaceUDP(
		"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32",
		publicKey(), 4, privateClock(1), privateResolver("10.203.1.1"),
		func(string, *net.UDPAddr) (privateUDPConnection, error) {
			return partial, errors.New("listen")
		},
		&privateTestController{},
	)
	if !errors.Is(err, ErrRead) || !partial.closed.Load() {
		t.Fatalf("partial listener cleanup: err=%v closed=%v", err, partial.closed.Load())
	}

	configureConnection := &privateTestConnection{}
	_, err = listenPrivateInterfaceUDP(
		"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32",
		publicKey(), 4, privateClock(1), privateResolver("10.203.1.1"),
		func(string, *net.UDPAddr) (privateUDPConnection, error) {
			return configureConnection, nil
		},
		&privateTestController{configureErr: errors.New("sensitive configure detail")},
	)
	if !errors.Is(err, ErrPrivateInterface) ||
		err.Error() != ErrPrivateInterface.Error() ||
		!configureConnection.closed.Load() {
		t.Fatalf(
			"configure cleanup: err=%v closed=%v",
			err,
			configureConnection.closed.Load(),
		)
	}
}

func TestPrivateServeOneRoundTripAndPinsEgress(t *testing.T) {
	for _, test := range []struct {
		bind, client, source string
	}{
		{"10.203.1.1:9999", "10.203.1.16", "10.203.1.16:49152"},
		{"[fd00:203::1]:9999", "fd00:203::16", "[fd00:203::16]:49152"},
	} {
		request := deterministicRequest()
		encoded, err := EncodeRequest(publicKey(), request)
		if err != nil {
			t.Fatal(err)
		}
		server, connection := privateServerForPacket(
			t, test.bind, test.client,
			privateTestPacket{
				payload: encoded,
				source:  netip.MustParseAddrPort(test.source),
			},
			privateSequenceClock(
				request.IssuedAtUnixMilliseconds+1,
				request.IssuedAtUnixMilliseconds+2,
			),
		)
		if err := server.ServeOne(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(connection.writes) != 1 ||
			connection.writes[0].destination != netip.MustParseAddrPort(test.source) ||
			connection.writes[0].interfaceIndex != privateTestInterfaceIndex {
			t.Fatalf("writes = %+v", connection.writes)
		}
		_ = server.Close()
	}
}

func TestPrivateServeOneDropsWrongSourceInterfaceAndFramingBeforeClock(t *testing.T) {
	request := deterministicRequest()
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	tests := []privateTestPacket{
		{
			payload: encoded,
			source:  netip.MustParseAddrPort("10.203.1.17:49152"),
		},
		{
			payload:        encoded,
			source:         netip.MustParseAddrPort("10.203.1.16:49152"),
			interfaceIndex: privateTestInterfaceIndex + 1,
		},
		{
			payload: append(append([]byte{}, encoded...), 0),
			flags:   1,
			source:  netip.MustParseAddrPort("10.203.1.16:49152"),
		},
		{
			payload: encoded[:len(encoded)-1],
			source:  netip.MustParseAddrPort("10.203.1.16:49152"),
		},
	}
	for _, packet := range tests {
		var clockCalls atomic.Int32
		server, connection := privateServerForPacket(
			t, "10.203.1.1:9999", "10.203.1.16", packet,
			func() (uint64, error) {
				clockCalls.Add(1)
				return request.IssuedAtUnixMilliseconds, nil
			},
		)
		if err := server.ServeOne(context.Background()); err != nil {
			t.Fatalf("drop was not silent: %v", err)
		}
		if clockCalls.Load() != 0 || len(connection.writes) != 0 {
			t.Fatalf("drop reached clock/write: %d/%d", clockCalls.Load(), len(connection.writes))
		}
		_ = server.Close()
	}
}

func TestPrivateServeOneAuthenticatesBeforeWindowAndClock(t *testing.T) {
	request := deterministicRequest()
	request.IssuedAtUnixMilliseconds = 10_000
	request.ExpiresAtUnixMilliseconds = 10_100
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("10.203.1.16:49152")

	mutated := append([]byte{}, encoded...)
	mutated[len(mutated)-1] ^= 1
	var unauthClockCalls atomic.Int32
	unauthServer, unauthConnection := privateServerForPacket(
		t, "10.203.1.1:9999", "10.203.1.16",
		privateTestPacket{payload: mutated, source: source},
		func() (uint64, error) {
			unauthClockCalls.Add(1)
			return 1, errors.New("must not be called")
		},
	)
	if err := unauthServer.ServeOne(context.Background()); err != nil {
		t.Fatalf("unauthenticated stale packet was terminal: %v", err)
	}
	if unauthClockCalls.Load() != 0 || len(unauthConnection.writes) != 0 {
		t.Fatal("unauthenticated packet reached clock or write")
	}
	_ = unauthServer.Close()

	for _, now := range []uint64{9_999, 10_101} {
		server, connection := privateServerForPacket(
			t, "10.203.1.1:9999", "10.203.1.16",
			privateTestPacket{payload: encoded, source: source},
			privateClock(now),
		)
		if err := server.ServeOne(context.Background()); err != nil {
			t.Fatalf("authenticated out-of-window packet was terminal: %v", err)
		}
		if len(connection.writes) != 0 || server.reflector.cache.Len() != 0 {
			t.Fatal("out-of-window packet was written or cached")
		}
		_ = server.Close()
	}
}

func TestPrivateServeOneReplaySilentAndLocalFailuresTerminal(t *testing.T) {
	request := deterministicRequest()
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("10.203.1.16:49152")
	server, connection := privateServerForPacket(
		t, "10.203.1.1:9999", "10.203.1.16",
		privateTestPacket{payload: encoded, source: source},
		privateClock(request.IssuedAtUnixMilliseconds),
	)
	if err := server.ServeOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := server.ServeOne(context.Background()); err != nil {
		t.Fatalf("replay was terminal: %v", err)
	}
	if len(connection.writes) != 1 {
		t.Fatalf("replay writes = %d", len(connection.writes))
	}
	_ = server.Close()

	clockServer, _ := privateServerForPacket(
		t, "10.203.1.1:9999", "10.203.1.16",
		privateTestPacket{payload: encoded, source: source},
		func() (uint64, error) { return 0, errors.New("clock") },
	)
	if err := clockServer.ServeOne(context.Background()); !errors.Is(err, ErrClock) {
		t.Fatalf("local clock failure: %v", err)
	}
	_ = clockServer.Close()

	writeServer, writeConnection := privateServerForPacket(
		t, "10.203.1.1:9999", "10.203.1.16",
		privateTestPacket{payload: encoded, source: source},
		privateClock(request.IssuedAtUnixMilliseconds),
	)
	writeConnection.shortWrite = true
	if err := writeServer.ServeOne(context.Background()); !errors.Is(err, ErrWrite) {
		t.Fatalf("short write: %v", err)
	}
	_ = writeServer.Close()
}

func TestPrivateServeOneStopsDuringInjectedClockWithoutReplayOrWrite(t *testing.T) {
	request := deterministicRequest()
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("10.203.1.16:49152")
	tests := []struct {
		name      string
		blockCall int32
		stop      func(context.CancelFunc, *PrivateUDPServer)
		want      error
	}{
		{
			name:      "cancel during received clock",
			blockCall: 1,
			stop: func(cancel context.CancelFunc, _ *PrivateUDPServer) {
				cancel()
			},
			want: ErrCancelled,
		},
		{
			name:      "close during sent clock",
			blockCall: 2,
			stop: func(_ context.CancelFunc, server *PrivateUDPServer) {
				if err := server.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			},
			want: ErrClosed,
		},
		{
			name:      "close precedes simultaneous cancellation",
			blockCall: 1,
			stop: func(cancel context.CancelFunc, server *PrivateUDPServer) {
				cancel()
				if err := server.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			},
			want: ErrClosed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reached := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			clock := func() (uint64, error) {
				call := calls.Add(1)
				if call == test.blockCall {
					close(reached)
					<-release
					return 0, errors.New("simultaneous injected clock failure")
				}
				return request.IssuedAtUnixMilliseconds, nil
			}
			server, connection := privateServerForPacket(
				t, "10.203.1.1:9999", "10.203.1.16",
				privateTestPacket{payload: encoded, source: source},
				clock,
			)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- server.ServeOne(ctx) }()
			select {
			case <-reached:
			case <-time.After(2 * time.Second):
				t.Fatal("injected clock was not reached")
			}
			test.stop(cancel, server)
			close(release)
			select {
			case serveErr := <-result:
				if !errors.Is(serveErr, test.want) {
					t.Fatalf("classification = %v, want %v", serveErr, test.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("ServeOne did not stop")
			}
			if server.reflector.cache.Len() != 0 || len(connection.writes) != 0 {
				t.Fatalf(
					"stopped request mutated state: cache=%d writes=%d",
					server.reflector.cache.Len(),
					len(connection.writes),
				)
			}
			cancel()
			_ = server.Close()
		})
	}
}

func TestPrivateServeOneCancellationCloseAndAdmissionClassification(t *testing.T) {
	newBlockingServer := func(t *testing.T) (*PrivateUDPServer, *privateTestConnection) {
		t.Helper()
		request := deterministicRequest()
		reflector, err := NewReflector(publicKey(), 4)
		if err != nil {
			t.Fatal(err)
		}
		connection := &privateTestConnection{
			readStarted: make(chan struct{}, 1),
			readRelease: make(chan struct{}),
			packet: privateTestPacket{
				err:            errors.New("unblocked"),
				source:         netip.MustParseAddrPort("10.203.1.16:49152"),
				interfaceIndex: privateTestInterfaceIndex,
			},
		}
		server, err := newPrivateUDPServer(
			connection, reflector,
			privateClock(request.IssuedAtUnixMilliseconds),
			&privateTestController{}, "udp4", privateTestInterfaceIndex,
			netip.MustParseAddrPort("10.203.1.1:9999"),
			netip.MustParseAddr("10.203.1.16"),
		)
		if err != nil {
			t.Fatal(err)
		}
		return server, connection
	}

	cancelServer, cancelConnection := newBlockingServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- cancelServer.ServeOne(ctx) }()
	<-cancelConnection.readStarted
	if err := cancelServer.ServeOne(context.Background()); !errors.Is(err, ErrPrivateBusy) {
		t.Fatalf("admission: %v", err)
	}
	cancel()
	if err := <-result; !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancellation: %v", err)
	}
	_ = cancelServer.Close()

	closeServer, closeConnection := newBlockingServer(t)
	closeResult := make(chan error, 1)
	go func() { closeResult <- closeServer.ServeOne(context.Background()) }()
	<-closeConnection.readStarted
	if err := closeServer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-closeResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("close classification: %v", err)
	}

	deadlineServer, _ := newBlockingServer(t)
	deadlineContext, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	if err := deadlineServer.ServeOne(deadlineContext); !errors.Is(err, ErrCancelled) {
		t.Fatalf("deadline classification: %v", err)
	}
	_ = deadlineServer.Close()
}

func TestPrivateConstructorsFailClosed(t *testing.T) {
	request := deterministicRequest()
	validClock := privateClock(request.IssuedAtUnixMilliseconds)
	validResolver := privateResolver("10.203.1.1")
	validListener := func(string, *net.UDPAddr) (privateUDPConnection, error) {
		return &privateTestConnection{}, nil
	}
	controller := &privateTestController{}
	if _, err := listenPrivateInterfaceUDP(
		"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32",
		publicKey(), 4, nil, validResolver, validListener, controller,
	); !errors.Is(err, ErrClock) {
		t.Fatalf("nil clock: %v", err)
	}
	if _, err := listenPrivateInterfaceUDP(
		"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32",
		publicKey(), 4, validClock, validResolver, nil, controller,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil listener: %v", err)
	}
	if _, err := listenPrivateInterfaceUDP(
		"10.203.1.1:9999", "winn-gw0", "10.203.1.16/32",
		publicKey(), 4, validClock, validResolver, validListener, nil,
	); !errors.Is(err, ErrPrivateInterface) {
		t.Fatalf("nil controller: %v", err)
	}

	var nilServer *PrivateUDPServer
	if err := nilServer.ServeOne(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil server: %v", err)
	}
	if err := (&PrivateUDPServer{}).ServeOne(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("malformed server: %v", err)
	}
}
