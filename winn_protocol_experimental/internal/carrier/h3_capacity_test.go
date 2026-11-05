package carrier

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// TestQUICHandshakeAlreadyProvesTheCarrierPath is the measurement behind
// deleting the HTTP/3 carrier's MTU probe.
//
// The probe existed to establish that the path carries a full-size Winn
// envelope. The claim tested here is that a completed QUIC handshake has
// already established it, in both directions, before the probe would have sent
// its first datagram -- so the probe was measuring something already known, and
// its only distinctive contribution was a failure mode a censor could trigger.
//
// The argument, and what each part of this test measures against the vendored
// quic-go rather than against its documentation:
//
//   - h3QUICConfig pins InitialPacketSize to H3InitialPacketSize(maxOuter).
//   - quic-go pads every client Initial packet to that size
//     (packet_packer.go, initialPaddingLen), so the ClientHello cannot reach the
//     server unless the path carries a datagram of that size. Subtest
//     "client datagrams above the floor dropped" measures this.
//   - The server pins the same floor, and its own first flight is padded to it
//     too, so the same holds in reverse. Subtest "server datagrams above the
//     floor dropped" measures this -- it is the direction the probe's
//     same-sized acknowledgement used to cover, and the reason this test checks
//     both rather than assuming symmetry.
//   - The floor leaves room for a full-size envelope plus HTTP datagram
//     framing. Subtest "uncensored" measures the capacity quic-go reports, with
//     zero packets on the wire.
//
// If a future quic-go stops padding client Initials, or the server's flight
// stops being padded, the censored subtests start passing the handshake and
// this test fails. That is the point: the reasoning is only as good as the
// version it was measured against.
func TestQUICHandshakeAlreadyProvesTheCarrierPath(t *testing.T) {
	const maxOuter = DefaultMaxDatagram + envelopeHeaderSize
	floor := int(H3InitialPacketSize(maxOuter))
	if floor <= maxOuter {
		t.Fatalf(
			"InitialPacketSize floor %d leaves no room for a %d-byte envelope",
			floor, maxOuter,
		)
	}

	for _, testCase := range []struct {
		name          string
		upLimit       int
		downLimit     int
		wantHandshake bool
	}{
		{
			name:          "uncensored",
			wantHandshake: true,
		},
		{
			// The censor-inducible teardown the probe used to hand out was
			// triggered by dropping exactly this size class. Dropping it now
			// stops the connection at the QUIC handshake, where every ordinary
			// QUIC client also stops.
			name:          "client datagrams above the floor dropped",
			upLimit:       floor - 1,
			wantHandshake: false,
		},
		{
			name:          "server datagrams above the floor dropped",
			downLimit:     floor - 1,
			wantHandshake: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			relay, connection := dialThroughSizeCensoringRelay(
				t, maxOuter, testCase.upLimit, testCase.downLimit,
			)
			if !testCase.wantHandshake {
				if connection != nil {
					t.Fatal(
						"handshake completed through a path that cannot carry " +
							"the configured Initial packet size; the carrier " +
							"can no longer infer the path from the handshake",
					)
				}
				return
			}
			if connection == nil {
				t.Fatal("handshake failed on an uncensored path")
			}

			// Every client datagram of the handshake is the padded floor.
			// Nothing smaller is a separate size class an observer could use to
			// tell the handshake apart, and nothing larger was required.
			for index, size := range relay.clientSizes() {
				if size != floor {
					t.Fatalf(
						"client handshake datagram %d was %d bytes, want the "+
							"padded floor %d",
						index, size, floor,
					)
				}
			}

			// The value the carrier reads instead of probing. Reading it emits
			// nothing: SendDatagram rejects an impossible size before it
			// queues anything.
			capacity := readQUICDatagramCapacity(t, connection)
			// The MASQUE write path spends a quarter stream ID varint and a
			// context ID on top of the envelope.
			const maximumHTTPDatagramFraming = 9
			if capacity-maximumHTTPDatagramFraming < maxOuter {
				t.Fatalf(
					"QUIC reports %d bytes of datagram capacity; a %d-byte "+
						"envelope plus %d bytes of HTTP datagram framing does "+
						"not fit, so the probe was not redundant",
					capacity, maxOuter, maximumHTTPDatagramFraming,
				)
			}
		})
	}
}

// readQUICDatagramCapacity reads quic-go's current datagram limit by asking it
// for a size no UDP datagram can ever be. SendDatagram checks the length before
// it copies or queues anything, so this costs zero bytes on the wire -- the
// same mechanism internal/masque.(*Conn).DatagramCapacity uses.
func readQUICDatagramCapacity(t *testing.T, connection *quic.Conn) int {
	t.Helper()
	err := connection.SendDatagram(make([]byte, 1<<16))
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf(
			"capacity query returned %v, want a DatagramTooLargeError carrying "+
				"the current limit", err,
		)
	}
	return int(tooLarge.MaxDatagramPayloadSize)
}

// sizeCensoringRelay is the adversary: a UDP forwarder that silently drops
// datagrams larger than a per-direction limit. A zero limit forwards everything.
type sizeCensoringRelay struct {
	upLimit   int
	downLimit int

	mu     sync.Mutex
	upSize []int
}

func (r *sizeCensoringRelay) clientSizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.upSize...)
}

// dialThroughSizeCensoringRelay runs a real quic-go handshake between a client
// and server that both pin H3InitialPacketSize(maxOuter), through a relay that
// censors by datagram size. It returns a nil connection when the handshake did
// not complete.
func dialThroughSizeCensoringRelay(
	t *testing.T, maxOuter, upLimit, downLimit int,
) (*sizeCensoringRelay, *quic.Conn) {
	t.Helper()
	lab := generateCarrierLab(t)
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tlsconfig.ServerAnonymousForALPN(
		lab.ServerCert, lab.ServerKey, suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := tlsconfig.ClientAnonymousForALPN(
		lab.CACert, "127.0.0.1", suite, http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	quicConfig := &quic.Config{
		EnableDatagrams:      true,
		Allow0RTT:            false,
		InitialPacketSize:    H3InitialPacketSize(maxOuter),
		HandshakeIdleTimeout: 2 * time.Second,
		MaxIdleTimeout:       5 * time.Second,
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, quicConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			serverConnection, acceptErr := listener.Accept(context.Background())
			if acceptErr != nil {
				return
			}
			t.Cleanup(func() {
				_ = serverConnection.CloseWithError(0, "")
			})
		}
	}()

	relay := &sizeCensoringRelay{upLimit: upLimit, downLimit: downLimit}
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = front.Close() })
	back, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = back.Close() })

	serverAddr, ok := listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listener address %T is not a UDP address", listener.Addr())
	}
	var clientAddrMu sync.Mutex
	var clientAddr *net.UDPAddr
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, addr, readErr := front.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			clientAddrMu.Lock()
			clientAddr = addr
			clientAddrMu.Unlock()
			relay.mu.Lock()
			relay.upSize = append(relay.upSize, count)
			relay.mu.Unlock()
			if relay.upLimit > 0 && count > relay.upLimit {
				continue
			}
			_, _ = back.WriteToUDP(buffer[:count], serverAddr)
		}
	}()
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, _, readErr := back.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if relay.downLimit > 0 && count > relay.downLimit {
				continue
			}
			clientAddrMu.Lock()
			destination := clientAddr
			clientAddrMu.Unlock()
			if destination == nil {
				continue
			}
			_, _ = front.WriteToUDP(buffer[:count], destination)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	connection, err := quic.DialAddr(
		ctx, front.LocalAddr().String(), clientTLS, quicConfig,
	)
	if err != nil {
		return relay, nil
	}
	t.Cleanup(func() { _ = connection.CloseWithError(0, "") })
	return relay, connection
}

// TestConfirmDatagramCapacityFailsClosedWithoutSendingAnything pins the two
// properties the deleted probe used to provide and the one it did not.
//
// Provided: the carrier refuses an underlay that cannot carry a full-size
// envelope, and it accepts one that can. Not provided: doing either without
// putting datagrams on the wire, which is what removes the censor's trigger.
func TestConfirmDatagramCapacityFailsClosedWithoutSendingAnything(t *testing.T) {
	const (
		maxInner = DefaultMaxDatagram
		maxOuter = DefaultMaxDatagram + envelopeHeaderSize
	)
	for _, testCase := range []struct {
		name       string
		capacity   int
		report     error
		wantAccept bool
	}{
		{name: "exactly enough", capacity: maxOuter, wantAccept: true},
		{name: "room to spare", capacity: maxOuter + 25, wantAccept: true},
		{name: "one byte short", capacity: maxOuter - 1},
		{name: "underlay cannot report", report: errors.New("no capacity")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			left, right := memoryPacketPair()
			defer right.Close()
			raw := &capacityReportingPacketConn{
				channelPacketConn: left,
				capacity:          testCase.capacity,
				err:               testCase.report,
			}
			client, err := newEnvelopePacketConn(raw, EnvelopeConfig{
				MaxInnerDatagram: maxInner,
				MaxOuterDatagram: maxOuter,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			_, confirmErr := client.ConfirmDatagramCapacity()
			if testCase.wantAccept && confirmErr != nil {
				t.Fatalf(
					"capacity %d rejected: %v", testCase.capacity, confirmErr,
				)
			}
			if !testCase.wantAccept && confirmErr == nil {
				t.Fatalf(
					"capacity %d accepted; a carrier that cannot carry a "+
						"full-size envelope must fail closed",
					testCase.capacity,
				)
			}
			if writes := raw.writes.Load(); writes != 0 {
				t.Fatalf(
					"capacity confirmation wrote %d datagrams; it must write "+
						"none, or the censor's trigger is back",
					writes,
				)
			}
		})
	}
}

// TestConfirmDatagramCapacityRejectsAnUnreportableUnderlay covers the carrier
// whose underlay has no established handshake to read -- it must fail closed
// rather than assume.
func TestConfirmDatagramCapacityRejectsAnUnreportableUnderlay(t *testing.T) {
	left, right := memoryPacketPair()
	defer right.Close()
	client, err := newEnvelopePacketConn(left, EnvelopeConfig{
		MaxInnerDatagram: DefaultMaxDatagram,
		MaxOuterDatagram: DefaultMaxDatagram + envelopeHeaderSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.ConfirmDatagramCapacity(); err == nil {
		t.Fatal(
			"an underlay that cannot report its capacity was accepted; " +
				"nothing has established that the path carries an envelope",
		)
	}
}

type capacityReportingPacketConn struct {
	*channelPacketConn
	capacity int
	err      error
	writes   atomic.Int32
}

func (c *capacityReportingPacketConn) DatagramCapacity() (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	return c.capacity, nil
}

func (c *capacityReportingPacketConn) WriteTo(
	packet []byte, address net.Addr,
) (int, error) {
	c.writes.Add(1)
	return c.channelPacketConn.WriteTo(packet, address)
}
