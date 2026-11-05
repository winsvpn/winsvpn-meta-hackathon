package carrier

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnvelopePaddingRoundTripAndTamperRejection(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 777)
	encoded, err := encodeEnvelope(envelopeData, 42, payload, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 1024 {
		t.Fatalf("padded length = %d", len(encoded))
	}
	decoded, err := decodeEnvelope(encoded, 1350)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.sequence != 42 || !bytes.Equal(decoded.payload, payload) {
		t.Fatalf("decoded envelope = %#v", decoded)
	}
	encoded[0] ^= 1
	if _, err := decodeEnvelope(encoded, 1350); err == nil {
		t.Fatal("tampered envelope accepted")
	}
}

func TestEnvelopeMTUProbeAndData(t *testing.T) {
	clientRaw, serverRaw := memoryPacketPair()
	client, err := newEnvelopePacketConn(clientRaw, EnvelopeConfig{
		MaxInnerDatagram:     1350,
		MaxOuterDatagram:     1400,
		DisableLengthPadding: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer serverRaw.Close()
	go func() {
		buffer := make([]byte, 1501)
		for {
			count, _, readErr := serverRaw.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			frame, decodeErr := decodeEnvelope(buffer[:count], 1350)
			if decodeErr != nil {
				continue
			}
			switch frame.kind {
			case envelopeProbe:
				if count != 1400 {
					t.Errorf(
						"privacy MTU probe size = %d, want padded wire size 1400",
						count,
					)
				}
				ack, _ := encodeEnvelope(envelopeProbeAck, frame.sequence, nil, count)
				_, _ = serverRaw.WriteTo(ack, nil)
			case envelopeData:
				reply, _ := encodeEnvelope(envelopeData, frame.sequence, frame.payload, count)
				_, _ = serverRaw.WriteTo(reply, nil)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	mtu, err := client.ProbeMTU(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if mtu != 1350 || client.EffectiveMTU() != 1350 {
		t.Fatalf("effective MTU = %d", mtu)
	}
	payload := bytes.Repeat([]byte("x"), 1350)
	if count, err := client.WriteTo(payload, nil); err != nil || count != len(payload) {
		t.Fatalf("write = %d, %v", count, err)
	}
	buffer := make([]byte, 1350)
	count, _, err := client.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:count], payload) {
		t.Fatal("enveloped data mismatch")
	}
}

// TestEnvelopeMTUProbeSendsExactlyOneDatagram replaces
// TestEnvelopeMTUProbeRetransmitsWithoutIdentifyingBurst, which pinned the
// opposite: that a lost probe is retransmitted on a jittered schedule.
//
// The retransmission was the defect, not the defence. The only production
// caller left is the HTTP/2 carrier, whose underlay is a reliable ordered TCP
// stream: a second identical datagram cannot deliver anything TCP has not
// already delivered. What the retries did buy was a censor-triggerable
// behaviour -- drop the client's datagrams of one size class and every
// connection emits three to six same-size datagrams over one to two seconds and
// then tears down. One datagram has no schedule to read.
func TestEnvelopeMTUProbeSendsExactlyOneDatagram(t *testing.T) {
	clientRaw, serverRaw := memoryPacketPair()
	client, err := newEnvelopePacketConn(clientRaw, EnvelopeConfig{
		MaxInnerDatagram: 1350,
		MaxOuterDatagram: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer serverRaw.Close()

	var probes atomic.Int32
	go serveMTUProbeAcks(serverRaw, func(packetSize int, _ envelope) bool {
		probes.Add(1)
		// Discovery follows the padding decision, so the expected size is
		// whatever an ordinary full-size data datagram already occupies.
		// Comparing against that rather than a literal keeps the property the
		// test exists for -- discovery must never probe below the signed AWG
		// size, and must never be a size of its own -- true in both padding
		// modes.
		expected := client.outerSize(1350 + envelopeHeaderSize)
		if packetSize != expected || packetSize < 1350+envelopeHeaderSize {
			t.Errorf(
				"probe size = %d, want the %d a full-size data datagram uses "+
					"and never below the signed AWG carrier size %d",
				packetSize, expected, 1350+envelopeHeaderSize,
			)
		}
		return true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	mtu, err := client.ProbeMTU(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if mtu != 1350 {
		t.Fatalf("effective MTU = %d, want the signed 1350", mtu)
	}
	if elapsed := time.Since(started); elapsed > mtuProbeMaxBudget {
		t.Fatalf(
			"discovery took %s, want within the %s budget",
			elapsed, mtuProbeMaxBudget,
		)
	}
	// Give any stray retransmission the whole former retry window to appear.
	time.Sleep(700 * time.Millisecond)
	if count := probes.Load(); count != mtuProbeTransmissions {
		t.Fatalf(
			"discovery sent %d datagrams, want exactly %d: a retry schedule is "+
				"a pattern a censor can induce by dropping one size class",
			count, mtuProbeTransmissions,
		)
	}
	maximumPayload := bytes.Repeat([]byte{0x5a}, 1350)
	if count, err := client.WriteTo(maximumPayload, nil); err != nil ||
		count != len(maximumPayload) {
		t.Fatalf("maximum post-probe data write = %d, %v", count, err)
	}
}

// TestEnvelopeMTUProbeUnderCensorshipEmitsNoBurst is the adversarial half: it
// models exactly the attack -- every client datagram of the probe's size class
// is dropped -- and pins what the client may do about it.
//
// It may send one datagram and it may fail closed. It may not produce a
// repeating pattern of same-size datagrams, because that pattern is what makes
// the teardown a remotely-triggerable identifier rather than an ordinary
// timeout.
func TestEnvelopeMTUProbeUnderCensorshipEmitsNoBurst(t *testing.T) {
	raw := newRecordingDeadlinePacketConn()
	client, err := newEnvelopePacketConn(raw, EnvelopeConfig{
		MaxInnerDatagram: 1350,
		MaxOuterDatagram: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The 2 s budget both carrier dialers wrap around the probe.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.ProbeMTU(ctx); err == nil {
		t.Fatal("probe succeeded with every datagram dropped; it must fail closed")
	}
	sizes := raw.Sizes()
	if len(sizes) != mtuProbeTransmissions {
		t.Fatalf(
			"censored setup put %d datagrams on the wire (%v), want exactly %d",
			len(sizes), sizes, mtuProbeTransmissions,
		)
	}
	if mtu := client.EffectiveMTU(); mtu != 1350 {
		t.Fatalf("censored probe changed effective MTU to %d", mtu)
	}
}

func TestEnvelopeMTUProbeCancellationInterruptsReadAndStopsSender(t *testing.T) {
	raw := newDeadlineBlockingPacketConn()
	client, err := newEnvelopePacketConn(raw, EnvelopeConfig{
		MaxInnerDatagram: 1350,
		MaxOuterDatagram: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := client.ProbeMTU(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ProbeMTU error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("ProbeMTU cancellation took %s", elapsed)
	}
	writesAfterReturn := raw.writes.Load()
	time.Sleep(350 * time.Millisecond)
	if got := raw.writes.Load(); got != writesAfterReturn {
		t.Fatalf("sender continued after ProbeMTU returned: %d -> %d writes", writesAfterReturn, got)
	}
}

func TestEnvelopeMTUProbeDoesNotFalseDowngradeSignedAWGSize(t *testing.T) {
	raw := newRecordingDeadlinePacketConn()
	client, err := newEnvelopePacketConn(raw, EnvelopeConfig{
		MaxInnerDatagram: 1350,
		MaxOuterDatagram: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 650*time.Millisecond)
	defer cancel()
	if _, err := client.ProbeMTU(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ProbeMTU error = %v, want context deadline", err)
	}
	if mtu := client.EffectiveMTU(); mtu != 1350 {
		t.Fatalf("effective MTU = %d, want unchanged signed-AWG size 1350", mtu)
	}
	sizes := raw.Sizes()
	if len(sizes) != mtuProbeTransmissions {
		t.Fatalf(
			"probe transmissions = %d, want exactly %d",
			len(sizes), mtuProbeTransmissions,
		)
	}
	required := client.outerSize(1350 + envelopeHeaderSize)
	for _, size := range sizes {
		if size != required || size < 1350+envelopeHeaderSize {
			t.Fatalf(
				"probe sizes = %v, want only the %d a full-size data datagram "+
					"uses and never below the signed AWG size %d",
				sizes, required, 1350+envelopeHeaderSize,
			)
		}
	}
}

func TestEnvelopeMTUProbeExplicitSizeRejectionFailsClosed(t *testing.T) {
	raw := &writeErrorPacketConn{
		deadlineBlockingPacketConn: newDeadlineBlockingPacketConn(),
		err:                        ErrDatagramTooLarge,
	}
	client, err := newEnvelopePacketConn(raw, EnvelopeConfig{
		MaxInnerDatagram: 1350,
		MaxOuterDatagram: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.ProbeMTU(context.Background()); !errors.Is(
		err, ErrDatagramTooLarge,
	) {
		t.Fatalf("ProbeMTU error = %v, want explicit size rejection", err)
	}
	if mtu := client.EffectiveMTU(); mtu != 1350 {
		t.Fatalf("explicit rejection changed effective MTU to %d", mtu)
	}
}

func TestEnvelopeMTUProbeRejectsUndersizedValidAcknowledgement(t *testing.T) {
	raw := newUndersizedAckPacketConn()
	client, err := newEnvelopePacketConn(raw, EnvelopeConfig{
		MaxInnerDatagram:     1350,
		MaxOuterDatagram:     1400,
		DisableLengthPadding: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.ProbeMTU(context.Background()); err == nil {
		t.Fatal("undersized acknowledgement for a valid sequence was accepted")
	}
	if mtu := client.EffectiveMTU(); mtu != 1350 {
		t.Fatalf("undersized acknowledgement changed effective MTU to %d", mtu)
	}
}

func TestEnvelopeMTUProbeRejectsDeadlineInstallationFailure(t *testing.T) {
	left, right := memoryPacketPair()
	raw := &deadlineErrorPacketConn{
		channelPacketConn: left,
		err:               errors.New("deadline unavailable"),
	}
	client, err := newEnvelopePacketConn(raw, EnvelopeConfig{
		MaxInnerDatagram: 1350,
		MaxOuterDatagram: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer right.Close()

	if _, err := client.ProbeMTU(context.Background()); !errors.Is(err, raw.err) {
		t.Fatalf("ProbeMTU error = %v, want %v", err, raw.err)
	}
}

func TestEnvelopeMigrationConsumesUnsupportedSocket(t *testing.T) {
	left, right := memoryPacketPair()
	client, err := newEnvelopePacketConn(left, EnvelopeConfig{
		MaxInnerDatagram: 1350,
		MaxOuterDatagram: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer right.Close()
	socket := &closeCountingPacketConn{}
	if err := client.MigratePath(
		context.Background(),
		socket,
	); err == nil {
		t.Fatal("unsupported migration unexpectedly succeeded")
	}
	if count := socket.closes.Load(); count != 1 {
		t.Fatalf("unsupported migration socket closes = %d, want 1", count)
	}
}

func serveMTUProbeAcks(
	server net.PacketConn,
	shouldAcknowledge func(int, envelope) bool,
) {
	buffer := make([]byte, AbsoluteMaxCarrierEnvelope+1)
	for {
		count, _, err := server.ReadFrom(buffer)
		if err != nil {
			return
		}
		frame, err := decodeEnvelope(buffer[:count], AbsoluteMaxDatagram)
		if err != nil || frame.kind != envelopeProbe ||
			!shouldAcknowledge(count, frame) {
			continue
		}
		ack, err := encodeEnvelope(
			envelopeProbeAck,
			frame.sequence,
			nil,
			count,
		)
		if err != nil {
			continue
		}
		_, _ = server.WriteTo(ack, nil)
		clear(ack)
	}
}

type channelPacketConn struct {
	incoming chan []byte
	peer     *channelPacketConn
	closed   chan struct{}
	once     sync.Once
}

func memoryPacketPair() (*channelPacketConn, *channelPacketConn) {
	left := &channelPacketConn{incoming: make(chan []byte, 16), closed: make(chan struct{})}
	right := &channelPacketConn{incoming: make(chan []byte, 16), closed: make(chan struct{})}
	left.peer = right
	right.peer = left
	return left, right
}

func (c *channelPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case packet := <-c.incoming:
		return copy(buffer, packet), fixedAddr("memory"), nil
	}
}

func (c *channelPacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	case c.peer.incoming <- append([]byte(nil), packet...):
		return len(packet), nil
	}
}

func (c *channelPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *channelPacketConn) LocalAddr() net.Addr              { return fixedAddr("memory") }
func (c *channelPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *channelPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *channelPacketConn) SetWriteDeadline(time.Time) error { return nil }

type deadlineErrorPacketConn struct {
	*channelPacketConn
	err error
}

func (c *deadlineErrorPacketConn) SetDeadline(time.Time) error {
	return c.err
}

type deadlineBlockingPacketConn struct {
	mu       sync.Mutex
	deadline time.Time
	update   chan struct{}
	closed   chan struct{}
	close    sync.Once
	writes   atomic.Int32
}

func newDeadlineBlockingPacketConn() *deadlineBlockingPacketConn {
	return &deadlineBlockingPacketConn{
		update: make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (c *deadlineBlockingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		deadline := c.deadline
		update := c.update
		c.mu.Unlock()

		if deadline.IsZero() {
			select {
			case <-c.closed:
				return 0, nil, net.ErrClosed
			case <-update:
				continue
			}
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(wait)
		select {
		case <-c.closed:
			timer.Stop()
			return 0, nil, net.ErrClosed
		case <-update:
			timer.Stop()
			continue
		case <-timer.C:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *deadlineBlockingPacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		c.writes.Add(1)
		return len(packet), nil
	}
}

func (c *deadlineBlockingPacketConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	return nil
}

func (*deadlineBlockingPacketConn) LocalAddr() net.Addr {
	return fixedAddr("deadline-blocking")
}

func (c *deadlineBlockingPacketConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	close(c.update)
	c.deadline = deadline
	c.update = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *deadlineBlockingPacketConn) SetReadDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

func (c *deadlineBlockingPacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

type recordingDeadlinePacketConn struct {
	*deadlineBlockingPacketConn
	sizesMu sync.Mutex
	sizes   []int
}

func newRecordingDeadlinePacketConn() *recordingDeadlinePacketConn {
	return &recordingDeadlinePacketConn{
		deadlineBlockingPacketConn: newDeadlineBlockingPacketConn(),
	}
}

func (c *recordingDeadlinePacketConn) WriteTo(
	packet []byte,
	_ net.Addr,
) (int, error) {
	c.sizesMu.Lock()
	c.sizes = append(c.sizes, len(packet))
	c.sizesMu.Unlock()
	c.writes.Add(1)
	return len(packet), nil
}

func (c *recordingDeadlinePacketConn) Sizes() []int {
	c.sizesMu.Lock()
	defer c.sizesMu.Unlock()
	return append([]int(nil), c.sizes...)
}

type writeErrorPacketConn struct {
	*deadlineBlockingPacketConn
	err error
}

func (c *writeErrorPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, c.err
}

type undersizedAckPacketConn struct {
	ack       chan []byte
	writeOnce sync.Once
	closeOnce sync.Once
	closed    chan struct{}
}

func newUndersizedAckPacketConn() *undersizedAckPacketConn {
	return &undersizedAckPacketConn{
		ack:    make(chan []byte, 1),
		closed: make(chan struct{}),
	}
}

func (c *undersizedAckPacketConn) ReadFrom(
	buffer []byte,
) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case packet, ok := <-c.ack:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		return copy(buffer, packet), fixedAddr("undersized-ack"), nil
	}
}

func (c *undersizedAckPacketConn) WriteTo(
	packet []byte,
	_ net.Addr,
) (int, error) {
	frame, err := decodeEnvelope(packet, AbsoluteMaxDatagram)
	if err != nil {
		return 0, err
	}
	c.writeOnce.Do(func() {
		ack, _ := encodeEnvelope(
			envelopeProbeAck,
			frame.sequence,
			nil,
			envelopeHeaderSize,
		)
		c.ack <- ack
		close(c.ack)
	})
	return len(packet), nil
}

func (c *undersizedAckPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*undersizedAckPacketConn) LocalAddr() net.Addr {
	return fixedAddr("undersized-ack")
}

func (*undersizedAckPacketConn) SetDeadline(time.Time) error      { return nil }
func (*undersizedAckPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*undersizedAckPacketConn) SetWriteDeadline(time.Time) error { return nil }
