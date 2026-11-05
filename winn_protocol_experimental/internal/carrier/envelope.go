package carrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	envelopeHeaderSize         = 16
	CarrierEnvelopeOverhead    = envelopeHeaderSize
	AbsoluteMaxCarrierEnvelope = AbsoluteMaxDatagram + envelopeHeaderSize
	// Path MTU discovery must not identify the protocol, and must not hand a
	// censor a behaviour they can trigger.
	//
	// Discovery used to send three identical maximum-size datagrams back to
	// back and then retransmit on a 300 ms metronome for up to 16
	// transmissions. That was shortened to one datagram at a time on a jittered
	// schedule, up to six transmissions. Both versions had the same defect, and
	// the jitter did not fix it: an adversary who drops the client's datagrams
	// of that one size class induces a burst of same-size datagrams followed by
	// a connection teardown, on demand, on every connection. That is worse than
	// a passive signature, because the censor does not have to wait for it.
	//
	// Discovery now sends exactly one datagram, after a jittered start delay,
	// within a jittered budget, padded to the size an ordinary full-size data
	// datagram already uses -- and only on a carrier whose underlay cannot
	// answer the question by itself. The HTTP/3 carrier answers it from its own
	// completed QUIC handshake and sends nothing at all; see
	// ConfirmDatagramCapacity. The HTTP/2 carrier rides a reliable ordered
	// stream, where an application-level retransmission of an identical
	// datagram cannot deliver anything TCP has not already delivered -- it is
	// pure signature. So there is no retry schedule left to fingerprint.
	mtuProbeMinBudget     = 1200 * time.Millisecond
	mtuProbeMaxBudget     = 1950 * time.Millisecond
	mtuProbeMinStartDelay = 5 * time.Millisecond
	mtuProbeMaxStartDelay = 95 * time.Millisecond
	// mtuProbeTransmissions is one, and the tests that pin it exist so that a
	// future "just retry once more" cannot quietly rebuild the burst.
	mtuProbeTransmissions = 1
	envelopeMagic         = "WCF2"
	envelopeData          = 1
	envelopeProbe         = 2
	envelopeProbeAck      = 3
	envelopeCover         = 4
)

type EnvelopeConfig struct {
	MaxInnerDatagram int
	MaxOuterDatagram int
	// DisableLengthPadding puts true inner datagram lengths on the wire.
	//
	// The field is negative on purpose. It used to be PrivacyPadding, whose
	// zero value left the bucket ladder inert: every configuration that did not
	// mention padding leaked inner lengths one-to-one, and one shipped path
	// could not turn it on at all. datapath.OpenWithCarrier takes a
	// caller-constructed dialer, so "the caller forgot" is a wire behaviour
	// decision made for every user that host serves.
	//
	// Inverted, the zero value pads and leaking exact lengths is something
	// somebody has to have written down.
	DisableLengthPadding bool
	PaddingBuckets       []int
}

type envelope struct {
	kind     byte
	sequence uint64
	payload  []byte
}

// carrierEnvelopeConfig is the single definition of the envelope configuration
// a carrier dialer hands to newEnvelopePacketConn. Both carriers route through
// it so the padding default cannot drift apart between them, and so a test can
// assert what a dialer that says nothing about padding actually puts on the
// wire.
func carrierEnvelopeConfig(
	maxInner, maxOuter int, disableLengthPadding bool,
) EnvelopeConfig {
	return EnvelopeConfig{
		MaxInnerDatagram:     maxInner,
		MaxOuterDatagram:     maxOuter,
		DisableLengthPadding: disableLengthPadding,
	}
}

// MTUAware is implemented by carrier connections that have measured an
// effective inner datagram size after accounting for Winn and transport
// framing.
type MTUAware interface {
	EffectiveMTU() int
}

type MTUProber interface {
	ProbeMTU(context.Context) (int, error)
}

// DatagramCapacityReporter is implemented by a carrier underlay that already
// knows how large a datagram it can carry, from a handshake it has already
// completed, and can say so without putting a packet on the wire.
//
// The HTTP/3 underlay is one: quic-go pads every client Initial packet to the
// configured InitialPacketSize, so a completed QUIC handshake is itself proof
// that the path carried a datagram larger than a full-size Winn envelope, in
// both directions. Asking it for the number is free.
type DatagramCapacityReporter interface {
	DatagramCapacity() (int, error)
}

// DatagramCapacityConfirmer is the carrier-level check built on top of that
// report: does the underlay carry a full-size Winn envelope?
type DatagramCapacityConfirmer interface {
	ConfirmDatagramCapacity() (int, error)
}

type CoverTrafficSender interface {
	SendCover(int) error
}

type SequencedWriter interface {
	WriteSequenced([]byte, net.Addr, uint64) (int, error)
}

type envelopePacketConn struct {
	raw       net.PacketConn
	config    EnvelopeConfig
	sequence  atomic.Uint64
	effective atomic.Int64
	closed    atomic.Bool
	readMu    sync.Mutex
	readFrame []byte
}

func newEnvelopePacketConn(raw net.PacketConn, config EnvelopeConfig) (*envelopePacketConn, error) {
	if raw == nil {
		return nil, errors.New("carrier packet connection is nil")
	}
	if config.MaxInnerDatagram <= 0 {
		config.MaxInnerDatagram = DefaultMaxDatagram
	}
	if config.MaxInnerDatagram < 576 || config.MaxInnerDatagram > AbsoluteMaxDatagram {
		return nil, errors.New("inner carrier datagram limit is invalid")
	}
	if config.MaxOuterDatagram <= 0 {
		config.MaxOuterDatagram = config.MaxInnerDatagram + envelopeHeaderSize
	}
	if config.MaxOuterDatagram < 1200 || config.MaxOuterDatagram > AbsoluteMaxCarrierEnvelope ||
		config.MaxOuterDatagram < config.MaxInnerDatagram+envelopeHeaderSize {
		return nil, errors.New("outer carrier datagram limit is invalid")
	}
	if len(config.PaddingBuckets) == 0 {
		config.PaddingBuckets = defaultPaddingBuckets()
	}
	connection := &envelopePacketConn{
		raw: raw, config: config,
		readFrame: make([]byte, config.MaxOuterDatagram+1),
	}
	connection.effective.Store(int64(config.MaxInnerDatagram))
	return connection, nil
}

func (c *envelopePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		count, address, err := c.raw.ReadFrom(c.readFrame)
		if err != nil {
			return 0, nil, err
		}
		frame, err := decodeEnvelope(c.readFrame[:count], c.config.MaxInnerDatagram)
		clear(c.readFrame[:count])
		if err != nil {
			return 0, address, err
		}
		switch frame.kind {
		case envelopeData:
			if len(frame.payload) > c.EffectiveMTU() {
				return 0, address, ErrDatagramTooLarge
			}
			return copy(buffer, frame.payload), address, nil
		case envelopeCover, envelopeProbeAck:
			continue
		default:
			return 0, address, errors.New("unexpected server carrier envelope")
		}
	}
}

func (c *envelopePacketConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	return c.WriteSequenced(packet, address, c.sequence.Add(1))
}

func (c *envelopePacketConn) WriteSequenced(packet []byte, address net.Addr, sequence uint64) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(packet) == 0 || len(packet) > c.EffectiveMTU() {
		return 0, ErrDatagramTooLarge
	}
	if sequence == 0 {
		return 0, errors.New("carrier data sequence must be positive")
	}
	encoded, err := encodeEnvelope(
		envelopeData, sequence, packet,
		c.outerSize(envelopeHeaderSize+len(packet)),
	)
	if err != nil {
		return 0, err
	}
	defer clear(encoded)
	_, err = c.raw.WriteTo(encoded, address)
	if err != nil {
		return 0, err
	}
	return len(packet), nil
}

// ConfirmDatagramCapacity checks that the underlay carries a full-size Winn
// envelope, using only what the underlay's own completed handshake already
// established. It puts nothing on the wire.
//
// This replaces ProbeMTU on any carrier whose underlay can answer the question
// itself. The probe's distinguishing contribution was never the measurement --
// it was that its failure was a censor-triggerable teardown. Reading the
// already-established number keeps the fail-closed property and removes the
// behaviour an adversary could induce.
//
// The returned size is the underlay's capacity, not the selected MTU: the inner
// AWG interface MTU is controller-signed and fixed for the session, so there is
// nothing to select. Either the underlay carries it or this carrier is unusable.
func (c *envelopePacketConn) ConfirmDatagramCapacity() (int, error) {
	reporter, ok := c.raw.(DatagramCapacityReporter)
	if !ok {
		return 0, errors.New(
			"carrier underlay cannot report its established datagram capacity",
		)
	}
	capacity, err := reporter.DatagramCapacity()
	if err != nil {
		return 0, fmt.Errorf("read carrier underlay datagram capacity: %w", err)
	}
	required := c.outerSize(c.config.MaxInnerDatagram + envelopeHeaderSize)
	if capacity < required {
		return capacity, fmt.Errorf(
			"carrier underlay carries %d bytes; a full-size Winn envelope needs %d",
			capacity, required,
		)
	}
	return capacity, nil
}

// ProbeMTU confirms, with one datagram, that the peer round-trips a full-size
// Winn envelope.
//
// It exists for the HTTP/2 carrier, whose underlay is a reliable ordered TCP
// stream and therefore has no path MTU to discover and no handshake-derived
// datagram size to read. What it establishes there is that the tunnel is wired
// end to end at full size, which nothing else on that carrier proves.
//
// It sends exactly one datagram. Over a reliable stream a second identical
// datagram cannot deliver anything TCP has not already delivered, so the old
// retry schedule bought nothing and cost a censor-triggerable burst. The
// HTTP/3 carrier does not call this at all; see ConfirmDatagramCapacity.
func (c *envelopePacketConn) ProbeMTU(ctx context.Context) (int, error) {
	if ctx == nil {
		return c.EffectiveMTU(), errors.New("MTU probe context is required")
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	probeDeadline := time.Now().Add(
		jitteredDuration(mtuProbeMinBudget, mtuProbeMaxBudget),
	)
	deadlineFromContext := false
	if contextDeadline, ok := ctx.Deadline(); ok && !contextDeadline.After(probeDeadline) {
		probeDeadline = contextDeadline
		deadlineFromContext = true
	}
	if !probeDeadline.After(time.Now()) {
		return c.EffectiveMTU(), errors.Join(
			errors.New("carrier MTU discovery deadline expired"),
			context.Cause(ctx),
		)
	}
	if err := c.raw.SetDeadline(probeDeadline); err != nil {
		return c.EffectiveMTU(),
			fmt.Errorf("set carrier MTU discovery deadline: %w", err)
	}

	// Never let the opening delay eat a short caller deadline: it is here to
	// decouple the exchange from the instant the carrier handshake completed,
	// not to spend the budget.
	maximumStartDelay := mtuProbeMaxStartDelay
	if quarterBudget := time.Until(probeDeadline) / 4; quarterBudget < maximumStartDelay {
		maximumStartDelay = quarterBudget
	}
	startDelay := jitteredDuration(mtuProbeMinStartDelay, maximumStartDelay)
	// The inner AWG interface MTU is controller-signed and fixed for this
	// session. A smaller carrier acknowledgement is therefore not a usable
	// success: it could pass the small readiness probes and later reject a
	// normal encrypted AWG datagram. Ask for the required size and let the
	// coordinator select a different carrier if the peer cannot carry it.
	requiredInnerSize := c.config.MaxInnerDatagram
	requiredOuterSize := c.outerSize(
		requiredInnerSize + envelopeHeaderSize,
	)
	sequence := c.sequence.Add(1)
	encoded, err := encodeEnvelope(
		envelopeProbe, sequence, nil, requiredOuterSize,
	)
	if err != nil {
		clearErr := c.raw.SetDeadline(time.Time{})
		return c.EffectiveMTU(), errors.Join(err, clearErr)
	}
	defer clear(encoded)

	// One datagram, held back by a jittered delay, padded to the size an
	// ordinary full-size data datagram already uses. There is no second one:
	// the number of transmissions is not a variable an observer can watch.
	if err := sleepWithContext(ctx, startDelay); err != nil {
		clearErr := c.raw.SetDeadline(time.Time{})
		return c.EffectiveMTU(), errors.Join(err, clearErr)
	}
	if _, err := c.raw.WriteTo(encoded, nil); err != nil {
		clearErr := c.raw.SetDeadline(time.Time{})
		return c.EffectiveMTU(), errors.Join(err, clearErr)
	}

	// The read below blocks until the jittered budget expires. A caller whose
	// context is cancelled rather than deadlined needs that read interrupted,
	// which is what this watcher does; it sends nothing.
	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	watcherError := make(chan error, 1)
	go func() {
		defer close(watcherDone)
		select {
		case <-stopWatcher:
		case <-ctx.Done():
			deadlineErr := c.raw.SetDeadline(time.Now())
			watcherError <- errors.Join(context.Cause(ctx), deadlineErr)
		}
	}()

	var (
		selectedMTU int
		lastError   error
	)
	for selectedMTU == 0 {
		count, _, readErr := c.raw.ReadFrom(c.readFrame)
		if readErr != nil {
			lastError = readErr
			break
		}
		if count != requiredOuterSize {
			clear(c.readFrame[:count])
			lastError = errors.New(
				"carrier MTU probe acknowledgement size mismatch",
			)
			continue
		}
		frame, decodeErr := decodeEnvelope(
			c.readFrame[:count],
			c.config.MaxInnerDatagram,
		)
		clear(c.readFrame[:count])
		if decodeErr != nil || frame.kind != envelopeProbeAck {
			lastError = errors.New("carrier MTU probe acknowledgement mismatch")
			continue
		}
		if frame.sequence != sequence {
			lastError = errors.New("carrier MTU probe acknowledgement sequence mismatch")
			continue
		}
		selectedMTU = requiredInnerSize
	}

	close(stopWatcher)
	<-watcherDone
	var watcherFailure error
	select {
	case err := <-watcherError:
		watcherFailure = err
	default:
	}
	if contextCause := context.Cause(ctx); contextCause != nil {
		watcherFailure = errors.Join(watcherFailure, contextCause)
	}
	if deadlineFromContext && errors.Is(lastError, os.ErrDeadlineExceeded) {
		watcherFailure = errors.Join(watcherFailure, context.DeadlineExceeded)
	}
	clearDeadlineErr := c.raw.SetDeadline(time.Time{})

	if selectedMTU > 0 && watcherFailure == nil && clearDeadlineErr == nil {
		return selectedMTU, nil
	}
	lastError = errors.Join(lastError, watcherFailure)
	if lastError == nil {
		lastError = errors.New("carrier MTU discovery ended without an acknowledgement")
	}
	return c.EffectiveMTU(), errors.Join(
		fmt.Errorf("carrier MTU discovery failed: %w", lastError),
		clearDeadlineErr,
	)
}

func (c *envelopePacketConn) EffectiveMTU() int {
	return int(c.effective.Load())
}

func (c *envelopePacketConn) SendCover(size int) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	if c.config.DisableLengthPadding {
		return errors.New("cover traffic requires length padding")
	}
	if size < envelopeHeaderSize || size > c.config.MaxOuterDatagram {
		return errors.New("cover traffic size is outside the carrier limit")
	}
	encoded, err := encodeEnvelope(envelopeCover, c.sequence.Add(1), nil, size)
	if err != nil {
		return err
	}
	defer clear(encoded)
	_, err = c.raw.WriteTo(encoded, nil)
	return err
}

func (c *envelopePacketConn) MigratePath(ctx context.Context, socket net.PacketConn) error {
	migrator, ok := c.raw.(PathMigrator)
	if !ok {
		if socket != nil {
			_ = socket.Close()
		}
		return errors.New("active carrier does not support in-place path migration")
	}
	return migrator.MigratePath(ctx, socket)
}

func (c *envelopePacketConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return c.raw.Close()
}

func (c *envelopePacketConn) LocalAddr() net.Addr {
	return c.raw.LocalAddr()
}

func (c *envelopePacketConn) SetDeadline(deadline time.Time) error {
	return c.raw.SetDeadline(deadline)
}

func (c *envelopePacketConn) SetReadDeadline(deadline time.Time) error {
	return c.raw.SetReadDeadline(deadline)
}

func (c *envelopePacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.raw.SetWriteDeadline(deadline)
}

func (c *envelopePacketConn) outerSize(minimum int) int {
	if c.config.DisableLengthPadding {
		return minimum
	}
	return paddedSize(
		minimum, c.config.PaddingBuckets, c.config.MaxOuterDatagram,
	)
}

// paddedSize rounds minimum up to the first configured bucket that fits, and
// pads to maximum when no bucket does.
//
// The fall-through used to return minimum, which silently disabled padding for
// exactly the datagrams that carry bulk payload. The shipped configuration
// sets MaxOuterDatagram to 1366 (a 1350-byte inner datagram plus the 16-byte
// header), so every bucket from 1400 up is out of range: a full-size datagram
// matched no bucket and went out at its true length even with padding on.
// Padding to maximum closes that, and has the side effect that a discovery
// datagram and a full-size data datagram are the same size on the wire.
func paddedSize(minimum int, buckets []int, maximum int) int {
	for _, bucket := range buckets {
		if bucket >= minimum && bucket <= maximum {
			return bucket
		}
	}
	if minimum <= maximum {
		return maximum
	}
	return minimum
}

// defaultPaddingBuckets is the length-padding ladder used in both directions.
// Client and server must agree on it: padding one direction only would leave
// the other direction's datagram lengths readable, which is most of the leak.
func defaultPaddingBuckets() []int {
	return []int{256, 512, 768, 1024, 1200, 1280, 1400, 1500, 1516}
}

// jitteredDuration returns a uniformly distributed duration in
// [minimum, maximum]. It draws from crypto/rand so that an observer cannot
// predict a schedule or correlate two connections by their timing.
func jitteredDuration(minimum, maximum time.Duration) time.Duration {
	if maximum <= minimum {
		return minimum
	}
	span := int64(maximum-minimum) + 1
	value, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return minimum + time.Duration(span/2)
	}
	return minimum + time.Duration(value.Int64())
}

// sleepWithContext waits for delay, or returns early if ctx is cancelled.
func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func encodeEnvelope(kind byte, sequence uint64, payload []byte, outerSize int) ([]byte, error) {
	if sequence == 0 {
		return nil, errors.New("carrier envelope sequence must be positive")
	}
	switch kind {
	case envelopeData:
		if len(payload) == 0 || len(payload) > AbsoluteMaxDatagram {
			return nil, errors.New("carrier data envelope payload is invalid")
		}
	case envelopeProbe, envelopeProbeAck, envelopeCover:
		if len(payload) != 0 {
			return nil, errors.New("carrier control envelope must not contain a payload")
		}
	default:
		return nil, errors.New("unknown carrier envelope type")
	}
	minimum := envelopeHeaderSize + len(payload)
	if outerSize < minimum || outerSize > AbsoluteMaxCarrierEnvelope {
		return nil, errors.New("carrier envelope size is invalid")
	}
	encoded := make([]byte, outerSize)
	copy(encoded[:4], envelopeMagic)
	encoded[4] = kind
	// #nosec G115 -- data payloads are bounded to 1,500 bytes; controls are zero.
	binary.BigEndian.PutUint16(encoded[6:8], uint16(len(payload)))
	binary.BigEndian.PutUint64(encoded[8:16], sequence)
	copy(encoded[16:], payload)
	return encoded, nil
}

func decodeEnvelope(encoded []byte, maxInner int) (envelope, error) {
	if len(encoded) < envelopeHeaderSize || len(encoded) > AbsoluteMaxCarrierEnvelope ||
		string(encoded[:4]) != envelopeMagic || encoded[5] != 0 {
		return envelope{}, errors.New("invalid carrier envelope")
	}
	kind := encoded[4]
	payloadLength := int(binary.BigEndian.Uint16(encoded[6:8]))
	sequence := binary.BigEndian.Uint64(encoded[8:16])
	if sequence == 0 || payloadLength > len(encoded)-envelopeHeaderSize {
		return envelope{}, errors.New("invalid carrier envelope length or sequence")
	}
	switch kind {
	case envelopeData:
		if payloadLength == 0 || payloadLength > maxInner {
			return envelope{}, ErrDatagramTooLarge
		}
	case envelopeProbe, envelopeProbeAck, envelopeCover:
		if payloadLength != 0 {
			return envelope{}, errors.New("carrier control envelope has a payload")
		}
	default:
		return envelope{}, errors.New("unknown carrier envelope type")
	}
	return envelope{
		kind: kind, sequence: sequence,
		payload: append([]byte(nil), encoded[envelopeHeaderSize:envelopeHeaderSize+payloadLength]...),
	}, nil
}
