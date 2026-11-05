package carrier

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// Stream is the §4.2 stream carrier: Winn3 messages over TCP, with or without
// TLS, with every record length encrypted.
//
// It is the answer to the measured failure. One `-p udp -j DROP` produced 24
// retries and 100 % loss against a datapath that had a single UDP transport;
// this carrier is what the session migrates onto, and it is built here rather
// than borrowed from the v1 stealth leg, whose TCP candidates are Xray's.
//
// # On the wire
//
// For every message, exactly one write of exactly one buffer:
//
//	first message:  salt(16) ‖ sealedLen(18) ‖ message
//	after that:            sealedLen(18) ‖ message
//
// With TCPFirstFlight, the first client record is inside a TLS ClientHello
// session ticket. Later records and gateway replies retain this framing.
// There is no handshake of this layer's own, no
// keepalive, no probe and no framing marker. A connection that is idle is a TCP
// connection with no bytes on it.
//
// # One write, and why it is a hard property rather than an optimisation
//
// Writing the sealed length and the message separately would be correct and
// would produce, on a NODELAY socket, an 18-byte segment in front of every
// message on every connection in the fleet. That is a fleet-wide constant
// expressed as a segment size instead of as bytes — the same failure class as
// the `0B 00 00 00` at offset 16 that characterised the entire user base of the
// protocol this replaces. TestOneWritePerMessage counts writes on the underlying
// conn and fails if a refactor ever splits them.
//
// # The salt travels with the first message, never on its own
//
// Two independent reasons, either sufficient:
//
//   - A gateway that wrote its salt on accept would emit 16 bytes in answer to
//     an unauthenticated TCP connection. §4.3 spends the entire design ensuring
//     the only way to make a gateway emit a byte is a fresh initiation that
//     authenticates under its admission key; a carrier-layer greeting would hand
//     back the probe oracle. TestGatewayWritesNothingBeforeItSends holds it.
//   - A salt written alone is a 16-byte first segment, fleet-wide. Carried with
//     the first message it is invisible, because the initiation it rides with is
//     padded by a uniform draw and the segment is variable-length.
//
// # Desynchronisation is terminal, on purpose
//
// If a sealed length does not open, the stream is dead. There is no
// resynchronisation and there will not be one: resynchronising means scanning
// for a marker, and a marker is a plaintext field at a findable offset, which is
// exactly what encrypting the length removes. Recv returns ErrStreamDesync and
// the carrier refuses to do anything further. It does NOT write to the peer and
// it does NOT close the connection on its own — see §4 of the handoff for the
// residual and for the bounded hold the gateway lane should build on top.
type Stream struct {
	conn                net.Conn
	class               Class
	tcpFirstFlight      bool
	recvFirstFlightDone bool

	// pathCeiling is the largest MaxMessageSize this class and family can wrap
	// without fragmenting. SetMaxMessageSize is bounded by it.
	pathCeiling int

	secret []byte
	role   Role
	clock  Clock
	rnd    io.Reader

	sendMu   sync.Mutex
	sendCip  *lengthCipher
	sendSalt []byte
	sentSalt bool
	sendBuf  []byte

	recvMu  sync.Mutex
	reader  *bufio.Reader
	recvCip *lengthCipher
	// Partial-read resume. A poll timeout must not discard bytes already
	// taken from the stream: those bytes are gone from the socket, and a
	// retry that starts the record over desynchronises a live peer.
	recvSalt    []byte
	recvSaltGot int
	recvRec     [LengthRecordOverhead]byte
	recvRecGot  int
	recvBody    []byte
	recvBodyGot int

	mu sync.Mutex
	// maxMessage is the send ceiling. recvCeiling is its high-water mark: a
	// SetMaxMessageSize that narrows this end does not narrow what the peer is
	// entitled to send, and refusing a message the peer was told it could send
	// would turn a widening into a teardown.
	maxMessage  int
	recvCeiling int
	closed      bool
	fatalErr    error
	stats       Stats
}

// StreamConfig configures a stream carrier over an established connection.
type StreamConfig struct {
	// Conn is the transport. A *tls.Conn is expected in production; a bare
	// *net.TCPConn is legal and is what an L4-fronted deployment or a test uses.
	// The connection must already be established: this package does not build
	// TLS configurations, because internal/tlsconfig is the single typed entry
	// point for every client tls.Config in this tree and a second one here would
	// be a second hello to keep in step. See §3 of the handoff.
	Conn net.Conn

	// Secret is the carrier secret the length layer is keyed from — the
	// gateway's admission secret. At least MinSecretSize bytes. The caller's
	// slice is copied; the copy is kept until the peer salt arrives so the
	// receive direction can be keyed. It is not the caller's buffer that is
	// retained.
	Secret []byte

	// Role selects which direction label this end seals with.
	Role Role

	// Class overrides the auto-detected class. Leave it zero: a *tls.Conn is
	// detected as ClassTLS and anything else as ClassTCP, and detecting it is
	// safer than being told, because a caller who mislabels a TLS connection as
	// TCP gets a 22-byte-too-large message and fragments every full-size packet.
	Class Class

	// TCPFirstFlight carries the initial client record in a TLS ClientHello
	// session ticket on the raw TCP gateway port. Both ends must opt in.
	TCPFirstFlight bool

	// MaxMessageSize is the send ceiling. Zero means MaxMessageSizeFor at
	// DefaultPathMTU for the detected class and family — a floor, not an
	// estimate. A caller that knows its path should say so, and a caller whose
	// session may migrate should pass Floor.
	MaxMessageSize int

	// PathMTU is the measured path MTU used to derive the ceiling when
	// MaxMessageSize is zero, and to bound SetMaxMessageSize. Zero means
	// DefaultPathMTU.
	PathMTU int

	// Clock and Rand are injected for tests. Nil means the system clock and
	// crypto/rand.
	Clock Clock
	Rand  io.Reader
}

// NewStream wraps an established connection in the §4.2 record layer.
//
// It writes nothing. The per-connection salt is drawn here and buffered; it
// reaches the wire with the first Send.
func NewStream(cfg StreamConfig) (*Stream, error) {
	if cfg.Conn == nil {
		return nil, wrap(ErrConfig, "no connection")
	}
	if len(cfg.Secret) < MinSecretSize {
		return nil, wrap(ErrSecret, "%d bytes, need at least %d", len(cfg.Secret), MinSecretSize)
	}
	if cfg.Role != RoleClient && cfg.Role != RoleGateway {
		return nil, wrap(ErrConfig, "unknown role %d", cfg.Role)
	}

	class := cfg.Class
	if class == ClassUnknown {
		class = ClassTCP
		if _, ok := cfg.Conn.(*tls.Conn); ok {
			class = ClassTLS
		}
	}
	if !class.Stream() {
		return nil, wrap(ErrConfig, "class %s is not a stream class", class)
	}
	if cfg.TCPFirstFlight && class != ClassTCP {
		return nil, wrap(ErrConfig, "TCP first flight requires raw TCP")
	}

	pathMTU := cfg.PathMTU
	if pathMTU == 0 {
		pathMTU = DefaultPathMTU
	}
	family := FamilyOf(cfg.Conn.RemoteAddr())
	ceiling := MaxMessageSizeFor(class, family, pathMTU)

	maxMessage := cfg.MaxMessageSize
	if maxMessage == 0 {
		maxMessage = ceiling
	}
	if err := checkSize(maxMessage, ceiling); err != nil {
		return nil, err
	}

	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		// A failure here is fatal rather than papered over. Falling back to a
		// weaker source would silently reuse a (key, nonce) pair across
		// connections, and it would do so exactly when nobody is watching.
		return nil, wrap(ErrConfig, "salt draw failed: %v", err)
	}
	sendCip, err := newLengthCipher(cfg.Secret, salt, cfg.Role.sendLabel())
	if err != nil {
		return nil, err
	}

	clock := cfg.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	secret := make([]byte, len(cfg.Secret))
	copy(secret, cfg.Secret)

	return &Stream{
		conn:           cfg.Conn,
		class:          class,
		tcpFirstFlight: cfg.TCPFirstFlight,
		pathCeiling:    ceiling,
		secret:         secret,
		role:           cfg.Role,
		clock:          clock,
		rnd:            rnd,
		sendCip:        sendCip,
		sendSalt:       salt,
		reader:         bufio.NewReaderSize(cfg.Conn, 4096),
		maxMessage:     maxMessage,
		recvCeiling:    maxMessage,
	}, nil
}

// Class reports the transport this carrier rides.
func (s *Stream) Class() Class { return s.class }

// MaxMessageSize is the current send ceiling.
func (s *Stream) MaxMessageSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxMessage
}

// SetMaxMessageSize narrows or widens the send ceiling on a live carrier.
//
// The receive ceiling only ever rises. Narrowing this end tells the peer
// nothing, so a peer that was entitled to send a larger message a moment ago
// must still be able to; refusing it would convert a size change into a
// teardown, and the teardown would happen at exactly the moment a session was
// migrating away from a blocked carrier.
func (s *Stream) SetMaxMessageSize(n int) error {
	if err := checkSize(n, s.pathCeiling); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.maxMessage = n
	if n > s.recvCeiling {
		s.recvCeiling = n
	}
	return nil
}

// Stats reports what this carrier has seen.
func (s *Stream) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// fatal is the carrier's own last unrecoverable error, read by Observe.
func (s *Stream) fatal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatalErr
}

// Send writes one message: salt on the first call, then the sealed length and
// the message, in a single write of a single buffer.
func (s *Stream) Send(ctx context.Context, msg []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(msg) == 0 {
		return ErrMessageEmpty
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	closed, fatalErr, maxMessage := s.closed, s.fatalErr, s.maxMessage
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if fatalErr != nil {
		return fatalErr
	}
	if len(msg) > maxMessage {
		return wrap(ErrMessageTooLarge, "%d bytes, ceiling %d", len(msg), maxMessage)
	}

	buf := s.sendBuf[:0]
	if !s.sentSalt {
		buf = append(buf, s.sendSalt...)
	}
	sealed, err := s.sendCip.seal(buf, len(msg))
	if err != nil {
		s.noteFatal(err)
		return err
	}
	buf = append(sealed, msg...)
	if s.tcpFirstFlight && s.role == RoleClient && !s.sentSalt {
		buf, err = encodeTCPFirstFlight(buf)
		if err != nil {
			s.noteFatal(err)
			return err
		}
	}
	s.sendBuf = buf

	stop := s.armWrite(ctx)
	n, err := s.conn.Write(buf)
	stop()
	if err != nil {
		s.mu.Lock()
		s.stats.SendErrors++
		s.mu.Unlock()
		// A short or failed write leaves the stream desynchronised: the length
		// record was consumed from the counter and the peer may have half a
		// message. There is no retransmission at this layer and there must not
		// be one, because re-sealing a length under a spent counter is a reused
		// nonce. The carrier is dead; the session migrates.
		s.noteFatal(err)
		return err
	}
	s.sentSalt = true

	s.mu.Lock()
	s.stats.Sent++
	s.stats.SentBytes += uint64(n)
	s.stats.LastSend = s.clock.Now()
	s.mu.Unlock()
	return nil
}

// Recv reads one length-prefixed frame and unseals it into msg.
//
// A poll timeout in the middle of a record keeps the bytes already taken and
// continues on the next Recv. Discarding them would desynchronise a live
// peer: the length counter may already have been spent, and the leftover
// bytes on the socket would be read as a new record. An idle timeout (no
// bytes of the current record yet) is still not fatal.
func (s *Stream) Recv(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	closed, fatalErr, ceiling := s.closed, s.fatalErr, s.recvCeiling
	s.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	if fatalErr != nil {
		return nil, fatalErr
	}

	stop := s.armRead(ctx)
	defer stop()
	if s.tcpFirstFlight && s.role == RoleGateway && !s.recvFirstFlightDone {
		first, err := readTCPFirstFlight(s.reader, ceiling+SaltSize+LengthRecordOverhead)
		if err != nil {
			s.noteFatal(err)
			return nil, err
		}
		s.reader = bufio.NewReader(io.MultiReader(bytes.NewReader(first), s.reader))
		s.recvFirstFlightDone = true
	}

	if s.recvCip == nil {
		if s.recvSalt == nil {
			s.recvSalt = make([]byte, SaltSize)
		}
		if err := readResume(s.reader, s.recvSalt, &s.recvSaltGot); err != nil {
			return nil, s.noteRecvErr(err)
		}
		cip, err := newLengthCipher(s.secret, s.recvSalt, s.role.recvLabel())
		if err != nil {
			return nil, s.noteRecvErr(err)
		}
		s.recvCip = cip
		clear(s.recvSalt)
		s.recvSalt = nil
		s.recvSaltGot = 0
	}

	if s.recvBody == nil {
		if err := readResume(s.reader, s.recvRec[:], &s.recvRecGot); err != nil {
			return nil, s.noteRecvErr(err)
		}
		n, err := s.recvCip.openLength(s.recvRec[:])
		if err != nil {
			return nil, s.noteRecvErr(err)
		}
		s.recvRecGot = 0
		if n < session.MessageFloor() || n > ceiling {
			// A length outside the agreed range is not a short message, it is a
			// stream that is no longer where it thinks it is. Treated as
			// desynchronisation rather than as a dropped message, because there is
			// no way to skip forward to the next record.
			return nil, s.noteRecvErr(wrap(ErrStreamDesync,
				"length %d outside [%d,%d]", n, session.MessageFloor(), ceiling))
		}
		s.recvBody = make([]byte, n)
		s.recvBodyGot = 0
	}

	if err := readResume(s.reader, s.recvBody, &s.recvBodyGot); err != nil {
		return nil, s.noteRecvErr(err)
	}
	msg := s.recvBody
	n := len(msg)
	s.recvBody = nil
	s.recvBodyGot = 0

	s.mu.Lock()
	s.stats.Delivered++
	s.stats.DeliveredBytes += uint64(n + LengthRecordOverhead)
	s.stats.LastDelivered = s.clock.Now()
	s.mu.Unlock()
	return msg, nil
}

// readResume fills dst[*got:] from r and advances *got. A timeout with a
// partial fill leaves *got where it is so the next Recv continues the same
// record rather than reinterpreting leftover socket bytes as a new one.
func readResume(r io.Reader, dst []byte, got *int) error {
	if *got >= len(dst) {
		return nil
	}
	n, err := io.ReadFull(r, dst[*got:])
	*got += n
	return err
}

// Close releases the transport and unblocks any Send or Recv in progress.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	err := s.conn.Close()
	s.sendMu.Lock()
	s.sendCip = nil
	clear(s.sendSalt)
	s.sendSalt = nil
	s.sendMu.Unlock()
	s.recvMu.Lock()
	s.recvCip = nil
	clear(s.recvSalt)
	s.recvSalt = nil
	s.recvSaltGot = 0
	s.recvMu.Unlock()
	s.mu.Lock()
	clear(s.secret)
	s.secret = nil
	s.mu.Unlock()
	return err
}

// noteRecvErr records a receive failure and marks the carrier dead when the
// failure is one there is no way back from.
//
// A read timeout is not fatal: the caller asked for a bounded wait and got one,
// and on a carrier that is being polled that is the ordinary case. Everything
// else on a stream is: a desynchronised record layer, a closed peer, a reset.
func (s *Stream) noteRecvErr(err error) error {
	s.mu.Lock()
	s.stats.RecvErrors++
	s.mu.Unlock()
	if isTimeout(err) {
		return err
	}
	s.noteFatal(err)
	return err
}

// noteFatal records the first unrecoverable error. Later errors do not overwrite
// it: the first one is the diagnosis and everything after it is a consequence.
func (s *Stream) noteFatal(err error) {
	s.mu.Lock()
	if s.fatalErr == nil {
		s.fatalErr = err
	}
	s.mu.Unlock()
}

// armRead sets the read deadline from ctx and returns a function that clears it.
//
// context.AfterFunc rather than a goroutine per call: the callback is registered
// on the context and only runs if the context is actually cancelled, so a
// long-lived datapath loop polling a carrier does not spawn a goroutine per
// packet.
func (s *Stream) armRead(ctx context.Context) func() {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	_ = s.conn.SetReadDeadline(deadline)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = s.conn.SetReadDeadline(aLongTimeAgo)
		close(finished)
	})
	return func() {
		if !stop() {
			<-finished
		}
		_ = s.conn.SetReadDeadline(time.Time{})
	}
}

// armWrite is armRead for the write side.
func (s *Stream) armWrite(ctx context.Context) func() {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	_ = s.conn.SetWriteDeadline(deadline)
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = s.conn.SetWriteDeadline(aLongTimeAgo)
		close(finished)
	})
	return func() {
		if !stop() {
			<-finished
		}
		_ = s.conn.SetWriteDeadline(time.Time{})
	}
}

// aLongTimeAgo is a deadline in the past, used to unblock a socket operation
// when its context is cancelled. It is the standard library's own idiom.
var aLongTimeAgo = time.Unix(1, 0)

// isTimeout reports whether err is a deadline expiry.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
