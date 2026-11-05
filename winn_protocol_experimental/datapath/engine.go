package datapath

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrClosed is returned by WriteInbound and ReadOutbound after Close.
var ErrClosed = errors.New("winn datapath engine is closed")

// ErrDatagramTooLarge is returned when a datagram exceeds the configured
// max_datagram in either direction.
var ErrDatagramTooLarge = errors.New(
	"winn datapath datagram exceeds the configured max_datagram",
)

// socketOpener is the single seam through which this package can create a UDP
// socket. It is a package variable so a test can assert that the adopt-a-
// descriptor path never reaches it. Production never replaces it.
var socketOpener = func(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

// Cover traffic schedule that breaks the 25s PersistentKeepalive metronome.
//
// DESIGN: A periodic schedule (e.g. every 5s) just moves the metronome; an
// observer would then see a 5s period instead of 25s. The schedule here is
// *random and memoryless in distribution*: each interval is sampled iid from a
// uniform distribution on [coverIntervalMin, coverIntervalMax] using
// crypto/rand. Uniform was chosen over a fixed period because it has no
// single Fourier component; the autocorrelation of the inter-arrival times is
// flat, and a censor who records timestamps cannot recover a period by
// averaging. The range [2s, 12s] was chosen so that the maximum gap (12s) is
// *strictly less than the keepalive (25s)*: any 25s outer gap is therefore
// chopped into at least two cover intervals and never appears verbatim in the
// observed stream. The cover frame uses envelopeCover with size 256 (the
// smallest padding bucket), which on the wire is the same 284/288 byte
// bucket as a real 32-byte keepalive, so size does not distinguish it.
//
// BANDWIDTH: average interval = (2+12)/2 = 7s => ~514 cover datagrams/hour
// * 256 bytes envelope (284 bytes on wire with QUIC framing) ≈ 146 kB/hour
// uplink ≈ 3.5 MB/day. With QUIC ACK downlink overhead (~40 bytes/cover)
// total ≈ 4 MB/day. For high-risk privacy profile this is the cost of
// breaking the timing correlator. The schedule is DEVICE-LOCAL (hard-coded
// here), not a served knob: a served knob would let whoever answers the
// config request dial the cover interval to hours and silently re-expose the
// heartbeat. Device-local is fail-closed; a controller cannot turn it off.
// This mirrors why envelope padding defaults to on (DisableLengthPadding's
// inverted zero value) rather than being opt-in.

const coverIntervalMin = 2 * time.Second
const coverIntervalMax = 12 * time.Second
const coverDatagramSize = 256

// coverTrafficSender is the carrier envelope's cover interface, re-declared
// locally so datapath does not import internal/carrier at the package level
// (which would be a layering violation for direct-awg). Any carrier PacketConn
// that is an envelopePacketConn implements it; a direct-awg UDP socket does not.
type coverTrafficSender interface {
	SendCover(int) error
}

// Engine is one in-process Winn datapath. Create it with Open.
type Engine struct {
	config  Config
	gateway *net.UDPAddr
	conn    net.PacketConn

	// ownsSocket records whether the engine created the socket itself. It is
	// reported in StatusJSON so a host can prove which happened.
	ownsSocket bool

	// filterGatewaySender gates the "accept only from the configured gateway"
	// check in the pump.
	//
	// It is TRUE for direct-awg, where conn is a bare UDP socket that may be
	// unconnected and an off-path sender could otherwise inject bytes the host
	// would hand straight to its AWG engine.
	//
	// It is FALSE when conn is a carrier from internal/carrier. There the
	// filter would be worse than useless: a carrier PacketConn reports a
	// synthetic peer (carrier.fixedAddr, not a *net.UDPAddr), so the check
	// would reject every datagram and the tunnel would look alive while
	// carrying nothing. The protection it provides is already stronger there —
	// each datagram arrives inside an authenticated Winn envelope over an
	// authenticated TLS 1.3 / QUIC connection, which an off-path sender cannot
	// forge.
	filterGatewaySender bool

	// headerTypes is the resolved AmneziaWG classification table, and
	// headersConfigured records whether it came from the configuration or from
	// the WireGuard default.
	headerTypes       AWGHeaderTypes
	headersConfigured bool

	queue chan []byte
	pool  chan []byte

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error

	pumpDone chan struct{}

	// pumpErr holds the first terminal receive error. It is surfaced through
	// StatusJSON and, once the queue drains, through ReadOutbound.
	pumpErr atomic.Pointer[error]

	openedAt time.Time

	// escalation is the carrier-escalation policy resolved from the normalized
	// configuration. Its zero value is EscalationOff, which is what every
	// configuration that does not name carrier_escalation resolves to, so the
	// field costs an inactive policy struct and nothing else.
	//
	// escalationMu guards it because the failover path (failover.go) REBINDS
	// the policy to the successor after a switch, so that the verdict a host
	// reads afterwards names the carrier the session is actually on rather
	// than the one it started on. Every other construction path writes it once
	// in newEngine and never again, and takes the read lock for free.
	escalationMu sync.RWMutex
	escalation   EscalationPolicy

	counters counters

	// cover traffic: breaks the 25s PersistentKeepalive metronome that
	// length padding alone does not. Only active for carrier transports;
	// direct-awg never implements CoverTrafficSender, so this stays nil
	// there. When the underlying conn is an envelopePacketConn with
	// padding enabled, a background loop emits indistinguishable
	// envelopeCover frames on a distribution with no recoverable period.
	coverCancel context.CancelFunc
	coverWg     sync.WaitGroup

	// superviseWg tracks the carrier-escalation supervisor (failover.go). It is
	// zero and never waited on for any engine built by Open or OpenWithCarrier,
	// which start no supervisor; Close waits on it so a switch in flight cannot
	// outlive the engine.
	superviseWg sync.WaitGroup
}

type counters struct {
	inboundDatagrams  atomic.Uint64
	inboundBytes      atomic.Uint64
	inboundRejected   atomic.Uint64
	outboundDatagrams atomic.Uint64
	outboundBytes     atomic.Uint64
	outboundDropped   atomic.Uint64
	outboundOversize  atomic.Uint64
	foreignSender     atomic.Uint64

	// Header-type classifications. Every one of these is monotonic and moves
	// only when a datagram was actually accepted onto or off the carrier: the
	// inbound ones after a successful socket write, the outbound ones only for
	// datagrams that came from the configured gateway and were within the
	// datagram limit. They are evidence, not cryptographic proof; see
	// AWGHeaderTypes.classify.
	txHandshakeInitiations atomic.Uint64
	txTransport            atomic.Uint64
	txTransportPayload     atomic.Uint64
	rxHandshakeResponses   atomic.Uint64
	rxTransport            atomic.Uint64
	rxTransportPayload     atomic.Uint64

	// firstRxUnixNano is set once, on the first datagram accepted from the
	// gateway. Zero means the gateway has never answered.
	firstRxUnixNano atomic.Int64

	// lastRxUnixNano is overwritten on every datagram accepted from the
	// gateway. Zero means the gateway has never answered.
	//
	// firstRxUnixNano cannot serve this purpose: it answers "did the far side
	// ever reply", which distinguishes a blocked carrier from a working one but
	// says nothing about a carrier that worked and then stopped. Telling those
	// two apart is the whole difference between VerdictBlocked and
	// VerdictStalled, and they warrant different responses. The cost is one
	// relaxed atomic store per accepted datagram on a path that has already
	// done a socket read.
	lastRxUnixNano atomic.Int64
}

// observeInbound records what an accepted host-to-gateway datagram looked like.
func (engine *Engine) observeInbound(packet []byte) {
	switch engine.headerTypes.classify(packet) {
	case ClassHandshakeInitiation:
		engine.counters.txHandshakeInitiations.Add(1)
	case ClassTransportData:
		engine.counters.txTransport.Add(1)
		if engine.headerTypes.carriesTransportPayload(packet) {
			engine.counters.txTransportPayload.Add(1)
		}
	case ClassUnknown, ClassHandshakeResponse, ClassCookieReply:
		// A client sending a handshake response or cookie reply would be
		// anomalous, and junk packets are expected under AmneziaWG. Neither is
		// evidence of transfer, so neither gets a counter of its own.
	}
}

// observeOutbound records what an accepted gateway-to-host datagram looked
// like. It runs on the pump, before the datagram is queued.
func (engine *Engine) observeOutbound(packet []byte) {
	now := time.Now().UTC().UnixNano()
	engine.counters.firstRxUnixNano.CompareAndSwap(0, now)
	engine.counters.lastRxUnixNano.Store(now)
	switch engine.headerTypes.classify(packet) {
	case ClassHandshakeResponse:
		engine.counters.rxHandshakeResponses.Add(1)
	case ClassTransportData:
		engine.counters.rxTransport.Add(1)
		if engine.headerTypes.carriesTransportPayload(packet) {
			engine.counters.rxTransportPayload.Add(1)
		}
	case ClassUnknown, ClassHandshakeInitiation, ClassCookieReply:
	}
}

// Open creates an engine from a JSON configuration blob and a UDP descriptor.
//
// udpFD >= 0 adopts the caller's socket. The engine takes ownership: Close
// closes it. This is the required shape on Android, where the descriptor must
// already have been through VpnService.protect.
//
// udpFD < 0 asks the engine to open its own socket, which it will do only if
// the configuration sets allow_own_socket. Otherwise it returns
// ErrOwnSocketRefused.
func Open(configJSON []byte, udpFD int) (*Engine, error) {
	config, err := ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	if config.Carrier != CarrierDirectAWG {
		// Checked before the descriptor is adopted, so a refused configuration
		// leaves the host's fd exactly where it was.
		return nil, fmt.Errorf("%w (requested %q)",
			ErrCarrierNoDialer, config.Carrier)
	}
	gateway, err := net.ResolveUDPAddr("udp", config.GatewayEndpoint)
	if err != nil {
		// Unreachable for a validated IP literal, but a silent nil address
		// here would send every datagram to nowhere.
		return nil, fmt.Errorf("winn datapath gateway endpoint: %w", err)
	}

	var conn net.PacketConn
	ownsSocket := false
	if udpFD >= 0 {
		conn, err = adoptUDPDescriptor(udpFD)
		if err != nil {
			return nil, err
		}
	} else {
		if !config.AllowOwnSocket {
			return nil, ErrOwnSocketRefused
		}
		network := "udp4"
		if gateway.IP.To4() == nil {
			network = "udp6"
		}
		conn, err = socketOpener(network, ":0")
		if err != nil {
			return nil, fmt.Errorf("winn datapath open UDP socket: %w", err)
		}
		ownsSocket = true
	}

	engine := newEngine(config, gateway, conn, ownsSocket)
	go engine.pump()
	return engine, nil
}

// OpenWithPacketConn builds an engine over an already-open connection. It is
// the seam the tests and the framed subprocess use; the socket rule is the
// caller's to honour, so it does not consult allow_own_socket.
func OpenWithPacketConn(config Config, conn net.PacketConn) (*Engine, error) {
	if conn == nil {
		return nil, errors.New("winn datapath packet connection is required")
	}
	normalized, err := config.normalize()
	if err != nil {
		return nil, err
	}
	gateway, err := net.ResolveUDPAddr("udp", normalized.GatewayEndpoint)
	if err != nil {
		return nil, fmt.Errorf("winn datapath gateway endpoint: %w", err)
	}
	engine := newEngine(normalized, gateway, conn, false)
	go engine.pump()
	return engine, nil
}

func newEngine(
	config Config,
	gateway *net.UDPAddr,
	conn net.PacketConn,
	ownsSocket bool,
) *Engine {
	headerTypes, headersConfigured := config.headerTypes()
	engine := &Engine{
		config:              config,
		gateway:             gateway,
		conn:                conn,
		ownsSocket:          ownsSocket,
		filterGatewaySender: true,
		headerTypes:         headerTypes,
		headersConfigured:   headersConfigured,
		queue:               make(chan []byte, config.QueueDepth),
		pool:                make(chan []byte, config.QueueDepth+1),
		closed:              make(chan struct{}),
		pumpDone:            make(chan struct{}),
		openedAt:            time.Now().UTC(),
		escalation:          escalationPolicyFromNormalized(config),
	}
	for range cap(engine.pool) {
		engine.pool <- make([]byte, config.MaxDatagram)
	}
	return engine
}

// enableCover starts the cover-traffic loop for a carrier engine.
// It is a no-op for direct-awg (which has no CoverTrafficSender) or when
// length padding is disabled (standard privacy). Hence cover is DEVICE-LOCAL:
// the schedule lives in this file, not in a served key, so a controller
// cannot disable it by serving a large interval. The loop runs until Close.
func (engine *Engine) enableCover() {
	sender, ok := engine.conn.(coverTrafficSender)
	if !ok {
		return
	}
	// The sender will refuse if padding is off; probe once with a zero-cost
	// check: try a dummy size validation by calling SendCover on a closed-size
	// probe? Instead we start the loop and let the first SendCover tell us.
	// If padding is disabled, the first call returns the padding error and the
	// goroutine exits without sending.
	ctx, cancel := context.WithCancel(context.Background())
	engine.coverCancel = cancel
	engine.coverWg.Add(1)
	go engine.coverLoop(ctx, sender)
}

func (engine *Engine) coverLoop(ctx context.Context, sender coverTrafficSender) {
	defer engine.coverWg.Done()
	for {
		delay := randomCoverInterval()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-engine.closed:
			timer.Stop()
			return
		case <-timer.C:
		}
		select {
		case <-engine.closed:
			return
		case <-ctx.Done():
			return
		default:
		}
		if err := sender.SendCover(coverDatagramSize); err != nil {
			if err.Error() == "cover traffic requires length padding" {
				return
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			// Transient error (e.g. QUIC congestion); back off briefly.
			select {
			case <-ctx.Done():
				return
			case <-engine.closed:
				return
			case <-time.After(time.Second):
			}
		}
	}
}

func randomCoverInterval() time.Duration {
	span := coverIntervalMax - coverIntervalMin
	if span <= 0 {
		return coverIntervalMin
	}
	return coverIntervalMin + secureCoverJitter(span)
}

func secureCoverJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)+1))
	if err != nil {
		return time.Duration(int64(maximum) / 2)
	}
	return time.Duration(value.Int64())
}

// WriteInbound hands one datagram from the host to the protocol: host tun side
// -> Winn -> gateway. It returns the number of bytes accepted.
//
// The engine copies nothing it does not have to: the datagram is written
// straight to the socket, so packet is not retained after the call returns.
func (engine *Engine) WriteInbound(packet []byte) (int, error) {
	if engine == nil {
		return 0, ErrClosed
	}
	select {
	case <-engine.closed:
		return 0, ErrClosed
	default:
	}
	if len(packet) == 0 {
		engine.counters.inboundRejected.Add(1)
		return 0, errors.New("winn datapath inbound datagram is empty")
	}
	if len(packet) > engine.config.MaxDatagram {
		engine.counters.inboundRejected.Add(1)
		return 0, fmt.Errorf("%w (%d > %d)",
			ErrDatagramTooLarge, len(packet), engine.config.MaxDatagram)
	}
	written, err := engine.conn.WriteTo(packet, engine.gateway)
	if err != nil {
		engine.counters.inboundRejected.Add(1)
		// A write against a closed socket races Close legitimately; report the
		// lifecycle error rather than a transport error the host cannot act on.
		select {
		case <-engine.closed:
			return 0, ErrClosed
		default:
		}
		return written, fmt.Errorf("winn datapath carrier write: %w", err)
	}
	engine.counters.inboundDatagrams.Add(1)
	// #nosec G115 -- the error return was handled above, so this is a
	// successful io.Writer result and 0 <= written <= len(packet).
	engine.counters.inboundBytes.Add(uint64(written))
	engine.observeInbound(packet)
	return written, nil
}

// ReadOutbound returns one datagram from the protocol to the host: gateway ->
// Winn -> host tun side. It blocks until a datagram is available, the engine is
// closed, or the carrier fails terminally.
//
// A datagram larger than len(packet) is truncated and reported with
// ErrDatagramTooLarge together with its full length, so a caller can size its
// buffer correctly instead of silently losing the tail.
func (engine *Engine) ReadOutbound(packet []byte) (int, error) {
	if engine == nil {
		return 0, ErrClosed
	}
	if len(packet) == 0 {
		return 0, errors.New("winn datapath outbound buffer is empty")
	}
	select {
	case buffer := <-engine.queue:
		return engine.deliver(buffer, packet)
	default:
	}
	select {
	case buffer := <-engine.queue:
		return engine.deliver(buffer, packet)
	case <-engine.closed:
		return 0, ErrClosed
	case <-engine.pumpDone:
		// Drain whatever the pump managed to queue before it stopped, then
		// report why it stopped.
		select {
		case buffer := <-engine.queue:
			return engine.deliver(buffer, packet)
		default:
		}
		if held := engine.pumpErr.Load(); held != nil {
			return 0, *held
		}
		return 0, ErrClosed
	}
}

// ReadOutboundTimeout is ReadOutbound with an upper bound. A zero or negative
// timeout means the same as ReadOutbound. On expiry it returns
// os.ErrDeadlineExceeded, which errors.Is(err, os.ErrDeadlineExceeded) matches.
func (engine *Engine) ReadOutboundTimeout(
	packet []byte,
	timeout time.Duration,
) (int, error) {
	if engine == nil {
		return 0, ErrClosed
	}
	if timeout <= 0 {
		return engine.ReadOutbound(packet)
	}
	if len(packet) == 0 {
		return 0, errors.New("winn datapath outbound buffer is empty")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case buffer := <-engine.queue:
		return engine.deliver(buffer, packet)
	case <-timer.C:
		return 0, ErrDeadlineExceeded
	case <-engine.closed:
		return 0, ErrClosed
	case <-engine.pumpDone:
		select {
		case buffer := <-engine.queue:
			return engine.deliver(buffer, packet)
		default:
		}
		if held := engine.pumpErr.Load(); held != nil {
			return 0, *held
		}
		return 0, ErrClosed
	}
}

func (engine *Engine) deliver(buffer, packet []byte) (int, error) {
	full := len(buffer)
	copied := copy(packet, buffer)
	clear(buffer[:full])
	engine.recycle(buffer)
	engine.counters.outboundDatagrams.Add(1)
	// #nosec G115 -- copy returns the number of elements copied, which is the
	// minimum of two lengths and so can never be negative.
	engine.counters.outboundBytes.Add(uint64(copied))
	if copied < full {
		return copied, fmt.Errorf("%w (%d > %d)",
			ErrDatagramTooLarge, full, len(packet))
	}
	return copied, nil
}

func (engine *Engine) recycle(buffer []byte) {
	select {
	case engine.pool <- buffer[:cap(buffer)]:
	default:
		// The pool is sized at queue depth + 1, so this cannot be reached
		// while the invariant holds. Dropping the buffer is still correct: it
		// is garbage, not state.
	}
}

// pump is the only reader of the carrier socket.
func (engine *Engine) pump() {
	defer close(engine.pumpDone)
	for {
		select {
		case <-engine.closed:
			return
		default:
		}
		var buffer []byte
		select {
		case buffer = <-engine.pool:
		case <-engine.closed:
			return
		}
		buffer = buffer[:cap(buffer)]
		count, sender, err := engine.conn.ReadFrom(buffer)
		if err != nil {
			engine.recycle(buffer)
			select {
			case <-engine.closed:
				return
			default:
			}
			terminal := fmt.Errorf("winn datapath carrier read: %w", err)
			engine.pumpErr.CompareAndSwap(nil, &terminal)
			return
		}
		if count <= 0 {
			engine.recycle(buffer)
			continue
		}
		if count > engine.config.MaxDatagram {
			engine.counters.outboundOversize.Add(1)
			clear(buffer[:count])
			engine.recycle(buffer)
			continue
		}
		// A connected socket already filters by peer, but an adopted
		// descriptor may be unconnected. Refusing datagrams from anywhere but
		// the signed gateway endpoint stops an off-path sender from injecting
		// bytes that the host would hand to its AWG engine.
		if engine.filterGatewaySender && !engine.fromGateway(sender) {
			engine.counters.foreignSender.Add(1)
			clear(buffer[:count])
			engine.recycle(buffer)
			continue
		}
		// Classify before queuing: what arrived from the gateway is a fact
		// about the carrier, and it must not depend on whether the host
		// happened to be draining fast enough to receive it.
		engine.observeOutbound(buffer[:count])
		select {
		case engine.queue <- buffer[:count]:
		default:
			// The host is not draining. Drop the OLDEST so a stalled reader
			// costs latency, not the whole session.
			select {
			case stale := <-engine.queue:
				clear(stale)
				engine.recycle(stale)
				engine.counters.outboundDropped.Add(1)
			default:
			}
			select {
			case engine.queue <- buffer[:count]:
			default:
				clear(buffer[:count])
				engine.recycle(buffer)
				engine.counters.outboundDropped.Add(1)
			}
		}
	}
}

func (engine *Engine) fromGateway(sender net.Addr) bool {
	if sender == nil {
		// An unconnected socket always reports a sender; a connected one may
		// not. Accepting nil is correct only because the kernel has already
		// filtered by peer in that case.
		return true
	}
	address, ok := sender.(*net.UDPAddr)
	if !ok {
		return false
	}
	return address.Port == engine.gateway.Port &&
		address.IP.Equal(engine.gateway.IP)
}

// Close is idempotent and synchronous. When it returns, the socket is closed,
// the pump goroutine has exited, and every queued datagram has been zeroed.
func (engine *Engine) Close() error {
	if engine == nil {
		return nil
	}
	engine.closeOnce.Do(func() {
		close(engine.closed)
		if engine.coverCancel != nil {
			engine.coverCancel()
		}
		// Closing the socket is what unblocks a pump parked in ReadFrom.
		err := engine.conn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			engine.closeErr = fmt.Errorf(
				"winn datapath close carrier socket: %w", err,
			)
		}
		<-engine.pumpDone
		engine.coverWg.Wait()
		// The supervisor selects on engine.closed, which is already closed, so
		// this waits only for a switch that was in flight when Close was
		// called. Waiting rather than abandoning it is what stops a Manager
		// from activating a replacement carrier after the engine that owns it
		// has gone.
		engine.superviseWg.Wait()
		for {
			select {
			case buffer := <-engine.queue:
				clear(buffer)
			default:
				return
			}
		}
	})
	return engine.closeErr
}
