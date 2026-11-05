// Package knockdial is the alternative connection-initiation step for the
// datapath carrier route: it sends one internal/knock Single Packet
// Authorization datagram immediately before a carrier dials, over the same
// socket the carrier is about to use.
//
// # Why this exists when internal/knock already does
//
// internal/knock has both halves of SPA already — Build/Verify, the server
// side Gate, and a client Send/SendVia — and cmd/winn-carrier-server and
// cmd/winn-carrier-client already use them. What had no way to reach them was
// the DATAPATH route: the profile-driven path in datapath/carrierhost that
// cmd/winn-datapath (Android, Windows) and cdatapath (Apple) use to build a
// carrier for the real tunnel. That route never calls a knock, because it has
// no place to put one: datapath.OpenWithCarrier owns the descriptor and calls
// Dial itself, and carrierhost.BuildDialer is explicitly forbidden from
// performing any network I/O of its own.
//
// This package is the seam that fits between them without moving either. It
// decorates a carrier.SuppliedSocketDialer, forwards every method, and does
// exactly one extra thing: on Dial, it writes one knock datagram first.
//
// # Why a dialer decorator and not a change to datapath
//
// datapath/carrier.go states an invariant this package must not break: the
// HOST opens the transport socket, the host protects it, and only then is it
// handed over, and a dialer that reaches OpenWithCarrier already holding a
// socket is refused (ErrCarrierSocketReused) so "the descriptor the engine
// adopted is provably the descriptor the carrier used". A decorator preserves
// that exactly: it opens nothing at construction, HasSuppliedSocket forwards
// to the inner dialer so the refusal still fires, and the socket it writes the
// knock over is the one datapath.installCarrierSocket just installed — the
// host's own protected descriptor, not a second one.
//
// The alternative — a pre-dial hook threaded through OpenWithCarrier — would
// change a signature that cdatapath's C ABI and cmd/winn-datapath both depend
// on, for no property this decorator does not already give.
//
// # The knock is never less protected than the transport
//
// That is the single rule this package follows, and it decides all three
// cases:
//
//   - A supplied PACKET socket (SocketKindPacket, the HTTP/3 CONNECT-UDP
//     carrier) was installed. The knock goes out on it with knock.SendVia. On
//     Android this is the socket VpnService.protect() already excluded from
//     the tunnel, which is exactly why knock.Send is documented as the wrong
//     call there: an unprotected knock socket can loop the datagram back into
//     the tunnel it is trying to establish.
//   - NO socket was supplied. This is only reachable when the datapath config
//     set allow_own_socket — datapath.installCarrierSocket returns
//     ErrOwnSocketRefused otherwise — which means the deployment has already
//     accepted that the carrier opens its own unprotected socket, and outer
//     traffic is excluded by route instead. A knock socket opened here is
//     exactly as protected as the transport socket, so knock.Send is used.
//   - A supplied STREAM socket (SocketKindStream, the HTTP/2 carrier). A UDP
//     knock cannot ride a connected TCP socket, and opening a separate UDP
//     socket beside it would be strictly less protected than the transport on
//     precisely the platform (Android) this route exists for. This is refused
//     at construction — ErrStreamCarrierUnsupported — not at Dial, so the
//     operator learns before any I/O happens. Lifting it needs a second,
//     host-protected UDP descriptor in the argv/C-ABI contract, which is a
//     host change, not a change here.
//
// # What this does NOT change
//
// Nothing about what Winn carries. datapath/status.go's statement stands
// unaltered: "Winn carries AmneziaWG outer datagrams opaquely: it holds no
// keys and verifies no authentication tag." A knock is not an AmneziaWG
// datagram, is never mixed into the relayed stream, and its key is not an
// AmneziaWG key. SPA decides only whether the far side answers at all; every
// authentication the tunnel relies on — the AmneziaWG handshake itself, and
// on this route also carrierauth, pqauth and mTLS — runs afterwards,
// unweakened, on whatever gets through. See internal/knock's package doc.
package knockdial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/knock"
)

// DefaultSettle is how long Dial waits after writing the knock before it lets
// the inner dialer start its handshake.
//
// The knock and the first handshake datagram leave the same socket back to
// back, and UDP guarantees no ordering: a handshake packet that overtakes the
// knock arrives at a gate that has not authorized this source yet and is
// silently dropped, costing a full dial timeout rather than 50ms. The value is
// chosen against this deployment's own measured connect distribution — p50
// 62.93ms, p95 81.22ms against a 3s connect-or-fail contract — where 50ms is
// noise, not budget. cmd/winn-carrier-client's own knock loop has no
// equivalent pause because it knocks every candidate node before a racing
// Connect, so its knocks already have the whole candidate loop as slack.
const DefaultSettle = 50 * time.Millisecond

// MaxSettle bounds Config.Settle. A settle longer than this is a
// misconfiguration eating the caller's connect budget, not a tuning choice.
const MaxSettle = 2 * time.Second

var (
	// ErrInnerDialerRequired means New was called with no dialer to decorate.
	ErrInnerDialerRequired = errors.New(
		"knockdial: an inner carrier dialer is required",
	)

	// ErrStreamCarrierUnsupported means the inner dialer takes a connected TCP
	// socket. See the package doc: a UDP knock cannot ride it, and a separate
	// UDP socket would be less protected than the transport.
	ErrStreamCarrierUnsupported = errors.New(
		"knockdial: SPA initiation needs a packet-socket carrier: a UDP knock " +
			"cannot ride the connected TCP socket a stream carrier is handed, " +
			"and opening a separate UDP socket beside it would be less " +
			"protected than the transport",
	)

	// ErrTargetRequired means no knock target was configured. There is no
	// default: the gate may sit in front of the carrier listener or in front
	// of the AmneziaWG gateway, and guessing wrong sends the deployment's
	// credential to the wrong host.
	ErrTargetRequired = errors.New("knockdial: a knock target is required")

	// ErrSettleTooLong means Config.Settle exceeds MaxSettle.
	ErrSettleTooLong = fmt.Errorf(
		"knockdial: settle delay must not exceed %s", MaxSettle,
	)
)

// Config is the client-side SPA configuration for one carrier dialer.
//
// Key is the only secret here and it is never logged, never copied into an
// error, and never written anywhere by this package.
type Config struct {
	// Key is this client's current SPA key. Loaded by the caller through
	// knock.LoadKeysFromFile, which is the loader that owns that file format.
	Key []byte

	// Target is the "host:port" the knock datagram is addressed to. It is
	// mandatory and has no default; see ErrTargetRequired.
	Target string

	// PacketSize is the exact datagram size, which must match the gate's. The
	// caller derives it — see internal/knock's package doc on why this package
	// cannot have a safe default.
	PacketSize int

	// Options is the freshness policy. It must match the gate's or every knock
	// simply fails to verify, which fails closed.
	Options knock.Options

	// Settle overrides DefaultSettle. Negative is rejected; zero uses the
	// default.
	Settle time.Duration
}

// Dialer decorates a carrier.SuppliedSocketDialer with one SPA knock before
// each Dial.
//
// It is safe for concurrent use to the same degree the inner dialer is: the
// only state it adds is the supplied socket recorded by UseSuppliedSocket,
// guarded by a mutex.
type Dialer struct {
	inner      carrier.PacketSocketDialer
	key        []byte
	target     string
	packetSize int
	options    knock.Options
	settle     time.Duration

	// sendVia and sendOwn are indirections for tests only. Production always
	// gets knock.SendVia and knock.Send.
	sendVia func(net.PacketConn, net.Addr, []byte, int, knock.Options) error
	sendOwn func(context.Context, string, []byte, int, knock.Options) error
	sleep   func(context.Context, time.Duration)

	mu      sync.Mutex
	packets net.PacketConn
}

// Interface compliance is asserted at compile time so a change to either
// carrier interface breaks the build here rather than at a call site.
var (
	_ carrier.SuppliedSocketDialer = (*Dialer)(nil)
	_ carrier.PacketSocketDialer   = (*Dialer)(nil)
)

// New wraps inner so that every Dial is preceded by one SPA knock.
//
// It performs no I/O and opens no socket, so the returned dialer is still
// legal to hand to datapath.OpenWithCarrier: HasSuppliedSocket forwards to
// inner, which has none.
func New(inner carrier.SuppliedSocketDialer, cfg Config) (*Dialer, error) {
	if inner == nil {
		return nil, ErrInnerDialerRequired
	}
	packetDialer, ok := inner.(carrier.PacketSocketDialer)
	if !ok || inner.SuppliedSocketKind() != carrier.SocketKindPacket {
		return nil, ErrStreamCarrierUnsupported
	}
	if cfg.Target == "" {
		return nil, ErrTargetRequired
	}
	if _, _, err := net.SplitHostPort(cfg.Target); err != nil {
		return nil, fmt.Errorf("knockdial: knock target %q: %w", cfg.Target, err)
	}
	settle := cfg.Settle
	switch {
	case settle < 0:
		return nil, errors.New("knockdial: settle delay must not be negative")
	case settle == 0:
		settle = DefaultSettle
	case settle > MaxSettle:
		return nil, ErrSettleTooLong
	}
	// Build one throwaway knock now, at construction, so a key that is too
	// short or a packet size that is impossible is a loud failure here rather
	// than a silently skipped knock at dial time. The packet is discarded; it
	// is never sent and never stored.
	if _, err := knock.Build(cfg.Key, cfg.PacketSize, time.Now(), cfg.Options); err != nil {
		return nil, err
	}
	return &Dialer{
		inner:      packetDialer,
		key:        append([]byte(nil), cfg.Key...),
		target:     cfg.Target,
		packetSize: cfg.PacketSize,
		options:    cfg.Options,
		settle:     settle,
		sendVia:    knock.SendVia,
		sendOwn:    knock.Send,
		sleep:      sleepContext,
	}, nil
}

// SuppliedSocketKind forwards to the inner dialer.
func (d *Dialer) SuppliedSocketKind() carrier.SocketKind {
	return d.inner.SuppliedSocketKind()
}

// HasSuppliedSocket forwards to the inner dialer. It deliberately does not
// report this decorator's own recorded socket separately: datapath's
// ErrCarrierSocketReused check asks "has the carrier already been given a
// socket", and the carrier is the inner dialer.
func (d *Dialer) HasSuppliedSocket() bool {
	return d.inner.HasSuppliedSocket()
}

// UseSuppliedSocket records the host's protected socket and forwards it to the
// inner dialer, which takes ownership. This decorator never closes it: it
// writes exactly one datagram to it in Dial.
func (d *Dialer) UseSuppliedSocket(conn net.PacketConn) error {
	if err := d.inner.UseSuppliedSocket(conn); err != nil {
		return err
	}
	d.mu.Lock()
	d.packets = conn
	d.mu.Unlock()
	return nil
}

// Dial sends one SPA knock, waits out the settle delay, then dials.
//
// A knock failure does NOT abort the dial. There is no acknowledgement to wait
// for — internal/knock's server side answers nothing on any path, by design —
// so a client cannot tell a delivered knock from a dropped one, and refusing
// to dial after a local write error would only convert a recoverable case
// (the target does not actually require SPA, or the datagram was in fact
// delivered) into a guaranteed failure. The fallback is therefore: proceed,
// and let the dial fail on its own if the gate really did drop it. That is
// also what cmd/winn-carrier-client already does with a failed knock.
func (d *Dialer) Dial(ctx context.Context) (net.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("knockdial: dial context is required")
	}
	if err := d.knock(ctx); err == nil {
		d.sleep(ctx, d.settle)
	}
	return d.inner.Dial(ctx)
}

// knock writes one datagram. See Dial on why its error is advisory.
func (d *Dialer) knock(ctx context.Context) error {
	d.mu.Lock()
	conn := d.packets
	d.mu.Unlock()

	if conn == nil {
		// No socket was supplied, so the inner carrier will open its own. See
		// the package doc: this is only reachable behind allow_own_socket, and
		// a knock socket here is exactly as protected as the transport.
		return d.sendOwn(ctx, d.target, d.key, d.packetSize, d.options)
	}
	addr, err := net.ResolveUDPAddr("udp", d.target)
	if err != nil {
		return fmt.Errorf("knockdial: resolving knock target: %w", err)
	}
	return d.sendVia(conn, addr, d.key, d.packetSize, d.options)
}

// sleepContext waits for d, returning early if ctx is done. It never reports
// which happened: the caller dials either way.
func sleepContext(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// DescribeForLog is a redacted one-line summary. It names the target and the
// sizing, which are transport parameters an operator's own connection log
// already has, and never the key or anything derived from it.
func (d *Dialer) DescribeForLog() string {
	return fmt.Sprintf(
		"winn spa initiation: target=%s packet_size=%d settle=%s",
		d.target, d.packetSize, d.settle,
	)
}
