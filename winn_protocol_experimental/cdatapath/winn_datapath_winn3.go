//go:build darwin

// winn_datapath_winn3.go — the winn/3 STANDALONE carrier path across the same
// C ABI, alongside direct-awg rather than instead of it.
//
// ---------------------------------------------------------------------------
// WHY A SECOND CREATE AND NOT A SECOND ABI
// ---------------------------------------------------------------------------
//
// WinnTunnelCreate and WinnTunnelCreateWithCarrier both build a
// datapath.Engine: the v1/v2 shape in which Winn RELAYS AmneziaWG's already
// encapsulated outer datagrams. The bytes crossing WinnTunnelWriteInbound and
// WinnTunnelReadOutbound are therefore "awg-datagram", and datapath.Config
// refuses "payload":"ip-packet" at create time precisely so that a host which
// pumps raw IP into that boundary fails at the handshake instead of forwarding
// cleartext on the wire.
//
// winn/3 standalone is the other shape. There is no AmneziaWG anywhere in it:
// the driver loop owns the session, the tun layer validates inner IP, and the
// bytes crossing the SAME two functions are "ip-packet". Nothing else about the
// ABI changes — the handle space, the negative error codes, the string
// ownership rule, the threading rule and WinnTunnelClose are shared verbatim,
// because a host that has already implemented the relay pump implements this
// one by changing which create it calls and which packets it feeds.
//
// The two registries are disjoint and handles are drawn from the one counter,
// so a handle is in at most one of them and the shared entry points can
// dispatch on presence with no tag byte and no ambiguity.
//
// ---------------------------------------------------------------------------
// WHY THE DEVICE IS THIS FILE'S AND NOT THE HOST'S FILE DESCRIPTOR
// ---------------------------------------------------------------------------
//
// winn3/tun.Device is ReadPacket/WritePacket/MTU. On Linux and Android a host
// satisfies it with the utun/tun file descriptor directly and Go never copies.
// On Apple it cannot: NEPacketTunnelFlow is an asynchronous Objective-C object
// with no public descriptor, and the one documented way to reach a descriptor
// behind it is a private key path that fails App Review. So on Apple the device
// has to be a queue whose two ends are the two ABI functions, which is exactly
// what abiDevice is:
//
//	host packetFlow.readPackets  -> WinnTunnelWriteInbound  -> device.ReadPacket
//	host packetFlow.writePackets <- WinnTunnelReadOutbound  <- device.WritePacket
//
// The cost is one copy in each direction, paid on a path that already copies
// once at the NEPacketTunnelFlow boundary.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE DELIBERATELY DOES NOT DO
// ---------------------------------------------------------------------------
//
//   - It does not promote a route, install a setting, or decide anything about
//     the host's posture. It PUBLISHES the two numbers §4.1 of
//     WINN3_TUN_LAYER_20260808.md says a promotion may be gated on
//     (winn3_gate_state and winn3_rx_packets) and stops there.
//   - It does not open a socket unless the configuration says it may. On Apple
//     the outer socket is kept off the tunnel by an excludedRoutes /32, and a
//     host that has not installed it must not be handed a socket by this file.
//   - It never resolves a hostname. gateway_endpoint is an IP literal with a
//     port, for the same reason WinnTunnelCreate requires one: a lookup here
//     is a lookup outside the tunnel.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/dualsign"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// winn3Contract is the winn/3 standalone contract name. It is deliberately NOT
// datapath.ContractVersion: a host that compares the two and finds them equal
// would conclude that a relay archive can carry inner IP, which is the exact
// mistake the payload class exists to prevent.
const winn3Contract = "winn-datapath/1+winn3"

// winn3Carrier is the only value the "carrier" field may take on this entry
// point. Naming direct-awg here is refused rather than honoured, for the same
// anti-downgrade reason WinnTunnelCreateWithCarrier refuses it.
const winn3Carrier = "winn3"

// winn3Payload is the only payload class this entry point accepts. It is the
// one datapath.Config refuses, and that asymmetry is the whole point.
const winn3Payload = "ip-packet"

var (
	errWinn3Config = errors.New("winn3: invalid configuration")

	// winn3DeviceClosed is what abiDevice returns once the tunnel is closing,
	// so tun.PumpOutbound unwinds instead of spinning.
	winn3DeviceClosed = errors.New("winn3: host device is closed")
)

// winn3Config is the create document. Decoded with DisallowUnknownFields, so a
// helpfully-added key is a hard refusal rather than a silent default — the same
// rule datapath.Config follows and for the same reason.
type winn3Config struct {
	Contract string `json:"contract"`
	Payload  string `json:"payload"`
	Carrier  string `json:"carrier"`

	// GatewayEndpoint is "ip:port". A hostname is refused.
	GatewayEndpoint string `json:"gateway_endpoint"`

	// StaticPrivate is this endpoint's X25519 static private key, base64.
	// GatewayStatic is the gateway's X25519 static public key, base64, learned
	// from the ML-DSA-65-signed descriptor the control plane already ships.
	StaticPrivate string `json:"static_private"`
	GatewayStatic string `json:"gateway_static"`

	// GatewayID and AdmissionKey are the admission profile, and they come from
	// the SAME signed descriptor as gateway_static. GatewayID binds an
	// admission tag to one gateway so an initiation captured at A cannot be
	// replayed at B; AdmissionKey is the secret the tag is computed under. A
	// client holds exactly one admission key.
	//
	// THEY ARE ENCODED DIFFERENTLY AND THAT ASYMMETRY IS DELIBERATE.
	// AdmissionKey is base64: it is a secret whose bytes are arbitrary, so a
	// JSON string cannot carry them any other way. GatewayID is the RAW STRING
	// — the operator's own gateway name, the identical text that
	// cmd/winn3-gateway takes in -gateway-id — because it is an authenticated
	// tag input that both ends must derive identically and every other host in
	// this tree derives it as []byte(theOperatorString). Base64-decoding it
	// here made the Apple client compute a different tag from the same operator
	// value, and a gateway that cannot verify a tag answers nothing at all. See
	// admissionProfile for where the descriptor's own base64 is decoded.
	//
	// Neither is ever put on the wire in the clear and neither is echoed in the
	// status document.
	GatewayID    string `json:"gateway_id"`
	AdmissionKey string `json:"admission_key"`

	// AuthEd25519 and AuthMLDSA65 are the gateway's dual-signature
	// attestation public keys, canonical base64 over exactly 32 and 1952 bytes.
	// Both absent preserves the legacy session byte-for-byte. Any other partial
	// or malformed shape is a create refusal, never a session that silently
	// drops the attestation.
	AuthEd25519 *string `json:"auth_ed25519"`
	AuthMLDSA65 *string `json:"auth_mldsa65"`

	// PSK is the optional 32-byte per-subscriber preshared key, base64. It is
	// what stands between a compromised GATEWAY static key and key-compromise
	// impersonation of this subscriber, and it is absent from the shipping
	// deployment today.
	PSK string `json:"psk"`

	// InnerV4 / InnerV6 are the addresses this tunnel owns, and InnerRouterV4 /
	// InnerRouterV6 the inner next hop. The router addresses are optional and
	// are used only as the source of a synthesised path-MTU packet.
	InnerV4       string `json:"inner_v4"`
	InnerV6       string `json:"inner_v6"`
	InnerRouterV4 string `json:"inner_router_v4"`
	InnerRouterV6 string `json:"inner_router_v6"`

	// PathMTU is the OUTER path MTU the plan floor is computed at. Zero means
	// carrier.DefaultPathMTU, the fleet default.
	//
	// It read tun.IPv6MinLinkMTU until 2026-08-10, which was the SAME NUMBER by
	// a different name. That is how the fleet default gets raised on three hosts
	// and not on the fourth: this seam is Apple's route into the engine, and a
	// raise that moved carrier.DefaultPathMTU alone would have left every Apple
	// client planning at 1280 against gateways planning at 1450 — a
	// path-MTU mismatch on every default session, which the notice now makes a
	// loud refusal rather than a black hole, but a total outage either way.
	PathMTU int `json:"path_mtu"`

	// CarrierClasses is the migration plan: every class the session may
	// escalate TO, not the one dialled. Empty means {"udp"} alone, which is a
	// plan that forbids migration rather than a plan that ignores it.
	CarrierClasses []string `json:"carrier_classes"`

	// AllowOwnSocket permits opening the outer socket here when udpFD < 0. A
	// host that must protect or exclude the socket itself leaves it false and
	// passes a descriptor.
	AllowOwnSocket bool `json:"allow_own_socket"`

	// SessionID is opaque and is echoed in the status document so a host can
	// correlate. It is never put on the wire.
	SessionID string `json:"session_id"`

	// dualAuth is derived from the two public JSON fields during strict decode.
	// Keeping the decoded bytes on this per-create value means openWinn3 binds
	// exactly what was validated, with no second decode that could drift.
	dualAuth session.DualAuthConfig
}

// winn3Tunnel is one supervised tunnel: a driver.Reconnect whose rounds are
// each a driver loop plus the queue that is its host device.
//
// loop and dev are the CURRENT round's. When a round's session dies the
// supervisor retires it and builds a fresh session on a fresh carrier wrapper
// over the same socket, and the handle the host holds stays valid throughout:
// the ABI functions follow the current round and absorb the recovery window
// rather than reporting the tunnel closed.
type winn3Tunnel struct {
	// mu guards loop, dev and next. It is never held while taking a device's
	// own mutex.
	mu     sync.Mutex
	loop   *driver.Loop
	dev    *abiDevice
	cancel context.CancelFunc

	// next closes when the next round is published or the supervisor ends, so
	// a host read parked on a retired round's device can move to its successor.
	next chan struct{}

	// socket is the outer socket every round's carrier borrows. closeSocket
	// closes it once, when the supervisor finishes.
	socket       *net.UDPConn
	socketOnce   sync.Once
	socketCloses atomic.Int32

	// recovering is true from a round's end until its successor is published.
	// It, closed, finished and everEstablished are written only under mu, so
	// snapshot reads all of them, and the current round, as one fact.
	recovering        atomic.Bool
	rounds            atomic.Uint64
	droppedRecovering atomic.Uint64

	// finished is set when the supervisor has returned, roundEnded when any
	// round has ended, and everProven when a round that ended had delivered.
	// All under mu.
	finished   bool
	roundEnded bool
	everProven bool

	sessionID    string
	carrierClass carrier.Class

	// ownSocket is true when THIS FILE opened the outer socket. On Apple that
	// means no descriptor was handed over, so nothing outside this process
	// could have excluded it from the tunnel's own routes — which is why it is
	// published rather than kept.
	ownSocket bool

	runErr atomic.Pointer[error]
	done   chan struct{}
	closed atomic.Bool
}

var (
	winn3Mu       sync.RWMutex
	winn3Registry = map[int64]*winn3Tunnel{}
)

func lookupWinn3(handle int64) *winn3Tunnel {
	winn3Mu.RLock()
	defer winn3Mu.RUnlock()
	return winn3Registry[handle]
}

// ---------------------------------------------------------------------------
// the host device
// ---------------------------------------------------------------------------

// abiDevice is tun.Device backed by the two ABI functions.
//
// outbound is what the host wrote in with WinnTunnelWriteInbound and the tun
// layer has not yet read; inbound is what the tun layer delivered and the host
// has not yet taken with WinnTunnelReadOutbound. Both are bounded: an unbounded
// queue in a packet datapath is a memory-growth bug waiting for a stall, and a
// dropped packet under back-pressure is what every other tun implementation
// does. Drops are counted so the silence is never unexplained.
type abiDevice struct {
	mtu int

	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond

	outbound [][]byte // host -> tunnel
	inbound  [][]byte // tunnel -> host
	depth    int

	closed bool

	// readMu is held for the whole of every ReadPacket, including its wait, so
	// retireReader can join the round's tun reader after close.
	readMu sync.Mutex

	droppedOutbound atomic.Uint64
	droppedInbound  atomic.Uint64
}

// winn3QueueDepth is a quarter second of a saturated 1 Gbit/s link at the inner
// MTU, rounded down to a power of two. Deep enough that a scheduling hiccup on
// either side does not drop, shallow enough that a stalled side cannot grow the
// process by more than a few megabytes.
const winn3QueueDepth = 256

func newABIDevice(mtu int) *abiDevice {
	d := &abiDevice{mtu: mtu, depth: winn3QueueDepth}
	d.notEmpty = sync.NewCond(&d.mu)
	d.notFull = sync.NewCond(&d.mu)
	return d
}

func (d *abiDevice) MTU() int { return d.mtu }

// ReadPacket is called by tun.PumpOutbound. It blocks until the host offers a
// packet or the device closes.
func (d *abiDevice) ReadPacket(buf []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	d.mu.Lock()
	for len(d.outbound) == 0 && !d.closed {
		d.notEmpty.Wait()
	}
	if len(d.outbound) == 0 {
		d.mu.Unlock()
		return 0, winn3DeviceClosed
	}
	pkt := d.outbound[0]
	d.outbound[0] = nil
	d.outbound = d.outbound[1:]
	d.notFull.Broadcast()
	d.mu.Unlock()

	// A short buffer is the caller's bug, not a reason to lose the packet
	// silently: copy what fits and report the truncation the way a tun device
	// would.
	n := copy(buf, pkt)
	if n < len(pkt) {
		return n, fmt.Errorf("winn3: read buffer of %d bytes is shorter than the %d-byte packet",
			len(buf), len(pkt))
	}
	return n, nil
}

// WritePacket is called by tun.Tunnel.Inbound after the packet has been
// VALIDATED. Reaching here is what makes tun.Stats().RxPackets move, which is
// the counter §4.1 says a promotion may be gated on — so a packet that gets
// here is a packet delivered, not merely arrived.
func (d *abiDevice) WritePacket(pkt []byte) (int, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return 0, winn3DeviceClosed
	}
	if len(d.inbound) >= d.depth {
		// Drop the OLDEST. A datapath that drops the newest under pressure
		// delivers a stale burst when the host wakes up; dropping the oldest
		// keeps the queue current, which is what inner TCP recovers from best.
		d.inbound[0] = nil
		d.inbound = d.inbound[1:]
		d.droppedInbound.Add(1)
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	d.inbound = append(d.inbound, cp)
	d.notEmpty.Broadcast()
	d.mu.Unlock()
	return len(pkt), nil
}

// offer is WinnTunnelWriteInbound's side: the host hands an inner packet in.
func (d *abiDevice) offer(pkt []byte) (int, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return 0, winn3DeviceClosed
	}
	if len(d.outbound) >= d.depth {
		d.outbound[0] = nil
		d.outbound = d.outbound[1:]
		d.droppedOutbound.Add(1)
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	d.outbound = append(d.outbound, cp)
	d.notEmpty.Broadcast()
	d.mu.Unlock()
	return len(pkt), nil
}

// take is WinnTunnelReadOutbound's side: the host collects a delivered packet.
func (d *abiDevice) take(buf []byte, timeout time.Duration) (int, error) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	d.mu.Lock()
	for len(d.inbound) == 0 && !d.closed {
		if deadline.IsZero() {
			d.notEmpty.Wait()
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			d.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		// sync.Cond has no timed wait. One waker per waiting take is cheap and
		// keeps the deadline honest without a second channel per device.
		// Hold the condition lock so the timeout cannot be signaled before Wait.
		timer := time.AfterFunc(remaining, func() {
			d.mu.Lock()
			d.notEmpty.Broadcast()
			d.mu.Unlock()
		})
		d.notEmpty.Wait()
		timer.Stop()
		if len(d.inbound) == 0 && !d.closed && time.Now().After(deadline) {
			d.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
	}
	if len(d.inbound) == 0 {
		d.mu.Unlock()
		return 0, winn3DeviceClosed
	}
	pkt := d.inbound[0]
	if len(buf) < len(pkt) {
		// Leave the packet queued. TOO_LARGE is a retryable host error — the
		// host can size to WinnTunnelMaxDatagram and call take again. Dequeue
		// then error used to drop a packet the tun layer had already validated
		// and counted as delivered.
		d.mu.Unlock()
		return 0, errWinn3TooLarge
	}
	d.inbound[0] = nil
	d.inbound = d.inbound[1:]
	d.notFull.Broadcast()
	d.mu.Unlock()
	return copy(buf, pkt), nil
}

var errWinn3TooLarge = errors.New("winn3: host buffer is smaller than the packet")

func (d *abiDevice) close() {
	d.mu.Lock()
	d.closed = true
	d.outbound = nil
	d.inbound = nil
	d.mu.Unlock()
	d.notEmpty.Broadcast()
	d.notFull.Broadcast()
}

// isClosed reports whether close has run.
func (d *abiDevice) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// retireReader waits until the round's tun reader has left the device. close
// must have run first, so a reader parked in ReadPacket has been woken.
func (d *abiDevice) retireReader(ctx context.Context) bool {
	joined := make(chan struct{})
	go func() {
		d.readMu.Lock()
		d.readMu.Unlock() //nolint:staticcheck // the lock is a join, not a guard
		close(joined)
	}()
	return winn3Await(ctx, joined)
}

// winn3CloseGrace bounds a retirement wait once the tunnel is being closed.
const winn3CloseGrace = 2 * time.Second

// winn3Await waits for done: without bound while ctx is live, because a
// successor must not be published before its predecessor is retired, and for
// at most winn3CloseGrace once ctx is done.
func winn3Await(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-ctx.Done():
	}
	select {
	case <-done:
		return true
	case <-time.After(winn3CloseGrace):
		return false
	}
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

// WinnTunnelCreateWinn3 opens one winn/3 STANDALONE tunnel.
//
// configJSON is a winn3Config document. udpFD is a UDP socket descriptor the
// host has already protected or excluded; THE ENGINE TAKES OWNERSHIP and closes
// it in WinnTunnelClose. Pass -1 only when the configuration sets
// allow_own_socket.
//
// Returns a positive handle, or 0 with an allocated error string in errorOut.
//
//export WinnTunnelCreateWinn3
func WinnTunnelCreateWinn3(
	configJSON *C.char,
	udpFD C.int,
	errorOut **C.char,
) C.longlong {
	if errorOut != nil {
		*errorOut = nil
	}
	if configJSON == nil {
		setError(errorOut, errors.New("winn3 configuration is NULL"))
		return 0
	}
	t, err := openWinn3([]byte(C.GoString(configJSON)), int(udpFD))
	if err != nil {
		setError(errorOut, err)
		return 0
	}
	handle := nextHandle.Add(1)
	winn3Mu.Lock()
	winn3Registry[handle] = t
	winn3Mu.Unlock()
	return C.longlong(handle)
}

// openWinn3 is the whole of create with no cgo in it, so the refusals are
// testable from ordinary Go.
func openWinn3(document []byte, udpFD int) (*winn3Tunnel, error) {
	cfg, err := decodeWinn3Config(document)
	if err != nil {
		return nil, err
	}

	classes, err := carrierClasses(cfg.CarrierClasses)
	if err != nil {
		return nil, err
	}
	pathMTU := cfg.PathMTU
	if pathMTU == 0 {
		// carrier.DefaultPathMTU and NOT tun.IPv6MinLinkMTU. The two were equal
		// until 2026-08-10 and the equality was load-bearing by accident; see
		// the field's doc comment.
		pathMTU = carrier.DefaultPathMTU
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		return nil, err
	}

	assign, err := assignment(cfg)
	if err != nil {
		return nil, err
	}
	// §2.3: an inner IPv6 assignment at a floor that cannot carry it is a
	// tunnel that drops all of its own v6 traffic. tun.New refuses it, but the
	// refusal reads better with the number that caused it.
	if assign.V6.IsValid() && !sizing.InnerIPv6 {
		return nil, fmt.Errorf(
			"%w: an inner IPv6 address needs an outer path MTU of at least %d over this plan; this one is %d",
			errWinn3Config, sizing.MinPathMTUForInnerIPv6, pathMTU)
	}

	// Validated here, before the socket, so a bad key or admission profile is
	// refused without touching the network. Every round derives its own copy.
	if _, _, err := keys(cfg); err != nil {
		return nil, err
	}
	if _, err := admissionProfile(cfg); err != nil {
		return nil, err
	}

	remote, err := gatewayEndpoint(cfg.GatewayEndpoint)
	if err != nil {
		return nil, err
	}

	conn, ownSocket, err := outerSocket(cfg, udpFD, remote)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &winn3Tunnel{
		cancel:    cancel,
		sessionID: cfg.SessionID,
		ownSocket: ownSocket,
		done:      make(chan struct{}),
		next:      make(chan struct{}),
		socket:    conn,
	}
	build := func() (*winn3Round, error) {
		return buildWinn3Round(ctx, t, cfg, conn, remote, sizing, pathMTU, assign)
	}
	// The first round is built here so its refusals still reach the host as
	// the create error.
	first, err := build()
	if err != nil {
		cancel()
		_ = conn.Close()
		return nil, err
	}
	t.carrierClass = first.car.Class()

	handed := false
	supervisor, err := driver.NewReconnect(driver.ReconnectConfig{
		Build: func() (driver.Runner, error) {
			if !handed {
				handed = true
				return first, nil
			}
			r, err := build()
			if err != nil {
				// Build touches no network, so a refusal now is a refusal
				// after any backoff too.
				return nil, fmt.Errorf("%w: %w", driver.ErrReconnectTerminal, err)
			}
			return r, nil
		},
		Attempts:   carrier.DefaultBackoffAttempts,
		ResetAfter: driver.DefaultReconnectResetAfter,
		Terminal:   driver.TerminalRoundError,
		// A tunnel that has never once established reports that now, as a
		// blocked status, rather than after five more handshake budgets.
		FailBeforeEstablishment: true,
	})
	if err != nil {
		cancel()
		_ = first.Close()
		_ = conn.Close()
		return nil, err
	}
	t.publish(first)
	go func() {
		defer close(t.done)
		runErr := supervisor.Run(ctx)
		if !handed {
			_ = first.Close()
		}
		if runErr != nil {
			t.runErr.Store(&runErr)
		}
		// The last round's device is closed. From here the host meets the
		// closed-device refusal it met before recovery existed: the tunnel has
		// ended and a host still sitting in ReadOutbound wakes with it.
		t.mu.Lock()
		t.recovering.Store(false)
		t.finished = true
		close(t.next)
		t.mu.Unlock()
		t.closeSocket()
	}()
	return t, nil
}

// buildWinn3Round builds one round over the tunnel's socket: its own keys and
// admission profile from cfg, a carrier wrapper that borrows the socket, its
// own device and a fresh loop. A failure closes what this call opened and never
// the socket.
func buildWinn3Round(
	ctx context.Context, t *winn3Tunnel, cfg winn3Config, conn *net.UDPConn, remote *net.UDPAddr,
	sizing driver.Sizing, pathMTU int, assign tun.Assignment,
) (*winn3Round, error) {
	static, gateway, err := keys(cfg)
	if err != nil {
		return nil, err
	}
	admission, err := admissionProfile(cfg)
	if err != nil {
		return nil, err
	}

	// A descriptor the host merely BOUND has no kernel-side peer filter, so the
	// carrier is told the peer explicitly and filters itself. A connected one
	// reports a RemoteAddr and needs neither. Guessing wrong in the permissive
	// direction is a tunnel that accepts datagrams from anywhere, so the test
	// is on the socket rather than on the configuration.
	//
	// OwnsConn false: the socket outlives the round, and a descriptor the host
	// handed over cannot be adopted twice.
	ucfg := carrier.UDPConfig{
		Conn:           conn,
		OwnsConn:       false,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        pathMTU,
	}
	if conn.RemoteAddr() == nil {
		ucfg.Peer = remote
	}
	car, err := carrier.NewUDP(ucfg)
	if err != nil {
		return nil, err
	}

	dev := newABIDevice(sizing.InnerMTU)

	// The gateway-to-client receive window W bounds the run of lost gateway
	// messages this session survives: W-1 on a clean stream, W/2-1 after a
	// recent loss. See winn3ClientTokenWindow in cmd/winn-datapath.
	// Receiver-local, so nothing on the wire changes.
	admission.TokenWindow = core.MaxTokenWindow

	sessionConfig := session.Config{
		Core:          admission,
		Static:        static,
		GatewayStatic: gateway,
		DualAuth:      cfg.dualAuth,
		// PadBucket is the design's default and PadNone is the zero value,
		// so leaving this unset would ship a length-shaping policy nobody
		// chose. Named here rather than defaulted for that reason.
		Padding: core.PadBucket,
	}
	if winn3TestSessionTweak != nil {
		winn3TestSessionTweak(&sessionConfig)
	}
	loop, err := driver.NewClient(driver.Config{
		Session: sessionConfig,
		Sizing:  sizing,
		Carrier: car,
		Tun: &tun.Config{
			Assign: assign,
			Device: dev,
		},
	})
	if err != nil {
		_ = car.Close()
		dev.close()
		return nil, err
	}
	return &winn3Round{t: t, ctx: ctx, loop: loop, dev: dev, car: car}, nil
}

// winn3Round is one supervised round, the driver.Runner the tunnel's Reconnect
// drives. The device is the round's so that a retired round's tun reader, which
// can stay parked in ReadPacket until its device closes, can never take a
// packet the host meant for the successor.
type winn3Round struct {
	t   *winn3Tunnel
	ctx context.Context

	loop *driver.Loop
	dev  *abiDevice
	car  carrier.Conn

	// published is guarded by t.mu.
	published bool
}

// Run publishes the round and drives its loop.
func (r *winn3Round) Run(ctx context.Context) error {
	if !r.t.publish(r) {
		return context.Canceled
	}
	err := r.loop.Run(ctx)
	if winn3TestHookRoundEnd != nil {
		winn3TestHookRoundEnd()
	}
	r.t.mu.Lock()
	if tn := r.loop.Tunnel(); tn != nil && tn.Stats().RxPackets > 0 {
		r.t.everProven = true
	}
	r.t.roundEnded = true
	r.t.recovering.Store(true)
	r.t.mu.Unlock()
	return err
}

// ProvenFor is the round's loop's.
func (r *winn3Round) ProvenFor() time.Duration { return r.loop.ProvenFor() }

// Established and PeerCloseReason are the round's loop's; see Reconnect.
func (r *winn3Round) Established() bool { return r.loop.Established() }

func (r *winn3Round) PeerCloseReason() session.CloseReason {
	return r.loop.PeerCloseReason()
}

var (
	_ driver.ProvenRunner      = (*winn3Round)(nil)
	_ driver.EstablishedRunner = (*winn3Round)(nil)
	_ driver.PeerCloseRunner   = (*winn3Round)(nil)
)

// Close retires the round: loop (latched, CLOSE offered while the carrier can
// still carry it), then the device, which wakes the tun reader and any host
// read, then a join on the reader, then the carrier wrappers. Never the socket.
func (r *winn3Round) Close() error {
	live := r.loop.Carrier()
	_ = r.loop.Close()
	r.dev.close()
	r.dev.retireReader(r.ctx)
	if live != nil && live != r.car {
		_ = live.Close()
	}
	_ = r.car.Close()
	return nil
}

// publish makes r the round the ABI reaches. It is idempotent and refuses once
// the host has closed the tunnel.
func (t *winn3Tunnel) publish(r *winn3Round) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return false
	}
	if r.published {
		return true
	}
	r.published = true
	t.loop = r.loop
	t.dev = r.dev
	t.recovering.Store(false)
	t.rounds.Add(1)
	close(t.next)
	t.next = make(chan struct{})
	return true
}

// winn3Snapshot is the tunnel's round state read as ONE fact under t.mu:
// owner closure, supervisor completion, the current round, and recovery.
// Deciding from fields read at different moments is how a host was once told
// "closed" while a successor round was live.
type winn3Snapshot struct {
	loop *driver.Loop
	dev  *abiDevice
	next <-chan struct{}

	closed     bool
	finished   bool
	recovering bool
	roundEnded bool
	everProven bool
	runErr     error
}

// winn3TestHookAfterSnapshot, when set, runs after every decision snapshot
// is taken and before it is used. Tests only: it is how a test publishes a
// successor exactly where a split read would have been torn. Nil in
// production.
var winn3TestHookAfterSnapshot func()

// winn3TestSessionTweak, when set, edits every round's session configuration
// before its loop is built. Tests only; nil in production.
var winn3TestSessionTweak func(*session.Config)

// winn3TestHookRoundEnd, when set, runs in a round's Run after its loop has
// returned (gate latched down) and before the round's end is recorded. Tests
// only; nil in production.
var winn3TestHookRoundEnd func()

func (t *winn3Tunnel) snapshot() winn3Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	next := t.next
	if next == nil {
		// A tunnel with no supervisor behind it has no successor to wait for.
		closed := make(chan struct{})
		close(closed)
		next = closed
	}
	var runErr error
	if err := t.runErr.Load(); err != nil {
		runErr = *err
	}
	return winn3Snapshot{
		loop:       t.loop,
		dev:        t.dev,
		next:       next,
		closed:     t.closed.Load(),
		finished:   t.finished,
		recovering: t.recovering.Load(),
		roundEnded: t.roundEnded,
		everProven: t.everProven,
		runErr:     runErr,
	}
}

// round returns the current round's loop and device, and a channel that closes
// when the next round is published or the supervisor ends.
func (t *winn3Tunnel) round() (*driver.Loop, *abiDevice, <-chan struct{}) {
	s := t.snapshot()
	return s.loop, s.dev, s.next
}

// recoveryAbsorbs reports whether a closed-device refusal from dev is only the
// recovery window: dev's round died and its successor is being built or has
// just been published. The host is then told nothing is wrong, because a host
// reads a closed tunnel as the end of protection. An operation that still
// holds a retired device is absorbed while its replacement is active; once the
// owner has closed the tunnel or the supervisor has finished, nothing is.
func (t *winn3Tunnel) recoveryAbsorbs(dev *abiDevice) bool {
	s := t.snapshot()
	if winn3TestHookAfterSnapshot != nil {
		winn3TestHookAfterSnapshot()
	}
	if s.closed || s.finished {
		return false
	}
	return s.recovering || s.dev != dev
}

// awaitRound waits for next or the deadline. False means the deadline passed.
func awaitRound(next <-chan struct{}, deadline time.Time) bool {
	if deadline.IsZero() {
		<-next
		return true
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-next:
		return true
	case <-timer.C:
		return false
	}
}

// closeSocket closes the tunnel's socket, once.
func (t *winn3Tunnel) closeSocket() {
	if t.socket == nil {
		return
	}
	t.socketOnce.Do(func() {
		t.socketCloses.Add(1)
		_ = t.socket.Close()
	})
}

func decodeWinn3Config(document []byte) (winn3Config, error) {
	// encoding/json.Decode of JSON null into a struct succeeds and leaves the
	// zero value. The contract check would then refuse contract "" as if the
	// host omitted the field. Same first-byte rule as decodeWinn3Create.
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) == 0 {
		return winn3Config{}, fmt.Errorf("%w: empty document", errWinn3Config)
	}
	if trimmed[0] != '{' {
		return winn3Config{}, fmt.Errorf("%w: document must be a JSON object", errWinn3Config)
	}
	var cfg winn3Config
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return winn3Config{}, fmt.Errorf("%w: %v", errWinn3Config, err)
	}
	// Same rule as datapath.ParseConfig: a second JSON value after the object
	// is an under-read. encoding/json.Decoder stops at the first value, so
	// `{"contract":"..."}{"payload":"awg-datagram"}` would otherwise create
	// with the first object's fields and silently drop the rest.
	if dec.More() {
		return winn3Config{}, fmt.Errorf(
			"%w: document must be a single JSON object", errWinn3Config)
	}
	if cfg.Contract != winn3Contract {
		return winn3Config{}, fmt.Errorf(
			"%w: contract is %q, this archive implements %q",
			errWinn3Config, cfg.Contract, winn3Contract)
	}
	// The payload class is checked BEFORE anything else about the transport,
	// because getting it wrong is the failure that puts cleartext on the wire.
	if cfg.Payload != winn3Payload {
		return winn3Config{}, fmt.Errorf(
			"%w: payload is %q; this entry point carries %q only, and %q belongs on WinnTunnelCreate",
			errWinn3Config, cfg.Payload, winn3Payload, "awg-datagram")
	}
	if cfg.Carrier != winn3Carrier {
		return winn3Config{}, fmt.Errorf(
			"%w: carrier is %q; this entry point builds %q only. direct-awg and http3-connect-udp "+
				"are the relay entry points and are refused here so the anti-downgrade check cannot be "+
				"bypassed by calling the other create",
			errWinn3Config, cfg.Carrier, winn3Carrier)
	}
	if err := rejectDuplicateWinn3DualAuthFields(trimmed); err != nil {
		return winn3Config{}, err
	}
	dualAuth, err := decodeWinn3DualAuthPublicKeys(cfg.AuthEd25519, cfg.AuthMLDSA65)
	if err != nil {
		return winn3Config{}, err
	}
	cfg.dualAuth = dualAuth
	return cfg, nil
}

// rejectDuplicateWinn3DualAuthFields preserves encoding/json's legacy
// last-key-wins behaviour for every existing field while refusing replacement
// of either new attestation key. A duplicated key can otherwise replace exact
// signed descriptor material after the first occurrence has already been
// staged, and DisallowUnknownFields does not reject duplicates.
func rejectDuplicateWinn3DualAuthFields(document []byte) error {
	dec := json.NewDecoder(bytes.NewReader(document))
	if _, err := dec.Token(); err != nil {
		return nil // decodeWinn3Config reports the syntax error with its stable shape.
	}
	counts := map[string]int{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil
		}
		name, ok := token.(string)
		if !ok {
			return nil
		}
		for _, protected := range []string{"auth_ed25519", "auth_mldsa65"} {
			if strings.EqualFold(name, protected) {
				counts[protected]++
				if counts[protected] > 1 {
					return fmt.Errorf("%w: %s is duplicated; replacing signed dual-auth material is refused",
						errWinn3Config, protected)
				}
			}
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil
		}
	}
	return nil
}

func decodeWinn3DualAuthPublicKeys(edEncoded, mlEncoded *string) (session.DualAuthConfig, error) {
	if edEncoded == nil && mlEncoded == nil {
		return session.DualAuthConfig{}, nil
	}
	if (edEncoded == nil) != (mlEncoded == nil) {
		return session.DualAuthConfig{}, fmt.Errorf(
			"%w: auth_ed25519 and auth_mldsa65 must be both present or both absent",
			errWinn3Config)
	}

	decode := func(field, encoded string, want int) ([]byte, error) {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: %s is not canonical base64 for exactly %d bytes",
				errWinn3Config, field, want)
		}
		if len(raw) != want || base64.StdEncoding.EncodeToString(raw) != encoded {
			return nil, fmt.Errorf("%w: %s is not canonical base64 for exactly %d bytes",
				errWinn3Config, field, want)
		}
		return raw, nil
	}
	edPublic, err := decode("auth_ed25519", *edEncoded, dualsign.Ed25519PublicKeySize)
	if err != nil {
		return session.DualAuthConfig{}, err
	}
	mlPublic, err := decode("auth_mldsa65", *mlEncoded, dualsign.MLDSA65PublicKeySize)
	if err != nil {
		return session.DualAuthConfig{}, err
	}
	return session.DualAuthConfig{
		Expected:      true,
		Ed25519Public: edPublic,
		MLDSA65Public: mlPublic,
	}, nil
}

func carrierClasses(names []string) ([]carrier.Class, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: carrier_classes must name the migration plan", errWinn3Config)
	}
	out := make([]carrier.Class, 0, len(names))
	hasUDP := false
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "udp":
			out = append(out, carrier.ClassUDP)
			hasUDP = true
		case "tcp":
			out = append(out, carrier.ClassTCP)
		case "tls":
			out = append(out, carrier.ClassTLS)
		default:
			return nil, fmt.Errorf("%w: %q is not a carrier class", errWinn3Config, name)
		}
	}
	if !hasUDP {
		return nil, fmt.Errorf("%w: carrier_classes must contain udp because this entry point dials udp", errWinn3Config)
	}
	return out, nil
}

func assignment(cfg winn3Config) (tun.Assignment, error) {
	var a tun.Assignment
	parse := func(field, value string, dst *netip.Addr) error {
		if value == "" {
			return nil
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return fmt.Errorf("%w: %s is not an IP address", errWinn3Config, field)
		}
		*dst = addr.Unmap()
		return nil
	}
	if err := parse("inner_v4", cfg.InnerV4, &a.V4); err != nil {
		return a, err
	}
	if err := parse("inner_v6", cfg.InnerV6, &a.V6); err != nil {
		return a, err
	}
	if err := parse("inner_router_v4", cfg.InnerRouterV4, &a.RouterV4); err != nil {
		return a, err
	}
	if err := parse("inner_router_v6", cfg.InnerRouterV6, &a.RouterV6); err != nil {
		return a, err
	}
	return a, nil
}

// minAdmissionKeyBytes mirrors winn3/core's unexported minAdmissionKeySize. It
// is restated rather than imported because core does not export it; the test
// TestTheAdmissionFloorHereIsStillCoresFloor asserts the two agree by feeding
// core a key one byte below this and requiring a refusal, so a change in core
// breaks this file's tests rather than silently loosening its gate.
const minAdmissionKeyBytes = 32

func keys(cfg winn3Config) (*core.StaticKey, *core.PublicKey, error) {
	priv, err := base64.StdEncoding.DecodeString(cfg.StaticPrivate)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: static_private is not base64", errWinn3Config)
	}
	static, err := core.NewStaticKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: static_private: %v", errWinn3Config, err)
	}
	pub, err := base64.StdEncoding.DecodeString(cfg.GatewayStatic)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: gateway_static is not base64", errWinn3Config)
	}
	gateway, err := core.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: gateway_static: %v", errWinn3Config, err)
	}
	return static, gateway, nil
}

// admissionProfile builds the core configuration from the create document's
// admission fields. It refuses an absent gateway id or admission key rather
// than letting core.Config's own validator produce a message ("gateway id is
// empty") that names a Go field no host can see.
//
// gateway_id is taken as the RAW BYTES of the string, and this is the single
// most load-bearing line in the file. It used to be base64-decoded here, and
// this entry point was the ONLY one of five in the tree that did:
// cmd/winn-datapath/winn3_keys.go, cmd/winn-datapath/winn3_run.go,
// cmd/winn3-labrig/main.go and cmd/winn3-gateway/main.go — the last of which is
// the gateway that answers — all take []byte(theOperatorString). The gateway id
// is an AUTHENTICATED INPUT to the admission tag and is never transmitted, so
// two ends that derive different bytes from the same operator value produce
// different tags, and a v3 gateway never answers a datagram whose tag it could
// not verify. The Apple client would therefore have been refused in silence,
// which on a censored network is indistinguishable from "no gateway is there".
//
// The signed descriptor DOES carry gateway_id base64-encoded — it is a
// canonical-JSON object and every byte-valued field in it is base64, checked by
// the hub at server/wins_control_plane_setup_ONETOUCH.sh (the
// descriptor-field-not-base64 refusal), bounded 1..255 DECODED bytes. That
// decode belongs at the DESCRIPTOR boundary, not here: this document is the
// host-to-engine interface, and the four other host-to-engine interfaces in
// this tree all hand the engine the operator string's bytes. On Apple the
// descriptor boundary is WinsWinn3CreateDocument.make in
// apple/WinsTunnelCore/WinsWinn3SessionStart.swift, which decodes [winn]
// gateway_id before writing it here.
//
// A consequence, stated rather than hidden: gateway_id must now be
// UTF-8-representable, because a JSON string is. The hub permits any 1..255
// bytes. Every other host in the tree already has that same narrowing — a CLI
// flag and a JSON profile string are both text — so it is the tree's existing
// constraint being applied consistently rather than a new one.
func admissionProfile(cfg winn3Config) (core.Config, error) {
	id := []byte(cfg.GatewayID)
	if len(id) == 0 {
		return core.Config{}, fmt.Errorf(
			"%w: gateway_id is required; it comes from the same ML-DSA-65-signed descriptor as "+
				"gateway_static and is what stops an initiation captured at one gateway from being "+
				"replayed at another", errWinn3Config)
	}
	key, err := base64.StdEncoding.DecodeString(cfg.AdmissionKey)
	if err != nil {
		return core.Config{}, fmt.Errorf("%w: admission_key is not base64", errWinn3Config)
	}
	if len(key) == 0 {
		return core.Config{}, fmt.Errorf(
			"%w: admission_key is required; without it no initiation this client sends carries a tag "+
				"the gateway will admit", errWinn3Config)
	}
	// The floor is core's (winn3/core/params.go, minAdmissionKeySize) and core
	// enforces it too — but only at driver.NewClient, which in openWinn3 runs
	// AFTER outerSocket has already opened a connection to the gateway. That
	// ordering buys an observable connection to a censored endpoint for a
	// session that could never be admitted, so the floor is applied here, where
	// nothing has been opened.
	//
	// The message names the length because length is the ONLY non-secret fact
	// that separates the two encodings an operator can plausibly write, and
	// getting it wrong costs a whole debugging session: the gateway's
	// admission file in this tree holds the ASCII HEX TEXT of the secret
	// (cmd/winn3-labrig runKeygen writes hex.EncodeToString and
	// buildGatewaySession reads the file RAW), so a 32-byte secret is 64
	// admission-key bytes at the gateway. A client that base64s the DECODED 32
	// bytes instead produces a well-formed, floor-passing, WRONG key, every
	// initiation is refused, and a v3 gateway refuses in silence. Nothing on
	// either end can tell that apart from a censor by itself — which is why
	// winn3/conform exists and why AdmissionRoundTrip is the check that
	// actually settles it. This refusal only catches the case length CAN see.
	if len(key) < minAdmissionKeyBytes {
		return core.Config{}, fmt.Errorf(
			"%w: admission_key decodes to %d bytes and at least %d are required. Check which "+
				"encoding the gateway holds: this tree's keygen writes the admission file as ASCII "+
				"HEX TEXT and the gateway reads that file raw, so admission_key is base64 of the "+
				"HEX TEXT, not base64 of the %d decoded bytes. The key FIELDS in this same document "+
				"are the opposite convention — base64 of raw bytes — and that asymmetry is real",
			errWinn3Config, len(key), minAdmissionKeyBytes, minAdmissionKeyBytes)
	}
	out := core.Config{
		Gateway: core.GatewayParams{
			AdmissionKeys: [][]byte{key},
			GatewayID:     id,
		},
	}
	if cfg.PSK != "" {
		psk, err := base64.StdEncoding.DecodeString(cfg.PSK)
		if err != nil {
			return core.Config{}, fmt.Errorf("%w: psk is not base64", errWinn3Config)
		}
		out.PSK = psk
	}
	return out, nil
}

func gatewayEndpoint(endpoint string) (*net.UDPAddr, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: gateway_endpoint is required", errWinn3Config)
	}
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: gateway_endpoint must be an IP literal with a port; a hostname is refused because "+
				"resolving one here would leak a lookup outside the tunnel", errWinn3Config)
	}
	if ap.Port() == 0 {
		return nil, fmt.Errorf("%w: gateway_endpoint port is zero", errWinn3Config)
	}
	return net.UDPAddrFromAddrPort(ap), nil
}

// outerSocket adopts the host's descriptor, or opens one when the configuration
// explicitly allows it. Adopting is the default because on three of five
// platforms a socket this file opened is a socket the host never protected.
func outerSocket(cfg winn3Config, udpFD int, remote *net.UDPAddr) (*net.UDPConn, bool, error) {
	if udpFD < 0 {
		if !cfg.AllowOwnSocket {
			return nil, false, fmt.Errorf(
				"%w: no socket was supplied and allow_own_socket is false; a socket opened here is a "+
					"socket the host never excluded from its own tunnel", errWinn3Config)
		}
		conn, err := net.DialUDP("udp", nil, remote)
		if err != nil {
			return nil, false, err
		}
		return conn, true, nil
	}

	// os.NewFile takes ownership of the descriptor; net.FilePacketConn DUPS it,
	// so the original must be closed or it leaks for the life of the process.
	f := os.NewFile(uintptr(udpFD), "winn3-carrier")
	if f == nil {
		return nil, false, fmt.Errorf("%w: %d is not a usable descriptor", errWinn3Config, udpFD)
	}
	pc, err := net.FilePacketConn(f)
	closeErr := f.Close()
	if err != nil {
		return nil, false, fmt.Errorf("%w: supplied descriptor is not a datagram socket: %v",
			errWinn3Config, err)
	}
	if closeErr != nil {
		_ = pc.Close()
		return nil, false, fmt.Errorf("%w: could not release the supplied descriptor: %v",
			errWinn3Config, closeErr)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, false, fmt.Errorf("%w: supplied descriptor is a %T, not a UDP socket",
			errWinn3Config, pc)
	}
	return conn, false, nil
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

// winn3Status is the status document. The two fields a route promotion may be
// gated on are named so that no host has to infer them:
//
//	winn3_gate_state == "carrying"  is Gate.State() == StateCarrying
//	winn3_rx_packets  > 0           is Stats().RxPackets > 0
//
// winn3_rx_offered is published NEXT TO it deliberately. RxOffered counts
// arrivals and RxPackets counts deliveries; a host that gates on the first has
// promoted on a packet that may have been rejected by the inner-IP validator,
// and publishing both is the cheapest way to make the wrong one visibly wrong.
type winn3Status struct {
	Contract     string `json:"contract"`
	Payload      string `json:"payload"`
	Carrier      string `json:"carrier"`
	CarrierClass string `json:"winn3_carrier_class"`
	SessionID    string `json:"session_id,omitempty"`

	RuntimeCompleted bool   `json:"winn3_runtime_completed"`
	Closed           bool   `json:"closed"`
	CarrierError     string `json:"carrier_error,omitempty"`

	GateState string `json:"winn3_gate_state"`
	MayCarry  bool   `json:"winn3_may_carry"`
	InnerMTU  int    `json:"winn3_inner_mtu"`
	InnerIPv6 bool   `json:"winn3_inner_ipv6"`
	PlanFloor int    `json:"winn3_plan_message_size"`
	// RENAMED 2026-08-09 from `winn3_plan_path_mtu`. The Apple sampler splits
	// every key on `_`/`-` and drops it if any token is in
	// `deniedRuntimeStatusFragments`, which holds `path` — so the old spelling
	// was allowlisted on the Swift side and still never reached the host. The
	// denial is a real privacy control (it keeps endpoints, hostnames and file
	// paths out of a status document a bug report carries) and was left alone;
	// the KEY moved past the token instead. `ceiling` says the same thing
	// `path` did here: the largest carrier datagram the plan may emit.
	PlanMTUCeiling int      `json:"winn3_plan_mtu_ceiling"`
	PlanClasses    []string `json:"winn3_plan_classes"`

	RxPackets uint64 `json:"winn3_rx_packets"`
	RxOffered uint64 `json:"winn3_rx_offered"`
	RxBytes   uint64 `json:"winn3_rx_bytes"`
	TxPackets uint64 `json:"winn3_tx_packets"`
	TxBytes   uint64 `json:"winn3_tx_bytes"`

	TxDroppedClosed uint64 `json:"winn3_tx_dropped_closed"`
	RxDroppedClosed uint64 `json:"winn3_rx_dropped_closed"`

	// The two INVALID counters, published together because they are the pair
	// that says "the tunnel refused" rather than "the tunnel is idle", and a
	// host that had only one of them would read the missing direction as
	// healthy.
	//
	// TxDroppedInvalid is the outbound deanonymisation refusal: the gate was
	// OPEN and the packet was refused anyway, because the tun layer would not
	// carry it — most importantly a source address this session was never
	// assigned. Until it was published here the only way to show that such a
	// packet never left the host was a packet capture, which is not something
	// that can be done on a user's phone.
	//
	// It is a count of packets this process refused locally. It carries no
	// address, no endpoint and no identifier, so it is safe to sample and log
	// in full.
	RxDroppedInvalid uint64 `json:"winn3_rx_dropped_invalid"`
	TxDroppedInvalid uint64 `json:"winn3_tx_dropped_invalid"`

	MessagesSent     uint64 `json:"winn3_messages_sent"`
	MessagesReceived uint64 `json:"winn3_messages_received"`
	Migrations       uint64 `json:"winn3_migrations"`

	// The device-queue overflow counters — the ONLY evidence that the ring
	// between this engine and its host overflowed and dropped packets. A user
	// reporting "slow and lossy" produces a diagnostic bundle whose cause is
	// invisible without them.
	//
	// RENAMED 2026-08-09 from `winn3_host_queue_dropped_{outbound,inbound}`.
	// Same mechanism as `PlanMTUCeiling` above: the Apple sampler denies the
	// `host` token, so both keys were allowlisted and both were eaten before
	// any host saw them. `queue` already carries the distinction that mattered
	// — these are QUEUE overflow drops, as opposed to the gate refusals in
	// `winn3_{rx,tx}_dropped_closed` and the validator refusals in
	// `winn3_{rx,tx}_dropped_invalid` — so dropping `host` costs no meaning.
	QueueDroppedOutbound uint64 `json:"winn3_queue_dropped_outbound"`
	QueueDroppedInbound  uint64 `json:"winn3_queue_dropped_inbound"`

	// SocketOwnedByEngine mirrors the relay path's field of the same meaning:
	// true here means the descriptor was never handed over, which on a platform
	// that must exclude the socket is a leak, not a detail.
	SocketOwnedByEngine bool `json:"socket_owned_by_engine"`

	// Lifecycle is the supervised tunnel's recovery state, one of the
	// driver.Lifecycle* values: "connecting", "connected", "recovering",
	// "blocked" or "stopped". LifecycleCause is set only with "blocked" and is
	// one of "never_established", "budget_spent" or "terminal"; the final
	// error's text is carrier_error. While "recovering" no retired round's
	// counters are published and winn3_may_carry is false; the host keeps its
	// capture as it is. "blocked" persists with winn3_runtime_completed true
	// and authorises no fallback to another protocol and no release of
	// capture. A host that does not know a value treats it as "blocked".
	Lifecycle      string `json:"winn3_lifecycle,omitempty"`
	LifecycleCause string `json:"winn3_lifecycle_cause,omitempty"`
}

func (t *winn3Tunnel) statusJSON() string {
	st := winn3Status{
		Contract:            winn3Contract,
		Payload:             winn3Payload,
		Carrier:             winn3Carrier,
		CarrierClass:        t.carrierClass.String(),
		SessionID:           t.sessionID,
		Closed:              t.closed.Load(),
		SocketOwnedByEngine: t.ownSocket,
	}
	// Completion is separate from the owner-close guard and includes normal exit.
	select {
	case <-t.done:
		st.RuntimeCompleted = true
	default:
	}
	// One snapshot for everything below: a round published between reading
	// the round and reading the recovery flag would otherwise publish the
	// retired round's counters as the live round's.
	snap := t.snapshot()
	if winn3TestHookAfterSnapshot != nil {
		winn3TestHookAfterSnapshot()
	}
	loop, dev := snap.loop, snap.dev
	st.Closed = snap.closed
	// While a round is being replaced the dead round's counters proved THAT
	// session and not the next one, so none of them is published.
	recovering := snap.recovering
	// roundRead is whether this document describes the round it read. The
	// snapshot says which round that is; the round can still end between the
	// snapshot and the gate read below, so the gate read decides too.
	roundRead := !recovering
	gateLive := false

	sizing := loop.Sizing()
	st.PlanFloor = sizing.MessageSize
	// `sizing.PathMTU` is the PLAN's own field name and is untouched — only the
	// published key moved past the sampler's denied `path` token.
	st.PlanMTUCeiling = sizing.PathMTU
	st.InnerIPv6 = sizing.InnerIPv6
	for _, c := range sizing.Classes {
		st.PlanClasses = append(st.PlanClasses, c.String())
	}

	if recovering {
		st.GateState = tun.StateClosed.String()
		st.InnerMTU = sizing.InnerMTU
	} else if tn := loop.Tunnel(); tn != nil {
		gate := tn.Gate().State()
		gateLive = gate != tun.StateDown && gate != tun.StateClosed
		st.GateState = gate.String()
		st.MayCarry = gate.MayCarry()
		st.InnerMTU = tn.InnerMTU()
		s := tn.Stats()
		st.RxPackets = s.RxPackets
		st.RxOffered = s.RxOffered
		st.RxBytes = s.RxBytes
		st.TxPackets = s.TxPackets
		st.TxBytes = s.TxBytes
		st.TxDroppedClosed = s.TxDroppedClosed
		st.RxDroppedClosed = s.RxDroppedClosed
		st.RxDroppedInvalid = s.RxDroppedInvalid
		st.TxDroppedInvalid = s.TxDroppedInvalid
	}

	if t.cancel != nil {
		st.Lifecycle, st.LifecycleCause = driver.Lifecycle(driver.LifecycleFacts{
			Stopped:         snap.closed,
			Finished:        snap.finished,
			RunErr:          snap.runErr,
			Recovering:      recovering,
			CurrentProven:   roundRead && st.MayCarry && st.RxPackets > 0,
			RoundProvenLive: roundRead && gateLive && st.RxPackets > 0,
			RoundEnded:      snap.roundEnded,
			EverProven:      snap.everProven || st.RxPackets > 0,
		})
		if st.Lifecycle == driver.LifecycleRecovering && roundRead {
			// The round this document read has proven delivery and is ending
			// (its gate latched down before its end was recorded), or it is a
			// successor that has proven nothing. Either way no round is proven
			// now, and none of its evidence is published as current.
			roundRead = false
			st.GateState, st.MayCarry, st.InnerMTU = tun.StateClosed.String(), false, sizing.InnerMTU
			st.RxPackets, st.RxOffered, st.RxBytes = 0, 0, 0
			st.TxPackets, st.TxBytes = 0, 0
			st.TxDroppedClosed, st.RxDroppedClosed = 0, 0
			st.RxDroppedInvalid, st.TxDroppedInvalid = 0, 0
		}
	}
	if err := t.runErr.Load(); err != nil && *err != nil {
		st.CarrierError = (*err).Error()
	} else if roundRead {
		if err := loop.CarrierErr(); err != nil {
			st.CarrierError = err.Error()
		}
	}

	if roundRead {
		ls := loop.Stats()
		st.MessagesSent = ls.MessagesSent
		st.MessagesReceived = ls.MessagesReceived
		st.Migrations = ls.Migrations

		st.QueueDroppedOutbound = dev.droppedOutbound.Load()
		st.QueueDroppedInbound = dev.droppedInbound.Load()
	}

	encoded, err := json.Marshal(st)
	if err != nil {
		return `{"contract":"` + winn3Contract + `","closed":true,` +
			`"carrier_error":"status could not be encoded"}`
	}
	return string(encoded)
}

func (t *winn3Tunnel) close() error {
	t.mu.Lock()
	claimed := t.closed.CompareAndSwap(false, true)
	t.mu.Unlock()
	if !claimed {
		return nil
	}
	// Order matters and mirrors Loop.Run's own teardown: cancel first so the
	// loop latches the gate down, then close the device so a host blocked in
	// ReadOutbound wakes. The supervisor retires the live round and builds no
	// other.
	loop, dev, _ := t.round()
	t.cancel()
	dev.close()
	err := loop.Close()
	select {
	case <-t.done:
	case <-time.After(2 * winn3CloseGrace):
		// The loop owns one goroutine per tunnel that can outlive Run if the
		// host never closes its device (driver §"Known costs"). It cannot move
		// a byte. Waiting forever here would turn that cost into a hang in the
		// host's stopTunnel, which is worse.
	}
	t.closeSocket()
	if err != nil {
		return err
	}
	if e := t.runErr.Load(); e != nil && *e != nil && !errors.Is(*e, context.Canceled) {
		return *e
	}
	return nil
}

// ---------------------------------------------------------------------------
// the shared entry points, winn3 half
// ---------------------------------------------------------------------------

func winn3WriteInbound(t *winn3Tunnel, buffer *C.char, length C.int) C.int {
	if buffer == nil || length <= 0 {
		return errArgument
	}
	if t.closed.Load() {
		return errClosed
	}
	return t.writeInbound(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(length)))
}

// writeInbound is WinnTunnelWriteInbound's side across rounds.
func (t *winn3Tunnel) writeInbound(packet []byte) C.int {
	_, dev, _ := t.round()
	n, err := dev.offer(packet)
	if err != nil {
		if t.recoveryAbsorbs(dev) {
			// Dropped, counted, and not reported: nothing is queued for a
			// round that does not exist yet, so the window stays bounded.
			t.droppedRecovering.Add(1)
			return C.int(len(packet))
		}
		return errClosed
	}
	return C.int(n)
}

func winn3ReadOutbound(t *winn3Tunnel, buffer *C.char, capacity C.int, timeoutMS C.int) C.int {
	if buffer == nil || capacity <= 0 {
		return errArgument
	}
	packet := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity))
	n, err := t.take(packet, timeoutMS)
	switch {
	case err == nil:
		return C.int(n)
	case errors.Is(err, os.ErrDeadlineExceeded):
		return errTimeout
	case errors.Is(err, errWinn3TooLarge):
		return errTooLarge
	case errors.Is(err, winn3DeviceClosed):
		return errClosed
	default:
		return errCarrier
	}
}

// take is WinnTunnelReadOutbound's side across rounds. A read that meets a
// retired round's closed device during recovery waits for the successor inside
// the same timeout instead of reporting the tunnel closed.
func (t *winn3Tunnel) take(packet []byte, timeoutMS C.int) (int, error) {
	deadline := time.Time{}
	if timeoutMS > 0 {
		deadline = time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	}
	for {
		_, dev, next := t.round()
		timeout := deadlineZero
		if !deadline.IsZero() {
			timeout = time.Until(deadline)
			if timeout <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
		}
		n, err := dev.take(packet, timeout)
		if !errors.Is(err, winn3DeviceClosed) || !t.recoveryAbsorbs(dev) {
			return n, err
		}
		if !awaitRound(next, deadline) {
			return 0, os.ErrDeadlineExceeded
		}
	}
}
