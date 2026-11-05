package datapath

// Carrier transports for the datapath.
//
// Open builds direct-awg: the engine writes each AmneziaWG outer datagram
// straight to the gateway over the caller's UDP socket. OpenWithCarrier builds
// the same engine over an internal/carrier carrier instead, so the same
// datagrams travel inside authenticated Winn envelopes over HTTP/3 CONNECT-UDP
// (MASQUE) or HTTP/2.
//
// The socket rule is identical in both cases and is the whole point: the HOST
// opens the transport socket, the host protects it (VpnService.protect on
// Android), and only then is it handed over. The carrier is constructed around
// that socket and, once given one, refuses to open another — see
// internal/carrier/supplied_socket.go.
//
// This entry point takes a dialer rather than more JSON because a carrier needs
// an authenticated configuration that has no business crossing the C ABI: a URI
// template or absolute HTTPS URL, a public target, a device identity or
// anonymous credential source, a TLS suite and a response verifier. So the
// PLAIN C entry point, WinnTunnelCreate, still builds direct-awg only; a host
// that wants a carrier does not get one by adding fields to that JSON. It
// either constructs the dialer itself and calls this, or — on Apple, which has
// no subprocess — hands cdatapath a whole profile document through the separate
// WinnTunnelCreateWithCarrier entry point, which builds the dialer via
// ./carrierhost and then calls this.
//
// ./carrierhost is that Go host for the platforms that reach this module as a
// SUBPROCESS rather than through the C ABI — Android, Linux and Windows, which
// speak the framed protocol in ./duplex. It reads the authenticated
// configuration from a file named on argv and builds the dialer, so the frame
// channel still carries nothing but Config and the plain C entry point is
// unaffected.
//
// Apple reaches carrierhost too, and this comment used to say it did not. The
// claim that "Apple keeps using the C archive and keeps getting direct-awg
// only" was true when the C surface had a single entry point; it stopped being
// true when ../cdatapath/winn_datapath_carrier.go added
// WinnTunnelCreateWithCarrier (declared at apple/EngineWrappers/WinnTunnel.h),
// which takes the profile document as a SECOND C STRING and calls
// OpenWithCarrier. Apple has no child process to hand a path to, so the
// document travels in memory instead of by path — a different delivery
// mechanism for the same authenticated configuration, not a different
// capability.

import (
	"context"
	"errors"
	"fmt"
	"net"

	"winsvpn.local/winnprotocol/internal/carrier"
)

var (
	// ErrCarrierDialerRequired is returned when OpenWithCarrier is called with
	// no dialer.
	ErrCarrierDialerRequired = errors.New(
		"winn datapath carrier dialer is required",
	)

	// ErrCarrierDialerMismatch is returned when the dialer does not match the
	// carrier the configuration names, or needs a different kind of socket than
	// the configuration's carrier does. Building an HTTP/2 carrier for a
	// configuration that says http3-connect-udp would put the tunnel on a
	// transport nobody chose.
	ErrCarrierDialerMismatch = errors.New(
		"winn datapath carrier dialer does not match the configured carrier",
	)

	// ErrCarrierSocketReused is returned when the dialer already holds a
	// supplied socket. OpenWithCarrier installs the descriptor it adopted and
	// must be able to prove that is the socket the carrier used; a dialer that
	// arrived pre-loaded makes that unprovable.
	ErrCarrierSocketReused = errors.New(
		"winn datapath carrier dialer already holds a supplied socket",
	)
)

// OpenWithCarrier creates an engine whose transport is a carrier built around
// the caller-supplied descriptor.
//
// transportFD >= 0 adopts the caller's socket and installs it in the dialer.
// The engine and then the carrier take ownership: Close closes the carrier,
// which closes the socket. The host must not close it again.
//
// The descriptor must match what the carrier needs, which the caller can read
// from dialer.SuppliedSocketKind() before it opens anything:
//
//	SocketKindPacket -> an UNCONNECTED UDP socket   (http3-connect-udp, MASQUE)
//	SocketKindStream -> a CONNECTED, plaintext TCP socket (http2-stream)
//
// transportFD < 0 is the desktop and Linux path, where the outer traffic is
// excluded by route rather than by a protected descriptor. It is permitted only
// when the configuration sets allow_own_socket, exactly as Open requires;
// otherwise it returns ErrOwnSocketRefused rather than letting a carrier open
// an unprotected socket on a platform that needed a protected one.
func OpenWithCarrier(
	ctx context.Context,
	configJSON []byte,
	transportFD int,
	dialer carrier.SuppliedSocketDialer,
) (*Engine, error) {
	if ctx == nil {
		return nil, errors.New("winn datapath carrier dial context is required")
	}
	config, err := ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	return openWithCarrier(ctx, config, transportFD, dialer)
}

// OpenConfigWithCarrier is OpenWithCarrier for a Config a caller already holds.
func OpenConfigWithCarrier(
	ctx context.Context,
	config Config,
	transportFD int,
	dialer carrier.SuppliedSocketDialer,
) (*Engine, error) {
	if ctx == nil {
		return nil, errors.New("winn datapath carrier dial context is required")
	}
	normalized, err := config.normalize()
	if err != nil {
		return nil, err
	}
	return openWithCarrier(ctx, normalized, transportFD, dialer)
}

func openWithCarrier(
	ctx context.Context,
	config Config,
	transportFD int,
	dialer carrier.SuppliedSocketDialer,
) (*Engine, error) {
	if dialer == nil {
		return nil, ErrCarrierDialerRequired
	}
	required, converted := suppliedSocketCarriers[config.Carrier]
	if !converted {
		// direct-awg has no dialer, and the four unimplemented carriers were
		// already refused by normalize. Either way this is not a carrier
		// OpenWithCarrier can build.
		return nil, fmt.Errorf(
			"%w: carrier %q is not one of the caller-supplied-socket carriers",
			ErrCarrierDialerMismatch, config.Carrier,
		)
	}
	if kind := dialer.SuppliedSocketKind(); kind != required {
		return nil, fmt.Errorf(
			"%w: carrier %q needs a %q socket, the dialer takes %q",
			ErrCarrierDialerMismatch, config.Carrier, required, kind,
		)
	}
	if dialer.HasSuppliedSocket() {
		return nil, ErrCarrierSocketReused
	}

	adopted, err := installCarrierSocket(dialer, required, transportFD, config)
	if err != nil {
		return nil, err
	}

	transport, err := dialer.Dial(ctx)
	if err != nil {
		// The dialer's own failure paths close the socket they were given, but
		// they are not this package's code and the descriptor came from the
		// host. Close it here too rather than risk leaking a descriptor the
		// host has already let go of; a second close on a closed socket is a
		// no-op we deliberately ignore.
		closeAdoptedSocket(adopted)
		return nil, fmt.Errorf("winn datapath dial %s carrier: %w",
			config.Carrier, err)
	}
	if transport == nil {
		closeAdoptedSocket(adopted)
		return nil, fmt.Errorf(
			"winn datapath %s carrier returned no connection", config.Carrier,
		)
	}

	gateway, err := net.ResolveUDPAddr("udp", config.GatewayEndpoint)
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("winn datapath gateway endpoint: %w", err)
	}

	engine := newEngine(config, gateway, transport, transportFD < 0)
	// A carrier PacketConn reports a synthetic peer, so the gateway sender
	// filter would drop every datagram. The carrier's own authenticated
	// envelope is the stronger check that replaces it. See Engine.
	engine.filterGatewaySender = false
	// Cover traffic: breaks the 25s PersistentKeepalive heartbeat that
	// length padding alone leaves visible. The envelope already defines
	// envelopeCover and bucketed padding; this is the schedule that puts it
	// on the wire via the carrierhost route (BuildDialer -> OpenWithCarrier).
	// It is device-local (see engine.go cover constants for rationale) and
	// only emits when padding is on (high-risk); standard privacy's
	// DisableLengthPadding causes SendCover to refuse and the loop exits.
	engine.enableCover()
	go engine.pump()
	return engine, nil
}

// installCarrierSocket adopts the caller's descriptor and hands it to the
// dialer. It returns the adopted socket so a later failure can release it.
func installCarrierSocket(
	dialer carrier.SuppliedSocketDialer,
	required carrier.SocketKind,
	transportFD int,
	config Config,
) (any, error) {
	if transportFD < 0 {
		if !config.AllowOwnSocket {
			return nil, ErrOwnSocketRefused
		}
		// Deliberately nothing installed: the dialer opens its own socket, the
		// path that is correct on desktop and Linux.
		return nil, nil
	}
	switch required {
	case carrier.SocketKindPacket:
		packetDialer, ok := dialer.(carrier.PacketSocketDialer)
		if !ok {
			return nil, fmt.Errorf(
				"%w: dialer reports %q but does not accept a packet socket",
				ErrCarrierDialerMismatch, required,
			)
		}
		conn, err := adoptUDPDescriptor(transportFD)
		if err != nil {
			return nil, err
		}
		if err := packetDialer.UseSuppliedSocket(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	case carrier.SocketKindStream:
		streamDialer, ok := dialer.(carrier.StreamSocketDialer)
		if !ok {
			return nil, fmt.Errorf(
				"%w: dialer reports %q but does not accept a stream socket",
				ErrCarrierDialerMismatch, required,
			)
		}
		conn, err := adoptStreamDescriptor(transportFD)
		if err != nil {
			return nil, err
		}
		if err := streamDialer.UseSuppliedSocket(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf(
			"%w: unknown socket kind %q", ErrCarrierDialerMismatch, required,
		)
	}
}

func closeAdoptedSocket(adopted any) {
	switch socket := adopted.(type) {
	case net.PacketConn:
		_ = socket.Close()
	case net.Conn:
		_ = socket.Close()
	}
}
