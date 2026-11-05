// Package datapath is the portable, in-process Winn Protocol v3 datapath.
//
// It exists so a host application that already owns a tunnel device — an
// Android VpnService, an Apple NEPacketTunnelProvider, a Windows WinTun
// adapter — can drive Winn without this module creating an OS network
// interface, editing a route, or executing nft/ip/awg. Nothing in this package
// or its transitive imports uses os/exec, and a test enforces that
// (TestEngineImportsNoSubprocessPackage).
//
// # What layer this actually is, stated before the API
//
// The Linux carrier assemblies in this module (internal/directawg,
// internal/h3candidate, wired by internal/linuxauto) do NOT hand Go raw IP
// packets. Read internal/directawg/linux_controller_common.go: the controller
// starts amneziawg-go as a subprocess, points its peer endpoint at a loopback
// UDP address with "awg set <if> peer <key> endpoint 127.0.0.1:<port>", and
// then internal/carrier.RelayLocalUDP moves AmneziaWG OUTER DATAGRAMS between
// that loopback socket and the outer carrier. The Noise_IKpsk2 handshake, the
// transport-data encryption and the AmneziaWG obfuscation (jc/jmin/jmax,
// s1..s4, h1..h4) all happen inside the external amneziawg-go binary.
//
// So the layer Winn owns in Go — and the only one it can own without importing
// a WireGuard implementation, which this module does not have in go.mod, in
// go.sum, or in the local module cache — is:
//
//	AmneziaWG outer datagram  <->  Winn carrier  <->  network
//
// This package implements exactly that layer, in process, with no subprocess
// and no socket of its own when the host supplies one. It does NOT implement
// AmneziaWG. A caller that hands it a raw IPv4 or IPv6 packet from a tun device
// would be handing an unencrypted packet to the gateway, so Open REFUSES the
// "ip-packet" payload mode rather than silently forwarding cleartext. See
// ErrPayloadUnimplemented for the precise list of what an "ip-packet" mode
// would require.
//
// # Placement in the host
//
//	host tun device            (host owns it: VpnService / NEPacketTunnel / WinTun)
//	  |
//	host's existing AWG engine (libwg-go.a on Apple, AmneziaWG GoBackend on
//	  |                         Android, winsvpn_awg_engine.exe on Windows)
//	  |  outer AWG datagrams
//	  v
//	datapath.Engine            <- this package
//	  |  Winn carrier
//	  v
//	caller-supplied UDP socket (Android: VpnService.protect(fd) FIRST)
//
// # The socket rule
//
// Open takes a file descriptor. When it is >= 0 the engine adopts it and never
// opens a socket; that is the only correct behaviour on Android, where an
// unprotected socket routes back into the tunnel and loops forever. The engine
// takes OWNERSHIP of the descriptor and closes it in Close, matching how the
// AmneziaWG Android bridge consumes a detached descriptor. When the descriptor
// is < 0 the engine opens its own socket, and only if the configuration says
// allow_own_socket:true, so that omitting a protected descriptor on Android
// fails loudly instead of looping.
//
// # Carriers
//
// Open builds one carrier: direct-awg, which writes each datagram to the
// gateway endpoint over the supplied UDP socket unchanged.
//
// OpenWithCarrier builds the same engine over an internal/carrier carrier —
// "http3-connect-udp" (which is the MASQUE carrier; internal/carrier.H3Dialer
// performs RFC 9298 CONNECT-UDP through internal/masque, and there is no
// separate MASQUE dialer in this module) or "http2-stream". Both of those
// dialers accept a caller-supplied, already-protected socket and refuse to open
// one of their own once given it, so the socket rule above holds unchanged: the
// host opens, the host protects, the host hands over. HTTP/3 and MASQUE take a
// UDP descriptor; HTTP/2 takes a CONNECTED TCP descriptor. Read
// Dialer.SuppliedSocketKind() before opening anything.
//
// A carrier needs an authenticated configuration — URI template or HTTPS URL,
// public target, device identity or anonymous credential source, TLS suite,
// response verifier — that does not belong in the JSON blob crossing the C ABI,
// which is why the dialer is passed as a value and why cdatapath still builds
// direct-awg only. reality-xhttp, websocket-tls, native-two-hop and
// privacy-two-hop have no dialer in internal/carrier at all and stay refused.
//
// # Concurrency and lifetime
//
// WriteInbound and ReadOutbound may be called concurrently, from different
// threads, and each is safe against a concurrent Close. Close is idempotent and
// synchronous: when it returns, the socket is closed, the pump goroutine has
// exited, and every queued datagram has been zeroed. After Close, WriteInbound
// and ReadOutbound return ErrClosed.
package datapath
