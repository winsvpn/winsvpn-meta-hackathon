// Command winn3-gateway is a reachable, multi-session Winn Protocol v3
// responder: a process that binds a real datagram socket and serves clients.
//
// # Why this exists
//
// Five platform lanes have built v3 client code and none of them had anything
// to connect to. cmd/winn3-labrig is a Linux-only ONE-session rig that needs a
// kernel tun device; winn3/gateway is a dispatch library that "holds no socket
// and no timer" and is wired into no datapath at all. Between the two there was
// no process a client could reach, on any platform, so no handshake had ever
// completed over a network and every host capability was honestly .absent.
//
// This binary closes exactly that gap and nothing wider.
//
// # What it is, precisely
//
// One unconnected UDP socket, a demultiplexer, and one winn3/driver responder
// loop per peer, joined by carrier.Pipe — which is the seam carrier/pipe.go was
// written for and says so in its doc comment:
//
//	"A gateway serves many sessions over one datagram socket, so the socket
//	 cannot belong to a session's carrier. The gateway's demultiplexer reads
//	 the socket, decides which session a message belongs to, and calls Deliver
//	 on that session's Pipe."
//
// # What it is NOT, and this matters
//
// It demultiplexes on the PEER ADDRESS, not on the demux token. That is the
// honest limitation of this binary and the reason it is not yet the shipping
// gateway:
//
//   - winn3/gateway's Table is the address-independent index the protocol
//     actually calls for, and it is NOT used here. A session here does not
//     survive a peer rebinding to a new source port, which §5.4 migration
//     requires and which the token index is what delivers.
//   - The reason it is not used is a real missing seam, not an oversight:
//     gateway.Gateway.Handle owns the handshake itself (core.Responder ->
//     WriteResponse -> *core.Session), while session.NewGateway builds its own
//     responder and reads the initiation off its carrier. There is no
//     constructor anywhere in winn3/session that adopts an already-established
//     *core.Session, so the two halves cannot currently be composed. Closing
//     that seam is the next piece of work and it belongs to whoever owns
//     winn3/session.
//
// Address demultiplexing is strictly weaker and strictly honest. It is enough
// to make a handshake complete, a packet round-trip and a promotion predicate
// fire over a real network, which is what nothing could do before.
//
// # The inner side
//
// Each session terminates against an in-process reflector (see reflect.go)
// rather than a kernel interface, so this runs unprivileged on macOS and Linux
// alike. It is a REFLECTOR and not a router: it forwards nothing to the
// internet, it swaps the addresses of what it is given and hands it back. That
// makes "a packet round-tripped" a statement about the whole chain — socket,
// handshake, session, frames, tun layer, and back — and it makes no statement
// whatever about forwarding, NAT or egress, which this binary does not do.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/dualsign"

	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// statusInterval matches cmd/winn-datapath and cmd/winn3-labrig so that the two
// ends of a session produce comparable timelines.
const statusInterval = time.Second

// readinessProbeTimeout makes readiness depend on one real socket read. A
// deadline result proves the read path is live without requiring a client
// packet, while any immediate non-timeout failure prevents publication.
const readinessProbeTimeout = 25 * time.Millisecond

const proofStatusPath = "/run/winn3-gateway/status.json"

// readBuffer bounds one datagram read. It is above any v3 message size at any
// path MTU; an oversize datagram is not a v3 message and the carrier's own
// ceiling is what rejects it.
const readBuffer = 65535

// gatewaySendQueue bounds how many inner packets one session may hold for the
// wire. The queue allocates lazily, one pooled 2 KiB slab per queued packet
// (session.DataBufferSlabBytes), so the bound is also the session's
// worst-case send memory: gatewaySendQueue * 2 KiB.
//
// It was 65536, which is 128 MiB per session, 8 GiB at the default 64
// sessions, and about 720 ms of standing queue at 1 Gbit/s. Measured on the
// L12 v2 rig (2026-09-23), one starved session under downlink overload filled
// all 65536 slots and held 260 MiB of heap; four filled sessions held 1 GiB.
// 8192 is 1.38 bandwidth-delay products at 1 Gbit/s and 65 ms (5,917 packets
// of 1373 B), the same depth Round 44 chose for the client's to-engine ring,
// and 16 MiB per session. cgroup_memory_budget_test.go bills this constant
// and measures that the queue allocates as billed.
const gatewaySendQueue = 8192

// inboxDepth is the per-session receive inbox between readLoop and the
// session. It is a QUEUE budget: how long a stall of the session goroutine is
// absorbed before readLoop starts dropping, at 16 MiB of pooled slabs per
// session at this depth.
//
// Ruling D23 derived the inbox from the token window the session receives at,
// so the inbox tracks the window's reorder tolerance. It was pinned at
// core.DefaultTokenWindow/2 = 512 from 2026-09-20, which Canada falsified on
// 2026-10-09: every upload run overflowed it (5,884 to 27,237 drops, 67 to
// 86% of them inside the first two seconds), because a 32-stream TCP ramp
// offers 38 to 40k datagrams/s against a serialized consumer near 30k/s, and
// 512 slots absorb only 13 to 17 ms of that deficit. The derivation now
// follows the window this binary actually configures,
// gatewayTokenWindow/4 = 8192:
//
//   - 8192 / 160,525 msg/s (1.8 Gbit/s at the 1402-byte message size) is
//     51 ms of full-rate absorption, and 836 ms at the measured 9.8k/s
//     ramp deficit, which covers every measured burst except the worst
//     two-second U3 arm, which the consumer-rate fixes (async TUN writes,
//     RPS) remove.
//   - 16 MiB of slabs per session, the same worst-case billing the send
//     queue already carries (gatewaySendQueue), so installerSessionKiB
//     moves once for both.
//   - D23's loss bound stays safe: the contiguous drop run at a full inbox
//     averages (A-S)/S messages, because every drained slot is refilled at
//     once while A>S (3.1 at the measured A=38.8k, S=29k), far under the
//     recent-loss cliff gatewayTokenWindow/2-1 = 16,383. A deeper inbox
//     only delays the onset of drops; it cannot lengthen a run.
//
// It stays a derivation from the window, never a bare literal, which is what
// pipe_window_test.go pins.
//
// Since the owner ruling of 2026-10-10 (TUNNEL-SPEED-2, inbox depth between
// 1,536 and 8,192 for the fastest speed at lower RAM) this constant is the
// D23 ceiling and the default of -uplink-inbox-depth, not the only depth: see
// uplinkInboxDepths.
const inboxDepth = gatewayTokenWindow / 4

// uplinkInboxDepths are the values -uplink-inbox-depth accepts: one quarter,
// one half and all of inboxDepth (2048, 4096 and 8192 at gatewayTokenWindow
// 32768), each still derived from the token window, never a literal. The owner
// ruling of 2026-10-10 picks the smallest depth whose measured speed stays
// within the agreed tolerance of 8192, so arms compare these three on one
// build. Every value keeps D23's two bounds, which
// TestEveryUplinkInboxDepthKeepsTheD23Bounds pins: at least twice the old
// 511-message reorder tolerance, and under the recent-loss cliff
// gatewayTokenWindow/2-1 = 16,383 (a full inbox drops short runs averaging
// (A-S)/S messages; a shallower inbox starts dropping sooner but cannot
// lengthen a run). The per-session memory bill follows the configured depth:
// 2 KiB of pooled slab per slot (cgroup_memory_budget_test.go).
var uplinkInboxDepths = [...]int{inboxDepth / 4, inboxDepth / 2, inboxDepth}

// defaultUplinkInboxDepth is the -uplink-inbox-depth default (inboxDepth, 8192
// for now) and what a server built without the flag (a zero inboxDepth field)
// uses. Production never assigns it; the only writer is the test-only init in
// uplink_inbox_depth_env_test.go, which runs this package's existing tests at
// each allowed depth from WINN3_TEST_UPLINK_INBOX_DEPTH.
var defaultUplinkInboxDepth = inboxDepth

// resolveUplinkInboxDepth validates -uplink-inbox-depth. Zero means the default;
// any value outside uplinkInboxDepths is refused before the socket exists,
// because an inbox depth nobody measured is not a posture.
func resolveUplinkInboxDepth(depth int) (int, error) {
	if depth == 0 {
		return defaultUplinkInboxDepth, nil
	}
	for _, allowed := range uplinkInboxDepths {
		if depth == allowed {
			return depth, nil
		}
	}
	return 0, fmt.Errorf("-uplink-inbox-depth is %d; it must be one of %d, %d or %d "+
		"(gatewayTokenWindow/16, /8 or /4)", depth,
		uplinkInboxDepths[0], uplinkInboxDepths[1], uplinkInboxDepths[2])
}

// gatewayTokenWindow is each session's client-to-gateway receive token window
// W, the uplink counterpart of cmd/winn-datapath's winn3ClientTokenWindow.
//
// It bounds the run of consecutive lost client messages a session survives: at
// most W-1 on a clean stream, but only W/2-1 when an earlier message was lost
// recently. Past that run the direction is stranded for good: every later
// client message, a REKEY_INIT included, is unopenable, and the session dies
// on the stall probe or on the 15 s rekey timeout. At core.DefaultTokenWindow
// that is 1023 or 511 messages, about 8 to 16 ms at 700 Mbit/s.
//
// The run is produced by readLoop dropping at a full inbox while the session
// goroutine is not scheduled, and by loss before the socket read. Measured on
// the L12 rig (2026-09-23, gateway held to 40% of one core): runs of 804 to
// 1720 messages killed default-window sessions at 700 Mbit/s uplink; runs
// reached 5729 under 1500 Mbit/s uplink and 13,858 under 1500 Mbit/s each way,
// which killed both such sessions at W=16384 (recent-loss cliff 8191) and
// none at 32768 or 65536. The UK gateway lost about 1,260 in one upload burst
// on the same day (lane L14).
//
// W is not free, and that is why it is not core.MaxTokenWindow. Every epoch
// install precomputes W demux tokens (one HMAC-SHA256 each) and holds them in
// a map: every handshake pays it twice (epoch 0, then the PQ ratchet) and
// every rekey once. Per epoch on the Linux arm64 test VM: 1.8 ms at 16384,
// 3.5 ms at 32768 and 7.2 ms at 65536 (9.8 and 23.0 ms for the last two at
// 40% of a vCPU), allocating 0.6, 1.2 and 2.4 MiB. A 64-client reconnect
// storm on the same starved gateway lost sessions to PQ-ratchet timeouts in
// proportion: none of 640 at 16384, 4 of 640 at 32768, 32 of 448 at 65536.
// 32768 is the smallest value that survived every sustained-overload run
// measured (recent-loss cliff 16383 against a longest run of 13,858). It
// still loses storm sessions, at about a tenth of the rate of 65536
// (0.6% against 7.1%). It is a finite
// tolerance, not protection against arbitrarily long starvation. inboxDepth
// is deliberately NOT derived from this value: the inbox bounds how long a
// stall is absorbed without loss, the window bounds how long a loss is
// survived, and they are separate budgets.
//
// It is receiver-local; nothing on the wire changes.
const gatewayTokenWindow = 32768

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "winn3-gateway: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("winn3-gateway", flag.ContinueOnError)
	mode := flags.String("mode", "serve", "keygen, derive-public, serve, resources or features")
	outDir := flags.String("out", "", "keygen, derive-public: directory to write key files into")

	listen := flags.String("listen", "", "serve: UDP address to bind, e.g. 127.0.0.1:51833")
	staticPath := flags.String("static", "", "serve, derive-public: path to this end's 32-byte X25519 private key")
	admission := flags.String("admission", "", "serve: path to the admission secret")
	dualEDKey := flags.String("dual-auth-ed-key", "",
		"serve, derive-public: 64-byte ed25519 private key (hex) for the dual-signature attestation; pairs with -dual-auth-ml-seed")
	dualMLSeed := flags.String("dual-auth-ml-seed", "",
		"serve, derive-public: 32-byte ML-DSA-65 seed (hex) for the dual-signature attestation; pairs with -dual-auth-ed-key")
	gatewayID := flags.String("gateway-id", "", "serve: the authenticated gateway identifier")
	innerV4 := flags.String("inner-v4", "10.64.0.1", "serve: this end's inner IPv4 address")
	routerV4 := flags.String("router-v4", "", "serve: the inner next hop, for PMTU signals only")
	innerV6 := flags.String("inner-v6", "", "serve: this end's inner IPv6 address (optional; required before inner IPv6 is carried)")
	routerV6 := flags.String("router-v6", "", "serve: the IPv6 inner next hop, for PMTU signals only")
	plan := flags.String("plan", "udp", "serve: comma-separated migration plan, e.g. udp,tcp,tls")
	pathMTU := flags.Int("path-mtu", carrier.DefaultPathMTU, "serve: the planning path MTU")
	listenerDF := flags.Bool("listener-df", false,
		"serve: set DF (IP_PMTUDISC_DO) on the shared UDP listener, so a datagram wider than the\n"+
			"    \troute fails its send with EMSGSIZE instead of leaving as fragments. Default off: the\n"+
			"    \tlistener keeps the kernel's default and fragmentation stays allowed, because clients\n"+
			"    \twhose own carrier sets no DF (iOS, macOS, Windows) can depend on fragments on a path\n"+
			"    \tnarrower than this node's NIC (Round CM2, OI-CM2-1a). WINN3_GATEWAY_LISTENER_DF=1\n"+
			"    \talso turns it on when this flag is not set; 0 or unset leaves it off; any other\n"+
			"    \tvalue is refused. The startup egress MTU check runs either way.")
	tcpIngressFlag := flags.Bool("tcp-ingress", false,
		"serve: classify TCP connections on the listen port as v3 streams (Round W, v3 over TCP)\n"+
			"    \tbefore they reach the cover HTTPS listener. Default off: every TCP connection goes\n"+
			"    \tstraight to the cover HTTPS/ECH listener, exactly as before Round W, and no v3\n"+
			"    \tsession is built over TCP whatever -plan says. Round W ships in its own rollout,\n"+
			"    \tafter the hub serves a tcp plan and a device canary (owner ruling 2026-09-24).\n"+
			"    \tWINN3_GATEWAY_TCP_INGRESS=1 also turns it on when this flag is not set; 0 or unset\n"+
			"    \tleaves it off; any other value is refused.")
	acceptTransit := flags.Bool("accept-transit", false,
		"serve: accept inner packets addressed to ANY destination, not only this end's inner address.\n"+
			"    \tA client with AllowedIPs 0.0.0.0/0 addresses every packet to the internet, never to\n"+
			"    \tthis responder, so without this every inner packet is refused as ErrNotForUs and\n"+
			"    \tRxPackets can never leave 0 — which is exactly what blocked promotion on the first\n"+
			"    \tstandalone iOS carriage (rx_offered 50 / rx_packets 0 / rx_dropped_invalid 50).\n"+
			"    \tRequired by -forward, and still martian/family/reflection-checked either way; without\n"+
			"    \t-forward this remains what it always was, a LAB RESPONDER ONLY setting.")
	maxSessions := flags.Int("max-sessions", 64, "serve: the session ceiling")
	demux := flags.String("demux", "address", "serve: session demultiplexing strategy: address (strict 5-tuple) or token (authenticated token indexing with dynamic re-anchoring)")
	runFor := flags.Duration("for", 0, "serve: exit after this long; zero runs until signalled")
	forward := flags.Bool("forward", false,
		"serve: carry real internet traffic instead of reflecting it. Creates a Linux TUN interface\n"+
			"    \t(-forward-if) addressed inside -forward-cidr and writes validated client packets to it;\n"+
			"    \tthe kernel's own IP forwarding and NAT — configured by the install script, never by\n"+
			"    \tthis process — carry them to the internet and back. Requires -accept-transit=true and\n"+
			"    \t-forward-cidr, refuses -inner-v6/-router-v6, and refuses outright on any OS but Linux.\n"+
			"    \tSee cmd/winn3-gateway's package doc and forward.go.")
	forwardIf := flags.String("forward-if", "winn3gw0",
		"serve: the TUN interface name -forward creates. Must not collide with awg0, amn0 or any\n"+
			"    \tother interface already on the host — this process refuses to adopt one that already\n"+
			"    \texists rather than silently reusing its state (see forward_linux.go, IFF_TUN_EXCL).")
	sendQueueFQ := flags.Bool("send-queue-fq", true,
		"serve: replace each session's single send FIFO with per-host-pair fair queueing and\n"+
			"    \tper-bucket CoDel (session.Driver.SetSendQueueFQ), so a sparse flow such as a probe is\n"+
			"    \tnot queued behind bulk downloads. Capacity unchanged. On by default since 2026-10-11\n"+
			"    \t(tunnel-speed round 2, Turn 14): on Canada it halved the loaded download p95 against\n"+
			"    \tthe single FIFO (123 to 132 ms against 212 to 313) at no throughput cost (Turn 7, F1).\n"+
			"    \tAn explicitly passed flag (either value) wins; WINN3_GATEWAY_SEND_QUEUE_FQ=0 restores\n"+
			"    \tthe single FIFO without touching the unit file. See sendfq_default.go.")
	tunGSO := flags.Bool("tun-gso", false,
		"serve: with -forward, open the TUN queues with IFF_VNET_HDR and let each async writer\n"+
			"    \tmerge a queued run of one TCP flow's segments into one GSO super packet (tun_gso.go),\n"+
			"    \tso the kernel forward path runs once per run instead of once per segment. The kernel\n"+
			"    \tsegments it back byte for byte. Coalesces only where -forward-async-write is in effect;\n"+
			"    \totherwise every packet is written alone behind a zero header. Off by default; an A/B arm.")
	forwardAsyncWrite := flags.Bool("forward-async-write", false,
		"serve: with -forward, hand each validated client packet to one writer goroutine per TUN\n"+
			"    \tqueue instead of writing it on the session's own goroutine, so one session's uplink can\n"+
			"    \tuse more than one core. Packets of one flow keep their order (same queue, one FIFO\n"+
			"    \twriter); a full queue blocks the session rather than dropping. On by default since\n"+
			"    \t2026-10-10 (tunnel-speed round 2, item 7): the serialized write capped a session\n"+
			"    \tnear 30k msg/s while the busiest thread sat under a third of a core; the measured\n"+
			"    \tintake gain is +19.9% alone, +46% with RPS. An explicitly passed flag (either value)\n"+
			"    \twins; WINN3_GATEWAY_ASYNC_WRITE=0 restores the synchronous write without touching\n"+
			"    \tthe unit file. Useful only with two or more CPUs: with fewer than two usable CPUs\n"+
			"    \t(affinity and cgroup cpu.max) it is ignored and logged at startup. See\n"+
			"    \tforward_async.go and forward_cpugate.go.")
	uplinkResequence := flags.Bool("uplink-resequence", false,
		"serve: enable the bounded receive resequencer (winn3/driver/reseq.go) on UDP peer\n"+
			"    \tsessions: hold an out-of-order authenticated message at most 3 ms, and at most 128\n"+
			"    \tmessages, 256 KiB and 192 inner packets, each bound enforced on its own; late\n"+
			"    \tauthenticated messages are delivered, never dropped; no copy, allocation or added\n"+
			"    \tdelay on the in-order path. Default off (tunnel-speed round 2): Canada measured\n"+
			"    \tthe uplink arrival-order inversion rate at 6.9 to 16.4%, which triggers item 5,\n"+
			"    \tand arm R1 runs this flag as an A/B before any default changes; while it is off\n"+
			"    \touter_reordered keeps counting pure arrival order at the socket.")
	uplinkInboxDepth := flags.Int("uplink-inbox-depth", defaultUplinkInboxDepth,
		"serve, resources: the per-session uplink receive inbox between readLoop and the session,\n"+
			"    \tin messages: 2048, 4096 or 8192 (gatewayTokenWindow/16, /8 or /4); any other value is\n"+
			"    \trefused. Each slot holds a 2 KiB pooled slab when full, so the depth is the inbox's\n"+
			"    \tworst-case memory per session (16 MiB at 8192, 4 MiB at 2048). Default 8192 until the\n"+
			"    \towner-ruled arms (2026-10-10) pick the smallest depth within tolerance of 8192.")
	speedtestIngestPort := flags.Int("speedtest-ingest-port", 0,
		"serve: port for the speedtest ingest HTTP listener bound to -inner-v4 on the TUN\n"+
			"    \tinterface (RV-B, Round 38 treaty). 0 disables it: the default keeps the process\n"+
			"    \tbyte-for-byte compatible with deploys that have not ratified the speedtest change.")
	forwardCIDR := flags.String("forward-cidr", "",
		"serve: the inner IPv4 subnet -forward routes for, e.g. 10.64.0.0/24. -inner-v4 must be a\n"+
			"    \thost address inside it, not the network or broadcast address. It must be the SAME\n"+
			"    \tsubnet the control plane assigns client inner_v4 addresses from, or a real client's\n"+
			"    \treturn traffic has no route back to this interface, and it must be DISJOINT from\n"+
			"    \tawg0's VPN_CIDR (10.8.0.0/16 by default) — this binary cannot see that installer's\n"+
			"    \tconfiguration to check the second half for you. No default: -forward refuses without it.")
	peerRegistry := flags.String("peer-registry", "",
		"serve: -forward authorization registry. JSON v1 maps each authenticated client X25519 static\n"+
			"    \tpublic key to its hub-issued inner IPv4 address. Required by -forward; reloaded on every\n"+
			"    \thandshake so an atomic hub update needs no gateway restart. An entry may also carry\n"+
			"    \t\"tier\":\"free\" or \"premium\" (see -free-mbps); absent means premium.")
	freeMbps := flags.Int("free-mbps", 100, "serve: free-tier inner Mbit/s of tunnel goodput, per direction and per free device on this\n"+
		"    \tgateway (the budget belongs to the authenticated key the hub's registry marks\n"+
		"    \t\"tier\":\"free\", so a reconnect continues it). 0 disables the cap entirely, and paying\n"+
		"    \tsessions are never limited. The burst is always 100 ms of the rate (no knob).\n"+
		"    \tWINN3_GATEWAY_FREE_MBIT is applied when this flag holds its default, so the shipped unit\n"+
		"    \tbakes no flag and an env edit plus a restart is the whole change; anything the env carries\n"+
		"    \tthat is not a decimal integer in 0..100000 is refused before the socket exists.")
	resolver := flags.Bool("resolver", false,
		"serve: answer DNS at THIS END'S -inner-v4, forwarding to -resolver-upstream. UDP needs no\n"+
			"    \tcapability, no /dev/net/tun and no -accept-transit: a query addressed to -inner-v4\n"+
			"    \tsatisfies winn3/tun's inbound rule as it stands, and a reply sourced FROM -inner-v4\n"+
			"    \tis the only inner source its outbound rule will carry. TCP/53 (the TC=1 retry path)\n"+
			"    \tis a kernel listener on -inner-v4:53, started only when -forward is also on, and that\n"+
			"    \tbind needs CAP_NET_BIND_SERVICE (write_unit grants it only in that branch; resolver\n"+
			"    \twithout forward must not gain it). SETTING THIS ADVERTISES NOTHING: every client\n"+
			"    \tplatform still refuses to start a standalone session for want of a resolver it can\n"+
			"    \tderive, and closing that gap is a signed-descriptor change that is deliberately not\n"+
			"    \tin this binary. See resolve.go and resolve_tcp.go.")
	resolverUpstream := flags.String("resolver-upstream", "",
		"serve: where -resolver forwards queries, as a literal address:port such as 10.8.1.1:53.\n"+
			"    \tNo default, on purpose: this host sees every name every session looks up, so it is\n"+
			"    \tan operator's stated decision and never a built-in. A hostname is refused — it\n"+
			"    \twould have to be resolved before this resolver could resolve. Reached from the\n"+
			"    \tHOST's own network, off-tunnel; it must NOT be inside -forward-cidr.")
	resolverTimeout := flags.Duration("resolver-timeout", dnsDefaultTimeout,
		"serve: how long one upstream DNS exchange may take before it is counted failed.")

	certPath := flags.String("cert", "",
		"serve: Winn leaf certificate PEM for the strict TLS profile the cover listener selects for an ECH-inner client")
	keyPath := flags.String("key", "",
		"serve: private key PEM for -cert")
	echKeysPath := flags.String("ech-keys", "",
		"serve: RFC 9849 ECH server key set; required so the cover origin can be a real ECH deployment")
	coverCertPath := flags.String("cover-cert", "",
		"serve: certificate PEM presented to unauthenticated TLS/QUIC peers; required unless -insecure-cover-reuses-winn-leaf")
	coverKeyPath := flags.String("cover-key", "",
		"serve: private key PEM for -cover-cert")
	coverServerName := flags.String("cover-server-name", "",
		"serve: private ECH-inner SNI that selects the Winn TLS profile; empty derives it from -cert")
	decoyOrigin := flags.String("decoy-origin", "",
		"serve: absolute http(s) URL reverse-proxied to unauthenticated peers; empty serves a per-deployment generated placeholder site")
	suiteName := flags.String("suite", protocol.DefaultSuite,
		"serve: strict hybrid suite for the cover listener's Winn TLS profile")
	allowWinnLeafAsCover := flags.Bool("insecure-cover-reuses-winn-leaf", false,
		"lab only: serve the Winn leaf to unauthenticated peers, disclosing its issuer to every prober")
	allowIdentifyingCover := flags.Bool("insecure-cover-identifies-operator", false,
		"lab only: accept a cover certificate whose subject names the operator (EV/OV attributes)")
	allowImplausibleCover := flags.Bool("insecure-cover-is-not-a-real-origin", false,
		"lab only: accept a cover certificate that could not belong to a real public origin")
	maxPreauthConnections := flags.Int("max-preauth-connections", 1024,
		"serve: ceiling on concurrent accepted TCP cover connections before authentication; 0 disables")
	maxPreauthConnectionsPerIP := flags.Int("max-preauth-connections-per-ip", 32,
		"serve: ceiling on concurrent accepted TCP cover connections from one source; 0 disables")
	statusJSON := flags.String("status-json", "",
		"serve: atomically publish the bounded GCP proof status contract; when set, the only accepted path is /run/winn3-gateway/status.json")

	if err := flags.Parse(args); err != nil {
		return err
	}
	forwardAsyncWriteSet := false
	sendQueueFQSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "forward-async-write" {
			forwardAsyncWriteSet = true
		}
		if f.Name == "send-queue-fq" {
			sendQueueFQSet = true
		}
	})

	switch *mode {
	case "keygen":
		return runKeygen(*outDir, out)
	case "derive-public":
		return runDerivePublic(*staticPath, *dualEDKey, *dualMLSeed, *outDir, out)
	case "resources":
		return runResources(serveOptions{plan: *plan, pathMTU: *pathMTU, maxSessions: *maxSessions,
			uplinkInboxDepth: *uplinkInboxDepth}, out)
	case "features":
		return runFeatures(out)
	case "serve":
		return runServe(serveOptions{
			listen:        *listen,
			staticPath:    *staticPath,
			admission:     *admission,
			gatewayID:     *gatewayID,
			dualEDKey:     *dualEDKey,
			dualMLSeed:    *dualMLSeed,
			innerV4:       *innerV4,
			routerV4:      *routerV4,
			innerV6:       *innerV6,
			routerV6:      *routerV6,
			plan:          *plan,
			pathMTU:       *pathMTU,
			listenerDF:    *listenerDF,
			tcpIngress:    *tcpIngressFlag,
			acceptTransit: *acceptTransit,
			maxSessions:   *maxSessions,
			demux:         *demux,
			runFor:        *runFor,
			forward:       *forward,
			forwardIf:     *forwardIf,
			forwardCIDR:   *forwardCIDR,
			peerRegistry:  *peerRegistry,
			freeMbps:      *freeMbps,

			forwardAsyncWrite:    *forwardAsyncWrite,
			forwardAsyncWriteSet: forwardAsyncWriteSet,
			tunGSO:               *tunGSO,
			sendQueueFQ:          *sendQueueFQ,
			sendQueueFQSet:       sendQueueFQSet,
			uplinkResequence:     *uplinkResequence,
			uplinkInboxDepth:     *uplinkInboxDepth,

			speedtestIngestPort: *speedtestIngestPort,

			resolver:         *resolver,
			resolverUpstream: *resolverUpstream,
			resolverTimeout:  *resolverTimeout,

			certPath:                   *certPath,
			keyPath:                    *keyPath,
			echKeysPath:                *echKeysPath,
			coverCertPath:              *coverCertPath,
			coverKeyPath:               *coverKeyPath,
			coverServerName:            *coverServerName,
			decoyOrigin:                *decoyOrigin,
			suite:                      *suiteName,
			allowWinnLeafAsCover:       *allowWinnLeafAsCover,
			allowIdentifyingCover:      *allowIdentifyingCover,
			allowImplausibleCover:      *allowImplausibleCover,
			maxPreauthConnections:      *maxPreauthConnections,
			maxPreauthConnectionsPerIP: *maxPreauthConnectionsPerIP,
			statusJSON:                 *statusJSON,
		}, out)
	default:
		return fmt.Errorf("-mode is %q; use keygen, derive-public, serve, resources or features", *mode)
	}
}

// runKeygen writes one static key pair and one admission secret.
//
// Deliberately byte-identical in format to cmd/winn3-labrig's keygen — hex, the
// same three file names — so that material generated by either drives both, and
// cmd/winn-datapath's client accepts it without a conversion step.
func runKeygen(dir string, out io.Writer) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("keygen needs -out")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	private := make([]byte, core.KeySize)
	if _, err := rand.Read(private); err != nil {
		return err
	}
	key, err := core.NewStaticKey(private)
	if err != nil {
		return err
	}
	clientPrivate := make([]byte, core.KeySize)
	if _, err := rand.Read(clientPrivate); err != nil {
		return err
	}
	clientKey, err := core.NewStaticKey(clientPrivate)
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	mlSeed, err := pqauth.GenerateSeed()
	if err != nil {
		return err
	}
	mlSigner, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
	if err != nil {
		return err
	}
	mlPub := append([]byte(nil), mlSigner.PublicBytes()...)
	mlSigner.Destroy()
	files := map[string][]byte{
		"static.key":    []byte(hex.EncodeToString(private)),
		"static.pub":    []byte(hex.EncodeToString(key.Public())),
		"admission.key": []byte(hex.EncodeToString(secret)),
		"client.key":    []byte(hex.EncodeToString(clientPrivate)),
		"client.pub":    []byte(hex.EncodeToString(clientKey.Public())),
		// Dual-signature attestation keys (docs/DUAL_SIGNATURE_SPEC.md).
		// The ML-DSA-65 signer seed is 32 bytes, the public half 1952; both
		// hex, like every other file here.
		"auth_ed25519.seed": []byte(hex.EncodeToString(edPriv)), // full 64-byte private (seed||public)
		"auth_ed25519.pub":  []byte(hex.EncodeToString(edPub)),
		"auth_mldsa65.seed": []byte(hex.EncodeToString(mlSeed)),
		"auth_mldsa65.pub":  []byte(hex.EncodeToString(mlPub)),
	}
	for name, body := range files {
		// Refuse to overwrite live credentials: O_EXCL fails loudly instead of
		// truncating an active gateway's identity and admission secret.
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("refusing to overwrite existing key file %s: %w", name, err)
		}
		if _, err := f.Write(body); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "{\"event\":\"keygen\",\"dir\":%q,\"gateway_public\":%q,\"client_public\":%q}\n",
		dir, hex.EncodeToString(key.Public()), hex.EncodeToString(clientKey.Public()))
	return nil
}

type serveOptions struct {
	listen        string
	staticPath    string
	admission     string
	gatewayID     string
	dualEDKey     string
	dualMLSeed    string
	innerV4       string
	routerV4      string
	innerV6       string
	routerV6      string
	plan          string
	pathMTU       int
	listenerDF    bool
	tcpIngress    bool
	acceptTransit bool
	maxSessions   int
	demux         string
	runFor        time.Duration

	// forward, forwardIf and forwardCIDR configure real traffic forwarding.
	// See forward.go's package doc and the -forward flag's help.
	forward      bool
	forwardIf    string
	forwardCIDR  string
	peerRegistry string
	freeMbps     int

	// forwardAsyncWrite is -forward-async-write. See forward_async.go.
	forwardAsyncWrite bool
	// forwardAsyncWriteSet records whether -forward-async-write was passed
	// at all, so the 2026-10-10 default flip cannot swallow an explicit
	// =false: a flag the operator typed always wins over the environment.
	forwardAsyncWriteSet bool
	// tunGSO is -tun-gso. See tun_gso.go.
	tunGSO bool
	// sendQueueFQ is -send-queue-fq (session.Driver.SetSendQueueFQ). See
	// sendfq_default.go for the 2026-10-11 default flip.
	sendQueueFQ bool
	// sendQueueFQSet records whether -send-queue-fq was passed at all, so
	// the default flip cannot swallow an explicit =false: a flag the
	// operator typed always wins over the environment.
	sendQueueFQSet bool
	// uplinkResequence is -uplink-resequence (item 5, arm R1). See
	// winn3/driver/reseq.go.
	uplinkResequence bool
	// uplinkInboxDepth is -uplink-inbox-depth; zero means
	// defaultUplinkInboxDepth. See resolveUplinkInboxDepth.
	uplinkInboxDepth int

	// speedtestIngestPort (RV-B) serves the inner-only speedtest ingest.
	speedtestIngestPort int

	// resolver, resolverUpstream and resolverTimeout configure the inner DNS
	// responder. UDP is independent of forward: it answers at -inner-v4 in
	// process and needs neither a kernel interface nor -accept-transit.
	// TCP/53 is not: startResolverTCP listens only when forward is also on,
	// because -inner-v4 is a host address only after newSharedGatewayTun.
	// See resolve.go and resolve_tcp.go.
	resolver         bool
	resolverUpstream string
	resolverTimeout  time.Duration

	certPath                   string
	keyPath                    string
	echKeysPath                string
	coverCertPath              string
	coverKeyPath               string
	coverServerName            string
	decoyOrigin                string
	suite                      string
	allowWinnLeafAsCover       bool
	allowIdentifyingCover      bool
	allowImplausibleCover      bool
	maxPreauthConnections      int
	maxPreauthConnectionsPerIP int
	statusJSON                 string

	// replayJournal is the exact validated WINN3_REPLAY_JOURNAL pathname.
	// runServe fills it from parseReplayJournalPath so inspect, NewResponder,
	// and the live identity check cannot observe different strings. Empty
	// means buildSessionConfig reads the environment through the same parser
	// (lab tests that construct a config without going through runServe).
	replayJournal string
}

type proofStatus struct {
	SchemaVersion         int    `json:"schema_version"`
	Contract              string `json:"contract"`
	Event                 string `json:"event"`
	Ready                 bool   `json:"ready"`
	Forward               bool   `json:"forward"`
	ProcessID             int    `json:"process_id"`
	ProcessNonce          string `json:"process_nonce"`
	BootID                string `json:"boot_id"`
	ProcessStartTicks     uint64 `json:"process_start_ticks"`
	ProcessStartedUTC     string `json:"process_started_utc"`
	ObservedUTC           string `json:"observed_utc"`
	ObservedMonotonicNS   uint64 `json:"observed_monotonic_ns"`
	Sequence              uint64 `json:"sequence"`
	InnerPacketsDelivered uint64 `json:"inner_packets_delivered"`
	Reflected             uint64 `json:"reflected"`
	RxDeviceWrites        uint64 `json:"rx_device_writes"`
}

type noOpProofStatusLease struct{}

func (noOpProofStatusLease) Close() error { return nil }

func sameProofStatusProcess(a, b proofStatus) bool {
	return a.ProcessID == b.ProcessID &&
		a.ProcessNonce == b.ProcessNonce &&
		a.BootID == b.BootID &&
		a.ProcessStartTicks == b.ProcessStartTicks &&
		a.ProcessStartedUTC == b.ProcessStartedUTC
}

// serveStatus is the operator document. It is a superset of cmd/winn3-labrig's
// labStatus: the same promotion counters, plus the per-gateway session census
// that a multi-session process has and a one-session rig does not.
type serveStatus struct {
	Event  string `json:"event"`
	Listen string `json:"listen,omitempty"`

	// Ready means this process can admit a new handshake. It can become false
	// while Sessions stays non-zero: a sticky replay-journal failure refuses
	// new handshakes fail-closed but deliberately leaves established sessions
	// carrying. ReplayJournalStatus explains that distinction to operators.
	Ready               bool   `json:"ready"`
	ReplayJournalStatus string `json:"replay_journal_status"`
	ProofProcessID      int    `json:"-"`
	ProofProcessNonce   string `json:"-"`
	ProofBootID         string `json:"-"`
	ProofProcessTicks   uint64 `json:"-"`
	ProofProcessStarted string `json:"-"`
	ProofObservedUTC    string `json:"-"`
	ProofObservedMonoNS uint64 `json:"-"`
	ProofSequence       uint64 `json:"-"`

	Sessions  int    `json:"sessions"`
	Admitted  uint64 `json:"admitted"`
	Built     uint64 `json:"sessions_built"`
	Datagrams uint64 `json:"datagrams"`
	// Strangers counts datagrams refused on length, or by the admission
	// screen, before any state was allocated for the address that sent them.
	Strangers uint64 `json:"stranger_datagrams"`

	// AdmissionThrottled counts initiation-sized datagrams from an unknown
	// address that the admission work budget (admission_meter.go) refused
	// before the screen ran. Nonzero means the budget is being spent as
	// fast as it refills: either a flood, or a reconnect storm large
	// enough that the operator should know the gateway is shedding it.
	AdmissionThrottled uint64 `json:"admission_throttled"`

	// EgressMTURefused counts admitted initiations (and token-demux rebinds)
	// refused because the kernel routes replies to that client through a
	// device narrower than the plan's widest datagram (Round CM3). Nonzero
	// means some clients' routes need a lower -path-mtu, or a route fixed.
	EgressMTURefused uint64 `json:"egress_mtu_refused"`

	// EgressMTUClosed counts established sessions closed because the route
	// their replies take narrowed below the plan's widest datagram after
	// admission (Round CM3 Turn 3; egress_session_watch.go).
	EgressMTUClosed uint64 `json:"egress_mtu_closed"`

	// EgressRoutingUnaccountable is true while a policy rule or route selects
	// on mark or TOS: all sessions are closed and new clients refused (Round
	// CM3 Turn 4). EgressSweepMaxUS is the longest egress sweep so far.
	EgressRoutingUnaccountable bool   `json:"egress_routing_unaccountable"`
	EgressSweepMaxUS           uint64 `json:"egress_sweep_max_us"`

	// EgressNetlinkIncomplete counts kernel answers to egress questions that
	// were discarded as incomplete: an interrupted or overrun dump, an error
	// inside a dump, a truncated, foreign, malformed or late answer (Round CM3
	// Turn 6; egress_netlink_answer.go). Each question is asked up to three
	// times; after that the gateway fails closed.
	EgressNetlinkIncomplete uint64 `json:"egress_netlink_incomplete"`

	// Replays counts initiations refused as already-answered before any state
	// was allocated, from an address that held no session.
	//
	// It is published separately from Strangers because it means something an
	// operator should act on and Strangers does not. Stranger datagrams are
	// ambient internet noise and a healthy gateway sees them constantly. A
	// non-zero Replays means somebody is re-sending a handshake this gateway
	// has already answered, from an address that never held the session — which
	// is either a middlebox duplicating packets or a censor probing with a
	// captured initiation to confirm a Winn3 gateway is here. Both are worth
	// knowing; the second is the threat this protocol exists to defeat.
	Replays uint64 `json:"replayed_initiations"`

	Refused uint64 `json:"refused_datagrams"`

	// BuildFailures counts datagrams for which no session could be built. Any
	// non-zero value is a configuration or capacity fault, never a posture.
	BuildFailures uint64 `json:"session_build_failures"`
	// SessionsReclaimed and SessionsSuperseded count -max-sessions slots taken
	// back from dead sessions under pressure and from sessions replaced by a
	// newer session of the same client key. See session_reclaim.go.
	SessionsReclaimed  uint64 `json:"sessions_reclaimed"`
	SessionsSuperseded uint64 `json:"sessions_superseded"`

	// Carrying counts sessions whose gate is StateCarrying; Promoted counts
	// sessions that satisfy the FULL promotion predicate, gate carrying AND
	// RxPackets > 0. They are separate because a gate that opened while nothing
	// was ever delivered is exactly the state that has been mistaken for a
	// working tunnel in this project before. Promoted is REFLECTOR-ONLY
	// evidence: it is structurally 0 under -forward, whose return path never
	// reaches tun.Tunnel and so can never make RxPackets rise — read
	// CarriageProven, not Promoted, to ask "is this gateway carrying" of a
	// gateway whose mode you do not already know.
	Carrying int `json:"carrying"`
	Promoted int `json:"promoted"`

	// CarriageProven is the ONE mode-aware answer to "has this gateway actually
	// moved an inner packet", and it is the field fleet health should read.
	//
	// Promoted answers that question for the reflector and only for the
	// reflector. Under -forward the return path deliberately bypasses
	// tun.Tunnel (see gatewayForwardDevice.ReadPacket), so DeviceProven never
	// latches, so RxPackets stays 0, so Promoted stays 0 no matter how much
	// real traffic the gateway forwards. Neither counter is wrong; each is
	// honest in its own layer, and forward mode is simply a different health
	// contract. Measured 2026-08-12 on a correctly-forwarding gateway:
	// carrying 2, promoted 0, rx_device_writes 8, rx_packets 0.
	//
	// So the conjunction is chosen by mode, and it is computed HERE, in Go,
	// next to the counters, for the reason cmd/winn-datapath/winn3_status.go
	// already gives for winn3PromotionReady: a host cannot get it wrong
	// because a host is not asked. Every reader that instead re-derived it
	// from the counters would have to know which mode this process is in and
	// which counter is structurally dead in that mode, and that is exactly
	// the derivation that produced a healthy gateway reported as dead.
	//
	//	-forward off: Promoted > 0
	//	-forward on:  Carrying > 0 && Forward.Device.Delivered > 0
	//
	// Both halves are required in forward mode for the same reason Promoted
	// is a conjunction: Carrying alone is a state machine's opinion, and
	// Delivered alone is a shared device that reached SOME session, not
	// necessarily one that is open. Together they are "a reply came back AND
	// it reached a live session", which is what Forward's own doc already
	// calls the forward-mode equivalent of promotion.
	//
	// Fail-closed by construction: false is the zero value, it is only ever
	// set by a positive conjunction, and a reader that cannot parse this
	// document or finds the field absent gets false, which claims nothing.
	// This field is never an input to widening a tunnel — that is
	// winn3PromotionReady's job on the client — it is operator and fleet
	// evidence only.
	CarriageProven bool `json:"carriage_proven"`

	RxPackets uint64 `json:"rx_packets"`
	RxOffered uint64 `json:"rx_offered"`
	TxPackets uint64 `json:"tx_packets"`

	// RxDeviceWrites is winn3/tun's ungated write count for the forward
	// (client -> device) direction: every packet actually handed to the
	// device backend, whether or not DeviceProven has latched yet. It is the
	// number to watch under -forward, where the return path bypasses
	// tun.Tunnel entirely (see Forward below) and so can never make
	// DeviceProven true — meaning RxPackets stays 0 by construction for a
	// forward-mode session no matter how much real traffic that session
	// carries. RxDeviceWrites is not gated on DeviceProven and stays honest
	// either way.
	RxDeviceWrites uint64 `json:"rx_device_writes"`

	// InnerPacketsDelivered mirrors Forward.Device.Delivered at the TOP level,
	// and is nil — the key absent — unless -forward is set, exactly like
	// Forward itself.
	//
	// It is the return-direction counterpart of RxDeviceWrites: that field is
	// the ungated truth for client -> internet, this one is the ungated truth
	// for internet -> client, and under -forward they are the pair that says
	// traffic moved when RxPackets structurally cannot.
	//
	// It is published at the top level, duplicating a nested field, because
	// the promotion-evidence path scans FLAT counter keys by name, and
	// `inner_packets_delivered` is already a member of the delivered-counter
	// set both rulers use (test/winn_protocol_dispatch_test.dart's
	// kWinnEvidenceDeliveredKeys, and step 5 of the cross-family verifier in
	// WINN3_PROMOTION_EVIDENCE_SUBSTRATE_20260812). Before this field, a
	// forward-mode gateway_posture.jsonl offered those rulers only rx_packets,
	// which is 0 by construction, so step 5 — which reads the gateway file
	// ALONE — would have failed the first standalone forward-mode bundle
	// while the Dart checker passed it, because the Dart checker pools the
	// whole bundle and the client's own rx_packets masked the gateway's zero.
	// Two rulers disagreeing means one is wrong; this closes the gap by
	// making the gateway publish the counter both already ask for, rather
	// than by weakening either ruler.
	//
	// A pointer, so the DISTINCTION is preserved: absent means "this gateway
	// is not forwarding, do not look for this counter here", while an
	// explicit 0 means "this gateway is forwarding and has delivered
	// nothing", which is a fault and must stay loudly visible rather than
	// vanishing under omitempty.
	InnerPacketsDelivered *uint64 `json:"inner_packets_delivered,omitempty"`

	RxDroppedInvalid uint64 `json:"rx_dropped_invalid"`
	RxDroppedClosed  uint64 `json:"rx_dropped_closed"`
	TxDroppedInvalid uint64 `json:"tx_dropped_invalid"`
	TxDroppedClosed  uint64 `json:"tx_dropped_closed"`

	// Why TxDroppedInvalid moved. Mirror of the rx_drop_* split: these sum
	// to tx_dropped_invalid. Four, not five — outbound cannot return
	// ErrNotForUs or ErrReflected; ErrSourceNotOurs is the outbound analogue
	// of NotForUs. Added 2026-08-12.
	TxDropFamilyOff     uint64 `json:"tx_drop_family_off"`
	TxDropMartian       uint64 `json:"tx_drop_martian"`
	TxDropSourceNotOurs uint64 `json:"tx_drop_source_not_ours"`
	TxDropMalformed     uint64 `json:"tx_drop_malformed"`

	// Why RxDroppedInvalid moved. These sum to it, and their difference is the
	// diagnosis: RxDropNotForUs dominating means a full-tunnel client is being
	// asked to be the destination of its own traffic rather than a next hop;
	// RxDropFamilyOff means one address family is unassigned. Added 2026-08-11
	// after the first standalone iOS carry showed rx_offered 50 / rx_packets 0 /
	// rx_dropped_invalid 50 with no way to tell WHICH of five rejections fired.
	RxDropFamilyOff uint64 `json:"rx_drop_family_off"`
	RxDropMartian   uint64 `json:"rx_drop_martian"`
	RxDropNotForUs  uint64 `json:"rx_drop_not_for_us"`
	RxDropReflected uint64 `json:"rx_drop_reflected"`
	RxDropMalformed uint64 `json:"rx_drop_malformed"`

	Reflected uint64 `json:"reflected"`

	// Session-driver and loop counters, published because "the gateway has a
	// session" and "the gateway is talking" are different claims and only the
	// second one is evidence.
	SessionStates    []string `json:"session_states"`
	MessagesSent     uint64   `json:"messages_sent"`
	MessagesReceived uint64   `json:"messages_received"`
	SendFailed       uint64   `json:"send_failed"`
	SendRefused      uint64   `json:"send_refused"`
	RecvFailed       uint64   `json:"recv_failed"`
	// Unopenable and PathNarrowedFor are summed from each session's loop
	// Stats. messages_received includes unopenable datagrams (readLoop
	// counts them); unopenable is the diagnosis. path_narrowed_for names a
	// path that still carries small packets — and so can keep promoted
	// true — while full-size flows die.
	Unopenable      uint64 `json:"unopenable"`
	PathNarrowedFor uint64 `json:"path_narrowed_for"`
	PipeSent        uint64 `json:"pipe_sent"`
	PipeDelivered   uint64 `json:"pipe_delivered"`
	PipeRecvErrors  uint64 `json:"pipe_recv_errors"`
	PipeSendErrors  uint64 `json:"pipe_send_errors"`
	// PipeInboxHighWater is the deepest any live session's inbox has been,
	// in messages (carrier.Stats.InboxHighWater): what sizes inboxDepth.
	PipeInboxHighWater uint64 `json:"pipe_inbox_high_water"`
	// PipeInboxSojourn sums the live sessions' inbox sojourn histograms and
	// PipeInboxSojournMaxUS is their longest wait (carrier.Stats.InboxSojourn,
	// InboxSojournMaxUS): the standing delay the inbox depth itself adds to
	// the uplink, read beside pipe_inbox_high_water. Bucket i, for i >= 1,
	// counts waits of 2^i to 2^(i+1)-1 hundred-microsecond units; bucket 0
	// under 0.2 ms; the last bucket 204.8 ms and over.
	PipeInboxSojourn      [carrier.InboxSojournBuckets]uint64 `json:"pipe_inbox_sojourn"`
	PipeInboxSojournMaxUS uint64                              `json:"pipe_inbox_sojourn_max_us"`
	// OuterReordered sums every session's authenticated uplink messages that
	// arrived after a later one, and OuterLost every session's uplink
	// messages that never opened: wire loss plus pipe_recv_errors (inbox
	// drops). SendQueueHighWater is the deepest any live session's send
	// queue has been, in inner packets: the gateway's downlink backlog.
	// SendQueueDepth sums the live sessions' send queues at this snapshot.
	// The sums can fall when a session leaves.
	OuterReordered     uint64 `json:"outer_reordered"`
	OuterLost          uint64 `json:"outer_lost"`
	SendQueueDepth     uint64 `json:"send_queue_depth"`
	SendQueueHighWater uint64 `json:"send_queue_high_water"`
	// SendQueueDropped sums every session's CoDel drops from the send queue
	// (session.SendQueueCoDel*): head packets shed because their sojourn
	// exceeded the target. Published at zero like its neighbours; read it
	// against SendQueueDepth and the download throughput in one bracket.
	SendQueueDropped uint64 `json:"send_queue_dropped"`
	// SendQueueOverflow sums the live sessions' fattest-bucket drops at the
	// send queue cap under -send-queue-fq. Zero without it.
	SendQueueOverflow uint64 `json:"send_queue_overflow"`

	// OuterReorderDepth splits outer_reordered by displacement, summed over
	// the live sessions: bucket i counts late messages 2^i to 2^(i+1)-1
	// counters below the highest opened, the last bucket 512 and over
	// (core.ReorderDepth). It says whether inversions come from one send
	// batch (at most 44) or from a second path (rate x skew).
	OuterReorderDepth core.ReorderDepth `json:"outer_reorder_depth"`

	InnerMTU    int `json:"inner_mtu"`
	MessageSize int `json:"message_size"`

	// UdpReadBuffer / UdpWriteBuffer are the kernel-granted SO_RCVBUF /
	// SO_SNDBUF. Linux silently clamps the request to net.core.rmem_max
	// and still returns success from setsockopt, so a status document that
	// only recorded the request would look healthy at rmem_default
	// (~256 KiB). These fields are the granted sizes, published at zero
	// rather than omitempty, because a permanent zero is how a skipped
	// SetReadBuffer would otherwise hide. UdpReadBufferRequested is the
	// constant this process asked for, so a clamp is visible without
	// reading stderr.
	UdpReadBufferRequested int `json:"udp_read_buffer_requested"`
	UdpReadBuffer          int `json:"udp_read_buffer"`
	UdpWriteBuffer         int `json:"udp_write_buffer"`

	// UdpRcvbufErrors is the host-wide Linux Udp: RcvbufErrors counter
	// from /proc/net/snmp, omitted where that file does not exist. It is
	// not per-socket. A rise during a readLoop stall is the overflow
	// these buffers exist to prevent; a rise caused by another process
	// is still worth seeing rather than hiding.
	UdpRcvbufErrors *uint64 `json:"udp_rcvbuf_errors,omitempty"`

	// UdpSendErrors is the shared socket's send-error evidence: transmit-queue
	// refusals returned to sessions, and other peers' socket errors absorbed
	// without blaming the session being served. Omitted when the socket has
	// no error-queue drain (non-Linux). See udp_send_errors.go.
	UdpSendErrors *udpSendErrorStatus `json:"udp_send_errors,omitempty"`

	Refusal string `json:"refusal,omitempty"`

	// Forward is nil unless -forward is set, in which case it is the
	// forwarding-table and shared-device evidence that Carrying/Promoted
	// above cannot see for this mode — see RxDeviceWrites's comment and
	// gatewayForwardDevice's doc in forward.go. Read together with gate
	// state and RxDeviceWrites the way the deployment runbook's diagnostic
	// table reads admitted/refused_datagrams/promoted: Forward.Device.Reads
	// rising with Forward.Device.Delivered rising alongside it is the
	// forward-mode equivalent of "promoted" — a reply actually came back
	// AND actually reached a session, not merely that the interface exists.
	Forward *gatewayForwardStatus `json:"forward,omitempty"`

	// Resolver is nil unless -resolver is set. Aggregate counters only — see
	// resolve.go's privacy note for why no name and no client address appears
	// here or anywhere else. Read Claimed against Answered: a Claimed that
	// rises while Answered does not is the upstream failing, and
	// UpstreamFailed against Refused separates "the upstream stopped
	// answering" from "this process hit its own in-flight ceiling".
	Resolver *resolverStats `json:"resolver,omitempty"`
}

func runServe(opts serveOptions, out io.Writer) error {
	if strings.TrimSpace(opts.listen) == "" {
		return errors.New("serve needs -listen")
	}
	// FIRST, before sizing, before any key file is read and long before a
	// socket exists. This is silent-refusal instance #5 and it is the same
	// argument preflightSession makes for #8: the operator is standing here
	// now, and the alternative to telling them now is telling nobody ever.
	if err := validateOperatorValues(opts); err != nil {
		return err
	}
	if err := validateProofStatusPath(opts.statusJSON); err != nil {
		return err
	}
	sizing, _, err := buildServeSizing(opts)
	if err != nil {
		return err
	}
	assign, err := parseAssignment(opts.innerV4, opts.routerV4, opts.innerV6, opts.routerV6)
	if err != nil {
		return err
	}
	if opts.maxSessions < 1 {
		// The shared UDP and TCP session ceiling would be reached before the
		// first client with a value of zero or less. Every session would be
		// refused in silence, by the same discarded error
		// preflightSession describes. A gateway that can serve nobody is a
		// configuration error, not a posture.
		return fmt.Errorf("-max-sessions is %d; a gateway whose session ceiling is below 1 "+
			"refuses every client in silence", opts.maxSessions)
	}
	depth, err := resolveUplinkInboxDepth(opts.uplinkInboxDepth)
	if err != nil {
		return err
	}
	opts.uplinkInboxDepth = depth
	// One line per start, so an arm's journal proves which depth ran.
	fmt.Fprintf(os.Stderr, "winn3-gateway: uplink inbox depth %d messages per session\n", depth)
	sendFQ, err := resolveSendQueueFQDefault(opts.sendQueueFQ, opts.sendQueueFQSet,
		os.Getenv(sendQueueFQDefaultEnv))
	if err != nil {
		return err
	}
	opts.sendQueueFQ = sendFQ
	// One line per start, the same proof the depth line gives an arm's
	// journal: which send queue this run used.
	if sendFQ {
		fmt.Fprintf(os.Stderr, "winn3-gateway: send queue: per-host-pair fair queueing with per-bucket CoDel (-send-queue-fq)\n")
	} else {
		fmt.Fprintf(os.Stderr, "winn3-gateway: send queue: single FIFO with CoDel (-send-queue-fq=false)\n")
	}
	if opts.tunGSO && !opts.forward {
		return errors.New("-tun-gso changes how -forward writes to its TUN interface and " +
			"means nothing without -forward; set both or neither")
	}
	if opts.forwardAsyncWrite && !opts.forward {
		return errors.New("-forward-async-write changes how -forward writes to its TUN interface and " +
			"means nothing without -forward; set both or neither")
	}
	if opts.demux == "" || opts.demux == "address" {
		if env := os.Getenv("WINN3_GATEWAY_DEMUX"); env != "" {
			opts.demux = env
		}
	}
	if opts.demux == "" {
		opts.demux = "address"
	}
	if opts.demux != "address" && opts.demux != "token" {
		return fmt.Errorf("-demux must be address or token, got %q", opts.demux)
	}
	// Same mapping as WINN3_GATEWAY_DEMUX above: the environment is read when
	// the flag holds its default. Refused before the socket exists.
	opts.listenerDF, err = resolveListenerDF(opts.listenerDF, os.Getenv(listenerDFEnv))
	if err != nil {
		return err
	}
	// The same mapping for -tcp-ingress (Round W off by default). Refused
	// before the socket exists.
	opts.tcpIngress, err = resolveTCPIngress(opts.tcpIngress, os.Getenv(tcpIngressEnv))
	if err != nil {
		return err
	}
	// The same mapping for the free-tier cap (owner D5, 2026-10-11). Refused
	// before the socket exists.
	opts.freeMbps, err = resolveFreeMbps(opts.freeMbps, os.Getenv(freeRateEnv))
	if err != nil {
		return err
	}
	// Durable replay is a production invariant. Parse the journal pathname
	// once, inspect that exact string, and pass it through buildSessionConfig
	// so a trimmed preflight path and a whitespace-suffixed runtime path
	// cannot name distinct journal and WAL files. A missing path must not
	// become a wiped replay window. Explicit WINN3_GATEWAY_REPLAY_JOURNAL=0
	// is the same class of bypass and is refused here, before listen.
	journalPath, err := requireReplayJournalPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winn3-gateway: replay-journal status=%s\n", replayJournalStatusLoadRefused)
		return err
	}
	opts.replayJournal = journalPath
	var forwardPrefixLen int
	var registry *peerRegistry
	if opts.forward {
		// Checked BEFORE preflightSession, for the same reason every other
		// refusal in this file fires before the socket exists: the operator
		// is standing here now.
		forwardPrefixLen, err = validateForwardMode(opts, assign)
		if err != nil {
			return err
		}
		prefix, _ := netip.ParsePrefix(opts.forwardCIDR)
		registry, err = newPeerRegistryWithRate(opts.peerRegistry, prefix, opts.freeMbps, assign.V4)
		if err != nil {
			return fmt.Errorf("-peer-registry: %w", err)
		}
	}
	sessionConfig, err := buildSessionConfig(opts, registry)
	if err != nil {
		return err
	}
	var resolverUpstream netip.AddrPort
	// Called regardless of -resolver: when -resolver is off, the validator
	// still refuses an inert -resolver-upstream or -resolver-timeout set
	// without it (see validateResolverMode), so an operator's stated
	// configuration is never silently ignored.
	resolverUpstream, err = validateResolverMode(opts, assign)
	if err != nil {
		return err
	}
	if err := preflightSession(sizing, sessionConfig, assign); err != nil {
		return err
	}
	if err := requireCoverFlags(opts); err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp4", opts.listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	// Round CM: before the socket exists, like every refusal above. See
	// egress_mtu.go for why a measured mismatch refuses and an unmeasured
	// route only warns. Unconditional: it does not depend on -listener-df
	// (Round CM2, OI-CM2-1a). The lookup is for this listener's own address
	// and port, so policy routing is followed (Round CM2 retro, L80).
	lookup := egressLookupFor(addr)
	egress, egressErr := measureEgress(lookup)
	if err := checkEgressMTU(sizing, lookup, egress, egressErr, os.Stderr); err != nil {
		return err
	}
	// Round CM3 Turn 4: a rule or route selecting on mark or TOS makes the
	// replies' route unaccountable (egress_mtu.go, checkRoutingAccountable).
	if err := checkRoutingAccountable(os.Stderr); err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	gotRead, gotWrite, err := configureUDPSocketBuffers(conn)
	if err != nil {
		return err
	}
	// DF on the shared listener only with -listener-df (Round CM2, OI-CM2-1a).
	// Off, the socket keeps the kernel default and one line says so. See
	// configureListenerDontFragment.
	if err := configureListenerDF(conn, opts.listenerDF, os.Stderr); err != nil {
		return err
	}
	sendErrorOptions := enableUDPSendErrorReporting(conn)

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.runFor > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.runFor)
		defer cancel()
	}

	cover, err := startCover(ctx, opts, conn, sizing.MessageSize, sessionConfig, sizing)
	if err != nil {
		return err
	}
	defer cover.stop()

	proofNonceBytes := make([]byte, 16)
	if _, err := rand.Read(proofNonceBytes); err != nil {
		return fmt.Errorf("create proof process nonce: %w", err)
	}
	proofBootID := ""
	proofProcessTicks := uint64(0)
	if opts.statusJSON != "" {
		proofBootID, proofProcessTicks, err = proofProcessIdentity()
		if err != nil {
			return fmt.Errorf("bind proof process identity: %w", err)
		}
	}
	proofStarted := time.Now()
	// The per-client guard asks about the socket as bound, so a -listen with
	// port 0 still carries the port the replies leave from, and with the
	// listener's own fwmark, if anything set one (Round CM3).
	boundAddr, _ := conn.LocalAddr().(*net.UDPAddr)
	guardLookup := egressLookupFor(boundAddr)
	if guardLookup.Mark, err = listenerMark(conn); err != nil {
		return fmt.Errorf("read the listener's SO_MARK for the egress guard: %w", err)
	}
	srv := &server{
		conn:                cover.v3,
		tcp:                 cover.tcp,
		udpReadBuffer:       gotRead,
		udpWriteBuffer:      gotWrite,
		udpSendErrorOptions: sendErrorOptions,
		sizing:              sizing,
		sessionCfg:          sessionConfig,
		assign:              assign,
		maxSessions:         opts.maxSessions,
		admission:           newAdmissionMeter(),
		demux:               opts.demux,
		peers:               make(map[netip.AddrPort]*peerSession),
		tcpPeers:            make(map[*peerSession]struct{}),
		acceptTransit:       opts.acceptTransit,
		uplinkResequence:    opts.uplinkResequence,
		inboxDepth:          opts.uplinkInboxDepth,
		sendQueueFQ:         opts.sendQueueFQ,
		peerRegistry:        registry,
		statusJSON:          opts.statusJSON,
		proofProcessID:      os.Getpid(),
		proofNonce:          hex.EncodeToString(proofNonceBytes),
		proofBootID:         proofBootID,
		proofTicks:          proofProcessTicks,
		proofStarted:        proofStarted.UTC().Format(time.RFC3339Nano),
		proofMonoStart:      proofStarted,
		egressGuard:         &clientEgressGuard{lookup: guardLookup, datagram: plannedIPv4Datagram(sizing)},
	}
	if registry != nil {
		// The accept-time per-key session cap (session_reclaim.go). The
		// registry's authorize callback runs inside core.ReadInitiation, so a
		// key at its cap is refused before a response is built: silence, and
		// a half-open the pressure rule reclaims at once.
		registry.admit = srv.keyMayOpenSession
	}

	if opts.forward {
		table := newForwardTable()
		table.registry = registry
		// OI-5: the uplink destination rule, built before the first session
		// exists. validateForwardMode already parsed -forward-cidr.
		forwardPrefix, _ := netip.ParsePrefix(opts.forwardCIDR)
		table.isolation, err = newForwardIsolation(forwardPrefix, assign.V4)
		if err != nil {
			return fmt.Errorf("-forward: %w", err)
		}
		go table.isolation.runLocalRefresh(ctx, isolationLocalRefresh)
		sharedDev, err := newSharedGatewayTunOpts(opts.forwardIf, assign.V4, forwardPrefixLen, sizing.InnerMTU, table,
			tunOptions{vnetHdr: opts.tunGSO})
		if err != nil {
			// Fail closed: nothing has bound the UDP socket's job away yet
			// and the deferred conn.Close above still runs, so a refusal here
			// leaves no dangling interface and no half-started server.
			return fmt.Errorf("-forward: %w", err)
		}
		defer func() { _ = sharedDev.Close() }()
		asyncDefault, asyncErr := resolveAsyncWriteDefault(opts.forwardAsyncWrite,
			opts.forwardAsyncWriteSet, os.Getenv(asyncWriteDefaultEnv))
		if asyncErr != nil {
			return asyncErr
		}
		opts.forwardAsyncWrite = asyncDefault
		if opts.forwardAsyncWrite {
			startAsyncWritesOnThisHost(sharedDev, os.Stderr)
		}
		go sharedDev.run(ctx)
		srv.forward = true
		srv.table = table
		srv.sharedDev = sharedDev
		// RV-B (Round 38 treaty): the primary speedtest target is the gateway
		// itself. The listener binds ONLY to the inner IPv4 on the TUN
		// interface, so reachability requires an admitted, encrypted session:
		// tunnel membership is the authentication. Off by default (-speedtest-
		// ingest-port 0) so existing deploys are byte-for-byte unchanged.
		if opts.speedtestIngestPort > 0 {
			if err := startSpeedtestIngest(ctx, assign.V4, opts.speedtestIngestPort, func(f string, a ...interface{}) {
				fmt.Fprintf(os.Stderr, "winn3-gateway: "+f+"\n", a...)
			}); err != nil {
				return fmt.Errorf("-speedtest-ingest-port: %w", err)
			}
		}
		fmt.Fprintf(os.Stderr,
			"winn3-gateway: -forward is on: %s is up at %s/%d, mtu %d. This process forwards to\n"+
				"  that interface only — the install script's sysctl and iptables state (not this\n"+
				"  binary) is what makes the kernel actually route and NAT it to the internet. See\n"+
				"  WINN3_GATEWAY_FORWARD in wins_winn3_gateway_install.sh.\n",
			opts.forwardIf, assign.V4, forwardPrefixLen, sizing.InnerMTU)
	}

	if opts.resolver {
		srv.resolver = newGatewayResolver(assign.V4, resolverUpstream, opts.resolverTimeout, dnsDefaultMaxInFlight)
		fmt.Fprintf(os.Stderr,
			"winn3-gateway: -resolver is on: answering DNS at %s:53, forwarding to %s.\n"+
				"  Every name every session looks up is seen by this process and by that upstream.\n"+
				"  Nothing per-query is logged here. This ADVERTISES NOTHING: no client is told this\n"+
				"  resolver exists, and every platform still refuses to start a standalone session\n"+
				"  until the signed descriptor names a resolver. See resolve.go.\n",
			assign.V4, resolverUpstream)
		if warn := resolverDerivationWarning(opts, assign); warn != "" {
			fmt.Fprintf(os.Stderr, "winn3-gateway: WARNING: %s\n", warn)
		}
		// After newSharedGatewayTun so -inner-v4 is a host address. No-op
		// without -forward (reflector has no tun address). Fail closed on
		// listen error: do not continue UDP-only while claiming :53.
		if err := startResolverTCP(ctx, srv.resolver, opts.forward, assign.V4); err != nil {
			return err
		}
	}

	local := conn.LocalAddr().String()
	fmt.Fprintf(os.Stderr, "winn3-gateway: listening on %s\n", local)
	fmt.Fprintf(os.Stderr,
		"winn3-gateway: UDP socket buffers requested %d, granted read=%d write=%d\n",
		udpSocketBufferBytes, gotRead, gotWrite)
	srv.proofListen = local
	return srv.serve(ctx, out)
}

// validateForwardMode refuses a -forward configuration that could not
// possibly carry traffic, before any privileged resource is touched.
//
// # Why -accept-transit is required rather than implied
//
// -forward could silently force AcceptTransit on internally instead of
// requiring the operator to also pass -accept-transit. That would be smaller,
// and it would be the one wrong kind of smaller this codebase keeps finding:
// validateOperatorValues refuses to trim a value that arrived with edge
// whitespace for the identical reason — an operator's stated configuration is
// not something this binary silently overrides on their behalf, because the
// next person reading `-forward` on this host's command line with no
// `-accept-transit` beside it would have no way to know a real relaxation of
// the address rule is in effect.
func validateForwardMode(opts serveOptions, assign tun.Assignment) (prefixLen int, err error) {
	if !opts.acceptTransit {
		return 0, errors.New(
			"-forward needs -accept-transit=true: a client whose AllowedIPs is 0.0.0.0/0 addresses " +
				"every packet to the real internet destination, never to this gateway's own inner " +
				"address, so without -accept-transit every inbound packet is refused as ErrNotForUs " +
				"before -forward's forwarding table would ever see one")
	}
	if assign.V6.IsValid() {
		return 0, errors.New(
			"-forward does not carry inner IPv6: the shared kernel interface and the return-path " +
				"forwarding table are IPv4 only. Omit -inner-v6 and -router-v6 when -forward is set")
	}
	if strings.TrimSpace(opts.forwardIf) == "" {
		return 0, errors.New("-forward-if is empty; name the TUN interface -forward creates")
	}
	if strings.TrimSpace(opts.forwardCIDR) == "" {
		return 0, errors.New(
			"-forward-cidr is unset, and this flag will not default it: it must name the inner " +
				"subnet -forward routes for, e.g. 10.64.0.0/24 — the SAME subnet the control plane " +
				"assigns client inner_v4 addresses from, or a real client's return traffic has no " +
				"route back to this interface — and it must be DISJOINT from awg0's VPN_CIDR " +
				"(10.8.0.0/16 by default). This binary cannot see that installer's configuration to " +
				"check the second half for you; get the two agreeing before running with -forward")
	}
	if strings.TrimSpace(opts.peerRegistry) == "" {
		return 0, errors.New("-forward needs -peer-registry: forwarding must bind each authenticated client static key to its hub-issued inner IPv4 address")
	}
	return parseForwardCIDR(opts.forwardCIDR, assign.V4)
}

// parseForwardCIDR validates -forward-cidr and confirms assignV4 (this
// gateway's own inner address) is a USABLE HOST address inside it — not the
// network or broadcast address of that prefix, either of which `ip addr add`
// still accepts but neither of which is a sound choice for a gateway's own
// interface address.
func parseForwardCIDR(cidr string, assignV4 netip.Addr) (prefixLen int, err error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, fmt.Errorf("-forward-cidr %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return 0, fmt.Errorf("-forward-cidr %q is not IPv4; -forward carries IPv4 only", cidr)
	}
	masked := prefix.Masked()
	if prefix.Addr() != masked.Addr() {
		return 0, fmt.Errorf("-forward-cidr %q has host bits set in the network portion; "+
			"give the network address, e.g. %s", cidr, masked)
	}
	if !prefix.Contains(assignV4) {
		return 0, fmt.Errorf("-inner-v4 %s is not inside -forward-cidr %s", assignV4, cidr)
	}
	bits := prefix.Bits()
	if bits >= 31 {
		return 0, fmt.Errorf("-forward-cidr %q is a /%d, which leaves no room for a client "+
			"address distinct from the gateway's own %s", cidr, bits, assignV4)
	}
	broadcast := lastAddrInPrefix(masked)
	if assignV4 == masked.Addr() || assignV4 == broadcast {
		return 0, fmt.Errorf("-inner-v4 %s is the network or broadcast address of -forward-cidr "+
			"%s, not a usable host address", assignV4, cidr)
	}
	return bits, nil
}

// lastAddrInPrefix computes an IPv4 prefix's broadcast address: the network
// address with every host bit set to 1.
func lastAddrInPrefix(p netip.Prefix) netip.Addr {
	network := p.Addr().As4()
	hostBits := uint(32 - p.Bits())
	var mask uint32
	if hostBits > 0 {
		mask = (uint32(1) << hostBits) - 1
	}
	v := binary.BigEndian.Uint32(network[:]) | mask
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}

// validateOperatorValues refuses an operator flag whose meaning turns on
// whitespace nobody typed on purpose, BEFORE anything is read, sized or bound.
//
// # The defect this closes
//
// Silent-refusal instance #5. gateway_id is an AUTHENTICATED INPUT to the
// admission tag and buildSessionConfig keys with the operator string's RAW
// BYTES — deliberately, and that line must stay raw for the reasons stated
// there. strings.TrimSpace appears in buildSessionConfig for the EMPTINESS
// CHECK only; the value keyed with has never been trimmed.
//
// Every host that receives the value as TRANSPORT TEXT trims it — Android's
// WinnV3Keys.from calls .trim(), Swift's winn3Field calls
// trimmingCharacters(in: .whitespacesAndNewlines), linux/runner's INI parser
// Trim()s every value — so `-gateway-id "winsgw01 "` here and `winsgw01` in the
// hub is two ends keyed one byte apart. A v3 gateway does not answer a datagram
// it could not authenticate, so the whole node then refuses every client in the
// fleet at once, in silence, which under this threat model reads as a censor.
//
// # Refuse, do not trim
//
// Trimming here is smaller and it is the wrong answer twice over. It would make
// the gateway silently disagree with a descriptor that legitimately encodes a
// space, and it would move the divergence rather than close it — the gateway is
// the end the other four hosts are measured against, so a normalisation rule
// invented here becomes a rule four hosts have to remember. Refusing costs one
// restart with the operator standing in front of the machine. Accepting costs a
// fleet, discovered days later from the wrong end.
//
// # What is deliberately NOT checked here
//
//   - The value keyed with. buildSessionConfig still takes the raw bytes, and
//     TestTheGatewayKeysWithTheOperatorValueUntrimmed still pins that it does.
//     The conformance adapter drives buildSessionConfig directly, on purpose,
//     so that the derivation this binary is measured by is what the datagram
//     path actually computes rather than what a start-up gate allowed.
//   - INTERNAL whitespace. "wins gw 01" is a name somebody may well have meant,
//     it round-trips through every host identically, and refusing it would be
//     the over-fire this family cannot afford.
//   - -admission and -static, which are PATHS rather than operator values. A
//     path carrying edge whitespace fails at os.ReadFile with the name of the
//     file it could not open, which is already loud and already points at the
//     right line. There is nothing silent to close there.
func validateOperatorValues(opts serveOptions) error {
	if opts.freeMbps < 0 || opts.freeMbps > 100000 {
		return errors.New("-free-mbps must be in 0..100000")
	}
	if trimmed := strings.TrimSpace(opts.gatewayID); trimmed != opts.gatewayID {
		return fmt.Errorf(
			"-gateway-id carries whitespace at its edges: %s. It is an authenticated "+
				"input to the admission tag and is keyed with the operator's RAW bytes, "+
				"while every host that reads it as transport text trims it — so this "+
				"gateway would compute a tag over %d bytes against the fleet's %d and "+
				"answer every client with the silence it answers every unauthenticated "+
				"datagram with. Start it with -gateway-id %q, or, if the whitespace was "+
				"deliberate, there is no spelling of it the other hosts can reproduce",
			edgeWhitespaceReport(opts.gatewayID),
			len(opts.gatewayID), len(trimmed), trimmed)
	}
	return nil
}

// edgeWhitespaceReport renders a value's edge whitespace so an operator can SEE
// it, because being invisible in a terminal is the whole of the defect.
//
// Everything in the string it returns is measured from the argument. Nothing is
// a constant: a diagnostic that prints a plausible number it did not compute is
// worse than no diagnostic, because it gets believed and then relayed.
func edgeWhitespaceReport(s string) string {
	noLead := strings.TrimLeftFunc(s, unicode.IsSpace)
	lead := s[:len(s)-len(noLead)]
	noTrail := strings.TrimRightFunc(noLead, unicode.IsSpace)
	trail := noLead[len(noTrail):]

	var b strings.Builder
	fmt.Fprintf(&b, "%q (hex %x)", s, s)
	for _, part := range []struct {
		where string
		runes string
	}{{"leading", lead}, {"trailing", trail}} {
		if part.runes == "" {
			continue
		}
		fmt.Fprintf(&b, ", %d %s whitespace byte(s)", len(part.runes), part.where)
		// BYTES is the unit that matters — the admission tag is computed over
		// bytes and the divergence is a byte-length one — but a single
		// non-ASCII space is several of them, and "2 leading whitespace
		// byte(s)" beside one code point reads like a miscount. Say both, and
		// only when they differ, so the ASCII case stays terse.
		if n := utf8.RuneCountInString(part.runes); n != len(part.runes) {
			fmt.Fprintf(&b, " in %d code point(s)", n)
		}
		b.WriteString(":")
		for _, r := range part.runes {
			fmt.Fprintf(&b, " %+q (%U)", r, r)
		}
	}
	return b.String()
}

// preflightSession proves the operator's configuration can build a session at
// all, BEFORE the socket is bound, by building one exactly the way the datagram
// path will and throwing it away.
//
// # The defect this closes
//
// This is silent-refusal instance #8 and the family it belongs to. A gateway
// started with -router-v4 equal to -inner-v4 parsed, started, bound, printed
// "listening", and then refused every handshake while logging NOTHING on either
// end. A lane lost a debugging cycle to it.
//
// The mechanism was NOT a routing state that swallowed the response. The
// configuration IS rejected, loudly and correctly, by winn3/tun (tun.go:169,
// "IPv4 router address equals the assigned address"). The rejection simply
// happened in the wrong place: session construction is lazy, so tun.New did not
// run until the first datagram arrived, and readLoop discards that error with a
// bare `continue` — deliberately, because a v3 gateway must never answer an
// unauthenticated peer. So a permanent, operator-caused configuration error was
// being re-made and re-discarded once per datagram, forever, with the only trace
// being `datagrams` climbing while `admitted` and `sessions_built` stayed at
// zero. Under this threat model that presents exactly as a censor.
//
// The fix is not to log at handshake time — a per-datagram log line on an
// unauthenticated path is a disk-fill an attacker can drive, which is why
// maxRefusalLogs exists. The fix is to find out at startup, where the operator
// is standing, and refuse.
//
// # Why a dry run and not a list of checks
//
// A hand-written copy of winn3/tun's address rules in this file would agree with
// itself while tun.New rejected something else — the exact failure
// buildServeSizing documents about calling driver.NewSizing from the conformance
// adapter. So this runs the REAL constructors, driver.NewGateway -> tun.New, in
// the same order and with the same values newSession uses. A rule added to
// either package is enforced here on the day it is added and this file does not
// have to be touched. It is also why it catches more than the pair that prompted
// it: a martian or wrong-family -inner-v4 or -router-v4 lands here too.
//
// It opens nothing and sends nothing. The carrier is a Pipe whose Out is never
// called, and the device is the same in-process reflector a real session gets,
// so this is safe to run before the listening socket exists.
func preflightSession(sizing driver.Sizing, sessionCfg session.Config, assign tun.Assignment) error {
	// The shared responder is a START-UP requirement, not a runtime nicety.
	//
	// This binary builds one session per peer ADDRESS, so without a Responder
	// carried on the config every peer would get its own empty handshake replay
	// cache and a captured initiation replayed from a second address would be
	// answered — a remote gateway detector. buildSessionConfig always installs
	// one; this refuses to start if some future path ever stops doing so,
	// because the symptom otherwise is invisible from the outside: the gateway
	// works perfectly for every legitimate client and is merely findable.
	if sessionCfg.Responder == nil {
		return errors.New(
			"this configuration carries no shared handshake responder, so every peer " +
				"address would get its own empty replay cache and a captured initiation " +
				"replayed from a second address would be answered — a remote gateway " +
				"detector. Build the config with buildSessionConfig, which installs one " +
				"via session.NewSharedResponder")
	}
	pipe, err := carrier.NewPipe(carrier.PipeConfig{
		Class:          carrier.ClassUDP,
		Out:            func([]byte) error { return errors.New("preflight carrier never sends") },
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		return fmt.Errorf("this configuration cannot carry traffic: %w", err)
	}
	defer func() { _ = pipe.Close() }()

	dev := newReflector(sizing.InnerMTU, assign.V4)
	defer func() { _ = dev.Close() }()

	tunCfg := tun.Config{
		Assign: assign,
		Device: dev,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}
	loop, err := driver.NewGateway(driver.Config{
		Session: sessionCfg,
		Sizing:  sizing,
		Carrier: pipe,
		Tun:     &tunCfg,
	})
	if err != nil {
		return fmt.Errorf(
			"this configuration cannot build a session, so no client could ever be "+
				"admitted and the gateway refuses to start rather than answer every "+
				"handshake with silence (-inner-v4 %s, -router-v4 %s, -path-mtu %d): %w",
			addrOrUnset(assign.V4), addrOrUnset(assign.RouterV4), sizing.PathMTU, err)
	}
	return loop.Close()
}

// addrOrUnset renders an optional address for an operator-facing message. The
// zero netip.Addr prints as "invalid IP", which reads as a complaint about a
// value the operator may never have typed.
func addrOrUnset(a netip.Addr) string {
	if !a.IsValid() {
		return "unset"
	}
	return a.String()
}

type replayJournalMonitor interface {
	ReplayJournalError() error
	VerifyReplayJournalPath() error
}

// server is the demultiplexer: one socket, many sessions.
type server struct {
	// sendQueueFQ is opts.sendQueueFQ (-send-queue-fq).
	sendQueueFQ bool

	conn           udpConn
	tcp            *tcpIngress
	udpReadBuffer  int
	udpWriteBuffer int
	// udpSendErrorOptions records which IP_RECVERR / IPV6_RECVERR options the
	// shared socket actually got, for truthful status coverage.
	udpSendErrorOptions carrier.SendErrorOptions
	sizing              driver.Sizing
	sessionCfg          session.Config
	assign              tun.Assignment
	maxSessions         int
	demux               string
	// acceptTransit relaxes the "is this addressed to me" check for every
	// session this server builds. Required by forward (see its flag's help);
	// otherwise still lab responder only.
	acceptTransit bool
	// uplinkResequence records -uplink-resequence for every peer session
	// startPeerSession builds (item 5, arm R1; default off).
	uplinkResequence bool
	// inboxDepth is the resolved -uplink-inbox-depth every peer session's
	// pipe is built with; read it through pipeInboxDepth.
	inboxDepth int

	// forward, table and sharedDev are set only when -forward is on. table is
	// the address -> session index every session's device writes into and
	// sharedDev's return-path pump reads out of; sharedDev is the one real
	// kernel TUN descriptor every session shares. See forward.go.
	forward        bool
	table          *forwardTable
	sharedDev      *sharedGatewayTun
	peerRegistry   *peerRegistry
	statusJSON     string
	proofProcessID int
	proofNonce     string
	proofBootID    string
	proofTicks     uint64
	proofStarted   string
	proofMonoStart time.Time
	proofListen    string
	proofSequence  atomic.Uint64

	// resolver is non-nil only when -resolver is on. One instance serves every
	// session, which is what makes its in-flight ceiling process-wide. See
	// resolve.go.
	resolver *gatewayResolver

	mu       sync.Mutex
	peers    map[netip.AddrPort]*peerSession
	tcpPeers map[*peerSession]struct{}
	building int
	// These hooks let a test hold release before table insertion. They are nil
	// for serving processes.
	afterTCPStart  func(*peerSession, error)
	holdTCPRelease func()

	// journalIdent is the live file the process bound after a successful
	// journal open. Readiness and new-handshake admission compare the
	// pathname against this identity so a rename, symlink, or create-over
	// race cannot keep ready=true while appends land on an unlinked inode.
	journalIdentMu     sync.Mutex
	journalIdent       os.FileInfo
	journalIdentPath   string
	journalIdentBroken atomic.Bool
	// journalMonitor is nil in production, where sessionCfg.Responder is the
	// monitor. The interface keeps readiness coupled to the active writer's
	// descriptor generation, including a legitimate compaction replacement,
	// instead of caching an inode outside replaystore.
	journalMonitor replayJournalMonitor

	admitted  atomic.Uint64
	datagrams atomic.Uint64

	// built counts session CONSTRUCTIONS, which is not the same number as
	// admitted and is the one that exposes churn. A demultiplexer that fails to
	// reuse a peer's session builds a fresh one for every datagram, completes a
	// handshake for each, and still shows a correct session census — so the
	// census cannot detect it and this counter can.
	built atomic.Uint64

	// admission is the read loop's screen work budget (admission_meter.go).
	// It is nil on servers assembled by tests, which keep the unmetered
	// behaviour; runServe always installs one.
	admission *admissionMeter

	// throttledCounts counts initiation-sized datagrams from an unknown
	// address that the admission meter refused before the screen ran.
	throttledCounts atomic.Uint64

	// strangers counts datagrams from an unknown address that could not have
	// been an initiation, and so never bought any state.
	strangers atomic.Uint64

	// replays counts initiation-sized datagrams from an unknown address that
	// the process-wide responder had already answered, and so never bought any
	// state either. See readLoop and serveStatus.Replays.
	replays atomic.Uint64

	// egressGuard, when set (runServe sets it), refuses a client whose
	// replies the kernel routes through a device narrower than the plan's
	// widest datagram. egressRefused counts those refusals, and
	// egressRefusedLogs bounds their log lines. See egress_mtu.go, PER CLIENT.
	egressGuard       *clientEgressGuard
	egressRefused     atomic.Uint64
	egressRefusedLogs atomic.Uint64
	// egressClosed counts established sessions closed because their replies'
	// route narrowed (egress_session_watch.go); egressClosedLogs bounds the
	// log lines.
	egressClosed     atomic.Uint64
	egressClosedLogs atomic.Uint64
	// egressUnaccountable is set while the host has a policy rule or route
	// that selects on mark or TOS (Round CM3 Turn 4): every session is closed
	// and every new client refused. egressSweepMaxUS is the longest egress
	// sweep seen, in microseconds.
	egressUnaccountable atomic.Bool
	egressSweepMaxUS    atomic.Uint64

	// refusedLogs bounds the diagnostic below. An unbounded log line on a
	// datagram path is a disk-fill an unauthenticated peer can drive.
	refusedLogs atomic.Uint64

	// buildFailures counts datagrams that reached a peer's session and found
	// none could be built. It is published because zero is the only value an
	// operator should ever see, and because before it existed this number was
	// the difference between "no clients are reaching me" and "every client is
	// reaching me and I am refusing them all in silence" — two postures that
	// looked identical in the status document.
	buildFailures    atomic.Uint64
	buildFailureLogs atomic.Uint64

	// reclaimed and superseded count slots taken back from dead and from
	// superseded sessions. See session_reclaim.go.
	reclaimed   atomic.Uint64
	superseded  atomic.Uint64
	reclaimLogs atomic.Uint64

	// retiring holds sessions removed from peers by a reclaim but not yet torn
	// down by their Run goroutine. It is bounded by retirementAllowance and
	// guarded by s.mu. See session_reclaim.go.
	retiring map[*peerSession]struct{}

	// keySessions is the live session count per client static key, read by
	// the accept-time per-key cap (keyMayOpenSession) and rebuilt by the serve
	// ticker (enforcePerKeyCap). keyMu guards it and is never held while s.mu
	// or a driver lock is taken. See session_reclaim.go, per-key cap.
	keyMu       sync.Mutex
	keySessions map[[32]byte]int

	// releaseGate is a test-only seam. When non-nil, releasePeer blocks on it
	// after removing the session from the table and before closing its
	// resources, so a test can hold a real teardown mid-flight. Nil in
	// production.
	releaseGate chan struct{}
}

// maxRefusalLogs is how many refusals are described before the counter alone
// carries the story.
const maxRefusalLogs = 20

// couldBeInitiation reports whether a datagram from an unknown peer is the
// right SIZE to be a handshake initiation. It says nothing about authenticity,
// which only core can decide.
func couldBeInitiation(n int) bool {
	return n > 0 && n <= core.MaxHandshakeMessage
}

// known reports whether an address already owns a session, without building one.
func (s *server) known(from netip.AddrPort) bool {
	s.mu.Lock()
	_, ok := s.peers[from]
	s.mu.Unlock()
	return ok
}

// screenInitiation asks the process-wide responder whether this datagram
// passes the admission tag at all and, if so, whether it is one it has already
// answered, without allocating anything and without consuming the replay slot.
// See the call site in readLoop and core.Responder.ScreenInitiation.
//
// A nil Responder means this server was assembled without going through
// buildSessionConfig, which no production path does — runServe builds the
// config there and preflightSession refuses to start a gateway whose config
// lacks one. It is answered "not a replay", i.e. exactly the behaviour this
// binary had before the screen existed, so an unusual harness degrades to the
// old path rather than to a gateway that answers nobody. That is not a hole in
// the replay defence: with no shared Responder there is no shared cache to
// screen against, and the defence that matters — silence — lives in
// ReadInitiation either way. It is answered "admissible, not a replay".
func (s *server) screenInitiation(msg []byte) (admissible, replayed bool) {
	resp := s.sessionCfg.Responder
	if resp == nil {
		return true, false
	}
	return resp.ScreenInitiation(msg)
}

// --- F-02 replay journal health ---------------------------------------------
//
// The persisted journal (core.Config.ReplayJournal, wired from
// WINN3_REPLAY_JOURNAL) makes the handshake replay window survive a restart,
// and durable recording is part of admitting a new handshake. Production
// serve refuses WINN3_GATEWAY_REPLAY_JOURNAL=0 and any absent or unusable
// pathname before listen. After start, readiness is bound to the live
// writable journal identity: a rename, symlink, or path race is sticky and
// refuses new handshakes while established sessions keep carrying. Any
// append, rewrite, or sync failure is the same: core returns ErrReplayJournal
// for that initiation and every later new initiation. The status document
// becomes ready=false and this periodic line reports "admission-blocked"
// once. A journal that cannot be loaded refuses startup and reports
// "load-refused". A lab run without a journal emits no health line and
// reports "disabled".
const (
	replayJournalStatusDisabled         = "disabled"
	replayJournalStatusOK               = "ok"
	replayJournalStatusAdmissionBlocked = "admission-blocked"
	replayJournalStatusLoadRefused      = "load-refused"

	replayJournalDisableRefused    = "WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused: durable replay is a non-bypassable production invariant"
	replayJournalPathRequired      = "WINN3_REPLAY_JOURNAL is absent or unusable; durable replay is a non-bypassable production invariant"
	replayJournalWhitespaceRefused = "WINN3_REPLAY_JOURNAL carries whitespace at its edges"
	replayJournalWALSuffix         = ".wal"
)

var errReplayJournalIdentity = errors.New("replay journal pathname identity changed; new handshakes are refused")

// replayJournalLog deduplicates the periodic journal-health report: one line
// per state change, never a line per tick. It is deliberately a pure
// last-value tracker so the state-change rule is testable without a socket,
// a ticker, or a broken filesystem.
type replayJournalLog struct {
	last string
}

// report returns the operator line for a state change, or "" when the state
// has not changed since the last report.
func (l *replayJournalLog) report(status string) string {
	if status == l.last {
		return ""
	}
	l.last = status
	return fmt.Sprintf("winn3-gateway: replay-journal status=%s", status)
}

// replayJournalReadiness reports new-handshake admission readiness, not
// process liveness. A sticky journal error or a pathname identity failure
// blocks new handshakes but does not tear down established sessions. An
// explicit WINN3_GATEWAY_REPLAY_JOURNAL=0 is load-refused. A lab run with
// no journal path is visible as disabled.
func (s *server) replayJournalReadiness() (bool, string) {
	if os.Getenv("WINN3_GATEWAY_REPLAY_JOURNAL") == "0" {
		return false, replayJournalStatusLoadRefused
	}
	path := s.sessionCfg.Core.ReplayJournal
	if path == "" {
		return true, replayJournalStatusDisabled
	}
	monitor := s.activeReplayJournalMonitor()
	if monitor == nil {
		return false, replayJournalStatusLoadRefused
	}
	if monitor.ReplayJournalError() != nil {
		return false, replayJournalStatusAdmissionBlocked
	}
	if err := s.verifyLiveReplayJournal(path); err != nil {
		return false, replayJournalStatusAdmissionBlocked
	}
	return true, replayJournalStatusOK
}

// admitsNewHandshakes is the UDP and TCP new-handshake gate. It must remain an
// in-memory check: unauthenticated initiation-sized traffic must not trigger Lstat,
// open, or fsync work on the single receive loop. The periodic readiness path
// monitors the pathname, while an authenticated replaystore append performs
// the transaction-time identity checks and publishes a sticky writer error.
// Established sessions are admitted by known() before this is consulted.
func (s *server) admitsNewHandshakes() bool {
	if os.Getenv("WINN3_GATEWAY_REPLAY_JOURNAL") == "0" {
		return false
	}
	if s.sessionCfg.Core.ReplayJournal == "" {
		return true
	}
	monitor := s.activeReplayJournalMonitor()
	if monitor == nil || s.journalIdentBroken.Load() {
		return false
	}
	return monitor.ReplayJournalError() == nil
}

func (s *server) activeReplayJournalMonitor() replayJournalMonitor {
	if s.journalMonitor != nil {
		return s.journalMonitor
	}
	if s.sessionCfg.Responder == nil {
		return nil
	}
	return s.sessionCfg.Responder
}

// requireReplayJournalEnv is the production start gate. It must run before
// buildSessionConfig so a missing pathname cannot be created as an empty
// journal (that empty file is the restart replay-protection bypass).
func requireReplayJournalEnv() error {
	_, err := requireReplayJournalPath()
	return err
}

// requireReplayJournalPath is the single production parse+inspect. It returns
// the exact validated pathname that every later layer must use: inspect, the
// serveOptions field, and core.Config.ReplayJournal. Edge whitespace is
// refused, not trimmed: TrimSpace(raw) and raw are distinct journal files,
// and they name distinct WAL directories (path+".wal").
func requireReplayJournalPath() (string, error) {
	switch flag := os.Getenv("WINN3_GATEWAY_REPLAY_JOURNAL"); flag {
	case "0":
		return "", errors.New(replayJournalDisableRefused)
	case "", "1":
	default:
		return "", fmt.Errorf("WINN3_GATEWAY_REPLAY_JOURNAL=%q must be 1 or unset; 0 is refused", flag)
	}
	path, err := parseReplayJournalPath(os.Getenv("WINN3_REPLAY_JOURNAL"))
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", errors.New(replayJournalPathRequired)
	}
	if _, err := inspectLiveReplayJournal(path); err != nil {
		return "", err
	}
	return path, nil
}

// parseReplayJournalPath is the only WINN3_REPLAY_JOURNAL parser. raw is the
// environment value or the already-validated pathname passed through serve
// options. Any value that differs from TrimSpace(raw) is refused: preflight
// used to trim, then runtime used the raw bytes, which created a second
// journal and a second WAL directory beside the file inspect had vouched for.
// Empty raw is unset (lab tests may omit a journal). The returned string is
// byte-identical to a successful raw input.
func parseReplayJournalPath(raw string) (string, error) {
	if raw != strings.TrimSpace(raw) {
		return "", replayJournalWhitespaceError(raw)
	}
	if raw == "" {
		return "", nil
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf(
			"WINN3_REPLAY_JOURNAL %q is not an absolute path; a relative journal would be "+
				"created relative to this process's working directory, so the gateway refuses it", raw)
	}
	return raw, nil
}

func replayJournalWhitespaceError(raw string) error {
	trimmed := strings.TrimSpace(raw)
	return fmt.Errorf(
		"%s: %s. Trimmed %q and raw %q are distinct journal pathnames, and %q and %q "+
			"are distinct WAL directories; the gateway refuses rather than inspecting one "+
			"and persisting another",
		replayJournalWhitespaceRefused,
		edgeWhitespaceReport(raw),
		trimmed, raw,
		trimmed+replayJournalWALSuffix, raw+replayJournalWALSuffix)
}

// inspectLiveReplayJournal vouches for one pathname: exact (no edge
// whitespace), absolute, present, regular, not a symlink, and openable for
// append. Lstat and the opened fd are bound together so a swap between the
// check and the open is refused. The path is used as supplied; this function
// never trims.
func inspectLiveReplayJournal(path string) (os.FileInfo, error) {
	exact, err := parseReplayJournalPath(path)
	if err != nil {
		return nil, err
	}
	if exact == "" {
		return nil, errors.New(replayJournalPathRequired)
	}
	path = exact
	li, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", replayJournalPathRequired, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("replay journal %s is a symbolic link; refusing rather than following a raced path", path)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("replay journal %s is not a regular file (mode %v)", path, li.Mode())
	}
	if li.Mode().Perm()&0o200 == 0 {
		return nil, fmt.Errorf("replay journal %s is not writable; refusing rather than starting without durable replay", path)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return nil, fmt.Errorf("replay journal %s is not a live writable journal: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("replay journal %s: stat after open: %w", path, err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(fi, after) || !os.SameFile(fi, li) {
		return nil, fmt.Errorf("replay journal %s was replaced while it was being opened; refusing rather than trusting a raced path", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("replay journal %s is not a regular file after open", path)
	}
	return fi, nil
}

func (s *server) verifyLiveReplayJournal(path string) error {
	if s.journalIdentBroken.Load() {
		return errReplayJournalIdentity
	}
	if monitor := s.activeReplayJournalMonitor(); monitor != nil && s.sessionCfg.Core.ReplayJournal == path {
		if err := monitor.VerifyReplayJournalPath(); err != nil {
			s.journalIdentBroken.Store(true)
			return err
		}
		return nil
	}
	info, err := inspectLiveReplayJournal(path)
	if err != nil {
		s.journalIdentBroken.Store(true)
		return err
	}
	s.journalIdentMu.Lock()
	defer s.journalIdentMu.Unlock()
	if s.journalIdent == nil {
		s.journalIdent = info
		s.journalIdentPath = path
		return nil
	}
	if s.journalIdentPath != path || !os.SameFile(s.journalIdent, info) {
		s.journalIdentBroken.Store(true)
		return errReplayJournalIdentity
	}
	return nil
}

// journalHealthLine is the one place the serve() tick consults for the
// journal line. It returns "" when a journal is deliberately disabled, so a
// journal-free run never falsely claims one, and lets the tracker deduplicate
// per state change. Extracted from serve() so the gating itself is testable
// without a socket or a ticker.
func (s *server) journalHealthLine(l *replayJournalLog) string {
	_, status := s.replayJournalReadiness()
	if status == replayJournalStatusDisabled {
		return ""
	}
	return l.report(status)
}

// peerSession is one client's responder loop and the pipe feeding it.
//
// dev is closableDevice rather than the concrete *reflector it always was
// before -forward existed: it is now either a *reflector (the default) or a
// *gatewayForwardDevice (server.forward), and everything here — the field's
// use in close(), status()'s type-switch for reflector-only counters — reads
// on either without caring which.
type peerSession struct {
	pipe *carrier.Pipe
	conn carrier.Conn
	loop *driver.Loop
	dev  closableDevice
	stop context.CancelFunc
	done chan struct{}
	// tcpReleased is guarded by server.mu so a loop that exits during
	// construction cannot be inserted into the TCP session table afterward.
	tcpReleased bool

	addrMu sync.RWMutex
	remote netip.AddrPort

	// admittedAt is when this session took its slot. The per-key cap retires
	// a key's surplus oldest admission first (session_reclaim.go).
	admittedAt time.Time

	// revoke is closeRevokedSessions' per-session state. See
	// revoked_sessions.go. Only the serve ticker goroutine touches it.
	revoke revokeState

	// egressClose is the egress watch's per-session teardown state. See
	// egress_session_watch.go. Only the egress watch goroutine touches it.
	egressClose egressCloseState

	// releaseOnce serializes releasePeer across its concurrent callers (the Run
	// goroutine on normal exit and Round M's forced release): exactly one runs
	// the teardown body to completion while the others block until it returns.
	// See releasePeer for the completion-ownership contract.
	releaseOnce sync.Once
}

func (ps *peerSession) carrier() carrier.Conn {
	if ps.conn != nil {
		return ps.conn
	}
	return ps.pipe
}

func (ps *peerSession) remoteAddrPort() netip.AddrPort {
	ps.addrMu.RLock()
	defer ps.addrMu.RUnlock()
	return ps.remote
}

func (ps *peerSession) setRemoteAddrPort(addr netip.AddrPort) {
	ps.addrMu.Lock()
	defer ps.addrMu.Unlock()
	ps.remote = addr
}

// serve reads the socket until the context ends.
//
// The read loop is the ONLY reader of the socket, and it never blocks on a
// session: Pipe.Deliver is non-blocking by construction and drops on a full
// inbox, which is the property carrier/pipe.go documents and the reason a slow
// session cannot stall every other session on this socket.
func (s *server) serve(ctx context.Context, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	proofLease, err := acquireProofStatusLease(s.statusJSON)
	if err != nil {
		return fmt.Errorf("acquire proof status lease: %w", err)
	}
	defer proofLease.Close()

	if err := invalidateProofStatusFile(s.statusJSON, s.proofNonce, true); err != nil {
		return fmt.Errorf("invalidate stale proof status: %w", err)
	}
	readErr := make(chan error, 1)
	readReady := make(chan error, 1)
	go func() { readErr <- s.readLoopEntered(ctx, readReady) }()
	if err := <-readReady; err != nil {
		cancel()
		_ = s.conn.SetReadDeadline(time.Now())
		<-readErr
		return fmt.Errorf("gateway read loop failed before readiness publication: %w", err)
	}
	if s.tcp != nil {
		s.tcp.setAdmissionGate(s.admitsNewHandshakes)
		go s.tcpLoop(ctx)
	}
	if s.proofListen != "" {
		listening := s.status()
		listening.Event = "listening"
		listening.Listen = s.proofListen
		if err := writeServeStatus(out, s.statusJSON, listening); err != nil {
			cancel()
			_ = s.conn.SetReadDeadline(time.Now())
			<-readErr
			_ = invalidateProofStatusFile(s.statusJSON, s.proofNonce, false)
			return err
		}
	}

	// Round CM3 Turn 3: established sessions' egress, rechecked on route
	// changes (egress_session_watch.go). It stops when serve returns; a sweep
	// that races closeAll only requests another Close, and Loop.Close and
	// releasePeer are both once-only.
	stopEgressWatch := s.startEgressWatch(ctx)
	defer stopEgressWatch()

	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	// F-02: the replay journal health is folded into this periodic path, not
	// given its own goroutine. One line per state change, to stderr (the
	// journal, operator-visible), and nothing at all when no journal is
	// configured -- see replayJournalLog above.
	var journalLog replayJournalLog
	for {
		select {
		case <-ctx.Done():
			// Unblock the parked ReadFromUDPAddrPort; the deferred Close in
			// runServe is what the read loop actually observes.
			_ = s.conn.SetReadDeadline(time.Now())
			<-readErr
			s.closeAll()
			final := s.status()
			final.Event = "stopped"
			final.Ready = false
			if err := writeServeStatus(out, s.statusJSON, final); err != nil {
				_ = invalidateProofStatusFile(s.statusJSON, s.proofNonce, false)
				return err
			}
			return nil
		case err := <-readErr:
			s.closeAll()
			final := s.status()
			final.Event = "stopped"
			final.Ready = false
			if err != nil {
				final.Refusal = err.Error()
			}
			if statusErr := writeServeStatus(out, s.statusJSON, final); statusErr != nil {
				_ = invalidateProofStatusFile(s.statusJSON, s.proofNonce, false)
				if err == nil {
					return statusErr
				}
				return fmt.Errorf("%v; status publication: %w", err, statusErr)
			}
			return err
		case <-ticker.C:
			s.closeRevokedSessions(time.Now())
			s.reclaimSupersededSessions()
			s.enforcePerKeyCap()
			if line := s.journalHealthLine(&journalLog); line != "" {
				fmt.Fprintln(os.Stderr, line)
			}
			if err := writeServeStatus(out, s.statusJSON, s.status()); err != nil {
				cancel()
				_ = s.conn.SetReadDeadline(time.Now())
				<-readErr
				_ = invalidateProofStatusFile(s.statusJSON, s.proofNonce, false)
				return err
			}
		}
	}
}

func (s *server) readLoop(ctx context.Context) error {
	return s.readLoopEntered(ctx, nil)
}

func (s *server) readLoopEntered(ctx context.Context, ready chan<- error) error {
	buf := make([]byte, readBuffer)
	probing := ready != nil
	if probing {
		if err := s.conn.SetReadDeadline(time.Now().Add(readinessProbeTimeout)); err != nil {
			ready <- err
			return err
		}
	}
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if probing {
			if err != nil && errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() == nil {
				if clearErr := s.conn.SetReadDeadline(time.Time{}); clearErr != nil {
					ready <- clearErr
					return clearErr
				}
				ready <- nil
				probing = false
				continue
			}
			if err != nil {
				ready <- err
				return err
			}
			if clearErr := s.conn.SetReadDeadline(time.Time{}); clearErr != nil {
				ready <- clearErr
				return clearErr
			}
			ready <- nil
			probing = false
		}
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) ||
				errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		s.datagrams.Add(1)

		known := s.known(from)
		if !known && s.demux == "token" && n >= core.TransportOverhead() {
			if ps := s.findSessionForDatagram(buf[:n]); ps != nil {
				if !s.clientEgressFits(from) {
					// The new address's replies would leave fragmented
					// (Round CM3). Keep the old binding; drop this datagram.
					continue
				}
				s.rebindPeer(ps, from)
				s.deliverSessionDatagram(ps, from, buf[:n])
				continue
			}
		}
		if !known && !couldBeInitiation(n) {
			// LENGTH FIRST, before any state is allocated for a stranger.
			//
			// This is winn3/gateway.Handle's ordering and it is here for its
			// reason: a comparison removes every datagram that could not be an
			// initiation whatever its contents, before anything is spent. It
			// matters more here than there, because address demultiplexing
			// makes the FIRST datagram from an address allocate a session, a
			// pipe, a device and two goroutines. Without this check a stranger
			// buys all of that with one junk byte.
			//
			// It is a partial mitigation and not the fix. See the package doc:
			// the fix is winn3/gateway's token index, under which an
			// unauthenticated datagram allocates nothing at all.
			s.strangers.Add(1)
			continue
		}
		if !known && !s.admitsNewHandshakes() {
			// Durable-replay admission is closed: explicit disable, a
			// missing or unusable journal, a pathname identity race, or a
			// sticky append failure. Established sessions stay on the
			// known() path above. SILENCE toward the peer.
			continue
		}
		if !known && !s.admission.allow(from, time.Now()) {
			// WORK BUDGET, still before any state is allocated and before
			// the screen spends anything. The screen below is the one
			// expensive thing an unauthenticated datagram can make this
			// single reader do (a whitening expansion plus one HMAC per
			// candidate bucket per admission key, no early exit), and it
			// runs on the same goroutine that delivers every established
			// session's traffic. Metering it here, as winn3/gateway.Handle
			// meters its own admission path, bounds what a flood can buy
			// and leaves established sessions, which take the known()
			// path above, untouched. Counted, never logged per datagram,
			// and SILENCE toward the peer: the peer sees exactly what it
			// sees for a failed screen.
			s.throttledCounts.Add(1)
			continue
		}
		admissible, replayed := true, false
		if !known {
			admissible, replayed = s.screenInitiation(buf[:n])
		}
		if !known && !admissible {
			// ADMISSION SCREEN, still before any state is allocated.
			//
			// A datagram that fails the admission tag can never become a
			// session: ReadInitiation refuses it before anything else. Before
			// this screen it still bought a session, a pipe, a device and two
			// goroutines, and held one -max-sessions slot for the whole
			// handshake budget (23.5 s) before being dropped, so one byte per
			// source port from anyone filled the ceiling and the gateway then
			// refused its real clients in silence. It is also what lets
			// sessionFor reclaim a dead session's slot: every datagram that
			// reaches sessionFor from here on has proved an admission key.
			// Silence toward the peer either way.
			s.strangers.Add(1)
			continue
		}
		if !known && replayed {
			// REPLAY, still before any state is allocated.
			//
			// The length check above only asks whether the datagram COULD be an
			// initiation. This asks the one further question that address
			// demultiplexing gets wrong on its own: have these exact bytes
			// already been answered, from anywhere? It is answered against the
			// ONE process-wide core.Responder buildSessionConfig installed, so
			// the answer does not depend on which address the datagram arrived
			// from — which is the whole point.
			//
			// This is NOT what makes the gateway silent to a replay. The shared
			// Responder is: its replay cache makes the driver's ReadInitiation
			// return ErrReplay, and every ReadInitiation failure is answered
			// with silence. What this closes is the RESOURCE half. Without it a
			// replay from a new address still bought a session, a pipe, a device
			// and two goroutines before being rejected, so a censor holding one
			// captured initiation could fill the session ceiling from arbitrary
			// addresses and make the gateway refuse its real clients — silently,
			// which under this threat model is indistinguishable from a censor.
			//
			// Only a message that passes admission AND is already in the replay
			// cache is stopped here. Unauthenticated noise was stopped by the
			// admission screen just above, from the same verifyAdmission call.
			// See core.Responder.ScreenInitiation and IsReplayedInitiation.
			//
			// A hit here is SILENT. Answering it with anything, including an
			// error, would be the probe oracle this entire path exists to close.
			s.replays.Add(1)
			continue
		}
		if !known && !s.clientEgressFits(from) {
			// PER-CLIENT EGRESS (Round CM3), still before any state is
			// allocated and only for a datagram that proved an admission key.
			// Silence toward the peer; counted and logged for the operator.
			continue
		}

		ps, err := s.sessionFor(ctx, from)
		if err != nil {
			// No room, or a session that could not be built. SILENCE TOWARD THE
			// PEER: it gets nothing, exactly as winn3/gateway's refusal paths
			// do. An error datagram here would be a gateway detector.
			//
			// Silence toward the peer is NOT silence toward the operator, and
			// conflating the two is what made this the eighth silent-refusal
			// defect in this protocol. This `continue` used to discard err
			// outright, so a -router-v4 that equalled -inner-v4 produced a
			// gateway that answered nobody and said nothing, on either end,
			// forever. preflightSession now refuses that configuration at
			// startup; the counter and the bounded log below are what remain
			// for anything that can only fail once traffic is flowing — the
			// session ceiling being the live example.
			//
			// A counter, not a log line per datagram: the ceiling is reachable
			// by an unauthenticated peer, so an unbounded log here is a
			// disk-fill it could drive. Same bound as the refusal log above.
			s.buildFailures.Add(1)
			if c := s.buildFailureLogs.Add(1); c <= maxRefusalLogs {
				// The peer address is redacted before it reaches durable
				// storage: a circumvention gateway must not keep a journal of
				// who reached it, and this line is reachable by an
				// unauthenticated peer.
				fmt.Fprint(os.Stderr, observability.RedactAddresses(fmt.Sprintf(
					"winn3-gateway: no session for %s: %v\n", from, err)))
				if c == maxRefusalLogs {
					fmt.Fprintf(os.Stderr,
						"winn3-gateway: further session-build failures will not be logged; "+
							"see session_build_failures\n")
				}
			}
			continue
		}
		// A Deliver error is a full inbox or an oversize message. Both are
		// counted inside the Pipe and neither is answered.
		//
		// It IS logged, rate-limited, to stderr and never to the peer. This is
		// the diagnostic that identifies the one misconfiguration this design
		// cannot detect any other way: two ends that computed different plan
		// floors because they were given different path MTUs. Nothing
		// negotiates that number, and without this line the symptom is a client
		// that hangs in handshaking against a gateway that looks healthy.
		s.deliverSessionDatagram(ps, from, buf[:n])
	}
}

// clientEgressFits runs the per-client egress check (egress_mtu.go, PER
// CLIENT) and counts and logs a refusal. The log never names the address.
func (s *server) clientEgressFits(from netip.AddrPort) bool {
	if s.egressGuard == nil {
		return true
	}
	if s.egressUnaccountable.Load() {
		s.egressRefused.Add(1)
		if c := s.egressRefusedLogs.Add(1); c <= maxRefusalLogs {
			fmt.Fprintf(egressLog, "winn3-gateway: refused a client: policy routing selects on mark or TOS, so "+
				"its replies' route cannot be accounted for (Round CM3); see egress_routing_unaccountable\n")
		}
		return false
	}
	r, ok := s.egressGuard.check(from)
	if ok {
		return true
	}
	s.egressRefused.Add(1)
	if c := s.egressRefusedLogs.Add(1); c <= maxRefusalLogs {
		if r.Err != nil {
			// The kernel refused to describe the reply flow, or did not answer
			// completely: fail closed. The error names no address
			// (errFlowNotDescribable, errNetlinkIncomplete or an errno).
			fmt.Fprintf(egressLog, "winn3-gateway: refused a client: the kernel refused or did not completely answer "+
				"the route lookup for its reply flow (%v), so the egress MTU cannot be checked (Round CM3); "+
				"see egress_mtu_refused\n", r.Err)
		} else {
			fmt.Fprintf(egressLog, "winn3-gateway: refused a client whose replies the kernel routes through %s "+
				"(mtu %d, route mtu %d, table %d): the plan's %d-byte IPv4 datagrams would leave fragmented "+
				"(Round CM3); see egress_mtu_refused\n",
				r.Device, r.MTU, r.RouteMTU, r.Table, s.egressGuard.datagram)
		}
		if c == maxRefusalLogs {
			fmt.Fprintf(egressLog, "winn3-gateway: further egress refusals will not be logged; see egress_mtu_refused\n")
		}
	}
	return false
}

// deliverSessionDatagram injects an arriving datagram into a session's pipe.
// Drops from queue saturation are counted by the Pipe and do not increment refusedLogs.
func (s *server) deliverSessionDatagram(ps *peerSession, from netip.AddrPort, buf []byte) {
	if derr := ps.pipe.Deliver(buf); derr != nil {
		if !errors.Is(derr, carrier.ErrQueueFull) {
			if c := s.refusedLogs.Add(1); c <= maxRefusalLogs {
				fmt.Fprint(os.Stderr, observability.RedactAddresses(fmt.Sprintf(
					"winn3-gateway: refused %d bytes from %s: %v (this end's plan floor is %d; "+
						"a peer built at a different path MTU computes a different floor)\n",
					len(buf), from, derr, s.sizing.MessageSize)))
				if c == maxRefusalLogs {
					fmt.Fprintf(os.Stderr,
						"winn3-gateway: further refusals will not be logged; see refused_datagrams\n")
				}
			}
		}
	}
}

// sessionFor returns the session for a peer, building one on first sight.
func (s *server) sessionFor(ctx context.Context, from netip.AddrPort) (*peerSession, error) {
	s.mu.Lock()
	if ps, ok := s.peers[from]; ok {
		s.mu.Unlock()
		return ps, nil
	}
	full := len(s.peers)+len(s.tcpPeers)+s.building >= s.maxSessions
	s.mu.Unlock()
	if full && !s.reclaimSlot(time.Now()) {
		// Refuse. A live session is never evicted to make room; only one
		// that reclaimSlot can show is dead or failed gives up its slot (see
		// session_reclaim.go). Waiting for releasePeer alone left a full map
		// full of corpses for the whole liveness budget: a client that exits
		// without CLOSE kept its slot for 50 to 80 s.
		return nil, errors.New("session ceiling reached")
	}
	s.mu.Lock()
	if len(s.peers)+len(s.tcpPeers)+s.building >= s.maxSessions {
		s.mu.Unlock()
		return nil, errors.New("session ceiling reached")
	}
	s.building++
	s.mu.Unlock()

	ps, err := s.newSession(ctx, from)
	s.mu.Lock()
	s.building--
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	if existing, ok := s.peers[from]; ok {
		// Lost a race with another datagram from the same peer.
		s.mu.Unlock()
		ps.close()
		return existing, nil
	}
	ps.admittedAt = time.Now()
	s.peers[from] = ps
	s.mu.Unlock()
	s.admitted.Add(1)
	fmt.Fprintf(os.Stderr, "winn3-gateway: new session admitted (#%d)\n", s.admitted.Load())
	return ps, nil
}

func (s *server) newSession(ctx context.Context, from netip.AddrPort) (*peerSession, error) {
	// FAIL CLOSED on a missing shared responder, at the exact point the defect
	// would otherwise be reinstated.
	//
	// This is the line that makes the cross-address replay property a class
	// invariant rather than one fixed instance. Everything below builds a
	// per-peer driver.Loop, and driver.NewGateway falls back to constructing
	// its OWN core.Responder when the config carries none — which is precisely
	// the partitioned-replay-cache defect
	// TestACapturedInitiationReplayedFromASecondAddressIsSilent exists to
	// catch. A future edit that reached here with an unshared config would not
	// fail any obvious way: the gateway would serve every legitimate client
	// perfectly and merely become findable by anyone holding one captured
	// initiation. So it is refused here, loudly, instead.
	//
	// The refusal is SILENT TOWARD THE PEER — sessionFor's caller counts it in
	// session_build_failures and logs it to stderr under the existing bound —
	// because an error datagram would itself be a gateway detector. See the
	// build-failure branch in readLoop.
	if s.sessionCfg.Responder == nil {
		return nil, errors.New(
			"refusing to build a session from a config with no shared handshake responder: " +
				"each peer address would get its own empty replay cache, and a captured " +
				"initiation replayed from a second address would be answered — a remote " +
				"gateway detector. Configs must come from buildSessionConfig")
	}
	ps := &peerSession{remote: from, done: make(chan struct{})}
	pipe, err := carrier.NewPipe(carrier.PipeConfig{
		Class: carrier.ClassUDP,
		Out: func(msg []byte) error {
			dest := ps.remoteAddrPort()
			_, werr := s.conn.WriteToUDPAddrPort(msg, dest)
			return werr
		},
		OutBatch: func(msgs []carrier.BatchMsg) (int, error) {
			dest := ps.remoteAddrPort()
			if bw, ok := s.conn.(batchWriter); ok {
				return bw.WriteBatchTo(msgs, dest)
			}
			for i := range msgs {
				payload := msgs[i].Payload[:msgs[i].N]
				if _, err := s.conn.WriteToUDPAddrPort(payload, dest); err != nil {
					return i, err
				}
			}
			return len(msgs), nil
		},
		MaxMessageSize: s.sizing.MessageSize,
		PathMTU:        s.sizing.PathMTU,

		// The inbox and the token window are separate budgets.
		//
		// The inbox bounds how long a stall of this session's goroutine is
		// absorbed before readLoop drops; the token window (gatewayTokenWindow)
		// bounds how long a run of drops is survived. Ruling D23 derived the
		// inbox from the window's reorder tolerance, first at
		// core.DefaultTokenWindow/2 = 512 (one slot above the 511-message
		// tolerance the gateway then ran at), and since 2026-10-10 at
		// gatewayTokenWindow/4 = 8192, after Canada measured the 512 inbox as
		// the uplink's loss point: a 32-stream TCP ramp offered 38 to 40k
		// datagrams/s for up to two seconds against a serialized consumer
		// near 30k/s, and 512 slots absorb 13 to 17 ms of that deficit. The
		// inbox is now one quarter of the window this binary configures
		// rather than half of the default one, still a derivation, never a
		// literal: it must track the window if the window ever moves again.
		// The session's own tolerance (gatewayTokenWindow/2 - 1 = 16,383)
		// remains wider than the inbox, so a burst the inbox cannot hold is
		// still dropped here and survived by the window.
		//
		// History, kept because the defect it records is the reason this field
		// is set at all: left at carrier.DefaultPipeDepth (256) this pipe was
		// narrower than the then-511-message tolerance, and a burst displacing
		// 257-511 packets was dropped as ErrQueueFull in readLoop BEFORE
		// session.Driver.Deliver, never reaching Session.Open. That is silent
		// inner loss on a tunnel whose Loop.Stats.Unopenable never moves.
		//
		// TestTheProductionInboxHoldsTheReorderTolerance pins the D23 value,
		// and pinNewSessionPipeDerivesDepthFromTheTokenWindow pins that the
		// replica of this literal still matches it. Since 2026-10-10 the
		// depth is -uplink-inbox-depth, one of uplinkInboxDepths, each a
		// derivation of the same window (owner ruling: fastest speed at lower
		// RAM).
		Depth: s.pipeInboxDepth(),
	})
	if err != nil {
		return nil, err
	}
	ps.pipe = pipe
	return s.startPeerSession(ctx, ps, pipe, nil)
}

// pipeInboxDepth is the inbox depth newSession builds every peer pipe with:
// the resolved -uplink-inbox-depth, or defaultUplinkInboxDepth on a server
// built without it.
func (s *server) pipeInboxDepth() int {
	if s.inboxDepth != 0 {
		return s.inboxDepth
	}
	return defaultUplinkInboxDepth
}

func (s *server) startPeerSession(ctx context.Context, ps *peerSession,
	conn carrier.Conn, authenticated *session.Driver) (*peerSession, error) {
	from := ps.remoteAddrPort()

	// The device backend, chosen once per server rather than per session: a
	// *reflector (the unmodified default, in-process, carries nothing) or a
	// *gatewayForwardDevice sharing s.sharedDev's real kernel interface
	// (server.forward). forwardDev is kept alongside dev, typed concretely,
	// purely so it can be bound to the *driver.Loop below once that exists —
	// see gatewayForwardDevice.bind's doc for why binding is a second step.
	var dev closableDevice
	var forwardDev *gatewayForwardDevice
	if s.forward {
		forwardDev = newGatewayForwardDevice(s.sharedDev, s.table, s.sizing.InnerMTU, s.peerRegistry)
		dev = forwardDev
	} else {
		dev = newReflector(s.sizing.InnerMTU, s.assign.V4)
	}
	// The resolver wraps whichever backend was chosen, rather than replacing
	// either. It claims only UDP/53 addressed to s.assign.V4 and passes every
	// other packet through untouched, so a session with -resolver on behaves
	// exactly as before for all traffic that is not a query to this endpoint.
	// See resolverDevice's doc.
	if s.resolver != nil {
		dev = newResolverDevice(dev, s.resolver, s.sizing.InnerMTU)
	}
	tunCfg := tun.Config{
		Assign:        s.assign,
		Device:        dev,
		Clock:         driver.SessionClock{Clock: driver.SystemClock{}},
		AcceptTransit: s.acceptTransit,
	}
	build := driver.NewGateway
	if authenticated != nil {
		build = func(cfg driver.Config) (*driver.Loop, error) {
			return driver.NewGatewayFromDriver(cfg, authenticated)
		}
	}
	loopCfg := driver.Config{
		Session: s.sessionCfg,
		Sizing:  s.sizing,
		Carrier: conn,
		Tun:     &tunCfg,
	}
	if s.uplinkResequence && ps.pipe != nil {
		// Item 5 (tunnel-speed), arm R1: the UDP uplink's arrival order
		// carries 6.9 to 16.4% receive-order inversions into inner TCP
		// (Canada 2026-10-09, R rising with intake against the 0.5% bar),
		// with the source still unisolated by matched measurements. The
		// resequencer repairs inversions within the agreed bounds (3 ms,
		// 128 messages, byte and inner-packet bounds, late authenticated
		// messages delivered). Off by default until arm R1 measures it: with
		// it off, outer_reordered counts authenticated consumption disorder;
		// it does not identify which endpoint or path introduced it.
		// A stream carrier is ordered by construction and gets none of this.
		loopCfg.Reseq.Enabled = true
	}
	loop, err := build(loopCfg)
	if err != nil {
		if ps.pipe != nil {
			_ = conn.Close()
		}
		_ = dev.Close()
		return nil, err
	}
	if forwardDev != nil {
		forwardDev.bind(loop)
	}
	if s.sendQueueFQ {
		loop.Session().SetSendQueueFQ()
	}
	s.built.Add(1)
	loopCtx, cancel := context.WithCancel(ctx)
	ps.conn = conn
	ps.loop = loop
	ps.dev = dev
	ps.stop = cancel
	go func() {
		defer close(ps.done)
		runErr := loop.Run(loopCtx)
		fmt.Fprint(os.Stderr, observability.RedactAddresses(fmt.Sprintf(
			"winn3-gateway: session %v loop.Run exited: err=%v state=%v\n", from, runErr, ps.loop.Session().State())))
		// Eviction: a session whose Run has returned is dead. Drop it from
		// the demux table (it must not occupy a -max-sessions slot) and
		// Close the device (so forwardTable.forget runs). Without this, a
		// client that reconnects from a new UDP port with the same inner
		// IP collides on a mapping the dead session still holds, and a
		// gateway at its ceiling fills with corpses and refuses everyone
		// in silence. See forwardTable's eviction doc and releasePeer.
		if ps.pipe != nil {
			s.releasePeer(from, ps)
		} else {
			s.releaseTCPPeer(ps)
		}
	}()
	return ps, nil
}

func (s *server) findSessionForDatagram(msg []byte) *peerSession {
	if len(msg) < core.TransportOverhead() {
		return nil
	}
	token := msg[:core.DemuxTokenSize]

	s.mu.Lock()
	candidates := make([]*peerSession, 0, len(s.peers))
	seen := make(map[*peerSession]bool, len(s.peers))
	for _, ps := range s.peers {
		if !seen[ps] {
			seen[ps] = true
			if ps.loop != nil && ps.loop.HoldsToken(token) {
				candidates = append(candidates, ps)
			}
		}
	}
	s.mu.Unlock()

	for _, cand := range candidates {
		if cand.loop.Authenticates(msg) {
			return cand
		}
	}
	return nil
}

func (s *server) rebindPeer(ps *peerSession, newAddr netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldAddr := ps.remoteAddrPort()
	if oldAddr == newAddr {
		return
	}
	if s.peers[oldAddr] == ps {
		delete(s.peers, oldAddr)
	}
	s.peers[newAddr] = ps
	ps.setRemoteAddrPort(newAddr)
}

// close asks the session to send CLOSE, waits for Run to return, then
// releases the pipe and the device.
//
// The order is load-bearing. Loop.Close queues a CLOSE frame and wakes the
// write loop; Run returns once that frame has been handed to the carrier
// (see Loop.Close's own comment). Cancelling the loop context first is the
// path TestCancellingRunLatchesTheGateDown pins: the session stays
// ESTABLISHED, writeLoop returns ctx.Err(), and the CLOSE that Close() then
// queues has nobody left to Poll it. The client sees silence until its own
// probe budget expires — CloseDesynchronised, indistinguishable from a
// censor dropping UDP.
//
// Pipe.Close must also wait. drain's Send is how CLOSE reaches the socket,
// and a closed pipe makes that Send fail after assemble's after-hook has
// already terminate()'d (nonce consumed, frame gone).
//
// stop() is only the backstop if Run does not return. releasePeer, which
// runs on the Run goroutine after it has returned, still cancels immediately
// — there is no write loop left to drain.
func (p *peerSession) close() {
	_ = p.loop.Close()
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		p.stop()
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
		}
	}
	_ = p.carrier().Close()
	_ = p.dev.Close()
}

// releasePeer drops ps from the demux table, closes its loop, pipe and device
// (so forwardTable.forget runs), and finally frees its retirement reservation.
//
// # Completion-ownership contract
//
// releasePeer has two callers for a retired session: the Run goroutine when
// Loop.Run returns, and Round M's forced release (advanceRevokedTeardown) as a
// last resort. They are serialized by ps.releaseOnce: exactly one caller runs
// the teardown body to completion while any concurrent caller blocks in Do until
// it returns and then does nothing. That single execution owns completion. It
// frees the retirement reservation (s.retiring) ONLY after the loop, pipe and
// device are closed, so:
//
//   - a session removed from the peer map keeps charging its retirement slot for
//     as long as it still holds those resources; a blocked close holds the
//     reservation rather than freeing it early, which bounds the retiring
//     population by actual resource occupancy;
//   - concurrent callers cannot free the reservation before the resources are
//     closed, because the second caller blocks in Do until the first finishes.
//
// The map check is the same shape as forget's pointer guard: a newer session
// that already occupies from must not be evicted by the old Run returning late.
func (s *server) releasePeer(from netip.AddrPort, ps *peerSession) {
	ps.releaseOnce.Do(func() {
		s.mu.Lock()
		if s.peers[from] == ps {
			delete(s.peers, from)
		}
		current := ps.remoteAddrPort()
		if current != from && s.peers[current] == ps {
			delete(s.peers, current)
		}
		s.mu.Unlock()
		ps.stop()
		// releaseGate is a test seam only (nil in production): it blocks the
		// resource teardown so a test can prove the reservation is held until
		// teardown completes, with the reservation still charged.
		if s.releaseGate != nil {
			<-s.releaseGate
		}
		_ = ps.loop.Close()
		_ = ps.carrier().Close()
		_ = ps.dev.Close()
		s.mu.Lock()
		delete(s.retiring, ps)
		s.mu.Unlock()
	})
}

func (s *server) closeAll() {
	// Retiring sessions were removed from s.peers but their Run goroutines are
	// still tearing them down; drain them first so shutdown owns their teardown
	// rather than orphaning them. A timeout is reported, not swallowed.
	if drained, timedOut := s.awaitRetiring(); timedOut > 0 {
		fmt.Fprintf(os.Stderr, "winn3-gateway: closeAll drained %d retiring session(s); %d did not "+
			"complete teardown within the wait and may still hold resources\n", drained, timedOut)
	}
	s.mu.Lock()
	all := make([]*peerSession, 0, len(s.peers)+len(s.tcpPeers))
	seen := make(map[*peerSession]bool, len(s.peers)+len(s.tcpPeers))
	for _, ps := range s.peers {
		if !seen[ps] {
			seen[ps] = true
			all = append(all, ps)
		}
	}
	for ps := range s.tcpPeers {
		if !seen[ps] {
			seen[ps] = true
			all = append(all, ps)
		}
	}
	s.peers = make(map[netip.AddrPort]*peerSession)
	s.tcpPeers = make(map[*peerSession]struct{})
	s.mu.Unlock()
	for _, ps := range all {
		ps.close()
	}
}

// status walks every live session and sums what they have done.
//
// Promoted applies the SAME conjunction cmd/winn-datapath's winn3PromotionReady
// and cmd/winn3-labrig's statusOf apply, and for the same reason: RxPackets
// counts deliveries, RxOffered counts arrivals, and a gate that opened over an
// empty tunnel is the failure this predicate exists to catch.
func (s *server) status() serveStatus {
	s.mu.Lock()
	all := make([]*peerSession, 0, len(s.peers)+len(s.tcpPeers))
	seen := make(map[*peerSession]bool, len(s.peers)+len(s.tcpPeers))
	for _, ps := range s.peers {
		if !seen[ps] {
			seen[ps] = true
			all = append(all, ps)
		}
	}
	for ps := range s.tcpPeers {
		if !seen[ps] {
			seen[ps] = true
			all = append(all, ps)
		}
	}
	s.mu.Unlock()

	ready, replayJournalStatus := s.replayJournalReadiness()
	out := serveStatus{
		Event:                  "posture",
		Ready:                  ready,
		ReplayJournalStatus:    replayJournalStatus,
		ProofProcessID:         s.proofProcessID,
		ProofProcessNonce:      s.proofNonce,
		ProofBootID:            s.proofBootID,
		ProofProcessTicks:      s.proofTicks,
		ProofProcessStarted:    s.proofStarted,
		ProofObservedUTC:       time.Now().UTC().Format(time.RFC3339Nano),
		ProofObservedMonoNS:    uint64(time.Since(s.proofMonoStart)),
		ProofSequence:          s.proofSequence.Add(1),
		Sessions:               len(all),
		Admitted:               s.admitted.Load(),
		Built:                  s.built.Load(),
		Datagrams:              s.datagrams.Load(),
		Strangers:              s.strangers.Load(),
		AdmissionThrottled:     s.throttledCounts.Load(),
		Replays:                s.replays.Load(),
		Refused:                s.refusedLogs.Load(),
		BuildFailures:          s.buildFailures.Load(),
		SessionsReclaimed:      s.reclaimed.Load(),
		SessionsSuperseded:     s.superseded.Load(),
		InnerMTU:               s.sizing.InnerMTU,
		MessageSize:            s.sizing.MessageSize,
		UdpReadBufferRequested: udpSocketBufferBytes,
		UdpReadBuffer:          s.udpReadBuffer,
		UdpWriteBuffer:         s.udpWriteBuffer,
		UdpRcvbufErrors:        hostUdpRcvbufErrors(),
		UdpSendErrors:          buildUDPSendErrorStatus(s.conn, s.udpSendErrorOptions),
	}
	// Round CM3 egress counters, set outside the literal above so its field
	// alignment (which a source pin in udp_socket_buffers_test.go reads) stays.
	out.EgressMTURefused = s.egressRefused.Load()
	out.EgressMTUClosed = s.egressClosed.Load()
	out.EgressRoutingUnaccountable = s.egressUnaccountable.Load()
	out.EgressSweepMaxUS = s.egressSweepMaxUS.Load()
	out.EgressNetlinkIncomplete = netlinkIncompleteAnswers.Load()
	for _, ps := range all {
		if sess := ps.loop.Session(); sess != nil {
			out.SessionStates = append(out.SessionStates, sess.State().String())
		}
		ls := ps.loop.Stats()
		out.MessagesSent += ls.MessagesSent
		out.MessagesReceived += ls.MessagesReceived
		out.SendFailed += ls.SendFailed
		out.SendRefused += ls.SendRefused
		out.RecvFailed += ls.RecvFailed
		out.Unopenable += ls.Unopenable
		out.PathNarrowedFor += ls.PathNarrowedFor
		out.OuterReordered += ls.OuterReordered
		out.OuterLost += ls.OuterLost
		out.OuterReorderDepth.Add(ls.OuterReorderDepth)
		out.SendQueueDepth += ls.DataQueueDepth
		out.SendQueueHighWater = max(out.SendQueueHighWater, ls.DataQueueHighWater)
		out.SendQueueDropped += ls.DataQueueDropped
		out.SendQueueOverflow += ls.DataQueueOverflow
		pst := ps.carrier().Stats()
		out.PipeSent += pst.Sent
		out.PipeDelivered += pst.Delivered
		out.PipeRecvErrors += pst.RecvErrors
		out.PipeSendErrors += pst.SendErrors
		out.PipeInboxHighWater = max(out.PipeInboxHighWater, pst.InboxHighWater)
		for i := range pst.InboxSojourn {
			out.PipeInboxSojourn[i] += pst.InboxSojourn[i]
		}
		out.PipeInboxSojournMaxUS = max(out.PipeInboxSojournMaxUS, pst.InboxSojournMaxUS)
		tunnel := ps.loop.Tunnel()
		if tunnel == nil {
			continue
		}
		gate := tunnel.Gate().State()
		st := tunnel.Stats()
		if gate == tun.StateCarrying {
			out.Carrying++
			if st.RxPackets > 0 {
				out.Promoted++
			}
		}
		out.RxPackets += st.RxPackets
		out.RxOffered += st.RxOffered
		out.TxPackets += st.TxPackets
		out.RxDeviceWrites += st.RxDeviceWrites
		out.RxDroppedInvalid += st.RxDroppedInvalid
		out.RxDroppedClosed += st.RxDroppedClosed
		out.RxDropFamilyOff += st.RxDropFamilyOff
		out.RxDropMartian += st.RxDropMartian
		out.RxDropNotForUs += st.RxDropNotForUs
		out.RxDropReflected += st.RxDropReflected
		out.RxDropMalformed += st.RxDropMalformed
		out.TxDroppedInvalid += st.TxDroppedInvalid
		out.TxDroppedClosed += st.TxDroppedClosed
		out.TxDropFamilyOff += st.TxDropFamilyOff
		out.TxDropMartian += st.TxDropMartian
		out.TxDropSourceNotOurs += st.TxDropSourceNotOurs
		out.TxDropMalformed += st.TxDropMalformed
		// Reflected is a *reflector-only counter. ps.dev is a
		// *gatewayForwardDevice instead whenever s.forward is set, and that
		// backend reflects nothing by construction, so the type assertion
		// simply does not add anything for it rather than needing its own
		// branch.
		//
		// With -resolver on, ps.dev is a *resolverDevice wrapping one of those
		// two, so the assertion is made against the WRAPPED device. Without
		// this unwrap the counter would silently read zero for every
		// reflector-mode session the moment -resolver was enabled, which is
		// the class of quietly-wrong evidence this tree exists to avoid.
		backend := ps.dev
		if rd, ok := backend.(*resolverDevice); ok {
			backend = rd.inner
		}
		if r, ok := backend.(*reflector); ok {
			out.Reflected += r.Reflected()
		}
	}
	if s.resolver != nil {
		stats := s.resolver.Stats()
		out.Resolver = &stats
	}
	if s.forward {
		out.Forward = &gatewayForwardStatus{
			Device: s.sharedDev.Stats(),
			Table:  s.table.Stats(),
		}
		delivered := out.Forward.Device.Delivered
		out.InnerPacketsDelivered = &delivered
	}
	out.CarriageProven = carriageProven(s.forward, out.Carrying, out.Promoted, out.Forward)
	return out
}

// carriageProven decides serveStatus.CarriageProven. See that field's doc for
// why the answer is computed once here rather than re-derived by each reader.
//
// It is a named function, and not three lines inlined above, so that the whole
// predicate can be exercised for both modes without standing up a Linux kernel
// interface: the forward half of this binary only RUNS on linux
// (forward_other.go refuses), but the rule about which counter is evidence in
// which mode is not platform-specific and is worth testing everywhere.
//
// fwd is nil whenever forward is false; a forward-mode call with a nil fwd
// would mean the status document lost the very evidence it is being asked
// about, so it returns false rather than falling through to the reflector
// predicate that is structurally unsatisfiable in that mode.
func carriageProven(forward bool, carrying, promoted int, fwd *gatewayForwardStatus) bool {
	if !forward {
		return promoted > 0
	}
	if fwd == nil {
		return false
	}
	return carrying > 0 && fwd.Device.Delivered > 0
}

// buildServeSizing resolves the migration plan and the plan floor this gateway
// will serve at.
//
// Extracted from runServe for ONE reason, and it is worth stating because
// "extracted for testability" is usually a smell: the cross-host conformance
// suite has to compare the number THIS BINARY really plans with, and a test
// that called driver.NewSizing itself would agree with itself while runServe
// ran on something else. That is not hypothetical — the conformance adapter did
// exactly that until the mutation harness for defect 3 (a gateway that ignores
// -path-mtu and plans at its own default) came back MISSED on 2026-08-09.
//
// Nothing else changed: runServe calls this and behaves as it did.
//
// The classes are returned alongside the sizing because the suite compares the
// resolved plan too — a gateway that silently dropped a class from -plan would
// produce a wider floor than the operator asked for, which is defect 2 with a
// different cause.
func buildServeSizing(opts serveOptions) (driver.Sizing, []carrier.Class, error) {
	classes, err := parsePlan(opts.plan)
	if err != nil {
		return driver.Sizing{}, nil, err
	}
	sizing, err := driver.NewSizing(opts.pathMTU, classes...)
	if err != nil {
		return driver.Sizing{}, nil, err
	}
	return sizing, classes, nil
}

// buildSessionConfig assembles the responder's configuration.
func buildSessionConfig(opts serveOptions, registries ...*peerRegistry) (session.Config, error) {
	staticBytes, err := readKeyFile(opts.staticPath)
	if err != nil {
		return session.Config{}, fmt.Errorf("-static: %w", err)
	}
	staticKey, err := core.NewStaticKey(staticBytes)
	if err != nil {
		return session.Config{}, fmt.Errorf("-static: %w", err)
	}
	rawSecret, err := securefile.ReadPrivateLimited(opts.admission, 4096)
	if err != nil {
		return session.Config{}, fmt.Errorf("-admission: %w", err)
	}
	// The admission secret is OPAQUE BYTES and is never decoded.
	//
	// This cost a debugging cycle and is worth stating plainly. keygen writes
	// the secret hex-encoded, so it is tempting to hex-decode it here — and
	// cmd/winn-datapath (winn3_run.go:372) and cmd/winn3-labrig (main.go:384)
	// both do exactly this instead: read the file and trim the trailing
	// newline, so the ASCII TEXT of the hex is the secret. Decoding on one end
	// only produces a different admission tag, ReadInitiation fails, and the
	// gateway answers with the silence it answers every unauthenticated
	// datagram with. The failure is therefore indistinguishable from "the
	// gateway is not there", which is precisely the failure mode this
	// protocol's silence property makes impossible to diagnose from the client.
	// Both ends must treat this file identically, byte for byte.
	secret := bytes.TrimRight(rawSecret, "\r\n")
	if !isCanonicalAdmissionSecret(secret) {
		return session.Config{}, errors.New(
			"-admission must contain exactly 64 lowercase hexadecimal ASCII bytes " +
				"after trailing CR/LF removal; use the file emitted by -mode keygen without hex-decoding it")
	}
	if strings.TrimSpace(opts.gatewayID) == "" {
		return session.Config{}, errors.New(
			"-gateway-id is empty: without it an initiation captured at one " +
				"gateway replays at another sharing the admission key")
	}

	var registry *peerRegistry
	if len(registries) > 0 {
		registry = registries[0]
	}
	accept := func([]byte) error { return nil }
	if registry != nil {
		accept = registry.authorize
	}
	if (opts.dualEDKey == "") != (opts.dualMLSeed == "") {
		return session.Config{}, errors.New("-dual-auth-ed-key and -dual-auth-ml-seed must be provided together")
	}
	var dual session.DualAuthConfig
	if opts.dualEDKey != "" {
		edRaw, err := securefile.ReadPrivateLimited(opts.dualEDKey, 4096)
		if err != nil {
			return session.Config{}, fmt.Errorf("-dual-auth-ed-key: %w", err)
		}
		edPriv, err := hex.DecodeString(strings.TrimSpace(string(bytes.TrimRight(edRaw, "\r\n"))))
		if err != nil || len(edPriv) != 64 {
			return session.Config{}, errors.New("-dual-auth-ed-key must hold 64 bytes hex (seed||public)")
		}
		mlRaw, err := securefile.ReadPrivateLimited(opts.dualMLSeed, 4096)
		if err != nil {
			return session.Config{}, fmt.Errorf("-dual-auth-ml-seed: %w", err)
		}
		mlSeed, err := hex.DecodeString(strings.TrimSpace(string(bytes.TrimRight(mlRaw, "\r\n"))))
		if err != nil || len(mlSeed) != dualsign.MLDSA65SeedSize {
			return session.Config{}, fmt.Errorf("-dual-auth-ml-seed must hold %d bytes hex", dualsign.MLDSA65SeedSize)
		}
		dual = session.DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
	}
	cfg := session.Config{
		DualAuth: dual,
		Core: core.Config{
			Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{secret},
				// RAW BYTES of the operator string, which is what
				// cmd/winn-datapath (winn3_keys.go:205, winn3_run.go:378) and
				// cmd/winn3-labrig (main.go:390) all do — and, since
				// 2026-08-09, what cdatapath does too. That last one used to
				// base64-DECODE this field, so an Apple client computed a
				// different admission tag from the identical operator value.
				// The divergence is RESOLVED, not merely reported here: the
				// core input is the operator string's bytes on every platform,
				// and the base64 that the signed hub descriptor genuinely
				// carries is decoded at the descriptor boundary instead
				// (WinsTunnelConfig.winn3GatewayIDOperatorText). See
				// docs/handoff/WINN3_HOST_SEAM_20260808.md §9.3.
				//
				// Keep this line raw. A gateway that decodes here is refused by
				// nothing and answers nobody: an unauthenticated datagram gets
				// no reply, so the wrong encoding produces no session and no
				// error on either side, which under this threat model reads as
				// a censor rather than as a bug. `winsgw01` is eight characters
				// of the base64 alphabet, so an ordinary operator name is
				// enough to trigger it.
				GatewayID: []byte(opts.gatewayID),
			},
		},
		Static:  staticKey,
		Padding: core.PadBucket,
		// ADMIT-ALL, stated rather than hidden, exactly as cmd/winn3-labrig
		// states it. core refuses a responder with no Accept precisely so that
		// "authenticated" is never silently read as "authorised". This binary
		// has no subscriber policy and says so rather than shipping a stub that
		// looks like one.
		Accept:    accept,
		SendQueue: gatewaySendQueue,
	}
	// Set before NewSharedResponder below: the responder builds every
	// session's receive window from its own copy of cfg.Core.
	cfg.Core.TokenWindow = gatewayTokenWindow

	// F-02: the persisted handshake replay journal. Production serve
	// (requireReplayJournalPath) refuses WINN3_GATEWAY_REPLAY_JOURNAL=0 and
	// any absent or unusable pathname before this constructor runs, so a
	// missing file cannot be created as an empty replay window, and it
	// passes the exact validated pathname in opts.replayJournal so this
	// constructor cannot getenv a whitespace-suffixed twin. When set,
	// core.NewResponder (through NewSharedResponder below) loads the journal
	// fail-closed and durably records every accepted initiation, so a
	// captured initiation stays refused across a gateway restart instead of
	// earning a fresh response. Unset is the lab/test helper path only.
	// parseReplayJournalPath is the only parser: edge whitespace is refused
	// (a trimmed path and the raw value are distinct journal and WAL files)
	// and a relative path is refused (it would be created inside this
	// process's working directory).
	rawJournal := opts.replayJournal
	if rawJournal == "" {
		rawJournal = os.Getenv("WINN3_REPLAY_JOURNAL")
	}
	journalPath, err := parseReplayJournalPath(rawJournal)
	if err != nil {
		return session.Config{}, err
	}
	if journalPath != "" {
		cfg.Core.ReplayJournal = journalPath
	}

	// ONE handshake responder for the whole process, shared by every session
	// this binary builds. It is set here, in the config constructor, rather
	// than in serve(), so that EVERY construction path gets it — including
	// tests that assemble a `server` literal directly. A path that could reach
	// newSession without it would silently reinstate the defect below.
	//
	// The defect, stated plainly, because it is the reason this exists:
	//
	// This binary demultiplexes on netip.AddrPort. sessionFor builds a session
	// per address and newSession calls driver.NewGateway, which — before
	// session.Config.Responder existed — called core.NewResponder and got a
	// fresh, EMPTY handshake replay cache for every peer address. The replay
	// cache is what stops a captured initiation from being replayed, so
	// partitioning it by source address means a censor who captures ONE real
	// initiation can replay it from any other address and be answered. An
	// ordinary host does not answer a stray UDP datagram with a Winn3
	// handshake response, so that reply is a remote test for "is there a Winn3
	// gateway at this address" — the exact property the cover, decoy and ECH
	// design exists to deny. core.Responder's own documentation calls
	// rebuilding a Responder "a security defect" for this reason;
	// winn3/gateway.Gateway holds one for the whole front door, and this binary
	// does not use winn3/gateway, so it had to be given the property directly.
	// TestACapturedInitiationReplayedFromASecondAddressIsSilent pins it.
	//
	// It costs a roaming client nothing: the cache is keyed on the recovered
	// initiation body, which carries a fresh per-handshake ephemeral, so a
	// client that rebinds and re-initiates hashes differently and is admitted.
	// Only a bit-identical replay is refused. See roam_behaviour_test.go.
	resp, err := session.NewSharedResponder(cfg)
	if err != nil {
		// F-02: with a journal configured, a responder build failure is a
		// journal load refusal (a torn or unreadable file refuses the start,
		// fail-closed). Emit the machine-readable status token the operator
		// can grep for beside the returned error.
		if cfg.Core.ReplayJournal != "" {
			fmt.Fprintf(os.Stderr, "winn3-gateway: replay-journal status=%s\n", replayJournalStatusLoadRefused)
		}
		return session.Config{}, fmt.Errorf("building the shared handshake responder: %w", err)
	}
	cfg.Responder = resp
	return cfg, nil
}

func isCanonicalAdmissionSecret(secret []byte) bool {
	if len(secret) != 64 {
		return false
	}
	for _, b := range secret {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

// readKeyFile accepts the same two encodings cmd/winn-datapath does.
func readKeyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("empty path")
	}
	raw, err := securefile.ReadPrivateLimited(path, 4096)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == hex.EncodedLen(core.KeySize) {
		if decoded, decodeErr := hex.DecodeString(trimmed); decodeErr == nil {
			return decoded, nil
		}
	}
	if len(raw) == core.KeySize {
		return raw, nil
	}
	return nil, fmt.Errorf("%d bytes; expected %d raw or %d hex characters",
		len(raw), core.KeySize, hex.EncodedLen(core.KeySize))
}

func parseAssignment(v4, routerV4, v6, routerV6 string) (tun.Assignment, error) {
	var out tun.Assignment
	if strings.TrimSpace(v4) == "" && strings.TrimSpace(v6) == "" {
		return out, errors.New("-inner-v4 and -inner-v6 are both empty; assign at least one inner address")
	}
	if strings.TrimSpace(v4) != "" {
		addr, err := netip.ParseAddr(v4)
		if err != nil {
			return out, fmt.Errorf("-inner-v4: %w", err)
		}
		out.V4 = addr
	}
	if strings.TrimSpace(routerV4) != "" {
		router, routerErr := netip.ParseAddr(routerV4)
		if routerErr != nil {
			return out, fmt.Errorf("-router-v4: %w", routerErr)
		}
		// The router is the inner NEXT HOP. It cannot be this gateway's own
		// inner address, and winn3/tun refuses the assignment outright
		// (tun.go:169). That refusal used to arrive at the first datagram
		// rather than here, where readLoop discarded it — see preflightSession
		// for the whole story. This is the message the operator gets, and it
		// names both flags and the value they collide on, because "IPv4 router
		// address equals the assigned address" does not tell an operator which
		// two things they typed are the problem.
		if router == out.V4 {
			return out, fmt.Errorf(
				"-router-v4 and -inner-v4 are both %s: the inner next hop cannot be this "+
					"gateway's own inner address. winn3/tun refuses that assignment, so every "+
					"session fails to build and the gateway answers every handshake with "+
					"silence, which under this threat model is indistinguishable from a "+
					"censor. Give -router-v4 the client-side next hop, or omit it entirely "+
					"(path-MTU signals are then dropped and counted instead of synthesised)",
				router)
		}
		out.RouterV4 = router
	}
	if strings.TrimSpace(v6) != "" {
		addr, err := netip.ParseAddr(v6)
		if err != nil {
			return out, fmt.Errorf("-inner-v6: %w", err)
		}
		out.V6 = addr
	}
	if strings.TrimSpace(routerV6) != "" {
		router, routerErr := netip.ParseAddr(routerV6)
		if routerErr != nil {
			return out, fmt.Errorf("-router-v6: %w", routerErr)
		}
		if router == out.V6 {
			return out, fmt.Errorf(
				"-router-v6 and -inner-v6 are both %s: the inner next hop cannot be this "+
					"gateway's own inner address. winn3/tun refuses that assignment, so every "+
					"session fails to build and the gateway answers every handshake with "+
					"silence, which under this threat model is indistinguishable from a censor.",
				router)
		}
		out.RouterV6 = router
	}
	return out, nil
}

func parsePlan(plan string) ([]carrier.Class, error) {
	parts := strings.Split(plan, ",")
	out := make([]carrier.Class, 0, len(parts))
	for _, p := range parts {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "udp":
			out = append(out, carrier.ClassUDP)
		case "tcp":
			out = append(out, carrier.ClassTCP)
		case "tls":
			out = append(out, carrier.ClassTLS)
		case "":
			continue
		default:
			return nil, fmt.Errorf("-plan names %q; use udp, tcp or tls", p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("-plan is empty")
	}
	return out, nil
}

func writeJSON(out io.Writer, v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	payload := append(encoded, '\n')
	n, err := out.Write(payload)
	if err == nil && n != len(payload) {
		return io.ErrShortWrite
	}
	return err
}

func validateProofStatusPath(path string) error {
	if path == "" {
		return nil
	}
	if path != proofStatusPath {
		return fmt.Errorf("-status-json is %q; production proof status is fixed at %s", path, proofStatusPath)
	}
	return nil
}

func proofStatusOf(status serveStatus) proofStatus {
	delivered := uint64(0)
	if status.InnerPacketsDelivered != nil {
		delivered = *status.InnerPacketsDelivered
	}
	ready := status.Ready && (status.Event == "listening" || status.Event == "posture")
	return proofStatus{
		SchemaVersion:         2,
		Contract:              "winsvpn-gcp-proof-winn3-status-v2",
		Event:                 status.Event,
		Ready:                 ready,
		Forward:               status.Forward != nil,
		ProcessID:             status.ProofProcessID,
		ProcessNonce:          status.ProofProcessNonce,
		BootID:                status.ProofBootID,
		ProcessStartTicks:     status.ProofProcessTicks,
		ProcessStartedUTC:     status.ProofProcessStarted,
		ObservedUTC:           status.ProofObservedUTC,
		ObservedMonotonicNS:   status.ProofObservedMonoNS,
		Sequence:              status.ProofSequence,
		InnerPacketsDelivered: delivered,
		Reflected:             status.Reflected,
		RxDeviceWrites:        status.RxDeviceWrites,
	}
}

func writeServeStatus(out io.Writer, path string, status serveStatus) error {
	if err := writeJSON(out, status); err != nil {
		return err
	}
	if path != "" {
		if err := writeProofStatusFile(path, proofStatusOf(status)); err != nil {
			return fmt.Errorf("publish proof status: %w", err)
		}
	}
	return nil
}
