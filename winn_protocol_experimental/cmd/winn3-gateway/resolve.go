package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// This file is the gateway's OWN inner DNS responder: a forwarder that answers
// UDP/53 addressed to THIS END'S INNER ADDRESS (-inner-v4) and to no other
// address whatsoever.
//
// It exists because standalone winn/3 refuses to start on every client
// platform for want of a resolver it can derive to be inside the tunnel
// (Apple WinsWinn3Resolvers.promotionRefusalReason, Android
// WinnV3Resolvers.promotionRefusalReason, Windows and Linux
// BuildPromotedPosture's dns_servers / dns_servers_are_inner gates). Those
// refusals are correct and NOTHING HERE RELAXES THEM. This file stands a
// resolver up; advertising it to a client is a separate, later, owner-gated
// change. See the ordering argument in
// docs/handoff/V3_RESOLVER_STANDUP_20260812_v3_resolver_standup.md: a
// descriptor that names a resolver before one answers turns four loud
// refusals into a green promotion pointing at silence.
//
// # Why the gateway's own inner address, and not a second address like .53
//
// winn3/tun/ip.go's validator.outbound is the whole argument, and reflect.go
// already states it for the reflector:
//
//	outbound (device -> tunnel):  src MUST be ours, dst MUST NOT be ours
//	inbound  (tunnel -> device):  dst MUST be ours, src MUST NOT be ours
//
// A DNS REPLY is an outbound packet, so its source must equal this endpoint's
// own assignment or the tunnel refuses to carry it and counts it as
// TxDroppedInvalid. A resolver at any other inner address (10.64.0.53, say)
// therefore cannot answer through winn3/tun at all -- its replies are
// ErrSourceNotOurs -- and could only ever be reached through the
// driver.Loop.SendInner bypass, which exists only in -forward mode and only
// for traffic the kernel already routed. So:
//
//   - a resolver at -inner-v4 works in BOTH reflector and -forward mode, needs
//     no relaxation of any address rule, and needs no -accept-transit (a query
//     addressed here satisfies "dst MUST be ours" exactly);
//   - a resolver at a second inner address structurally REQUIRES -forward,
//     hence /dev/net/tun and CAP_NET_ADMIN, hence relaxing the systemd unit's
//     PrivateDevices=yes and empty CapabilityBoundingSet on a node that serves
//     real users, plus a second daemon to run it.
//
// This process needs none of that for UDP. deploy/systemd/winn3-gateway.service
// runs as User=winn3-gateway with an empty capability set and PrivateDevices=yes
// in reflector mode, and the UDP path's only new kernel resource is an ordinary
// outbound AF_INET UDP socket, which RestrictAddressFamilies already permits.
// TCP/53 is different: it is a kernel listening socket on -inner-v4:53, started
// only when BOTH -forward and -resolver are on (see resolve_tcp.go), and that
// bind needs CAP_NET_BIND_SERVICE in both CapabilityBoundingSet and
// AmbientCapabilities. write_unit() grants it only in that branch; resolver
// without forward must not gain it, because there is no tun address and a
// successful bind would be on a host address, including the WAN.
//
// The second consequence is about the wire: -inner-v4 is what the client
// receives as `inner_router_v4`, which is ALREADY one of the descriptor's 18
// signed fields. The address a client would need is therefore already in its
// possession; the only thing still missing on the wire is a signed statement
// that this gateway answers there. That is the descriptor decision, and it is
// the owner's, not this file's.
//
// # What this is NOT
//
// Not a recursive resolver, not a cache, and not a filter. It relays a query's
// UDP payload to one operator-named upstream and relays the answer back. It
// parses DNS only where it must: enough to refuse a packet that is not a
// query, enough to synthesise a TC=1 answer when a reply will not fit the
// inner MTU, and enough to synthesise a SERVFAIL when the upstream exchange
// fails. Everything else is opaque bytes.
//
// # Privacy, stated because it cannot be inferred
//
// Every name a session looks up passes through this process in the clear and
// is then seen by -resolver-upstream. This file logs NOTHING per query: no
// name, no client address, no upstream address, at any level. The counters
// below are aggregate and nothing else. That is deliberate and matches the
// discipline winn3/tun/ip.go's ErrSourceNotOurs already keeps, where the error
// text refuses to name the address it saw because a log line is a record.
//
// # The boundary of that guarantee
//
// "Logs nothing per query" covers queries THIS RESPONDER CLAIMS — the
// well-formed, unfragmented UDP/53 datagrams claim() accepts. A packet that
// claim() refuses is not dropped; it passes through to the wrapped device
// untouched, as if this responder were not configured. Under -forward the
// wrapped device is the kernel tun, so a claimed-shape-but-malformed UDP/53 to
// this endpoint (fragmented, a UDP length anomaly, or QR=1) falls through to
// the host stack, where a host-side resolver such as AdGuard may answer it AND
// log it. The privacy guarantee of this file therefore does NOT extend to that
// case. Two responders with different privacy properties can answer the same
// address depending on packet shape, which is also fingerprintable. We chose to
// DOCUMENT this boundary rather than refuse to carry such packets, because
// claim()'s refusal is the pass-through path that real (non-DNS) traffic relies
// on and dropping claimed-shape-but-malformed UDP/53 would be a new policy that
// changes what the gateway carries for packets not addressed to -inner-v4. An
// operator who wants the no-log guarantee for ALL UDP/53 to this endpoint must
// ensure no host resolver listens on -inner-v4, or run the responder on a host
// with no other 53 listener on that address.

const (
	// ipv4HeaderMinBytes and udpHeaderBytes size the headers this file writes.
	// winn3/carrier/sizing.go has its own copies for the MTU arithmetic; these
	// are here because this file builds real headers rather than budgeting for
	// them, and a shared constant would tie a packet builder to a sizing
	// calculator that has no reason to change together with it.
	ipv4HeaderMinBytes = 20
	udpHeaderBytes     = 8

	// ipProtoUDP is IPv4 protocol 17.
	ipProtoUDP = 17

	// dnsPort is the only destination port this responder claims.
	dnsPort = 53

	// dnsHeaderBytes is the fixed DNS message header: ID, flags, and the four
	// section counts.
	dnsHeaderBytes = 12

	// dnsUpstreamReadCap bounds one upstream answer. Larger than any inner MTU
	// on purpose: an answer must be READ before it can be measured against the
	// MTU, and an answer silently cut off at the MTU would be handed to the
	// client as a complete message when it is a fragment of one. Reading up to
	// this and THEN deciding is what makes the TC=1 path possible.
	dnsUpstreamReadCap = 4096

	// dnsDefaultTimeout bounds one upstream exchange.
	dnsDefaultTimeout = 5 * time.Second

	// dnsDefaultMaxInFlight bounds concurrent upstream exchanges across all
	// sessions this process serves.
	//
	// This is a real limit, not a formality. Each in-flight query holds one
	// file descriptor against the unit's LimitNOFILE=8192 and one goroutine
	// against TasksMax=256, and every session reaching this responder is
	// authenticated but not therefore trusted -- an authenticated peer that
	// floods queries is exactly the case a gateway must survive. Over the
	// limit, queries are dropped and counted rather than queued: a queue would
	// answer them late, after the client has already retried, which converts a
	// visible refusal into invisible latency.
	dnsDefaultMaxInFlight = 32

	// dnsDefaultMaxInFlightPerClient bounds in-flight upstream exchanges a
	// SINGLE session (keyed on the client's inner address) may hold, below the
	// process-wide dnsDefaultMaxInFlight. Without it, one authenticated peer
	// sending minimal queries would saturate the shared semaphore and every
	// other session would get Refused probabilistically — which in this
	// product's threat model is indistinguishable from censorship ("my DNS
	// intermittently returns nothing"). 8 of 32 keeps one session from
	// starving the rest while leaving five sessions able to run at their own
	// share simultaneously.
	dnsDefaultMaxInFlightPerClient = 8

	// resolverInboxDepth bounds queued replies, matching reflectorDepth's
	// reasoning: a full queue drops rather than blocks, because the queuing
	// side must never stall a session's delivery path.
	resolverInboxDepth = 256
)

// errResolverDeviceClosed is ReadPacket's unblocking error, matching the shape
// errReflectorClosed and errGatewayForwardDeviceClosed already establish.
var errResolverDeviceClosed = errors.New("resolver device closed")

// errDNSReplyTooLarge is exchange's signal that an upstream datagram filled the
// dnsUpstreamReadCap buffer, so it could not be read whole. It is NOT an
// upstream failure: the upstream answered, and the answer is merely too large
// to read, which means it can never fit the inner MTU and must take the TC=1
// path rather than be delivered truncated with a checksum that verifies over
// bytes that are a fragment of the real message.
var errDNSReplyTooLarge = errors.New("dns reply exceeds the read cap")

// resolverStats is the -resolver half of serveStatus. Aggregate only: see this
// file's privacy note for why there is nothing per-query here and nothing
// per-query anywhere else either.
type resolverStats struct {
	// Upstream is the operator's -resolver-upstream value, echoed so a status
	// document says where queries went. This is the ONE address in this struct
	// and it is the operator's own configuration, not any user's traffic.
	Upstream string `json:"upstream"`

	// Claimed counts inner packets this responder took because they were
	// UDP/53 addressed to -inner-v4. Everything else is passed through to the
	// wrapped device and never counted here.
	Claimed uint64 `json:"claimed"`

	// Answered counts replies queued for the client.
	Answered uint64 `json:"answered"`

	// Truncated counts answers that did not fit the inner MTU and were
	// replaced by a TC=1 response, telling the client to retry over TCP.
	// In -forward + -resolver mode this process also answers TCP/53 (see
	// resolve_tcp.go); Truncated > 0 with TcpAnswered == 0 is then a
	// bind/firewall/cap defect, not "DNSSEC is rare". In reflector mode
	// there is no TCP listener because -inner-v4 is not a host address.
	Truncated uint64 `json:"truncated"`

	// TCP counters are kept separate from the UDP ones above so a live unit
	// can tell "UDP works, TCP does not" from Truncated alone. Do not fold
	// TCP successes into Answered or TCP failures into UpstreamFailed.
	TcpAccepted       uint64 `json:"tcp_accepted"`
	TcpAnswered       uint64 `json:"tcp_answered"`
	TcpUpstreamFailed uint64 `json:"tcp_upstream_failed"`
	TcpRefused        uint64 `json:"tcp_refused"`
	TcpDropped        uint64 `json:"tcp_dropped"`

	// UpstreamFailed counts exchanges that produced no usable answer: dial
	// failure, timeout, a reply whose transaction ID did not match, or a reply
	// too short to be a DNS message.
	//
	// Every one of these also sends the client a synthesised SERVFAIL (see
	// emitServFail); the counter's meaning is unchanged by that, because what
	// it counts is the failed exchange and not what was said about it.
	UpstreamFailed uint64 `json:"upstream_failed"`

	// Refused counts queries dropped because dnsDefaultMaxInFlight was already
	// reached. Distinguished from UpstreamFailed because the diagnosis is
	// opposite: this one is local pressure, that one is the upstream. That is
	// also why a refusal stays SILENT while an upstream failure is answered
	// SERVFAIL -- see WritePacket.
	Refused uint64 `json:"refused"`

	// Dropped counts answers that could not be queued because the reply inbox
	// was full, plus TC=1 and SERVFAIL responses that could not be synthesised.
	Dropped uint64 `json:"dropped"`

	// RelayDropped counts packets relayed from the wrapped device (the
	// reflector or the -forward mode kernel device) that could not be queued
	// because the reply inbox was full. Kept separate from Dropped so a full
	// inbox in the relay path is never misread as an answer this responder
	// dropped.
	RelayDropped uint64 `json:"relay_dropped"`

	// Unauthorized counts claimed queries refused before any upstream
	// exchange because, in registry-backed -forward mode, the session's
	// authenticated peer was not authorized for the query's inner source
	// address. Silent toward the peer, like every other refusal here.
	Unauthorized uint64 `json:"unauthorized"`

	// ReplySuppressed counts replies, upstream or synthesised (TC=1,
	// SERVFAIL), withheld because that authorization was withdrawn between
	// the query and delivery.
	ReplySuppressed uint64 `json:"reply_suppressed"`
}

// gatewayResolver answers DNS for one gateway process. One instance is shared
// by every session, which is what makes dnsDefaultMaxInFlight a process-wide
// ceiling rather than a per-session one.
type gatewayResolver struct {
	ours     netip.Addr
	upstream netip.AddrPort
	timeout  time.Duration

	// sem is the in-flight bound, process-wide across all sessions. A token is
	// taken non-blockingly; failure to take one is a refusal, never a wait.
	sem chan struct{}

	// perClient limits in-flight queries per session (keyed on the client
	// address), so one authenticated peer cannot saturate the process-wide sem
	// and starve every other session. See dnsDefaultMaxInFlightPerClient.
	perClientMu sync.Mutex
	perClient   map[netip.Addr]int

	// idByDst supplies the IPv4 identification field, keyed per destination.
	// DF is always set so the field is never used for reassembly and carries no
	// reassembly meaning; a per-destination counter keeps one packet capture
	// readable without exposing a process-wide counter that any authenticated
	// client could read as "how many DNS replies did the whole process emit
	// since my last one", which would be a cross-session activity oracle.
	idMu    sync.Mutex
	idByDst map[netip.Addr]uint32

	claimed        atomic.Uint64
	answered       atomic.Uint64
	truncated      atomic.Uint64
	upstreamFailed atomic.Uint64
	refused        atomic.Uint64
	dropped        atomic.Uint64
	relayDropped   atomic.Uint64
	unauthorized   atomic.Uint64
	suppressed     atomic.Uint64

	tcpAccepted       atomic.Uint64
	tcpAnswered       atomic.Uint64
	tcpUpstreamFailed atomic.Uint64
	tcpRefused        atomic.Uint64
	tcpDropped        atomic.Uint64

	// tcpLn is the process-wide TCP/53 listener, owned here rather than on
	// resolverDevice: there is one resolverDevice per session, and closing a
	// session must not close the listener. Nil unless -forward and -resolver
	// are both on and listen succeeded.
	tcpLnMu sync.Mutex
	tcpLn   net.Listener
}

func newGatewayResolver(ours netip.Addr, upstream netip.AddrPort, timeout time.Duration, maxInFlight int) *gatewayResolver {
	if maxInFlight <= 0 {
		maxInFlight = dnsDefaultMaxInFlight
	}
	return &gatewayResolver{
		ours:      ours,
		upstream:  upstream,
		timeout:   timeout,
		sem:       make(chan struct{}, maxInFlight),
		perClient: make(map[netip.Addr]int),
		idByDst:   make(map[netip.Addr]uint32),
	}
}

func (r *gatewayResolver) Stats() resolverStats {
	return resolverStats{
		Upstream:          r.upstream.String(),
		Claimed:           r.claimed.Load(),
		Answered:          r.answered.Load(),
		Truncated:         r.truncated.Load(),
		UpstreamFailed:    r.upstreamFailed.Load(),
		Refused:           r.refused.Load(),
		Dropped:           r.dropped.Load(),
		RelayDropped:      r.relayDropped.Load(),
		Unauthorized:      r.unauthorized.Load(),
		ReplySuppressed:   r.suppressed.Load(),
		TcpAccepted:       r.tcpAccepted.Load(),
		TcpAnswered:       r.tcpAnswered.Load(),
		TcpUpstreamFailed: r.tcpUpstreamFailed.Load(),
		TcpRefused:        r.tcpRefused.Load(),
		TcpDropped:        r.tcpDropped.Load(),
	}
}

// acquireClient reserves one of a single session's in-flight slots, keyed on
// the client's inner address. Non-blocking: failure is a refusal, and the
// caller must not have taken a token yet (see WritePacket, which checks the
// per-session share before the process-wide semaphore so an over-share session
// is refused without consuming a global token another session could use).
func (r *gatewayResolver) acquireClient(c netip.Addr) bool {
	r.perClientMu.Lock()
	defer r.perClientMu.Unlock()
	if r.perClient[c] >= dnsDefaultMaxInFlightPerClient {
		return false
	}
	r.perClient[c]++
	return true
}

// releaseClient returns one of a session's in-flight slots. Sessions are
// recycled from the map at zero so the map does not grow without bound as
// clients come and go.
func (r *gatewayResolver) releaseClient(c netip.Addr) {
	r.perClientMu.Lock()
	defer r.perClientMu.Unlock()
	r.perClient[c]--
	if r.perClient[c] <= 0 {
		delete(r.perClient, c)
	}
}

// nextID returns the next IPv4 identification field for one destination. A
// per-destination counter means a client only ever sees its OWN replies' IDs,
// so it cannot infer how many replies the whole process emitted since its last
// one. See idByDst's comment.
func (r *gatewayResolver) nextID(dst netip.Addr) uint32 {
	r.idMu.Lock()
	defer r.idMu.Unlock()
	r.idByDst[dst]++
	return r.idByDst[dst]
}

// dnsQuery is one claimed query, already checked to be addressed here.
type dnsQuery struct {
	client     netip.Addr
	clientPort uint16
	payload    []byte
}

// claim reports whether pkt is a DNS query THIS responder answers.
//
// Every check is a refusal to widen. In order, and each for its own reason:
//
//   - IPv4 only, with a header length inside the buffer. Inner IPv6 is not
//     answered for the same reason reflect.go does not reflect it.
//   - NOT A FRAGMENT. A fragmented query cannot be answered without
//     reassembly, and a responder that read the first fragment's UDP header
//     and ignored the rest would answer a question it only half received.
//     Both the MF bit and a non-zero fragment offset refuse here.
//   - protocol UDP, destination port 53, destination address EXACTLY -inner-v4.
//     The address test is an equality against one address, never a containment
//     test against a prefix, matching validator.outbound's own reasoning about
//     why a prefix test forwards every other host inside the prefix.
//   - the DNS header is present and its QR bit is 0. A RESPONSE arriving as
//     though it were a query is either a loop or something trying to have this
//     process relay a forged answer upstream; it is refused rather than
//     forwarded.
//
// A packet this refuses is not dropped -- it is passed through to the wrapped
// device untouched, exactly as if this responder were not configured. Refusing
// to CLAIM is not refusing to CARRY.
func (r *gatewayResolver) claim(pkt []byte) (dnsQuery, bool) {
	if len(pkt) < ipv4HeaderMinBytes || pkt[0]>>4 != 4 {
		return dnsQuery{}, false
	}
	// The IPv4 total-length field MUST equal the bytes actually present. Safe
	// today only by composition with Tunnel.deliver, which presents whole
	// validated packets; if claim were ever called on a raw device read, a UDP
	// length field larger than total-ihl but within the buffer would splice
	// another flow's stale bytes into the payload sent UPSTREAM — a cross-flow
	// leak to the resolver operator. Refusing here makes that impossible by
	// construction rather than by call-site discipline.
	if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		return dnsQuery{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMinBytes || ihl > len(pkt) {
		return dnsQuery{}, false
	}
	if pkt[9] != ipProtoUDP {
		return dnsQuery{}, false
	}
	// Flags and fragment offset share bytes 6-7: the low 13 bits are the
	// offset and bit 0x20 of byte 6 is MF. A packet with either set is part of
	// a fragmented datagram.
	if pkt[6]&0x20 != 0 || (uint16(pkt[6]&0x1f)<<8|uint16(pkt[7])) != 0 {
		return dnsQuery{}, false
	}
	if !r.ours.Is4() {
		return dnsQuery{}, false
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if dst != r.ours {
		return dnsQuery{}, false
	}
	if ihl+udpHeaderBytes > len(pkt) {
		return dnsQuery{}, false
	}
	udp := pkt[ihl:]
	if binary.BigEndian.Uint16(udp[2:4]) != dnsPort {
		return dnsQuery{}, false
	}
	// The UDP length field covers header + payload. Trust the SHORTER of it
	// and the bytes actually present, never the field alone: a length field
	// larger than the buffer is the classic parsing differential winn3/tun's
	// ip.go warns about, and one smaller is a padded datagram whose tail is
	// not part of the message.
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < udpHeaderBytes || udpLen > len(udp) {
		return dnsQuery{}, false
	}
	payload := udp[udpHeaderBytes:udpLen]
	if len(payload) < dnsHeaderBytes {
		return dnsQuery{}, false
	}
	if payload[2]&0x80 != 0 {
		// QR set: this is a response, not a query.
		return dnsQuery{}, false
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	if src == r.ours {
		// Would violate the outbound rule dst != ours on the way back, and
		// cannot arise from a validated inbound packet (ErrReflected catches
		// it first). Refused here rather than trusted.
		return dnsQuery{}, false
	}
	if binary.BigEndian.Uint16(udp[0:2]) == 0 {
		// A client source port of 0 cannot receive a reply on the wire (port 0
		// is never a valid bind port), so a claimed query from it could only
		// produce a reply destined for a port that does not exist. Refuse.
		return dnsQuery{}, false
	}
	// Copy the payload: pkt belongs to the delivery path's buffer and is
	// reused the moment this returns, while the query outlives this call by
	// the whole upstream round trip.
	out := make([]byte, len(payload))
	copy(out, payload)
	return dnsQuery{
		client:     src,
		clientPort: binary.BigEndian.Uint16(udp[0:2]),
		payload:    out,
	}, true
}

// exchange performs one upstream round trip and returns the answer's DNS
// payload.
//
// One ephemeral connected socket per query, deliberately. A connected UDP
// socket makes the kernel drop any datagram not from the upstream, which is
// the off-path spoofing defence; a single shared socket would need transaction
// demultiplexing in this file and would give a spoofer one target instead of
// one per query. The transaction-ID check below is a second, cheap layer on
// top of that and not a substitute for it.
func (r *gatewayResolver) exchange(payload []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(r.upstream))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(r.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsUpstreamReadCap)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= dnsUpstreamReadCap {
			// buf filled to capacity, so the datagram did not fit. This is
			// exactly the silent truncation dnsUpstreamReadCap exists to
			// prevent: a larger datagram is cut off at Read's buffer bound and
			// returned as n==4096, err==nil, which would be delivered as a
			// complete answer with a checksum over truncated bytes. Treat it
			// as "does not fit" so it always takes the TC path. TC-ing a
			// legitimately-exactly-4096-byte answer is harmlessly conservative.
			return nil, errDNSReplyTooLarge
		}
		if n < dnsHeaderBytes {
			// Too short to be a DNS message. Keep reading until the deadline
			// rather than failing the query on one runt datagram.
			continue
		}
		if buf[0] != payload[0] || buf[1] != payload[1] {
			// Transaction ID mismatch. Same reasoning: do not let one
			// mismatched datagram end an exchange whose real answer may still
			// be in flight.
			continue
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, nil
	}
}

// dnsQuestionSectionEnd returns the offset just past a message's single
// question section.
//
// Bounded label walking and nothing else: no compression pointers are
// followed, and a length byte with either high bit set (0xC0 pointer, 0x80
// reserved) refuses outright. A question section never legitimately carries a
// pointer, so refusing is not a limitation -- it is the parser declining to
// implement the feature that turns DNS parsers into infinite loops.
//
// Refuses any message whose QDCOUNT is not exactly 1, because everything that
// calls this needs to COPY the question back and a count it did not verify is
// a count it would copy wrong.
func dnsQuestionSectionEnd(msg []byte) (int, bool) {
	if len(msg) < dnsHeaderBytes {
		return 0, false
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return 0, false
	}
	i := dnsHeaderBytes
	for {
		if i >= len(msg) {
			return 0, false
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 != 0 {
			return 0, false
		}
		i += 1 + l
		if i > len(msg) {
			return 0, false
		}
	}
	// QTYPE and QCLASS.
	if i+4 > len(msg) {
		return 0, false
	}
	return i + 4, true
}

// dnsTruncatedAnswer synthesises a TC=1 response to query, for the case where
// the real answer will not fit the inner MTU.
//
// Built from the QUERY rather than from the oversize answer, because the query
// is the message this process received intact and the answer is the one it has
// decided it cannot carry. The result is a header plus the question, with
// every section count but QDCOUNT zeroed -- which is what TC=1 means and is
// the only shape that cannot claim data it is not carrying.
//
// # The limitation this makes visible, and how TCP closes it
//
// TC=1 tells a client to retry over TCP/53. claim() still takes UDP only:
// TCP SYNs must reach the kernel, not this wrapper, so the listener in
// resolve_tcp.go can accept them. That listener exists only when -forward
// and -resolver are both on; reflector mode has no host address for
// -inner-v4, so Truncated stays the visibility there. An EDNS0 clamp is
// not a substitute: it only moves which box truncates.
func dnsTruncatedAnswer(query []byte) ([]byte, bool) {
	out, ok := dnsSynthesisedResponse(query)
	if !ok {
		return nil, false
	}
	// TC=1, the one bit that distinguishes this from the shared shell. Byte 3's
	// RCODE stays 0 (NOERROR): a truncated answer carries no error, because the
	// answer exists and merely does not fit.
	out[2] |= 0x02
	return out, true
}

// dnsSynthesisedResponse builds the message shell that every response this file
// synthesises has in common: the header plus the question echoed back verbatim,
// with QR set, RA set, the query's CD echoed, and every section count but
// QDCOUNT zeroed.
//
// Factored out of dnsTruncatedAnswer so the SERVFAIL path REUSES the exact
// question-echoing and header construction that was already reviewed, rather
// than growing a second encoder that could drift from it. Its two callers differ
// by one bit each: TC in byte 2 for truncation, RCODE in byte 3 for SERVFAIL.
//
// The byte layout, confirmed against RFC 1035 section 4.1.1 rather than assumed:
//
//	byte 2: QR(0x80) Opcode(0x78) AA(0x04) TC(0x02) RD(0x01)
//	byte 3: RA(0x80) Z(0x40) AD(0x20) CD(0x10) RCODE(0x0f)
//
// so masking the query's byte 2 with 0x79 keeps exactly the opcode and RD while
// clearing AA and TC.
func dnsSynthesisedResponse(query []byte) ([]byte, bool) {
	end, ok := dnsQuestionSectionEnd(query)
	if !ok {
		return nil, false
	}
	out := make([]byte, end)
	copy(out, query[:end])
	// Byte 2: QR=1, opcode and RD preserved from the query, AA=0, TC=0.
	out[2] = (query[2] & 0x79) | 0x80
	// Byte 3: RA=1, Z=0, RCODE=0. The CD bit (0x10) from the query is echoed so
	// a client that set checking-disabled keeps its own stated policy rather
	// than having the responder silently clear it.
	out[3] = 0x80 | (query[3] & 0x10)
	// QDCOUNT stays as copied (verified to be 1); the rest carry nothing.
	binary.BigEndian.PutUint16(out[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT
	return out, true
}

// dnsServFailAnswer synthesises a SERVFAIL (RCODE=2) response to query, for the
// case where the upstream exchange failed and there is no answer to relay.
//
// # Why an upstream failure must be answered at all
//
// The alternative, and what this responder did before, is to count the failure
// and return -- so the client hears NOTHING. In a censorship-circumvention
// product silence is indistinguishable from blocking: it is the exact
// observation a censor's drop produces, and here it happened under a green
// "Connected" light for every name. A stub that hears nothing waits out its own
// timeout and then usually retries the same dead upstream, so one unreachable
// resolver becomes a multi-second stall per name rather than a fast, legible
// failure.
//
// SERVFAIL is what a real recursor returns once its own timeout budget is spent,
// so it is the answer a stub already knows how to handle: fail this name now,
// move to the next configured resolver if there is one. It converts a slow
// stub-timeout cascade into a fast diagnosable failure, and inside the sealed
// session it discloses nothing to anyone off-path -- the reply travels the same
// encrypted datapath as any other answer, and this file still logs nothing per
// query.
//
// # What it is NOT
//
// Not TC=1. Truncation says "the answer exists, retry over TCP"; an upstream
// failure is not a truncation, and a TC-flavoured SERVFAIL would send the stub
// to TCP/53 instead of reporting the failure. Not NXDOMAIN either: that would
// assert the name does
// not exist, which this responder has no basis to claim and which stubs and
// browsers cache as a negative result. SERVFAIL asserts only "this server could
// not answer", which is precisely what happened and is not cached as truth about
// the name.
//
// The in-flight-cap refusal deliberately does NOT come here; see WritePacket.
func dnsServFailAnswer(query []byte) ([]byte, bool) {
	out, ok := dnsSynthesisedResponse(query)
	if !ok {
		return nil, false
	}
	// RCODE=2 (SERVFAIL) in the low nibble of byte 3. Written as an explicit
	// clear-then-set rather than a bare OR so it still states RCODE=2 exactly if
	// the shared shell ever stops guaranteeing a zero nibble. TC stays 0.
	out[3] = (out[3] &^ 0x0f) | 0x02
	return out, true
}

// buildReply wraps a DNS payload in the UDP and IPv4 headers that make it a
// legal outbound packet for winn3/tun: sourced from this endpoint's own
// assignment, addressed to the client that asked. See this file's header for
// why the source address is not a free choice.
func (r *gatewayResolver) buildReply(q dnsQuery, payload []byte) []byte {
	total := ipv4HeaderMinBytes + udpHeaderBytes + len(payload)
	pkt := make([]byte, total)

	pkt[0] = 0x45 // IPv4, IHL 5
	pkt[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(r.nextID(q.client)))
	// DF set, fragment offset 0. This responder never fragments: an answer
	// that would not fit is answered TC=1 instead, so DF is a statement of
	// fact rather than a request to the network.
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64 // TTL
	pkt[9] = ipProtoUDP
	// pkt[10:12] checksum, filled below.
	ours := r.ours.As4()
	client := q.client.As4()
	copy(pkt[12:16], ours[:])
	copy(pkt[16:20], client[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:ipv4HeaderMinBytes]))

	udp := pkt[ipv4HeaderMinBytes:]
	binary.BigEndian.PutUint16(udp[0:2], dnsPort)
	binary.BigEndian.PutUint16(udp[2:4], q.clientPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderBytes+len(payload)))
	copy(udp[udpHeaderBytes:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(r.ours, q.client, udp))
	return pkt
}

// udpChecksum computes the IPv4 UDP checksum over the pseudo-header and the
// datagram.
//
// The checksum field inside udp must be zero on entry. A computed zero is
// transmitted as 0xffff, because zero is the on-the-wire encoding for "no
// checksum" and this responder always has one. Optional though it is for IPv4,
// it is computed: a client stack that validates it and finds it wrong drops
// the answer silently, which is the least diagnosable failure available.
func udpChecksum(src, dst netip.Addr, udp []byte) uint16 {
	var sum uint32
	s := src.As4()
	d := dst.As4()
	for _, b := range [][]byte{s[:], d[:]} {
		sum += uint32(binary.BigEndian.Uint16(b[0:2]))
		sum += uint32(binary.BigEndian.Uint16(b[2:4]))
	}
	sum += uint32(ipProtoUDP)
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	out := ^uint16(sum)
	if out == 0 {
		return 0xffff
	}
	return out
}

// resolverDevice is the tun.Device wrapper that puts the responder in front of
// whichever backend this gateway is running: the reflector, or the -forward
// mode kernel device.
//
// # Why a wrapper and not a branch inside each backend
//
// The two backends disagree about almost everything -- one answers in process,
// the other hands packets to a kernel interface and gets replies back through
// driver.Loop.SendInner -- but they agree about the one thing this needs: a
// packet addressed to -inner-v4 UDP/53 is not traffic either of them should
// see. Wrapping keeps reflect.go and forward.go byte-for-byte unchanged, which
// matters because reflect.go's claim about itself ("forwards nothing, resolves
// nothing and egresses nothing") is pinned in winn3/conform/conform.go and is
// still exactly true of the reflector: this responder is not the reflector.
//
// # The read side
//
// ReadPacket must merge two sources -- this responder's replies and whatever
// the wrapped device produces -- and tun.Device gives no way to select across
// a blocking ReadPacket. So one pump goroutine drains the wrapped device into
// the same inbox the responder queues into. In -forward mode that pump parks
// forever on gatewayForwardDevice.ReadPacket and exits at Close, which is
// correct and costs one idle goroutine; in reflector mode it relays.
//
// Either way every reply leaving here is validated by winn3/tun's outbound
// rule exactly as before. Nothing about this wrapper bypasses that check, and
// that is the property that makes it safe to put in the delivery path.
type resolverDevice struct {
	inner closableDevice
	res   *gatewayResolver
	mtu   int

	// authorize, when non-nil, reports whether this session's authenticated
	// peer is currently authorized for a query's inner source address. It is
	// set only in registry-backed -forward mode (see newResolverDevice) and is
	// consulted before the upstream exchange and again before delivery.
	authorize func(client netip.Addr) bool
	bandwidth func(client netip.Addr, n int, down bool) bool

	inbox chan resolverInboxItem
	done  chan struct{}

	closeOnce sync.Once
}

// resolverInboxItem is one packet waiting for ReadPacket. client is the
// querying inner address for this responder's own replies and is invalid for
// packets relayed from the wrapped device, which are not DNS replies.
type resolverInboxItem struct {
	pkt    []byte
	client netip.Addr
}

// authorized applies the session's registry authorization to client. With no
// registry (reflector mode, or -forward without one, which validateForwardMode
// refuses) there is nothing to apply.
func (d *resolverDevice) authorized(client netip.Addr) bool {
	return d.authorize == nil || d.authorize(client)
}

var _ closableDevice = (*resolverDevice)(nil)

func newResolverDevice(inner closableDevice, res *gatewayResolver, mtu int) *resolverDevice {
	d := &resolverDevice{
		inner: inner,
		res:   res,
		mtu:   mtu,
		inbox: make(chan resolverInboxItem, resolverInboxDepth),
		done:  make(chan struct{}),
	}
	// Registry-backed -forward mode: DNS is held to the same authorization as
	// forwarding. Without this the resolver claimed UDP/53 BEFORE the forward
	// device's registry check ran, so a revoked peer kept a working resolver
	// (and a DNS channel to the internet) for as long as its session lived.
	// The check is bound to the authenticated session peer and its permitted
	// inner address, never to the query's source address alone.
	if fd, ok := inner.(*gatewayForwardDevice); ok && fd.registry != nil {
		d.authorize = fd.authorizesSource
		d.bandwidth = fd.allowSourcePacket
	}
	go d.pump()
	return d
}

// pump relays the wrapped device's read side into the shared inbox. It exits
// on the wrapped device's first read error, which Close guarantees by closing
// the wrapped device.
func (d *resolverDevice) pump() {
	buf := make([]byte, tun.MaxIPPacket)
	for {
		n, err := d.inner.ReadPacket(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if !d.queue(resolverInboxItem{pkt: pkt}) {
			// The relay path hit a full inbox. Counted separately from the
			// resolver's own drops so a busy relay is never misread as DNS
			// answers this responder dropped.
			d.res.relayDropped.Add(1)
		}
	}
}

// queue offers a packet to the inbox and reports whether it was admitted,
// dropping rather than blocking. See reflectorDepth: the queuing side is a
// session's delivery path and must never stall. The caller owns the counter to
// bump on a drop, so a drop in the resolver's own delivery path and a drop in
// the wrapped device's relay path are counted distinctly (see relayDropped).
func (d *resolverDevice) queue(item resolverInboxItem) bool {
	select {
	case <-d.done:
		return false
	default:
	}
	select {
	case d.inbox <- item:
		return true
	default:
		return false
	}
}

// replyOutcome is what queueReply did with one of this responder's replies.
type replyOutcome int

const (
	replyQueued replyOutcome = iota
	replyDropped
	replySuppressed
)

// queueReply queues one reply to q, upstream or synthesised, unless the
// session's authorization for q.client has been withdrawn since the query.
// A suppression is counted here; queued and dropped are the caller's to count.
func (d *resolverDevice) queueReply(q dnsQuery, reply []byte) replyOutcome {
	if !d.authorized(q.client) {
		d.res.suppressed.Add(1)
		return replySuppressed
	}
	if d.queue(resolverInboxItem{pkt: reply, client: q.client}) {
		return replyQueued
	}
	return replyDropped
}

// WritePacket claims DNS queries addressed to this endpoint and passes
// everything else through untouched.
//
// It returns len(pkt) for a claimed query for the reason reflector.WritePacket
// gives: the return value is the DEVICE's contract, "the host took these
// bytes", and is not a statement about whether a reply was produced.
//
// # Why the in-flight refusals below stay silent, when an upstream failure does not
//
// These two arms look alike and must not be collapsed. An upstream failure is
// TERMINAL for that query: it was put to the upstream and the upstream did not
// answer, so retrying it immediately gets the same nothing, and SERVFAIL is the
// honest report (see dnsServFailAnswer). A cap refusal is the opposite -- the
// query was never sent anywhere, the condition is transient local overload, and
// the very next attempt may succeed. Answering SERVFAIL here would tell a stub
// to give up on, or fail over from, a name that would have resolved a moment
// later, converting this gateway's own backpressure into an apparent resolution
// failure. Dropping is what makes the client's existing retry the right move,
// which is the same reasoning dnsDefaultMaxInFlight gives for refusing rather
// than queueing.
func (d *resolverDevice) WritePacket(pkt []byte) (int, error) {
	q, ok := d.res.claim(pkt)
	if !ok {
		return d.inner.WritePacket(pkt)
	}
	d.res.claimed.Add(1)
	// Authorization before anything is spent on the query, and silent toward
	// the peer: an unauthorized session gets no resolver at all.
	if !d.authorized(q.client) {
		d.res.unauthorized.Add(1)
		return len(pkt), nil
	}
	if d.bandwidth != nil && !d.bandwidth(q.client, len(pkt), false) {
		return len(pkt), nil
	}
	// Per-session share first: an over-share session is refused without
	// consuming a process-wide token, so it cannot starve the other sessions
	// that share dnsDefaultMaxInFlight. See dnsDefaultMaxInFlightPerClient.
	if !d.res.acquireClient(q.client) {
		d.res.refused.Add(1)
		return len(pkt), nil
	}
	select {
	case d.res.sem <- struct{}{}:
	default:
		d.res.releaseClient(q.client)
		d.res.refused.Add(1)
		return len(pkt), nil
	}
	go d.answer(q)
	return len(pkt), nil
}

// answer runs one upstream exchange and queues the reply.
//
// It is not waited for at Close. The socket deadline bounds it to
// gatewayResolver.timeout, and queue() drops once done is closed, so the
// goroutine cannot outlive the timeout and cannot deliver into a closed
// session. Waiting would make session teardown block for up to that timeout on
// an upstream that has already stopped answering, which is the failure mode
// this gateway is least able to afford.
func (d *resolverDevice) answer(q dnsQuery) {
	defer func() {
		<-d.res.sem
		d.res.releaseClient(q.client)
	}()

	// Re-check at dispatch: authorization can be withdrawn between WritePacket
	// and this goroutine running, and no upstream exchange may start for a
	// peer the registry no longer authorizes.
	if !d.authorized(q.client) {
		d.res.unauthorized.Add(1)
		return
	}
	answer, err := d.res.exchange(q.payload)
	if err != nil {
		if errors.Is(err, errDNSReplyTooLarge) {
			// The upstream answered but the reply would not even fit the read
			// cap, so it can never fit the inner MTU. Same TC=1 path as an
			// oversize-but-readable answer.
			d.emitTruncated(q)
			return
		}
		// The upstream produced no usable answer. Count it, then TELL THE
		// CLIENT: a counter the client cannot see is not a reply, and silence
		// here is the one failure mode this product exists to prevent. See
		// dnsServFailAnswer for why SERVFAIL and not TC=1, NXDOMAIN or nothing.
		d.res.upstreamFailed.Add(1)
		d.emitServFail(q)
		return
	}
	if len(answer) > d.mtu-ipv4HeaderMinBytes-udpHeaderBytes {
		d.emitTruncated(q)
		return
	}
	switch d.queueReply(q, d.res.buildReply(q, answer)) {
	case replyQueued:
		d.res.answered.Add(1)
	case replyDropped:
		// A full inbox is a drop, not an answer: a query must not be counted
		// as both Answered and Dropped in the same breath.
		d.res.dropped.Add(1)
	}
}

// emitTruncated synthesises and queues a TC=1 answer for a query whose real
// answer cannot be carried, whether because it exceeds the inner MTU budget or
// because it exceeded dnsUpstreamReadCap entirely. Counts Truncated on success
// and Dropped when the truncated reply cannot be queued or synthesised.
func (d *resolverDevice) emitTruncated(q dnsQuery) {
	budget := d.mtu - ipv4HeaderMinBytes - udpHeaderBytes
	if budget <= 0 {
		d.res.dropped.Add(1)
		return
	}
	truncated, ok := dnsTruncatedAnswer(q.payload)
	if !ok || len(truncated) > budget {
		d.res.dropped.Add(1)
		return
	}
	switch d.queueReply(q, d.res.buildReply(q, truncated)) {
	case replyQueued:
		d.res.truncated.Add(1)
	case replyDropped:
		d.res.dropped.Add(1)
	}
}

// emitServFail synthesises and queues a SERVFAIL for a query whose upstream
// exchange failed, so the client hears a fast, legible failure instead of
// nothing at all.
//
// # Counters
//
// Deliberately bumps no counter of its own on success. The caller has already
// counted the event in UpstreamFailed, which keeps its established meaning
// ("exchanges that produced no usable answer") -- this only changes what the
// CLIENT hears, never what the operator's status document reports, so no
// existing reading of resolverStats is invalidated. On failure to synthesise or
// queue it counts Dropped, exactly as emitTruncated does for the same two
// conditions.
//
// The budget check mirrors emitTruncated's and is not redundant: a SERVFAIL is
// header plus question, which is small, but "small" is a property of the
// question a client sent and this responder does not get to assume it.
func (d *resolverDevice) emitServFail(q dnsQuery) {
	budget := d.mtu - ipv4HeaderMinBytes - udpHeaderBytes
	if budget <= 0 {
		d.res.dropped.Add(1)
		return
	}
	servfail, ok := dnsServFailAnswer(q.payload)
	if !ok || len(servfail) > budget {
		d.res.dropped.Add(1)
		return
	}
	if d.queueReply(q, d.res.buildReply(q, servfail)) == replyDropped {
		d.res.dropped.Add(1)
	}
}

// ReadPacket returns the next reply, from either source. See the type doc.
//
// A reply of this responder's own whose authorization was withdrawn while it
// waited in the inbox is suppressed here, at the last point before delivery.
func (d *resolverDevice) ReadPacket(buf []byte) (int, error) {
	for {
		select {
		case item := <-d.inbox:
			if item.client.IsValid() && !d.authorized(item.client) {
				d.res.suppressed.Add(1)
				continue
			}
			if item.client.IsValid() && d.bandwidth != nil && !d.bandwidth(item.client, len(item.pkt), true) {
				continue
			}
			if len(item.pkt) > len(buf) {
				return 0, errors.New("resolver device: reply exceeds the read buffer")
			}
			return copy(buf, item.pkt), nil
		case <-d.done:
			return 0, errResolverDeviceClosed
		}
	}
}

// MTU reports the wrapped device's MTU unchanged. This wrapper adds no
// encapsulation.
func (d *resolverDevice) MTU() int { return d.inner.MTU() }

// Close closes the wrapped device first, which is what unblocks the pump, then
// unblocks any parked ReadPacket.
func (d *resolverDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.inner.Close()
		close(d.done)
	})
	return err
}

// validateResolverMode refuses a -resolver configuration that could not work,
// before the socket exists and while the operator is still standing there.
//
// Every refusal here is a value this binary CAN check. The one it cannot is
// whether the upstream actually answers, and no amount of flag validation
// substitutes for that; resolverStats.UpstreamFailed is where that shows up.
func validateResolverMode(opts serveOptions, assign tun.Assignment) (netip.AddrPort, error) {
	// Never silently ignore an operator's stated configuration: -resolver-upstream
	// and -resolver-timeout do nothing without -resolver, and a non-default
	// value set that way is noise that should have been a refusal (this tree's
	// stated bar, matching validateForwardMode refusing to imply
	// -accept-transit). Refuse rather than let two flags look configured while
	// being inert.
	if !opts.resolver {
		if opts.resolverUpstream != "" {
			return netip.AddrPort{}, errors.New(
				"-resolver-upstream is set but -resolver is not; the upstream value would be ignored. Set -resolver, or unset it")
		}
		// Only an override of the flag's own default (dnsDefaultTimeout) is a
		// real operator statement. The zero value is not one: it is what the
		// flag parser never produces, and what callers that construct
		// serveOptions directly leave as "unspecified". A non-zero, non-default
		// timeout set without -resolver is the inert flag this refuses.
		if opts.resolverTimeout != 0 && opts.resolverTimeout != dnsDefaultTimeout {
			return netip.AddrPort{}, fmt.Errorf(
				"-resolver-timeout %s is set but -resolver is not; the value would be ignored. Set -resolver, or unset it",
				opts.resolverTimeout)
		}
		return netip.AddrPort{}, nil
	}
	if opts.resolverTimeout <= 0 {
		return netip.AddrPort{}, fmt.Errorf(
			"-resolver-timeout %s is not positive; this value is not silently replaced with a default (see resolve.go)",
			opts.resolverTimeout)
	}
	if !assign.V4.IsValid() {
		return netip.AddrPort{}, errors.New(
			"-resolver needs -inner-v4: this responder answers at THIS END'S inner address and " +
				"nowhere else, because winn3/tun's outbound rule requires a reply's source to be " +
				"exactly this endpoint's assignment (see resolve.go)")
	}
	raw := opts.resolverUpstream
	if raw == "" {
		return netip.AddrPort{}, errors.New(
			"-resolver is set but -resolver-upstream is empty, and this flag will not default it: " +
				"the upstream sees every name every session looks up, so which resolver that is has " +
				"to be an operator's stated decision and never a built-in")
	}
	upstream, err := netip.ParseAddrPort(raw)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf(
			"-resolver-upstream %q must be a literal address:port such as 10.8.1.1:53 (%w). A "+
				"hostname would have to be resolved before this resolver could resolve anything, "+
				"which is the bootstrap lookup [winn] endpoint refuses for the same reason", raw, err)
	}
	if !upstream.Addr().Is4() {
		return netip.AddrPort{}, fmt.Errorf(
			"-resolver-upstream %s is not IPv4; this responder carries IPv4 only", upstream)
	}
	if upstream.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf(
			"-resolver-upstream %s names port 0; state the port explicitly, normally 53", upstream)
	}
	if upstream.Addr() == assign.V4 {
		return netip.AddrPort{}, fmt.Errorf(
			"-resolver-upstream %s is this gateway's own -inner-v4: the responder would forward "+
				"every query to itself. The upstream must be reachable from the HOST, off-tunnel, "+
				"not through the tunnel this process serves", upstream)
	}
	if assign.RouterV4.IsValid() && upstream.Addr() == assign.RouterV4 {
		return netip.AddrPort{}, fmt.Errorf(
			"-resolver-upstream %s is -router-v4, the inner next hop; nothing answers queries there", upstream)
	}
	if opts.forward && opts.forwardCIDR != "" {
		prefix, perr := netip.ParsePrefix(opts.forwardCIDR)
		if perr == nil && prefix.Contains(upstream.Addr()) {
			return netip.AddrPort{}, fmt.Errorf(
				"-resolver-upstream %s is inside -forward-cidr %s, the tunnel's own inner subnet. "+
					"This process reaches its upstream from the HOST's network namespace, where that "+
					"subnet belongs to clients, so the query would be routed back into a tunnel "+
					"instead of out to a resolver", upstream, opts.forwardCIDR)
		}
	}
	return upstream, nil
}

// resolverDerivationWarning names the one way a correct -resolver setup still
// ends up underivable BY THE CLIENT, or "" when this binary can see no such
// problem. It returns a warning rather than a refusal because nothing this
// process does today is advertised to any client: see the -resolver flag help.
//
// # The trap
//
// Every client platform derives "is this resolver inside my tunnel" the same
// way, and the conservative floor is a /24 around the client's OWN assignment:
// Apple WinsWinn3Resolvers.notInnerReason's last clause, Android
// WinnV3Resolvers.sameInnerBlock, which is literally
// `(a and 0xFFFFFF00L) == (b and 0xFFFFFF00L)`. The reason is stated in
// Apple's own comment -- the descriptor carries the assignment as a bare
// address with NO PREFIX, so a /24 is the narrowest inner space a host can
// name without inventing a number on the wire.
//
// The hub, meanwhile, allocates client inner addresses out of
// WINN3_INNER_POOL_CIDR, whose default is a /16
// (server/wins_control_plane_setup_ONETOUCH.sh, allocate_winn3_inner_ip walks
// pool.hosts() in order). A /16 pool and a /24 derivation floor do not
// disagree until the pool spills past its first /24 -- and then they disagree
// silently and only for the clients that spilled. With this responder at
// 10.10.0.1, the first ~253 devices sit in 10.10.0.0/24 and can derive it;
// device 254 lands in 10.10.1.x and cannot, and the refusal it gets says
// nothing about allocation order because nothing on the client knows about
// allocation order.
//
// This binary cannot see WINN3_INNER_POOL_CIDR. -forward-cidr is the only
// place the same subnet is stated to this process, and its own flag help says
// it must be the subnet the control plane assigns from -- so it is the one
// value here that can expose the mismatch, and only when -forward is also on.
func resolverDerivationWarning(opts serveOptions, assign tun.Assignment) string {
	if !opts.resolver || opts.forwardCIDR == "" || !assign.V4.Is4() {
		return ""
	}
	prefix, err := netip.ParsePrefix(opts.forwardCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() >= 24 {
		return ""
	}
	ours := assign.V4.As4()
	return fmt.Sprintf(
		"-forward-cidr %s is wider than a /24, and every client platform derives "+
			"\"this resolver is inside my tunnel\" against a /24 around its OWN inner_v4 "+
			"(Apple notInnerReason's last clause, Android sameInnerBlock). This responder "+
			"answers at %s, so only clients allocated inside %d.%d.%d.0/24 could ever derive "+
			"it; any client the hub allocates outside that /24 would refuse the resolver even "+
			"though it answers. Either keep the allocation pool inside one /24, or settle the "+
			"descriptor field so the resolver address is stated rather than derived.",
		opts.forwardCIDR, assign.V4, ours[0], ours[1], ours[2])
}
