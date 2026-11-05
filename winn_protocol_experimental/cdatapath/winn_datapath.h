/*
 * winn_datapath.h - Winn Protocol v3 in-process datapath, C ABI.
 *
 * This is the CURATED companion to the header cgo generates beside
 * libwinn_datapath.a. Both declare the same symbols; this one additionally
 * carries the status codes, the ownership rules and the buffer sizing that a
 * generated header cannot express. An Objective-C or Swift wrapper should
 * include THIS file and link the archive.
 *
 * Build the archive with:
 *   tools/build_winn_protocol_engine.sh datapath-ios-arm64    <out>/libwinn_datapath.a
 *   tools/build_winn_protocol_engine.sh datapath-darwin-arm64 <out>/libwinn_datapath.a
 *
 * WHAT THIS CARRIES, AND WHAT IT DOES NOT.
 *
 * The bytes crossing WinnTunnelWriteInbound and WinnTunnelReadOutbound are
 * AmneziaWG OUTER DATAGRAMS: exactly what the host's own AWG engine would
 * otherwise have sent to, and received from, the gateway's UDP endpoint. They
 * are NOT raw IP packets off the tun device. This archive contains no
 * AmneziaWG implementation; it carries already-encapsulated datagrams over the
 * Winn carrier. Set "payload":"awg-datagram" in the configuration. The value
 * "ip-packet" is refused at create time, deliberately, because forwarding a
 * raw tun packet here would put cleartext on the wire.
 *
 * Placement in an NEPacketTunnelProvider:
 *
 *   packetFlow  <->  the host's AWG engine (libwg-go.a)  <->  THIS  <->  network
 *
 * MEMORY. Every char* returned by this archive is heap-allocated here and MUST
 * be released with WinnTunnelFreeString. This matches the WinnFreeString
 * contract in the existing clientbinding shared library exactly. NULL is never
 * used to report success.
 *
 * THREADING. WinnTunnelWriteInbound and WinnTunnelReadOutbound may be called
 * concurrently from different threads, and both are safe against a concurrent
 * WinnTunnelClose. A blocking WinnTunnelReadOutbound returns
 * WINN_TUNNEL_ERR_CLOSED promptly when the tunnel is closed, so a reader thread
 * never has to be killed.
 *
 * CARRIERS. WinnTunnelCreate builds "direct-awg" only: it takes a plain C
 * string and nothing a dialer could be built from. WinnTunnelCreateWithCarrier
 * is the additive second entry point for a carrier that needs an authenticated
 * configuration -- currently "http3-connect-udp" (MASQUE) -- delivered as a
 * SECOND C string, a carrierhost.Profile document, alongside the same
 * datapath.Config configJSON the first entry point takes. This does not hand a
 * dialer across the boundary -- cgo has no way to do that, and nothing here
 * tries -- it hands the DOCUMENT the dialer is built from, entirely on the Go
 * side of the call, exactly as configJSON already crosses for direct-awg. See
 * WinnTunnelCreateWithCarrier below and datapath/carrierhost/profile.go for
 * why the document itself carries no key material and is safe to move this
 * way: every credential is named by path and opened by this process, never by
 * the caller.
 */

#ifndef WINN_DATAPATH_H
#define WINN_DATAPATH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The contract string this header was written against. Compare it with
 * WinnTunnelContractVersion() at startup and refuse to proceed on a mismatch;
 * a wrapper built for a different contract is a silent-corruption risk, not a
 * warning.
 */
#define WINN_TUNNEL_CONTRACT_VERSION "winn-datapath/1"

/*
 * Negative status codes. These are the ONLY negative values
 * WinnTunnelWriteInbound and WinnTunnelReadOutbound can return; anything >= 0
 * is a byte count.
 */
#define WINN_TUNNEL_ERR_HANDLE    (-1) /* no such handle                     */
#define WINN_TUNNEL_ERR_CLOSED    (-2) /* the tunnel is closed               */
#define WINN_TUNNEL_ERR_TIMEOUT   (-3) /* timeout expired, no datagram       */
#define WINN_TUNNEL_ERR_TOO_LARGE (-4) /* buffer too small, datagram dropped */
#define WINN_TUNNEL_ERR_CARRIER   (-5) /* terminal carrier failure           */
#define WINN_TUNNEL_ERR_ARGUMENT  (-6) /* NULL buffer or non-positive size   */

/* Release a string returned by any function in this header. NULL is a no-op. */
extern void WinnTunnelFreeString(char *value);

/* Contract version of the archive itself. Caller frees. */
extern char *WinnTunnelContractVersion(void);

/* Winn v3 connectivity contract version, e.g. "winn/3". Caller frees. */
extern char *WinnTunnelProtocolVersion(void);

/*
 * Largest datagram any configuration may permit. Size read buffers with this
 * rather than a guessed MTU: a buffer smaller than the datagram that arrives
 * yields WINN_TUNNEL_ERR_TOO_LARGE and the datagram is lost.
 */
extern int WinnTunnelMaxDatagram(void);

/*
 * Create one tunnel.
 *
 * configJSON  the datapath configuration, for example:
 *
 *   {"contract":"winn-datapath/1",
 *    "payload":"awg-datagram",
 *    "carrier":"direct-awg",
 *    "gateway_endpoint":"203.0.113.9:51820",
 *    "max_datagram":1350,
 *    "session_id":"<opaque>"}
 *
 *   gateway_endpoint must be an IP literal with a port. A hostname is refused,
 *   because resolving one here would leak a DNS lookup outside the tunnel.
 *
 *   "carrier" must be "direct-awg" through THIS C surface. The Go package also
 *   implements the "http3-connect-udp" (MASQUE) and "http2-stream" carriers,
 *   and both of them ride a caller-supplied, already-protected socket exactly
 *   as direct-awg does — they are not refused for lack of protection. What they
 *   need is an authenticated carrier configuration (URI template or HTTPS URL,
 *   public target, device identity or anonymous credential source, TLS suite,
 *   response verifier) that has no business crossing a C string. A Go host
 *   builds the dialer itself and calls datapath.OpenWithCarrier; asking for
 *   either carrier here is refused with that reason rather than ignored.
 *
 * udpFD       a UDP socket descriptor the host has already prepared. THE
 *             ENGINE TAKES OWNERSHIP and closes it in WinnTunnelClose; the
 *             caller must not close it. Pass -1 to let the engine open its
 *             own socket, which it does only if the configuration sets
 *             "allow_own_socket":true.
 *
 * errorOut    on failure receives an allocated message the caller must free.
 *             On success it is set to NULL.
 *
 * Returns a handle > 0, or 0 on failure. Handles are never reused.
 */
extern long long WinnTunnelCreate(char *configJSON, int udpFD, char **errorOut);

/*
 * Hand one datagram from the host to the protocol (host side -> gateway).
 * Returns the byte count, or a negative WINN_TUNNEL_ERR_* code. The buffer is
 * not retained past the call.
 */
extern int WinnTunnelWriteInbound(long long handle, char *buffer, int length);

/*
 * Take one datagram from the protocol for the host (gateway -> host side).
 * timeoutMS <= 0 blocks until a datagram arrives, the tunnel closes, or the
 * carrier fails. Returns the byte count, or a negative WINN_TUNNEL_ERR_* code.
 */
extern int WinnTunnelReadOutbound(long long handle, char *buffer, int capacity,
                                  int timeoutMS);

/*
 * Machine-readable status as JSON. Caller frees. Never returns NULL: an
 * unknown handle yields a JSON object saying so.
 *
 * Check "socket_owned_by_engine": on a platform where the host must supply a
 * protected socket, a true here means the descriptor was never handed over.
 *
 * DO NOT GATE ROUTE PROMOTION ON "up".
 *
 *   "up"  means only that the engine is open and the carrier socket has not
 *         failed. It is link liveness. It is true for a socket that has never
 *         carried a byte.
 *
 * Gate on "transport_observed_both_ways", backed by the monotonic counters
 * "rx_transport_payload_datagrams" and "tx_transport_payload_datagrams". Those
 * move only when a datagram carrying the AmneziaWG transport-data header type,
 * larger than a bare 32-byte keepalive, crossed the carrier in that direction —
 * and inbound only from the configured gateway endpoint. A peer cannot produce
 * transport-data messages without having completed the handshake and derived
 * transport keys.
 *
 * There is deliberately NO "handshake_completed" field. This archive carries
 * AmneziaWG datagrams opaquely: it holds no keys and verifies no authentication
 * tag, so every field above is a header-type comparison on bytes it cannot
 * decrypt. An on-path replay from the gateway's address moves the same
 * counters. The authoritative handshake signal is the host's own AWG engine.
 * The correct gate is the conjunction of both:
 *
 *   transport_observed_both_ways  AND  hostAWGEngine.latestHandshake is recent
 *
 * Classification needs the signed AmneziaWG values, passed in the configuration
 * as "awg_header_types":{"h1":...,"h2":...,"h3":...,"h4":...,
 *                        "s1":...,"s2":...,"s3":...,"s4":...}.
 * Without them the engine falls back to plain WireGuard 1..4 and reports
 * "awg_classification":"wireguard-default-1234", under which obfuscated traffic
 * classifies as nothing. That string together with zero transport counters is a
 * configuration gap, not a dead tunnel.
 *
 * SUPPLY s1, s2, s3 AND s4 WHENEVER THE DEPLOYMENT SETS THEM. AmneziaWG
 * prepends that many random bytes to a handshake initiation, a handshake
 * response, a cookie reply and a payload-carrying transport message, so the
 * header word is at that offset rather than at offset 0. Omitting s1, s2 or s3
 * leaves the handshake counters — "tx_handshake_initiations",
 * "rx_handshake_responses" and "handshake_response_observed" — permanently at
 * zero and false on a perfectly healthy tunnel, because the classifier is
 * reading padding. The status fields "awg_prefix_padding_s1" through
 * "awg_prefix_padding_s4" report the offsets actually in use; check them before
 * concluding from a "handshake_response_observed":false that the gateway is
 * silent.
 *
 * Omitting a nonzero s4 is worse than omitting the others: no payload-carrying
 * transport datagram classifies at all, so "transport_observed_both_ways" — the
 * one field a route-promotion gate may use — stays false on a healthy tunnel.
 * A zero in "awg_prefix_padding_s4" against a deployment configured with a
 * nonzero s4 is the diagnosis.
 *
 * s4 was refused outright until the shipping engine's keepalive behaviour was
 * established from the source it was compiled from. IT IS NOW ACCEPTED AND
 * ACTED ON. The engine that ships in android/app/libs/amneziawg.aar does NOT
 * pad keepalives: its build info names amneziawg-go v0.2.16, but that is only
 * the REQUIRED version and a replace directive substitutes the
 * github.com/wgtunnel fork, whose device/send.go applies the transport prefix
 * only when the message length differs from the 32-byte keepalive size.
 *
 * The consequence for a host reading these counters: under a nonzero s4 a
 * payload-carrying transport datagram carries its header word at offset s4
 * while a bare keepalive carries it at offset 0 at a total length of exactly
 * 32 bytes. Both are counted in "tx_transport_datagrams" and
 * "rx_transport_datagrams"; only the former is counted in the two
 * "..._payload_datagrams" fields, so a tunnel exchanging nothing but
 * keepalives can never raise "transport_observed_both_ways".
 *
 * A nonzero s4 that leaves no room inside "max_datagram" for a
 * payload-carrying transport datagram is refused at WinnTunnelCreate, because
 * it would leave the payload counters permanently at zero on a healthy tunnel.
 *
 * NOT VERIFIED ON DEVICE. The shipping profile sets s4=0, so a nonzero s4 has
 * unit coverage only and has never run against a real gateway.
 */
extern char *WinnTunnelStatusJSON(long long handle);

/*
 * Stop the tunnel, close the socket it owns, and retire the handle. Idempotent;
 * closing an unknown handle is not an error. Returns NULL on success, or an
 * allocated error string the caller must free.
 */
extern char *WinnTunnelClose(long long handle);

/*
 * Create one tunnel over an authenticated carrier -- currently
 * "http3-connect-udp" (MASQUE) -- instead of direct-awg.
 *
 * configJSON  the same datapath configuration WinnTunnelCreate takes, except
 *             "carrier" must name a carrier THIS FUNCTION was given a
 *             matching profile for. "direct-awg" is refused here: that
 *             carrier is what WinnTunnelCreate is for, and honouring it here
 *             too would make the anti-downgrade check bypassable by calling
 *             the other entry point.
 *
 * carrierProfileJSON  a carrierhost.Profile document (see
 *             winn_protocol_experimental/datapath/carrierhost/profile.go):
 *             the authenticated carrier configuration datapath.Config
 *             deliberately does not carry -- a URI template, a public
 *             target, a device identity, a TLS suite, a response verifier.
 *             Decoded with DisallowUnknownFields, exactly like configJSON, so
 *             a misspelled or stray field is a hard refusal rather than a
 *             silent default.
 *
 *             CONTAINS NO KEY MATERIAL. Every credential -- the device ML-DSA
 *             seed, the client private key, the pinned controller verifier
 *             set, the Winn CA, the ECH config list -- is named by PATH
 *             (controller_pins_path, root_ca_path, ech_config_list_path,
 *             device_seed_path, client_cert_path, client_key_path) and opened
 *             by THIS PROCESS, under its own identity, by the loader that
 *             already owns that file format. The caller builds this string
 *             and hands it over; it never opens, inspects, or forwards any of
 *             the files it names. Moving it as a string rather than a path is
 *             safe for exactly the reason a path would have been: nothing
 *             about trusting this document changes by keeping its bytes in
 *             memory instead of writing them to a file this same process
 *             would immediately read back. It is still secret-ADJACENT
 *             (it names every private credential file on this device) and a
 *             caller should treat it with the same care as configJSON: never
 *             logged, zeroed when done.
 *
 * udpFD, errorOut and the handle/ownership contract are identical to
 * WinnTunnelCreate. THE ENGINE TAKES OWNERSHIP of udpFD on success. Returns a
 * handle > 0, or WINN_TUNNEL_INVALID_HANDLE on failure with an allocated
 * message in *errorOut.
 */
extern long long WinnTunnelCreateWithCarrier(char *configJSON,
                                             char *carrierProfileJSON,
                                             int udpFD, char **errorOut);

/*
 * ===========================================================================
 * WINN/3 STANDALONE
 * ===========================================================================
 *
 * The two creates above build the RELAY shape: Winn carries AmneziaWG's
 * already-encapsulated outer datagrams, and the bytes crossing
 * WinnTunnelWriteInbound / WinnTunnelReadOutbound are "awg-datagram".
 *
 * WinnTunnelCreateWinn3 builds the STANDALONE shape. There is no AmneziaWG in
 * it at all: the winn/3 driver loop owns the session, the winn/3 tun layer
 * validates inner IP, and the bytes crossing THE SAME TWO FUNCTIONS are
 * "ip-packet".
 *
 *     WinnTunnelWriteInbound   host tun read  -> tunnel   (outbound inner IP)
 *     WinnTunnelReadOutbound   tunnel         -> host tun (inbound inner IP,
 *                                                          already VALIDATED)
 *
 * Everything else is shared verbatim: the handle space (one counter, so a
 * winn/3 handle and a relay handle can never collide), the negative
 * WINN_TUNNEL_ERR_* codes, the string ownership rule, the threading rule,
 * WinnTunnelStatusJSON and WinnTunnelClose.
 *
 * ---------------------------------------------------------------------------
 * THE CONFIGURATION
 * ---------------------------------------------------------------------------
 *
 *   {"contract":"winn-datapath/1+winn3",
 *    "payload":"ip-packet",
 *    "carrier":"winn3",
 *    "gateway_endpoint":"203.0.113.9:51820",
 *    "static_private":"<base64 X25519 private>",
 *    "gateway_static":"<base64 X25519 public>",
 *    "gateway_id":"wins-sea-01",
 *    "admission_key":"<base64>",
 *    "auth_ed25519":"<canonical base64, exactly 32 bytes, optional pair>",
 *    "auth_mldsa65":"<canonical base64, exactly 1952 bytes, optional pair>",
 *    "psk":"<base64, optional>",
 *    "inner_v4":"10.13.0.2",
 *    "inner_router_v4":"10.13.0.1",
 *    "inner_v6":"", "inner_router_v6":"",
 *    "path_mtu":1400,
 *    "carrier_classes":["udp","tls"],
 *    "allow_own_socket":false,
 *    "session_id":"<opaque>"}
 *
 * Decoded with DisallowUnknownFields, so a stray key is a hard refusal.
 * auth_ed25519 and auth_mldsa65 must be both absent (legacy mode) or both
 * present. A half pair, wrong length, non-canonical encoding, or duplicated
 * replacement is refused before a socket is opened. A valid pair is bound to
 * session.DualAuth with Expected=true, so DATA cannot carry until both gateway
 * signatures verify against these exact public keys.
 *
 * "contract" is NOT WINN_TUNNEL_CONTRACT_VERSION. A host that found them equal
 * would conclude a relay archive can carry inner IP, which is the exact mistake
 * the payload class exists to prevent.
 *
 * "carrier" must be "winn3". direct-awg and http3-connect-udp are refused here
 * for the same anti-downgrade reason WinnTunnelCreateWithCarrier refuses
 * direct-awg: two entry points that accept each other's carriers are one entry
 * point with a bypass.
 *
 * "carrier_classes" is the MIGRATION PLAN — every class the session may
 * escalate TO, not the one dialled. The inner MTU is computed over the whole
 * plan, because a floor computed over the dialled class alone black-holes every
 * full-size flow on the first migration while the tunnel still reports up.
 *
 * "gateway_id" and "admission_key" arrive on the same ML-DSA-65-signed gateway
 * descriptor as "gateway_static", and are required: without them no initiation
 * this client sends carries a tag the gateway will admit.
 *
 * THEY ARE ENCODED DIFFERENTLY HERE, AND A HOST THAT GETS THIS WRONG GETS NO
 * ERROR. "admission_key" is base64 because it is a secret with arbitrary bytes.
 * "gateway_id" is the RAW OPERATOR STRING — byte for byte the same text the
 * gateway is started with — because it is an authenticated input to the
 * admission tag that is NEVER TRANSMITTED, so the two ends never compare notes
 * about it. A host that base64-encodes it here computes a tag over different
 * bytes than the gateway does, the gateway declines to answer an initiation
 * whose tag it cannot verify, and the symptom on the device is a tunnel that
 * never comes up with nothing logged anywhere — which on a censored network is
 * indistinguishable from the gateway being blocked.
 *
 * The signed descriptor transports "gateway_id" base64-encoded, like every
 * byte-valued field in its canonical JSON. THE HOST DECODES IT before putting
 * it here. On Apple that is WinsWinn3CreateDocument.make.
 *
 * udpFD: THE ENGINE TAKES OWNERSHIP. Pass -1 only with "allow_own_socket":true.
 * A socket this archive opened is a socket nothing outside the process could
 * have excluded from the tunnel's own routes, which on Apple and Android is a
 * leak rather than a convenience — so the default is a refusal.
 *
 * ---------------------------------------------------------------------------
 * THE ONE THING A ROUTE-PROMOTION GATE MAY READ
 * ---------------------------------------------------------------------------
 *
 * WinnTunnelStatusJSON on a winn/3 handle publishes, among others:
 *
 *   "winn3_gate_state"  the tun layer's gate; "carrying" is the only carrying
 *                       value, and it is Gate.State() == StateCarrying
 *   "winn3_rx_packets"  inner packets VALIDATED AND DELIVERED to the host
 *                       device, i.e. Stats().RxPackets
 *   "winn3_rx_offered"  inner packets that merely ARRIVED, i.e. RxOffered
 *
 * A promotion is earned by BOTH of the first two — gate carrying AND
 * rx_packets > 0 — and by neither of them alone. "winn3_rx_offered" is
 * published next to rx_packets on purpose: it is the counter a host reaches for
 * by mistake, and a gate built on arrivals promotes on a packet the inner-IP
 * validator may have rejected.
 *
 * DO NOT GATE ON "winn3_may_carry" ALONE. It is the gate state as a boolean and
 * says the session believes DATA may flow; it does not say anything reached the
 * host.
 *
 * Returns a handle > 0, or 0 on failure with an allocated message in *errorOut.
 */
extern long long WinnTunnelCreateWinn3(char *configJSON, int udpFD,
                                       char **errorOut);

#ifndef WINS_WINN3_PACKET_BATCH_H
#define WINS_WINN3_PACKET_BATCH_H
#include <stddef.h>
#include <stdint.h>

/* Apple 64-bit ABI. All integers are in host byte order. */
#define WINS_WINN3_BATCH_MAX 32
#define WINS_WINN3_PACKET_STRIDE 24
#define WINS_WINN3_PACKET_MAX 65535

typedef struct WinsWinn3PacketDescriptor {
  void *data;
  uint32_t length;
  uint32_t capacity;
  uint32_t family;
  uint32_t reserved;
} WinsWinn3PacketDescriptor;

#if defined(__cplusplus)
static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
#else
_Static_assert(sizeof(WinsWinn3PacketDescriptor) == 24, "packet descriptor stride");
_Static_assert(offsetof(WinsWinn3PacketDescriptor, length) == 8, "packet length offset");
#endif
#endif

/*
 * Stage 4 standalone packet arrays. Descriptor layout is fixed at 24 bytes:
 * pointer at 0, uint32 length at 8, capacity at 12, family at 16, reserved at 20.
 * count is 0..32 and stride must be 24. Family is host AF_INET or AF_INET6.
 * reserved must be zero in both directions.
 * Enqueue requires 0 < length <= capacity <= 65535 and matching IP version.
 * Dequeue requires length=family=reserved=0 and 0 < capacity <= 65535.
 * All descriptors and referenced buffers belong to the caller and must remain
 * valid and unmodified for the call. No pointer is retained. Output buffers
 * must not overlap each other or the descriptors. Entire-batch validation
 * precedes side effects. Invalid batches return ERR_ARGUMENT unchanged.
 * Return is a processed PREFIX count, or a negative WINN_TUNNEL_ERR_* if no
 * packet was processed. Zero count is a no-op on a live standalone handle.
 * Enqueue preserves the bounded drop-oldest queue, counting evictions, and
 * accepts the whole batch under the device lock. Dequeue waits for one packet
 * (timeoutMS <= 0 waits until close/data), then drains available packets only.
 * A short buffer leaves that packet queued: return ERR_TOO_LARGE if first,
 * otherwise return the completed prefix. Suffix buffers/descriptors are intact.
 * Close wakes blocked calls; handles are never reused. Scalar APIs remain.
 */
extern int WinsWinn3EnqueuePackets(long long handle, void *descriptors,
                                  int count, int stride);
extern int WinsWinn3DequeuePackets(long long handle, void *descriptors,
                                  int count, int stride, int timeoutMS);

#ifdef __cplusplus
}
#endif

#endif /* WINN_DATAPATH_H */
