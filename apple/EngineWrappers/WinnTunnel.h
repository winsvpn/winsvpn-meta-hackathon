/*
 * WinnTunnel.h — C surface of the Winn Protocol in-process datapath on Apple.
 *
 * AUTHORITY. The prototypes below are transcribed from the cgo-generated
 * header that ships beside the real archive:
 *
 *     tools/winn_conformance_build_out/libwinn-datapath-ios-arm64.h
 *     tools/winn_conformance_build_out/libwinn-datapath-darwin-arm64.h  (identical)
 *
 * They are byte-for-byte the same eleven declarations, using the same C types
 * cgo emits (`long long`, `int`, `char *`, `char **`) rather than fixed-width
 * spellings. Do NOT "improve" them into fixed-width integer types, void
 * pointers, or const-qualified pointers: a difference that is merely
 * ABI-compatible today is still a difference the conformance guard has to
 * reason about, and a difference that is NOT ABI-compatible is memory
 * corruption that no linker can catch, because C carries no arity.
 *
 * This file exists alongside the generated header only to carry what a
 * generated header cannot express: the status codes, the ownership rules, the
 * buffer sizing, and the payload model. That split mirrors the curated
 * companion header the datapath lane maintains at
 * winn_protocol_experimental/cdatapath/winn_datapath.h.
 *
 * ENFORCEMENT. tools/verify_winn_abi_conformance.sh compiles this header and
 * the generated header in one translation unit, for every platform slice the
 * wrapper targets, and does the same for WinsWinnPacketEngine.m and
 * WinnTunnelTestDouble.c. A divergence is a build failure, not a code review
 * item. tools/build_apple_engine_wrappers.sh runs it before it builds the Winn
 * wrapper. An earlier revision of this file was written against a plan
 * document instead of the archive and disagreed with it on 4 of 5 entry
 * points; the test double implemented the same wrong contract, so every test
 * passed. That is the failure this guard exists to prevent.
 *
 * ---------------------------------------------------------------------------
 * WHAT CROSSES THIS BOUNDARY — READ BEFORE CHANGING THE PUMP
 * ---------------------------------------------------------------------------
 *
 * The bytes crossing WinnTunnelWriteInbound and WinnTunnelReadOutbound are
 * AmneziaWG OUTER DATAGRAMS: exactly what the host's own AWG engine would
 * otherwise have sent to, and received from, the gateway's UDP endpoint. They
 * are NOT raw IP packets off the tun device. The archive contains no AmneziaWG
 * implementation; it carries already-encapsulated datagrams over the Winn
 * carrier. The configuration must set "payload":"awg-datagram"; the value
 * "ip-packet" is refused at create time, deliberately, because forwarding a
 * raw tun packet here would put cleartext on the wire.
 *
 * The correct placement inside an NEPacketTunnelProvider is therefore:
 *
 *     packetFlow <-> host AWG engine (libwg-go.a) <-> THIS <-> network
 *
 * See the header comment in WinsWinnPacketEngine.m for the current AWG
 * outer-datagram seam placement and the declarations below for the ABI.
 *
 * ---------------------------------------------------------------------------
 * CARRIERS ON APPLE
 * ---------------------------------------------------------------------------
 *
 * WinnTunnelCreate takes a plain `int udpFD` and no dialer, and still builds
 * "direct-awg" only. That did not change and this comment's original warning
 * still holds in spirit: DO NOT EXTEND THIS ABI, OR ANY ABI, TO CARRY A
 * DIALER. A carrier.SuppliedSocketDialer is a Go interface value — TLS state,
 * an HTTP/3 client, closures — and cgo has no mechanism to marshal one into a
 * C function argument. That was never a policy choice available to relax; it
 * is not possible.
 *
 * What WAS a policy choice, and is now made the other way, is whether the
 * DOCUMENT a dialer is built FROM could cross this boundary. It can, the same
 * way configJSON already does: as a plain C string. WinnTunnelCreateWithCarrier
 * is the additive second entry point that takes one — a carrierhost.Profile
 * document — and builds the dialer entirely on the Go side of the call, using
 * datapath.OpenConfigWithCarrier internally. The caller never touches, builds,
 * or even sees anything Go-shaped; it moves two strings, exactly as it always
 * moved one. See WinnTunnelCreateWithCarrier below.
 *
 * Through WinnTunnelCreate the carrier must still be "direct-awg"; anything
 * else is refused with that reason, and calling that entry point is still how
 * a caller states it is not supplying a carrier profile.
 *
 * ---------------------------------------------------------------------------
 * MEMORY
 * ---------------------------------------------------------------------------
 *
 * Every char * returned by this archive is heap-allocated by Go and MUST be
 * released with WinnTunnelFreeString — never free(). NULL is never used to
 * report success: a function that can fail writes an allocated message through
 * an out parameter, and a NULL out value means no error.
 *
 * ---------------------------------------------------------------------------
 * THREADING
 * ---------------------------------------------------------------------------
 *
 * WinnTunnelWriteInbound and WinnTunnelReadOutbound may be called concurrently
 * from different threads, and both are safe against a concurrent
 * WinnTunnelClose. A blocking WinnTunnelReadOutbound returns
 * WINN_TUNNEL_ERR_CLOSED promptly when the tunnel is closed, so a reader
 * thread never has to be killed.
 *
 * Rules that hold on every platform: Go never creates an OS network interface,
 * never edits routes, and never shells out. The host owns the tunnel device;
 * Go owns the protocol.
 */

#ifndef WINS_WINN_TUNNEL_H
#define WINS_WINN_TUNNEL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque tunnel handle. cgo declares every handle parameter as `long long`, so
 * this typedef must be `long long` and nothing else. Positive values are live
 * handles. Handles are never reused within the lifetime of the process, so a
 * stale handle always fails cleanly instead of addressing a later tunnel.
 */
typedef long long WinnTunnelHandle;

/* Returned by WinnTunnelCreate when no tunnel could be created. */
#define WINN_TUNNEL_INVALID_HANDLE ((WinnTunnelHandle)0)

/*
 * The contract string this header was written against. Compare it against
 * WinnTunnelContractVersion() at startup and refuse to proceed on a mismatch:
 * a wrapper built for a different contract is a silent-corruption risk, not a
 * warning. wins_winn_packet_engine_start() does exactly that.
 */
#define WINN_TUNNEL_CONTRACT_VERSION "winn-datapath/1"

/*
 * Negative status codes. These are the ONLY negative values
 * WinnTunnelWriteInbound and WinnTunnelReadOutbound can return; anything >= 0
 * is a byte count. Transcribed from the datapath lane's curated header and
 * from the `errHandle`..`errArgument` constants in cdatapath/winn_datapath.go.
 *
 * Note that a read timeout reports WINN_TUNNEL_ERR_TIMEOUT and NOT 0. An
 * earlier revision of this header assumed a 0 return meant "nothing queued";
 * the real archive never says that.
 */
#define WINN_TUNNEL_ERR_HANDLE    (-1) /* no such handle                     */
#define WINN_TUNNEL_ERR_CLOSED    (-2) /* the tunnel is closed               */
#define WINN_TUNNEL_ERR_TIMEOUT   (-3) /* timeout expired, no datagram       */
#define WINN_TUNNEL_ERR_TOO_LARGE (-4) /* buffer too small, datagram dropped */
#define WINN_TUNNEL_ERR_CARRIER   (-5) /* terminal carrier failure           */
#define WINN_TUNNEL_ERR_ARGUMENT  (-6) /* NULL buffer or non-positive size   */

/* Release a string returned by any function below. NULL is a no-op. */
extern void WinnTunnelFreeString(char* value);

/* Contract version of the archive itself. Caller frees. */
extern char* WinnTunnelContractVersion(void);

/* Winn v3 connectivity contract version, e.g. "winn/3". Caller frees. */
extern char* WinnTunnelProtocolVersion(void);

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
 *   gateway_endpoint must be an IP literal with a port; a hostname is refused,
 *   because resolving one here would leak a DNS lookup outside the tunnel.
 *   Secret-bearing and process-local: never log it.
 *
 * udpFD       a UDP socket descriptor the host has already prepared. THE
 *             ENGINE TAKES OWNERSHIP and closes it in WinnTunnelClose; the
 *             caller must not close it. Pass -1 to let the engine open its own
 *             socket, which it does ONLY if the configuration sets
 *             "allow_own_socket":true. That flag fails closed, so passing -1
 *             without it is a create-time error, not a fallback.
 *
 * errorOut    on failure receives an allocated message the caller must release
 *             with WinnTunnelFreeString. On success it is set to NULL. Pass
 *             the address of a NULL-initialised char *; the archive writes
 *             through this pointer, so an uninitialised one is a wild store.
 *
 * Returns a handle > 0, or WINN_TUNNEL_INVALID_HANDLE on failure.
 */
extern long long WinnTunnelCreate(char* configJSON, int udpFD, char** errorOut);

/*
 * Hand one datagram from the host to the protocol (host side -> gateway).
 * Returns the byte count, or a negative WINN_TUNNEL_ERR_* code. The buffer is
 * not retained past the call.
 */
extern int WinnTunnelWriteInbound(long long handle, char* buffer, int length);

/*
 * Take one datagram from the protocol for the host (gateway -> host side).
 * timeoutMS <= 0 blocks until a datagram arrives, the tunnel closes, or the
 * carrier fails. Returns the byte count, or a negative WINN_TUNNEL_ERR_* code.
 */
extern int WinnTunnelReadOutbound(long long handle, char* buffer, int capacity, int timeoutMS);

/*
 * Machine-readable status as JSON. Caller releases it with
 * WinnTunnelFreeString. Never returns NULL: an unknown handle yields a JSON
 * object saying so, so a wrapper can always log something meaningful. The
 * document must contain no key material — it is surfaced through the provider
 * status file.
 *
 * DO NOT GATE ROUTE PROMOTION ON "up". That field is link liveness only, and
 * is true for a socket that has never carried a byte. Gate on
 * "transport_observed_both_ways" AND a recent latestHandshake from the host's
 * own AWG engine; this archive holds no keys and cannot authenticate anything
 * it counts.
 */
extern char* WinnTunnelStatusJSON(long long handle);

/*
 * Stop the tunnel, close the socket it owns, and retire the handle. Idempotent;
 * closing an unknown handle is not an error. Must unblock any in-flight
 * WinnTunnelReadOutbound. Returns NULL on success, or an allocated error
 * string the caller must release with WinnTunnelFreeString.
 */
extern char* WinnTunnelClose(long long handle);

/*
 * Create one tunnel over an authenticated carrier — currently
 * "http3-connect-udp" (MASQUE) — instead of direct-awg. See "CARRIERS ON
 * APPLE" above.
 *
 * configJSON           identical in shape to WinnTunnelCreate's, except
 *                       "carrier" must name the same carrier
 *                       carrierProfileJSON builds. "direct-awg" is refused
 *                       here — call WinnTunnelCreate for that — and a carrier
 *                       that disagrees with the profile is refused by name
 *                       rather than silently resolved either way.
 *
 * carrierProfileJSON    a carrierhost.Profile document. Decoded with
 *                       DisallowUnknownFields, exactly like configJSON. NAMES
 *                       every credential this session needs BY PATH —
 *                       controller_pins_path, root_ca_path,
 *                       ech_config_list_path, device_seed_path,
 *                       client_cert_path, client_key_path — and contains no
 *                       key material itself; every one of those files is
 *                       opened by the archive, under this process's own
 *                       identity, never by the caller. Secret-adjacent even
 *                       so (it names every private credential file on this
 *                       device): never log it, and release it the way
 *                       configJSON is released.
 *
 * udpFD, errorOut and the handle/ownership contract are identical to
 * WinnTunnelCreate: THE ENGINE TAKES OWNERSHIP of udpFD on success; errorOut
 * must point at a NULL-initialised char*.
 *
 * Returns a handle > 0, or WINN_TUNNEL_INVALID_HANDLE on failure.
 *
 * DECLARATION PROVENANCE: this declaration, and the "CARRIERS ON APPLE"
 * block above, were lost from this header in the 2026-08-08 loss event that
 * also took the seam start sequence out of WinsPacketTunnelEngine.swift
 * (docs/handoff/RECOVERY_20260808.md). The Go export, the generated header
 * and the wrapper's call site all survived, so nothing failed until
 * tools/verify_apple_winn_seam.sh tried to compile the wrapper against THIS
 * header — the only one on its include path. Restored from 934f7b4.
 */
extern long long WinnTunnelCreateWithCarrier(char* configJSON,
                                             char* carrierProfileJSON,
                                             int udpFD, char** errorOut);

/*
 * ===========================================================================
 * WINN/3 STANDALONE
 * ===========================================================================
 *
 * The two creates above build the RELAY shape: Winn carries AmneziaWG's
 * already-encapsulated outer datagrams, and the bytes crossing
 * WinnTunnelWriteInbound / WinnTunnelReadOutbound are "awg-datagram".
 *
 * WinnTunnelCreateWinn3 builds the STANDALONE shape. There is no AmneziaWG
 * anywhere beneath it: Winn/3 owns its own handshake, AEAD, rekey and framing,
 * and the bytes crossing the SAME four pump functions are "ip-packet" — raw
 * inner IP starting at the version nibble. Only the create differs; the Go side
 * dispatches on the handle, so WriteInbound, ReadOutbound, StatusJSON and Close
 * serve both shapes unchanged. That is why only a create needed adding here,
 * and it is the whole reason this declaration is easy to forget.
 *
 * DUAL AUTH CONFIG. The strict JSON object may carry auth_ed25519 and
 * auth_mldsa65 as an optional pair: canonical base64 over exactly 32 and 1952
 * public-key bytes. Both absent preserves the legacy create shape. Missing,
 * half-provisioned, malformed, wrong-length, or duplicate replacement material
 * is refused before the outer socket opens. A valid pair sets
 * session.DualAuth.Expected, so the session gate stays closed until both
 * gateway signatures verify against those exact keys.
 *
 * WHY THIS DECLARATION EXISTS AT ALL. The Apple pump resolves this symbol by
 * dlsym and would work without it. It is here because this header claims, at
 * the top, to be byte-for-byte parity with the generated header — and a curated
 * header that silently describes ten of eleven entry points is worse than no
 * header, because a reader concludes the eleventh does not exist. That is not
 * hypothetical: WinnTunnelCreateWithCarrier went missing from this file in the
 * 2026-08-08 loss event and nothing failed until a compile tried to use it.
 *
 * STATUS FIELDS. WinnTunnelStatusJSON on a winn/3 handle publishes the
 * "winn3_*" field set. Three of them decide promotion, and the difference
 * between two of them is the trap:
 *
 *   "winn3_gate_state"  the tun layer's gate; "carrying" is the only carrying
 *                       value, and it is Gate.State() == StateCarrying
 *   "winn3_rx_packets"  inner packets VALIDATED AND DELIVERED to the host,
 *                       i.e. Stats().RxPackets
 *   "winn3_rx_offered"  inner packets that merely ARRIVED, i.e. RxOffered
 *
 * A promotion is earned by BOTH gate-carrying AND rx_packets > 0, and by
 * neither alone. "winn3_rx_offered" sits next to rx_packets deliberately: it is
 * the counter a host reaches for by mistake, and a gate built on arrivals
 * promotes on a packet the inner-IP validator may have rejected.
 *
 * DO NOT GATE ON "winn3_may_carry" ALONE. It is the gate state as a boolean and
 * says the session believes data may flow; it does not say anything reached the
 * host.
 *
 * udpFD, errorOut and the handle/ownership contract are identical to
 * WinnTunnelCreate: THE ENGINE TAKES OWNERSHIP of udpFD on success, and
 * errorOut must point at a NULL-initialised char*.
 *
 * Returns a handle > 0, or WINN_TUNNEL_INVALID_HANDLE on failure with an
 * allocated message in *errorOut.
 */
extern long long WinnTunnelCreateWinn3(char* configJSON, int udpFD,
                                       char** errorOut);

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

#endif /* WINS_WINN_TUNNEL_H */
