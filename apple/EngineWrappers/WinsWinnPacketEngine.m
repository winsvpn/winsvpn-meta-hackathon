/*
 * WinsWinnPacketEngine.m — Apple host side of the Winn Protocol datapath.
 *
 * Additive sibling of WinsAmneziaWGPacketEngine.m. It exports the same v1
 * Win's VPN C ABI shape (contract_version / create / start / stop / destroy)
 * so WinsNativePacketTunnelEngine can load it through the identical
 * dlopen/dlsym path, and it carries Winn Protocol instead of AmneziaWG.
 *
 * ---------------------------------------------------------------------------
 * WHERE THIS SITS, AND WHY IT MOVED
 * ---------------------------------------------------------------------------
 *
 * The bytes crossing WinnTunnelWriteInbound and WinnTunnelReadOutbound are
 * AmneziaWG OUTER DATAGRAMS, not raw IP packets. The archive contains no
 * AmneziaWG implementation, so a raw tun packet handed to it would be forwarded
 * to the gateway in cleartext; it refuses "payload":"ip-packet" at create time
 * precisely so a host that gets this wrong fails at the handshake instead of on
 * the wire. See the contract note at the top of WinnTunnel.h.
 *
 * An earlier revision of this file pumped the utun device straight into that
 * boundary and recorded, in this comment block, that it was on the wrong side
 * of the AmneziaWG engine and that WinnTunnelCreate therefore refused. This
 * revision moves it to the correct side:
 *
 *     packetFlow <-> host AWG engine (libwg-go.a) <-> THIS SEAM <-> network
 *
 * The AmneziaWG engine keeps the utun device and keeps doing all of the
 * cryptography. What changes is only where its OUTER datagrams go: instead of
 * leaving from a socket of its own, its peer endpoint is pointed at a loopback
 * UDP port this wrapper listens on, so those already-encapsulated datagrams
 * land in this process first and are relayed to the gateway by the Winn
 * datapath.
 *
 * This is the same arrangement Android already runs (WinnAwgLoopbackSeam.kt)
 * and the same one internal/carrier.RelayLocalUDP implements on Linux. It is
 * deliberately not a new design: three hosts converging on one seam is the
 * point, because the payload boundary is the thing that has been got wrong
 * twice in this tree already.
 *
 * ---------------------------------------------------------------------------
 * WHY THE SEAM SOCKET NEEDS NO EXCLUSION, AND THE ONE THAT DOES
 * ---------------------------------------------------------------------------
 *
 * The seam socket is BOUND TO 127.0.0.1 and only ever talks to 127.0.0.1. It
 * has no route off the device at all, so it cannot be captured by the tunnel's
 * own routes and cannot dead-loop. The containment is structural rather than
 * administrative — nothing has to remember to mark it.
 *
 * The one socket that does touch the network is the Winn engine's outer socket.
 * On Apple the engine opens it (WinnTunnelCreate is passed udpFD = -1, which
 * requires "allow_own_socket":true) and it is kept out of the tunnel by
 * NEIPv4Settings.excludedRoutes carrying WinsTunnelConfig's /32 exclusion for
 * the transport endpoint.
 *
 * THAT EXCLUSION IS A LIVE HAZARD FOR THIS DESIGN AND THE SWIFT SIDE MUST
 * HANDLE IT. WinsTunnelConfig.transportIPv4ExclusionRoute derives its /32 from
 * transportEndpointHost, which falls back to the AmneziaWG peer endpoint host.
 * Once that peer endpoint is rewritten to 127.0.0.1 for this seam, the fallback
 * yields loopback and the /32 for the REAL gateway disappears — leaving the
 * engine's outer socket to be captured by the tunnel's default route. The Xray
 * stealth transport, which rewrites the same peer endpoint, avoids this by
 * supplying the real carrier host through the [xray] section; Winn must supply
 * it the same way, from the [winn] endpoint. A Winn tunnel whose exclusion
 * route resolves to loopback must not be started.
 *
 * ---------------------------------------------------------------------------
 * ORDERING
 * ---------------------------------------------------------------------------
 *
 * The seam binds an EPHEMERAL loopback port, so the port is not known until
 * after start. The host must therefore bring this engine up FIRST, read the
 * port with wins_winn_packet_engine_awg_seam_port(), rewrite the AmneziaWG peer
 * endpoint to 127.0.0.1:<port>, and only then start the AmneziaWG engine. That
 * is the same order Android uses, and it is what makes the port impossible to
 * guess wrong: there is no second place the number is written down.
 *
 * Picking the port on the host side instead would mean binding a probe socket,
 * closing it, and hoping nothing else took the port in between. This ABI grew
 * one additive accessor rather than that race.
 */

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <TargetConditionals.h>

#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <os/log.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "WinnTunnel.h"

/*
 * The largest outer datagram the seam will relay. The read buffer is sized
 * from WinnTunnelMaxDatagram() at start, and this is the compile-time ceiling
 * that sizing is checked against.
 */
#define WINS_WINN_DATAGRAM_BUFFER_BYTES 2048

/*
 * The carriers this ABI can build, and therefore the only values of
 * [winn] carrier this wrapper may accept. WIDENED, by name, from direct-awg
 * alone: WinnTunnelCreateWithCarrier (see WinnTunnel.h) now lets this process
 * build an authenticated http3-connect-udp (MASQUE) carrier from a
 * carrierhost.Profile document delivered as a second C string. It is still
 * true that no dialer, and nothing Go-shaped, ever crosses this boundary —
 * only two documents do, exactly as one always did.
 *
 * http2-stream stays refused, for the same reason Android and Linux exclude
 * it: the engine implements it, but its dialer needs a CONNECTED, protected
 * TCP socket, and this wrapper opens one UNCONNECTED UDP socket
 * (allow_own_socket) for its outer transport. Accepting it here would move
 * the failure from a named refusal to a socket-kind mismatch deep inside the
 * archive. A carrier joins this set when the HOST can supply what its dialer
 * takes, not when the engine gains the carrier.
 *
 * Any OTHER config naming an unrecognised carrier must still be REFUSED here.
 * Building a direct-awg document from it would be the worst kind of silent
 * downgrade available in this tree: the session would start, the tunnel would
 * carry traffic, and an authenticated post-quantum outer transport the gateway
 * negotiated would have been replaced by plain UDP with nobody told.
 * lib/winn_protocol_dispatch.dart emits this key on EVERY winn/3 config, so an
 * absent value means a config written before the key existed and normalizes
 * to direct-awg exactly as it does on Android and Linux.
 */
#define WINS_WINN_SUPPORTED_CARRIER "direct-awg"
#define WINS_WINN_SUPPORTED_CARRIER_HTTP3 "http3-connect-udp"

/*
 * The [winn] key carrying the carrier profile document, built and validated
 * entirely in Swift (WinsWinnCarrierProfile) from the served carrier-profile
 * fields plus this device's locally resolved credential files, and handed
 * down through the SAME launch descriptor as every other [winn] value —
 * never through a new argument on the shared five-symbol carrier ABI, which
 * every engine wrapper (AmneziaWG, Xray, Winn) is loaded through identically.
 * Present only when carrier is http3-connect-udp; required in that case.
 */
static NSString *const kWinsWinnCarrierProfileKey = @"winn_carrier_profile";

/* True for exactly the carrier names this ABI can build a document for. */
static bool wins_winn_carrier_supported(NSString *lowercaseCarrier) {
  return [lowercaseCarrier isEqualToString:@WINS_WINN_SUPPORTED_CARRIER] ||
         [lowercaseCarrier isEqualToString:@WINS_WINN_SUPPORTED_CARRIER_HTTP3];
}

/* Bound on the inbound poll so a torn-down engine always makes progress. */
#define WINS_WINN_INBOUND_POLL_MILLISECONDS 250

/*
 * timeoutMS handed to every WinnTunnelReadOutbound call.
 *
 * This is a deliberate value, not a placeholder. Four things pin it:
 *
 * 1. It must be > 0. The archive treats timeoutMS <= 0 as "block until a
 *    datagram, a close, or a carrier failure". That is safe on its own —
 *    WinnTunnelClose is contractually required to unblock an in-flight read —
 *    but it means the loop only re-reads `stopping` when the archive decides
 *    to return. A bounded wait keeps the wrapper's own stop flag authoritative
 *    rather than making shutdown depend entirely on the archive.
 *
 * 2. 250 ms is the same bound WINS_WINN_INBOUND_POLL_MILLISECONDS already
 *    applies to the inbound poll, for exactly the same reason. Both pumps then
 *    have one worst-case shutdown latency to reason about instead of two.
 *
 * 3. Upper bound: worst-case join latency after stopTunnel. WinnTunnelClose is
 *    issued before the joins, so 250 ms is a backstop for a close that does
 *    not unblock, not the normal teardown path. It stays far inside the window
 *    NetworkExtension allows a provider to stop in.
 *
 * 4. Lower bound: this parameter replaces a 200 us busy-poll, which woke the
 *    outbound thread ~5000 times a second on a completely idle tunnel. At
 *    250 ms an idle tunnel wakes at most 4 times a second. Inside a
 *    NetworkExtension on a battery-powered device that is the whole reason the
 *    parameter is worth choosing carefully.
 *
 * It costs carried traffic nothing: the call returns as soon as a datagram is
 * available, and the timeout bounds only idleness.
 */
#define WINS_WINN_OUTBOUND_READ_TIMEOUT_MILLISECONDS 250

/*
 * Backoff for a 0-length return from WinnTunnelReadOutbound. The contract says
 * the call returns a byte count or a negative WINN_TUNNEL_ERR_* code and that a
 * dry timeout is WINN_TUNNEL_ERR_TIMEOUT, so 0 is not a documented outcome.
 * It is throttled rather than trusted: an undocumented 0 returned immediately
 * would otherwise spin this thread at 100% CPU inside the appex, which iOS
 * terminates the extension for.
 */
#define WINS_WINN_IDLE_POLL_MICROSECONDS 200

/*
 * ---------------------------------------------------------------------------
 * SEAM BACKPRESSURE AND DROP ACCOUNTING
 * ---------------------------------------------------------------------------
 *
 * MEASURED DEFECT (macOS, arm64, 2026-08-04/05). Under an UNPACED burst the
 * seam lost a third of everything the AmneziaWG engine handed it, silently:
 *
 *   4,195 datagrams offered at ~130,000 pkt/s  ->  1,380 lost  (32.90%)
 *   20,000 datagrams offered at ~234,000 pkt/s ->  9,255 lost  (46.27%)
 *
 * In every run the kernel's own "dropped due to full socket buffers" counter
 * (netstat -s -p udp) moved by EXACTLY the number of missing datagrams. So the
 * loss was neither corruption nor a torn-down pump: the datagrams were
 * discarded by the kernel on THIS socket's receive queue, before recvfrom ever
 * saw them, and therefore upstream of every counter in the entire system. The
 * Go engine's tx_rejected stayed at zero throughout, because nothing was ever
 * rejected — nothing arrived. That is why this was invisible.
 *
 * WHY THERE IS NO TRUE BACKPRESSURE TO APPLY, AND WHAT IS DONE INSTEAD.
 *
 * The producer is amneziawg-go sending to its configured peer endpoint. That is
 * a UDP socket by definition of WireGuard, and on a UDP loopback path sendto
 * completes successfully even when the receiver's buffer is full — the kernel
 * accepts the datagram and then discards it at delivery. There is no sockopt,
 * no socket kind and no flag that makes that sender block, and the peer is a
 * third-party engine this wrapper does not control. Blocking the sender is
 * therefore not available at this seam. Saying so plainly is better than
 * shipping something named "backpressure" that is not.
 *
 * What IS available, and what this implements:
 *
 *   1. REMOVE THE STALL THAT CAUSED THE BACKLOG. The receive thread used to do
 *      recvfrom and then WinnTunnelWriteInbound on the same thread. That write
 *      goes through cgo into the Go engine's conn.WriteTo, which BLOCKS when
 *      the outer socket's send buffer is full — genuine downstream
 *      backpressure, correctly applied, but with nothing draining the seam
 *      while it was applied. The socket is now drained by a thread that does
 *      nothing but recvfrom, and the write happens on a second thread. The
 *      downstream stall still stalls, but it no longer stops the drain.
 *
 *   2. MOVE THE DROP POINT SOMEWHERE IT CAN BE COUNTED. Between the two
 *      threads is a bounded ring this wrapper owns. If the ring fills, the
 *      datagram is dropped — but by us, with an exact count, a direction, and
 *      a log line. A kernel receive-queue drop is unattributable and
 *      uncountable on Darwin (there is no per-socket drop statistic and no
 *      SO_RERROR); a drop against our own ring is neither.
 *
 *   3. STATE THE BUFFER INSTEAD OF INHERITING IT. SO_RCVBUF is set explicitly
 *      and the value the kernel actually granted is recorded and reported.
 *      This is a shock absorber for the gap between a burst arriving and the
 *      drainer being scheduled. IT IS NOT THE FIX: a bigger buffer only moves
 *      the cliff, which is precisely why the granted size is reported next to
 *      a high-water mark of the backlog, so anyone can see how close the
 *      socket actually came to overflowing.
 *
 *   4. PROVE THE RESIDUE. Before each drain the pending backlog is sampled
 *      with SO_NREAD and the maximum is kept. A high-water mark that stays far
 *      below the granted buffer is evidence that the kernel had no reason to
 *      drop; one that approaches it is the warning that it did.
 *
 * Nothing here changes the bytes that cross the seam or the order they cross
 * it. The ring is strictly first-in-first-out and drops only from the tail.
 */

/*
 * Ring slots between the seam drainer and the engine writer.
 *
 * WHAT THIS NUMBER IS FOR, STATED PRECISELY, BECAUSE "MAKE THE BUFFER BIGGER"
 * IS THE WRONG ANSWER TO THE WRONG PROBLEM.
 *
 * A buffer absorbs a BOUNDED burst whose arrival rate exceeds the service
 * rate. It does nothing whatever about SUSTAINED overload — there the deficit
 * accumulates without limit and any finite buffer only postpones the loss.
 * Both cases are real here and they are handled differently: this constant
 * addresses the first, and the drop accounting addresses the second. Growing
 * this number is explicitly NOT how the second one gets fixed.
 *
 * Measured on this machine, arm64 macOS, 2026-08-05:
 *
 *   WinnTunnelWriteInbound in isolation      225,300 datagrams/s (4.44 us each)
 *   the writer's rate with the drainer running ~141,000 datagrams/s
 *   an unpaced producer offers                ~191,000 datagrams/s
 *
 * so the worst-case deficit under a full-rate burst is about 50,000
 * datagrams/s. The burst of record — the 4 MiB, 4,195-datagram transfer this
 * defect was found on — lasts about 22 ms at that offered rate and therefore
 * runs a deficit of roughly 1,100 datagrams. Measured, at exactly that burst,
 * four consecutive runs each:
 *
 *   1024 slots   1, 1, 108, 137 datagrams lost   (sized at the deficit: no margin)
 *   2048 slots   0, 0, 0, 0                      (86% margin)
 *   4096 slots   0, 0, 0, 0                      (no better, and twice the memory)
 *
 * 2048 is the smallest power of two with real margin over the measured burst.
 *
 * THE COST IS REAL AND IS NOT HIDDEN: slots * max_datagram of resident memory,
 * which is 2.87 MB at the shipping max_datagram of 1400. The extension's
 * measured footprint with both Go runtimes co-resident is 14.0 MB
 * phys_footprint, projected to 20-24 MB under load, against an iOS jetsam
 * ceiling around 50 MB. This adds about 3 MB to that projection. On macOS it
 * is immaterial; on iOS it is a deliberate trade of ~6% of the jetsam budget
 * for the elimination of a 34% loss event, and it is the number to revisit
 * first if the appex ever measures close to the ceiling.
 */
#define WINS_WINN_SEAM_RING_SLOTS 2048

/*
 * Requested SO_RCVBUF for the seam socket. The kernel clamps to
 * kern.ipc.maxsockbuf and the granted value is read back with getsockopt and
 * reported, so what is in force is a measured number rather than this wish.
 */
#define WINS_WINN_SEAM_RCVBUF_BYTES (2 * 1024 * 1024)

/* Bound on the writer thread's wait so a torn-down engine always progresses. */
#define WINS_WINN_RING_WAIT_MILLISECONDS 250

/*
 * Datagrams the writer claims per lock acquisition. See wins_winn_ring_claim
 * for the measurement that chose a batch over one-at-a-time.
 */
#define WINS_WINN_RING_BATCH 32

/*
 * Minimum gap between drop log lines. Under a sustained overflow every dropped
 * datagram logging once would itself become a load source, and the running
 * totals are in the stats accessor anyway. One line per second is enough to
 * make the condition impossible to miss in Console.
 */
#define WINS_WINN_DROP_LOG_INTERVAL_NANOSECONDS (1000ULL * 1000ULL * 1000ULL)

/*
 * The one logging channel this file has, and the reason it is allowed here.
 *
 * The rule at the top of this file — that the wrapper has no logging channel
 * because it handles a secret-bearing launch descriptor — is about the
 * DESCRIPTOR. Everything emitted through this handle is an integer counter.
 * No configuration value, endpoint, session id, key or datagram byte is ever
 * passed to it, and the format strings below take only unsigned long long.
 *
 * It exists because a counter nobody reads is how this defect stayed invisible
 * for as long as it did. The stats accessor is the machine-readable answer;
 * this is the one that shows up without anyone having asked.
 */
static os_log_t wins_winn_seam_log(void) {
#if DEBUG
  static os_log_t handle;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    handle = os_log_create("org.winsvpn.winn", "seam");
  });
  return handle;
#else
  return OS_LOG_DISABLED;
#endif
}

static uint64_t wins_winn_monotonic_nanoseconds(void) {
  return clock_gettime_nsec_np(CLOCK_MONOTONIC);
}

/*
 * Bounded FIFO between the seam drainer (single producer) and the engine
 * writer (single consumer). A mutex and a condition variable rather than a
 * lock-free ring: the critical section is a memcpy of at most max_datagram
 * bytes, the contention is between exactly two threads, and correctness under
 * teardown is worth more here than the tens of nanoseconds the atomics would
 * save.
 */
typedef struct WinsWinnSeamRing {
  uint8_t *storage;
  uint32_t *lengths;
  uint32_t slots;
  uint32_t slot_bytes;
  uint32_t head;
  uint32_t occupied;
  /*
   * One past the highest slot index ever written. calloc'd storage is backed
   * by untouched zero pages; only slots below this mark ever held a datagram,
   * so only they need wiping at close.
   */
  uint32_t touched;
  /*
   * Atomic because the writer tests it outside the lock on its idle path,
   * where taking the mutex only to read one bool would put a lock acquisition
   * on the teardown path of an otherwise idle tunnel. It is still SET under
   * the lock, next to the broadcast, so a waiter cannot miss the transition.
   */
  atomic_bool shutdown;
  pthread_mutex_t mutex;
  pthread_cond_t not_empty;
} WinsWinnSeamRing;

typedef struct WinsWinnSeamCounters {
  /* Datagrams recvfrom returned to us from the AmneziaWG engine. */
  atomic_ullong rx_datagrams;
  atomic_ullong rx_bytes;
  /* Dropped because OUR ring was full. Exact, and the whole point. */
  atomic_ullong rx_ring_dropped;
  /* Dropped before the ring for reasons this wrapper already had. */
  atomic_ullong rx_foreign_sender;
  atomic_ullong rx_oversize;
  /* Handed to WinnTunnelWriteInbound, and what came back. */
  atomic_ullong tx_written;
  atomic_ullong tx_too_large;
  atomic_ullong tx_failed;
  /* Gateway -> AmneziaWG engine, the reverse leg of the same seam. */
  atomic_ullong seam_sent;
  atomic_ullong seam_send_failed;
  atomic_ullong seam_no_peer;
  /*
   * Largest backlog SO_NREAD ever reported before a drain, in bytes. Compared
   * against the granted SO_RCVBUF this is the evidence for or against a
   * kernel-side drop having been possible at all.
   */
  atomic_ullong rx_backlog_high_water_bytes;
  /* Rate limiter for the drop log. */
  atomic_ullong last_drop_log_nanoseconds;
} WinsWinnSeamCounters;

typedef struct WinsWinnPacketEngine {
  char *launch_json;
  /*
   * The datapath.Config document, built from the [winn] section. Held
   * separately from launch_json because the launch descriptor is NOT a
   * datapath.Config: it carries schema_version, transport_mode, interface,
   * peer and required_components, none of which are fields of datapath.Config,
   * which decodes with DisallowUnknownFields and would reject the first one.
   */
  char *config_json;
  /*
   * The carrierhost.Profile document, present only when config_json's carrier
   * is not direct-awg. NULL selects WinnTunnelCreate at start; non-NULL
   * selects WinnTunnelCreateWithCarrier. Built and required at create time,
   * same as config_json, so a carrier session missing its profile fails
   * before any socket or thread exists.
   */
  char *carrier_profile_json;
  int32_t udp_fd;
  /* The loopback seam the AmneziaWG peer endpoint is pointed at. */
  int seam_fd;
  uint16_t seam_port;
  /*
   * The AWG engine's loopback source port, host byte order, 0 until the host
   * reads the engine's own listen_port and calls
   * wins_winn_packet_engine_expect_awg_port. Inbound admission and every
   * outbound destination use only this port; nothing is learned from traffic.
   */
  atomic_uint expected_awg_port;
  int max_datagram;
  int wake_read_fd;
  int wake_write_fd;
  WinnTunnelHandle tunnel;
  pthread_t inbound_thread;
  pthread_t outbound_thread;
  /*
   * The engine writer. inbound_thread now only drains the socket; this one
   * owns every WinnTunnelWriteInbound call, so a blocked write can no longer
   * stop the drain. See the SEAM BACKPRESSURE block above.
   */
  pthread_t writer_thread;
  bool inbound_thread_started;
  bool outbound_thread_started;
  bool writer_thread_started;
  atomic_bool stopping;
  bool started;
  CFTypeRef retained_packet_flow;
  /* Bounded FIFO between inbound_thread and writer_thread. */
  WinsWinnSeamRing ring;
  bool ring_ready;
  /* SO_RCVBUF the kernel actually granted on the seam socket. */
  int seam_rcvbuf_granted;
  WinsWinnSeamCounters counters;
} WinsWinnPacketEngine;

/*
 * Emits one line naming the running drop totals, at most once per
 * WINS_WINN_DROP_LOG_INTERVAL_NANOSECONDS. Integers only.
 */
static void wins_winn_note_drop(WinsWinnPacketEngine *engine) {
  uint64_t now = wins_winn_monotonic_nanoseconds();
  uint64_t previous =
      atomic_load_explicit(&engine->counters.last_drop_log_nanoseconds,
                           memory_order_relaxed);
  if (previous != 0 && now - previous < WINS_WINN_DROP_LOG_INTERVAL_NANOSECONDS) {
    return;
  }
  if (!atomic_compare_exchange_strong_explicit(
          &engine->counters.last_drop_log_nanoseconds, &previous, now,
          memory_order_relaxed, memory_order_relaxed)) {
    return;
  }
  os_log_error(wins_winn_seam_log(),
               "winn seam dropping outbound datagrams: ring_dropped=%llu "
               "received=%llu written=%llu write_failed=%llu "
               "backlog_high_water=%llu rcvbuf=%llu",
               (unsigned long long)atomic_load(&engine->counters.rx_ring_dropped),
               (unsigned long long)atomic_load(&engine->counters.rx_datagrams),
               (unsigned long long)atomic_load(&engine->counters.tx_written),
               (unsigned long long)atomic_load(&engine->counters.tx_failed),
               (unsigned long long)atomic_load(
                   &engine->counters.rx_backlog_high_water_bytes),
               (unsigned long long)engine->seam_rcvbuf_granted);
}

static bool wins_winn_ring_open(WinsWinnPacketEngine *engine) {
  WinsWinnSeamRing *ring = &engine->ring;
  memset(ring, 0, sizeof(*ring));
  ring->slots = WINS_WINN_SEAM_RING_SLOTS;
  ring->slot_bytes = (uint32_t)engine->max_datagram;
  ring->storage = calloc((size_t)ring->slots, (size_t)ring->slot_bytes);
  if (ring->storage == NULL) {
    return false;
  }
  ring->lengths = calloc((size_t)ring->slots, sizeof(uint32_t));
  if (ring->lengths == NULL) {
    free(ring->storage);
    ring->storage = NULL;
    return false;
  }
  if (pthread_mutex_init(&ring->mutex, NULL) != 0) {
    free(ring->storage);
    free(ring->lengths);
    ring->storage = NULL;
    ring->lengths = NULL;
    return false;
  }
  if (pthread_cond_init(&ring->not_empty, NULL) != 0) {
    pthread_mutex_destroy(&ring->mutex);
    free(ring->storage);
    free(ring->lengths);
    ring->storage = NULL;
    ring->lengths = NULL;
    return false;
  }
  engine->ring_ready = true;
  return true;
}

/*
 * Zeroes every slot before releasing it. The ring holds AmneziaWG outer
 * datagrams, and the rest of this file is careful not to leave those in freed
 * memory.
 */
static void wins_winn_ring_close(WinsWinnPacketEngine *engine) {
  WinsWinnSeamRing *ring = &engine->ring;
  if (!engine->ring_ready) {
    return;
  }
  /*
   * Cleared FIRST. wins_winn_packet_engine_seam_stats takes ring->mutex behind
   * this flag, and clearing it only after pthread_mutex_destroy would leave a
   * window in which a caller locks a destroyed mutex.
   */
  engine->ring_ready = false;
  if (ring->storage != NULL) {
    size_t wipe_bytes =
        (size_t)ring->touched * (size_t)ring->slot_bytes;
    if (wipe_bytes != 0) {
      memset_s(ring->storage, wipe_bytes, 0, wipe_bytes);
    }
    free(ring->storage);
    ring->storage = NULL;
  }
  if (ring->lengths != NULL) {
    free(ring->lengths);
    ring->lengths = NULL;
  }
  pthread_cond_destroy(&ring->not_empty);
  pthread_mutex_destroy(&ring->mutex);
}

/* Wakes the writer so it can observe shutdown. */
static void wins_winn_ring_shutdown(WinsWinnPacketEngine *engine) {
  if (!engine->ring_ready) {
    return;
  }
  pthread_mutex_lock(&engine->ring.mutex);
  atomic_store(&engine->ring.shutdown, true);
  pthread_cond_broadcast(&engine->ring.not_empty);
  pthread_mutex_unlock(&engine->ring.mutex);
}

/*
 * Producer side. Returns false when the ring is full, which is a COUNTED drop.
 * Tail drop rather than head drop: these are outer datagrams on their way to
 * the gateway, and discarding the newest keeps what is already queued in the
 * order AmneziaWG sealed it.
 */
static bool wins_winn_ring_push(WinsWinnPacketEngine *engine,
                                const uint8_t *datagram, uint32_t length) {
  WinsWinnSeamRing *ring = &engine->ring;
  if (length == 0 || length > ring->slot_bytes) {
    return false;
  }
  bool was_empty = false;
  pthread_mutex_lock(&ring->mutex);
  if (atomic_load(&ring->shutdown) || ring->occupied == ring->slots) {
    pthread_mutex_unlock(&ring->mutex);
    return false;
  }
  uint32_t slot = (ring->head + ring->occupied) % ring->slots;
  memcpy(ring->storage + (size_t)slot * (size_t)ring->slot_bytes, datagram,
         length);
  ring->lengths[slot] = length;
  if (slot + 1 > ring->touched) {
    ring->touched = slot + 1;
  }
  was_empty = ring->occupied == 0;
  ring->occupied += 1;
  pthread_mutex_unlock(&ring->mutex);
  /*
   * Signalled only on the empty -> non-empty edge. Signalling per datagram
   * would put a futex wake in the hot path at six figures a second for a
   * writer that is already running.
   */
  if (was_empty) {
    pthread_cond_signal(&ring->not_empty);
  }
  return true;
}

/*
 * Consumer side, claim half. Reserves a CONTIGUOUS run of up to
 * WINS_WINN_RING_BATCH queued slots and returns where it starts and how many,
 * WITHOUT advancing anything. The caller reads straight out of ring storage
 * and calls wins_winn_ring_release when it is done with them.
 *
 * WHY A BATCH AND NOT ONE AT A TIME. The first version of this took the lock,
 * copied one datagram out, and released — two lock acquisitions and a memcpy
 * per datagram, against a producer taking the same lock at over 190,000
 * datagrams a second. Measured on this machine, that contention held the
 * writer to ~137,000 datagrams/s while WinnTunnelWriteInbound on its own
 * sustains 225,300/s (4.44 us per call, measured directly), so the ring itself
 * had become the bottleneck it was added to remove.
 *
 * WHY THIS IS SAFE WITHOUT HOLDING THE LOCK. Single producer, single consumer.
 * The producer only ever writes to slot (head + occupied) % slots, and
 * `occupied` is not decremented until release, so the run being read is
 * exactly the region the producer is forbidden to touch. Restricting the run
 * to the end of the array keeps it contiguous and avoids a wrap check in the
 * read loop.
 */
static uint32_t wins_winn_ring_claim(WinsWinnPacketEngine *engine,
                                     uint32_t *out_start, bool wait) {
  WinsWinnSeamRing *ring = &engine->ring;
  pthread_mutex_lock(&ring->mutex);
  while (wait && ring->occupied == 0 && !atomic_load(&ring->shutdown)) {
    struct timespec deadline;
    deadline.tv_sec = 0;
    deadline.tv_nsec = WINS_WINN_RING_WAIT_MILLISECONDS * 1000L * 1000L;
    if (pthread_cond_timedwait_relative_np(&ring->not_empty, &ring->mutex,
                                           &deadline) != 0) {
      break;
    }
  }
  uint32_t available = ring->occupied;
  uint32_t start = ring->head;
  pthread_mutex_unlock(&ring->mutex);
  if (available == 0) {
    return 0;
  }
  if (available > WINS_WINN_RING_BATCH) {
    available = WINS_WINN_RING_BATCH;
  }
  /* Keep the run contiguous by stopping at the end of the array. */
  if (start + available > ring->slots) {
    available = ring->slots - start;
  }
  *out_start = start;
  return available;
}

static void wins_winn_ring_release(WinsWinnPacketEngine *engine, uint32_t taken) {
  WinsWinnSeamRing *ring = &engine->ring;
  if (taken == 0) {
    return;
  }
  pthread_mutex_lock(&ring->mutex);
  ring->head = (ring->head + taken) % ring->slots;
  ring->occupied -= taken;
  pthread_mutex_unlock(&ring->mutex);
}

static NSDictionary *wins_winn_launch_dictionary(const char *launch_json) {
  if (launch_json == NULL || launch_json[0] == '\0') {
    return nil;
  }
  NSData *data = [NSData dataWithBytes:launch_json length:strlen(launch_json)];
  if (data.length == 0) {
    return nil;
  }
  NSError *error = nil;
  id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
  if (error != nil || ![object isKindOfClass:[NSDictionary class]]) {
    return nil;
  }
  return (NSDictionary *)object;
}

/*
 * The `winn` object reaches the wrapper straight from the parsed tunnel
 * config, where every value is an INI string, so both NSString and NSNumber
 * have to be accepted.
 */
static NSString *wins_winn_section_string(NSDictionary *launch, NSString *key) {
  id winn = [launch objectForKey:@"winn"];
  if (![winn isKindOfClass:[NSDictionary class]]) {
    return nil;
  }
  id value = [(NSDictionary *)winn objectForKey:key];
  if ([value isKindOfClass:[NSString class]]) {
    NSString *text = [(NSString *)value
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    return text.length > 0 ? text : nil;
  }
  if ([value isKindOfClass:[NSNumber class]]) {
    return [(NSNumber *)value stringValue];
  }
  return nil;
}

/*
 * Reads an unsigned integer from the [winn] section. Returns false when the key
 * is absent, and leaves *out untouched; returns false with *out set to a
 * sentinel is deliberately NOT a case, because a malformed value must be
 * distinguishable from an absent one.
 */
static bool wins_winn_section_uint(NSDictionary *launch, NSString *key,
                                   unsigned long long *out, bool *malformed) {
  *malformed = false;
  NSString *text = wins_winn_section_string(launch, key);
  if (text == nil) {
    return false;
  }
  const char *bytes = text.UTF8String;
  if (bytes == NULL || bytes[0] == '\0') {
    *malformed = true;
    return false;
  }
  for (const char *cursor = bytes; *cursor != '\0'; cursor += 1) {
    if (*cursor < '0' || *cursor > '9') {
      *malformed = true;
      return false;
    }
  }
  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(bytes, &end, 10);
  if (errno != 0 || end == NULL || *end != '\0') {
    *malformed = true;
    return false;
  }
  *out = parsed;
  return true;
}

static bool wins_winn_parse_header_spec_text(NSString *trimmed,
                                                  unsigned long long *out_start,
                                                  unsigned long long *out_end) {
  // Mirrors VpnConfigValidator.parseAwgHeaderSpec and WinsTunnelConfig.parsedHeaderSpec.
  // `trimmed` is already whitespace-trimmed and non-nil.
  if (trimmed.length == 0 || trimmed.length > 21) {
    return false;
  }
  // interior whitespace (any whitespace remaining after trimming is interior)
  if ([trimmed rangeOfCharacterFromSet:[NSCharacterSet whitespaceCharacterSet]].location !=
      NSNotFound) {
    return false;
  }
  // \r, \n, \0 check (whitespace already handled \r\n, but be explicit for \0)
  const char *bytes = trimmed.UTF8String;
  if (bytes == NULL) return false;
  for (const char *c = bytes; *c != '\0'; c += 1) {
    if (*c == '\r' || *c == '\n' || *c == '\0') return false;
  }
  NSArray<NSString *> *parts = [trimmed componentsSeparatedByString:@"-"];
  if (parts.count == 1) {
    NSString *part = parts[0];
    if (part.length == 0 || part.length > 10) return false;
    for (NSUInteger i = 0; i < part.length; i += 1) {
      unichar ch = [part characterAtIndex:i];
      if (ch < '0' || ch > '9') return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(part.UTF8String, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || v < 5 || v > 0xFFFFFFFFULL) return false;
    *out_start = v;
    *out_end = v;
    return true;
  }
  if (parts.count != 2) return false;
  NSString *startText = parts[0];
  NSString *endText = parts[1];
  if (startText.length == 0 || startText.length > 10 || endText.length == 0 ||
      endText.length > 10) {
    return false;
  }
  for (NSString *part in parts) {
    for (NSUInteger i = 0; i < part.length; i += 1) {
      unichar ch = [part characterAtIndex:i];
      if (ch < '0' || ch > '9') return false;
    }
  }
  errno = 0;
  char *end = NULL;
  unsigned long long s = strtoull(startText.UTF8String, &end, 10);
  if (errno != 0 || end == NULL || *end != '\0') return false;
  errno = 0;
  unsigned long long e = strtoull(endText.UTF8String, &end, 10);
  if (errno != 0 || end == NULL || *end != '\0') return false;
  if (s < 5 || e > 0xFFFFFFFFULL || e < s) return false;
  unsigned long long width = e - s + 1;
  if (width > 0xFFFFFFFFULL) return false;
  if (width == 0) return false; // overflowed 2^32 span that wraps to 0
  *out_start = s;
  *out_end = e;
  return true;
}

static bool wins_winn_section_header_spec(NSDictionary *launch, NSString *key,
                                          unsigned long long *out_start,
                                          unsigned long long *out_end, bool *malformed) {
  *malformed = false;
  NSString *text = wins_winn_section_string(launch, key);
  if (text == nil) return false;
  unsigned long long s = 0, e = 0;
  if (!wins_winn_parse_header_spec_text(text, &s, &e)) {
    *malformed = true;
    return false;
  }
  *out_start = s;
  *out_end = e;
  return true;
}

/*
 * JSON string escaping for the config document. Only the characters JSON
 * requires: quote, backslash, and everything below 0x20. The [winn] values are
 * config-supplied, so an unescaped newline here would let one forge a second
 * JSON member.
 */
static void wins_winn_append_json_string(NSMutableString *out, NSString *value) {
  [out appendString:@"\""];
  NSUInteger length = value.length;
  for (NSUInteger index = 0; index < length; index += 1) {
    unichar character = [value characterAtIndex:index];
    switch (character) {
      case '"':
        [out appendString:@"\\\""];
        break;
      case '\\':
        [out appendString:@"\\\\"];
        break;
      case '\n':
        [out appendString:@"\\n"];
        break;
      case '\r':
        [out appendString:@"\\r"];
        break;
      case '\t':
        [out appendString:@"\\t"];
        break;
      default:
        if (character < 0x20) {
          [out appendFormat:@"\\u%04x", (unsigned)character];
        } else {
          [out appendFormat:@"%C", character];
        }
        break;
    }
  }
  [out appendString:@"\""];
}

/*
 * Builds the datapath.Config document from the [winn] section.
 *
 * THE SCHEMA IS THE ENGINE'S, NOT THIS FILE'S. Every key emitted below is a
 * field of datapath.Config in winn_protocol_experimental/datapath/config.go,
 * which decodes with DisallowUnknownFields — so a helpfully-added extra key is
 * a hard create-time error, not a silent default. This mirrors
 * android/.../WinnEngineConfig.kt, which builds the same document from the same
 * INI section for the subprocess transport.
 *
 * out_carrier, when non-NULL, receives the RESOLVED carrier (never nil on
 * success: an absent [winn] carrier resolves to direct-awg) as a value owned
 * by `launch` or a compile-time constant — the caller must not release it.
 * Left untouched on failure.
 *
 * Returns nil when the section cannot produce a document the engine would
 * accept. Never logs a value: the section is secret-bearing.
 */
static char *wins_winn_build_config_json(NSDictionary *launch, int max_datagram_ceiling,
                                         NSString **out_carrier) {
  NSString *endpoint = wins_winn_section_string(launch, @"endpoint");
  if (endpoint == nil) {
    /* An IP literal with a port is required; the engine refuses a hostname
     * because resolving one would leak a lookup outside the tunnel. The engine
     * itself is the authority on the format, so this only checks presence. */
    return NULL;
  }

  /*
   * The carrier gate. See wins_winn_carrier_supported() above: this ABI can
   * build exactly two carriers, so any other value is a refusal rather than
   * something to normalize away. Checked before anything else is parsed so a
   * carrier this wrapper cannot honour never reaches the engine at all.
   */
  NSString *rawCarrier = wins_winn_section_string(launch, @"carrier");
  NSString *carrier =
      rawCarrier != nil ? rawCarrier.lowercaseString : @WINS_WINN_SUPPORTED_CARRIER;
  if (!wins_winn_carrier_supported(carrier)) {
    return NULL;
  }

  bool malformed = false;
  unsigned long long max_datagram = 0;
  bool has_max_datagram =
      wins_winn_section_uint(launch, @"max_datagram", &max_datagram, &malformed);
  if (malformed) {
    return NULL;
  }
  if (has_max_datagram &&
      (max_datagram == 0 || max_datagram > (unsigned long long)max_datagram_ceiling)) {
    return NULL;
  }

  NSString *session_id = wins_winn_section_string(launch, @"session_id");

   /*
    * h1..h4 are all-or-nothing, and pairwise non-overlapping. With ranges the
    * test is interval intersection rather than equality -- the engine's own
    * mergeWithDevice refuses an overlapping set ("headers must not overlap"), so
    * accepting one here would hand the host a config it cannot start. For
    * scalars this degrades to equality, i.e. the pairwise-distinctness rule that
    * was here before ranges. Each header is an AwgHeaderSpec (start-end) where
    * a bare value is the degenerate range start==end, exactly as
    * device/magic-header.go stores it.
    */
   unsigned long long header_starts[4] = {0, 0, 0, 0};
   unsigned long long header_ends[4] = {0, 0, 0, 0};
   NSString *const header_keys[4] = {@"h1", @"h2", @"h3", @"h4"};
   // 0xFFFFFFFF ceiling parity
   int header_count = 0;
   for (int index = 0; index < 4; index += 1) {
     unsigned long long s = 0, e = 0;
     if (wins_winn_section_header_spec(launch, header_keys[index], &s, &e, &malformed)) {
       header_starts[index] = s;
       header_ends[index] = e;
       header_count += 1;
     } else if (malformed) {
       return NULL;
     }
   }
   if (header_count != 0 && header_count != 4) {
     return NULL;
   }
   if (header_count == 4) {
     for (int a = 0; a < 4; a += 1) {
       for (int b = a + 1; b < 4; b += 1) {
         if (header_starts[a] <= header_ends[b] && header_starts[b] <= header_ends[a]) {
           return NULL;
         }
       }
     }
   }

  /*
   * s1..s4 are the AmneziaWG prefix padding sizes. They are optional in
   * datapath.Config, but omitting a nonzero one silently kills the counter
   * class it pads: without s1/s2/s3 the handshake counters never move, and
   * without a nonzero s4 the TRANSPORT counters never move — and those are the
   * ones a route-promotion gate reads. They are accepted here so that a host
   * which supplies them gets meaningful status; nothing in the tree emits them
   * into the [winn] section yet.
   */
  unsigned long long padding[4] = {0, 0, 0, 0};
  NSString *const padding_keys[4] = {@"s1", @"s2", @"s3", @"s4"};
  bool has_padding[4] = {false, false, false, false};
  for (int index = 0; index < 4; index += 1) {
    has_padding[index] =
        wins_winn_section_uint(launch, padding_keys[index], &padding[index], &malformed);
    if (malformed) {
      return NULL;
    }
    if (has_padding[index] && padding[index] > 0xFFFFULL) {
      return NULL;
    }
  }

  NSMutableString *document = [NSMutableString stringWithCapacity:320];
  [document appendString:@"{\"contract\":"];
  wins_winn_append_json_string(document, @WINN_TUNNEL_CONTRACT_VERSION);
  /*
   * payload is the single most consequential value in this document. It
   * declares that Inbound and Outbound carry AmneziaWG OUTER datagrams, which
   * is true only because the pump below reads the loopback seam and not the
   * utun device.
   */
  [document appendString:@",\"payload\":\"awg-datagram\""];
  /*
   * carrier is the RESOLVED value, not a constant: the guard above has already
   * refused every config naming a carrier this ABI cannot build, so what
   * reaches here is exactly direct-awg or http3-connect-udp, and the document
   * states which one was verified rather than assuming direct-awg.
   */
  [document appendString:@",\"carrier\":"];
  wins_winn_append_json_string(document, carrier);
  [document appendString:@",\"gateway_endpoint\":"];
  wins_winn_append_json_string(document, endpoint);
  if (has_max_datagram) {
    [document appendFormat:@",\"max_datagram\":%llu", max_datagram];
  }
  if (session_id != nil) {
    [document appendString:@",\"session_id\":"];
    wins_winn_append_json_string(document, session_id);
  }
  /*
   * allow_own_socket is TRUE on Apple and false on Android, and the difference
   * is not a preference. Android hands over a descriptor it has already run
   * through VpnService.protect(), so the engine must never open one. Apple has
   * no protect(): the outer socket is kept off the tunnel by
   * NEIPv4Settings.excludedRoutes instead, which is a property of the route
   * table rather than of a descriptor, so the engine opening its own socket is
   * the supported arrangement. See the hazard note at the top of this file
   * about that exclusion route disappearing once the peer endpoint is loopback.
   */
   [document appendString:@",\"allow_own_socket\":true"];
   if (header_count == 4) {
     [document appendString:@",\"awg_header_types\":{"];
     for (int i = 0; i < 4; i += 1) {
       if (i > 0) [document appendString:@","];
       [document appendFormat:@"\"h%d\":", i + 1];
       if (header_starts[i] == header_ends[i]) {
         [document appendFormat:@"%llu", header_starts[i]];
       } else {
         [document appendFormat:@"\"%llu-%llu\"", header_starts[i], header_ends[i]];
       }
     }
     for (int index = 0; index < 4; index += 1) {
       if (has_padding[index] && padding[index] != 0) {
         [document appendFormat:@",\"s%d\":%llu", index + 1, padding[index]];
       }
     }
     [document appendString:@"}"];
   }
   [document appendString:@"}"];

  const char *utf8 = document.UTF8String;
  if (utf8 == NULL) {
    return NULL;
  }
  char *copy = strdup(utf8);
  if (copy != NULL && out_carrier != NULL) {
    *out_carrier = carrier;
  }
  return copy;
}

/*
 * Extracts the carrier profile document Swift built for a carrier session —
 * see kWinsWinnCarrierProfileKey above. Returns a heap copy the caller owns,
 * or NULL if the key is absent, empty, or not a string. This function does
 * NOT parse or validate the document: the real WinnTunnelCreateWithCarrier
 * does that, with the real carrierhost.ParseProfile, and a refusal there
 * names the actual field that was wrong. Duplicating that validation here in
 * Objective-C would be a second copy of ~150 lines of rules to keep in sync
 * and would only ever be evidence about a copy of the contract, not the
 * contract itself.
 */
static char *wins_winn_carrier_profile_json(NSDictionary *launch) {
  id value = [launch objectForKey:kWinsWinnCarrierProfileKey];
  if (![value isKindOfClass:[NSString class]]) {
    return NULL;
  }
  NSString *text =
      [(NSString *)value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
  if (text.length == 0) {
    return NULL;
  }
  const char *utf8 = text.UTF8String;
  return utf8 != NULL ? strdup(utf8) : NULL;
}

static bool wins_winn_should_stop(WinsWinnPacketEngine *engine) {
  return atomic_load_explicit(&engine->stopping, memory_order_acquire);
}

/*
 * Opens the loopback seam on an ephemeral port.
 *
 * Bound to 127.0.0.1 and not to the wildcard. That is the structural
 * containment described at the top of this file: a socket bound to the loopback
 * address has no route off the device, so it cannot be captured by the tunnel's
 * routes and needs no exclusion of its own.
 */
static bool wins_winn_open_seam(WinsWinnPacketEngine *engine) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }

  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_len = (__uint8_t)sizeof(address);
  address.sin_family = AF_INET;
  address.sin_port = 0;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0) {
    close(fd);
    return false;
  }

  struct sockaddr_in bound;
  memset(&bound, 0, sizeof(bound));
  socklen_t bound_length = (socklen_t)sizeof(bound);
  if (getsockname(fd, (struct sockaddr *)&bound, &bound_length) != 0) {
    close(fd);
    return false;
  }

  /*
   * NON-BLOCKING, so the inbound pump can drain the receive queue to empty and
   * stop on EAGAIN instead of returning to poll() after every single datagram.
   * The old loop paid a poll AND a recvfrom per datagram; under a burst that
   * halved the drain rate for no benefit, since poll had already said there
   * was something there.
   *
   * The outbound pump's sendto on this same descriptor becomes non-blocking
   * too. That is handled where it happens: a would-block on a loopback send is
   * counted, not ignored and not treated as terminal.
   */
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    close(fd);
    return false;
  }

  /*
   * Stated rather than inherited. On the machine this was measured on the
   * default was net.inet.udp.recvspace = 786,896 bytes, which is about 560
   * datagrams at the shipping max_datagram — and the measured overflow began
   * at datagram ~1,300 of an unpaced burst, exactly where a buffer that size
   * plus a concurrently draining reader would put it.
   *
   * A failure to enlarge it is NOT fatal: the drainer, the ring and the
   * accounting are what fix the defect, and they work at whatever size the
   * kernel grants. What must not happen is not knowing the size, so the
   * granted value is read back and reported alongside the backlog high-water
   * mark.
   */
  int requested = WINS_WINN_SEAM_RCVBUF_BYTES;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, (socklen_t)sizeof(requested));
  int granted = 0;
  socklen_t granted_length = (socklen_t)sizeof(granted);
  if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &granted, &granted_length) != 0) {
    granted = 0;
  }
  engine->seam_rcvbuf_granted = granted;

  engine->seam_fd = fd;
  engine->seam_port = ntohs(bound.sin_port);
  return engine->seam_port != 0;
}

/*
 * Admits only the loopback port the host published from the AWG engine's own
 * listen_port. Before that call nothing is admitted, and the inbound pump does
 * not read the seam at all, so early datagrams wait in the kernel queue. A
 * port match is not process authentication.
 */
static bool wins_winn_accept_peer(
    WinsWinnPacketEngine *engine,
    const struct sockaddr_in *sender) {
  if (sender->sin_family != AF_INET ||
      sender->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
    return false;
  }
  unsigned expected = atomic_load_explicit(
      &engine->expected_awg_port, memory_order_acquire);
  return expected != 0 && ntohs(sender->sin_port) == expected;
}

/*
 * AWG engine -> protocol, stage one of two: DRAIN ONLY.
 *
 * This thread must never do anything whose duration it does not control.
 * Everything it does per datagram is a recvfrom, a peer comparison and a
 * memcpy into the ring. The engine write — which blocks whenever the outer
 * socket applies backpressure — belongs to wins_winn_inbound_writer, because
 * while this thread is blocked nothing is emptying the kernel's receive queue
 * and every datagram that arrives is silently discarded by the kernel. That
 * was the measured defect; see the SEAM BACKPRESSURE block at the top.
 */
static void *wins_winn_inbound_pump(void *context) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)context;
  uint8_t buffer[WINS_WINN_DATAGRAM_BUFFER_BYTES];
  /*
   * One byte larger than the engine's limit, so a datagram that would not fit
   * is detected and dropped rather than silently truncated by recvfrom and
   * forwarded as a corrupt AWG frame. relay.go uses the same maxDatagram+1
   * trick.
   */
  const size_t capacity =
      (size_t)engine->max_datagram + 1 <= sizeof(buffer)
          ? (size_t)engine->max_datagram + 1
          : sizeof(buffer);

  while (!wins_winn_should_stop(engine)) {
    /*
     * Keep startup datagrams in the kernel queue until the host publishes
     * the AWG engine's actual port. Receiving them earlier would discard
     * the first handshake or admit an unauthenticated first sender.
     */
    if (atomic_load_explicit(
            &engine->expected_awg_port, memory_order_acquire) == 0) {
      struct pollfd binding_wait;
      binding_wait.fd = engine->wake_read_fd;
      binding_wait.events = POLLIN;
      binding_wait.revents = 0;

      int binding_ready = poll(&binding_wait, 1, 1);
      if (binding_ready < 0) {
        if (errno == EINTR || errno == EAGAIN) {
          continue;
        }
        break;
      }
      if (binding_ready > 0 &&
          (binding_wait.revents &
           (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0) {
        break;
      }
      continue;
    }

    struct pollfd fds[2];
    fds[0].fd = engine->seam_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = engine->wake_read_fd;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    int ready = poll(fds, 2, WINS_WINN_INBOUND_POLL_MILLISECONDS);
    if (ready < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        continue;
      }
      break;
    }
    if (ready == 0) {
      continue;
    }
    if ((fds[1].revents & POLLIN) != 0) {
      break;
    }
    if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      break;
    }
    if ((fds[0].revents & POLLIN) == 0) {
      continue;
    }

    /*
     * How much the kernel was holding at the moment poll woke us. This is the
     * only view Darwin offers of the queue that was overflowing, and the high
     * water mark it feeds is what distinguishes "the buffer was never close to
     * full" from "the buffer was full and the kernel was discarding". There is
     * no per-socket drop counter to read instead.
     */
    int pending = 0;
    if (ioctl(engine->seam_fd, FIONREAD, &pending) == 0 && pending > 0) {
      unsigned long long observed = (unsigned long long)pending;
      unsigned long long previous = atomic_load_explicit(
          &engine->counters.rx_backlog_high_water_bytes, memory_order_relaxed);
      while (observed > previous &&
             !atomic_compare_exchange_weak_explicit(
                 &engine->counters.rx_backlog_high_water_bytes, &previous,
                 observed, memory_order_relaxed, memory_order_relaxed)) {
      }
    }

    /*
     * DRAIN TO EMPTY. poll has already reported readability, so returning to
     * it after a single datagram costs one wasted syscall per datagram in
     * exactly the condition where syscalls are the scarce resource. The loop
     * ends on EAGAIN, which the non-blocking socket guarantees.
     */
    bool socket_failed = false;
    for (;;) {
      struct sockaddr_in sender;
      memset(&sender, 0, sizeof(sender));
      socklen_t sender_length = (socklen_t)sizeof(sender);
      ssize_t read_bytes = recvfrom(engine->seam_fd, buffer, capacity, 0,
                                    (struct sockaddr *)&sender, &sender_length);
      if (read_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        if (errno == EINTR) {
          continue;
        }
        socket_failed = true;
        break;
      }
      if (read_bytes == 0) {
        continue;
      }
      if (sender_length < (socklen_t)sizeof(struct sockaddr_in) ||
          !wins_winn_accept_peer(engine, &sender)) {
        /* A datagram from anything other than the pinned AWG engine. Dropping
         * it is what stops another local process injecting into the tunnel or
         * harvesting the gateway's replies. Counted, because a nonzero value
         * here is somebody probing the seam. */
        atomic_fetch_add(&engine->counters.rx_foreign_sender, 1);
        continue;
      }
      if ((size_t)read_bytes > (size_t)engine->max_datagram) {
        /* Oversize for this configuration: drop the datagram, keep the
         * tunnel. */
        atomic_fetch_add(&engine->counters.rx_oversize, 1);
        continue;
      }

      atomic_fetch_add(&engine->counters.rx_datagrams, 1);
      atomic_fetch_add(&engine->counters.rx_bytes, (unsigned long long)read_bytes);

      if (!wins_winn_ring_push(engine, buffer, (uint32_t)read_bytes)) {
        /*
         * THE DROP, AND IT IS OURS. The writer has fallen far enough behind
         * that 1024 datagrams are already waiting. Losing this one is the same
         * outcome the kernel used to produce, with the one difference that
         * matters: it is counted, it is attributable to this direction, and it
         * says so in the log.
         */
        atomic_fetch_add(&engine->counters.rx_ring_dropped, 1);
        wins_winn_note_drop(engine);
        continue;
      }
    }
    if (socket_failed) {
      break;
    }
  }

  /* Release a writer parked on the ring even if stop() has not run yet. */
  wins_winn_ring_shutdown(engine);
  return NULL;
}

/*
 * AWG engine -> protocol, stage two: the engine write, and the only place
 * WinnTunnelWriteInbound is called.
 *
 * This thread is ALLOWED to block. That is the point of splitting it out: the
 * Go engine's conn.WriteTo blocking on a full outer send buffer is genuine
 * downstream backpressure and must be respected, not bypassed. What it must
 * not do is stall the seam drain while it waits.
 */
static void *wins_winn_inbound_writer(void *context) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)context;
  WinsWinnSeamRing *ring = &engine->ring;
  bool terminal = false;

  while (!wins_winn_should_stop(engine) && !terminal) {
    uint32_t start = 0;
    uint32_t claimed = wins_winn_ring_claim(engine, &start, true);
    if (claimed == 0) {
      /* Shutdown, or the bounded wait expired with nothing queued. */
      if (atomic_load(&ring->shutdown)) {
        break;
      }
      continue;
    }

    uint32_t completed = 0;
    for (uint32_t index = 0; index < claimed; index += 1) {
      uint32_t slot = start + index;
      uint32_t length = ring->lengths[slot];
      completed += 1;
      if (length == 0) {
        continue;
      }
      /*
       * The archive declares the buffer as char *, so the cast is to char *
       * and not to a void * that would silently accept a different prototype.
       * The bytes are read straight out of ring storage: the producer cannot
       * touch this run until it is released, so there is nothing to copy.
       */
      int written = WinnTunnelWriteInbound(
          engine->tunnel,
          (char *)(ring->storage + (size_t)slot * (size_t)ring->slot_bytes),
          (int)length);
      if (written < 0) {
        /*
         * An oversize datagram is dropped by the archive and costs one packet;
         * the tunnel itself is still healthy, so it must not tear the pump
         * down. Every other negative code is terminal for this handle.
         */
        if (written == WINN_TUNNEL_ERR_TOO_LARGE) {
          atomic_fetch_add(&engine->counters.tx_too_large, 1);
          continue;
        }
        atomic_fetch_add(&engine->counters.tx_failed, 1);
        os_log_error(wins_winn_seam_log(),
                     "winn seam inbound writer stopping, engine code=%lld "
                     "written=%llu ring_dropped=%llu",
                     (long long)written,
                     (unsigned long long)atomic_load(
                         &engine->counters.tx_written),
                     (unsigned long long)atomic_load(
                         &engine->counters.rx_ring_dropped));
        terminal = true;
        break;
      }
      atomic_fetch_add(&engine->counters.tx_written, 1);
    }
    /* Release exactly what was consumed, so a terminal exit mid-batch does not
     * hand the producer slots the writer never read. */
    wins_winn_ring_release(engine, completed);
  }

  return NULL;
}

/* protocol -> AWG engine. Outer datagrams the gateway sent back. */
static void *wins_winn_outbound_pump(void *context) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)context;
  uint8_t buffer[WINS_WINN_DATAGRAM_BUFFER_BYTES];
  const int capacity = engine->max_datagram <= (int)sizeof(buffer)
                           ? engine->max_datagram
                           : (int)sizeof(buffer);

  while (!wins_winn_should_stop(engine)) {
    int datagram_bytes = WinnTunnelReadOutbound(
        engine->tunnel, (char *)buffer, capacity,
        WINS_WINN_OUTBOUND_READ_TIMEOUT_MILLISECONDS);
    if (datagram_bytes < 0) {
      /*
       * TIMEOUT is the bounded wait expiring with nothing queued: re-check the
       * stop flag and wait again. TOO_LARGE means the archive dropped one
       * oversize datagram rather than truncating into this buffer, which costs
       * a packet and leaves the tunnel healthy. Every other negative code —
       * HANDLE, CLOSED, CARRIER, ARGUMENT — is terminal for this handle.
       */
      if (datagram_bytes == WINN_TUNNEL_ERR_TIMEOUT ||
          datagram_bytes == WINN_TUNNEL_ERR_TOO_LARGE) {
        continue;
      }
      break;
    }
    if (datagram_bytes == 0) {
      usleep(WINS_WINN_IDLE_POLL_MICROSECONDS);
      continue;
    }
    if (datagram_bytes > capacity) {
      continue;
    }
    unsigned expected = atomic_load_explicit(
        &engine->expected_awg_port, memory_order_acquire);
    if (expected == 0) {
      atomic_fetch_add(&engine->counters.seam_no_peer, 1);
      continue;
    }

    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_len = (__uint8_t)sizeof(destination);
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    destination.sin_port = htons((in_port_t)expected);

    ssize_t written = sendto(
        engine->seam_fd, buffer, (size_t)datagram_bytes, 0,
        (const struct sockaddr *)&destination,
        (socklen_t)sizeof(destination));
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
        /*
         * The reverse leg of the same defect, and the one thing here that
         * cannot be fixed from this side. The AmneziaWG engine owns the
         * receiving socket; if IT is not draining, the kernel discards on
         * delivery and this sendto still reports success. What is reachable is
         * this: a send that fails outright is counted instead of being
         * mistaken for a torn carrier, and the count says the seam had more to
         * deliver than the AWG engine was taking.
         */
        atomic_fetch_add(&engine->counters.seam_send_failed, 1);
        wins_winn_note_drop(engine);
        continue;
      }
      break;
    }
    atomic_fetch_add(&engine->counters.seam_sent, 1);
  }

  return NULL;
}

/*
 * WinnTunnelClose returns NULL on success or an allocated message the caller
 * must release with WinnTunnelFreeString. Every close in this file goes through
 * here, because a dropped return value leaks on every failing teardown and
 * teardown is the path that fails.
 *
 * The message is released rather than reported: this wrapper has no logging
 * channel by design (it handles a secret-bearing launch descriptor), and the
 * authoritative post-mortem is WinnTunnelStatusJSON, read by the Swift layer.
 */
static void wins_winn_close_tunnel(WinsWinnPacketEngine *engine) {
  if (engine->tunnel <= WINN_TUNNEL_INVALID_HANDLE) {
    return;
  }
  char *close_error = WinnTunnelClose(engine->tunnel);
  if (close_error != NULL) {
    WinnTunnelFreeString(close_error);
  }
}

/*
 * The archive's own contract string must match the one WinnTunnel.h was
 * transcribed from. A wrapper built against a different contract is a
 * silent-corruption risk rather than a warning, so this refuses to start
 * instead of degrading. This is the runtime half of the guard that
 * tools/verify_winn_abi_conformance.sh enforces at build time: the build step
 * proves the sources agree, this proves the archive actually loaded at runtime
 * is the one they agree with.
 */
static bool wins_winn_contract_matches(void) {
  char *contract = WinnTunnelContractVersion();
  if (contract == NULL) {
    return false;
  }
  bool matches = strcmp(contract, WINN_TUNNEL_CONTRACT_VERSION) == 0;
  WinnTunnelFreeString(contract);
  return matches;
}

static void wins_winn_close_wake_pipe(WinsWinnPacketEngine *engine) {
  if (engine->wake_read_fd >= 0) {
    close(engine->wake_read_fd);
    engine->wake_read_fd = -1;
  }
  if (engine->wake_write_fd >= 0) {
    close(engine->wake_write_fd);
    engine->wake_write_fd = -1;
  }
}

static void wins_winn_close_seam(WinsWinnPacketEngine *engine) {
  if (engine->seam_fd >= 0) {
    close(engine->seam_fd);
    engine->seam_fd = -1;
  }
  engine->seam_port = 0;
  atomic_store_explicit(&engine->expected_awg_port, 0u, memory_order_release);
}

__attribute__((visibility("default")))
int wins_winn_packet_engine_contract_version(void) {
  return 1;
}

__attribute__((visibility("default")))
void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow) {
  @autoreleasepool {
    NSDictionary *launch = wins_winn_launch_dictionary(launch_json);
    if (launch == nil) {
      return NULL;
    }

    WinsWinnPacketEngine *engine =
        (WinsWinnPacketEngine *)calloc(1, sizeof(WinsWinnPacketEngine));
    if (engine == NULL) {
      return NULL;
    }

    /*
     * The validated launch descriptor is forwarded verbatim. It is
     * secret-bearing, process-local data: never log it.
     */
    engine->launch_json = strdup(launch_json);
    engine->carrier_profile_json = NULL;
    /*
     * Apple passes -1: the engine opens its own outer socket, which is
     * permitted only because the configuration sets allow_own_socket and the
     * provider's excludedRoutes keep it off the tunnel.
     */
    engine->udp_fd = -1;
    engine->seam_fd = -1;
    engine->seam_port = 0;
    engine->max_datagram = 0;
    engine->wake_read_fd = -1;
    engine->wake_write_fd = -1;
    engine->tunnel = WINN_TUNNEL_INVALID_HANDLE;
    engine->started = false;
    atomic_store_explicit(&engine->stopping, false, memory_order_release);
    atomic_store_explicit(&engine->expected_awg_port, 0u, memory_order_release);
    if (packet_flow != NULL) {
      /*
       * Retained only to keep the NEPacketTunnelFlow alive for the lifetime of
       * the engine, matching the AmneziaWG wrapper. Winn never reads it: the
       * AmneziaWG engine owns the tun device, and this seam sits below it.
       */
      engine->retained_packet_flow = CFRetain(packet_flow);
    }

    /*
     * The config document is built at create time so a [winn] section the
     * engine could never accept fails before a socket is opened or a thread is
     * spawned. WinnTunnelMaxDatagram() is the archive's own ceiling, which is
     * the only correct bound to validate max_datagram against.
     */
    NSString *resolvedCarrier = nil;
    int ceiling = WinnTunnelMaxDatagram();
    if (ceiling > 0) {
      engine->config_json = wins_winn_build_config_json(launch, ceiling, &resolvedCarrier);
    }

    /*
     * A carrier session's profile is required at the SAME time as its config:
     * both are secret-adjacent, config-derived documents that must exist
     * before a socket or thread does, and a session that resolved to
     * http3-connect-udp with no usable profile is exactly as unstartable as
     * one with no [winn] endpoint. Routing the failure through config_json
     * reuses the cleanup below instead of adding a second copy of it.
     */
    if (engine->config_json != NULL &&
        [resolvedCarrier isEqualToString:@WINS_WINN_SUPPORTED_CARRIER_HTTP3]) {
      engine->carrier_profile_json = wins_winn_carrier_profile_json(launch);
      if (engine->carrier_profile_json == NULL) {
        memset_s(engine->config_json, strlen(engine->config_json), 0,
                 strlen(engine->config_json));
        free(engine->config_json);
        engine->config_json = NULL;
      }
    }

    if (engine->launch_json == NULL || engine->config_json == NULL) {
      if (engine->retained_packet_flow != NULL) {
        CFRelease(engine->retained_packet_flow);
      }
      if (engine->launch_json != NULL) {
        memset_s(engine->launch_json, strlen(engine->launch_json), 0,
                 strlen(engine->launch_json));
        free(engine->launch_json);
      }
      if (engine->config_json != NULL) {
        memset_s(engine->config_json, strlen(engine->config_json), 0,
                 strlen(engine->config_json));
        free(engine->config_json);
      }
      if (engine->carrier_profile_json != NULL) {
        memset_s(engine->carrier_profile_json, strlen(engine->carrier_profile_json), 0,
                 strlen(engine->carrier_profile_json));
        free(engine->carrier_profile_json);
      }
      free(engine);
      return NULL;
    }

    return engine;
  }
}

__attribute__((visibility("default")))
int wins_winn_packet_engine_start(void *opaque_engine) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)opaque_engine;
  if (engine == NULL || engine->config_json == NULL) {
    return 0;
  }
  if (engine->started) {
    return 1;
  }

  /*
   * Preflight the archive before anything is allocated. Both checks are about
   * the archive that actually loaded, which is the one thing a compile-time
   * guard cannot see.
   */
  if (!wins_winn_contract_matches()) {
    return 0;
  }
  int max_datagram = WinnTunnelMaxDatagram();
  if (max_datagram <= 0 ||
      max_datagram > (int)(WINS_WINN_DATAGRAM_BUFFER_BYTES - 1)) {
    /*
     * The archive states the largest datagram any configuration may permit, and
     * the contract is explicit that a read buffer is sized from this and never
     * from a guessed MTU. The buffer here is fixed at compile time, so the
     * check is that the fixed size is still sufficient for the archive that
     * actually loaded. The -1 leaves room for the oversize-detection byte the
     * inbound pump reads into.
     */
    return 0;
  }
  engine->max_datagram = max_datagram;

  if (!wins_winn_open_seam(engine)) {
    return 0;
  }

  /*
   * Allocated before the tunnel and the threads, so an engine that cannot get
   * its ring never opens a carrier it would then have to unwind. Sized from
   * max_datagram, which is only known once the archive has been asked.
   */
  if (!wins_winn_ring_open(engine)) {
    wins_winn_close_seam(engine);
    return 0;
  }

  int wake_fds[2] = {-1, -1};
  if (pipe(wake_fds) != 0) {
    wins_winn_ring_close(engine);
    wins_winn_close_seam(engine);
    return 0;
  }

  engine->wake_read_fd = wake_fds[0];
  engine->wake_write_fd = wake_fds[1];
  atomic_store_explicit(&engine->stopping, false, memory_order_release);

  /*
   * errorOut MUST start NULL and MUST be released with WinnTunnelFreeString.
   * The archive writes through this pointer, so passing an uninitialised one
   * is a wild store, and dropping the result leaks on every failed create.
   */
  char *create_error = NULL;
  /*
   * carrier_profile_json is NULL for direct-awg and non-NULL for exactly the
   * carriers this ABI can build a document for (see
   * wins_winn_carrier_supported()) -- create() already refused every other
   * carrier and required a profile wherever one is needed, so its mere
   * presence here is what selects the entry point, with no second carrier
   * check to keep in sync with the one create() already made.
   */
  WinnTunnelHandle tunnel =
      engine->carrier_profile_json != NULL
          ? WinnTunnelCreateWithCarrier(engine->config_json, engine->carrier_profile_json,
                                        (int)engine->udp_fd, &create_error)
          : WinnTunnelCreate(engine->config_json, (int)engine->udp_fd, &create_error);
  if (create_error != NULL) {
#if defined(WINS_WINN_ENGINE_TESTING) && WINS_WINN_ENGINE_TESTING
    /*
     * Testing builds only. The message is the archive's own refusal reason, and
     * seeing it is the difference between a diagnosable failure and a silent
     * one. Production builds release it unread: this wrapper has no logging
     * channel and the message can quote configuration.
     */
    fprintf(stderr, "WinnTunnelCreate refused: %s\n", create_error);
#endif
    WinnTunnelFreeString(create_error);
    create_error = NULL;
  }
  if (tunnel <= WINN_TUNNEL_INVALID_HANDLE) {
    wins_winn_close_wake_pipe(engine);
    wins_winn_ring_close(engine);
    wins_winn_close_seam(engine);
    return 0;
  }
  engine->tunnel = tunnel;

  /*
   * Started before the drainer, so there is never a window in which datagrams
   * are being pushed into a ring nobody is emptying.
   */
  if (pthread_create(&engine->writer_thread, NULL, wins_winn_inbound_writer, engine) != 0) {
    wins_winn_close_tunnel(engine);
    engine->tunnel = WINN_TUNNEL_INVALID_HANDLE;
    wins_winn_close_wake_pipe(engine);
    wins_winn_ring_close(engine);
    wins_winn_close_seam(engine);
    return 0;
  }
  engine->writer_thread_started = true;

  if (pthread_create(&engine->inbound_thread, NULL, wins_winn_inbound_pump, engine) != 0) {
    atomic_store_explicit(&engine->stopping, true, memory_order_release);
    wins_winn_close_tunnel(engine);
    wins_winn_ring_shutdown(engine);
    pthread_join(engine->writer_thread, NULL);
    engine->writer_thread_started = false;
    engine->tunnel = WINN_TUNNEL_INVALID_HANDLE;
    wins_winn_close_wake_pipe(engine);
    wins_winn_ring_close(engine);
    wins_winn_close_seam(engine);
    return 0;
  }
  engine->inbound_thread_started = true;

  if (pthread_create(&engine->outbound_thread, NULL, wins_winn_outbound_pump, engine) != 0) {
    atomic_store_explicit(&engine->stopping, true, memory_order_release);
    wins_winn_close_tunnel(engine);
    if (engine->wake_write_fd >= 0) {
      ssize_t ignored = write(engine->wake_write_fd, "x", 1);
      (void)ignored;
    }
    pthread_join(engine->inbound_thread, NULL);
    engine->inbound_thread_started = false;
    wins_winn_ring_shutdown(engine);
    pthread_join(engine->writer_thread, NULL);
    engine->writer_thread_started = false;
    engine->tunnel = WINN_TUNNEL_INVALID_HANDLE;
    wins_winn_close_wake_pipe(engine);
    wins_winn_ring_close(engine);
    wins_winn_close_seam(engine);
    return 0;
  }
  engine->outbound_thread_started = true;

  engine->started = true;
  return 1;
}

/*
 * ADDITIVE SEVENTH SYMBOL. The seam's own counters, as a JSON object, written
 * into a caller-supplied buffer. Returns the number of bytes written excluding
 * the terminator, or 0 if nothing could be written.
 *
 * WHY THIS EXISTS. WinnTunnelStatusJSON reports what the Go ENGINE saw. The
 * datagrams this defect lost never reached the engine — they were discarded by
 * the kernel on the seam's receive queue — so every field in that document
 * stayed at a healthy zero while a third of the traffic disappeared. These
 * counters are on the other side of that boundary, which is the only side from
 * which the loss is visible at all.
 *
 * A buffer rather than a returned string, so there is no eighth symbol to free
 * it with and no ownership rule for a caller to get wrong.
 *
 * Nothing here is config-derived: every value is an integer this wrapper
 * counted itself, so this is safe to log in full, unlike the launch descriptor.
 */
__attribute__((visibility("default")))
int wins_winn_packet_engine_seam_stats(void *opaque_engine, char *out, int capacity) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)opaque_engine;
  if (engine == NULL || out == NULL || capacity <= 0) {
    return 0;
  }
  unsigned long long queued = 0;
  if (engine->ring_ready) {
    pthread_mutex_lock(&engine->ring.mutex);
    queued = engine->ring.occupied;
    pthread_mutex_unlock(&engine->ring.mutex);
  }
  int written = snprintf(
      out, (size_t)capacity,
      "{\"seam_rx_datagrams\":%llu,\"seam_rx_bytes\":%llu,"
      "\"seam_rx_ring_dropped\":%llu,\"seam_rx_foreign_sender\":%llu,"
      "\"seam_rx_oversize\":%llu,\"seam_tx_written\":%llu,"
      "\"seam_tx_too_large\":%llu,\"seam_tx_failed\":%llu,"
      "\"seam_sent_to_awg\":%llu,\"seam_send_failed\":%llu,"
      "\"seam_no_peer\":%llu,\"seam_ring_slots\":%llu,"
      "\"seam_ring_queued\":%llu,\"seam_rx_backlog_high_water_bytes\":%llu,"
      "\"seam_rcvbuf_bytes\":%llu}",
      (unsigned long long)atomic_load(&engine->counters.rx_datagrams),
      (unsigned long long)atomic_load(&engine->counters.rx_bytes),
      (unsigned long long)atomic_load(&engine->counters.rx_ring_dropped),
      (unsigned long long)atomic_load(&engine->counters.rx_foreign_sender),
      (unsigned long long)atomic_load(&engine->counters.rx_oversize),
      (unsigned long long)atomic_load(&engine->counters.tx_written),
      (unsigned long long)atomic_load(&engine->counters.tx_too_large),
      (unsigned long long)atomic_load(&engine->counters.tx_failed),
      (unsigned long long)atomic_load(&engine->counters.seam_sent),
      (unsigned long long)atomic_load(&engine->counters.seam_send_failed),
      (unsigned long long)atomic_load(&engine->counters.seam_no_peer),
      (unsigned long long)(engine->ring_ready ? engine->ring.slots : 0), queued,
      (unsigned long long)atomic_load(
          &engine->counters.rx_backlog_high_water_bytes),
      (unsigned long long)engine->seam_rcvbuf_granted);
  if (written < 0 || written >= capacity) {
    return 0;
  }
  return written;
}

/*
 * ADDITIVE EIGHTH SYMBOL. The Go engine's own WinnTunnelStatusJSON, copied
 * into a caller-supplied buffer. Returns bytes written excluding the
 * terminator, or 0.
 *
 * WHY A PASSTHROUGH AND NOT AN ACCESSOR FOR THE HANDLE. Handing out the raw
 * WinnTunnelHandle would let any caller invoke WinnTunnelClose on the tunnel
 * this engine is pumping, which would tear the session down from outside the
 * lifecycle that owns it and leave both pump threads reading a retired handle.
 * The only thing the handle was wanted for is the status document, so the
 * status document is what is exposed. Nothing about the counters needs the
 * handle itself.
 *
 * READ IT TOGETHER WITH wins_winn_packet_engine_seam_stats, not instead of it.
 * They observe opposite sides of the seam boundary and the burst defect was
 * visible only on one of them: during a 200,000-datagram run at full rate this
 * document reported tx_rejected=0 and rx_dropped=0 while the seam's own
 * counters recorded every datagram that had been lost. tx_rejected counts what
 * the ENGINE refused; it cannot count what never reached the engine.
 */
__attribute__((visibility("default")))
int wins_winn_packet_engine_status_json(void *opaque_engine, char *out, int capacity) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)opaque_engine;
  if (engine == NULL || out == NULL || capacity <= 0) {
    return 0;
  }
  if (!engine->started || engine->tunnel <= WINN_TUNNEL_INVALID_HANDLE) {
    return 0;
  }
  char *status = WinnTunnelStatusJSON(engine->tunnel);
  if (status == NULL) {
    return 0;
  }
  size_t length = strlen(status);
  if (length >= (size_t)capacity) {
    WinnTunnelFreeString(status);
    return 0;
  }
  memcpy(out, status, length + 1);
  WinnTunnelFreeString(status);
  return (int)length;
}

/*
 * The loopback port the AmneziaWG peer endpoint must be rewritten to, or 0
 * before start / after stop.
 *
 * ADDITIVE SIXTH SYMBOL, deliberately outside the v1 five-symbol carrier ABI
 * that WinsNativePacketTunnelEngine resolves. The generic loader is unchanged
 * and still finds exactly the five it knows; only a Winn-aware caller looks
 * this one up. Widening the shared carrier ABI for something only one carrier
 * has would have made every other wrapper implement a no-op.
 */
__attribute__((visibility("default")))
int wins_winn_packet_engine_awg_seam_port(void *opaque_engine) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)opaque_engine;
  if (engine == NULL || !engine->started) {
    return 0;
  }
  return (int)engine->seam_port;
}

__attribute__((visibility("default")))
int wins_winn_packet_engine_expect_awg_port(void *opaque_engine, int port) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)opaque_engine;
  if (engine == NULL || !engine->started || port <= 0 || port > 65535) {
    return 0;
  }
  atomic_store_explicit(
      &engine->expected_awg_port, (unsigned)port, memory_order_release);
  return 1;
}

__attribute__((visibility("default")))
void wins_winn_packet_engine_stop(void *opaque_engine) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)opaque_engine;
  if (engine == NULL || !engine->started) {
    return;
  }

  atomic_store_explicit(&engine->stopping, true, memory_order_release);
  if (engine->wake_write_fd >= 0) {
    ssize_t ignored = write(engine->wake_write_fd, "x", 1);
    (void)ignored;
  }

  /*
   * Close before joining: the contract requires WinnTunnelClose to unblock an
   * in-flight WinnTunnelReadOutbound, which is what lets the outbound pump
   * observe the stop flag. engine->tunnel is deliberately left intact until
   * after the joins — the pumps still read it, and a closed handle returning a
   * negative code is exactly how they are meant to unwind.
   */
  wins_winn_close_tunnel(engine);

  if (engine->inbound_thread_started) {
    pthread_join(engine->inbound_thread, NULL);
    engine->inbound_thread_started = false;
  }
  /*
   * The drainer is joined first so nothing is still pushing, then the ring is
   * shut down and the writer joined. Joining the writer earlier would race a
   * push against a freed ring.
   */
  wins_winn_ring_shutdown(engine);
  if (engine->writer_thread_started) {
    pthread_join(engine->writer_thread, NULL);
    engine->writer_thread_started = false;
  }
  if (engine->outbound_thread_started) {
    pthread_join(engine->outbound_thread, NULL);
    engine->outbound_thread_started = false;
  }
  engine->tunnel = WINN_TUNNEL_INVALID_HANDLE;

  /*
   * ONE UNCONDITIONAL LINE PER SESSION, drops or no drops. The whole reason
   * this defect survived a passing end-to-end run is that a lossless session
   * and a 34%-loss session produced identical output. They no longer do.
   */
  {
    unsigned long long dropped = atomic_load(&engine->counters.rx_ring_dropped);
    unsigned long long received = atomic_load(&engine->counters.rx_datagrams);
    if (dropped > 0 || atomic_load(&engine->counters.seam_send_failed) > 0) {
      os_log_error(wins_winn_seam_log(),
                   "winn seam closed WITH LOSS: received=%llu written=%llu "
                   "ring_dropped=%llu send_failed=%llu backlog_high_water=%llu "
                   "rcvbuf=%llu",
                   received,
                   (unsigned long long)atomic_load(&engine->counters.tx_written),
                   dropped,
                   (unsigned long long)atomic_load(
                       &engine->counters.seam_send_failed),
                   (unsigned long long)atomic_load(
                       &engine->counters.rx_backlog_high_water_bytes),
                   (unsigned long long)engine->seam_rcvbuf_granted);
    } else {
      os_log(wins_winn_seam_log(),
             "winn seam closed clean: received=%llu written=%llu "
             "backlog_high_water=%llu rcvbuf=%llu",
             received,
             (unsigned long long)atomic_load(&engine->counters.tx_written),
             (unsigned long long)atomic_load(
                 &engine->counters.rx_backlog_high_water_bytes),
             (unsigned long long)engine->seam_rcvbuf_granted);
    }
  }

  wins_winn_close_wake_pipe(engine);
  wins_winn_ring_close(engine);
  /* The seam socket is this wrapper's own; unlike the utun device it must be
   * closed here. */
  wins_winn_close_seam(engine);
  engine->started = false;
}

__attribute__((visibility("default")))
void wins_winn_packet_engine_destroy(void *opaque_engine) {
  WinsWinnPacketEngine *engine = (WinsWinnPacketEngine *)opaque_engine;
  if (engine == NULL) {
    return;
  }

  wins_winn_packet_engine_stop(engine);
  if (engine->launch_json != NULL) {
    memset(engine->launch_json, 0, strlen(engine->launch_json));
    free(engine->launch_json);
    engine->launch_json = NULL;
  }
  if (engine->config_json != NULL) {
    memset(engine->config_json, 0, strlen(engine->config_json));
    free(engine->config_json);
    engine->config_json = NULL;
  }
  if (engine->carrier_profile_json != NULL) {
    memset(engine->carrier_profile_json, 0, strlen(engine->carrier_profile_json));
    free(engine->carrier_profile_json);
    engine->carrier_profile_json = NULL;
  }
  if (engine->retained_packet_flow != NULL) {
    CFRelease(engine->retained_packet_flow);
    engine->retained_packet_flow = NULL;
  }
  free(engine);
}
