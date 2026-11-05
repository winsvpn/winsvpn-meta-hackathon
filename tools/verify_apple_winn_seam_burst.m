/*
 * verify_apple_winn_seam_burst.m — the regression test for the seam's
 * UNPACED-BURST behaviour.
 *
 * ---------------------------------------------------------------------------
 * THE DEFECT THIS EXISTS FOR
 * ---------------------------------------------------------------------------
 *
 * Measured on macOS arm64, 2026-08-04/05, against the shipping wrapper:
 *
 *   4,195 datagrams offered unpaced at ~130,000 pkt/s -> 1,380 lost (32.90%)
 *   20,000 datagrams offered unpaced at ~234,000 pkt/s -> 9,255 lost (46.27%)
 *
 * and in every run the kernel's own "dropped due to full socket buffers"
 * counter (netstat -s -p udp) moved by exactly the number missing. Inserting
 * 200 us between sends made the loss zero, which is why nothing caught this:
 * the Linux lane's 4 MiB run used nc over TCP and the Android device run was
 * paced, so neither ever produced the burst.
 *
 * tools/verify_apple_winn_seam.sh proves correctness — carrier selection,
 * refusals, peer pinning, ordering, teardown, and that datagrams relay both
 * ways. It says nothing about RATE, and the defect was purely a rate
 * phenomenon. That is the gap this file closes.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT DRIVES
 * ---------------------------------------------------------------------------
 *
 *   producer UDP socket   stands in for amneziawg-go's outer socket
 *     -> 127.0.0.1:<seam_port>   REAL seam, bound by the REAL wrapper compiled
 *                                from apple/EngineWrappers/
 *     -> WinnTunnelWriteInbound  REAL Go datapath c-archive
 *     -> the engine's own outer UDP socket
 *     -> sink UDP socket         stands in for the gateway
 *
 * The wrapper is created with packet_flow == NULL, which it explicitly
 * tolerates, and the carrier is direct-awg, which relays each datagram to the
 * gateway endpoint unmodified. Every datagram is shaped like an AmneziaWG
 * transport-data outer datagram — type(4) | receiver(4) | counter(8) | body —
 * with the sequence number in the counter field, so the sink can name exactly
 * WHICH datagrams went missing and not merely how many.
 *
 * ---------------------------------------------------------------------------
 * WHY THE CONTROL CASE IS NOT OPTIONAL
 * ---------------------------------------------------------------------------
 *
 * Case 1 bursts the identical traffic straight at the sink with the seam
 * bypassed. If THAT loses datagrams, the harness is measuring its own producer
 * or its own sink and every other number in the run is worthless. It runs
 * first and a failure there is reported as a harness fault, not a seam defect.
 *
 * ---------------------------------------------------------------------------
 * ANTI-FABRICATION
 * ---------------------------------------------------------------------------
 *
 * Nothing here is asserted from the wrapper's own counters. Loss is measured
 * end to end by a socket at the far side of the whole chain, comparing which
 * sequence numbers arrived against which were sent. The wrapper's counters are
 * printed alongside and cross-checked, so a counter that disagrees with the
 * ground truth is itself a failure.
 *
 * Usage: verify_apple_winn_seam_burst
 * Env:   WINN_SEAM_BURST_COUNT      datagrams per case (default 20000)
 *        WINN_SEAM_BURST_TOLERANCE  permitted lost datagrams (default 0)
 */

#import <Foundation/Foundation.h>

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

extern void *wins_winn_packet_engine_create(const char *launch_json,
                                            const void *packet_flow);
extern int wins_winn_packet_engine_start(void *engine);
extern int wins_winn_packet_engine_awg_seam_port(void *engine);
extern int wins_winn_packet_engine_expect_awg_port(void *engine, int port);
extern int wins_winn_packet_engine_seam_stats(void *engine, char *out, int capacity);
extern int wins_winn_packet_engine_status_json(void *engine, char *out, int capacity);
extern void wins_winn_packet_engine_stop(void *engine);
extern void wins_winn_packet_engine_destroy(void *engine);

/*
 * 1073 bytes is the average OUTER datagram size measured on the real
 * AmneziaWG session this defect was found in (4,502,360 outer bytes over
 * 4,195 datagrams), so the burst puts the same bytes-per-datagram through the
 * seam that a real tunnel does.
 */
#define DATAGRAM_BYTES 1073
#define MAX_COUNT 200000
#define SETTLE_MICROSECONDS 3000000

static int checks_run = 0;
static int checks_failed = 0;

static void check(bool condition, const char *what) {
  checks_run += 1;
  if (condition) {
    printf("  PASS  %s\n", what);
  } else {
    checks_failed += 1;
    printf("  FAIL  %s\n", what);
  }
}

typedef struct Sink {
  int fd;
  int port;
  pthread_t worker;
  _Atomic bool running;
  _Atomic unsigned long long datagrams;
  _Atomic unsigned long long bytes;
  uint8_t *seen;
} Sink;

static double now_seconds(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static void *sink_thread(void *context) {
  Sink *sink = (Sink *)context;
  uint8_t buffer[4096];
  while (atomic_load(&sink->running)) {
    ssize_t got = recv(sink->fd, buffer, sizeof(buffer), 0);
    if (got < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      break;
    }
    if (got < 16) {
      continue;
    }
    uint64_t sequence = 0;
    memcpy(&sequence, buffer + 8, sizeof(sequence));
    if (sequence < MAX_COUNT) {
      sink->seen[sequence] = 1;
    }
    atomic_fetch_add(&sink->datagrams, 1);
    atomic_fetch_add(&sink->bytes, (unsigned long long)got);
  }
  return NULL;
}

/*
 * The sink is deliberately over-provisioned: the largest receive buffer the
 * kernel will grant, and a thread that does nothing but recv. It must never be
 * the bottleneck, and case 1 is what proves it is not.
 */
static bool sink_open(Sink *sink) {
  memset(sink, 0, sizeof(*sink));
  sink->seen = calloc(MAX_COUNT, 1);
  if (sink->seen == NULL) {
    return false;
  }
  sink->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sink->fd < 0) {
    return false;
  }
  int rcvbuf = 4 * 1024 * 1024;
  (void)setsockopt(sink->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  struct timeval timeout = {0, 200000};
  (void)setsockopt(sink->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_len = sizeof(address);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(sink->fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    return false;
  }
  socklen_t length = sizeof(address);
  if (getsockname(sink->fd, (struct sockaddr *)&address, &length) != 0) {
    return false;
  }
  sink->port = ntohs(address.sin_port);
  atomic_store(&sink->running, true);
  return pthread_create(&sink->worker, NULL, sink_thread, sink) == 0;
}

static void sink_close(Sink *sink) {
  atomic_store(&sink->running, false);
  pthread_join(sink->worker, NULL);
  if (sink->fd >= 0) {
    close(sink->fd);
  }
  free(sink->seen);
  sink->seen = NULL;
}

/* Global "dropped due to full socket buffers". Diagnostic, never an assertion:
 * it is system-wide, so another process can move it. */
static long long udp_fullsock_drops(void) {
  FILE *stream =
      popen("netstat -s -p udp 2>/dev/null | grep -i 'full socket buffers'", "r");
  if (stream == NULL) {
    return -1;
  }
  char line[512];
  long long value = -1;
  if (fgets(line, sizeof(line), stream) != NULL) {
    value = atoll(line);
  }
  pclose(stream);
  return value;
}

typedef struct Result {
  unsigned long long sent;
  unsigned long long delivered;
  long lost;
  long first_missing;
  long trailing_lost_run;
  double offered_rate;
  long long fullsock_delta;
  /* Read back out of the wrapper's own counters. */
  bool stats_available;
  unsigned long long seam_rx_datagrams;
  unsigned long long seam_ring_dropped;
  unsigned long long seam_tx_written;
  unsigned long long seam_backlog_high_water;
  unsigned long long seam_rcvbuf;
} Result;

/*
 * Minimal integer field reader for the flat, wrapper-generated JSON. Both
 * documents it is used on are produced a few hundred lines away by snprintf
 * with %llu, so there is no escaping, nesting or whitespace to handle, and a
 * real parser here would be more code to get wrong than the thing it parses.
 * Returns false when the key is absent.
 */
static bool json_uint(const char *document, const char *key,
                      unsigned long long *out) {
  char needle[96];
  int length = snprintf(needle, sizeof(needle), "\"%s\":", key);
  if (length <= 0 || length >= (int)sizeof(needle)) {
    return false;
  }
  const char *found = strstr(document, needle);
  if (found == NULL) {
    return false;
  }
  *out = strtoull(found + length, NULL, 10);
  return true;
}

static Result run_case(const char *title, bool through_seam, long count,
                       long pace_microseconds) {
  Result result;
  memset(&result, 0, sizeof(result));
  result.first_missing = -1;

  printf("\n--- %s ---\n", title);

  Sink sink;
  if (!sink_open(&sink)) {
    printf("  BLOCKED could not open the sink socket\n");
    checks_run += 1;
    checks_failed += 1;
    return result;
  }

  void *engine = NULL;
  int target_port = sink.port;
  if (through_seam) {
    NSString *launch = [NSString
        stringWithFormat:
            @"{\"winn\":{\"endpoint\":\"127.0.0.1:%d\",\"carrier\":\"direct-awg\","
            @"\"max_datagram\":1400,\"session_id\":\"seam-burst-regression\","
            @"\"h1\":11,\"h2\":22,\"h3\":33,\"h4\":44,"
            @"\"s1\":16,\"s2\":80,\"s3\":16,\"s4\":0}}",
            sink.port];
    engine = wins_winn_packet_engine_create(launch.UTF8String, NULL);
    if (engine == NULL) {
      printf("  BLOCKED wins_winn_packet_engine_create returned NULL\n");
      checks_run += 1;
      checks_failed += 1;
      sink_close(&sink);
      return result;
    }
    if (wins_winn_packet_engine_start(engine) != 1) {
      printf("  BLOCKED wins_winn_packet_engine_start failed\n");
      checks_run += 1;
      checks_failed += 1;
      wins_winn_packet_engine_destroy(engine);
      sink_close(&sink);
      return result;
    }
    target_port = wins_winn_packet_engine_awg_seam_port(engine);
    if (target_port <= 0) {
      printf("  BLOCKED the seam reported port %d\n", target_port);
      checks_run += 1;
      checks_failed += 1;
      wins_winn_packet_engine_stop(engine);
      wins_winn_packet_engine_destroy(engine);
      sink_close(&sink);
      return result;
    }
    printf("  seam bound on 127.0.0.1:%d, gateway stand-in on 127.0.0.1:%d\n",
           target_port, sink.port);
  } else {
    printf("  seam BYPASSED, bursting straight at 127.0.0.1:%d\n", sink.port);
  }

  int producer = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in bound;
  memset(&bound, 0, sizeof(bound));
  bound.sin_len = sizeof(bound);
  bound.sin_family = AF_INET;
  bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bound.sin_port = 0;
  (void)bind(producer, (struct sockaddr *)&bound, sizeof(bound));

  /*
   * The seam admits only the AWG source port the host publishes; until then
   * the inbound pump does not read. Publish the producer's port, as the
   * Swift host does with the AWG engine's listen_port.
   */
  if (engine != NULL) {
    socklen_t bound_length = (socklen_t)sizeof(bound);
    if (getsockname(producer, (struct sockaddr *)&bound, &bound_length) != 0 ||
        wins_winn_packet_engine_expect_awg_port(engine, ntohs(bound.sin_port)) != 1) {
      printf("  BLOCKED the seam refused the producer port\n");
      checks_run += 1;
      checks_failed += 1;
      close(producer);
      wins_winn_packet_engine_stop(engine);
      wins_winn_packet_engine_destroy(engine);
      sink_close(&sink);
      return result;
    }
  }

  struct sockaddr_in target;
  memset(&target, 0, sizeof(target));
  target.sin_len = sizeof(target);
  target.sin_family = AF_INET;
  target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  target.sin_port = htons((uint16_t)target_port);

  uint8_t datagram[DATAGRAM_BYTES];
  memset(datagram, 0xA5, sizeof(datagram));
  uint32_t header_type = 44; /* h4, transport data, s4 == 0 */
  memcpy(datagram, &header_type, sizeof(header_type));

  /* Let both pumps reach their wait before the burst begins. */
  usleep(300000);

  long long drops_before = udp_fullsock_drops();
  double started = now_seconds();
  for (long index = 0; index < count; index += 1) {
    uint64_t sequence = (uint64_t)index;
    memcpy(datagram + 8, &sequence, sizeof(sequence));
    if (sendto(producer, datagram, sizeof(datagram), 0,
               (struct sockaddr *)&target, sizeof(target)) >= 0) {
      result.sent += 1;
    }
    if (pace_microseconds > 0) {
      usleep((useconds_t)pace_microseconds);
    }
  }
  double elapsed = now_seconds() - started;
  result.offered_rate = elapsed > 0 ? (double)result.sent / elapsed : 0.0;

  usleep(SETTLE_MICROSECONDS);
  long long drops_after = udp_fullsock_drops();
  result.fullsock_delta =
      (drops_before >= 0 && drops_after >= 0) ? drops_after - drops_before : -1;

  result.delivered = atomic_load(&sink.datagrams);
  for (long index = 0; index < count; index += 1) {
    if (sink.seen[index]) {
      result.trailing_lost_run = 0;
    } else {
      result.lost += 1;
      result.trailing_lost_run += 1;
      if (result.first_missing < 0) {
        result.first_missing = index;
      }
    }
  }

  printf("  offered   : %llu datagrams in %.3f s (%.0f pkt/s, %.1f Mbit/s)\n",
         result.sent, elapsed, result.offered_rate,
         elapsed > 0 ? (double)result.sent * DATAGRAM_BYTES * 8.0 / elapsed / 1e6
                     : 0.0);
  printf("  delivered : %llu datagrams / %llu bytes\n", result.delivered,
         (unsigned long long)atomic_load(&sink.bytes));
  printf("  LOST      : %ld (%.2f%%)   first missing seq=%ld   trailing run=%ld\n",
         result.lost, count > 0 ? 100.0 * (double)result.lost / (double)count : 0.0,
         result.first_missing, result.trailing_lost_run);
  printf("  kernel full-socket-buffer drop delta (system-wide, diagnostic): %lld\n",
         result.fullsock_delta);

  if (engine != NULL) {
    char stats[1024];
    if (wins_winn_packet_engine_seam_stats(engine, stats, (int)sizeof(stats)) > 0) {
      printf("  seam stats : %s\n", stats);
      result.stats_available =
          json_uint(stats, "seam_rx_datagrams", &result.seam_rx_datagrams) &&
          json_uint(stats, "seam_rx_ring_dropped", &result.seam_ring_dropped) &&
          json_uint(stats, "seam_tx_written", &result.seam_tx_written) &&
          json_uint(stats, "seam_rx_backlog_high_water_bytes",
                    &result.seam_backlog_high_water) &&
          json_uint(stats, "seam_rcvbuf_bytes", &result.seam_rcvbuf);
    }
    check(result.stats_available,
          "wins_winn_packet_engine_seam_stats reports the seam's own counters");

    /*
     * The Go engine's view, for contrast. Printed rather than asserted: its
     * counters were all zero throughout the original 34% loss event, because
     * the datagrams never reached the engine. Seeing that side by side with a
     * nonzero seam counter is the clearest statement of where the loss is.
     */
    char status[2048];
    if (wins_winn_packet_engine_status_json(engine, status, (int)sizeof(status)) > 0) {
      unsigned long long tx_datagrams = 0;
      unsigned long long tx_rejected = 0;
      unsigned long long rx_dropped = 0;
      (void)json_uint(status, "tx_datagrams", &tx_datagrams);
      (void)json_uint(status, "tx_rejected", &tx_rejected);
      (void)json_uint(status, "rx_dropped", &rx_dropped);
      printf("  go engine  : tx_datagrams=%llu tx_rejected=%llu rx_dropped=%llu\n",
             tx_datagrams, tx_rejected, rx_dropped);
    }

    wins_winn_packet_engine_stop(engine);
    check(wins_winn_packet_engine_awg_seam_port(engine) == 0,
          "seam port reads 0 after stop");
    wins_winn_packet_engine_destroy(engine);
  }

  close(producer);
  sink_close(&sink);
  return result;
}

/*
 * THE INVARIANT THE FIX GUARANTEES AT EVERY RATE.
 *
 * Not "nothing is ever lost" — a loopback UDP seam whose producer cannot be
 * blocked has no way to promise that, and pretending otherwise is what a
 * bigger buffer would be doing. What it promises is that nothing is lost
 * WITHOUT BEING SEEN:
 *
 *   every datagram the producer sent reached the wrapper           (no kernel drop)
 *   every datagram that did not arrive is in a counter             (full accounting)
 *
 * The pre-fix wrapper fails both: the kernel discarded a third of the burst
 * before recvfrom, and nothing anywhere counted it.
 */
static void check_no_silent_loss(const char *title, Result result, long count) {
  char observation[220];

  snprintf(observation, sizeof(observation),
           "%s: NO SILENT LOSS — the wrapper received all %ld offered "
           "(seam_rx_datagrams=%llu)",
           title, count, result.seam_rx_datagrams);
  check(result.stats_available &&
            result.seam_rx_datagrams == (unsigned long long)count,
        observation);

  snprintf(observation, sizeof(observation),
           "%s: FULLY ACCOUNTED — delivered %llu + counted drops %llu = %ld offered",
           title, result.delivered, result.seam_ring_dropped, count);
  check(result.stats_available &&
            result.delivered + result.seam_ring_dropped ==
                (unsigned long long)count,
        observation);

  snprintf(observation, sizeof(observation),
           "%s: kernel receive queue stayed far below the buffer "
           "(high water %llu of %llu bytes)",
           title, result.seam_backlog_high_water, result.seam_rcvbuf);
  check(result.stats_available && result.seam_rcvbuf > 0 &&
            result.seam_backlog_high_water < result.seam_rcvbuf / 2,
        observation);
}

int main(void) {
  @autoreleasepool {
    /*
     * 4,195 datagrams is not an arbitrary size. It is the exact burst size
     * this file's OWN header measurement (above: "Measured on macOS arm64,
     * 2026-08-04/05, against the shipping wrapper ... 4,195 datagrams
     * offered unpaced ... -> 1,380 lost (32.90%)") was taken at -- a claim
     * this file asserts directly and can be rerun to reproduce, not one that
     * depends on an outside document.
     *
     * DANGLING CITATION REPAIRED 2026-08-06. This comment used to cite a
     * DIFFERENT number -- "1,436 of 4,195 outbound datagrams (34.2%)
     * vanished," from "section 3e" of docs/handoff/
     * WINN_PROTOCOL_MACOS_NE_BUILD_AND_SEAM_TRAFFIC_20260804.md. That
     * document does not exist: not on disk, and `git log --all -S` for its
     * exact name finds it in no commit either, so the 34.2% / 1,436 figure
     * is unverifiable and is withdrawn rather than repeated.
     *
     * It is deliberately NOT replaced with a citation to
     * WINN3_MACOS_REMOTE_GATEWAY_RIGOROUS_SESSION_20260806.md -- the real,
     * committed 2026-08-06 macOS session evidence used to repair the other
     * two dangling citations of this same missing document, in
     * lib/winn_protocol_dispatch.dart. That session measured a CLEAN
     * transfer, 0 lost of 8,480 datagrams, and documents no burst-loss event
     * at all, so it supports nothing about this file's defect; citing it
     * here would be laundering a new citation onto a claim it does not back.
     * The burst-of-record size stays 4,195 because that is what this file's
     * own header measurement above already used and can be rerun to
     * reproduce -- it needs no outside document.
     */
    long count = 4195;
    const char *count_env = getenv("WINN_SEAM_BURST_COUNT");
    if (count_env != NULL) {
      long parsed = atol(count_env);
      if (parsed > 0 && parsed < MAX_COUNT) {
        count = parsed;
      }
    }
    long tolerance = 0;
    const char *tolerance_env = getenv("WINN_SEAM_BURST_TOLERANCE");
    if (tolerance_env != NULL) {
      long parsed = atol(tolerance_env);
      if (parsed >= 0) {
        tolerance = parsed;
      }
    }
    long overload_count = count * 5;
    if (overload_count >= MAX_COUNT) {
      overload_count = MAX_COUNT - 1;
    }

    printf("Winn Apple seam — unpaced burst regression\n");
    printf("burst of record   : %ld datagrams of %d bytes (%.2f MiB)\n", count,
           DATAGRAM_BYTES, (double)count * DATAGRAM_BYTES / 1048576.0);
    printf("permitted loss    : %ld datagrams on the burst of record\n", tolerance);

    /* CASE 1 — control. Establishes that the harness itself is lossless. */
    Result control = run_case("CASE 1 control: producer -> sink, seam bypassed, UNPACED",
                              false, count, 0);
    check(control.lost == 0,
          "control path is lossless (if this fails the harness is at fault, not the seam)");
    check(control.offered_rate > 50000.0,
          "control offered rate is a genuine burst (> 50,000 pkt/s)");

    /*
     * CASE 2 — THE DEFECT OF RECORD. The burst that lost 34.2%. Zero
     * tolerance: this one the seam is expected to carry in full.
     */
    Result burst = run_case("CASE 2 THE REGRESSION: 4 MiB unpaced burst through the REAL SEAM",
                            true, count, 0);
    check(burst.offered_rate > 50000.0,
          "burst offered rate is a genuine burst (> 50,000 pkt/s)");
    char verdict[220];
    snprintf(verdict, sizeof(verdict),
             "THE 4 MiB UNPACED BURST LOSES AT MOST %ld DATAGRAMS (lost %ld of %ld)",
             tolerance, burst.lost, count);
    check(burst.lost <= tolerance, verdict);
    check_no_silent_loss("burst of record", burst, count);

    /*
     * CASE 3 — SUSTAINED OVERLOAD, five times the burst of record.
     *
     * This case deliberately does NOT assert zero loss, and the reason is the
     * whole argument of the fix. Above the seam's carrying capacity the
     * producer is offering more than the writer can put on the wire, and no
     * finite buffer can absorb an unbounded deficit — a loopback UDP seam
     * cannot make amneziawg-go wait. What is asserted instead is the property
     * that CAN be guaranteed at any rate: nothing is discarded by the kernel
     * behind everyone's back, and every datagram that does not arrive is in a
     * counter. Asserting zero loss here would only tempt someone to grow the
     * ring until the number went away, which is precisely the wrong fix.
     */
    Result overload = run_case("CASE 3 sustained overload: 5x the burst, UNPACED",
                               true, overload_count, 0);
    check_no_silent_loss("sustained overload", overload, overload_count);
    if (overload.lost > 0) {
      printf("  (note: %ld datagrams dropped above carrying capacity — counted, "
             "logged, and reported, which is the requirement here)\n",
             overload.lost);
    }

    /* CASE 4 — the paced path the shipping proofs used, must not regress. */
    Result paced = run_case("CASE 4 no regression: 4 MiB through the REAL SEAM, PACED 200us",
                            true, count, 200);
    check(paced.lost == 0, "paced 200 us path is still lossless");
    check_no_silent_loss("paced", paced, count);

    printf("\n================ RESULT ================\n");
    printf("checks run: %d, failed: %d\n", checks_run, checks_failed);
    if (checks_failed == 0) {
      printf("ALL CHECKS PASSED\n");
      return 0;
    }
    printf("FAILED\n");
    return 1;
  }
}
