/*
 * WinnTunnelTestDouble.c — local stand-in for the Winn Protocol c-archive.
 *
 * NOT SHIPPING CODE. The real WinnTunnel* symbols come from the `datapath`
 * lane's Go `-buildmode=c-archive`, now landed at
 * tools/winn_conformance_build_out/libwinn-datapath-{ios,darwin}-arm64.a. This
 * file remains only so WinsWinnPacketEngine.m can be compiled, linked, and
 * actually run on a development machine and on the slices the real archive
 * does not cover (no x86_64 and no simulator archive exists).
 *
 * It implements the same C surface as an in-process loopback: whatever is
 * written inbound comes back out outbound, unchanged. Nothing here does any
 * protocol work, opens any socket, or touches the network. It must never be
 * linked into a shipping artifact — apple/EngineArtifacts/README.md and the
 * staging gate's symbol check are what keep a double out of a release build.
 *
 * WHY THIS FILE IS DANGEROUS, AND WHAT NOW STOPS IT.
 *
 * An earlier revision implemented the signatures a provisional WinnTunnel.h
 * had ASSUMED rather than the ones the archive exports: no errorOut on create,
 * no timeoutMS on read, void instead of char * from close. Because the double
 * faithfully implemented the wrong contract, `-Werror` was green on all five
 * platform slices while the real archive would have read an uninitialised
 * register as an out-parameter and written through it. A double is only ever
 * evidence about the contract it was written against.
 *
 * tools/verify_winn_abi_conformance.sh now compiles this file in the same
 * translation unit as the cgo-generated header, so a definition here that
 * disagrees with the archive is a build failure. Do not change a signature in
 * this file without changing the archive; change it to match the archive.
 *
 * FIDELITY. The behaviours below deliberately mirror the real contract, not a
 * convenient one:
 *   - a dry read returns WINN_TUNNEL_ERR_TIMEOUT, never 0;
 *   - timeoutMS is honoured, including the timeoutMS <= 0 blocking form;
 *   - create reports failure through errorOut and returns 0;
 *   - close returns NULL on success;
 *   - every returned char * is heap allocated and freed by WinnTunnelFreeString.
 * The one thing it does NOT mirror is the payload model: the real archive
 * carries AmneziaWG outer datagrams and refuses "payload":"ip-packet", while
 * this loopback accepts any bytes. That is called out here because it is the
 * next place a double could quietly certify a wrong contract.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "WinnTunnel.h"

#define WINN_DOUBLE_MAX_TUNNELS 4
#define WINN_DOUBLE_QUEUE_DEPTH 64
#define WINN_DOUBLE_MAX_PACKET_BYTES WINS_WINN3_PACKET_MAX

/*
 * Mirrors carrier.AbsoluteMaxDatagram in the Go lane, which is what the real
 * WinnTunnelMaxDatagram reports.
 */
#define WINN_DOUBLE_MAX_DATAGRAM 1500

typedef struct {
  uint8_t bytes[WINN_DOUBLE_MAX_PACKET_BYTES];
  int length;
} WinnDoublePacket;

typedef struct {
  int in_use;
  int closed;
  int udp_fd;
  uint64_t packets_in;
  uint64_t packets_out;
  uint64_t bytes_in;
  uint64_t bytes_out;
  uint64_t dropped;
  int head;
  int tail;
  int count;
  WinnDoublePacket queue[WINN_DOUBLE_QUEUE_DEPTH];
} WinnDoubleTunnel;

static pthread_mutex_t winn_double_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t winn_double_ready = PTHREAD_COND_INITIALIZER;
static WinnDoubleTunnel winn_double_tunnels[WINN_DOUBLE_MAX_TUNNELS];

static WinnDoubleTunnel *winn_double_lookup(long long handle) {
  if (handle <= 0 || handle > WINN_DOUBLE_MAX_TUNNELS) {
    return NULL;
  }
  WinnDoubleTunnel *tunnel = &winn_double_tunnels[handle - 1];
  return tunnel->in_use ? tunnel : NULL;
}

/* Every string this file hands back is allocated the same way it is freed. */
static char *winn_double_string(const char *value) {
  size_t length = strlen(value) + 1;
  char *copy = (char *)malloc(length);
  if (copy != NULL) {
    memcpy(copy, value, length);
  }
  return copy;
}

void WinnTunnelFreeString(char *value) {
  if (value != NULL) {
    free(value);
  }
}

char *WinnTunnelContractVersion(void) {
  /*
   * The double must report the contract the wrapper was built against, or
   * wins_winn_packet_engine_start refuses to start against it. Keeping this
   * tied to the header's macro means the double cannot drift from the wrapper
   * without the wrapper noticing.
   */
  return winn_double_string(WINN_TUNNEL_CONTRACT_VERSION);
}

char *WinnTunnelProtocolVersion(void) { return winn_double_string("winn/3"); }

int WinnTunnelMaxDatagram(void) { return WINN_DOUBLE_MAX_DATAGRAM; }

long long WinnTunnelCreate(char *configJSON, int udpFD, char **errorOut) {
  if (errorOut != NULL) {
    *errorOut = NULL;
  }
  if (configJSON == NULL || configJSON[0] == '\0') {
    if (errorOut != NULL) {
      *errorOut = winn_double_string("winn datapath configuration is NULL");
    }
    return 0;
  }

  pthread_mutex_lock(&winn_double_lock);
  long long handle = 0;
  for (int index = 0; index < WINN_DOUBLE_MAX_TUNNELS; index += 1) {
    if (winn_double_tunnels[index].in_use) {
      continue;
    }
    memset(&winn_double_tunnels[index], 0, sizeof(WinnDoubleTunnel));
    winn_double_tunnels[index].in_use = 1;
    winn_double_tunnels[index].udp_fd = udpFD;
    handle = (long long)(index + 1);
    break;
  }
  pthread_mutex_unlock(&winn_double_lock);

  if (handle == 0 && errorOut != NULL) {
    *errorOut = winn_double_string("winn datapath test double is out of slots");
  }
  return handle;
}

int WinnTunnelWriteInbound(long long handle, char *buffer, int length) {
  pthread_mutex_lock(&winn_double_lock);
  WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
  if (tunnel == NULL) {
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_HANDLE;
  }
  if (tunnel->closed) {
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_CLOSED;
  }
  if (buffer == NULL || length <= 0) {
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_ARGUMENT;
  }
  if (length > WINN_DOUBLE_MAX_PACKET_BYTES) {
    tunnel->dropped += 1;
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_TOO_LARGE;
  }
  if (tunnel->count == WINN_DOUBLE_QUEUE_DEPTH) {
    /* Queue pressure is a drop, not an error: the real carrier can drop too. */
    tunnel->dropped += 1;
    pthread_mutex_unlock(&winn_double_lock);
    return length;
  }

  WinnDoublePacket *slot = &tunnel->queue[tunnel->tail];
  memcpy(slot->bytes, buffer, (size_t)length);
  slot->length = length;
  tunnel->tail = (tunnel->tail + 1) % WINN_DOUBLE_QUEUE_DEPTH;
  tunnel->count += 1;
  tunnel->packets_in += 1;
  tunnel->bytes_in += (uint64_t)length;
  pthread_cond_broadcast(&winn_double_ready);
  pthread_mutex_unlock(&winn_double_lock);
  return length;
}

/* Absolute deadline `timeoutMS` in the future, for pthread_cond_timedwait. */
static void winn_double_deadline(struct timespec *deadline, int timeoutMS) {
  struct timeval now;
  gettimeofday(&now, NULL);
  long long nanoseconds =
      (long long)now.tv_usec * 1000LL + (long long)timeoutMS * 1000000LL;
  deadline->tv_sec = now.tv_sec + (time_t)(nanoseconds / 1000000000LL);
  deadline->tv_nsec = (long)(nanoseconds % 1000000000LL);
}

int WinnTunnelReadOutbound(long long handle, char *buffer, int capacity,
                           int timeoutMS) {
  struct timespec deadline;
  int bounded = timeoutMS > 0;
  if (bounded) {
    winn_double_deadline(&deadline, timeoutMS);
  }

  pthread_mutex_lock(&winn_double_lock);
  for (;;) {
    WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
    if (tunnel == NULL) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_HANDLE;
    }
    if (tunnel->closed) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_CLOSED;
    }
    if (buffer == NULL || capacity <= 0) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_ARGUMENT;
    }

    if (tunnel->count > 0) {
      WinnDoublePacket *slot = &tunnel->queue[tunnel->head];
      int length = slot->length;
      tunnel->head = (tunnel->head + 1) % WINN_DOUBLE_QUEUE_DEPTH;
      tunnel->count -= 1;
      if (length > capacity) {
        /* Contract: drop rather than truncate, and say so. */
        tunnel->dropped += 1;
        pthread_mutex_unlock(&winn_double_lock);
        return WINN_TUNNEL_ERR_TOO_LARGE;
      }
      memcpy(buffer, slot->bytes, (size_t)length);
      tunnel->packets_out += 1;
      tunnel->bytes_out += (uint64_t)length;
      pthread_mutex_unlock(&winn_double_lock);
      return length;
    }

    /*
     * Nothing queued. The real archive blocks here and reports
     * WINN_TUNNEL_ERR_TIMEOUT when the bounded wait expires — it never returns
     * 0 for an empty queue. timeoutMS <= 0 blocks until a datagram or a close.
     */
    int wait_result = bounded ? pthread_cond_timedwait(&winn_double_ready,
                                                       &winn_double_lock,
                                                       &deadline)
                              : pthread_cond_wait(&winn_double_ready,
                                                  &winn_double_lock);
    if (bounded && wait_result == ETIMEDOUT) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_TIMEOUT;
    }
  }
}

char *WinnTunnelStatusJSON(long long handle) {
  pthread_mutex_lock(&winn_double_lock);
  WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
  if (tunnel == NULL) {
    pthread_mutex_unlock(&winn_double_lock);
    /* Contract: never NULL, even for an unknown handle. */
    return winn_double_string("{\"contract\":\"" WINN_TUNNEL_CONTRACT_VERSION
                              "\",\"closed\":true,"
                              "\"carrier_error\":\"unknown tunnel handle\"}");
  }
  unsigned long long packets_in = (unsigned long long)tunnel->packets_in;
  unsigned long long packets_out = (unsigned long long)tunnel->packets_out;
  unsigned long long bytes_in = (unsigned long long)tunnel->bytes_in;
  unsigned long long bytes_out = (unsigned long long)tunnel->bytes_out;
  unsigned long long dropped = (unsigned long long)tunnel->dropped;
  int closed = tunnel->closed;
  pthread_mutex_unlock(&winn_double_lock);

  char *json = (char *)malloc(384);
  if (json == NULL) {
    return NULL;
  }
  snprintf(json, 384,
           "{\"contract\":\"" WINN_TUNNEL_CONTRACT_VERSION "\","
           "\"engine_runtime_implementation\":\"test_double\","
           "\"engine_runtime_closed\":%s,"
           "\"engine_runtime_packets_in\":%llu,"
           "\"engine_runtime_packets_out\":%llu,"
           "\"engine_runtime_bytes_in\":%llu,"
           "\"engine_runtime_bytes_out\":%llu,"
           "\"engine_runtime_dropped\":%llu}",
           closed ? "true" : "false", packets_in, packets_out, bytes_in,
           bytes_out, dropped);
  return json;
}

char *WinnTunnelClose(long long handle) {
  pthread_mutex_lock(&winn_double_lock);
  WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
  if (tunnel != NULL) {
    /*
     * in_use stays set so the handle keeps reporting WINN_TUNNEL_ERR_CLOSED
     * rather than WINN_TUNNEL_ERR_HANDLE. A double does not need to recycle
     * slots. The broadcast is what makes close unblock an in-flight read, which
     * the contract requires.
     */
    tunnel->closed = 1;
  }
  pthread_cond_broadcast(&winn_double_ready);
  pthread_mutex_unlock(&winn_double_lock);
  /* Contract: NULL on success, including for an unknown handle. */
  return NULL;
}

int WinsWinn3EnqueuePackets(long long handle, void *descriptors, int count, int stride) {
  if (descriptors == NULL || count < 0 || count > WINS_WINN3_BATCH_MAX || stride != WINS_WINN3_PACKET_STRIDE) {
    return WINN_TUNNEL_ERR_ARGUMENT;
  }
  if (count == 0) {
    return 0;
  }
  pthread_mutex_lock(&winn_double_lock);
  WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
  if (tunnel == NULL) {
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_HANDLE;
  }
  if (tunnel->closed) {
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_CLOSED;
  }

  uint8_t *desc_bytes = (uint8_t *)descriptors;
  for (int i = 0; i < count; i++) {
    WinsWinn3PacketDescriptor *d =
        (WinsWinn3PacketDescriptor *)(desc_bytes + i * stride);
    if (d->data == NULL || d->length == 0 || d->length > d->capacity ||
        d->capacity > WINS_WINN3_PACKET_MAX || d->reserved != 0) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_ARGUMENT;
    }
    uint8_t version = ((const uint8_t *)d->data)[0] >> 4;
    if (!((version == 4 && d->family == 2) ||
          (version == 6 && d->family == 30))) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_ARGUMENT;
    }
  }

  int enqueued = 0;
  for (int i = 0; i < count; i++) {
    WinsWinn3PacketDescriptor *d = (WinsWinn3PacketDescriptor *)(desc_bytes + i * stride);
    if (tunnel->count >= WINN_DOUBLE_QUEUE_DEPTH) {
      tunnel->head = (tunnel->head + 1) % WINN_DOUBLE_QUEUE_DEPTH;
      tunnel->count -= 1;
      tunnel->dropped += 1;
    }
    WinnDoublePacket *slot = &tunnel->queue[tunnel->tail];
    int copy_len = (int)d->length;
    memcpy(slot->bytes, d->data, (size_t)copy_len);
    slot->length = copy_len;
    tunnel->tail = (tunnel->tail + 1) % WINN_DOUBLE_QUEUE_DEPTH;
    tunnel->count += 1;
    tunnel->packets_in += 1;
    tunnel->bytes_in += (uint64_t)copy_len;
    enqueued++;
  }
  pthread_cond_broadcast(&winn_double_ready);
  pthread_mutex_unlock(&winn_double_lock);
  return enqueued;
}

int WinsWinn3DequeuePackets(long long handle, void *descriptors, int count, int stride, int timeoutMS) {
  if (descriptors == NULL || count <= 0 || count > WINS_WINN3_BATCH_MAX || stride != WINS_WINN3_PACKET_STRIDE) {
    return WINN_TUNNEL_ERR_ARGUMENT;
  }
  uint8_t *desc_bytes = (uint8_t *)descriptors;
  for (int i = 0; i < count; i++) {
    WinsWinn3PacketDescriptor *d = (WinsWinn3PacketDescriptor *)(desc_bytes + i * stride);
    if (d->data == NULL || d->length != 0 || d->capacity == 0 || d->capacity > WINS_WINN3_PACKET_MAX || d->family != 0 || d->reserved != 0) {
      return WINN_TUNNEL_ERR_ARGUMENT;
    }
  }

  pthread_mutex_lock(&winn_double_lock);
  WinnDoubleTunnel *tunnel = winn_double_lookup(handle);
  if (tunnel == NULL) {
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_HANDLE;
  }
  if (tunnel->closed) {
    pthread_mutex_unlock(&winn_double_lock);
    return WINN_TUNNEL_ERR_CLOSED;
  }

  struct timespec deadline;
  int bounded = 0;
  if (timeoutMS > 0) {
    bounded = 1;
    struct timeval now;
    gettimeofday(&now, NULL);
    deadline.tv_sec = now.tv_sec + (timeoutMS / 1000);
    long long nsec = ((long long)now.tv_usec * 1000LL) +
                     (((long long)timeoutMS % 1000LL) * 1000000LL);
    if (nsec >= 1000000000LL) {
      deadline.tv_sec += 1;
      nsec -= 1000000000LL;
    }
    deadline.tv_nsec = (long)nsec;
  }

  while (tunnel->count == 0) {
    if (tunnel->closed) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_CLOSED;
    }
    int wait_result = bounded ? pthread_cond_timedwait(&winn_double_ready,
                                                       &winn_double_lock,
                                                       &deadline)
                              : pthread_cond_wait(&winn_double_ready,
                                                  &winn_double_lock);
    if (bounded && wait_result == ETIMEDOUT) {
      pthread_mutex_unlock(&winn_double_lock);
      return WINN_TUNNEL_ERR_TIMEOUT;
    }
  }

  int dequeued = 0;
  while (dequeued < count && tunnel->count > 0) {
    WinsWinn3PacketDescriptor *d = (WinsWinn3PacketDescriptor *)(desc_bytes + dequeued * stride);
    WinnDoublePacket *slot = &tunnel->queue[tunnel->head];
    int length = slot->length;
    if ((uint32_t)length > d->capacity) {
      if (dequeued == 0) {
        pthread_mutex_unlock(&winn_double_lock);
        return WINN_TUNNEL_ERR_TOO_LARGE;
      }
      break;
    }
    memcpy(d->data, slot->bytes, (size_t)length);
    d->length = (uint32_t)length;
    uint8_t first_byte = slot->bytes[0];
    d->family = ((first_byte >> 4) == 6) ? 30 : 2; /* AF_INET6=30, AF_INET=2 */
    tunnel->head = (tunnel->head + 1) % WINN_DOUBLE_QUEUE_DEPTH;
    tunnel->count -= 1;
    tunnel->packets_out += 1;
    tunnel->bytes_out += (uint64_t)length;
    dequeued++;
  }

  pthread_mutex_unlock(&winn_double_lock);
  return dequeued;
}
