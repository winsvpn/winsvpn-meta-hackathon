// The downlink half of the bulk tun bridge: write a run of packets, one
// write(2) per packet, with no JNI in the loop. Kept free of jni.h so a host
// test can drive it against a datagram socketpair standing in for the tun.
//
// A tun write is one whole packet or nothing, so a short count is a device
// fault, never a partial packet to resume, and so is a failure that leaves
// errno at 0. A full device (EAGAIN) or an interrupted write (EINTR) stops a
// lane and returns to the caller, which waits for POLLOUT (or simply calls
// again after EINTR) OUTSIDE native code, under its own lifetime checks: no
// thread ever waits or retries inside this file, so a close or a rebind is
// never held up by a full device or a signal storm. The per-packet done flags
// make that retry exact: a packet already written is skipped, so nothing is
// written twice or dropped.
//
// LANES. lanes == 1 writes the run in order on the calling thread. lanes > 1
// splits the run by inner flow (addresses, protocol, and ports for an
// unfragmented TCP or UDP packet) across up to kMaxLanes threads: lane 0 is
// the caller, lanes 1..3 are persistent native workers. A tun write runs the
// inner IP and TCP receive path on the writing thread, so lanes spread that
// kernel work over cores. Packets of one flow share a lane and keep their
// order; a lane stops at its first failure, so what a flow has written is
// always a prefix of that flow, and the retry keeps per-flow order too. The
// call joins every lane before it returns, so a later run never passes an
// earlier one.
#pragma once

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

namespace winn_tun {

constexpr int kMaxLanes = 4;
constexpr int kMaxRunPackets = 512;
// Below this a run goes out on the caller alone: a sparse or interactive
// batch must not pay a worker wake.
constexpr int kMinParallelPackets = 24;

using WriteFn = ssize_t (*)(int, const void*, size_t);

// The default write. A named wrapper rather than &::write, because bionic's
// fortified write() carries pass_object_size and its address cannot be taken.
inline ssize_t SystemWrite(int fd, const void* data, size_t size) {
  return ::write(fd, data, size);
}

// A retryable stop, which the caller waits out or simply retries: the
// descriptor is momentarily full, or a signal interrupted the write.
// Anything else is a fault.
inline bool IsRetryable(int error) {
  if (error == EAGAIN || error == EWOULDBLOCK || error == EINTR) return true;
#if defined(__APPLE__)
  // Host tests only: a full AF_UNIX datagram socketpair reports ENOBUFS on
  // Darwin where Linux reports EAGAIN. Android never compiles this branch.
  if (error == ENOBUFS) return true;
#endif
  return false;
}

inline uint32_t Mix(uint32_t h, const uint8_t* p, int n) {
  for (int i = 0; i < n; i++) {
    h ^= p[i];
    h *= 16777619u;
  }
  return h;
}

inline uint32_t Finish(uint32_t h) {
  h ^= h >> 16;
  h *= 0x7feb352du;
  h ^= h >> 15;
  h *= 0x846ca68bu;
  h ^= h >> 16;
  return h;
}

// Flow key of one inner IP packet. Every fragment of a datagram hashes by
// addresses and protocol alone, so a fragmented datagram never splits across
// lanes. Anything that is not IPv4 or IPv6 hashes to one constant.
inline uint32_t FlowHash(const uint8_t* p, int32_t n) {
  uint32_t h = 2166136261u;
  if (p == nullptr || n < 1) return Finish(h);
  if (n >= 20 && (p[0] >> 4) == 4) {
    const int ihl = (p[0] & 0x0f) * 4;
    const bool fragment = ((p[6] & 0x3f) | p[7]) != 0;
    const uint8_t proto = p[9];
    h = Mix(h, p + 9, 1);
    h = Mix(h, p + 12, 8);
    if (!fragment && (proto == 6 || proto == 17) && ihl >= 20 && n >= ihl + 4) {
      h = Mix(h, p + ihl, 4);
    }
    return Finish(h);
  }
  if (n >= 40 && (p[0] >> 4) == 6) {
    const uint8_t next = p[6];
    h = Mix(h, p + 6, 1);
    h = Mix(h, p + 8, 32);
    if ((next == 6 || next == 17) && n >= 44) h = Mix(h, p + 40, 4);
    return Finish(h);
  }
  return Finish(h);
}

// One run: count packets inside base, plus one done flag per packet. write
// is SystemWrite in production; host tests script it to produce what a
// socketpair cannot on demand (EINTR, a short write, errno 0).
struct Run {
  int fd;
  const uint8_t* base;
  size_t base_length;
  const int32_t* offsets;
  const int32_t* lengths;
  int32_t count;
  uint8_t* done;
  WriteFn write;
};

// 0 when packet k went out whole, else the errno that stopped it.
inline int WriteOne(const Run& run, int k) {
  const int32_t offset = run.offsets[k];
  const int32_t length = run.lengths[k];
  if (offset < 0 || length <= 0 || static_cast<size_t>(offset) > run.base_length ||
      static_cast<size_t>(length) > run.base_length - static_cast<size_t>(offset)) {
    return EINVAL;
  }
  // One attempt: EINTR comes back to the caller like EAGAIN, never retried
  // here, so a signal storm cannot keep the lifetime lease held.
  const ssize_t written = run.write(run.fd, run.base + offset, static_cast<size_t>(length));
  if (written == static_cast<ssize_t>(length)) return 0;
  if (written >= 0) return EIO;
  const int error = errno;
  return error != 0 ? error : EIO;
}

struct Lane {
  const Run* run;
  int16_t order[kMaxRunPackets];
  int n;
  int error;
};

// Writes this lane's packets in order, skipping done ones, and stops at the
// first failure. Each packet index belongs to exactly one lane, so lanes
// never touch the same done flag.
inline void RunLane(Lane* lane) {
  lane->error = 0;
  for (int i = 0; i < lane->n; i++) {
    const int k = lane->order[i];
    if (lane->run->done[k] != 0) continue;
    const int error = WriteOne(*lane->run, k);
    if (error != 0) {
      lane->error = error;
      return;
    }
    lane->run->done[k] = 1;
  }
}

// Persistent workers for lanes 1..kMaxLanes-1. Constant-initialized at
// namespace scope, so the library needs no C++ runtime support for it.
struct LanePool {
  pthread_mutex_t mu;
  pthread_cond_t wake;
  pthread_cond_t idle;
  pthread_mutex_t submit;
  Lane* job[kMaxLanes - 1];
  int pending;
  bool started;
  bool failed;
  int index[kMaxLanes - 1];
};

inline LanePool gLanePool = {
    PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, PTHREAD_COND_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER, {nullptr, nullptr, nullptr}, 0, false, false, {0, 1, 2},
};

inline void* LaneWorker(void* arg) {
  LanePool& pool = gLanePool;
  const int w = *static_cast<int*>(arg);
#if defined(__APPLE__)
  pthread_setname_np("CalcTunW");
#else
  char name[16] = {'C', 'a', 'l', 'c', 'T', 'u', 'n', 'W', '-', static_cast<char>('1' + w), 0};
  pthread_setname_np(pthread_self(), name);
#endif
  pthread_mutex_lock(&pool.mu);
  for (;;) {
    while (pool.job[w] == nullptr) pthread_cond_wait(&pool.wake, &pool.mu);
    Lane* lane = pool.job[w];
    pthread_mutex_unlock(&pool.mu);
    RunLane(lane);
    pthread_mutex_lock(&pool.mu);
    pool.job[w] = nullptr;
    if (--pool.pending == 0) pthread_cond_signal(&pool.idle);
  }
  return nullptr;
}

// Called with pool.submit held.
inline bool StartLanePool() {
  LanePool& pool = gLanePool;
  if (pool.started) return true;
  if (pool.failed) return false;
  for (int w = 0; w < kMaxLanes - 1; w++) {
    pthread_t thread;
    if (pthread_create(&thread, nullptr, LaneWorker, &pool.index[w]) != 0) {
      // Workers already started stay parked; this pool is never used again
      // and every later run goes out on the caller alone.
      pool.failed = true;
      return false;
    }
    pthread_detach(thread);
  }
  pool.started = true;
  return true;
}

// Writes every packet of the run not yet marked done, on min(lanes, 4)
// lanes. Returns how many packets of the run are done after the call (0 to
// count), or -errno when a lane hit a fault (EIO, EBADF and so on, or EINVAL
// for a packet outside base, in which case nothing was written); a fault wins
// over a full device. Fewer than count with no fault means a lane met a full
// device or an interrupted write: wait for POLLOUT and call again with the
// same done flags.
inline int32_t WriteRunLanes(const Run& run, int lanes) {
  if (run.count < 0 || run.count > kMaxRunPackets) return -EINVAL;
  if (run.count == 0) return 0;
  if (lanes < 1) lanes = 1;
  if (lanes > kMaxLanes) lanes = kMaxLanes;
  if (run.count < kMinParallelPackets) lanes = 1;

  // A malformed run writes nothing: every packet must lie inside base.
  for (int k = 0; k < run.count; k++) {
    const int32_t offset = run.offsets[k];
    const int32_t length = run.lengths[k];
    if (offset < 0 || length <= 0 || static_cast<size_t>(offset) > run.base_length ||
        static_cast<size_t>(length) > run.base_length - static_cast<size_t>(offset)) {
      return -EINVAL;
    }
  }

  // Ports are unavailable on fragments and some IPv6 extension chains.
  // Keep the entire mixed run ordered when one flow can have two hash keys.
  // Inspect done packets too, so a retry uses the same lane assignment.
  // A run already on one lane has nothing to order, so it skips the scan.
  for (int k = 0; lanes > 1 && k < run.count; k++) {
    const uint8_t* p = run.base + run.offsets[k];
    const int32_t n = run.lengths[k];
    const bool ipv4_fragment = n >= 20 && (p[0] >> 4) == 4 &&
        (((p[6] & 0x3f) | p[7]) != 0);
    const bool ipv6_extension = n >= 40 && (p[0] >> 4) == 6 &&
        p[6] != 6 && p[6] != 17;
    if (ipv4_fragment || ipv6_extension) {
      lanes = 1;
      break;
    }
  }

  Lane lane[kMaxLanes];
  for (int l = 0; l < lanes; l++) {
    lane[l].run = &run;
    lane[l].n = 0;
    lane[l].error = 0;
  }
  for (int k = 0; k < run.count; k++) {
    if (run.done[k] != 0) continue;
    const int l = lanes == 1 ? 0
        : static_cast<int>(FlowHash(run.base + run.offsets[k], run.lengths[k]) %
                           static_cast<uint32_t>(lanes));
    lane[l].order[lane[l].n++] = static_cast<int16_t>(k);
  }

  int busy = 0;
  for (int l = 0; l < lanes; l++) busy += lane[l].n > 0 ? 1 : 0;
  bool parallel = busy > 1;
  LanePool& pool = gLanePool;
  if (parallel) {
    pthread_mutex_lock(&pool.submit);
    if (!StartLanePool()) {
      pthread_mutex_unlock(&pool.submit);
      parallel = false;
    }
  }
  if (parallel) {
    pthread_mutex_lock(&pool.mu);
    for (int l = 1; l < lanes; l++) {
      if (lane[l].n > 0) {
        pool.job[l - 1] = &lane[l];
        pool.pending++;
      }
    }
    pthread_cond_broadcast(&pool.wake);
    pthread_mutex_unlock(&pool.mu);
    if (lane[0].n > 0) RunLane(&lane[0]);
    pthread_mutex_lock(&pool.mu);
    while (pool.pending > 0) pthread_cond_wait(&pool.idle, &pool.mu);
    pthread_mutex_unlock(&pool.mu);
    pthread_mutex_unlock(&pool.submit);
  } else {
    // One busy lane, or no workers: every lane on the caller, each still in
    // order, so per-flow order holds exactly as it does in parallel.
    for (int l = 0; l < lanes; l++) {
      if (lane[l].n == 0) continue;
      RunLane(&lane[l]);
      if (lane[l].error != 0 && !IsRetryable(lane[l].error)) break;
    }
  }

  for (int l = 0; l < lanes; l++) {
    if (lane[l].error != 0 && !IsRetryable(lane[l].error)) return -lane[l].error;
  }
  int32_t done = 0;
  for (int k = 0; k < run.count; k++) done += run.done[k] != 0 ? 1 : 0;
  return done;
}

}  // namespace winn_tun
