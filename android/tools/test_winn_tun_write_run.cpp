// Host test for winn_tun::WriteRunLanes, the loop behind the Android downlink
// bulk tun writer. A SOCK_DGRAM socketpair stands in for the tun: like a tun
// write, one send is one whole message, so order, boundaries and resume
// points are observable from the other end. A scripted write function covers
// what a socketpair cannot produce on demand (EINTR, a short write, a failure
// that leaves errno at 0).
//
//   c++ -std=c++17 -Wall -Wextra -Werror -pthread -fsanitize=address,undefined \
//     -I android/app/src/main/cpp android/tools/test_winn_tun_write_run.cpp \
//     -o /tmp/test_winn_tun_write_run && /tmp/test_winn_tun_write_run
//   (and again with -fsanitize=thread for the lane workers)
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <mutex>
#include <vector>

#include "winn_tun_write_run.h"

namespace {

int failures = 0;

void Check(bool ok, const char* what) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s (errno %d)\n", what, errno);
    failures++;
  }
}

// Packets laid out like a WinnV3PacketBatch (a 16-byte header before every
// payload). Each payload is an IPv4 TCP header for one of `flows` flows,
// followed by the packet's global index and its sequence within its flow.
struct Slab {
  std::vector<uint8_t> bytes;
  std::vector<int32_t> offsets;
  std::vector<int32_t> lengths;
  std::vector<int> flow;
  std::vector<int> seq;
};

constexpr int kHeader = 40;

Slab MakeSlab(int count, int base_length, int flows) {
  Slab slab;
  std::vector<int> next(flows, 0);
  size_t cursor = 0;
  for (int i = 0; i < count; i++) {
    const int length = base_length + (i % 7);
    const int f = i % flows;
    cursor += 16;
    slab.offsets.push_back(static_cast<int32_t>(cursor));
    slab.lengths.push_back(length);
    slab.flow.push_back(f);
    slab.seq.push_back(next[f]++);
    slab.bytes.resize(cursor + length);
    uint8_t* p = &slab.bytes[cursor];
    for (int j = 0; j < length; j++) p[j] = static_cast<uint8_t>((i * 31 + j) & 0xff);
    memset(p, 0, kHeader);
    p[0] = 0x45;
    p[9] = 6;
    p[12] = 10; p[15] = 2;            // 10.0.0.2
    p[16] = 10; p[19] = 1;            // 10.0.0.1
    p[20] = static_cast<uint8_t>((1000 + f) >> 8);
    p[21] = static_cast<uint8_t>((1000 + f) & 0xff);
    p[22] = 0x01; p[23] = 0xbb;       // 443
    p[24] = static_cast<uint8_t>(i & 0xff);
    p[25] = static_cast<uint8_t>((i >> 8) & 0xff);
    p[26] = static_cast<uint8_t>(slab.seq.back() & 0xff);
    p[27] = static_cast<uint8_t>((slab.seq.back() >> 8) & 0xff);
    cursor += length;
  }
  return slab;
}

winn_tun::Run MakeRun(int fd, Slab& slab, int first, int count, std::vector<uint8_t>& done) {
  done.assign(count, 0);
  return winn_tun::Run{fd, slab.bytes.data(), slab.bytes.size(), slab.offsets.data() + first,
                       slab.lengths.data() + first, count, done.data(), winn_tun::SystemWrite};
}

// Reads every queued message; checks each is a whole packet of the slab and
// that within each flow sequence numbers arrive exactly once and in order.
struct Receiver {
  const Slab* slab;
  std::vector<int> expect;  // next sequence per flow
  int total = 0;
  bool ok = true;
  std::vector<int> global;  // global indices in arrival order

  bool Take(int fd, int flags) {
    uint8_t buffer[4096];
    const ssize_t n = recv(fd, buffer, sizeof(buffer), flags);
    if (n <= 0) return false;
    const int index = buffer[24] | (buffer[25] << 8);
    if (index < 0 || index >= static_cast<int>(slab->lengths.size()) ||
        n != slab->lengths[index] ||
        memcmp(buffer, &slab->bytes[slab->offsets[index]], static_cast<size_t>(n)) != 0) {
      ok = false;
      return true;
    }
    const int f = slab->flow[index];
    if (slab->seq[index] != expect[f]) ok = false;
    expect[f] = slab->seq[index] + 1;
    global.push_back(index);
    total++;
    return true;
  }

  void Drain(int fd) {
    while (Take(fd, MSG_DONTWAIT)) {
    }
  }
};

Receiver MakeReceiver(const Slab& slab, int flows) {
  Receiver r;
  r.slab = &slab;
  r.expect.assign(flows, 0);
  return r;
}

void TestOneLaneWritesInOrder() {
  int fds[2];
  Check(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0, "socketpair");
  Slab slab = MakeSlab(5, 60, 3);
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeRun(fds[0], slab, 0, 5, done);
  Check(winn_tun::WriteRunLanes(run, 1) == 5, "one lane writes every packet");
  Receiver r = MakeReceiver(slab, 3);
  r.Drain(fds[1]);
  Check(r.ok && r.total == 5, "packets arrive whole and once");
  for (int i = 0; i < 5; i++) Check(r.global[i] == i, "one lane keeps the batch order");
  for (int i = 0; i < 5; i++) Check(done[i] == 1, "every written packet is marked done");
  Check(winn_tun::WriteRunLanes(run, 1) == 5, "a call with every packet done writes nothing");
  Check(!r.Take(fds[1], MSG_DONTWAIT), "nothing is written twice");
  close(fds[0]);
  close(fds[1]);
}

void TestMalformedRunWritesNothing() {
  int fds[2];
  Check(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0, "socketpair");
  for (int lanes : {1, 4}) {
    Slab slab = MakeSlab(40, 60, 4);
    slab.offsets[30] = static_cast<int32_t>(slab.bytes.size()) - 10;  // runs off the end
    std::vector<uint8_t> done;
    const winn_tun::Run run = MakeRun(fds[0], slab, 0, 40, done);
    Check(winn_tun::WriteRunLanes(run, lanes) == -EINVAL, "a packet outside the slab is refused");
    uint8_t spare[64];
    Check(recv(fds[1], spare, sizeof(spare), MSG_DONTWAIT) < 0, "a refused run writes nothing");
    slab.offsets[30] = -1;
    Check(winn_tun::WriteRunLanes(run, lanes) == -EINVAL, "a negative offset is refused");
  }
  close(fds[0]);
  close(fds[1]);
}

// A full device stops the lanes; the caller drains (standing in for the
// kernel making room) and calls again with the same done flags.
void TestFullDeviceResumesExactlyOnce(int lanes, int flows, int run_size) {
  int fds[2];
  Check(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0, "socketpair");
  Check(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0, "nonblocking writer");
  const int total = 4000;
  Slab slab = MakeSlab(total, 900, flows);
  Receiver r = MakeReceiver(slab, flows);
  int stalls = 0;
  for (int first = 0; first < total; first += run_size) {
    const int count = first + run_size <= total ? run_size : total - first;
    std::vector<uint8_t> done;
    const winn_tun::Run run = MakeRun(fds[0], slab, first, count, done);
    for (int attempt = 0;; attempt++) {
      const int32_t result = winn_tun::WriteRunLanes(run, lanes);
      Check(result >= 0 && result <= count, "a full device is not a fault");
      if (result == count) break;
      stalls++;
      if (attempt > 10000) {
        Check(false, "a run never completed");
        return;
      }
      r.Drain(fds[1]);
    }
  }
  r.Drain(fds[1]);
  Check(r.ok, "per-flow order holds and every packet is whole across resumes");
  Check(r.total == total, "every packet arrives exactly once");
  Check(stalls > 0, "the test filled the device at least once");
  if (lanes == 1) {
    bool ordered = true;
    for (int i = 0; i < total; i++) ordered = ordered && r.global[i] == i;
    Check(ordered, "one lane keeps the global order across resumes");
  }
  close(fds[0]);
  close(fds[1]);
}

struct DrainArgs {
  int fd;
  Receiver* receiver;
  int want;
};

void* DrainThread(void* arg) {
  DrainArgs* a = static_cast<DrainArgs*>(arg);
  while (a->receiver->total < a->want) {
    if (!a->receiver->Take(a->fd, 0)) break;
  }
  return nullptr;
}

// Lanes in parallel with a live reader: the pool path, for the thread
// sanitizer. A Darwin datagram socketpair reports ENOBUFS rather than
// blocking when the reader falls behind, so a partial run is retried, which
// is also the seam's contract.
void TestParallelLanesKeepPerFlowOrder() {
  int fds[2];
  Check(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0, "socketpair");
  const int total = 6000;
  Slab slab = MakeSlab(total, 200, 16);
  Receiver r = MakeReceiver(slab, 16);
  DrainArgs args{fds[1], &r, total};
  pthread_t reader;
  Check(pthread_create(&reader, nullptr, DrainThread, &args) == 0, "reader thread");
  for (int first = 0; first < total; first += 128) {
    const int count = first + 128 <= total ? 128 : total - first;
    std::vector<uint8_t> done;
    const winn_tun::Run run = MakeRun(fds[0], slab, first, count, done);
    int32_t result = 0;
    for (int attempt = 0; attempt < 100000; attempt++) {
      result = winn_tun::WriteRunLanes(run, 4);
      if (result < 0 || result == count) break;
      usleep(50);
    }
    Check(result == count, "every run completes with a live reader");
    if (result != count) break;
  }
  pthread_join(reader, nullptr);
  Check(r.ok && r.total == total, "parallel lanes deliver every packet once, in order per flow");
  close(fds[0]);
  close(fds[1]);
}

void TestShortRunStaysOnTheCallerInOrder() {
  int fds[2];
  Check(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0, "socketpair");
  const int count = winn_tun::kMinParallelPackets - 1;
  Slab slab = MakeSlab(count, 60, 8);
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeRun(fds[0], slab, 0, count, done);
  Check(winn_tun::WriteRunLanes(run, 4) == count, "a short run is written");
  Receiver r = MakeReceiver(slab, 8);
  r.Drain(fds[1]);
  bool ordered = r.total == count;
  for (int i = 0; ordered && i < count; i++) ordered = r.global[i] == i;
  Check(ordered, "a run below the parallel threshold keeps the batch order");
  close(fds[0]);
  close(fds[1]);
}

void TestDeviceFaultIsReported() {
  for (int lanes : {1, 4}) {
    Slab slab = MakeSlab(64, 50, 8);
    std::vector<uint8_t> done;
    const winn_tun::Run run = MakeRun(-1, slab, 0, 64, done);
    Check(winn_tun::WriteRunLanes(run, lanes) == -EBADF, "a bad descriptor is a fault");
  }
}

void TestFlowHash() {
  Slab slab = MakeSlab(4, 60, 2);  // packets 0 and 2 share flow 0, 1 and 3 flow 1
  const uint8_t* p0 = &slab.bytes[slab.offsets[0]];
  const uint8_t* p1 = &slab.bytes[slab.offsets[1]];
  const uint8_t* p2 = &slab.bytes[slab.offsets[2]];
  Check(winn_tun::FlowHash(p0, slab.lengths[0]) == winn_tun::FlowHash(p2, slab.lengths[2]),
        "one five-tuple hashes alike");
  Check(winn_tun::FlowHash(p0, slab.lengths[0]) != winn_tun::FlowHash(p1, slab.lengths[1]),
        "different ports hash apart");
  std::vector<uint8_t> frag(p0, p0 + slab.lengths[0]);
  std::vector<uint8_t> frag_other_ports = frag;
  frag[6] = 0x20;  // more fragments
  frag_other_ports[6] = 0x20;
  frag_other_ports[20] ^= 0x55;
  Check(winn_tun::FlowHash(frag.data(), static_cast<int32_t>(frag.size())) ==
            winn_tun::FlowHash(frag_other_ports.data(), static_cast<int32_t>(frag_other_ports.size())),
        "fragments hash without ports");
  Check(winn_tun::FlowHash(nullptr, 0) == winn_tun::FlowHash(reinterpret_cast<const uint8_t*>("x"), 1),
        "non-IP input has one constant flow");
}

// Scripted write. Never touches a descriptor: it records the packet index
// (payload bytes 24 and 25) of every packet it accepts, and fails the packet
// whose index is stop_index exactly once, the way stop_mode says. Lane
// workers call it concurrently, so its state is atomic or under a mutex.
enum class StopMode { kInterrupt, kShortWrite, kSilentFailure };
std::atomic<int> scripted_calls{0};
std::atomic<int> stop_index{-1};
std::atomic<bool> stop_fired{false};
StopMode stop_mode = StopMode::kInterrupt;
std::mutex scripted_mu;
std::vector<int> scripted_seen;
// Where the packet index sits. 24 for the IPv4 slabs; an IPv6 slab moves it
// past its 40-byte header, since bytes 24 to 39 are its destination address.
std::atomic<int> index_offset{24};

void ResetScript(int index, StopMode mode) {
  scripted_calls = 0;
  stop_index = index;
  stop_fired = false;
  stop_mode = mode;
  index_offset = 24;
  std::lock_guard<std::mutex> lock(scripted_mu);
  scripted_seen.clear();
}

ssize_t ScriptedWrite(int /*fd*/, const void* data, size_t size) {
  scripted_calls++;
  const uint8_t* p = static_cast<const uint8_t*>(data);
  const int off = index_offset;
  const int index = p[off] | (p[off + 1] << 8);
  bool expected = false;
  if (index == stop_index && stop_fired.compare_exchange_strong(expected, true)) {
    switch (stop_mode) {
      case StopMode::kInterrupt:
        errno = EINTR;
        return -1;
      case StopMode::kShortWrite:
        return static_cast<ssize_t>(size) - 1;
      case StopMode::kSilentFailure:
        errno = 0;
        return -1;
    }
  }
  std::lock_guard<std::mutex> lock(scripted_mu);
  scripted_seen.push_back(index);
  return static_cast<ssize_t>(size);
}

winn_tun::Run MakeScriptedRun(Slab& slab, int count, std::vector<uint8_t>& done) {
  winn_tun::Run run = MakeRun(-1, slab, 0, count, done);
  run.write = ScriptedWrite;
  return run;
}

// Astra T2: EINTR ends the call with the completed prefix; nothing inside the
// native call retries it, and the next call resumes at the interrupted packet.
void TestInterruptedWriteStopsTheLaneWithoutRetrying() {
  Slab slab = MakeSlab(10, 50, 1);
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeScriptedRun(slab, 10, done);
  ResetScript(3, StopMode::kInterrupt);
  Check(winn_tun::WriteRunLanes(run, 1) == 3, "EINTR stops the run at the interrupted packet");
  Check(scripted_calls == 4, "EINTR is not retried inside the native call");
  Check(done[2] == 1 && done[3] == 0, "the interrupted packet is not marked done");
  Check(winn_tun::WriteRunLanes(run, 1) == 10, "the next call writes the rest");
  Check(scripted_calls == 11, "the resumed call writes each remaining packet once");
  bool ordered = scripted_seen.size() == 10;
  for (int i = 0; ordered && i < 10; i++) ordered = scripted_seen[i] == i;
  Check(ordered, "the resumed call starts at the interrupted packet and keeps order");
}

void TestInterruptedWriteInOneLaneIsNotAFault() {
  Slab slab = MakeSlab(64, 50, 8);
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeScriptedRun(slab, 64, done);
  ResetScript(13, StopMode::kInterrupt);
  const int32_t first = winn_tun::WriteRunLanes(run, 4);
  Check(first >= 0 && first < 64, "EINTR in one lane is a retryable stop, not a fault");
  Check(winn_tun::WriteRunLanes(run, 4) == 64, "the next call completes the run");
  std::vector<int> count(64, 0);
  std::vector<int> next(8, 0);
  bool per_flow = true;
  for (int index : scripted_seen) {
    if (index < 0 || index >= 64) {
      per_flow = false;
      continue;
    }
    count[index]++;
    if (slab.seq[index] != next[slab.flow[index]]) per_flow = false;
    next[slab.flow[index]] = slab.seq[index] + 1;
  }
  bool once = true;
  for (int c : count) once = once && c == 1;
  Check(once, "every packet is written exactly once across the interrupted call");
  Check(per_flow, "per-flow order holds across the interrupted call");
}

void TestShortWriteAndSilentFailureAreFaults() {
  for (StopMode mode : {StopMode::kShortWrite, StopMode::kSilentFailure}) {
    Slab slab = MakeSlab(4, 50, 1);
    std::vector<uint8_t> done;
    const winn_tun::Run run = MakeScriptedRun(slab, 4, done);
    ResetScript(2, mode);
    Check(winn_tun::WriteRunLanes(run, 1) == -EIO,
          mode == StopMode::kShortWrite ? "a short write is EIO" : "a failure with errno 0 is EIO");
    Check(done[1] == 1 && done[2] == 0, "a faulted packet is never marked done");
  }
}

void TestOnlyFullOrInterruptedIsRetryable() {
  Check(winn_tun::IsRetryable(EAGAIN) && winn_tun::IsRetryable(EWOULDBLOCK) &&
            winn_tun::IsRetryable(EINTR),
        "EAGAIN, EWOULDBLOCK and EINTR are retryable stops");
  Check(!winn_tun::IsRetryable(EBADF) && !winn_tun::IsRetryable(EIO) &&
            !winn_tun::IsRetryable(EINVAL) && !winn_tun::IsRetryable(0),
        "EBADF, EIO, EINVAL and 0 are not");
}

void TestMixedFragmentRunPreservesOrderOnRetry() {
  Slab slab = MakeSlab(64, 64, 1);
  slab.bytes[slab.offsets[0] + 6] = 0x20;
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeScriptedRun(slab, 64, done);
  ResetScript(0, StopMode::kInterrupt);
  Check(winn_tun::WriteRunLanes(run, 4) == 0,
        "a stopped fragment cannot be passed by its unfragmented flow");
  Check(scripted_seen.empty(), "no later packet passes the stopped fragment");
  Check(winn_tun::WriteRunLanes(run, 4) == 64, "the mixed run resumes");
  bool ordered = scripted_seen.size() == 64;
  for (int i = 0; ordered && i < 64; i++) ordered = scripted_seen[i] == i;
  Check(ordered, "the mixed run is written once in input order");
}

// IPv6 packets of one inner flow: packet 0 carries a Destination Options
// header (next header 60), so FlowHash keys it without ports; the rest are
// plain TCP and are keyed with ports. src_last picks the source address.
Slab MakeIpv6MixedSlab(int count, uint8_t src_last) {
  Slab slab;
  size_t cursor = 0;
  for (int i = 0; i < count; i++) {
    const int length = 80;
    cursor += 16;
    slab.offsets.push_back(static_cast<int32_t>(cursor));
    slab.lengths.push_back(length);
    slab.flow.push_back(0);
    slab.seq.push_back(i);
    slab.bytes.resize(cursor + length);
    uint8_t* p = &slab.bytes[cursor];
    memset(p, 0, length);
    p[0] = 0x60;
    p[5] = static_cast<uint8_t>(length - 40);
    p[6] = i == 0 ? 60 : 6;
    p[7] = 64;
    p[8] = 0xfd; p[23] = src_last;    // fd00::src_last
    p[24] = 0xfd; p[39] = 1;          // fd00::1
    p[40] = 0x03; p[41] = 0xe8;       // 1000
    p[42] = 0x01; p[43] = 0xbb;       // 443
    p[44] = static_cast<uint8_t>(i & 0xff);
    p[45] = static_cast<uint8_t>((i >> 8) & 0xff);
    cursor += length;
  }
  return slab;
}

// The IPv6 half of the guard: an extension-header packet and the plain TCP
// packets of its flow hash to different lanes, so without the guard a stopped
// extension packet is passed by later packets of its own flow.
void TestMixedIpv6ExtensionRunPreservesOrderOnRetry() {
  Slab slab;
  bool apart = false;
  for (int src = 2; src < 64 && !apart; src++) {
    slab = MakeIpv6MixedSlab(64, static_cast<uint8_t>(src));
    const uint32_t ext = winn_tun::FlowHash(&slab.bytes[slab.offsets[0]], slab.lengths[0]);
    const uint32_t tcp = winn_tun::FlowHash(&slab.bytes[slab.offsets[1]], slab.lengths[1]);
    apart = ext % 4 != tcp % 4;
  }
  Check(apart, "fixture: the extension packet and its TCP flow hash to different lanes");
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeScriptedRun(slab, 64, done);
  ResetScript(0, StopMode::kInterrupt);
  index_offset = 44;
  Check(winn_tun::WriteRunLanes(run, 4) == 0,
        "a stopped IPv6 extension packet cannot be passed by its flow");
  Check(scripted_seen.empty(), "no later IPv6 packet passes the stopped extension packet");
  Check(winn_tun::WriteRunLanes(run, 4) == 64, "the mixed IPv6 run resumes");
  bool ordered = scripted_seen.size() == 64;
  for (int i = 0; ordered && i < 64; i++) ordered = scripted_seen[i] == i;
  Check(ordered, "the mixed IPv6 run is written once in input order");
}

// A retry keeps the lane count of the first call: the guard reads packets
// already marked done, so a fragment written before the stop still keeps the
// rest of its run on one lane, in input order, as the header promises.
void TestMixedRunKeepsOneLaneAfterTheFragmentIsWritten() {
  Slab slab = MakeSlab(64, 64, 8);
  slab.bytes[slab.offsets[0] + 6] = 0x20;
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeScriptedRun(slab, 64, done);
  ResetScript(10, StopMode::kInterrupt);
  Check(winn_tun::WriteRunLanes(run, 4) == 10, "one lane stops at the interrupted packet");
  Check(done[0] == 1, "the fragment went out before the stop");
  Check(winn_tun::WriteRunLanes(run, 4) == 64, "the retry completes the run");
  bool ordered = scripted_seen.size() == 64;
  for (int i = 0; ordered && i < 64; i++) ordered = scripted_seen[i] == i;
  Check(ordered, "the retry stays on one lane and keeps input order");
}

// The guard reads the whole run, not only its first packet: a fragment in the
// middle of a single-flow run still keeps every packet of the run on one lane.
void TestFragmentInsideTheRunKeepsItOnOneLane() {
  Slab slab = MakeSlab(64, 64, 1);
  const int frag = 37;
  slab.bytes[slab.offsets[frag] + 6] = 0x20;
  const uint32_t f = winn_tun::FlowHash(&slab.bytes[slab.offsets[frag]], slab.lengths[frag]);
  const uint32_t t = winn_tun::FlowHash(&slab.bytes[slab.offsets[0]], slab.lengths[0]);
  Check(f % 4 != t % 4, "fixture: the fragment and its TCP flow hash to different lanes");
  std::vector<uint8_t> done;
  const winn_tun::Run run = MakeScriptedRun(slab, 64, done);
  ResetScript(frag, StopMode::kInterrupt);
  Check(winn_tun::WriteRunLanes(run, 4) == frag, "one lane stops at the interrupted fragment");
  bool prefix = scripted_seen.size() == static_cast<size_t>(frag);
  for (int i = 0; prefix && i < frag; i++) prefix = scripted_seen[i] == i;
  Check(prefix, "no packet after the stopped fragment was written");
  Check(winn_tun::WriteRunLanes(run, 4) == 64, "the run resumes");
  bool ordered = scripted_seen.size() == 64;
  for (int i = 0; ordered && i < 64; i++) ordered = scripted_seen[i] == i;
  Check(ordered, "the run is written once in input order");
}

}  // namespace

int main() {
  TestOneLaneWritesInOrder();
  TestMalformedRunWritesNothing();
  TestFullDeviceResumesExactlyOnce(1, 1, 64);
  TestFullDeviceResumesExactlyOnce(1, 8, 64);
  TestFullDeviceResumesExactlyOnce(4, 8, 128);
  TestFullDeviceResumesExactlyOnce(4, 1, 128);
  TestParallelLanesKeepPerFlowOrder();
  TestShortRunStaysOnTheCallerInOrder();
  TestDeviceFaultIsReported();
  TestFlowHash();
  TestInterruptedWriteStopsTheLaneWithoutRetrying();
  TestInterruptedWriteInOneLaneIsNotAFault();
  TestShortWriteAndSilentFailureAreFaults();
  TestOnlyFullOrInterruptedIsRetryable();
  TestMixedFragmentRunPreservesOrderOnRetry();
  TestMixedIpv6ExtensionRunPreservesOrderOnRetry();
  TestMixedRunKeepsOneLaneAfterTheFragmentIsWritten();
  TestFragmentInsideTheRunKeepsItOnOneLane();
  if (failures != 0) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  printf("winn_tun::WriteRunLanes: all tests passed\n");
  return 0;
}
