// verify_linux_winn_seam_burst.cc — the UNPACED-BURST regression for the Linux
// Winn loopback seam.
//
// WHY THIS EXISTS
//
// The Linux seam was recorded as "proven" because a 4 MiB transfer completed
// with a matching SHA-256. That transfer was moved with `nc` over TCP, whose
// congestion control PACES the sender, so it never once created the condition
// this file tests. Correctness and rate are different properties; the paced
// proof could not have caught a burst defect and did not.
//
// WHAT IT DRIVES
//
//   producer UDP socket  ->  the REAL loopback seam bound by BindLinuxWinnSeam
//                        ->  the REAL InboundPump in linux/runner/linux_winn_host.cc
//                        ->  the REAL cmd/winn-datapath engine subprocess
//                        ->  sink UDP socket   (stands in for the gateway)
//
// The carrier is direct-awg, so the engine relays each inner datagram to the
// configured gateway endpoint unchanged and the sink can name exactly WHICH
// sequence numbers went missing. Datagrams are shaped as AmneziaWG
// transport-data frames with the sequence number in the counter field.
//
// Case 1 bursts the identical traffic straight at the sink with the seam
// BYPASSED. If that case ever loses a datagram the harness is at fault, not the
// seam, and every other number in the run is worthless.
//
// WHAT IT ASSERTS, AND WHAT IT DELIBERATELY DOES NOT
//
// It does NOT assert "nothing is ever lost". A loopback UDP seam whose producer
// is a third-party AmneziaWG engine cannot be made to block — on loopback UDP
// `sendto` succeeds even when the receiver's queue is full, and the kernel
// discards at delivery. Asserting zero loss at any rate would only tempt
// someone to grow the ring until the number went away.
//
// It asserts the two things that CAN be guaranteed at any offered rate:
//   1. every datagram the producer sent REACHED the host process — no drop in
//      the kernel, where it is invisible and uncountable, and
//   2. every datagram that did not come out the far side is IN A COUNTER.
//
// Loss is measured end to end by the sink, never from the seam's own counters;
// the counters are then cross-checked AGAINST that ground truth.
//
// Usage: verify_linux_winn_seam_burst <path-to-winn-datapath-binary>

#include "../linux/runner/linux_winn_host.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// -------------------------------------------------------------------------
// The seam's own counters, if this build of the host has them.
//
// Declared WEAK on purpose, at global scope so it names the SAME
// winsvpn::winn::LinuxWinnSeamStatsJson the header declares once the fix has
// landed. The same harness source compiles and links against the pre-fix host,
// where the symbol exists nowhere and a weak undefined reference resolves to
// zero, and against the fixed host, where the strong definition wins. The
// binary DISCOVERS which host it was linked against rather than being told by
// the build script — so the "before" and "after" runs are the same test, not
// two different ones.
// -------------------------------------------------------------------------
namespace winsvpn::winn {
__attribute__((weak)) std::string LinuxWinnSeamStatsJson();
}  // namespace winsvpn::winn

namespace {

// The average OUTER datagram size of the real AmneziaWG session the defect was
// found on: 4,502,360 outer bytes over 4,195 datagrams.
constexpr size_t kDatagramBytes = 1073;
// The burst of record: 4 MiB of outer AmneziaWG traffic.
constexpr int kBurstOfRecord = 4195;

// ...offered at the rate the burst of record actually ran at. The Apple
// measurement puts that burst at ~22 ms for 4,195 datagrams, i.e. ~190,000
// datagrams/s, and the reproduction on this file matched the field loss at
// 130k-190k. This is the DEFINED bar, not "as fast as the host can spin":
// letting the producer free-run offers anywhere from 270k to 640k pkt/s on a
// 16-core box and turns the result into a coin flip on the scheduler.
constexpr int kBurstOfRecordPps = 190000;

// Paced case: the shape of the ORIGINAL Linux "proof", which moved its 4 MiB
// over TCP and was therefore paced by congestion control the whole way.
constexpr int kPacedPps = 5000;
constexpr int kMaxCount = 200000;
constexpr int kMaxDatagram = 1400;

int g_checks = 0;
int g_failed = 0;

void Check(bool ok, const std::string& what) {
  ++g_checks;
  if (!ok) ++g_failed;
  std::printf("  %s  %s\n", ok ? "PASS" : "FAIL", what.c_str());
}

int64_t NowUs() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

// The kernel's "dropped because the socket receive queue was full" counter.
// This is the Linux analogue of Darwin's udps_fullsock, and it is the whole
// point of the exercise: a drop counted HERE happened before recvfrom could
// ever see the datagram, which puts it upstream of every counter in the system
// and is exactly why the defect stayed invisible through two passing proofs.
uint64_t UdpRcvbufErrors() {
  std::ifstream snmp("/proc/net/snmp");
  std::string line;
  std::string header;
  while (std::getline(snmp, line)) {
    if (line.rfind("Udp:", 0) != 0) continue;
    if (header.empty()) {
      header = line;
      continue;
    }
    std::istringstream head(header);
    std::istringstream vals(line);
    std::string name, value;
    head >> name;  // "Udp:"
    vals >> name;  // "Udp:"
    std::string field;
    while (head >> field) {
      if (!(vals >> value)) break;
      if (field == "RcvbufErrors") return std::strtoull(value.c_str(), nullptr, 10);
    }
    return 0;
  }
  return 0;
}

// -------------------------------------------------------------------------
// The sink: stands in for the gateway at the far side of the whole chain.
//
// Deliberately over-provisioned — the largest receive buffer the kernel will
// grant, and a drain thread that does nothing else — so that a datagram missing
// at the sink is a datagram the SEAM lost, not one the harness lost.
// -------------------------------------------------------------------------
struct Sink {
  int fd = -1;
  uint16_t port = 0;
  std::vector<uint8_t> seen;
  std::atomic<bool> running{false};
  std::atomic<unsigned long long> datagrams{0};
  std::atomic<unsigned long long> bytes{0};
  std::thread worker;

  // recvmmsg, for the same reason the seam's drainer uses it: a sink that
  // takes one datagram per syscall becomes the bottleneck at these rates and
  // then the CONTROL case fails, which is the harness accusing itself. It has
  // done exactly that here, so the instrument is built not to.
  static constexpr size_t kSinkBatch = 128;
  static constexpr size_t kSinkSlot = 2048;

  void Loop() {
    std::vector<uint8_t> buffer(kSinkBatch * kSinkSlot);
    std::vector<mmsghdr> messages(kSinkBatch);
    std::vector<iovec> iovecs(kSinkBatch);
    while (running.load()) {
      for (size_t i = 0; i < kSinkBatch; ++i) {
        iovecs[i].iov_base = buffer.data() + i * kSinkSlot;
        iovecs[i].iov_len = kSinkSlot;
        std::memset(&messages[i], 0, sizeof(messages[i]));
        messages[i].msg_hdr.msg_iov = &iovecs[i];
        messages[i].msg_hdr.msg_iovlen = 1;
      }
      timespec timeout{0, 200000000};
      const int got = recvmmsg(fd, messages.data(),
                               static_cast<unsigned>(kSinkBatch), 0, &timeout);
      if (got <= 0) continue;
      for (int i = 0; i < got; ++i) {
        const size_t length = messages[i].msg_len;
        if (length < 16) continue;
        uint64_t sequence = 0;
        std::memcpy(&sequence, buffer.data() + i * kSinkSlot + 8,
                    sizeof(sequence));
        if (sequence < static_cast<uint64_t>(kMaxCount)) seen[sequence] = 1;
        datagrams.fetch_add(1);
        bytes.fetch_add(static_cast<unsigned long long>(length));
      }
    }
  }

  bool Open() {
    seen.assign(kMaxCount, 0);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    int rcvbuf = 16 * 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    timeval timeout{0, 200000};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
      return false;
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
      return false;
    }
    port = ntohs(address.sin_port);
    running.store(true);
    worker = std::thread([this] { Loop(); });
    return true;
  }

  void Reset() {
    std::fill(seen.begin(), seen.end(), 0);
    datagrams.store(0);
    bytes.store(0);
  }

  int Delivered(int count) const {
    int total = 0;
    for (int i = 0; i < count; ++i) total += seen[i] ? 1 : 0;
    return total;
  }

  int FirstMissing(int count) const {
    for (int i = 0; i < count; ++i)
      if (!seen[i]) return i;
    return -1;
  }

  void Close() {
    running.store(false);
    if (worker.joinable()) worker.join();
    if (fd >= 0) close(fd);
    fd = -1;
  }
};

// An AmneziaWG transport-data frame carrying its sequence number in the counter
// field, so a datagram that arrives can be named and one that does not can be
// named too.
void FillDatagram(std::vector<uint8_t>* out, uint64_t sequence) {
  out->assign(kDatagramBytes, 0);
  (*out)[0] = 4;  // transport data
  const uint32_t receiver = htonl(0x5732454eu);
  std::memcpy(out->data() + 4, &receiver, sizeof(receiver));
  std::memcpy(out->data() + 8, &sequence, sizeof(sequence));
  for (size_t i = 16; i < kDatagramBytes; ++i) {
    (*out)[i] = static_cast<uint8_t>((sequence * 31u + i) & 0xff);
  }
}

struct BurstResult {
  int offered = 0;
  int delivered = 0;
  double seconds = 0;
  uint64_t kernel_drop_delta = 0;
};

// Offers `count` datagrams to `port` at `target_pps` datagrams per second
// (0 = as fast as the CPU allows), then waits for the chain to quiesce.
//
// THE RATE IS CONTROLLED ON PURPOSE. An "unpaced" producer on a 16-core host
// offers between 270,000 and 640,000 datagrams/s depending on nothing but how
// the scheduler felt, and a test whose input rate is whatever the machine
// happened to do is not a test -- it fails or passes for reasons that have
// nothing to do with the code under test. Spacing is a busy-wait rather than
// sleep_for because the target interval here is a few microseconds and
// sleep_for's granularity is worse than the quantity being measured.
BurstResult Offer(Sink* sink, uint16_t port, int count, int target_pps) {
  sink->Reset();
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int sndbuf = 4 * 1024 * 1024;
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  sockaddr_in target{};
  target.sin_family = AF_INET;
  target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  target.sin_port = htons(port);

  std::vector<uint8_t> datagram;
  const uint64_t before = UdpRcvbufErrors();
  const int64_t started = NowUs();
  const double interval_us =
      target_pps > 0 ? 1e6 / static_cast<double>(target_pps) : 0.0;
  for (int i = 0; i < count; ++i) {
    if (interval_us > 0.0) {
      const int64_t due =
          started + static_cast<int64_t>(interval_us * static_cast<double>(i));
      while (NowUs() < due) {
        // busy-wait: the interval is microseconds, finer than any sleep
      }
    }
    FillDatagram(&datagram, static_cast<uint64_t>(i));
    (void)!sendto(fd, datagram.data(), datagram.size(), 0,
                  reinterpret_cast<sockaddr*>(&target), sizeof(target));
  }
  const int64_t ended = NowUs();
  // Let the chain drain. Generous: the point is never to blame the seam for a
  // datagram that was merely still in flight.
  std::this_thread::sleep_for(std::chrono::milliseconds(2500));
  const uint64_t after = UdpRcvbufErrors();
  close(fd);

  BurstResult result;
  result.offered = count;
  result.delivered = sink->Delivered(count);
  result.seconds = static_cast<double>(ended - started) / 1e6;
  result.kernel_drop_delta = after - before;
  return result;
}

void ReportBurst(const char* label, const BurstResult& r, const Sink& sink) {
  const int lost = r.offered - r.delivered;
  const double rate = r.seconds > 0 ? r.offered / r.seconds : 0;
  std::printf("  %s\n", label);
  std::printf("  offered   : %d datagrams in %.3f s (%.0f pkt/s, %.1f Mbit/s)\n",
              r.offered, r.seconds, rate,
              rate * kDatagramBytes * 8.0 / 1e6);
  std::printf("  delivered : %d datagrams\n", r.delivered);
  std::printf("  LOST      : %d (%.2f%%)", lost,
              r.offered ? 100.0 * lost / r.offered : 0.0);
  if (lost > 0) std::printf("   first missing seq=%d", sink.FirstMissing(r.offered));
  std::printf("\n");
  std::printf("  kernel full-socket-buffer drop delta: %llu\n",
              (unsigned long long)r.kernel_drop_delta);
}

uint64_t StatField(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\":";
  const size_t at = json.find(needle);
  if (at == std::string::npos) return UINT64_MAX;
  return std::strtoull(json.c_str() + at + needle.size(), nullptr, 10);
}

bool SeamStatsAvailable() {
  auto fn = &winsvpn::winn::LinuxWinnSeamStatsJson;
  return fn != nullptr;
}

std::string SeamStats() {
  auto fn = &winsvpn::winn::LinuxWinnSeamStatsJson;
  return fn != nullptr ? fn() : std::string();
}

// The assertions that survive at any offered rate.
//
// `require_no_kernel_drops` is true for the BURST OF RECORD — the defect that
// was actually observed in the field, where the seam must keep up completely.
// It is false for the SUSTAINED-OVERLOAD case, and that is a measured decision
// rather than a convenience: at a stock net.core.rmem_max the kernel clamps the
// seam's 2 MiB SO_RCVBUF request to 416 KiB, which is ~2 ms of headroom at this
// rate, so a drainer descheduled longer than that still loses in the kernel
// during a sustained overload. Measured here: 2 runs in 12. Under a container
// with CAP_NET_ADMIN, where SO_RCVBUFFORCE grants the full 4 MiB, the same case
// loses NOTHING AT ALL — kernel and ring both zero, 9 runs in 10.
//
// Asserting zero there anyway would produce a flaky test, and a flaky test gets
// ignored — which is the exact mechanism by which this defect survived two
// "successful" proofs. So the number is REPORTED and folded into the accounting
// identity instead of being asserted away.
void AssertAccounted(const char* case_name,
                     const BurstResult& r,
                     bool require_no_kernel_drops) {
  const int lost = r.offered - r.delivered;

  if (require_no_kernel_drops) {
    Check(r.kernel_drop_delta == 0,
          std::string(case_name) +
              ": NO SILENT LOSS — every offered datagram reached the host "
              "process (kernel drop delta " +
              std::to_string(r.kernel_drop_delta) + ")");
  } else if (r.kernel_drop_delta != 0) {
    std::printf(
        "  NOTE: %llu datagrams were dropped by the KERNEL under sustained\n"
        "        overload — the SO_RCVBUF clamp, not the seam. See the comment\n"
        "        on AssertAccounted. They are counted below, not hidden.\n",
        (unsigned long long)r.kernel_drop_delta);
  }

  if (!SeamStatsAvailable()) {
    Check(false, std::string(case_name) +
                     ": DROPS ARE COUNTABLE — the host exposes seam counters "
                     "(LinuxWinnSeamStatsJson is absent from this build)");
    Check(false, std::string(case_name) +
                     ": FULLY ACCOUNTED — delivered + counted drops = offered "
                     "(no counter exists to account with)");
    return;
  }

  const std::string stats = SeamStats();
  std::printf("  seam stats : %s\n", stats.c_str());
  const uint64_t received = StatField(stats, "seam_rx_datagrams");
  const uint64_t ring_dropped = StatField(stats, "seam_rx_ring_dropped");
  const uint64_t oversize = StatField(stats, "seam_rx_oversize");
  const uint64_t foreign = StatField(stats, "seam_rx_foreign_sender");
  const uint64_t write_failed = StatField(stats, "seam_tx_write_failed");

  // Everything the producer sent is either something the host SAW, or something
  // the kernel counted on the way in. Nothing may fall outside both.
  Check(received + r.kernel_drop_delta == static_cast<uint64_t>(r.offered),
        std::string(case_name) + ": NO SILENT LOSS — host received " +
            std::to_string(received) + " + kernel counted " +
            std::to_string(r.kernel_drop_delta) + " = " +
            std::to_string(r.offered) + " offered");

  // ...and everything the host saw either came out the far side or is in one of
  // OUR counters. This is the property that did not exist before: pre-fix, the
  // drops were in the kernel where Linux gives no per-socket attribution, so
  // there was no counter anywhere that could close this identity.
  const uint64_t counted =
      ring_dropped + oversize + foreign + write_failed + r.kernel_drop_delta;
  Check(static_cast<uint64_t>(r.delivered) + counted ==
            static_cast<uint64_t>(r.offered),
        std::string(case_name) + ": FULLY ACCOUNTED — delivered " +
            std::to_string(r.delivered) + " + counted drops " +
            std::to_string(counted) + " = " + std::to_string(r.offered) +
            " (lost " + std::to_string(lost) + ")");
}

// Brings up a real seam + real engine subprocess for one case, and tears it
// down again. Every case needs the identical eight lines otherwise.
struct SeamSession {
  uint16_t seam_port = 0;
  bool up = false;
  std::string error;

  bool Start(const std::string& engine_path, uint16_t sink_port) {
    int seam_fd = winsvpn::winn::BindLinuxWinnSeam(&seam_port, &error);
    if (seam_fd < 0) return false;
    winsvpn::winn::LinuxWinnParams params;
    params.endpoint = "127.0.0.1:" + std::to_string(sink_port);
    params.max_datagram = kMaxDatagram;
    params.carrier = "direct-awg";
    params.h[0] = 11; params.h[1] = 22; params.h[2] = 33; params.h[3] = 44;
    params.s[0] = 16; params.s[1] = 80; params.s[2] = 16; params.s[3] = 0;
    // Ownership of seam_fd passes to this call on EVERY outcome.
    up = winsvpn::winn::StartLinuxWinnEngine(engine_path, seam_fd, params,
                                             &error);
    return up;
  }

  ~SeamSession() {
    if (up) winsvpn::winn::StopLinuxWinnEngine();
  }
};

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: %s <path-to-winn-datapath-binary>\n", argv[0]);
    return 2;
  }
  const std::string engine_path = argv[1];

  const int burst_count = std::getenv("WINN_SEAM_BURST_COUNT")
                              ? std::atoi(std::getenv("WINN_SEAM_BURST_COUNT"))
                              : kBurstOfRecord;

  std::printf("=== Linux Winn loopback seam — UNPACED BURST regression ===\n");
  std::printf("engine     : %s\n", engine_path.c_str());
  std::printf("datagram   : %zu bytes (the real session's average OUTER size)\n",
              kDatagramBytes);
  std::printf("seam stats : %s\n",
              SeamStatsAvailable()
                  ? "present (LinuxWinnSeamStatsJson linked)"
                  : "ABSENT — this host build has no seam counters at all");
  std::printf("\n");

  Sink sink;
  if (!sink.Open()) {
    std::fprintf(stderr, "the sink could not be opened\n");
    return 2;
  }

  // ---------------------------------------------------------------------
  // CASE 1 — CONTROL. Seam bypassed. A failure here is a HARNESS fault.
  // ---------------------------------------------------------------------
  std::printf("--- CASE 1 CONTROL: burst of record at %d pkt/s, seam BYPASSED ---\n",
              kBurstOfRecordPps);
  {
    const BurstResult r = Offer(&sink, sink.port, burst_count, kBurstOfRecordPps);
    ReportBurst("(producer -> sink directly)", r, sink);
    Check(r.delivered == r.offered,
          "control: the harness itself loses nothing (" +
              std::to_string(r.delivered) + " of " + std::to_string(r.offered) +
              ")");
    Check(r.kernel_drop_delta == 0, "control: no kernel drops without the seam");
  }
  std::printf("\n");

  // ---------------------------------------------------------------------
  // CASE 2 — THE REGRESSION. The 4 MiB burst of record, through the seam,
  // at the rate the burst of record actually ran at.
  // ---------------------------------------------------------------------
  std::printf("--- CASE 2 THE REGRESSION: 4 MiB burst of record (%d pkt/s) through the REAL SEAM ---\n",
              kBurstOfRecordPps);
  {
    SeamSession session;
    if (!session.Start(engine_path, sink.port)) {
      std::fprintf(stderr, "seam/engine did not start: %s\n",
                   session.error.c_str());
      sink.Close();
      return 2;
    }
    const BurstResult r =
        Offer(&sink, session.seam_port, burst_count, kBurstOfRecordPps);
    ReportBurst("(producer -> seam -> engine -> sink)", r, sink);
    const std::string go_status = winsvpn::winn::LinuxWinnEngineStatusJson();
    std::printf("  go engine  : %s\n",
                go_status.empty() ? "(no status)" : go_status.c_str());

    Check(r.delivered == r.offered,
          "THE 4 MiB BURST OF RECORD LOSES AT MOST 0 DATAGRAMS (lost " +
              std::to_string(r.offered - r.delivered) + " of " +
              std::to_string(r.offered) + ")");
    AssertAccounted("burst of record", r, /*require_no_kernel_drops=*/true);
  }
  std::printf("\n");

  // ---------------------------------------------------------------------
  // CASE 3 — SUSTAINED OVERLOAD. 5x the DURATION at the same rate, so this
  // tests sustained carrying capacity rather than how fast this particular
  // host can spin a send loop. Loss is PERMITTED; silence is not.
  // ---------------------------------------------------------------------
  std::printf("--- CASE 3 sustained overload: 5x the burst at %d pkt/s ---\n",
              kBurstOfRecordPps);
  {
    SeamSession session;
    if (!session.Start(engine_path, sink.port)) {
      std::fprintf(stderr, "seam/engine did not start: %s\n",
                   session.error.c_str());
      sink.Close();
      return 2;
    }
    const BurstResult r =
        Offer(&sink, session.seam_port, burst_count * 5, kBurstOfRecordPps);
    ReportBurst("(producer -> seam -> engine -> sink)", r, sink);
    // NOTE: no zero-loss assertion. Above carrying capacity a finite buffer
    // cannot absorb an unbounded deficit, and pretending otherwise is how a
    // ring gets grown until a number goes away.
    AssertAccounted("sustained overload", r, /*require_no_kernel_drops=*/false);
  }
  std::printf("\n");

  // ---------------------------------------------------------------------
  // CASE 4 — THE PACED PATH MUST NOT REGRESS. This is the shape of the
  // original Linux "proof": paced, and lossless. It stays lossless.
  // ---------------------------------------------------------------------
  std::printf("--- CASE 4 paced %d pkt/s: the pre-existing proof must not regress ---\n",
              kPacedPps);
  {
    SeamSession session;
    if (!session.Start(engine_path, sink.port)) {
      std::fprintf(stderr, "seam/engine did not start: %s\n",
                   session.error.c_str());
      sink.Close();
      return 2;
    }
    const int paced_count = burst_count < 2000 ? burst_count : 2000;
    const BurstResult r =
        Offer(&sink, session.seam_port, paced_count, kPacedPps);
    ReportBurst("(producer -> seam -> engine -> sink, paced)", r, sink);
    Check(r.delivered == r.offered,
          "paced path: still lossless (" + std::to_string(r.delivered) +
              " of " + std::to_string(r.offered) + ")");
    Check(r.kernel_drop_delta == 0, "paced path: no kernel drops");
  }
  std::printf("\n");

  // ---------------------------------------------------------------------
  // CHARACTERISATION, NOT AN ASSERTION. Where does this seam actually stop
  // coping, and does it stop coping in OUR ring (countable) or in the kernel
  // (invisible)? Printed so the ceiling is a published number rather than
  // something a future reader has to rediscover. Nothing here can fail the
  // run -- a ceiling that moves with the host is not a regression.
  // ---------------------------------------------------------------------
  if (std::getenv("WINN_SEAM_SWEEP") != nullptr) {
    std::printf("--- RATE SWEEP (reported, not asserted) ---\n");
    std::printf("  %10s %10s %10s %12s %12s\n", "offered/s", "delivered",
                "lost", "ring_dropped", "kernel_drop");
    for (const int pps : {100000, 150000, 190000, 250000, 300000, 400000,
                          500000, 0}) {
      SeamSession session;
      if (!session.Start(engine_path, sink.port)) break;
      const BurstResult r =
          Offer(&sink, session.seam_port, burst_count, pps);
      uint64_t ring_dropped = 0;
      if (SeamStatsAvailable()) {
        ring_dropped = StatField(SeamStats(), "seam_rx_ring_dropped");
      }
      std::printf("  %10.0f %10d %10d %12llu %12llu\n",
                  r.seconds > 0 ? r.offered / r.seconds : 0.0, r.delivered,
                  r.offered - r.delivered, (unsigned long long)ring_dropped,
                  (unsigned long long)r.kernel_drop_delta);
    }
    std::printf("\n");
  }

  sink.Close();

  std::printf("checks run: %d, failed: %d\n", g_checks, g_failed);
  return g_failed == 0 ? 0 : 1;
}
