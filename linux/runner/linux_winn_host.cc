#include "linux_winn_host.h"

// Generated from carrierhost.Profile's own json tags by
// winn_protocol_experimental/cmd/winn-carrier-keys. Never edit it here; a
// Go test fails the build if it drifts from the schema.
#include "linux_winn_carrier_profile_keys.h"

// The frame codec is NOT reimplemented here. windows/runner/winn_frame.h is the
// normative reference implementation of the WNN3 layout -- the Go package says
// so in its own doc ("fixed by WINN_PROTOCOL_PLATFORM_PLAN.md section 2 and its
// reference implementation, windows/runner/winn_frame.h") and pins the exact
// bytes against it in TestGoldenFrameBytes. It is standard C++17 with no
// <windows.h>, deliberately so it can be shared. A second copy on this side
// would be a second thing to drift; including the one that is already pinned is
// the whole point.
#include "../../windows/runner/winn_frame.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace winsvpn::winn {
namespace {

// Mirrors WinnEngineConfig.kt so the two hosts cannot drift.
constexpr char kContractVersion[] = "winn-datapath/1";
constexpr char kPayloadAwgDatagram[] = "awg-datagram";
constexpr char kCarrierDirectAwg[] = "direct-awg";

// carrierhost.CarrierHTTP3 / CarrierHTTP2. kCarrierHttp2 exists ONLY so the
// gate can refuse it by name with the real reason; it is never accepted.
constexpr char kCarrierHttp3[] = "http3-connect-udp";
constexpr char kCarrierHttp2[] = "http2-stream";

// carrierhost.ProfileVersion, and the only authorization mode this host offers.
// carrierhost refuses "anonymous-token" outright -- that route needs an issued
// privacy-token pool verified against the signed manifest's issuer keys, which
// is not a file a loader can read -- so there is no way to ask for it here.
constexpr char kCarrierProfileVersion[] = "winn-carrier-profile/1";
constexpr char kAuthModeIdentity[] = "identity";

constexpr char kPrivacyStandard[] = "standard";
constexpr char kPrivacyHighRisk[] = "high-risk";

// carrier.DefaultMaxDatagram bounds; mirrors carrierhost.normalize.
constexpr int kMinInnerDatagram = 32;
constexpr int kMaxInnerDatagram = 1500;

// knock.HeaderSize (a 16-byte nonce plus a 32-byte HMAC-SHA256 tag) and
// carrier.AbsoluteMaxDatagram. A knock must fit in ONE unfragmented datagram.
constexpr int kSpaMinPacketSize = 48;
constexpr uint64_t kSpaMaxPacketSize = 1500;

// A generous ceiling on the freshness scalars. They are policy, not secrets,
// and they must match the gate exactly; this only bounds what a served config
// can make this host parse.
constexpr uint64_t kSpaMaxSeconds = 86400;

// Where the profile and its credentials live, under the per-user private data
// directory. Mirrors Android's PROFILE_DIRECTORY_NAME / PROFILE_FILE_NAME.
constexpr char kWinnStateDirName[] = "winn";
constexpr char kCarrierProfileFileName[] = "carrier-profile.json";
constexpr int kMinDatagram = 32;
constexpr int kMaxDatagramCeiling = 1500;
constexpr size_t kMaxSessionIdBytes = 128;

// How long to wait for the engine's CreateAck. The Android bridge uses 10s and
// the engine's own carrier dial is bounded at 30s; direct-awg does no dial at
// all, so 10s here is generous rather than tight.
constexpr int kCreateAckTimeoutMs = 10000;
constexpr int kStatusTimeoutMs = 2000;
constexpr int kCloseAckWaitMs = 750;

std::string Trim(const std::string& value) {
  size_t start = 0;
  while (start < value.size() &&
         std::isspace(static_cast<unsigned char>(value[start])) != 0) {
    ++start;
  }
  size_t end = value.size();
  while (end > start &&
         std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
    --end;
  }
  return value.substr(start, end - start);
}

std::string LowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

bool IsSectionHeaderLine(const std::string& line) {
  return line.size() >= 3 && line.front() == '[' && line.back() == ']';
}

std::map<std::string, std::string> ParseIniSection(const std::string& config,
                                                   const std::string& wanted) {
  std::map<std::string, std::string> out;
  std::istringstream stream(config);
  std::string line;
  bool in_section = false;
  const std::string target = LowerAscii(wanted);
  while (std::getline(stream, line)) {
    const std::string trimmed = Trim(line);
    if (IsSectionHeaderLine(trimmed)) {
      in_section = LowerAscii(trimmed.substr(1, trimmed.size() - 2)) == target;
      continue;
    }
    if (!in_section) continue;
    const size_t equals = trimmed.find('=');
    if (equals == std::string::npos) continue;
    out[LowerAscii(Trim(trimmed.substr(0, equals)))] =
        Trim(trimmed.substr(equals + 1));
  }
  return out;
}

bool SectionTruthy(const std::map<std::string, std::string>& section,
                   const std::string& key) {
  const auto it = section.find(key);
  if (it == section.end()) return false;
  const std::string value = LowerAscii(Trim(it->second));
  return value == "true" || value == "1" || value == "yes" || value == "y";
}

// Parses an unsigned decimal that fits in 64 bits. Returns false on anything
// else, including a leading sign, whitespace inside, or overflow.
bool ParseUnsigned(const std::string& text, uint64_t max, uint64_t* out) {
  if (text.empty() || text.size() > 20) return false;
  uint64_t value = 0;
  for (const unsigned char c : text) {
    if (std::isdigit(c) == 0) return false;
    if (value > (UINT64_MAX - static_cast<uint64_t>(c - '0')) / 10) return false;
    value = value * 10 + static_cast<uint64_t>(c - '0');
  }
  if (value > max) return false;
  *out = value;
  return true;
}

// Parses one H1..H4 value in either spelling: "44" or "1000-4000".
// Mirrors VpnConfigValidator.parseAwgHeaderSpec (Dart) and is the single
// source of truth for the winn/3 path on Linux. Being more permissive than
// the engine (e.g. accepting "1000 - 4000" with interior whitespace) lets
// through a profile the far end cannot start.
bool ParseHeaderSpec(const std::string& raw, LinuxAwgHeaderSpec* out) {
  if (out == nullptr) return false;
  const std::string text = Trim(raw);
  if (text.empty() || text.size() > 21) return false;
  for (const unsigned char c : text) {
    if (c == '\r' || c == '\n' || c == '\0') return false;
    if (std::isspace(c) != 0) return false;
  }
  const size_t sep = text.find('-');
  if (sep == std::string::npos) {
    if (text.size() > 10) return false;
    uint64_t v = 0;
    if (!ParseUnsigned(text, 0xFFFFFFFFULL, &v) || v < 5) return false;
    out->start = static_cast<uint32_t>(v);
    out->end = static_cast<uint32_t>(v);
    return true;
  }
  const std::string startText = text.substr(0, sep);
  const std::string endText = text.substr(sep + 1);
  if (startText.empty() || endText.empty()) return false;
  if (endText.find('-') != std::string::npos) return false;
  if (startText.size() > 10 || endText.size() > 10) return false;
  uint64_t s = 0, e = 0;
  if (!ParseUnsigned(startText, 0xFFFFFFFFULL, &s) || s < 5) return false;
  if (!ParseUnsigned(endText, 0xFFFFFFFFULL, &e)) return false;
  if (e < s) return false;
  uint64_t width = e - s + 1;
  if (width > 0xFFFFFFFFULL || width == 0) return false;
  out->start = static_cast<uint32_t>(s);
  out->end = static_cast<uint32_t>(e);
  return true;
}

bool IsIpv4Literal(const std::string& host) {
  in_addr address{};
  if (inet_pton(AF_INET, host.c_str(), &address) != 1) return false;
  const uint32_t value = ntohl(address.s_addr);
  if (value == 0) return false;                       // unspecified
  const uint32_t first = (value >> 24) & 0xFFu;
  return first < 224 || first > 239;                  // not multicast
}

bool IsIpv6Literal(const std::string& host) {
  in6_addr address{};
  if (inet_pton(AF_INET6, host.c_str(), &address) != 1) return false;
  if (address.s6_addr[0] == 0xFF) return false;       // ff00::/8 multicast
  for (int index = 0; index < 16; ++index) {
    if (address.s6_addr[index] != 0) return true;
  }
  return false;                                       // ::
}

std::string JsonEscape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const char raw : value) {
    const unsigned char c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          static const char kHex[] = "0123456789abcdef";
          out += "\\u00";
          out += kHex[(c >> 4) & 0xF];
          out += kHex[c & 0xF];
        } else {
          out += raw;
        }
    }
  }
  return out;
}

// True for a string of exactly `length` lowercase hex digits. Uppercase is
// rejected rather than folded: carrierhost compares these as strings.
bool IsLowerHex(const std::string& value, size_t length) {
  if (value.size() != length) return false;
  for (const char c : value) {
    const bool digit = c >= '0' && c <= '9';
    const bool lower = c >= 'a' && c <= 'f';
    if (!digit && !lower) return false;
  }
  return true;
}

// True for an absolute https URL that names a host. Deliberately strict and
// deliberately not a general URL parser: this value becomes the RFC 9298 URI
// template the carrier dials, so "looks roughly like a URL" is not the bar.
bool IsAbsoluteHttpsUrlWithHost(const std::string& value) {
  static const std::string kScheme = "https://";
  if (value.size() <= kScheme.size()) return false;
  if (value.compare(0, kScheme.size(), kScheme) != 0) return false;
  const size_t host_start = kScheme.size();
  const size_t host_end = value.find_first_of("/?#", host_start);
  const std::string host = host_end == std::string::npos
                               ? value.substr(host_start)
                               : value.substr(host_start, host_end - host_start);
  if (host.empty()) return false;
  // No whitespace, no credentials-in-URL, nothing that would need escaping in
  // the JSON document this ends up in.
  if (host.find_first_of(" \t\r\n\"\\@") != std::string::npos) return false;
  return true;
}

// The per-user private data directory, mirroring PrivateDataBaseDirectory() in
// linux_tunnel_backend.cc: only an absolute XDG_DATA_HOME, or an absolute HOME
// plus "/.local/share", is legitimate. NEVER falls back to a shared,
// world-writable location such as /tmp -- callers fail closed instead.
std::string PrivateWinnStateDirectory() {
  const char* xdg = std::getenv("XDG_DATA_HOME");
  std::string base;
  if (xdg != nullptr && xdg[0] == '/') {
    base = xdg;
  } else {
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] != '/') return "";
    base = std::string(home) + "/.local/share";
  }
  return base + "/wins_vpn/" + kWinnStateDirName;
}

// A FRESH carrier session id: 16 CSPRNG bytes as 32 lowercase hex, matching
// mobility.ValidSessionID and WinnCarrierProfile.newSessionId.
//
// GENERATED HERE, DELIBERATELY NOT TAKEN FROM `[winn] session_id`. Android's own
// comment says why, and it is a privacy property rather than a formatting one:
// "a session identifier the control plane picked would link the session to the
// account that fetched the config." The `[winn] session_id` came from the server,
// so reusing it for the carrier would hand the carrier operator exactly the
// correlation the separate identifier exists to prevent.
//
// /dev/urandom rather than rand(): this value is an anti-correlation identifier,
// so a predictable one defeats its only purpose.
bool NewCarrierSessionId(std::string* out) {
  if (out == nullptr) return false;
  unsigned char bytes[16];
  const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  size_t got = 0;
  while (got < sizeof(bytes)) {
    const ssize_t n = ::read(fd, bytes + got, sizeof(bytes) - got);
    if (n <= 0) {
      if (n < 0 && errno == EINTR) continue;
      ::close(fd);
      return false;
    }
    got += static_cast<size_t>(n);
  }
  ::close(fd);
  static const char kHex[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(32);
  for (const unsigned char b : bytes) {
    hex.push_back(kHex[(b >> 4) & 0x0F]);
    hex.push_back(kHex[b & 0x0F]);
  }
  *out = hex;
  return true;
}

// Marks a descriptor close-on-exec.
//
// This matters more than it looks: RunCommand() in linux_tunnel_backend.cc uses
// std::system(), which forks, so without this the seam socket and both engine
// pipes would be inherited by every privileged helper shell this app runs --
// including one running as root.
//
// Written with fcntl rather than SOCK_CLOEXEC/pipe2 so this file compiles and
// its behaviour can be exercised on any POSIX host, not only on Linux. That is
// the same reason winn_frame.h is standard C++17: a layer that can only be
// built on its target platform is a layer that only gets verified there.
bool SetCloseOnExec(int fd) {
  const int flags = fcntl(fd, F_GETFD);
  return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

// B-05 (audits 2026-08-28): a pipe whose descriptors are close-on-exec
// ATOMICALLY. On Linux, pipe2(O_CLOEXEC) closes the window where another
// thread's fork+exec could inherit an engine-channel endpoint before the
// fcntl ran. The pipe()+fcntl fallback is for non-Linux TEST builds only
// (the shipped engine hosts are Linux; the test hosts are single-threaded).
bool PipeCloexec(int fds[2]) {
#if defined(__linux__)
  return pipe2(fds, O_CLOEXEC) == 0;
#else
  if (pipe(fds) != 0) return false;
  if (!SetCloseOnExec(fds[0]) || !SetCloseOnExec(fds[1])) {
    close(fds[0]);
    close(fds[1]);
    fds[0] = fds[1] = -1;
    return false;
  }
  return true;
#endif
}

int64_t NowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

// ---------------------------------------------------------------------------
// The loopback seam's burst backpressure. See
// docs/handoff/WINN_SEAM_BURST_BACKPRESSURE_20260805.md, and
// apple/EngineWrappers/WinsWinnPacketEngine.m, which is the reference
// implementation this mirrors.
//
// THE DEFECT. One thread did poll() -> recvfrom() -> WriteFrameLocked(). That
// last call writes into the engine subprocess's stdin pipe and BLOCKS when the
// engine is slower than the producer -- which is genuine downstream
// backpressure, correctly applied. But while it blocked, NOTHING was draining
// the seam socket, and everything AmneziaWG sent during that window was
// discarded by the kernel on the socket's receive queue, upstream of every
// counter in the system. Measured on this file before the change: 4,195
// datagrams offered unpaced, 1,429 delivered, 2,766 lost (65.94%), and the
// kernel's UDP RcvbufErrors counter moved by exactly 2,766.
//
// THERE IS NO TRUE BACKPRESSURE AVAILABLE HERE, and saying so is better than
// shipping something named backpressure that is not. The producer is
// amneziawg-go sending to its configured peer endpoint over UDP. On loopback
// UDP, sendto COMPLETES SUCCESSFULLY even when the receiver's queue is full;
// the kernel accepts the datagram and discards it at delivery. No socket
// option makes that sender block, and the peer is a third-party engine this
// host does not control.
//
// What is done instead, in order of how much it matters:
//   1. SPLIT THE DRAIN FROM THE WRITE. The drainer thread does nothing but
//      recvfrom; a second thread does the blocking pipe write. This is the
//      actual fix. Downstream backpressure still applies; it no longer stops
//      the drain.
//   2. MOVE THE DROP POINT SOMEWHERE IT CAN BE COUNTED. Between the two is a
//      bounded FIFO ring this file owns. When it fills, the datagram is dropped
//      by US, with an exact count and a log line, instead of by the kernel,
//      where Linux offers only a process-wide RcvbufErrors and no per-socket
//      statistic at all.
//   3. STATE THE BUFFER INSTEAD OF INHERITING IT. SO_RCVBUF is set explicitly
//      and the GRANTED value is read back and reported next to a high-water
//      mark of the backlog. A bigger buffer only moves the cliff -- reporting
//      both is what lets anyone see whether it is even the mechanism.
// ---------------------------------------------------------------------------

// Derived from the Apple measurement and then verified here, not chosen to make
// a test pass: the writer's sustained rate is below an unpaced producer's, so
// the ring must cover the deficit for the length of a burst. 2048 slots is the
// smallest power of two with real margin at the 4 MiB burst of record. Raising
// it does not remove loss under SUSTAINED overload -- no finite buffer absorbs
// an unbounded deficit -- which is why the regression test asserts accounting
// rather than zero loss.
constexpr size_t kSeamRingSlots = 2048;

// Slots claimed per lock acquisition by the writer, and coalesced into a SINGLE
// write() syscall. On Apple, batching moved nothing because each datagram cost
// its own cgo call into the Go engine no matter how they were grouped. Here the
// engine is a subprocess behind a pipe, so a batch really is one syscall, and
// that is what lifts the writer's ceiling above the producer's offered rate.
constexpr size_t kSeamWriteBatch = 32;

// Datagrams lifted per recvmmsg() on Linux. Same lever on the drain side, and
// the one that matters more: with the writer batched, the DRAINER became the
// ceiling and the loss moved straight back into the kernel.
constexpr size_t kSeamRecvBatch = 128;

// Requested SO_RCVBUF for the seam socket. Linux returns twice the requested
// value from getsockopt (it accounts for skb overhead), so the number reported
// as "granted" is the kernel's own accounting figure, not a second request.
constexpr int kSeamRcvbufBytes = 2 * 1024 * 1024;

// At most one drop line per second. A burst produces thousands of drops and a
// line each would be its own denial of service against the log.
constexpr int64_t kSeamDropLogIntervalMs = 1000;

// Every one of these is counted by THIS file, so unlike the engine's status
// document -- which carries the gateway endpoint -- all of it is safe to log.
struct SeamCounters {
  std::atomic<unsigned long long> rx_datagrams{0};
  std::atomic<unsigned long long> rx_bytes{0};
  std::atomic<unsigned long long> rx_ring_dropped{0};
  std::atomic<unsigned long long> rx_foreign_sender{0};
  std::atomic<unsigned long long> rx_oversize{0};
  std::atomic<unsigned long long> tx_written{0};
  std::atomic<unsigned long long> tx_write_failed{0};
  std::atomic<unsigned long long> awg_sent{0};
  std::atomic<unsigned long long> awg_send_failed{0};
  std::atomic<unsigned long long> awg_no_peer{0};
  // The most bytes ever seen queued in the socket's receive buffer, sampled
  // with FIONREAD each wakeup. Read against rcvbuf_bytes below: that ratio is
  // the evidence for or against the buffer being the mechanism.
  std::atomic<unsigned long long> rx_backlog_high_water_bytes{0};
  std::atomic<unsigned long long> rcvbuf_bytes{0};
  std::atomic<long long> last_drop_log_ms{0};
};

// Single producer (the drainer), single consumer (the writer). Strictly FIFO,
// tail-drop only, so datagram ORDER is unchanged -- a reordering seam would
// turn a rate defect into an authentication failure at the gateway.
struct SeamRing {
  std::mutex mutex;
  std::condition_variable signal;
  std::vector<uint8_t> storage;   // kSeamRingSlots * slot_bytes
  std::vector<uint32_t> lengths;  // per-slot payload length
  size_t slot_bytes = 0;
  size_t head = 0;   // next slot the writer will read
  size_t queued = 0; // slots currently occupied
  bool closed = false;

  void Init(size_t datagram_bytes) {
    slot_bytes = datagram_bytes;
    storage.assign(kSeamRingSlots * slot_bytes, 0);
    lengths.assign(kSeamRingSlots, 0);
    head = 0;
    queued = 0;
    closed = false;
  }
};

// ---------------------------------------------------------------------------
// The running engine. One at a time, guarded by g_mutex.
// ---------------------------------------------------------------------------

struct EngineState {
  pid_t pid = -1;
  int stdin_fd = -1;      // host -> engine frames
  int stdout_fd = -1;     // engine -> host frames
  int seam_fd = -1;       // the loopback AWG-datagram seam
  int wake_fd[2] = {-1, -1};  // self-pipe that unblocks both pumps on stop

  std::thread inbound;    // seam -> ring   (DRAINS ONLY; never blocks on write)
  std::thread writer;     // ring -> Inbound frames (does the blocking write)
  std::thread outbound;   // Outbound frames -> seam

  SeamRing ring;
  SeamCounters counters;

  std::atomic<bool> stopping{false};
  std::atomic<bool> channel_up{false};

  std::mutex write_mutex;   // one frame at a time on stdin_fd

  std::mutex status_mutex;
  std::condition_variable status_signal;
  std::string last_status;
  int64_t last_status_at = 0;
  std::string failure;
  bool close_acked = false;

  // The AWG engine's own source address: 127.0.0.1 and the ListenPort this
  // host reserved and wrote into its configuration, set by
  // StartLinuxWinnEngine before either pump starts and never learned from
  // traffic. Mirrors RelayConfig.ExpectedLocalPeer: datagrams from any other
  // local process are dropped, including one that reaches the seam first.
  // This is a socket check, not process authentication: StartLinuxWinnEngine
  // has confirmed that a root-owned socket holds the port, which no
  // unprivileged process can share, and root is trusted on this host.
  std::mutex peer_mutex;
  sockaddr_in awg_peer{};
  bool awg_peer_known = false;

  // Latched from the params this host started the session with, and never from
  // anything the engine says back. It is the input to the route-promotion gate
  // and to the periodic health check: false means the datapath's transport
  // counters cannot fire, so no proof is obtainable and the session must be
  // refused rather than promoted. Immutable for the life of the session, so
  // both readers take it under g_mutex without any further synchronisation.
  bool headers_classify = false;
};

std::mutex g_mutex;
EngineState* g_engine = nullptr;

constexpr int kEnginePipeWriteTimeoutMilliseconds = 5000;

bool WriteEnginePipeAll(int fd, const uint8_t* data, size_t size) {
  if (fd < 0 || (data == nullptr && size != 0)) return false;
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 ||
      ((flags & O_NONBLOCK) == 0 &&
       fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)) {
    return false;
  }
  const auto deadline = std::chrono::steady_clock::now() +
      std::chrono::milliseconds(kEnginePipeWriteTimeoutMilliseconds);
  size_t offset = 0;
  while (offset < size) {
    if (std::chrono::steady_clock::now() >= deadline) {
      errno = ETIMEDOUT;
      return false;
    }
    const ssize_t written = write(fd, data + offset, size - offset);
    if (written > 0) {
      offset += static_cast<size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) continue;
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        errno = ETIMEDOUT;
        return false;
      }
      const int remaining = static_cast<int>(
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
              .count());
      pollfd writable{fd, POLLOUT, 0};
      const int ready = poll(&writable, 1, std::max(1, remaining));
      if (ready < 0 && errno == EINTR) continue;
      if (ready == 0) continue;
      if (ready < 0 || (writable.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        return false;
      }
      if (writable.revents & POLLOUT) continue;
    }
    return false;
  }
  return true;
}

bool WriteFrameLocked(EngineState* state, Opcode opcode,
                      const uint8_t* payload, size_t size) {
  std::vector<uint8_t> frame;
  if (!EncodeFrame(opcode, payload, size, &frame)) return false;
  std::lock_guard<std::mutex> guard(state->write_mutex);
  if (state->stdin_fd < 0) return false;
  return WriteEnginePipeAll(state->stdin_fd, frame.data(), frame.size());
}

void RecordFailure(EngineState* state, const std::string& reason) {
  {
    std::lock_guard<std::mutex> guard(state->status_mutex);
    if (state->failure.empty()) state->failure = reason;
  }
  state->channel_up.store(false);
  state->status_signal.notify_all();
}

// ---------------------------------------------------------------------------
// Seam instrumentation. INTEGERS ONLY on every one of these paths: no endpoint,
// no session id, no configuration value and no datagram byte is ever passed to
// a log call in this file. The engine subprocess already inherits this stderr
// by design (see the fork site) so diagnostics land in the app's own log.
// ---------------------------------------------------------------------------

// Rate-limited to one line per second. A burst drops thousands of datagrams;
// a line each would be its own denial of service against the log.
void LogSeamDropIfDue(EngineState* state) {
  const int64_t now = NowMs();
  long long previous = state->counters.last_drop_log_ms.load();
  if (now - static_cast<int64_t>(previous) < kSeamDropLogIntervalMs) return;
  if (!state->counters.last_drop_log_ms.compare_exchange_strong(
          previous, static_cast<long long>(now))) {
    return;
  }
  std::fprintf(stderr,
               "winn seam dropping outbound datagrams: ring_dropped=%llu "
               "received=%llu written=%llu write_failed=%llu "
               "backlog_high_water=%llu rcvbuf=%llu\n",
               state->counters.rx_ring_dropped.load(),
               state->counters.rx_datagrams.load(),
               state->counters.tx_written.load(),
               state->counters.tx_write_failed.load(),
               state->counters.rx_backlog_high_water_bytes.load(),
               state->counters.rcvbuf_bytes.load());
}

// ONE LINE PER SESSION, UNCONDITIONALLY, and a different one when the session
// lost something. A lossless session and a lossy session produced byte-for-byte
// identical output before this existed -- which is precisely how a 34% loss
// survived an end-to-end run that was recorded as a proof.
void LogSeamSessionClose(EngineState* state) {
  const unsigned long long dropped = state->counters.rx_ring_dropped.load();
  const unsigned long long oversize = state->counters.rx_oversize.load();
  const unsigned long long foreign = state->counters.rx_foreign_sender.load();
  const unsigned long long write_failed = state->counters.tx_write_failed.load();
  const unsigned long long send_failed = state->counters.awg_send_failed.load();
  if (dropped + oversize + foreign + write_failed + send_failed > 0) {
    std::fprintf(stderr,
                 "winn seam closed WITH LOSS: received=%llu written=%llu "
                 "ring_dropped=%llu oversize=%llu foreign_sender=%llu "
                 "write_failed=%llu send_failed=%llu no_peer=%llu "
                 "backlog_high_water=%llu rcvbuf=%llu\n",
                 state->counters.rx_datagrams.load(),
                 state->counters.tx_written.load(), dropped, oversize, foreign,
                 write_failed, send_failed,
                 state->counters.awg_no_peer.load(),
                 state->counters.rx_backlog_high_water_bytes.load(),
                 state->counters.rcvbuf_bytes.load());
    return;
  }
  std::fprintf(stderr,
               "winn seam closed clean: received=%llu written=%llu "
               "backlog_high_water=%llu rcvbuf=%llu\n",
               state->counters.rx_datagrams.load(),
               state->counters.tx_written.load(),
               state->counters.rx_backlog_high_water_bytes.load(),
               state->counters.rcvbuf_bytes.load());
}

// Tail-drop enqueue. Returns false when the ring was full, which is a DROP WE
// OWN: counted exactly, attributed to a direction, and logged. Contrast with
// the kernel drop it replaces, which Linux reports only as a process-wide
// RcvbufErrors with no per-socket breakdown and no way to attribute.
// Caller holds ring.mutex. Returns false when the ring was full.
bool SeamRingPushLocked(EngineState* state, const uint8_t* data, size_t size) {
  if (state->ring.closed) return false;
  if (state->ring.queued >= kSeamRingSlots) {
    state->counters.rx_ring_dropped.fetch_add(1);
    return false;
  }
  const size_t slot = (state->ring.head + state->ring.queued) % kSeamRingSlots;
  std::memcpy(&state->ring.storage[slot * state->ring.slot_bytes], data, size);
  state->ring.lengths[slot] = static_cast<uint32_t>(size);
  ++state->ring.queued;
  return true;
}

#ifndef __linux__
// Single-datagram enqueue for the portable drain path. On Linux the batched
// drain pushes under one lock acquisition instead, so this is not compiled
// there rather than left as an unused function.
bool SeamRingPush(EngineState* state, const uint8_t* data, size_t size) {
  bool ok;
  {
    std::lock_guard<std::mutex> guard(state->ring.mutex);
    ok = SeamRingPushLocked(state, data, size);
  }
  if (ok) state->ring.signal.notify_one();
  return ok;
}
#endif

// The blocking half. This thread, and ONLY this thread, may block: the write
// below goes into the engine subprocess's stdin pipe and stalls whenever the
// engine is slower than the producer. That stall is correct backpressure. The
// entire point of the split is that it no longer stops the seam being drained.
void SeamWriterPump(EngineState* state) {
  std::vector<uint8_t> batch;   // whole claimed run, encoded, written ONCE
  std::vector<uint8_t> frame;   // scratch for a single EncodeFrame
  while (true) {
    size_t claimed = 0;
    batch.clear();
    {
      std::unique_lock<std::mutex> guard(state->ring.mutex);
      state->ring.signal.wait(guard, [state] {
        return state->ring.queued > 0 || state->ring.closed;
      });
      if (state->ring.queued == 0 && state->ring.closed) return;
      // A contiguous run of up to kSeamWriteBatch slots.
      claimed = std::min(state->ring.queued, kSeamWriteBatch);
      claimed = std::min(claimed, kSeamRingSlots - state->ring.head);
      const size_t first = state->ring.head;
      // ENCODED UNDER THE LOCK, straight out of ring storage, so the payload is
      // copied once rather than staged into a second scratch buffer first. The
      // slots are not released until after the write, but the encode has to
      // happen before the lock is dropped because the drainer may reuse them
      // the moment it is.
      for (size_t i = 0; i < claimed; ++i) {
        const size_t slot = first + i;  // contiguous by construction
        if (!EncodeFrame(Opcode::kInbound,
                         &state->ring.storage[slot * state->ring.slot_bytes],
                         state->ring.lengths[slot], &frame)) {
          continue;  // cannot happen: length was bounded at receive
        }
        batch.insert(batch.end(), frame.begin(), frame.end());
      }
    }

    // ONE write() FOR THE WHOLE BATCH. The unbatched version paid a syscall per
    // datagram, and the measurement that mattered was that this writer is
    // syscall-bound, not lock-bound: coalescing here is what lifts the writer's
    // ceiling above the producer's offered rate. Buffering alone does not --
    // a ring big enough to hide a syscall-bound writer is a ring sized to make
    // a test pass.
    bool ok;
    {
      std::lock_guard<std::mutex> guard(state->write_mutex);
      ok = state->stdin_fd >= 0 &&
           WriteEnginePipeAll(state->stdin_fd, batch.data(), batch.size());
    }
    {
      std::lock_guard<std::mutex> guard(state->ring.mutex);
      state->ring.head = (state->ring.head + claimed) % kSeamRingSlots;
      state->ring.queued -= claimed;
    }
    if (!ok) {
      state->counters.tx_write_failed.fetch_add(claimed);
      if (!state->stopping.load()) {
        RecordFailure(state, "the Winn engine channel failed while writing");
      }
      return;
    }
    state->counters.tx_written.fetch_add(claimed);
  }
}

// Reads engine->host frames and demultiplexes by opcode. Outbound frames
// interleave with responses at any time, so this cannot assume request/response
// ordering -- the Go doc says so explicitly and a host that assumed otherwise
// would deadlock on the first datagram that overtook a status reply.
void OutboundPump(EngineState* state) {
  FrameReader reader(/*accept_engine_to_host=*/true);
  std::array<uint8_t, 65536> chunk{};
  while (!state->stopping.load()) {
    pollfd fds[2];
    fds[0] = {state->stdout_fd, POLLIN, 0};
    fds[1] = {state->wake_fd[0], POLLIN, 0};
    const int ready = poll(fds, 2, -1);
    if (ready < 0) {
      if (errno == EINTR) continue;
      RecordFailure(state, "the Winn engine channel could not be polled");
      return;
    }
    if ((fds[1].revents & POLLIN) != 0) return;  // stop requested
    if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;

    const ssize_t count = read(state->stdout_fd, chunk.data(), chunk.size());
    if (count < 0) {
      if (errno == EINTR) continue;
      RecordFailure(state, "the Winn engine channel failed while reading");
      return;
    }
    if (count == 0) {
      RecordFailure(state, "the Winn engine closed its channel");
      return;
    }
    reader.Append(chunk.data(), static_cast<size_t>(count));

    for (;;) {
      Frame frame;
      const DecodeStatus status = reader.Next(&frame);
      if (status == DecodeStatus::kNeedMore) break;
      if (status == DecodeStatus::kInvalid) {
        // Never resynchronize. Scanning forward for the next magic turns a
        // length confusion into an attacker-chosen frame boundary.
        RecordFailure(state, "the Winn engine sent an invalid frame");
        return;
      }
      switch (frame.opcode) {
        case Opcode::kOutbound: {
          sockaddr_in peer{};
          bool known = false;
          {
            std::lock_guard<std::mutex> guard(state->peer_mutex);
            peer = state->awg_peer;
            known = state->awg_peer_known;
          }
          if (!known) {
            // Unreachable while StartLinuxWinnEngine pins the reserved port;
            // kept so an unpinned state can never invent a destination.
            state->counters.awg_no_peer.fetch_add(1);
            break;
          }
          // The return value used to be discarded entirely: a failed sendto and
          // a successful one were indistinguishable from outside this process.
          // It is counted now rather than retried, because on a blocking
          // loopback UDP socket the failures that remain are real errors, not
          // transient fullness.
          //
          // KNOWN LIMIT, NOT CLAIMED AS FIXED: the AmneziaWG engine owns the
          // RECEIVING socket on this leg. If it is not draining, the kernel
          // discards on delivery and this sendto still reports success. That
          // residue is not reachable from this side.
          if (sendto(state->seam_fd, frame.payload.data(),
                     frame.payload.size(), 0,
                     reinterpret_cast<const sockaddr*>(&peer),
                     sizeof(peer)) < 0) {
            state->counters.awg_send_failed.fetch_add(1);
          } else {
            state->counters.awg_sent.fetch_add(1);
          }
          break;
        }
        case Opcode::kCreateAck:
        case Opcode::kStatusResponse: {
          {
            std::lock_guard<std::mutex> guard(state->status_mutex);
            state->last_status.assign(frame.payload.begin(),
                                      frame.payload.end());
            state->last_status_at = NowMs();
          }
          state->status_signal.notify_all();
          break;
        }
        case Opcode::kCloseAck: {
          {
            std::lock_guard<std::mutex> guard(state->status_mutex);
            state->close_acked = true;
          }
          state->status_signal.notify_all();
          return;
        }
        case Opcode::kError: {
          std::string text(frame.payload.begin(), frame.payload.end());
          if (text.size() > 300) text.resize(300);
          RecordFailure(state, "the Winn engine reported: " + text);
          return;
        }
        default:
          RecordFailure(state, "the Winn engine sent an unexpected frame");
          return;
      }
    }
  }
}

// Validation only -- deliberately does NOT touch the ring, so the batched drain
// below can validate a whole recvmmsg batch and then take ring.mutex once.
// Shared by both drain implementations so the two cannot drift in what they
// accept. Returns true when the datagram should be queued.
bool SeamDatagramAccepted(EngineState* state,
                          int max_datagram,
                          size_t size,
                          const sockaddr_in& sender) {
  state->counters.rx_datagrams.fetch_add(1);
  state->counters.rx_bytes.fetch_add(static_cast<unsigned long long>(size));

  // Structural containment, restated as a check: the seam is bound to
  // 127.0.0.1, so a non-loopback sender cannot arrive, but the pin is what
  // keeps a second local process from injecting into this tunnel. The pin is
  // the reserved ListenPort, set before the pumps start; the first sender is
  // never adopted, because any local process can be first.
  if (sender.sin_family != AF_INET ||
      (ntohl(sender.sin_addr.s_addr) >> 24) != 127) {
    state->counters.rx_foreign_sender.fetch_add(1);
    return false;
  }
  {
    std::lock_guard<std::mutex> guard(state->peer_mutex);
    if (!state->awg_peer_known ||
        state->awg_peer.sin_port != sender.sin_port ||
        state->awg_peer.sin_addr.s_addr != sender.sin_addr.s_addr) {
      state->counters.rx_foreign_sender.fetch_add(1);
      return false;  // not the AmneziaWG engine's reserved socket
    }
  }
  if (size > static_cast<size_t>(max_datagram)) {
    state->counters.rx_oversize.fetch_add(1);
    return false;  // oversize: dropped, never truncated
  }
  return true;
}

// Reads AmneziaWG's outer datagrams off the seam and hands them to the ring.
//
// THIS THREAD MUST NEVER BLOCK ON ANYTHING BUT poll(). Every statement below is
// either a syscall on the seam socket, a bounded memcpy, or a counter. The
// blocking pipe write that used to live here is now SeamWriterPump's job. If a
// future change adds anything here that can wait on the engine, the defect
// documented above comes straight back and the burst regression will say so.
void InboundPump(EngineState* state, int max_datagram) {
  // maxDatagram+1 per slot, exactly as internal/carrier/relay.go and the Android
  // seam do, so an oversize datagram is DETECTED rather than silently
  // truncated: a truncated AWG datagram would fail authentication at the
  // gateway and look like a network fault instead of a configuration one.
#ifdef __linux__
  std::vector<uint8_t> buffer(kSeamRecvBatch *
                              (static_cast<size_t>(max_datagram) + 1));
  std::vector<mmsghdr> messages(kSeamRecvBatch);
  std::vector<iovec> iovecs(kSeamRecvBatch);
  std::vector<sockaddr_in> senders(kSeamRecvBatch);
  const size_t slot = static_cast<size_t>(max_datagram) + 1;
#else
  std::vector<uint8_t> buffer(static_cast<size_t>(max_datagram) + 1);
#endif
  while (!state->stopping.load()) {
    pollfd fds[2];
    fds[0] = {state->seam_fd, POLLIN, 0};
    fds[1] = {state->wake_fd[0], POLLIN, 0};
    const int ready = poll(fds, 2, -1);
    if (ready < 0) {
      if (errno == EINTR) continue;
      RecordFailure(state, "the Winn seam could not be polled");
      return;
    }
    if ((fds[1].revents & POLLIN) != 0) return;
    if ((fds[0].revents & POLLIN) == 0) continue;

    // DRAIN TO EMPTY. The old loop took ONE datagram per poll() and went back
    // to sleep, paying two syscalls per datagram in exactly the condition where
    // syscalls are the scarce resource. MSG_DONTWAIT is used rather than
    // O_NONBLOCK on the descriptor so that the reverse leg's sendto keeps the
    // blocking semantics it was written against -- the drain-to-empty property
    // is what matters, and this gets it without changing the other direction.
    unsigned long long pass_bytes = 0;
#ifdef __linux__
    // recvmmsg lifts kSeamRecvBatch datagrams per syscall. This is the drainer's
    // half of the same measurement that produced the batched writer: with the
    // writer coalesced, the DRAINER became the ceiling and the loss moved back
    // into the kernel. One datagram per syscall could not keep ahead of an
    // unpaced loopback producer, and no receive buffer size fixes that -- it
    // only changes how long it takes to overflow.
    while (!state->stopping.load()) {
      for (size_t i = 0; i < kSeamRecvBatch; ++i) {
        iovecs[i].iov_base = buffer.data() + i * slot;
        iovecs[i].iov_len = slot;
        std::memset(&messages[i], 0, sizeof(messages[i]));
        messages[i].msg_hdr.msg_iov = &iovecs[i];
        messages[i].msg_hdr.msg_iovlen = 1;
        messages[i].msg_hdr.msg_name = &senders[i];
        messages[i].msg_hdr.msg_namelen = sizeof(senders[i]);
      }
      const int got = recvmmsg(state->seam_fd, messages.data(),
                               static_cast<unsigned>(kSeamRecvBatch),
                               MSG_DONTWAIT, nullptr);
      if (got < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;  // queue is empty
        RecordFailure(state, "the Winn seam failed while reading");
        return;
      }
      if (got == 0) break;
      // ONE ring.mutex acquisition and ONE condition-variable signal for the
      // whole batch. Per-datagram locking here was measurable: at 64 datagrams
      // per syscall it put 64 lock round trips and 64 notify_one calls between
      // the drainer and its next recvmmsg, and the drainer being slow is the
      // failure mode this entire change exists to remove.
      bool any_pushed = false;
      bool any_dropped = false;
      {
        std::lock_guard<std::mutex> guard(state->ring.mutex);
        for (int i = 0; i < got; ++i) {
          const size_t size = messages[i].msg_len;
          if (size == 0) continue;
          pass_bytes += static_cast<unsigned long long>(size);
          if (!SeamDatagramAccepted(state, max_datagram, size, senders[i])) {
            continue;
          }
          if (SeamRingPushLocked(state, buffer.data() + i * slot, size)) {
            any_pushed = true;
          } else {
            any_dropped = true;
          }
        }
      }
      if (any_pushed) state->ring.signal.notify_one();
      // Counted inside SeamRingPushLocked. This is the drop that used to happen
      // in the kernel, where nothing on Linux could attribute it to this socket.
      if (any_dropped) LogSeamDropIfDue(state);
      if (static_cast<size_t>(got) < kSeamRecvBatch) break;  // queue is empty
    }
#else
    // Portable fallback. This file is deliberately buildable on any POSIX host
    // -- a layer that can only be compiled on its target platform is a layer
    // that only ever gets verified there -- so the single-datagram drain stays
    // for everything that is not Linux. It still drains to empty; it just pays
    // a syscall per datagram to do it.
    while (!state->stopping.load()) {
      sockaddr_in sender{};
      socklen_t sender_size = sizeof(sender);
      const ssize_t count =
          recvfrom(state->seam_fd, buffer.data(), buffer.size(), MSG_DONTWAIT,
                   reinterpret_cast<sockaddr*>(&sender), &sender_size);
      if (count < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;  // queue is empty
        RecordFailure(state, "the Winn seam failed while reading");
        return;
      }
      if (count == 0) continue;
      pass_bytes += static_cast<unsigned long long>(count);
      if (!SeamDatagramAccepted(state, max_datagram,
                                static_cast<size_t>(count), sender)) {
        continue;
      }
      if (!SeamRingPush(state, buffer.data(), static_cast<size_t>(count))) {
        LogSeamDropIfDue(state);
      }
    }
#endif

    // How much had piled up by the time this thread was scheduled. Read
    // against seam_rcvbuf_bytes, this is the evidence for or against the
    // receive buffer being the mechanism.
    //
    // NOT sampled with FIONREAD: on Linux, SIOCINQ on a UDP socket reports the
    // size of the NEXT PENDING DATAGRAM, not the total queued -- unlike Darwin,
    // where it is the whole backlog. Bytes drained in one wakeup is the honest
    // cheap equivalent, and it is a LOWER BOUND on the backlog rather than a
    // guess dressed up as a measurement.
    unsigned long long previous =
        state->counters.rx_backlog_high_water_bytes.load();
    while (pass_bytes > previous &&
           !state->counters.rx_backlog_high_water_bytes
                .compare_exchange_weak(previous, pass_bytes)) {
    }
  }
}

void CloseIfOpen(int* fd) {
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

// Tears everything down. Caller holds g_mutex.
void TeardownLocked(EngineState* state) {
  state->stopping.store(true);
  state->channel_up.store(false);

  // Ask politely first so the engine can flush and answer CloseAck.
  if (state->stdin_fd >= 0) {
    WriteFrameLocked(state, Opcode::kClose, nullptr, 0);
    std::unique_lock<std::mutex> guard(state->status_mutex);
    state->status_signal.wait_for(
        guard, std::chrono::milliseconds(kCloseAckWaitMs),
        [state] { return state->close_acked; });
  }

  // Unblock the pumps. ORDER MATTERS: the drainer stops first, then the ring is
  // closed so the writer flushes what is still queued and exits, and only then
  // is the engine's stdin closed. Closing stdin first would turn every datagram
  // still in the ring into a write failure at teardown -- loss manufactured by
  // the shutdown path rather than by the burst.
  if (state->wake_fd[1] >= 0) {
    const uint8_t byte = 1;
    (void)!write(state->wake_fd[1], &byte, 1);
  }
  if (state->inbound.joinable()) state->inbound.join();
  {
    std::lock_guard<std::mutex> guard(state->ring.mutex);
    state->ring.closed = true;
  }
  state->ring.signal.notify_all();
  if (state->writer.joinable()) state->writer.join();

  CloseIfOpen(&state->stdin_fd);
  if (state->outbound.joinable()) state->outbound.join();

  // ONE LINE PER SESSION, ALWAYS. This is the property whose absence let a 34%
  // loss pass for a successful run.
  LogSeamSessionClose(state);

  CloseIfOpen(&state->stdout_fd);
  CloseIfOpen(&state->seam_fd);
  CloseIfOpen(&state->wake_fd[0]);
  CloseIfOpen(&state->wake_fd[1]);

  if (state->pid > 0) {
    int status = 0;
    for (int attempt = 0; attempt < 30; ++attempt) {
      // B-06: WNOHANG polling is interrupted by unrelated signals
      // (SIGCHLD for other children included); EINTR means poll again,
      // and only a reaped-pid or a real error ends the loop.
      const pid_t reaped = waitpid(state->pid, &status, WNOHANG);
      if (reaped == state->pid) {
        state->pid = -1;
        break;
      }
      if (reaped < 0 && errno == EINTR) continue;
      if (reaped < 0) {
        state->pid = -1;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (state->pid > 0) {
      kill(state->pid, SIGKILL);
      // B-06: the blocking reap retries EINTR so an unrelated signal
      // cannot strand a killed child unreaped.
      for (;;) {
        const pid_t reaped = waitpid(state->pid, &status, 0);
        if (reaped == state->pid) break;
        if (reaped < 0 && errno == EINTR) continue;
        break;  // ECHILD &c: nothing left to reap.
      }
      state->pid = -1;
    }
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

bool LinuxConfigSelectsWinnProtocol(const std::string& raw_config) {
  return SectionTruthy(ParseIniSection(raw_config, "winn"), "enabled");
}

bool SplitLinuxWinnEndpoint(const std::string& endpoint,
                            std::string* host,
                            std::string* port) {
  if (endpoint.empty() || host == nullptr || port == nullptr) return false;
  std::string parsed_host;
  std::string parsed_port;
  if (endpoint.front() == '[') {
    const size_t end = endpoint.find(']');
    if (end == std::string::npos || end + 1 >= endpoint.size() ||
        endpoint[end + 1] != ':') {
      return false;
    }
    parsed_host = endpoint.substr(1, end - 1);
    parsed_port = endpoint.substr(end + 2);
    if (!IsIpv6Literal(parsed_host)) return false;
  } else {
    const size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos || colon == 0) return false;
    parsed_host = endpoint.substr(0, colon);
    parsed_port = endpoint.substr(colon + 1);
    if (!IsIpv4Literal(parsed_host)) return false;
  }
  uint64_t port_value = 0;
  if (!ParseUnsigned(parsed_port, 65535, &port_value) || port_value == 0) {
    return false;
  }
  *host = parsed_host;
  *port = parsed_port;
  return true;
}

bool ParseLinuxWinnSection(const std::string& raw_config,
                           LinuxWinnParams* out,
                           std::string* error) {
  if (out == nullptr || error == nullptr) return false;
  const std::map<std::string, std::string> section =
      ParseIniSection(raw_config, "winn");
  if (!SectionTruthy(section, "enabled")) {
    *error = "The Winn Protocol section is not enabled.";
    return false;
  }

  LinuxWinnParams params;

  // THE CARRIER GATE, and it is checked FIRST on purpose.
  //
  // This is the native anti-downgrade check: a configuration naming a carrier
  // this host cannot build must fail, never quietly become direct-awg. It runs
  // before the unknown-key sweep below because a carrier session's `[winn]`
  // section also carries the carrier-profile keys (masque_template,
  // public_target, suite, ...) that build the separate document
  // `winn-datapath -carrier-profile` reads. Sweeping first would refuse such a
  // config for carrying "masque_template", which is true but names the wrong
  // cause; this host's actual limitation is that it builds direct-awg only.
  // WIDENED for http3-connect-udp, and the widening is additive. The gate did
  // and still does refuse every carrier this host cannot build; what changed is
  // that http3-connect-udp is no longer one of them. `cmd/winn-datapath` accepts
  // `-carrier-profile PATH`, loads a carrierhost.Profile from it and calls
  // OpenWithCarrier, and this host now builds that document -- so naming the
  // carrier here is no longer a claim the engine cannot honour.
  //
  // http2-stream stays refused, for the same reason Android excludes it: the
  // engine implements it, but its dialer needs a CONNECTED TCP socket this host
  // does not open. Accepting it would move the failure from a named refusal
  // here to a socket-kind mismatch inside the engine, after a socket has
  // already been handed to the child. A carrier joins this list when the HOST
  // can supply what its dialer takes, not when the engine gains the carrier.
  const auto carrier_entry = section.find("carrier");
  const std::string carrier = carrier_entry == section.end() ||
                                      Trim(carrier_entry->second).empty()
                                  ? std::string(kCarrierDirectAwg)
                                  : LowerAscii(Trim(carrier_entry->second));
  if (carrier != kCarrierDirectAwg && carrier != kCarrierHttp3) {
    if (carrier == kCarrierHttp2) {
      *error =
          "This server selected the \"" + carrier +
          "\" Winn Protocol v3 transport. The engine implements it, but its "
          "dialer needs a connected TCP socket this Linux host does not open, "
          "so it is refused here where the reason can be stated rather than "
          "inside the engine after a socket has been handed over. Starting a "
          "different transport instead would downgrade the session the server "
          "negotiated, so the connection was stopped.";
      return false;
    }
    *error = "This server selected the \"" + carrier +
             "\" Winn Protocol v3 transport, which this Linux build cannot "
             "build, and starting an unauthenticated transport instead "
             "would downgrade the session the server negotiated, so the "
             "connection was stopped.";
    return false;
  }
  params.carrier = carrier;

  // An UNRECOGNISED KEY IS A REFUSAL. WinnEngineConfig.from throws on one and
  // datapath.ParseConfig decodes with DisallowUnknownFields, so dropping it
  // here would be the one place in the chain that lies about what took effect.
  // The last eleven are WinnCarrierProfile.CARRIER_KEYS, folded in exactly as
  // Android folds them into RESERVED_KEYS. They describe the CARRIER PROFILE, a
  // separate document that travels as a file path on argv; not one of them is a
  // field of datapath.Config, so this host consumes them and never forwards
  // them. They are accepted for a direct-awg section too -- as on Android --
  // because the unknown-key sweep's job is to catch a field nobody reads, and
  // these are read.
  // The thirteen datapath.Config-shaped keys this host reads itself. The
  // carrier-profile keys are NOT listed beside them any more: they come from
  // kServedCarrierProfileKeys in the generated header, which is derived from
  // carrierhost.Profile's own json tags.
  //
  // This used to be one hand-typed array of 24, one of four identical copies
  // across C++, Kotlin, Swift and Dart. That all four agreed with each other is
  // exactly why nobody noticed that none of them agreed with the schema:
  // carrierhost.Profile grew five spa_ fields, every copy silently excluded
  // them, and an unrecognised key IS A REFUSAL here -- so serving a knock
  // parameter would not have merely been ignored on Linux, it would have failed
  // the whole connection.
  static const std::array<const char*, 13> kHostKeys = {
      "enabled", "endpoint", "session_id", "max_datagram", "carrier",
      "h1",      "h2",       "h3",         "h4",
      "s1",      "s2",       "s3",         "s4"};
  for (const auto& entry : section) {
    if (entry.first.empty()) continue;
    const bool known =
        std::find_if(kHostKeys.begin(), kHostKeys.end(),
                     [&entry](const char* key) {
                       return entry.first == key;
                     }) != kHostKeys.end() ||
        std::find_if(kServedCarrierProfileKeys.begin(),
                     kServedCarrierProfileKeys.end(),
                     [&entry](const char* key) {
                       return entry.first == key;
                     }) != kServedCarrierProfileKeys.end();
    if (!known) {
      *error = "The Winn Protocol section carries \"" + entry.first +
               "\", which is not a field of the engine's configuration; the "
               "engine rejects unknown fields.";
      return false;
    }
  }

  const auto endpoint_entry = section.find("endpoint");
  params.endpoint =
      endpoint_entry == section.end() ? "" : Trim(endpoint_entry->second);
  std::string host;
  std::string port;
  if (!SplitLinuxWinnEndpoint(params.endpoint, &host, &port)) {
    *error =
        "The Winn Protocol gateway endpoint is not an IP literal with a port. "
        "The engine will not resolve a hostname, because that lookup would "
        "leave the device outside the tunnel.";
    return false;
  }

  const auto session_entry = section.find("session_id");
  params.session_id =
      session_entry == section.end() ? "" : Trim(session_entry->second);
  if (params.session_id.size() > kMaxSessionIdBytes) {
    *error = "The Winn Protocol session identifier is too long.";
    return false;
  }

  const auto datagram_entry = section.find("max_datagram");
  if (datagram_entry != section.end() && !Trim(datagram_entry->second).empty()) {
    uint64_t value = 0;
    if (!ParseUnsigned(Trim(datagram_entry->second), kMaxDatagramCeiling,
                       &value) ||
        value < static_cast<uint64_t>(kMinDatagram)) {
      *error = "The Winn Protocol datagram size is outside the range the "
               "engine accepts.";
      return false;
    }
    params.max_datagram = static_cast<int>(value);
  } else {
    params.max_datagram = kMaxDatagramCeiling;
  }

  // WINN_MANDATORY_HEADERS 2026-08-08: h1..h4 are REQUIRED for winn/3.
  // A blind classifier (no h1..h4) makes transport_observed_both_ways never fire
  // and keeps the convergence gate WARNED AND PROMOTED — a dead tunnel reported as
  // connected, worse than no gate. Hub always serves all four, so mandatory
  // cannot fleet-lockout. Each h1..h4 may be a scalar (44) or a range
  // (16777216-1086324735); ParseHeaderSpec handles both and the non-overlap test
  // is interval intersection rather than equality — the engine's own mergeWithDevice
  // refuses an overlapping set, so accepting one here would hand the host a config
  // it cannot start. For scalars this degrades to equality. Each header is an
  // AwgHeaderSpec (start-end) where a bare value is the degenerate range
  // start==end, exactly as device/magic-header.go stores it. The parser mirrors
  // VpnConfigValidator.parseAwgHeaderSpec.
  static const std::array<const char*, 4> kHeaderKeys = {"h1", "h2", "h3", "h4"};
  static const std::array<const char*, 4> kPaddingKeys = {"s1", "s2", "s3", "s4"};
  int header_present = 0;
  // 0xFFFFFFFF ceiling parity
  for (size_t index = 0; index < kHeaderKeys.size(); ++index) {
    const auto entry = section.find(kHeaderKeys[index]);
    if (entry == section.end() || Trim(entry->second).empty()) continue;
    LinuxAwgHeaderSpec spec;
    if (!ParseHeaderSpec(entry->second, &spec)) {
      *error = "The Winn Protocol AmneziaWG header types must be 32-bit "
               "unsigned values or ranges.";
      return false;
    }
    params.h[index] = spec;
    ++header_present;
  }
  if (header_present != 4) {
    std::string missing;
    for (size_t i = 0; i < kHeaderKeys.size(); ++i) {
      const auto e = section.find(kHeaderKeys[i]);
      if (e == section.end() || Trim(e->second).empty()) {
        if (!missing.empty()) missing += ", ";
        missing += kHeaderKeys[i];
      }
    }
    *error = "The Winn Protocol AmneziaWG header types h1..h4 are REQUIRED for winn/3; missing " +
             (missing.empty() ? std::string("all four") : missing) +
             " — without them transport_observed_both_ways can never fire and the convergence gate cannot protect the tunnel.";
    return false;
  }
  for (int a = 0; a < 4; ++a) {
    for (int b = a + 1; b < 4; ++b) {
      if (params.h[a].overlaps(params.h[b])) {
        *error = "The Winn Protocol AmneziaWG header types must be pairwise "
                 "distinct.";
        return false;
      }
    }
  }
  for (size_t index = 0; index < kPaddingKeys.size(); ++index) {
    const auto entry = section.find(kPaddingKeys[index]);
    if (entry == section.end() || Trim(entry->second).empty()) continue;
    uint64_t value = 0;
    if (!ParseUnsigned(Trim(entry->second), 0xFFFFull, &value)) {
      *error = "The Winn Protocol AmneziaWG padding sizes must be 16-bit "
               "unsigned values.";
      return false;
    }
    if (header_present != 4 && value != 0) {
      *error = "The Winn Protocol AmneziaWG padding sizes require the header "
               "types they are offsets into.";
      return false;
    }
    params.s[index] = static_cast<uint16_t>(value);
  }

  // THE CARRIER PROFILE, built LAST and only for a carrier that has one.
  //
  // Ordering matters and matches WinnCarrierProfile.from: the credentials are
  // resolved after every scalar has been validated, so a malformed section
  // fails on the field that is actually wrong rather than on credentials that
  // are merely absent. A device with no credentials and a typo'd suite should
  // be told about the typo.
  if (params.carrier != kCarrierDirectAwg) {
    LinuxWinnCarrierProfile profile;
    profile.carrier = params.carrier;

    // The eight with no safe default. A missing `suite` or `manifest_digest`
    // cannot be guessed without weakening the session or silently claiming a
    // different deployment, so each is required rather than defaulted.
    struct RequiredField {
      const char* key;
      std::string* target;
    };
    const std::array<RequiredField, 8> required = {{
        {"masque_template", &profile.masque_template},
        {"public_target", &profile.public_target},
        {"server_name", &profile.server_name},
        {"suite", &profile.suite},
        {"controller_id", &profile.controller_id},
        {"device_id", &profile.device_id},
        {"device_pq_algorithm", &profile.device_pq_algorithm},
        {"manifest_digest", &profile.manifest_digest},
    }};
    for (const auto& field : required) {
      const auto entry = section.find(field.key);
      const std::string value =
          entry == section.end() ? std::string() : Trim(entry->second);
      if (value.empty()) {
        *error = std::string("The Winn Protocol carrier \"") + params.carrier +
                 "\" needs \"" + field.key +
                 "\", which this configuration does not carry; starting "
                 "without it would either weaken the session or silently claim "
                 "a different deployment, so the connection was stopped.";
        return false;
      }
      *field.target = value;
    }

    // masque_template must be an absolute https URL naming a host.
    if (!IsAbsoluteHttpsUrlWithHost(profile.masque_template)) {
      *error = "The Winn Protocol masque_template must be an absolute https "
               "URL naming a host.";
      return false;
    }

    // The proxy resolves public_target, not this device, so the DNS-leak rule
    // that governs the gateway endpoint does not apply. It is still required to
    // be an IP literal, because the AmneziaWG gateway is named by address
    // everywhere else in this client and a hostname here would be a second,
    // silent naming scheme. carrierhost enforces the same rule.
    {
      std::string host;
      std::string port;
      if (!SplitLinuxWinnEndpoint(profile.public_target, &host, &port)) {
        *error = "The Winn Protocol public_target must be an IP literal with a "
                 "port, not a hostname.";
        return false;
      }
    }

    if (profile.server_name.size() > 253 ||
        profile.server_name.find_first_of(" \t\r\n\"\\") != std::string::npos) {
      *error = "The Winn Protocol server_name is not a host name.";
      return false;
    }

    // LOAD-BEARING ALLOWLIST, not defensive duplication. carrierhost.normalize
    // checks only that `suite` is non-empty; tlsconfig.ParseSuite runs inside
    // BuildDialer, which the engine calls at CREATE time -- after this host has
    // already opened the outer socket. Refusing here keeps the failure before
    // that point.
    profile.suite = LowerAscii(profile.suite);
    static const std::array<const char*, 3> kSupportedSuites = {
        "x25519-mlkem768", "p256-mlkem768", "p384-mlkem1024"};
    if (std::find_if(kSupportedSuites.begin(), kSupportedSuites.end(),
                     [&profile](const char* suite) {
                       return profile.suite == suite;
                     }) == kSupportedSuites.end()) {
      *error = "The Winn Protocol suite \"" + profile.suite +
               "\" is not a hybrid post-quantum group this engine offers; "
               "refusing rather than letting the session negotiate a weaker "
               "one.";
      return false;
    }

    if (profile.controller_id.size() > 128) {
      *error = "The Winn Protocol controller_id is too long.";
      return false;
    }
    if (profile.device_id.size() > 128) {
      *error = "The Winn Protocol device_id is too long.";
      return false;
    }

    profile.device_pq_algorithm = LowerAscii(profile.device_pq_algorithm);
    if (profile.device_pq_algorithm != "mldsa65" &&
        profile.device_pq_algorithm != "mldsa87") {
      *error = "The Winn Protocol device_pq_algorithm must name the ML-DSA "
               "parameter set the device key was generated for.";
      return false;
    }

    profile.manifest_digest = LowerAscii(profile.manifest_digest);
    if (!IsLowerHex(profile.manifest_digest, 64)) {
      *error = "The Winn Protocol manifest_digest must be 64 lowercase "
               "hexadecimal characters; the carrier server compares it, so a "
               "wrong value would silently claim a different deployment.";
      return false;
    }

    // The three with a defined default in carrierhost, hence optional.
    const auto epoch_entry = section.find("sequence_epoch");
    if (epoch_entry != section.end() && !Trim(epoch_entry->second).empty()) {
      profile.sequence_epoch = LowerAscii(Trim(epoch_entry->second));
      if (!IsLowerHex(profile.sequence_epoch, 32)) {
        *error = "The Winn Protocol sequence_epoch must be 32 lowercase "
                 "hexadecimal characters.";
        return false;
      }
    }

    profile.max_inner_datagram = kMaxInnerDatagram;
    const auto inner_entry = section.find("max_inner_datagram");
    if (inner_entry != section.end() && !Trim(inner_entry->second).empty()) {
      uint64_t value = 0;
      if (!ParseUnsigned(Trim(inner_entry->second),
                         static_cast<uint64_t>(kMaxInnerDatagram), &value) ||
          static_cast<int>(value) < kMinInnerDatagram) {
        *error = "The Winn Protocol max_inner_datagram must be within [32, "
                 "1500].";
        return false;
      }
      profile.max_inner_datagram = static_cast<int>(value);
    }

    // Defaults to high-risk, matching Android: the safer of the two is the one
    // a configuration gets by saying nothing.
    profile.privacy_profile = kPrivacyHighRisk;
    const auto privacy_entry = section.find("privacy_profile");
    if (privacy_entry != section.end() &&
        !Trim(privacy_entry->second).empty()) {
      profile.privacy_profile = LowerAscii(Trim(privacy_entry->second));
      if (profile.privacy_profile != kPrivacyStandard &&
          profile.privacy_profile != kPrivacyHighRisk) {
        *error = "The Winn Protocol privacy_profile must be \"standard\" or "
                 "\"high-risk\".";
        return false;
      }
    }

    // SINGLE PACKET AUTHORIZATION.
    //
    // No http3-versus-http2 check is needed: SupportedCarriers already refuses
    // every carrier but http3-connect-udp above, which is strictly stronger
    // than the engine's own SPA rule (ErrSPAStreamCarrierUnsupported).
    {
      const auto mode_entry = section.find("spa_mode");
      const std::string spa_mode =
          mode_entry == section.end() ? std::string()
                                      : LowerAscii(Trim(mode_entry->second));
      // Every spa_ field except the mode itself.
      std::string stray;
      for (const char* key : kSpaCarrierProfileKeys) {
        if (std::string(key) == "spa_mode") continue;
        const auto entry = section.find(key);
        if (entry != section.end() && !Trim(entry->second).empty()) {
          if (stray.empty() || std::string(key) < stray) stray = key;
        }
      }

      if (spa_mode.empty() || spa_mode == kSpaModeOff) {
        // Refused, not ignored -- ErrSPAFieldWithoutMode. A target left behind
        // after SPA was turned off is the operator believing a defence is
        // armed that is not.
        if (!stray.empty()) {
          *error = "The Winn Protocol section sets \"" + stray +
                   "\" without spa_mode = " + kSpaModeRequired +
                   "; refusing rather than silently ignoring a configured "
                   "single-packet-authorization parameter.";
          return false;
        }
      } else if (spa_mode != kSpaModeRequired) {
        *error = "The Winn Protocol spa_mode must be \"" +
                 std::string(kSpaModeOff) + "\" or \"" +
                 std::string(kSpaModeRequired) + "\".";
        return false;
      } else {
        profile.spa_required = true;

        const auto target_entry = section.find("spa_target");
        profile.spa_target = target_entry == section.end()
                                 ? std::string()
                                 : Trim(target_entry->second);
        // No default, deliberately: the gate may sit in front of the carrier
        // listener or in front of the AmneziaWG gateway, and a wrong guess
        // sends the deployment's shared credential to a host that is not
        // supposed to have it.
        {
          std::string spa_host;
          std::string spa_port;
          if (!SplitLinuxWinnEndpoint(profile.spa_target, &spa_host,
                                      &spa_port)) {
            *error = "The Winn Protocol spa_target is required when spa_mode "
                     "is " + std::string(kSpaModeRequired) +
                     ", and must be an IP literal with a port, not a hostname.";
            return false;
          }
        }

        struct SpaScalar {
          const char* key;
          int* target;
          uint64_t ceiling;
        };
        const std::array<SpaScalar, 3> spa_scalars = {{
            {"spa_packet_size", &profile.spa_packet_size, kSpaMaxPacketSize},
            {"spa_bucket_window_seconds", &profile.spa_bucket_window_seconds,
             kSpaMaxSeconds},
            {"spa_max_skew_seconds", &profile.spa_max_skew_seconds,
             kSpaMaxSeconds},
        }};
        for (const auto& scalar : spa_scalars) {
          const auto entry = section.find(scalar.key);
          if (entry == section.end() || Trim(entry->second).empty()) continue;
          uint64_t value = 0;
          if (!ParseUnsigned(Trim(entry->second), scalar.ceiling, &value)) {
            *error = std::string("The Winn Protocol ") + scalar.key +
                     " is not a whole number this engine can use.";
            return false;
          }
          *scalar.target = static_cast<int>(value);
        }
        // A knock is ONE unfragmented datagram: a censor that already drops or
        // flags fragmented UDP would turn it into a worse fingerprint than
        // having no SPA at all. 0 means "let the engine derive it".
        if (profile.spa_packet_size != 0 &&
            profile.spa_packet_size < kSpaMinPacketSize) {
          *error = "The Winn Protocol spa_packet_size must be within [48, "
                   "1500].";
          return false;
        }
        // knock.Options.resolve: a bucket is at least a second and the skew is
        // at least a bucket. A pair that violates this produces a knock that
        // silently never verifies, which looks identical to a wrong key.
        if (profile.spa_bucket_window_seconds != 0 &&
            profile.spa_max_skew_seconds != 0 &&
            profile.spa_max_skew_seconds < profile.spa_bucket_window_seconds) {
          *error = "The Winn Protocol spa_max_skew_seconds must be at least "
                   "spa_bucket_window_seconds.";
          return false;
        }
      }
    }

    // carrierhost.normalize hard-requires this: ValidSessionID(profile.SessionID)
    // refuses anything that is not 32 lowercase hex, so a profile without it
    // fails to parse every time. It is generated, never copied from the config.
    if (!NewCarrierSessionId(&profile.session_id)) {
      *error = "Could not generate a Winn carrier session identifier from "
               "/dev/urandom; refusing rather than starting a carrier session "
               "with a predictable identifier.";
      return false;
    }

    if (!ResolveLinuxWinnCarrierCredentials(&profile, error)) {
      return false;
    }

    params.carrier_profile = profile;
    params.has_carrier_profile = true;
  }

  *out = params;
  return true;
}

bool RewriteAwgPeerEndpointToSeam(const std::string& awg_config,
                                  uint16_t seam_port,
                                  uint16_t awg_listen_port,
                                  std::string* out) {
  if (out == nullptr || awg_listen_port == 0) return false;
  std::istringstream stream(awg_config);
  std::ostringstream rewritten;
  std::string line;
  int replaced = 0;
  int interfaces = 0;
  while (std::getline(stream, line)) {
    const std::string trimmed = Trim(line);
    const size_t equals = trimmed.find('=');
    const std::string key =
        equals == std::string::npos ? "" : LowerAscii(Trim(trimmed.substr(0, equals)));
    if (key == "endpoint") {
      ++replaced;
      rewritten << "Endpoint = 127.0.0.1:" << seam_port << '\n';
    } else if (key == "listenport") {
      // The reserved port written under [Interface] is the only one the seam
      // admits, so no other ListenPort may survive.
      continue;
    } else {
      rewritten << line << '\n';
      if (equals == std::string::npos && trimmed.size() >= 2 &&
          trimmed.front() == '[' && trimmed.back() == ']' &&
          LowerAscii(Trim(trimmed.substr(1, trimmed.size() - 2))) ==
              "interface") {
        ++interfaces;
        rewritten << "ListenPort = " << awg_listen_port << '\n';
      }
    }
  }
  // EXACTLY one. Zero would leave AmneziaWG with nowhere to send and two would
  // mean one of them still points at the real gateway, so its outer datagrams
  // would leave this host unprotected while we believed they were carried.
  // Exactly one [Interface], so the pinned ListenPort is the one AmneziaWG
  // binds.
  if (replaced != 1 || interfaces != 1) return false;
  *out = rewritten.str();
  return true;
}

bool ResolveLinuxWinnCarrierCredentials(LinuxWinnCarrierProfile* profile,
                                        std::string* error) {
  if (profile == nullptr || error == nullptr) return false;
  const std::string directory = PrivateWinnStateDirectory();
  if (directory.empty()) {
    *error = "Win's VPN has no private per-user directory (HOME and "
             "XDG_DATA_HOME are both unset or relative), so the Winn carrier "
             "credentials cannot be located; refusing rather than falling back "
             "to a shared location such as /tmp.";
    return false;
  }

  // Ordered, and the order maps positionally onto the six path fields below.
  // Each entry is (file name, what it is) so a refusal can say what is missing
  // rather than only that something is.
  struct CredentialFile {
    const char* name;
    const char* purpose;
    std::string* target;
  };
  const std::array<CredentialFile, 6> files = {{
      {"controller_pins.json",
       "the pinned controller ML-DSA verifier set, the profile's trust anchor",
       &profile->controller_pins_path},
      {"winn_root_ca.pem",
       "the Winn CA the carrier certificate must chain to; the system trust "
       "store is not it",
       &profile->root_ca_path},
      {"ech_config_list.bin",
       "the Encrypted Client Hello config list, without which the TLS profile "
       "is a single-probe fingerprint",
       &profile->ech_config_list_path},
      {"device_mldsa_seed.bin", "the device's ML-DSA private seed",
       &profile->device_seed_path},
      {"client_cert.pem", "the mTLS client certificate identity mode requires",
       &profile->client_cert_path},
      {"client_key.pem", "the mTLS client private key",
       &profile->client_key_path},
  }};

  for (const auto& file : files) {
    const std::string path = directory + "/" + file.name;
    // stat, NOT open. The point of naming secrets by path is that this process
    // never holds them; opening one here to "check it" would defeat exactly
    // that. The engine opens them.
    struct stat info = {};
    if (stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
      *error = std::string("The Winn carrier credential \"") + file.name +
               "\" (" + file.purpose +
               ") is not provisioned on this machine. None of these is "
               "generated by this app; until they are provisioned a winn/3 "
               "session cannot use an authenticated carrier, and starting an "
               "unauthenticated one instead would downgrade the session the "
               "server negotiated. Expected at: " + path;
      return false;
    }
    if (access(path.c_str(), R_OK) != 0) {
      *error = std::string("The Winn carrier credential \"") + file.name +
               "\" is present but unreadable at: " + path;
      return false;
    }
    *file.target = path;
  }

  // THE KNOCK KEY, resolved only when this session actually knocks.
  //
  // Deliberately not one of the six above: those are needed by every carrier
  // session, this one only by a session whose served config turned SPA on.
  // Requiring it unconditionally would break every existing carrier profile on
  // a machine with no knock key, which is every machine today.
  //
  // IT FAILS CLOSED, and that is the point. carrierhost accepts any non-empty
  // spa_key_path at PARSE time; the file is not opened until BuildDialer, at
  // create time, long after the outer socket exists. So a machine with no key
  // would build a valid-looking profile, start a tunnel, and fail somewhere the
  // user experiences only as "it doesn't connect". Checking here makes that a
  // named refusal before anything is allocated.
  if (profile->spa_required) {
    const std::string path =
        directory + "/" + std::string(kSpaKeyCredentialFileName);
    struct stat info = {};
    if (stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
      *error = std::string("This server asked for single packet "
                           "authorization, but the knock key \"") +
               kSpaKeyCredentialFileName +
               "\" is not provisioned on this machine. The key is a "
               "deployment-scoped shared secret the operator distributes out "
               "of band; nothing in this app generates one. Without it the "
               "engine would send a knock no gate can verify and the "
               "connection would fail with nothing reporting why, so it is "
               "refused here instead. Expected at: " + path;
      return false;
    }
    if (access(path.c_str(), R_OK) != 0) {
      *error = std::string("The Winn knock key is present but unreadable at: ") +
               path;
      return false;
    }
    profile->spa_key_path = path;
  }
  return true;
}

std::string BuildLinuxWinnCarrierProfileJson(
    const LinuxWinnCarrierProfile& profile) {
  // Key order matches WinnCarrierProfile.toJson() so the two platforms'
  // documents can be compared byte for byte in review.
  std::ostringstream json;
  json << "{\"profile\":\"" << kCarrierProfileVersion << "\""
       << ",\"carrier\":\"" << JsonEscape(profile.carrier) << "\"";
  // masque_template is HTTP/3 only, and h2_url set on an HTTP/3 profile is
  // ErrCarrierFieldMismatch, so the field belonging to the other carrier is
  // never emitted rather than emitted empty.
  if (profile.carrier == kCarrierHttp3) {
    json << ",\"masque_template\":\"" << JsonEscape(profile.masque_template)
         << "\"";
  }
  json << ",\"public_target\":\"" << JsonEscape(profile.public_target) << "\""
       << ",\"server_name\":\"" << JsonEscape(profile.server_name) << "\""
       << ",\"suite\":\"" << JsonEscape(profile.suite) << "\""
       << ",\"controller_id\":\"" << JsonEscape(profile.controller_id) << "\""
       << ",\"controller_pins_path\":\""
       << JsonEscape(profile.controller_pins_path) << "\""
       << ",\"root_ca_path\":\"" << JsonEscape(profile.root_ca_path) << "\""
       << ",\"ech_config_list_path\":\""
       << JsonEscape(profile.ech_config_list_path) << "\""
       << ",\"authorization_mode\":\"" << kAuthModeIdentity << "\""
       << ",\"device_id\":\"" << JsonEscape(profile.device_id) << "\""
       << ",\"device_pq_algorithm\":\""
       << JsonEscape(profile.device_pq_algorithm) << "\""
       << ",\"device_seed_path\":\"" << JsonEscape(profile.device_seed_path)
       << "\""
       << ",\"client_cert_path\":\"" << JsonEscape(profile.client_cert_path)
       << "\""
       << ",\"client_key_path\":\"" << JsonEscape(profile.client_key_path)
       << "\"";
  json << ",\"session_id\":\"" << JsonEscape(profile.session_id) << "\"";
  if (!profile.sequence_epoch.empty()) {
    json << ",\"sequence_epoch\":\"" << JsonEscape(profile.sequence_epoch)
         << "\"";
  }
  json << ",\"manifest_digest\":\"" << JsonEscape(profile.manifest_digest)
       << "\""
       << ",\"max_inner_datagram\":" << profile.max_inner_datagram
       << ",\"privacy_profile\":\"" << JsonEscape(profile.privacy_profile)
       << "\"";
  // SINGLE PACKET AUTHORIZATION. Emitted only when it is actually on.
  //
  // Be exact about why. carrierhost.normalizeSPA REFUSES a document carrying a
  // NON-EMPTY spa_ field while the mode is off (ErrSPAFieldWithoutMode). It
  // does NOT refuse an empty one: the stray sweep tests TrimSpace(...) != ""
  // for strings and != 0 for the scalars, so "spa_mode":"off" and
  // "spa_target":"" parse fine and are indistinguishable from absent. An
  // earlier version of this comment claimed they were a hard parse failure;
  // that was checked against ParseProfile and is false. Omitting is still the
  // rule, because a document with no spa_ substring cannot be misread, and
  // because the failure that IS real is one-sided: a non-empty stray refuses
  // the whole profile, and an emitter that never writes these keys unless SPA
  // is on can never produce one.
  //
  // Field order matches carrierhost.Profile's own declaration order, and
  // WinnCarrierProfile.toJson() on Android.
  if (profile.spa_required) {
    json << ",\"spa_mode\":\"" << kSpaModeRequired << "\""
         // A PATH, never the key. This host resolves it and never opens it:
         // knock.LoadKeysFromFile, the loader that owns the format, reads it
         // inside the engine's BuildDialer.
         << ",\"spa_key_path\":\"" << JsonEscape(profile.spa_key_path) << "\""
         << ",\"spa_target\":\"" << JsonEscape(profile.spa_target) << "\"";
    // 0 means "use the engine's derived or default value", and the engine does
    // exactly that, so omitting is identical to sending 0.
    if (profile.spa_packet_size != 0) {
      json << ",\"spa_packet_size\":" << profile.spa_packet_size;
    }
    if (profile.spa_bucket_window_seconds != 0) {
      json << ",\"spa_bucket_window_seconds\":"
           << profile.spa_bucket_window_seconds;
    }
    if (profile.spa_max_skew_seconds != 0) {
      json << ",\"spa_max_skew_seconds\":" << profile.spa_max_skew_seconds;
    }
  }
  // `manifest_path` is NEVER emitted. Naming a manifest makes carrierhost
  // refuse the profile, because it does not run LoadVerifiedNodeV2 and will not
  // read its own transport fields while claiming a manifest was checked.
  json << "}";
  return json.str();
}

std::string DescribeLinuxWinnCarrierProfile(
    const LinuxWinnCarrierProfile& profile) {
  std::ostringstream out;
  out << "winn carrier profile: version=" << kCarrierProfileVersion
      << " carrier=" << profile.carrier << " suite=" << profile.suite
      << " mode=" << kAuthModeIdentity
      << " privacy=" << profile.privacy_profile
      << " pq_algorithm=" << profile.device_pq_algorithm
      << " max_inner_datagram=" << profile.max_inner_datagram
      << " manifest_verified=false"
      // The MODE only. Never the key path, never the target: the path names a
      // credential file and the target names a host that is supposed to be
      // invisible, and the whole point of SPA is that neither is discoverable
      // from this machine's logs. Matches carrierhost.Profile.DescribeForLog.
      << " spa=" << (profile.spa_required ? kSpaModeRequired : kSpaModeOff);
  return out.str();
}

bool WriteLinuxWinnCarrierProfile(const LinuxWinnCarrierProfile& profile,
                                  std::string* path,
                                  std::string* error) {
  if (path == nullptr || error == nullptr) return false;
  const std::string directory = PrivateWinnStateDirectory();
  if (directory.empty()) {
    *error = "Win's VPN has no private per-user directory in which to write "
             "the Winn carrier profile; refusing rather than falling back to a "
             "shared location such as /tmp.";
    return false;
  }

  const std::string target = directory + "/" + kCarrierProfileFileName;
  const std::string document = BuildLinuxWinnCarrierProfileJson(profile);

  // O_CREAT|O_EXCL onto a fresh temp name, mode 0600 from the moment the inode
  // exists, then rename over the target. The mode is set BEFORE any bytes are
  // written, so the document naming every credential path on this machine is
  // never briefly world-readable. O_NOFOLLOW refuses a symlink planted at the
  // name; O_CLOEXEC keeps it out of the engine we are about to exec.
  const std::string temp = target + ".tmp";
  ::unlink(temp.c_str());
  const int fd = ::open(temp.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
  if (fd < 0) {
    *error = "Could not create the Winn carrier profile at " + temp + ": " +
             std::strerror(errno);
    return false;
  }
  size_t written = 0;
  bool ok = true;
  while (written < document.size()) {
    const ssize_t count =
        ::write(fd, document.data() + written, document.size() - written);
    if (count < 0) {
      if (errno == EINTR) continue;
      ok = false;
      break;
    }
    written += static_cast<size_t>(count);
  }
  if (ok && ::fsync(fd) != 0) ok = false;
  ::close(fd);
  if (!ok) {
    ::unlink(temp.c_str());
    *error = "Could not write the Winn carrier profile.";
    return false;
  }
  if (::rename(temp.c_str(), target.c_str()) != 0) {
    ::unlink(temp.c_str());
    *error = "Could not install the Winn carrier profile at " + target + ": " +
             std::strerror(errno);
    return false;
  }
  *path = target;
  return true;
}

std::string BuildLinuxWinnConfigJson(const LinuxWinnParams& params) {
  // Key order matches WinnEngineConfig.toConfigJson() so the two platforms'
  // Create payloads can be compared byte for byte in review.
  std::ostringstream json;
  json << "{\"contract\":\"" << kContractVersion << "\""
       << ",\"payload\":\"" << kPayloadAwgDatagram << "\""
       // The RESOLVED carrier, not a constant. datapath.openWithCarrier looks
       // the dialer up by `suppliedSocketCarriers[config.Carrier]`, so a Create
       // that said direct-awg while a carrier profile was on argv would be
       // refused by the engine -- and worse, a Create that said direct-awg and
       // was ACCEPTED would carry the session over the wrong transport. Android
       // emits the resolved carrier here for the same reason.
       << ",\"carrier\":\"" << JsonEscape(params.carrier) << "\""
       << ",\"gateway_endpoint\":\"" << JsonEscape(params.endpoint) << "\""
       << ",\"max_datagram\":" << params.max_datagram;
  if (!params.session_id.empty()) {
    json << ",\"session_id\":\"" << JsonEscape(params.session_id) << "\"";
  }
  // TRUE only here, and only honestly: datapath/carrier.go permits an engine to
  // open its own socket when transportFD < 0 exactly because the desktop model
  // excludes that socket by route/mark instead of by descriptor. The caller has
  // installed awg-quick's fwmark on the gateway destination before this runs.
   json << ",\"allow_own_socket\":true";
   const bool has_headers = params.h[0].start != 0 || params.h[1].start != 0 ||
                            params.h[2].start != 0 || params.h[3].start != 0;
   if (has_headers) {
     json << ",\"awg_header_types\":{";
     for (int i = 0; i < 4; ++i) {
       if (i > 0) json << ",";
       json << "\"h" << (i + 1) << "\":";
       if (params.h[i].isRange()) {
         json << "\"" << params.h[i].spec() << "\"";
       } else {
         json << params.h[i].start;
       }
     }
     json << ",\"s1\":" << params.s[0] << ",\"s2\":" << params.s[1]
          << ",\"s3\":" << params.s[2] << ",\"s4\":" << params.s[3] << "}";
   }
   json << "}";
   return json.str();
}

int BindLinuxWinnSeam(uint16_t* port, std::string* error) {
  if (port == nullptr || error == nullptr) return -1;
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    *error = "The Winn loopback seam socket could not be created.";
    return -1;
  }
  if (!SetCloseOnExec(fd)) {
    close(fd);
    *error = "The Winn loopback seam socket could not be made close-on-exec.";
    return -1;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1, never wildcard
  address.sin_port = 0;
  if (bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) !=
      0) {
    close(fd);
    *error = "The Winn loopback seam socket could not be bound to 127.0.0.1.";
    return -1;
  }
  // STATE THE BUFFER INSTEAD OF INHERITING IT. This is a shock absorber for the
  // gap between a burst arriving and the drainer being scheduled -- it is NOT
  // the fix, because a bigger buffer only moves the cliff. It is set explicitly
  // so that the granted size can be REPORTED next to the backlog high-water
  // mark, which is what lets anyone see whether the buffer is even the
  // mechanism. The failure is deliberately not fatal: an inherited default is
  // worse than this, but it still works.
  const int requested = kSeamRcvbufBytes;
#ifdef SO_RCVBUFFORCE
  // SO_RCVBUF is silently CLAMPED to net.core.rmem_max, which is 208 KiB on a
  // stock kernel -- about 190 outer AWG datagrams, so a request for 2 MiB
  // usually grants a tenth of it. SO_RCVBUFFORCE ignores that ceiling but needs
  // CAP_NET_ADMIN, which this process normally does not have. Tried first and
  // allowed to fail; the granted value is read back either way and REPORTED, so
  // nobody has to guess which of the two took effect.
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &requested,
                 sizeof(requested)) != 0) {
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested));
  }
#else
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested));
#endif

  sockaddr_in bound{};
  socklen_t bound_size = sizeof(bound);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_size) != 0 ||
      bound.sin_port == 0) {
    close(fd);
    *error = "The Winn loopback seam socket did not report a port.";
    return -1;
  }
  *port = ntohs(bound.sin_port);
  return fd;
}

namespace {

// AmneziaWG binds its ListenPort when awg-quick brings the interface up, and
// the userspace engine does that on its own TUN event, so the bind can land a
// moment after the privileged start returns. A port that is not held by then
// refuses the start: AmneziaWG has failed to bind it, and nothing it sends
// could reach the seam from that port.
constexpr int kAwgListenPortConfirmDeadlineMs = 2000;
constexpr int kAwgListenPortConfirmTickMs = 25;

// What the kernel's UDP tables say about one local port. Accumulates across
// /proc/net/udp and /proc/net/udp6.
struct UdpPortHolders {
  bool root_wildcard = false;  // 0.0.0.0:<port>, uid 0
  bool other_user = false;     // any socket on <port> whose uid is not 0
};

// Parses /proc/net/udp or /proc/net/udp6. Each socket line is "sl: local rem
// st tx:rx tr:when retrnsmt uid ...", local being <8 or 32 hex address>:<4
// hex port>. Returns false when the header or a socket line does not have
// that shape, so a format change refuses the start instead of passing it.
bool ParseProcNetUdpHolders(const std::string& table,
                            uint16_t port,
                            UdpPortHolders* holders) {
  if (holders == nullptr) return false;
  std::istringstream lines(table);
  std::string line;
  if (!std::getline(lines, line) ||
      line.find("local_address") == std::string::npos) {
    return false;
  }
  while (std::getline(lines, line)) {
    if (Trim(line).empty()) continue;
    std::istringstream fields(line);
    std::string slot, local, remote, state, queues, timer, retransmits, uid;
    if (!(fields >> slot >> local >> remote >> state >> queues >> timer >>
          retransmits >> uid)) {
      return false;
    }
    const size_t colon = local.find(':');
    if ((colon != 8 && colon != 32) || local.size() != colon + 5 ||
        local.rfind(':') != colon ||
        local.find_first_not_of("0123456789ABCDEFabcdef:") !=
            std::string::npos ||
        uid.empty() ||
        uid.find_first_not_of("0123456789") != std::string::npos) {
      return false;
    }
    if (std::strtoul(local.substr(colon + 1).c_str(), nullptr, 16) != port) {
      continue;
    }
    if (uid != "0") {
      holders->other_user = true;
    } else if (colon == 8 && local.compare(0, 8, "00000000") == 0) {
      holders->root_wildcard = true;
    }
  }
  return true;
}

// Reads one /proc/net UDP table into *holders. A missing udp6 table (IPv6
// disabled) is not an error; a missing udp table, or either table in a shape
// the parser does not know, is.
bool ReadProcNetUdpHolders(const char* path,
                           bool required,
                           uint16_t port,
                           UdpPortHolders* holders) {
  std::ifstream file(path);
  if (!file.is_open()) return !required;
  std::ostringstream table;
  return static_cast<bool>(table << file.rdbuf()) &&
         ParseProcNetUdpHolders(table.str(), port, holders);
}

// Waits, up to kAwgListenPortConfirmDeadlineMs, for the reserved ListenPort to
// be held by a root-owned IPv4 wildcard socket and by no socket of any other
// user, IPv4 or IPv6. AmneziaWG runs as root, binds that wildcard without
// SO_REUSEADDR or SO_REUSEPORT, and fails rather than falls back when the port
// is taken (amneziawg-go v3.1.20260814: uapi.go:329-330, device.go:544-546,
// conn/controlfns_linux.go). So once this holds, a datagram from 127.0.0.1 on
// that port comes from a root-owned socket. /proc/net/udp is world-readable,
// so the unprivileged host can read it although it cannot read AmneziaWG's
// root-only UAPI.
bool ConfirmAwgListenPortHeldByRoot(uint16_t port, std::string* error) {
  for (int waited = 0;; waited += kAwgListenPortConfirmTickMs) {
    UdpPortHolders holders;
    const bool read =
        ReadProcNetUdpHolders("/proc/net/udp", true, port, &holders) &&
        ReadProcNetUdpHolders("/proc/net/udp6", false, port, &holders);
    if (read && !holders.other_user && holders.root_wildcard) return true;
    if (!read || holders.other_user ||
        waited >= kAwgListenPortConfirmDeadlineMs) {
      break;
    }
    usleep(kAwgListenPortConfirmTickMs * 1000);
  }
  *error = "Refusing to start Winn Protocol v3: the AmneziaWG engine's "
           "reserved source port is not held by AmneziaWG alone, so the Winn "
           "seam could not tell it from another local sender.";
  return false;
}

}  // namespace

bool ReserveLinuxAwgListenPort(uint16_t* port, std::string* error) {
  if (port == nullptr || error == nullptr) return false;
  *port = 0;
  for (int attempt = 0; attempt < 16; ++attempt) {
    const int v4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (v4 < 0) break;
    if (!SetCloseOnExec(v4)) {
      close(v4);
      break;
    }
    sockaddr_in any4{};
    any4.sin_family = AF_INET;
    any4.sin_addr.s_addr = htonl(INADDR_ANY);
    any4.sin_port = 0;
    sockaddr_in bound4{};
    socklen_t bound4_size = sizeof(bound4);
    if (bind(v4, reinterpret_cast<const sockaddr*>(&any4), sizeof(any4)) != 0 ||
        getsockname(v4, reinterpret_cast<sockaddr*>(&bound4), &bound4_size) !=
            0 ||
        bound4.sin_port == 0) {
      close(v4);
      break;
    }
    // AmneziaWG also binds the IPv6 wildcard on the same port. A host without
    // IPv6 cannot create the socket, and AmneziaWG skips that family there.
    bool free_on_v6 = true;
    const int v6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (v6 >= 0) {
      (void)SetCloseOnExec(v6);
      const int v6_only = 1;
      (void)setsockopt(v6, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only,
                       sizeof(v6_only));
      sockaddr_in6 any6{};
      any6.sin6_family = AF_INET6;
      any6.sin6_addr = in6addr_any;
      any6.sin6_port = bound4.sin_port;
      if (bind(v6, reinterpret_cast<const sockaddr*>(&any6), sizeof(any6)) !=
              0 &&
          errno == EADDRINUSE) {
        free_on_v6 = false;
      }
      close(v6);
    }
    close(v4);
    if (free_on_v6) {
      *port = ntohs(bound4.sin_port);
      return true;
    }
  }
  *error = "Refusing to start Winn Protocol v3: no local UDP port could be "
           "reserved for the AmneziaWG engine, so the Winn seam could not "
           "tell it from another local sender.";
  return false;
}

bool StartLinuxWinnEngine(const std::string& engine_path,
                          int seam_fd,
                          const LinuxWinnParams& params,
                          std::string* error) {
  if (error == nullptr) {
    if (seam_fd >= 0) close(seam_fd);
    return false;
  }
  std::lock_guard<std::mutex> guard(g_mutex);
  // The seam descriptor is adopted here on EVERY outcome, not only on success.
  // The caller has one thing to remember rather than two, and the failure paths
  // below are exactly the ones a leak would hide in.
  if (g_engine != nullptr) {
    *error = "A Winn Protocol engine is already running.";
    if (seam_fd >= 0) close(seam_fd);
    return false;
  }
  if (seam_fd < 0) {
    *error = "The Winn loopback seam is not open.";
    return false;
  }
  if (params.awg_listen_port == 0) {
    *error = "Refusing to start Winn Protocol v3: the AmneziaWG engine's own "
             "source port was not reserved, so the Winn seam could not tell "
             "it from another local sender.";
    close(seam_fd);
    return false;
  }
  // Before the pin is set and before either pump starts, so a process that
  // took the reserved port first is never admitted. AmneziaWG's datagrams
  // queue in the seam's receive buffer meanwhile and are drained afterwards.
  if (!ConfirmAwgListenPortHeldByRoot(params.awg_listen_port, error)) {
    close(seam_fd);
    return false;
  }

  // The carrier profile is written HERE, before the fork, deliberately.
  //
  // Everything between fork() and execv() in the child must be
  // async-signal-safe, which writing a file and building strings is not. The
  // child only reads the c_str() of a string the parent already owns.
  //
  // Fail-closed: a carrier session whose profile cannot be written does not
  // fall back to direct-awg. It stops, with the seam adopted and released like
  // every other failure path above.
  std::string carrier_profile_path;
  if (params.has_carrier_profile) {
    std::string write_error;
    if (!WriteLinuxWinnCarrierProfile(params.carrier_profile,
                                      &carrier_profile_path, &write_error)) {
      *error = write_error;
      close(seam_fd);
      return false;
    }
  }

  int to_engine[2] = {-1, -1};
  int from_engine[2] = {-1, -1};
  int wake[2] = {-1, -1};
  // B-05: atomic close-on-exec pipes -- no fork+exec race window.
  bool pipes_ok = PipeCloexec(to_engine) && PipeCloexec(from_engine) &&
                  PipeCloexec(wake);
  if (!pipes_ok) {
    for (int* pair : {to_engine, from_engine, wake}) {
      if (pair[0] >= 0) close(pair[0]);
      if (pair[1] >= 0) close(pair[1]);
    }
    close(seam_fd);
    *error = "The Winn engine channel could not be created.";
    return false;
  }

#ifdef F_SETPIPE_SZ
  // The writer's actual sink. A pipe defaults to 64 KiB, which is ~46 outer AWG
  // datagrams -- so the engine falling a few milliseconds behind used to stall
  // the writer almost immediately. Enlarging it is the same "state the buffer
  // instead of inheriting it" move as SO_RCVBUF on the seam, and it is NOT the
  // fix either: it widens the window the split thread already made survivable.
  // Best-effort, because the ceiling is /proc/sys/fs/pipe-max-size and a
  // refusal here is not a reason to fail a tunnel.
  (void)fcntl(to_engine[1], F_SETPIPE_SZ, 1024 * 1024);
#endif

  const pid_t pid = fork();
  if (pid < 0) {
    for (int* pair : {to_engine, from_engine, wake}) {
      close(pair[0]);
      close(pair[1]);
    }
    close(seam_fd);
    *error = "The Winn Protocol engine could not be started.";
    return false;
  }
  if (pid == 0) {
    // Child. stdin/stdout carry frames; stderr is left attached so engine
    // diagnostics land in the app's own log rather than being swallowed.
    dup2(to_engine[0], STDIN_FILENO);
    dup2(from_engine[1], STDOUT_FILENO);
    close(to_engine[0]);
    close(to_engine[1]);
    close(from_engine[0]);
    close(from_engine[1]);
    close(wake[0]);
    close(wake[1]);
    close(seam_fd);
    // No positional arguments: cmd/winn-datapath treats a stray one as fatal.
    //
    // `-carrier-profile PATH` is appended only for a carrier that has a
    // profile. Without the flag the binary calls datapath.Open and builds
    // direct-awg exactly as before, so the direct-awg argv is byte-identical to
    // what shipped -- the widening is additive on the wire too, not only in the
    // gate. The path string is owned by the parent and was built before fork.
    const char* argv[] = {engine_path.c_str(),
                          "-transport",
                          "stdio",
                          carrier_profile_path.empty()
                              ? nullptr
                              : "-carrier-profile",
                          carrier_profile_path.empty()
                              ? nullptr
                              : carrier_profile_path.c_str(),
                          nullptr};
    execv(engine_path.c_str(), const_cast<char* const*>(argv));
    _exit(127);
  }

  close(to_engine[0]);
  close(from_engine[1]);

  EngineState* state = new EngineState();
  state->pid = pid;
  state->stdin_fd = to_engine[1];
  state->stdout_fd = from_engine[0];
  state->seam_fd = seam_fd;
  state->wake_fd[0] = wake[0];
  state->wake_fd[1] = wake[1];
  // THE PIN, FROM THIS HOST'S OWN INPUT, before either pump starts. AmneziaWG
  // was configured with ListenPort = params.awg_listen_port, and
  // ConfirmAwgListenPortHeldByRoot found that port held by a root-owned socket
  // alone, so this is the only loopback socket the seam accepts datagrams from
  // and the only one it sends to. A datagram that reached the seam first, from
  // any local process, is refused rather than adopted.
  state->awg_peer.sin_family = AF_INET;
  state->awg_peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  state->awg_peer.sin_port = htons(params.awg_listen_port);
  state->awg_peer_known = true;
  // Latched from the SAME `params` that BuildLinuxWinnConfigJson turns into the
  // Create document four lines below, so the boolean the gate reads and the
  // `awg_header_types` the engine received cannot disagree. Deriving it from
  // the engine's reply instead is the defect this replaces.
  state->headers_classify = LinuxWinnHeadersClassify(params);

  state->outbound = std::thread(OutboundPump, state);

  const std::string config_json = BuildLinuxWinnConfigJson(params);
  if (!WriteFrameLocked(state, Opcode::kCreate,
                        reinterpret_cast<const uint8_t*>(config_json.data()),
                        config_json.size())) {
    *error = "The Winn Protocol engine did not accept its configuration.";
    TeardownLocked(state);
    delete state;
    return false;
  }

  // Wait for CreateAck (or the Error that replaces it).
  {
    std::unique_lock<std::mutex> status_guard(state->status_mutex);
    const bool acked = state->status_signal.wait_for(
        status_guard, std::chrono::milliseconds(kCreateAckTimeoutMs),
        [state] {
          return !state->last_status.empty() || !state->failure.empty();
        });
    if (!acked || !state->failure.empty()) {
      std::string reason = state->failure.empty()
                               ? "the Winn Protocol engine did not acknowledge "
                                 "its configuration in time"
                               : state->failure;
      status_guard.unlock();
      *error = "Winn Protocol could not start: " + reason + ".";
      TeardownLocked(state);
      delete state;
      return false;
    }
  }

  state->channel_up.store(true);

  // The ring sits between the two, sized from the negotiated datagram ceiling
  // so a slot always holds a whole datagram. Started BEFORE the drainer so the
  // very first burst has a consumer.
  const int slot_bytes =
      params.max_datagram > 0 ? params.max_datagram : kMaxDatagramCeiling;
  state->ring.Init(static_cast<size_t>(slot_bytes));
  {
    int granted = 0;
    socklen_t granted_size = sizeof(granted);
    if (getsockopt(state->seam_fd, SOL_SOCKET, SO_RCVBUF, &granted,
                   &granted_size) == 0) {
      state->counters.rcvbuf_bytes.store(
          static_cast<unsigned long long>(granted));
    }
  }
  state->writer = std::thread(SeamWriterPump, state);
  state->inbound = std::thread(InboundPump, state, params.max_datagram);
  g_engine = state;
  return true;
}

void StopLinuxWinnEngine() {
  EngineState* state = nullptr;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    state = g_engine;
    g_engine = nullptr;
    if (state == nullptr) return;
    TeardownLocked(state);
  }
  delete state;
}

bool LinuxWinnEngineRunning() {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_engine == nullptr) return false;
  // Deliberately not "the process exists". A live process with a torn-down
  // channel carries nothing, and reporting that as a working tunnel is exactly
  // the failure this project has already been bitten by.
  if (!g_engine->channel_up.load()) return false;
  if (g_engine->pid <= 0) return false;
  int status = 0;
  return waitpid(g_engine->pid, &status, WNOHANG) == 0;
}

std::string LinuxWinnEngineStatusJson() {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_engine == nullptr || !g_engine->channel_up.load()) return "";
  EngineState* state = g_engine;
  int64_t before = 0;
  {
    std::lock_guard<std::mutex> status_guard(state->status_mutex);
    before = state->last_status_at;
  }
  if (!WriteFrameLocked(state, Opcode::kStatusRequest, nullptr, 0)) return "";
  std::unique_lock<std::mutex> status_guard(state->status_mutex);
  state->status_signal.wait_for(
      status_guard, std::chrono::milliseconds(kStatusTimeoutMs),
      [state, before] {
        return state->last_status_at != before || !state->failure.empty();
      });
  return state->last_status;
}

bool LinuxWinnEngineHeadersClassify() {
  std::lock_guard<std::mutex> guard(g_mutex);
  return g_engine != nullptr && g_engine->headers_classify;
}

WinnTransportGate LinuxWinnTransportGate(std::string* status_json,
                                         std::string* reason) {
  // WINN_FAIL_OPEN_CLOSED 2026-08-09, mirroring WindowsWinnTransportGate.
  //
  // What used to stand in for this lived in linux_tunnel_backend.cc and
  // returned TRUE -- "the transport converged" -- whenever the engine's status
  // reply did not contain the exact substring
  // `"awg_classification":"configured-h1h4"`, saying so only through
  // g_warning. Route promotion therefore turned on the SPELLING OF A FIELD IN
  // A REPLY: an engine-side rename, a version skew between the shipped host and
  // the shipped engine, or an encoder that emitted a space after the colon each
  // disabled the gate silently and left the user's default route, DNS and IPv6
  // pointed into a carrier that had never been proven to carry one datagram.
  //
  // The justification written beside it appealed to h1..h4 being mandatory in
  // ParseLinuxWinnSection (linux_winn_host.cc:1254 and :1292) -- that is, to
  // the HOST'S OWN PARSED CONFIGURATION. So the check now tests that, at
  // state->headers_classify, latched in StartLinuxWinnEngine from the params
  // this host built the Create document from. The engine's reply can no longer
  // move the gate; it can only fail to satisfy it.
  bool engine_present = false;
  bool headers_classify = false;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    engine_present = g_engine != nullptr;
    headers_classify = engine_present && g_engine->headers_classify;
  }
  // Released before LinuxWinnEngineStatusJson(), which takes the same
  // non-recursive mutex.
  if (!engine_present) {
    if (status_json != nullptr) status_json->clear();
    if (reason != nullptr) {
      *reason = "the Winn Protocol engine is not running.";
    }
    return WinnTransportGate::kNotYetObserved;
  }
  // Queried ONLY when the answer can depend on it. A session whose own h1..h4
  // table cannot classify is refused whatever the engine says, so asking costs
  // up to kStatusTimeoutMs for a verdict already known -- and the caller's
  // convergence budget is the user's connect latency.
  std::string status;
  if (headers_classify) {
    status = LinuxWinnEngineStatusJson();
  }
  if (status_json != nullptr) *status_json = status;
  return DecideWinnTransportGate(headers_classify, status, reason);
}

std::string LinuxWinnSeamStatsJson() {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_engine == nullptr) return "";
  EngineState* state = g_engine;
  size_t queued = 0;
  {
    std::lock_guard<std::mutex> ring_guard(state->ring.mutex);
    queued = state->ring.queued;
  }
  std::ostringstream json;
  json << "{\"seam_rx_datagrams\":" << state->counters.rx_datagrams.load()
       << ",\"seam_rx_bytes\":" << state->counters.rx_bytes.load()
       << ",\"seam_rx_ring_dropped\":" << state->counters.rx_ring_dropped.load()
       << ",\"seam_rx_foreign_sender\":"
       << state->counters.rx_foreign_sender.load()
       << ",\"seam_rx_oversize\":" << state->counters.rx_oversize.load()
       << ",\"seam_tx_written\":" << state->counters.tx_written.load()
       << ",\"seam_tx_write_failed\":"
       << state->counters.tx_write_failed.load()
       << ",\"seam_awg_sent\":" << state->counters.awg_sent.load()
       << ",\"seam_awg_send_failed\":"
       << state->counters.awg_send_failed.load()
       << ",\"seam_awg_no_peer\":" << state->counters.awg_no_peer.load()
       << ",\"seam_ring_slots\":" << kSeamRingSlots
       << ",\"seam_ring_queued\":" << queued
       << ",\"seam_rx_backlog_high_water_bytes\":"
       << state->counters.rx_backlog_high_water_bytes.load()
       << ",\"seam_rcvbuf_bytes\":" << state->counters.rcvbuf_bytes.load()
       << "}";
  return json.str();
}

}  // namespace winsvpn::winn
