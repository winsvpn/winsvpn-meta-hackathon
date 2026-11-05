#include "linux_winn3_host.h"

// The duplex frame codec is NOT reimplemented here. windows/runner/winn_frame.h
// is the normative reference implementation of the WNN3 layout -- the Go
// package pins the exact bytes against it in TestGoldenFrameBytes -- and
// linux_winn_host.cc already includes it for the winn/1 relay. A second copy on
// the v3 side would be a second thing to drift.
#include "../../windows/runner/winn_frame.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
// <net/if.h> for struct ifreq and IFNAMSIZ, <linux/if_tun.h> for TUNSETIFF and
// the IFF_ flags. Deliberately not <linux/if.h>, which collides with the first.
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
// The one pre-promotion inner probe SendLinuxWinn3InnerPromotionProbe sends:
// a datagram ICMP ("ping") socket with the kernel filling id and checksum.
// <sys/time.h> for struct timeval, which the reply window uses.
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace winsvpn::winn3host {
namespace {

using winsvpn::winn::DecodeStatus;
using winsvpn::winn::EncodeFrame;
using winsvpn::winn::Frame;
using winsvpn::winn::FrameReader;
using winsvpn::winn::Opcode;

// The create document's fixed fields. Held as named constants beside each
// other so a call site cannot confuse them with the winn/1 values, and so a
// test can assert that a v3 document never emits `awg-datagram`. Getting this
// wrong in the winn/1 direction is what puts CLEARTEXT on the wire: a v1 engine
// fed inner IP packets forwards them to the gateway unencrypted.
constexpr char kPayloadIpPacket[] = "ip-packet";
constexpr char kPayloadAwgDatagram[] = "awg-datagram";

// winn3Keys.Version. The engine refuses any other value rather than trying to
// interpret it.
constexpr char kKeysVersion[] = "winn3-keys/1";
constexpr char kRoleClient[] = "client";
constexpr size_t kDualAuthEd25519Bytes = 32;
constexpr size_t kDualAuthMldsa65Bytes = 1952;
constexpr char kDualAuthEd25519File[] = "auth_ed25519.pub";
constexpr char kDualAuthMldsa65File[] = "auth_mldsa65.pub";

// The private directory and the file this host writes there.
constexpr char kWinn3StateDirName[] = "winn3";
constexpr char kKeysFileName[] = "winn3-keys.json";

// Frame-channel timeouts. The create budget is generous because a censored path
// is slow and the engine dials the outer socket inside handleCreate; the status
// budget is short because a host that waits seconds for a counter has turned a
// poll into a stall.
constexpr int kCreateAckTimeoutMs = 35000;
constexpr int kStatusTimeoutMs = 2000;
constexpr int kCloseAckWaitMs = 750;

// The tun pump's bounded ring.
//
// The v1 seam's measured defect applies here in shape though not in mechanism:
// one thread doing read() -> WriteFrame() blocks on the engine's stdin pipe
// whenever the engine falls behind, and while it is blocked nothing is draining
// the tun device. The DIFFERENCE from the seam is that a tun backlog is
// visible -- the kernel counts the qdisc drops and `ip -s link` reports them --
// whereas the loopback UDP socket offered only a process-wide RcvbufErrors. So
// this is not the invisible-loss defect; it is the same stall, with a counter.
// The split is kept anyway because the stall itself is the problem: an
// outbound direction that halts while the engine is busy is a tunnel that
// stutters under exactly the load it exists to carry.
constexpr size_t kTunRingSlots = 2048;

// Slots claimed per lock acquisition and coalesced into ONE write() syscall.
// The v1 measurement that mattered was that this writer is syscall-bound
// rather than lock-bound; the engine is a subprocess behind a pipe here too.
constexpr size_t kTunWriteBatch = 32;

std::string Trim(const std::string& value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return std::string();
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::string JsonEscape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          static const char kHex[] = "0123456789abcdef";
          out += "\\u00";
          out.push_back(kHex[(static_cast<unsigned char>(c) >> 4) & 0x0F]);
          out.push_back(kHex[static_cast<unsigned char>(c) & 0x0F]);
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

bool Fail(std::string* error, const std::string& message) {
  if (error != nullptr) *error = message;
  return false;
}

bool IsAbsolutePath(const std::string& value) {
  const std::string trimmed = Trim(value);
  return !trimmed.empty() && trimmed.front() == '/';
}

bool IsIpv4Literal(const std::string& host) {
  int octets = 0;
  size_t at = 0;
  while (at <= host.size()) {
    size_t digits = 0;
    int value = 0;
    while (at < host.size() && host[at] >= '0' && host[at] <= '9') {
      value = value * 10 + (host[at] - '0');
      if (++digits > 3 || value > 255) return false;
      ++at;
    }
    if (digits == 0) return false;
    ++octets;
    if (at == host.size()) break;
    if (host[at] != '.') return false;
    ++at;
  }
  return octets == 4;
}

bool IsIpv6Literal(const std::string& host) {
  if (host.empty() || host.find(':') == std::string::npos) return false;
  for (const char c : host) {
    const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F');
    if (!hex && c != ':' && c != '.') return false;
  }
  return true;
}

// Canonical dotted-quad parsing for ADDRESS EQUALITY: two spellings of one
// address ("010.000.000.001" vs "10.0.0.1" vs "10.0.0.01") must compare
// equal, so equality is decided over the numeric value, not the text. The
// same rules IsIpv4Literal applies to the endpoint host are applied here
// (up to three digits per octet, 0-255, decimal -- never inet_aton's octal
// reading of a leading zero, which inet_pton has no business accepting), so
// the guard can NEVER say "different spellings" about one address, and two
// genuinely different addresses can never collide.
bool ParseIpv4LiteralUint32(const std::string& host, uint32_t* out) {
  if (out == nullptr) return false;
  uint32_t value = 0;
  int octets = 0;
  size_t at = 0;
  while (at <= host.size()) {
    size_t digits = 0;
    uint32_t octet = 0;
    while (at < host.size() && host[at] >= '0' && host[at] <= '9') {
      octet = octet * 10 + static_cast<uint32_t>(host[at] - '0');
      if (++digits > 3 || octet > 255) return false;
      ++at;
    }
    if (digits == 0) return false;
    value = (value << 8) | octet;
    ++octets;
    if (at == host.size()) break;
    if (host[at] != '.') return false;
    ++at;
  }
  if (octets != 4) return false;
  *out = value;
  return true;
}

std::string PrivateWinn3StateDirectory() {
  const char* xdg = std::getenv("XDG_DATA_HOME");
  std::string base;
  if (xdg != nullptr && xdg[0] == '/') {
    base = xdg;
  } else {
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] != '/') return "";
    base = std::string(home) + "/.local/share";
  }
  return base + "/wins_vpn/" + kWinn3StateDirName;
}

// Creates `directory` and every missing parent, 0700.
//
// WHY THIS IS HERE. Until 2026-08-09 nothing in this file created a directory,
// and WriteLinuxWinn3KeysDocument opened its temporary file directly under
// PrivateWinn3StateDirectory(). On a machine where that directory did not
// already exist -- which is EVERY machine before a v3 session has ever run,
// because nothing else writes there -- the open failed with ENOENT and
// StartLinuxWinn3Engine returned "Could not create the Winn v3 key document".
// It went unnoticed because StartLinuxWinn3Engine had no caller at all until
// the same day, so the first real call was also the first failure.
//
// 0700 and not 0755: the document names every key file on the device by
// absolute path, and the reason the code refuses to fall back to /tmp is the
// same reason the directory holding it must not be traversable by other users.
// The mode is passed to mkdir rather than chmod'd afterwards so the directory
// is never briefly world-readable, which is the rule WriteSecretFile follows
// for the files inside it.
//
// An existing directory is success. A non-directory at the name is not, and is
// reported rather than written through.
bool EnsurePrivateDirectory(const std::string& directory, std::string* error) {
  if (directory.empty() || directory.front() != '/') {
    return Fail(error, "The Winn v3 private directory path is not absolute.");
  }
  std::string built;
  size_t index = 1;
  while (index <= directory.size()) {
    const size_t slash = directory.find('/', index);
    const size_t end = slash == std::string::npos ? directory.size() : slash;
    built = directory.substr(0, end);
    index = end + 1;
    if (::mkdir(built.c_str(), 0700) != 0 && errno != EEXIST) {
      return Fail(error, "Could not create the Winn v3 private directory at " +
                             built + ": " + std::strerror(errno));
    }
    struct stat info {};
    if (::stat(built.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
      return Fail(error, "The Winn v3 private directory path " + built +
                             " is not a directory.");
    }
  }
  return true;
}

// B-05 (audits 2026-08-28): atomic close-on-exec pipes on Linux; the
// pipe()+fcntl fallback is non-Linux test builds only (where this host is
// exercised single-threaded).
#if defined(__linux__)
bool PipeCloexec(int fds[2]) {
  return pipe2(fds, O_CLOEXEC) == 0;
}
#else
bool SetCloseOnExec(int fd) {
  const int flags = fcntl(fd, F_GETFD);
  return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

bool PipeCloexec(int fds[2]) {
  if (pipe(fds) != 0) return false;
  if (!SetCloseOnExec(fds[0]) || !SetCloseOnExec(fds[1])) {
    close(fds[0]);
    close(fds[1]);
    fds[0] = fds[1] = -1;
    return false;
  }
  return true;
}
#endif

int64_t NowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

// ---------------------------------------------------------------------------
// The running session. One at a time, guarded by g_mutex.
// ---------------------------------------------------------------------------

struct TunRing {
  std::mutex mutex;
  std::condition_variable signal;
  std::vector<uint8_t> storage;
  std::vector<uint32_t> lengths;
  size_t slot_bytes = 0;
  size_t head = 0;
  size_t queued = 0;
  bool closed = false;

  void Init(size_t packet_bytes) {
    slot_bytes = packet_bytes;
    storage.assign(kTunRingSlots * slot_bytes, 0);
    lengths.assign(kTunRingSlots, 0);
    head = 0;
    queued = 0;
    closed = false;
  }
};

// Every field here is an integer this file counted itself. No address, no
// endpoint and no packet byte reaches a log call anywhere in this file.
struct PumpCounters {
  std::atomic<unsigned long long> tun_read_packets{0};
  std::atomic<unsigned long long> tun_read_bytes{0};
  std::atomic<unsigned long long> tun_read_oversize{0};
  std::atomic<unsigned long long> ring_dropped{0};
  std::atomic<unsigned long long> inbound_frames{0};
  std::atomic<unsigned long long> inbound_write_failed{0};
  std::atomic<unsigned long long> outbound_frames{0};
  std::atomic<unsigned long long> tun_write_failed{0};
};

struct SessionState {
  pid_t pid = -1;
  int stdin_fd = -1;   // host -> engine frames
  int stdout_fd = -1;  // engine -> host frames
  int tun_fd = -1;     // the host's own /dev/net/tun device
  int wake_fd[2] = {-1, -1};

  std::thread reader;   // tun -> ring (DRAINS ONLY; never blocks on the pipe)
  std::thread writer;   // ring -> Inbound frames (does the blocking write)
  std::thread outbound; // Outbound frames -> tun

  TunRing ring;
  PumpCounters counters;

  std::atomic<bool> stopping{false};
  std::atomic<bool> channel_up{false};

  std::mutex write_mutex;

  std::mutex status_mutex;
  std::condition_variable status_signal;
  std::string last_status;
  int64_t last_status_at = 0;
  std::string failure;
  bool close_acked = false;
};

std::mutex g_mutex;
SessionState* g_session = nullptr;

// The teardown's own memory of the session, separate from g_session because
// the engine subprocess outlives no failure: by the time StopTunnel runs, the
// process half may already be gone while the POSTURE half -- the /32 on the
// physical interface, the resolver settings -- is exactly what must still be
// reversed. Guarded by g_mutex along with g_session: one lock, one session.
LinuxWinn3Params g_session_params;
bool g_session_registered = false;

// The last promotion attempt's resolver mechanism and outcome, for the status
// document. Its OWN mutex rather than g_mutex: a posture is applied by a caller
// that need not have started an engine at all -- the privileged posture drivers
// do exactly that -- and hanging this off the session would make the mechanism
// invisible in precisely the runs that exist to measure it.
std::mutex g_resolver_status_mutex;
LinuxWinn3ResolverMechanism g_resolver_mechanism =
    LinuxWinn3ResolverMechanism::kUnknown;
LinuxWinn3PostureOutcome g_promoted_outcome =
    LinuxWinn3PostureOutcome::kNotAttempted;
bool g_promoted_capturing = false;
std::string g_resolver_detail;

// Bootstrap status, published under its OWN key. The promoted path publishes
// under `promoted_posture` and the bootstrap deliberately does not, so an
// operator needs a second place to read it. Same mutex: a posture is applied by
// a caller that need not have started an engine, and hanging this off the
// session would make it invisible in the runs that exist to measure it.
LinuxWinn3PostureOutcome g_bootstrap_outcome =
    LinuxWinn3PostureOutcome::kNotAttempted;
bool g_bootstrap_capturing = false;
bool g_bootstrap_exclusion_installed = false;
bool g_bootstrap_stale_repaired = false;
std::string g_bootstrap_error;

bool WriteAll(int fd, const uint8_t* data, size_t size) {
  size_t written = 0;
  while (written < size) {
    const ssize_t count = write(fd, data + written, size - written);
    if (count < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (count == 0) return false;
    written += static_cast<size_t>(count);
  }
  return true;
}

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

bool WriteFrameLocked(SessionState* state, Opcode opcode,
                      const uint8_t* payload, size_t size) {
  std::vector<uint8_t> frame;
  if (!EncodeFrame(opcode, payload, size, &frame)) return false;
  std::lock_guard<std::mutex> guard(state->write_mutex);
  if (state->stdin_fd < 0) return false;
  return WriteEnginePipeAll(state->stdin_fd, frame.data(), frame.size());
}

void RecordFailure(SessionState* state, const std::string& reason) {
  {
    std::lock_guard<std::mutex> guard(state->status_mutex);
    if (state->failure.empty()) state->failure = reason;
  }
  state->channel_up.store(false);
  state->status_signal.notify_all();
}

bool RingPush(SessionState* state, const uint8_t* data, size_t size) {
  std::lock_guard<std::mutex> guard(state->ring.mutex);
  if (state->ring.closed) return false;
  if (state->ring.queued == kTunRingSlots) {
    state->counters.ring_dropped.fetch_add(1);
    return false;  // TAIL DROP, counted here rather than lost in the kernel.
  }
  const size_t slot =
      (state->ring.head + state->ring.queued) % kTunRingSlots;
  std::memcpy(&state->ring.storage[slot * state->ring.slot_bytes], data, size);
  state->ring.lengths[slot] = static_cast<uint32_t>(size);
  ++state->ring.queued;
  state->ring.signal.notify_one();
  return true;
}

// ring -> Inbound frames. The ONLY thread that blocks on the engine's stdin.
void FrameWritePump(SessionState* state) {
  std::vector<uint8_t> batch;
  std::vector<uint8_t> frame;
  while (true) {
    size_t claimed = 0;
    batch.clear();
    {
      std::unique_lock<std::mutex> guard(state->ring.mutex);
      state->ring.signal.wait(guard, [state] {
        return state->ring.queued > 0 || state->ring.closed;
      });
      if (state->ring.queued == 0 && state->ring.closed) return;
      claimed = std::min(state->ring.queued, kTunWriteBatch);
      claimed = std::min(claimed, kTunRingSlots - state->ring.head);
      const size_t first = state->ring.head;
      for (size_t i = 0; i < claimed; ++i) {
        const size_t slot = first + i;  // contiguous by construction
        if (!EncodeFrame(Opcode::kInbound,
                         &state->ring.storage[slot * state->ring.slot_bytes],
                         state->ring.lengths[slot], &frame)) {
          continue;  // cannot happen: the length was bounded at read time
        }
        batch.insert(batch.end(), frame.begin(), frame.end());
      }
    }

    bool ok;
    {
      std::lock_guard<std::mutex> guard(state->write_mutex);
      ok = state->stdin_fd >= 0 &&
           WriteEnginePipeAll(state->stdin_fd, batch.data(), batch.size());
    }
    {
      std::lock_guard<std::mutex> guard(state->ring.mutex);
      state->ring.head = (state->ring.head + claimed) % kTunRingSlots;
      state->ring.queued -= claimed;
    }
    if (!ok) {
      state->counters.inbound_write_failed.fetch_add(claimed);
      if (!state->stopping.load()) {
        RecordFailure(state, "the Winn v3 engine channel failed while writing");
      }
      return;
    }
    state->counters.inbound_frames.fetch_add(claimed);
  }
}

// tun -> ring. MUST NEVER BLOCK ON ANYTHING BUT poll(); see kTunRingSlots.
void TunReadPump(SessionState* state, int inner_mtu) {
  // inner_mtu + 1, so an oversize packet is DETECTED rather than silently
  // truncated. A truncated inner packet fails the far end's validator and looks
  // like a network fault instead of an MTU one.
  std::vector<uint8_t> buffer(static_cast<size_t>(inner_mtu) + 1);
  while (!state->stopping.load()) {
    pollfd fds[2];
    fds[0] = {state->tun_fd, POLLIN, 0};
    fds[1] = {state->wake_fd[0], POLLIN, 0};
    const int ready = poll(fds, 2, -1);
    if (ready < 0) {
      if (errno == EINTR) continue;
      RecordFailure(state, "the Winn v3 tun device could not be polled");
      return;
    }
    if ((fds[1].revents & POLLIN) != 0) return;  // stop requested
    if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;

    const ssize_t count = read(state->tun_fd, buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      RecordFailure(state, "the Winn v3 tun device could not be read");
      return;
    }
    if (count == 0) continue;
    const size_t size = static_cast<size_t>(count);
    state->counters.tun_read_packets.fetch_add(1);
    state->counters.tun_read_bytes.fetch_add(size);
    if (size > static_cast<size_t>(inner_mtu)) {
      state->counters.tun_read_oversize.fetch_add(1);
      continue;  // dropped, never truncated
    }
    (void)RingPush(state, buffer.data(), size);
  }
}

// Engine -> host frames, demultiplexed by opcode. Outbound frames interleave
// with responses at any time, so this cannot assume request/response ordering.
void OutboundPump(SessionState* state) {
  FrameReader reader(/*accept_engine_to_host=*/true);
  std::array<uint8_t, 65536> chunk{};
  // One Frame for the pump's life, so payload capacity is reused across
  // reads as well as across the frames of one read.
  Frame frame;
  while (!state->stopping.load()) {
    pollfd fds[2];
    fds[0] = {state->stdout_fd, POLLIN, 0};
    fds[1] = {state->wake_fd[0], POLLIN, 0};
    const int ready = poll(fds, 2, -1);
    if (ready < 0) {
      if (errno == EINTR) continue;
      RecordFailure(state, "the Winn v3 engine channel could not be polled");
      return;
    }
    if ((fds[1].revents & POLLIN) != 0) return;
    if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;

    const ssize_t count = read(state->stdout_fd, chunk.data(), chunk.size());
    if (count < 0) {
      if (errno == EINTR) continue;
      RecordFailure(state, "the Winn v3 engine channel failed while reading");
      return;
    }
    if (count == 0) {
      RecordFailure(state, "the Winn v3 engine closed its channel");
      return;
    }
    reader.Append(chunk.data(), static_cast<size_t>(count));

    for (;;) {
      const DecodeStatus status = reader.Next(&frame);
      if (status == DecodeStatus::kNeedMore) break;
      if (status == DecodeStatus::kInvalid) {
        // Never resynchronize. Scanning forward for the next magic turns a
        // length confusion into an attacker-chosen frame boundary.
        RecordFailure(state, "the Winn v3 engine sent an invalid frame");
        return;
      }
      switch (frame.opcode) {
        case Opcode::kOutbound: {
          // An inner IP packet the tun layer VALIDATED and is delivering. This
          // write is what moves RxPackets, which is half of promotion_ready --
          // so a host that swallowed these would never be promoted, which is
          // the fail-closed direction.
          if (!WriteAll(state->tun_fd, frame.payload.data(),
                        frame.payload.size())) {
            state->counters.tun_write_failed.fetch_add(1);
          } else {
            state->counters.outbound_frames.fetch_add(1);
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
          if (text.size() > 400) text.resize(400);
          RecordFailure(state, "the Winn v3 engine reported: " + text);
          return;
        }
        default:
          RecordFailure(state, "the Winn v3 engine sent an unexpected frame");
          return;
      }
    }
  }
}

void CloseIfOpen(int* fd) {
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

void TeardownLocked(SessionState* state) {
  state->stopping.store(true);
  state->channel_up.store(false);

  // Close, best effort, so the engine tears its tunnel down rather than being
  // killed mid-session. A CloseAck is waited for briefly and never forever.
  if (state->stdin_fd >= 0) {
    (void)WriteFrameLocked(state, Opcode::kClose, nullptr, 0);
    std::unique_lock<std::mutex> guard(state->status_mutex);
    state->status_signal.wait_for(guard,
                                  std::chrono::milliseconds(kCloseAckWaitMs),
                                  [state] { return state->close_acked; });
  }

  {
    std::lock_guard<std::mutex> guard(state->ring.mutex);
    state->ring.closed = true;
  }
  state->ring.signal.notify_all();
  if (state->wake_fd[1] >= 0) {
    const uint8_t byte = 1;
    (void)!write(state->wake_fd[1], &byte, 1);
  }

  {
    std::lock_guard<std::mutex> guard(state->write_mutex);
    CloseIfOpen(&state->stdin_fd);
  }

  if (state->reader.joinable()) state->reader.join();
  if (state->writer.joinable()) state->writer.join();
  if (state->outbound.joinable()) state->outbound.join();

  CloseIfOpen(&state->stdout_fd);
  CloseIfOpen(&state->tun_fd);
  CloseIfOpen(&state->wake_fd[0]);
  CloseIfOpen(&state->wake_fd[1]);

  if (state->pid > 0) {
    int status = 0;
    // B-06: EINTR-aware reaping. WNOHANG polls and the blocking reap both
    // retry on EINTR (an unrelated SIGCHLD used to make a poll read as
    // "still running" and the final reap return early), and only a reaped
    // pid or a real error moves the sequence on.
    auto poll_reaped = [&]() -> bool {
      for (;;) {
        const pid_t reaped = waitpid(state->pid, &status, WNOHANG);
        if (reaped == state->pid) return true;
        if (reaped < 0 && errno == EINTR) continue;
        return reaped < 0;  // ECHILD etc.: nothing to wait for.
      }
    };
    bool reaped = false;
    for (int i = 0; i < 40 && !reaped; ++i) {
      reaped = poll_reaped();
      if (!reaped) usleep(25 * 1000);
    }
    if (!reaped) {
      kill(state->pid, SIGTERM);
      for (int i = 0; i < 20 && !reaped; ++i) {
        reaped = poll_reaped();
        if (!reaped) usleep(25 * 1000);
      }
      if (!reaped) {
        kill(state->pid, SIGKILL);
        for (;;) {
          const pid_t blocked = waitpid(state->pid, &status, 0);
          if (blocked == state->pid) break;
          if (blocked < 0 && errno == EINTR) continue;
          break;
        }
      }
    }
    state->pid = -1;
  }
}

std::string JoinArgv(const std::vector<std::string>& argv) {
  std::string joined;
  for (const std::string& token : argv) {
    if (!joined.empty()) joined.push_back(' ');
    joined += token;
  }
  return joined;
}

// DELETED 2026-08-10: `RunAll`, which ran a command list and returned bool.
//
// It was the last thing in this file that could report a partial application as
// a bare `false`. Both appliers now run their own list so that the prefix which
// already succeeded is a recorded fact -- `LinuxWinn3PostureResult::applied` --
// rather than something a caller has to infer from a boolean that cannot carry
// it. Nothing replaced it, on purpose: a shared "run these and tell me yes or
// no" is exactly the shape that made both defects possible, and reintroducing
// it would make the third one available.

// True when the argument vector ran and exited zero. A probe, so a non-zero
// exit is an ANSWER rather than an error: nothing is logged as a failure and
// nothing is returned in *error.
bool Probe(const LinuxWinn3PrivilegedRunner& run,
           const std::vector<std::string>& argv) {
  if (!run) return false;
  std::string ignored;
  return run(argv, std::string(), &ignored);
}

// The reversal of one applied posture command, or an empty vector when the
// command has no reversal and needs none.
//
// `ip ... add ...` becomes `ip ... del ...` with every other token identical,
// which is the same construction RenderLinuxWinn3ExclusionTeardown already uses
// and for the same reason: two independently written vectors can describe two
// different routes, and one vector with one token swapped cannot.
//
// `ip link set dev D mtu N up` is deliberately NOT reversed. There is no
// "unset" for it, the bootstrap already ran the identical command, and an MTU
// on a device nothing is routed to captures nothing -- so leaving it is safe
// and inventing a reversal for it would be the guess this whole path exists to
// avoid.
std::vector<std::string> ReverseOfPostureCommand(
    const std::vector<std::string>& argv) {
  if (argv.empty() || argv[0] != "ip") return {};
  bool has_add = false;
  for (const std::string& token : argv) {
    if (token == "link") return {};
    if (token == "add") has_add = true;
  }
  if (!has_add) return {};
  std::vector<std::string> reversed = argv;
  for (std::string& token : reversed) {
    if (token == "add") token = "del";
  }
  return reversed;
}

// The one must-succeed `ip ... route del` a teardown renders is the
// outer-socket exclusion's removal: `ip -4|-6 route del <gw>/32|128 ...`.
// Every other `ip ... route del` in the teardown -- the promoted /1 pair --
// is best effort. This predicate lets the unified stop skip the exclusion
// removal when no exclusion was ever installed, so an idempotent stop on a
// machine with nothing up cannot fabricate a failure out of a route that was
// never there.
bool IsExclusionRemoval(const LinuxWinn3Command& command) {
  if (command.best_effort || command.argv.size() < 4) return false;
  return command.argv[0] == "ip" && command.argv[2] == "route" &&
         command.argv[3] == "del";
}

// The interface a rendered posture command is scoped to -- the token after
// `dev` -- or "" when the command names no interface.
//
// Every posture command RenderLinuxPostureCommands emits names one, and so does
// the exclusion. The resolver commands do not, and "" is the right answer for
// them rather than a guess.
std::string PostureCommandDevice(const std::vector<std::string>& argv) {
  for (size_t i = 0; i + 1 < argv.size(); ++i) {
    if (argv[i] == "dev") return argv[i + 1];
  }
  return std::string();
}

// What a failed attempt LEFT IN THE KERNEL: the commands that ran and succeeded
// minus every one whose reversal actually removed it.
//
// A command with no reversal is not residue and is not counted. `ip link set
// dev D mtu N up` is the only one, and all three reasons agree: there is no
// `del` form of it that could have failed, an MTU on a device nothing is routed
// to moves no traffic, and the device it is set on dies with its descriptor.
std::vector<std::vector<std::string>> ResidueOfAttempt(
    const std::vector<std::vector<std::string>>& applied,
    const std::vector<std::vector<std::string>>& rollback_failed) {
  std::vector<std::vector<std::string>> residue;
  for (const std::vector<std::string>& argv : applied) {
    const std::vector<std::string> reversed = ReverseOfPostureCommand(argv);
    if (reversed.empty()) continue;
    for (const std::vector<std::string>& failed : rollback_failed) {
      if (failed == reversed) {
        residue.push_back(argv);
        break;
      }
    }
  }
  return residue;
}

// Whether any of `installed` is scoped to an interface that is NOT the tun --
// which is to say, whether any of it survives this process.
//
// The tun is opened with TUNSETIFF and no TUNSETPERSIST, so it and everything
// addressed or routed on it disappear when the last descriptor closes. An `ip`
// command on the PHYSICAL interface is the exception, and the outer-socket
// exclusion is the one the Winn v3 postures render. Asking the question by
// device rather than by matching the exclusion's own argument vector means a
// future command on the physical interface is counted without anyone having to
// remember to count it.
bool AnyCommandOutlivesTheTun(
    const std::vector<std::vector<std::string>>& installed,
    const std::string& tun_device) {
  for (const std::vector<std::string>& argv : installed) {
    const std::string device = PostureCommandDevice(argv);
    if (!device.empty() && device != tun_device) return true;
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// sizing
// ---------------------------------------------------------------------------
namespace sizing {

std::vector<std::string> CarrierClasses() {
  return {"udp", "tcp", "tls"};
}

bool CarrierOverhead(const std::string& carrier_class, bool ipv4, int* out) {
  if (out == nullptr) return false;
  const int ip = ipv4 ? kIPv4HeaderBytes : kIPv6HeaderBytes;
  const std::string name = Trim(carrier_class);
  if (name == "udp") {
    *out = ip + kUdpHeaderBytes;
    return true;
  }
  if (name == "tcp") {
    *out = ip + kTcpHeaderBytes + kLengthRecordOverhead;
    return true;
  }
  if (name == "tls") {
    *out = ip + kTcpHeaderBytes + kTlsRecordBytes + kLengthRecordOverhead;
    return true;
  }
  // Never a default. cmd/winn-datapath's winn3ClassNamed refuses the same set,
  // because a floor computed over a class nobody named is a floor that
  // guarantees nothing.
  return false;
}

int MaxMessageSizeForPath(int path_mtu, int carrier_overhead) {
  const int n = path_mtu - carrier_overhead;
  if (n < kMessageFloor) return kMessageFloor;
  if (n > kMaxTransportPayload) return kMaxTransportPayload;
  return n;
}

bool PlanFloorMessageSize(int path_mtu,
                          const std::vector<std::string>& carrier_classes,
                          int* out, std::string* error) {
  if (out == nullptr) return false;
  if (carrier_classes.empty()) {
    return Fail(error,
                "a migration plan must name the carrier classes the session "
                "may escalate to: the message floor is computed over the list, "
                "and a class left out of it is a class the floor did not "
                "account for");
  }
  if (path_mtu <= 0) {
    return Fail(error, "the outer path MTU must be positive");
  }
  int best = 0;
  for (const std::string& carrier_class : carrier_classes) {
    for (const bool ipv4 : {true, false}) {
      int overhead = 0;
      if (!CarrierOverhead(carrier_class, ipv4, &overhead)) {
        return Fail(error,
                    "unknown carrier class \"" + Trim(carrier_class) +
                        "\"; use udp, tcp or tls. cmd/winn-datapath refuses "
                        "the same name rather than charging it a default");
      }
      const int n = MaxMessageSizeForPath(path_mtu, overhead);
      if (best == 0 || n < best) best = n;
    }
  }
  *out = best;
  return true;
}

bool PlanFloorInnerMtu(int path_mtu,
                       const std::vector<std::string>& carrier_classes,
                       int* out, std::string* error) {
  if (out == nullptr) return false;
  int message = 0;
  if (!PlanFloorMessageSize(path_mtu, carrier_classes, &message, error)) {
    return false;
  }
  const int inner = InnerMtu(message);
  if (inner < kMinInnerMtuV4) {
    return Fail(error,
                "a path MTU of " + std::to_string(path_mtu) +
                    " over this plan yields an inner MTU of " +
                    std::to_string(inner) + ", below the " +
                    std::to_string(kMinInnerMtuV4) + "-byte IPv4 floor");
  }
  *out = inner;
  return true;
}

bool PlanCarriesInnerIPv6(int path_mtu,
                          const std::vector<std::string>& carrier_classes) {
  int inner = 0;
  if (!PlanFloorInnerMtu(path_mtu, carrier_classes, &inner, nullptr)) {
    return false;
  }
  return inner >= kIPv6MinLinkMtu;
}

bool AssertsAgreeWithGo(std::string* error) {
  const auto expect = [error](bool condition, const char* what) {
    if (!condition) Fail(error, what);
    return condition;
  };
  if (!expect(InnerMtuForPath(1500, kUdpOverIPv4Overhead) == 1443,
              "InnerMTUForPath(1500, 28) must be 1443")) {
    return false;
  }
  if (!expect(InnerMtuForPath(1500, kUdpOverIPv6Overhead) == 1423,
              "InnerMTUForPath(1500, 48) must be 1423")) {
    return false;
  }
  if (!expect(InnerMtuForPath(1280, kUdpOverIPv6Overhead) == 1203,
              "InnerMTUForPath(1280, 48) must be 1203")) {
    return false;
  }
  if (!expect(CarrierMessageFor(kIPv6MinLinkMtu) == 1309,
              "MinCarrierMessageForIPv6() must be 1309")) {
    return false;
  }
  const std::vector<std::string> plan = CarrierClasses();
  int message = 0;
  int inner = 0;
  if (!PlanFloorMessageSize(1500, plan, &message, error)) return false;
  if (!expect(message == 1388, "Floor(1500, udp, tcp, tls) must be 1388")) {
    return false;
  }
  if (!PlanFloorInnerMtu(1500, plan, &inner, error)) return false;
  if (!expect(inner == 1359,
              "the plan floor inner MTU at a 1500-byte path must be 1359")) {
    return false;
  }
  if (!PlanFloorMessageSize(1280, plan, &message, error)) return false;
  if (!expect(message == 1168, "Floor(1280, udp, tcp, tls) must be 1168")) {
    return false;
  }
  if (!PlanFloorInnerMtu(1280, plan, &inner, error)) return false;
  if (!expect(inner == 1139,
              "the plan floor inner MTU at a 1280-byte path must be 1139")) {
    return false;
  }
  // The 84-byte gap the create seam exists to catch: the difference between the
  // dialled UDP/IPv4 carrier's overhead and the plan's worst case, TLS/IPv6.
  if (!expect(InnerMtuForPath(1500, kUdpOverIPv4Overhead) - 1359 == 84,
              "the dialled-carrier gap at a 1500-byte path must be 84 bytes")) {
    return false;
  }
  return true;
}

}  // namespace sizing

// ---------------------------------------------------------------------------
// The key document
// ---------------------------------------------------------------------------

bool BuildLinuxWinn3KeysJson(const LinuxWinn3Keys& keys, std::string* out,
                             std::string* error) {
  if (out == nullptr) return false;
  if (Trim(keys.role) != kRoleClient) {
    // `gateway` is a legal value of the Go document and this host never writes
    // it: a client that identified itself as the gateway would be given
    // cfg.Accept = admit-all and no gateway static key to authenticate against,
    // which is an unauthenticated peer by configuration.
    return Fail(error,
                "the Linux Winn v3 host is always the client; role \"" +
                    Trim(keys.role) +
                    "\" is the lab responder's and is refused here");
  }
  if (Trim(keys.gateway_id).empty()) {
    return Fail(error,
                "the Winn v3 key document needs a gateway_id: without it an "
                "initiation captured at one gateway replays at another that "
                "shares the admission key");
  }
  if (!IsAbsolutePath(keys.static_path)) {
    return Fail(error,
                "the Winn v3 key document needs an absolute static_path");
  }
  if (!IsAbsolutePath(keys.gateway_static_path)) {
    return Fail(error,
                "the Winn v3 key document needs an absolute "
                "gateway_static_path: a client authenticates the gateway by "
                "its static key and there is no anonymous mode");
  }
  if (!IsAbsolutePath(keys.admission_path)) {
    return Fail(error,
                "the Winn v3 key document needs an absolute admission_path");
  }
  const std::string ed_path = Trim(keys.dual_auth_ed25519_pub_path);
  const std::string ml_path = Trim(keys.dual_auth_mldsa65_pub_path);
  if (ed_path.empty() != ml_path.empty()) {
    return Fail(error,
                "dual_auth_ed25519_pub_path and dual_auth_mldsa65_pub_path "
                "must be set together");
  }
  if (!ed_path.empty()) {
    if (!IsAbsolutePath(ed_path) || !IsAbsolutePath(ml_path)) {
      return Fail(error,
                  "the Winn v3 key document needs absolute dual-auth public "
                  "key paths");
    }
  }
  if (Trim(keys.outer_socket_exclusion).empty()) {
    // This host always sets allow_own_socket, because `-transport stdio` cannot
    // carry a descriptor and the engine therefore opens the outer socket
    // itself. winn3_create.go refusal 4 rejects that combination unless the key
    // document declares the exclusion, so an empty one here is a start that
    // fails at create time rather than a start that fails now.
    return Fail(error,
                "the Winn v3 key document must declare the outer-socket "
                "exclusion this host installed: the engine opens its own outer "
                "socket under allow_own_socket, and a socket this host did not "
                "exclude sends the engine's own datagrams into the tunnel it "
                "carries");
  }

  std::ostringstream json;
  json << "{\"version\":\"" << kKeysVersion << "\""
       << ",\"role\":\"" << kRoleClient << "\""
       << ",\"gateway_id\":\"" << JsonEscape(Trim(keys.gateway_id)) << "\""
       << ",\"static_path\":\"" << JsonEscape(Trim(keys.static_path)) << "\""
       << ",\"gateway_static_path\":\""
       << JsonEscape(Trim(keys.gateway_static_path)) << "\""
       << ",\"admission_path\":\"" << JsonEscape(Trim(keys.admission_path))
       << "\"";
  if (!ed_path.empty()) {
    json << ",\"dual_auth_ed25519_pub_path\":\"" << JsonEscape(ed_path) << "\""
         << ",\"dual_auth_mldsa65_pub_path\":\"" << JsonEscape(ml_path) << "\"";
  }
  json << ",\"outer_socket_exclusion\":\""
       << JsonEscape(Trim(keys.outer_socket_exclusion)) << "\""
       << ",\"fast_pq\":" << (keys.fast_pq ? "true" : "false")
       << ",\"rekey_after_messages\":" << keys.rekey_after_messages << "}";
  *out = json.str();
  return true;
}

std::string DescribeLinuxWinn3Keys(const LinuxWinn3Keys& keys) {
  std::ostringstream out;
  out << "winn3 keys version=" << kKeysVersion << " role=" << Trim(keys.role)
      << " exclusion_declared="
      << (Trim(keys.outer_socket_exclusion).empty() ? "false" : "true")
      << " dual_auth="
      << (Trim(keys.dual_auth_ed25519_pub_path).empty() ? "false" : "true")
      << " fast_pq=" << (keys.fast_pq ? "true" : "false")
      << " rekey_lowered=" << (keys.rekey_after_messages != 0 ? "true"
                                                              : "false");
  return out.str();
}

bool WriteLinuxWinn3KeysDocument(const LinuxWinn3Keys& keys, std::string* path,
                                 std::string* error) {
  if (path == nullptr) return false;
  std::string document;
  if (!BuildLinuxWinn3KeysJson(keys, &document, error)) return false;

  const std::string directory = PrivateWinn3StateDirectory();
  if (directory.empty()) {
    return Fail(error,
                "Win's VPN has no private per-user directory in which to write "
                "the Winn v3 key document; refusing rather than falling back "
                "to a shared location such as /tmp, where a file naming every "
                "key on this device would hand an attacker the map");
  }
  if (!EnsurePrivateDirectory(directory, error)) return false;
  const std::string target = directory + "/" + kKeysFileName;
  const std::string temp = target + ".tmp";
  ::unlink(temp.c_str());
  // Mode 0600 from the moment the inode exists, so the document is never
  // briefly world-readable. O_NOFOLLOW refuses a symlink planted at the name;
  // O_CLOEXEC keeps it out of the engine we are about to exec -- which reads it
  // by PATH, under its own uid, exactly as intended.
  const int fd = ::open(temp.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
  if (fd < 0) {
    return Fail(error, "Could not create the Winn v3 key document at " + temp +
                           ": " + std::strerror(errno));
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
    return Fail(error, "Could not write the Winn v3 key document.");
  }
  if (::rename(temp.c_str(), target.c_str()) != 0) {
    ::unlink(temp.c_str());
    return Fail(error, "Could not install the Winn v3 key document at " +
                           target + ": " + std::strerror(errno));
  }
  *path = target;
  return true;
}

// ---------------------------------------------------------------------------
// The served `[winn]` section
//
// See the header for why this arrived on 2026-08-09 and what its absence meant.
// ---------------------------------------------------------------------------

namespace {

std::string LowerAscii(std::string value) {
  for (char& c : value) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return value;
}

std::vector<std::string> SplitCommaList(const std::string& value) {
  std::vector<std::string> out;
  size_t begin = 0;
  while (begin <= value.size()) {
    const size_t comma = value.find(',', begin);
    const size_t end = comma == std::string::npos ? value.size() : comma;
    const std::string item = Trim(value.substr(begin, end - begin));
    if (!item.empty()) out.push_back(item);
    if (comma == std::string::npos) break;
    begin = comma + 1;
  }
  return out;
}

// STRICT standard-alphabet base64, or false.
//
// Strict is load-bearing and the reason is the whole subject of this contract.
// Every byte-valued field on the ML-DSA-65-signed gateway descriptor is base64
// and reaches `[winn]` untouched; a lenient decoder that tolerated whitespace,
// the URL-safe alphabet or missing padding would turn a mangled descriptor
// value into PLAUSIBLE BYTES -- a tag the gateway cannot verify, and no answer
// from anywhere, on a network where "no answer" is what censorship looks like.
bool DecodeBase64(const std::string& value, std::string* out) {
  if (out == nullptr || value.empty() || value.size() % 4 != 0) return false;
  auto sextet = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  size_t padding = 0;
  while (padding < 2 && value.size() > padding &&
         value[value.size() - 1 - padding] == '=') {
    padding++;
  }
  std::string decoded;
  decoded.reserve(value.size() / 4 * 3);
  for (size_t i = 0; i < value.size(); i += 4) {
    uint32_t block = 0;
    int bits = 0;
    for (size_t j = 0; j < 4; ++j) {
      const char c = value[i + j];
      if (c == '=') {
        if (i + 4 != value.size() || j < 4 - padding) return false;
        block <<= 6;
        continue;
      }
      const int s = sextet(c);
      if (s < 0) return false;
      block = (block << 6) | static_cast<uint32_t>(s);
      bits += 6;
    }
    for (int shift = 16, produced = 0; produced < bits / 8;
         shift -= 8, ++produced) {
      decoded.push_back(static_cast<char>((block >> shift) & 0xFF));
    }
  }
  *out = decoded;
  return true;
}

std::string LowerHex(const std::string& raw) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(raw.size() * 2);
  for (size_t i = 0; i < raw.size(); ++i) {
    const unsigned char byte = static_cast<unsigned char>(raw[i]);
    out[i * 2] = kDigits[byte >> 4];
    out[i * 2 + 1] = kDigits[byte & 0x0F];
  }
  return out;
}

// The value of one key in one section, or empty.
std::string WinnSectionValue(const std::string& raw_config,
                             const std::string& want_key) {
  std::string section;
  size_t begin = 0;
  while (begin <= raw_config.size()) {
    const size_t newline = raw_config.find('\n', begin);
    const size_t end =
        newline == std::string::npos ? raw_config.size() : newline;
    const std::string line = Trim(raw_config.substr(begin, end - begin));
    begin = newline == std::string::npos ? raw_config.size() + 1 : newline + 1;
    if (line.empty() || line.front() == '#' || line.front() == ';') continue;
    if (line.size() >= 3 && line.front() == '[' && line.back() == ']') {
      section = LowerAscii(line.substr(1, line.size() - 2));
      continue;
    }
    if (section != "winn") continue;
    const auto equals = line.find('=');
    if (equals != std::string::npos &&
        LowerAscii(Trim(line.substr(0, equals))) == want_key) {
      return Trim(line.substr(equals + 1));
    }
  }
  return std::string();
}

// Writes one secret 0600, mode set before any byte exists at the name.
bool WriteSecretFile(const std::string& target, const std::string& contents,
                     std::string* error) {
  const std::string temp = target + ".tmp";
  ::unlink(temp.c_str());
  const int fd = ::open(temp.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
  if (fd < 0) {
    return Fail(error, "Could not create the Winn v3 key file at " + temp +
                           ": " + std::strerror(errno));
  }
  size_t written = 0;
  bool ok = true;
  while (written < contents.size()) {
    const ssize_t count =
        ::write(fd, contents.data() + written, contents.size() - written);
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
    return Fail(error, "Could not write the Winn v3 key file.");
  }
  if (::rename(temp.c_str(), target.c_str()) != 0) {
    ::unlink(temp.c_str());
    return Fail(error, "Could not install the Winn v3 key file at " + target +
                           ": " + std::strerror(errno));
  }
  return true;
}

}  // namespace

bool LinuxConfigSelectsWinn3(const std::string& raw_config) {
  return LowerAscii(WinnSectionValue(raw_config, "carrier")) ==
         kLinuxWinnCarrierWinn3;
}

bool NormalizeLinuxWinn3NodeIdentity(const std::string& raw,
                                     std::string* out) {
  if (out == nullptr) return false;
  out->clear();
  for (char ch : raw) {
    if (static_cast<unsigned char>(ch) > 0x7f) return false;
  }
  const std::string trimmed = Trim(raw);
  if (trimmed.size() < 2 || trimmed.size() > 40) return false;
  std::string lowered;
  lowered.reserve(trimmed.size());
  for (char ch : trimmed) {
    const unsigned char value = static_cast<unsigned char>(ch);
    lowered.push_back(value >= 'A' && value <= 'Z'
                          ? static_cast<char>(value + ('a' - 'A'))
                          : static_cast<char>(value));
  }
  const unsigned char first = static_cast<unsigned char>(lowered.front());
  if (!((first >= 'a' && first <= 'z') ||
        (first >= '0' && first <= '9'))) {
    return false;
  }
  for (size_t index = 1; index < lowered.size(); ++index) {
    const unsigned char value = static_cast<unsigned char>(lowered[index]);
    if ((value >= 'a' && value <= 'z') ||
        (value >= '0' && value <= '9') || value == '-') {
      continue;
    }
    return false;
  }
  *out = lowered;
  return true;
}

bool ParseLinuxWinn3Section(const std::string& raw_config,
                            LinuxWinn3Params* params,
                            LinuxWinn3ServedKeyMaterial* material,
                            std::string* error) {
  if (params == nullptr || material == nullptr) {
    return Fail(error, "no winn/3 configuration to fill");
  }
  *params = LinuxWinn3Params();
  *material = LinuxWinn3ServedKeyMaterial();
  if (!LinuxConfigSelectsWinn3(raw_config)) {
    return Fail(error,
                "this configuration does not select Winn Protocol v3: [winn] "
                "carrier is not \"winn3\"");
  }

  LinuxWinn3Params parsed;
  LinuxWinn3ServedKeyMaterial keys;
  std::string gateway_id_b64;
  std::string static_b64;
  std::string gateway_static_b64;
  std::string admission_b64;
  std::string auth_ed25519_b64;
  std::string auth_mldsa65_b64;
  bool saw_descriptor_node = false;
  bool saw_selected_node = false;

  std::string section;
  size_t begin = 0;
  while (begin <= raw_config.size()) {
    const size_t newline = raw_config.find('\n', begin);
    const size_t end =
        newline == std::string::npos ? raw_config.size() : newline;
    const std::string line = Trim(raw_config.substr(begin, end - begin));
    begin = newline == std::string::npos ? raw_config.size() + 1 : newline + 1;
    if (line.empty() || line.front() == '#' || line.front() == ';') continue;
    if (line.size() >= 3 && line.front() == '[' && line.back() == ']') {
      section = LowerAscii(line.substr(1, line.size() - 2));
      continue;
    }
    if (section != "winn") continue;
    const auto equals = line.find('=');
    if (equals == std::string::npos) {
      return Fail(error, "the [winn] line \"" + line + "\" is not key = value");
    }
    const std::string key = LowerAscii(Trim(line.substr(0, equals)));
    const std::string value = Trim(line.substr(equals + 1));

    if (key == "enabled") {
      const std::string lowered = LowerAscii(value);
      if (lowered != "true" && lowered != "false" && lowered != "1" &&
          lowered != "0" && lowered != "yes" && lowered != "no") {
        return Fail(error, "[winn] enabled is neither true nor false");
      }
    } else if (key == "carrier") {
      if (LowerAscii(value) != kLinuxWinnCarrierWinn3) {
        return Fail(error, "[winn] carrier is \"" + value +
                               "\", which does not select Winn Protocol v3");
      }
    } else if (key == "endpoint") {
      parsed.gateway_endpoint = value;
    } else if (key == "inner_v4") {
      parsed.inner_address = value;
    } else if (key == "inner_router_v4") {
      parsed.inner_next_hop = value;
    } else if (key == "inner_resolver_v4") {
      // KNOWN, STORED, AND CONSUMED BY DERIVATION. See
      // LinuxWinn3Params::inner_resolver. The key had to be recognised BEFORE
      // the control plane emitted it, or the `else` below would refuse the
      // entire served configuration and standalone v3 would stop working on
      // Linux the day the descriptor bumps. Since 2026-08-12 the value is also
      // carried into PostureInput and derived against in winn3_posture.h's
      // `namespace resolvers`. Absent from every descriptor signed to date, so
      // this branch is still unreachable in the field today.
      parsed.inner_resolver = value;
    } else if (key == "static_private") {
      static_b64 = value;
    } else if (key == "gateway_static") {
      gateway_static_b64 = value;
    } else if (key == "gateway_id") {
      gateway_id_b64 = value;
    } else if (key == "admission_key") {
      admission_b64 = value;
    } else if (key == "auth_ed25519") {
      auth_ed25519_b64 = value;
    } else if (key == "auth_mldsa65") {
      auth_mldsa65_b64 = value;
    } else if (key == "path_mtu") {
      if (value.empty()) {
        return Fail(error, "[winn] path_mtu is empty");
      }
      char* stop = nullptr;
      const long number = std::strtol(value.c_str(), &stop, 10);
      if (stop == nullptr || *stop != '\0' || number <= 0 || number > 65535) {
        return Fail(error, "[winn] path_mtu is not a usable number");
      }
      parsed.path_mtu = static_cast<int>(number);
    } else if (key == "carrier_classes") {
      parsed.carrier_classes = SplitCommaList(LowerAscii(value));
    } else if (key == "session_id") {
      parsed.session_id = value;
    } else if (key == "node") {
      if (saw_descriptor_node) {
        return Fail(error, "[winn] node is duplicated");
      }
      saw_descriptor_node = true;
      if (!NormalizeLinuxWinn3NodeIdentity(value, &parsed.descriptor_node)) {
        return Fail(error,
                    "[winn] node is not a strict ASCII node identity");
      }
    } else if (key == "selected_node") {
      if (saw_selected_node) {
        return Fail(error, "[winn] selected_node is duplicated");
      }
      saw_selected_node = true;
      if (!NormalizeLinuxWinn3NodeIdentity(value, &parsed.selected_node)) {
        return Fail(error,
                    "[winn] selected_node is not a strict ASCII node identity");
      }
    } else if (key == "psk") {
      // Optional, absent in the shipping deployment, and consumed by the engine
      // rather than by this host. Named so it is a KNOWN key: an unrecognised
      // one is a refusal here, so leaving it out would turn a perfectly good
      // served config into a Linux-only failure.
    } else {
      return Fail(error,
                  "[winn] carries the unrecognised key \"" + key +
                      "\". It is refused rather than ignored, because a dropped "
                      "key looks exactly like a key that took effect, and the "
                      "two that could silently not take effect here are the "
                      "migration plan and the inner address.");
    }
  }

  std::string host;
  std::string port;
  if (Trim(parsed.descriptor_node).empty() ||
      Trim(parsed.selected_node).empty() ||
      parsed.descriptor_node != parsed.selected_node) {
    return Fail(error,
                "[winn] signed descriptor node and selected node must both "
                "be present and match");
  }
  if (!SplitLinuxWinn3Endpoint(parsed.gateway_endpoint, &host, &port)) {
    return Fail(error,
                "[winn] endpoint must be an IP literal with a port. A hostname "
                "here would be resolved on the censored path, for a tunnel "
                "whose staged posture exists so that no resolver is touched "
                "until the datapath is proven.");
  }
  if (Trim(parsed.inner_address).empty()) {
    return Fail(error,
                "[winn] inner_v4 is absent; the inner address comes from the "
                "ML-DSA-65-signed gateway descriptor and nothing else in this "
                "configuration carries it. A v3 session shares no address space "
                "with the AmneziaWG relay, and the winn/3 tun layer drops every "
                "packet whose source does not match its assignment.");
  }
  if (Trim(parsed.inner_next_hop).empty()) {
    return Fail(error,
                "[winn] inner_router_v4 is absent; it is the inner next hop and "
                "the only included route a bootstrap posture may carry");
  }
  if (parsed.carrier_classes.empty()) {
    return Fail(error,
                "[winn] carrier_classes names no classes. It must name EVERY "
                "class the session may escalate to, because the message floor "
                "-- and therefore the interface MTU -- is computed over it, and "
                "a floor computed over nothing guarantees nothing.");
  }
  for (const std::string& entry : parsed.carrier_classes) {
    if (entry != "udp" && entry != "tcp" && entry != "tls") {
      return Fail(error, "[winn] carrier_classes names the unknown class \"" +
                             entry + "\"; use udp, tcp or tls");
    }
  }

  // THE DESCRIPTOR BOUNDARY, AND THE ONLY DECODE OF gateway_id.
  //
  // It is base64 over the OPERATOR'S GATEWAY NAME because the signed descriptor
  // carries every byte-valued field that way. The engine takes the name's RAW
  // BYTES: it is an authenticated input to the admission tag and is never
  // transmitted, so a second decode is not a loud mistake -- `winsgw01` is
  // eight characters of the base64 alphabet, and the wrong answer is six
  // plausible bytes and a gateway that never answers.
  if (Trim(gateway_id_b64).empty()) {
    return Fail(error,
                "[winn] gateway_id is absent; it binds an admission tag to one "
                "gateway so an initiation captured at A cannot be replayed at B");
  }
  std::string gateway_name;
  if (!DecodeBase64(Trim(gateway_id_b64), &gateway_name) ||
      gateway_name.empty()) {
    return Fail(error,
                "[winn] gateway_id is not usable: the signed descriptor carries "
                "it base64-encoded over the operator's gateway name, and this "
                "value does not decode to one. The engine is handed the decoded "
                "name, byte for byte what the gateway itself is configured "
                "with, because the admission tag is computed over it and is "
                "never transmitted.");
  }
  parsed.keys.gateway_id = gateway_name;
  parsed.keys.role = kRoleClient;

  const struct {
    const char* key;
    const std::string* value;
    std::string* out;
    size_t exact_bytes;  // 0 means "any non-empty length"
    const char* role;
  } required[] = {
      {"static_private", &static_b64, &keys.static_private, 32,
       "this device's 32-byte X25519 private key"},
      {"gateway_static", &gateway_static_b64, &keys.gateway_static, 32,
       "the gateway's 32-byte X25519 public key; a client authenticates the "
       "gateway by its static key and there is no anonymous mode"},
      // NOT 32, and this is the one that matters most. The admission secret is
      // OPAQUE: keygen writes 64 ASCII hex characters and every consumer keys
      // with those characters, never with the 32 bytes they encode. Requiring
      // 32 here would enforce the exact defect -- a gateway that admits the
      // datagram, BUILDS a session, and then goes completely silent.
      {"admission_key", &admission_b64, &keys.admission_secret, 0,
       "the admission secret's own bytes, opaque and never decoded again"},
  };
  for (const auto& item : required) {
    if (Trim(*item.value).empty()) {
      return Fail(error, std::string("[winn] ") + item.key +
                             " is absent; it must carry base64 over " +
                             item.role);
    }
    std::string raw;
    if (!DecodeBase64(Trim(*item.value), &raw) || raw.empty()) {
      return Fail(error,
                  std::string("[winn] ") + item.key +
                      " is not base64. Every byte-valued field on the signed "
                      "gateway descriptor is base64-encoded and reaches the "
                      "[winn] section untouched.");
    }
    if (item.exact_bytes != 0 && raw.size() != item.exact_bytes) {
      return Fail(error, std::string("[winn] ") + item.key + " decodes to " +
                             std::to_string(raw.size()) +
                             " bytes; it must be " +
                             std::to_string(item.exact_bytes) + " -- " +
                             item.role);
    }
    *item.out = raw;
  }

  const bool ed_empty = Trim(auth_ed25519_b64).empty();
  const bool ml_empty = Trim(auth_mldsa65_b64).empty();
  if (ed_empty != ml_empty) {
    return Fail(error,
                "[winn] auth_ed25519 and auth_mldsa65 are the optional pair "
                "and must be both present or both absent");
  }
  if (!ed_empty) {
    std::string ed_raw;
    std::string ml_raw;
    if (!DecodeBase64(Trim(auth_ed25519_b64), &ed_raw) || ed_raw.empty()) {
      return Fail(error,
                  "[winn] auth_ed25519 is not base64. Every byte-valued field "
                  "on the signed gateway descriptor is base64-encoded and "
                  "reaches the [winn] section untouched.");
    }
    if (!DecodeBase64(Trim(auth_mldsa65_b64), &ml_raw) || ml_raw.empty()) {
      return Fail(error,
                  "[winn] auth_mldsa65 is not base64. Every byte-valued field "
                  "on the signed gateway descriptor is base64-encoded and "
                  "reaches the [winn] section untouched.");
    }
    if (ed_raw.size() != kDualAuthEd25519Bytes) {
      return Fail(error, "[winn] auth_ed25519 decodes to " +
                             std::to_string(ed_raw.size()) +
                             " bytes; it must be " +
                             std::to_string(kDualAuthEd25519Bytes) +
                             " -- the gateway's Ed25519 attestation public key");
    }
    if (ml_raw.size() != kDualAuthMldsa65Bytes) {
      return Fail(error, "[winn] auth_mldsa65 decodes to " +
                             std::to_string(ml_raw.size()) +
                             " bytes; it must be " +
                             std::to_string(kDualAuthMldsa65Bytes) +
                             " -- the gateway's ML-DSA-65 attestation public "
                             "key");
    }
    keys.auth_ed25519_hex = LowerHex(ed_raw);
    keys.auth_mldsa65_hex = LowerHex(ml_raw);
  }

  *params = parsed;
  *material = keys;
  return true;
}

bool ValidateLinuxWinn3IndependentSelectedNode(
    const std::string& raw_config, const std::string& caller_selected_node,
    std::string* error) {
  LinuxWinn3Params parsed;
  LinuxWinn3ServedKeyMaterial material;
  if (!ParseLinuxWinn3Section(raw_config, &parsed, &material, error)) {
    return false;
  }
  std::string normalized_caller;
  if (!NormalizeLinuxWinn3NodeIdentity(caller_selected_node,
                                       &normalized_caller) ||
      normalized_caller != parsed.descriptor_node ||
      normalized_caller != parsed.selected_node) {
    return Fail(error,
                "independently selected node must be a strict ASCII identity "
                "and match both signed descriptor node fields; missing, "
                "conflicting, or Unicode caller identity is refused before "
                "tunnel start");
  }
  return true;
}

bool WriteLinuxWinn3KeyFiles(const LinuxWinn3ServedKeyMaterial& material,
                             LinuxWinn3Params* params, std::string* error) {
  if (params == nullptr) return false;
  const std::string directory = PrivateWinn3StateDirectory();
  if (directory.empty()) {
    return Fail(error,
                "Win's VPN has no private per-user directory in which to write "
                "the Winn v3 key files; refusing rather than falling back to a "
                "shared location such as /tmp");
  }
  // CREATE THE DIRECTORY FIRST, 2026-08-21 (app-level live-test lane).
  // WriteSecretFile opens its temporary file directly under this directory
  // and creates nothing, so on a machine where no v3 session has ever run --
  // which is every machine before the first -- the open fails ENOENT. This is
  // the exact defect the keys-DOCUMENT writer already documents and repairs
  // for itself (EnsurePrivateDirectory in WriteLinuxWinn3KeysDocument); the
  // key-FILES writer runs FIRST on the served path, so it must ensure the
  // directory too, or the first real call is also the first failure.
  if (!EnsurePrivateDirectory(directory, error)) return false;
  const struct {
    const char* name;
    const std::string* contents;
    std::string* path;
  } files[] = {
      {"static.key", &material.static_private, &params->keys.static_path},
      {"gateway.pub", &material.gateway_static,
       &params->keys.gateway_static_path},
      {"admission.key", &material.admission_secret,
       &params->keys.admission_path},
  };
  for (const auto& file : files) {
    if (file.contents->empty()) {
      return Fail(error, std::string("the Winn v3 key material for ") +
                             file.name +
                             " is empty; this did not come from "
                             "ParseLinuxWinn3Section, which refuses that");
    }
    const std::string target = directory + "/" + file.name;
    if (!WriteSecretFile(target, *file.contents, error)) return false;
    *file.path = target;
  }
  const bool ed_empty = material.auth_ed25519_hex.empty();
  const bool ml_empty = material.auth_mldsa65_hex.empty();
  if (ed_empty != ml_empty) {
    return Fail(error,
                "the Winn v3 dual-auth pair is half-provisioned; this did not "
                "come from ParseLinuxWinn3Section, which refuses that");
  }
  const std::string ed_target = directory + "/" + kDualAuthEd25519File;
  const std::string ml_target = directory + "/" + kDualAuthMldsa65File;
  if (ed_empty) {
    ::unlink(ed_target.c_str());
    ::unlink(ml_target.c_str());
    params->keys.dual_auth_ed25519_pub_path.clear();
    params->keys.dual_auth_mldsa65_pub_path.clear();
  } else {
    if (!WriteSecretFile(ed_target, material.auth_ed25519_hex, error)) {
      return false;
    }
    if (!WriteSecretFile(ml_target, material.auth_mldsa65_hex, error)) {
      return false;
    }
    params->keys.dual_auth_ed25519_pub_path = ed_target;
    params->keys.dual_auth_mldsa65_pub_path = ml_target;
  }
  return true;
}

// ---------------------------------------------------------------------------
// The create document
// ---------------------------------------------------------------------------

bool SplitLinuxWinn3Endpoint(const std::string& endpoint, std::string* host,
                             std::string* port) {
  if (host == nullptr || port == nullptr) return false;
  const std::string value = Trim(endpoint);
  if (value.empty()) return false;
  std::string host_part;
  std::string port_part;
  if (value.front() == '[') {
    const auto close = value.find(']');
    if (close == std::string::npos || close + 2 >= value.size() ||
        value[close + 1] != ':') {
      return false;
    }
    host_part = value.substr(1, close - 1);
    port_part = value.substr(close + 2);
    if (!IsIpv6Literal(host_part)) return false;
  } else {
    const auto colon = value.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= value.size()) {
      return false;
    }
    host_part = value.substr(0, colon);
    port_part = value.substr(colon + 1);
    if (!IsIpv4Literal(host_part)) return false;
  }
  if (port_part.empty() || port_part.size() > 5) return false;
  int port_value = 0;
  for (const char c : port_part) {
    if (c < '0' || c > '9') return false;
    port_value = port_value * 10 + (c - '0');
  }
  if (port_value <= 0 || port_value > 65535) return false;
  *host = host_part;
  *port = port_part;
  return true;
}

bool BuildLinuxWinn3CreateJson(const LinuxWinn3Params& params,
                               std::string* out, std::string* error) {
  if (out == nullptr) return false;

  std::string host;
  std::string port;
  if (!SplitLinuxWinn3Endpoint(params.gateway_endpoint, &host, &port)) {
    return Fail(error,
                "the Winn v3 gateway endpoint must be an IP literal with a "
                "port: a hostname here is a DNS lookup on the censored path, "
                "which is the observable the staged posture exists to avoid");
  }
  if (Trim(params.inner_address).empty()) {
    return Fail(error,
                "a Winn v3 session needs an assigned inner address: the "
                "inner-IP validator's whole job is to refuse a packet "
                "addressed to somebody else, and it validates against the "
                "ADDRESS rather than the prefix");
  }
  if (params.carrier_classes.empty()) {
    return Fail(error,
                "a Winn v3 session needs a migration plan naming every carrier "
                "class it may escalate to");
  }

  const int path_mtu =
      params.path_mtu > 0 ? params.path_mtu : sizing::kDefaultPathMtu;
  int inner_mtu = 0;
  if (!sizing::PlanFloorInnerMtu(path_mtu, params.carrier_classes, &inner_mtu,
                                 error)) {
    return false;
  }

  std::ostringstream json;
  // Key order is WinnV3EngineConfig.toJson()'s, verbatim, so the Android and
  // Linux create payloads can be diffed byte for byte in review.
  json << "{\"payload\":\"" << kPayloadIpPacket << "\""
       << ",\"gateway_endpoint\":\"" << JsonEscape(Trim(params.gateway_endpoint))
       << "\""
       << ",\"inner_address\":\"" << JsonEscape(Trim(params.inner_address))
       << "\""
       << ",\"inner_next_hop\":\"" << JsonEscape(Trim(params.inner_next_hop))
       << "\""
       << ",\"inner_mtu\":" << inner_mtu << ",\"path_mtu\":" << path_mtu
       << ",\"carrier_classes\":[";
  for (size_t i = 0; i < params.carrier_classes.size(); ++i) {
    if (i > 0) json << ",";
    json << "\"" << JsonEscape(Trim(params.carrier_classes[i])) << "\"";
  }
  json << "]"
       << ",\"session_id\":\"" << JsonEscape(Trim(params.session_id)) << "\""
       // TRUE, and honest only because the caller installed the
       // destination-scoped exclusion first and declared it in the key
       // document. `-transport stdio` cannot carry a descriptor, so the engine
       // opens its own socket, and this is the only combination refusal 4
       // admits. It is deliberately NOT the Android value: there the host
       // protects the socket with VpnService.protect and hands the descriptor
       // over, so Android emits false.
       << ",\"allow_own_socket\":true"
       // FALSE. This host owns the device; an engine that also opened one would
       // be two devices for one tunnel.
       << ",\"owns_tun\":false}";
  *out = json.str();

  // Belt and braces against a future edit: the v1 payload class must not be
  // reachable from this function. A v1 engine fed inner IP packets forwards
  // them to the gateway in cleartext, which is the worst outcome on this
  // threat model, so it is worth one string search of our own document.
  if (out->find(kPayloadAwgDatagram) != std::string::npos) {
    out->clear();
    return Fail(error,
                "refusing to emit a Winn v3 create document that names the "
                "winn/1 relay payload class");
  }
  return true;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

std::string DescribeLinuxWinn3Exclusion(const LinuxWinn3Params& params) {
  std::string host;
  std::string port;
  if (!SplitLinuxWinn3Endpoint(params.gateway_endpoint, &host, &port)) {
    return std::string();
  }
  const std::string next_hop = Trim(params.physical_next_hop);
  const std::string device = Trim(params.physical_interface);
  if (device.empty()) return std::string();
  // A sentence, not a command. The engine does not parse it; it is echoed in
  // the status document so the claim sits beside the counters it explains.
  //
  // ON-LINK GATEWAYS, added 2026-08-21 (app-level live-test lane). A gateway
  // on the host's own subnet has no next hop -- `ip route get <host>` returns
  // `dev <iface>` with no `via` -- and the previous rule ("no next hop means
  // no exclusion") refused every such topology. The exclusion an on-link
  // gateway needs is the direct-device form the renderer below emits: the /32
  // on the physical interface, which still beats the promoted 0.0.0.0/1 pair
  // on specificity.
  const std::string route = next_hop.empty()
                                ? "host route " + host + "/32 dev " + device +
                                      " (on-link)"
                                : "host route " + host + "/32 via " + next_hop +
                                      " dev " + device;
  return route +
         " (destination-scoped: there is no awg-quick fwmark in a standalone "
         "v3 session, and a /32 beats the promoted 0.0.0.0/1 pair on "
         "specificity)";
}

std::vector<std::vector<std::string>> RenderLinuxWinn3ExclusionCommands(
    const LinuxWinn3Params& params) {
  std::vector<std::vector<std::string>> commands;
  std::string host;
  std::string port;
  if (!SplitLinuxWinn3Endpoint(params.gateway_endpoint, &host, &port)) {
    return commands;
  }
  const std::string next_hop = Trim(params.physical_next_hop);
  const std::string device = Trim(params.physical_interface);
  if (device.empty()) return commands;
  const bool v6 = IsIpv6Literal(host);
  const std::string prefix = host + (v6 ? "/128" : "/32");
  if (next_hop.empty()) {
    // ON-LINK GATEWAYS, added 2026-08-21 (app-level live-test lane). A
    // gateway on the host's own subnet is reached directly through the
    // physical interface, so the exclusion is the same /32 pinned to `dev`
    // with no `via` -- the direct route keeps the engine's outer socket off
    // the tunnel exactly as the routed form does, and `ip route del` matches
    // the identical vector at teardown, so the repair-before-add probe stays
    // exact.
    commands.push_back({"ip", v6 ? "-6" : "-4", "route", "add", prefix, "dev",
                        device});
  } else {
    commands.push_back({"ip", v6 ? "-6" : "-4", "route", "add", prefix, "via",
                        next_hop, "dev", device});
  }
  return commands;
}

std::vector<std::vector<std::string>> RenderLinuxWinn3ExclusionTeardown(
    const LinuxWinn3Params& params) {
  std::vector<std::vector<std::string>> commands;
  for (std::vector<std::string> argv :
       RenderLinuxWinn3ExclusionCommands(params)) {
    // Same vector with `add` replaced by `del`, so the two can never describe
    // different routes.
    for (std::string& token : argv) {
      if (token == "add") token = "del";
    }
    commands.push_back(argv);
  }
  return commands;
}

winsvpn::winn3::PostureInput LinuxWinn3PostureInput(
    const LinuxWinn3Params& params) {
  winsvpn::winn3::PostureInput input;
  const std::string inner = Trim(params.inner_address);
  const std::string hop = Trim(params.inner_next_hop);
  if (inner.find(':') != std::string::npos) {
    input.inner_v6 = inner;
    input.router_v6 = hop;
  } else {
    input.inner_v4 = inner;
    input.router_v4 = hop;
  }
  input.outer_socket_exclusion = DescribeLinuxWinn3Exclusion(params);
  input.full_routes = params.full_routes;
  input.dns_servers = params.dns_servers;
  input.dns_servers_are_inner = params.dns_servers_are_inner;
  // The signed resolver, carried across so winn3_posture.h can DERIVE
  // inner-ness from it. Both fields are passed and neither is translated into
  // the other: `dns_servers_are_inner` is the local declaration and stays
  // exactly that, and the derived path in BuildPromotedPosture does not consult
  // it. Empty on every descriptor signed to date, and empty selects the
  // declaration path -- the behaviour this function had before the field
  // existed. Windows does the same in PostureInputFrom, in the same words.
  input.inner_resolver_v4 = params.inner_resolver;
  return input;
}

const char* LinuxWinn3ResolverMechanismName(
    LinuxWinn3ResolverMechanism value) {
  switch (value) {
    case LinuxWinn3ResolverMechanism::kSystemdResolved:
      return "systemd-resolved";
    case LinuxWinn3ResolverMechanism::kResolvconf:
      return "resolvconf";
    case LinuxWinn3ResolverMechanism::kResolvConfFile:
      return "resolv.conf";
    case LinuxWinn3ResolverMechanism::kNone:
      return "none";
    case LinuxWinn3ResolverMechanism::kUnknown:
      break;
  }
  return "unknown";
}

const char* LinuxWinn3PostureOutcomeName(LinuxWinn3PostureOutcome value) {
  switch (value) {
    case LinuxWinn3PostureOutcome::kApplied:
      return "applied";
    case LinuxWinn3PostureOutcome::kNotAttempted:
      return "not-attempted";
    case LinuxWinn3PostureOutcome::kRolledBack:
      return "rolled-back";
    case LinuxWinn3PostureOutcome::kExclusionBlocked:
      return "exclusion-blocked";
    case LinuxWinn3PostureOutcome::kPartiallyApplied:
      break;
  }
  return "partially-applied";
}

// The persistent backup of the user's own /etc/resolv.conf.
//
// NOT under /run. /run is a tmpfs, and a reboot would destroy the only copy of
// the user's resolvers while leaving the tunnel's resolvers in /etc -- turning
// a recoverable state into a permanent one, which is the opposite of what a
// backup is for.
// Declared extern in the header so linux_tunnel_backend.cc's privileged argv
// allowlist pins the EXACT same strings the renderer emits (a literal copy in
// that file would drift silently and the posture would refuse with a message
// that reads like a host defect). `const` alone at namespace scope would give
// these internal linkage and the backend TU would see a different, undefined
// symbol.
extern const char kResolvConfPath[] = "/etc/resolv.conf";
extern const char kResolvConfBackupDir[] = "/var/lib/winsvpn";
extern const char kResolvConfBackup[] = "/var/lib/winsvpn/winn3-resolv.conf.orig";

// The body written to /etc/resolv.conf, which explains itself.
//
// A user whose name resolution has stopped working reads the cause out of the
// file that is causing it, and an operator gets the absolute path of the
// original without needing this source. That is the whole mitigation for the
// one window this mechanism has.
std::string RenderResolvConfBody(const winsvpn::winn3::PosturePlan& plan) {
  std::string body;
  body += "# Written by Win's VPN (Winn Protocol v3) when the tunnel was\n";
  body += "# promoted. The resolvers below are reachable ONLY through the\n";
  body += "# tunnel and will not answer once it stops.\n";
  body += "#\n";
  body += "# Your original file was saved to:\n";
  body += "#   ";
  body += kResolvConfBackup;
  body += "\n";
  body += "# It is restored automatically when the tunnel stops, and also on\n";
  body += "# the next start if the tunnel was killed before it could. If you\n";
  body += "# are reading this with no tunnel running, copy that file back\n";
  body += "# over this one.\n";
  for (const std::string& resolver : plan.dns_servers) {
    body += "nameserver " + resolver + "\n";
  }
  return body;
}

std::vector<LinuxWinn3Command> RenderLinuxWinn3ResolverCommands(
    const std::string& interface_name, const winsvpn::winn3::PosturePlan& plan,
    LinuxWinn3ResolverMechanism mechanism) {
  std::vector<LinuxWinn3Command> commands;
  if (plan.dns_servers.empty()) return commands;

  switch (mechanism) {
    case LinuxWinn3ResolverMechanism::kSystemdResolved: {
      LinuxWinn3Command dns;
      dns.argv = {"resolvectl", "dns", interface_name};
      for (const std::string& resolver : plan.dns_servers) {
        dns.argv.push_back(resolver);
      }
      commands.push_back(dns);
      // `~.` makes this link's resolvers authoritative for ALL names. Without
      // it systemd-resolved keeps using the machine's existing resolvers for
      // anything outside the link's own search domain, which is name
      // resolution over the censored path -- exactly what installing resolvers
      // at promotion is for.
      LinuxWinn3Command domain;
      domain.argv = {"resolvectl", "domain", interface_name, "~."};
      commands.push_back(domain);
      return commands;
    }
    case LinuxWinn3ResolverMechanism::kResolvconf: {
      // openresolv has NO argument form: the resolv.conf body goes in on
      // standard input. `-m 0` gives the tunnel the lowest metric, which
      // openresolv orders FIRST, so the tunnel's resolvers are consulted ahead
      // of the physical link's rather than after them -- the same job `~.`
      // does on the systemd-resolved path. `-x` marks them exclusive, which is
      // what actually stops the physical link's resolvers being used at all,
      // and it is the flag wg-quick uses for the identical reason.
      LinuxWinn3Command add;
      add.argv = {"resolvconf", "-a", interface_name, "-m", "0", "-x"};
      for (const std::string& resolver : plan.dns_servers) {
        add.stdin_bytes += "nameserver " + resolver + "\n";
      }
      commands.push_back(add);
      return commands;
    }
    case LinuxWinn3ResolverMechanism::kResolvConfFile: {
      // 1. The backup directory. `mkdir -p` is idempotent and says nothing
      //    about whether a previous session left anything behind.
      LinuxWinn3Command make_dir;
      make_dir.argv = {"mkdir", "-p", kResolvConfBackupDir};
      commands.push_back(make_dir);

      // 2. REPAIR BEFORE BACKUP. A backup that already exists means a previous
      //    session was killed before its teardown ran, so /etc/resolv.conf is
      //    currently a TUNNEL's file and backing it up would overwrite the
      //    user's own resolvers with a dead tunnel's. Restoring first makes
      //    the backup always the user's file no matter how the last session
      //    ended. Best effort: on a first-ever run there is nothing to
      //    restore and `cp` fails, which is the normal case rather than an
      //    error.
      LinuxWinn3Command repair;
      repair.argv = {"cp", "-f", kResolvConfBackup, kResolvConfPath};
      repair.best_effort = true;
      commands.push_back(repair);

      // 3. The backup itself, and this one MUST succeed: writing the tunnel's
      //    resolvers without having saved the user's is precisely the
      //    stranding this mechanism is designed not to do.
      LinuxWinn3Command backup;
      backup.argv = {"cp", "-f", kResolvConfPath, kResolvConfBackup};
      commands.push_back(backup);

      // 4. The rewrite. `tee` writes through the existing inode rather than
      //    replacing it, so a bind mount or an open reader keeps working, and
      //    the body carries its own restore instructions.
      LinuxWinn3Command write;
      write.argv = {"tee", kResolvConfPath};
      write.stdin_bytes = RenderResolvConfBody(plan);
      commands.push_back(write);
      return commands;
    }
    case LinuxWinn3ResolverMechanism::kNone:
    case LinuxWinn3ResolverMechanism::kUnknown:
      // Never "install nothing and promote anyway". The caller refuses on the
      // mechanism before it reaches a renderer, and BuildPromotedPosture has
      // already refused an empty resolver set before that.
      return commands;
  }
  return commands;
}

std::vector<LinuxWinn3Command> RenderLinuxWinn3ResolverTeardown(
    const std::string& interface_name, LinuxWinn3ResolverMechanism mechanism) {
  std::vector<LinuxWinn3Command> commands;
  switch (mechanism) {
    case LinuxWinn3ResolverMechanism::kSystemdResolved: {
      LinuxWinn3Command revert;
      revert.argv = {"resolvectl", "revert", interface_name};
      revert.best_effort = true;
      commands.push_back(revert);
      return commands;
    }
    case LinuxWinn3ResolverMechanism::kResolvconf: {
      LinuxWinn3Command del;
      del.argv = {"resolvconf", "-d", interface_name, "-f"};
      del.best_effort = true;
      commands.push_back(del);
      return commands;
    }
    case LinuxWinn3ResolverMechanism::kResolvConfFile: {
      // The restore is NOT best effort. It is the only command in any teardown
      // whose failure leaves the user worse off than before the session
      // started, because its residue is a file rather than a route on a device
      // that has already gone away.
      LinuxWinn3Command restore;
      restore.argv = {"cp", "-f", kResolvConfBackup, kResolvConfPath};
      commands.push_back(restore);
      // Removed only AFTER the restore, and best effort: a leftover backup is
      // harmless -- the next promotion treats it as a repair and restores it
      // again -- while removing it before the restore would destroy the only
      // copy.
      LinuxWinn3Command drop;
      drop.argv = {"rm", "-f", kResolvConfBackup};
      drop.best_effort = true;
      commands.push_back(drop);
      return commands;
    }
    case LinuxWinn3ResolverMechanism::kNone:
    case LinuxWinn3ResolverMechanism::kUnknown:
      return commands;
  }
  return commands;
}

LinuxWinn3ResolverMechanism DetectLinuxWinn3ResolverMechanism(
    const LinuxWinn3Params& params, const LinuxWinn3PrivilegedRunner& run,
    std::string* detail) {
  const auto say = [detail](const std::string& text) {
    if (detail != nullptr) *detail = text;
  };
  if (params.resolver_mechanism_override !=
      LinuxWinn3ResolverMechanism::kUnknown) {
    // Pinned, and NOT verified -- that is what pinning means. Said out loud in
    // the detail so a log never shows a mechanism without showing that nothing
    // probed for it.
    say(std::string("the resolver mechanism was pinned to '") +
        LinuxWinn3ResolverMechanismName(params.resolver_mechanism_override) +
        "' by configuration, so this host probed for nothing");
    return params.resolver_mechanism_override;
  }
  if (!run) {
    say("no privileged executor was supplied, so no resolver mechanism could "
        "be probed");
    return LinuxWinn3ResolverMechanism::kNone;
  }

  // 1. systemd-resolved. The probe TOUCHES THE BUS rather than the binary.
  //    `resolvectl --version` succeeds on a machine whose resolved is not
  //    running, and a machine whose resolved is not running is exactly the one
  //    that answered exit 127 to `resolvectl dns` on 2026-08-10 with both
  //    capturing routes already installed.
  if (Probe(run, {"resolvectl", "--no-pager", "status"})) {
    say("`resolvectl --no-pager status` succeeded, so systemd-resolved is "
        "running and reachable on this host's bus");
    return LinuxWinn3ResolverMechanism::kSystemdResolved;
  }

  // 2. resolvconf / openresolv. `-l` lists the resolv.conf files resolvconf is
  //    managing, which needs its state directory to exist and be usable, so it
  //    fails on a host that has the binary and a broken installation.
  if (Probe(run, {"resolvconf", "-l"})) {
    say("`resolvectl` could not reach systemd-resolved; `resolvconf -l` "
        "succeeded, so resolvconf/openresolv manages this host's resolvers");
    return LinuxWinn3ResolverMechanism::kResolvconf;
  }

  // 3. /etc/resolv.conf, directly, and only when the deployment allows it.
  if (!params.allow_direct_resolv_conf) {
    say("neither systemd-resolved nor resolvconf answered, and this session "
        "was configured with allow_direct_resolv_conf false, so there is no "
        "mechanism left and the posture must not widen");
    return LinuxWinn3ResolverMechanism::kNone;
  }
  //    A SYMLINK IS REFUSED. The normal reason /etc/resolv.conf is a symlink is
  //    that something else owns it -- /run/systemd/resolve/stub-resolv.conf,
  //    /run/resolvconf/resolv.conf -- and writing through the link would
  //    clobber another manager's file while its manager was merely not
  //    answering. A machine in that state is broken in a way this host must
  //    not paper over.
  if (Probe(run, {"test", "-h", kResolvConfPath})) {
    say("neither systemd-resolved nor resolvconf answered, and /etc/resolv.conf "
        "is a symbolic link, which means another resolver manager owns it; "
        "rewriting it would clobber that manager's file, so there is no "
        "mechanism left");
    return LinuxWinn3ResolverMechanism::kNone;
  }
  if (Probe(run, {"test", "-f", kResolvConfPath})) {
    say("neither systemd-resolved nor resolvconf answered; /etc/resolv.conf is "
        "a regular file and will be rewritten directly, with the original "
        "saved to " +
        std::string(kResolvConfBackup));
    return LinuxWinn3ResolverMechanism::kResolvConfFile;
  }

  say("no resolver mechanism answered: systemd-resolved is not reachable, "
      "resolvconf is not installed, and /etc/resolv.conf is not a regular "
      "file. The route set and the resolver set have to move together, so "
      "this host must not widen its posture");
  return LinuxWinn3ResolverMechanism::kNone;
}

bool VerifyLinuxWinn3BootstrapCommandsAreNarrow(
    const std::vector<std::vector<std::string>>& commands,
    std::string* error) {
  for (const std::vector<std::string>& argv : commands) {
    std::string joined;
    for (const std::string& token : argv) {
      if (!joined.empty()) joined.push_back(' ');
      joined += token;
    }
    for (const std::string& token : argv) {
      // The two halves of the promoted default route, and a literal default.
      if (token == "0.0.0.0/1" || token == "128.0.0.0/1" ||
          token == "0.0.0.0/0" || token == "::/0" || token == "default") {
        return Fail(error,
                    "a bootstrap posture rendered a default route: `" + joined +
                        "`. The plan said it took none, so the renderer and "
                        "the plan disagree and the argument vector is the one "
                        "that would have moved the user's traffic.");
      }
      if (token == "-6") {
        return Fail(error,
                    "a bootstrap posture rendered an IPv6 command: `" + joined +
                        "`. IPv6 is a promotion widening and is absent from "
                        "every bootstrap posture.");
      }
      // Every mechanism, not only systemd-resolved's. A check that knew one
      // renderer would pass a bootstrap that rewrote /etc/resolv.conf, and the
      // three mechanisms exist precisely so the resolver step is not always
      // `resolvectl`.
      if (token == "resolvectl" || token == "dnsservers" ||
          token == "resolvconf" || token == "/etc/resolv.conf") {
        return Fail(error,
                    "a bootstrap posture rendered a resolver: `" + joined +
                        "`. Resolvers are installed at promotion and never "
                        "before, because a resolver reachable outside the "
                        "tunnel resolves names over the censored path.");
      }
    }
  }
  return true;
}

std::vector<LinuxWinn3Command> RenderLinuxWinn3TeardownCommands(
    const LinuxWinn3Params& params, LinuxWinn3ResolverMechanism mechanism) {
  const std::string device = Trim(params.interface_name);
  std::vector<LinuxWinn3Command> commands;

  // THE PROMOTED DEFAULT-ROUTE HALVES FIRST, AS EXPLICIT `del`s.
  //
  // Until 2026-08-23 this renderer relied on the link deletion below to sweep
  // the /1 pair, because a route scoped to a deleted device goes with it. That
  // is true WHEN the deletion runs. The fleet measured the other case: after a
  // stop that ran neither half of the v3 teardown, the tun, the /1 pair and
  // the /32 all stayed up. Deleting the link was never reached. So the pair is
  // removed explicitly, best effort, in the reverse of the promotion's install
  // order -- the same "the widest thing installed is the first thing removed"
  // rule the promotion rollback already uses -- and it is best effort because
  // the engine's tun descriptor close, which StopLinuxWinn3Standalone performs
  // first, usually deletes the interface and these routes before they run.
  // `ip route del` against a route that is already gone fails, and treating
  // that as a failed teardown would report every clean stop as dirty.
  if (!device.empty()) {
    const struct {
      bool v6;
      const char* prefix;
    } halves[] = {
        {true, winsvpn::winn3::detail::kIPv6DefaultRouteHighHalf},
        {true, winsvpn::winn3::detail::kIPv6DefaultRouteLowHalf},
        {false, winsvpn::winn3::detail::kDefaultRouteHighHalf},
        {false, winsvpn::winn3::detail::kDefaultRouteLowHalf},
    };
    for (const auto& half : halves) {
      LinuxWinn3Command del;
      if (half.v6) {
        del.argv = {"ip", "-6", "route", "del", half.prefix, "dev", device};
      } else {
        del.argv = {"ip", "route", "del", half.prefix, "dev", device};
      }
      del.best_effort = true;
      commands.push_back(del);
    }
  }
  // The resolvers second, and by the mechanism that INSTALLED them rather than
  // by a fresh detection. Re-detecting at teardown asks a machine that may
  // already have changed -- a resolved that has since started would answer for
  // an interface openresolv is holding -- and the answer is used to decide what
  // to undo, which is the one question a guess must not be allowed near.
  for (const LinuxWinn3Command& command :
       RenderLinuxWinn3ResolverTeardown(device, mechanism)) {
    commands.push_back(command);
  }
  if (!device.empty()) {
    // Deleting the link removes every route and address scoped to it in one
    // step, which is why the promoted /1 pair needs no separate removal. The
    // host's own default route is untouched because the /1 pair never replaced
    // it -- it only beat it on specificity. Verified by execution on a live
    // Linux kernel: after this teardown `ip route show` carried the container's
    // own `default via ... dev eth0` unchanged and no winsvpn3 residue.
    //
    // THESE TWO ARE BEST EFFORT AND A CALLER MUST NOT TREAT THEIR FAILURE AS
    // A FAILED TEARDOWN. A tun device opened with TUNSETIFF and no TUNSETPERSIST
    // disappears when its last descriptor closes, so StopLinuxWinn3Engine --
    // which closes the descriptor -- usually deletes the interface before these
    // run, and both then fail with "Cannot find device". Measured: exactly
    // that, on the Linux run of 2026-08-09. The commands that MUST succeed are
    // the resolver restore above, on the /etc/resolv.conf mechanism, and the
    // exclusion removal below: those two are the only ones whose residue
    // outlives the process -- a rewritten resolv.conf, and a stale host route
    // to a gateway this device no longer talks to.
    LinuxWinn3Command down;
    down.argv = {"ip", "link", "set", "dev", device, "down"};
    down.best_effort = true;
    commands.push_back(down);
    LinuxWinn3Command remove;
    remove.argv = {"ip", "link", "delete", "dev", device};
    remove.best_effort = true;
    commands.push_back(remove);
  }
  // LAST. While the exclusion is still installed the gateway is merely
  // reachable by its own physical path, which is what it was before the tunnel
  // existed. Removing it first would leave a window in which tunnel routes
  // still exist and the engine's own datagrams match them.
  for (const std::vector<std::string>& argv :
       RenderLinuxWinn3ExclusionTeardown(params)) {
    LinuxWinn3Command command;
    command.argv = argv;
    commands.push_back(command);
  }
  return commands;
}

// ---------------------------------------------------------------------------
// The promotion gate
// ---------------------------------------------------------------------------

LinuxWinn3Promotion DecideLinuxWinn3Promotion(
    bool engine_running, const std::string& status_json,
    winsvpn::winn3::EngineStatus* parsed, std::string* reason) {
  winsvpn::winn3::EngineStatus status;
  if (parsed != nullptr) *parsed = winsvpn::winn3::EngineStatus();
  const auto say = [reason](const std::string& text) {
    if (reason != nullptr) *reason = text;
  };

  if (!engine_running) {
    say("the Winn Protocol v3 engine is not running, so the datapath can never "
        "prove itself and there is nothing to wait for.");
    return LinuxWinn3Promotion::kRefuse;
  }
  if (Trim(status_json).empty()) {
    say("the Winn Protocol v3 engine has not answered a status request yet.");
    return LinuxWinn3Promotion::kNotYet;
  }
  if (!winsvpn::winn3::ParseWinn3StatusLine(status_json, &status)) {
    // A document without `promotion_ready` is from an engine that does not
    // speak this contract. Assuming false would be indistinguishable from an
    // engine that said false -- safe, but it hides a version mismatch that
    // would never be diagnosed. So it is named, and it is not fatal: an engine
    // mid-start can emit a line this parser refuses.
    say("the Winn Protocol v3 engine published a status document this host "
        "cannot parse, so no posture may be widened on it. Either the engine "
        "is older than this host or its status schema has drifted.");
    return LinuxWinn3Promotion::kNotYet;
  }
  if (parsed != nullptr) *parsed = status;

  if (!status.refusal.empty()) {
    // The engine reports a refusal only for a condition it will not retry out
    // of -- a failed session, a dead carrier -- so this is final rather than a
    // reason to keep polling.
    say("the Winn Protocol v3 engine refused the session: " + status.refusal);
    return LinuxWinn3Promotion::kRefuse;
  }
  if (status.promotion_ready) {
    // Belt and braces, and NOT a recomputation of the predicate. The engine
    // computes `Gate.State() == StateCarrying && Stats().RxPackets > 0` once,
    // in Go, beside the counters. A document that claims ready while
    // contradicting the evidence for it disagrees with ITSELF, and trusting
    // the field over the evidence for it is how a host promotes on a bug.
    //
    // BOTH HALVES, AND UNTIL 2026-08-12 IT WAS ONE. The predicate is a
    // conjunction and only the delivery half was refused here. The gate half
    // IS compared -- below, in the branch this one falls past -- but that
    // branch is wording only: it runs when the field already said false, to
    // name which half a held session is waiting on. It stays exactly as it is.
    // What it could not do from down there is refuse, because it is
    // unreachable the moment the field says true, so a document reading
    // ready=true beside a gate that may not carry returned kPromote.
    //
    // The engine cannot write that document -- cmd/winn-datapath's
    // winn3StatusFrom reads the gate once and derives both fields from that one
    // value -- so this is defence in depth against a malformed or substituted
    // status line rather than a live engine bug. `gate_state` is also OPTIONAL
    // to ParseWinn3StatusLine, so an engine that publishes promotion_ready
    // without it parses to an empty gate state, which is not the carrying one.
    if (status.gate_state != winsvpn::winn3::kCarryingGate) {
      say("the Winn Protocol v3 engine reported the datapath proven while also "
          "reporting the session gate as '" +
          status.gate_state + "', not '" + winsvpn::winn3::kCarryingGate +
          "', so the status document disagrees with itself and was refused "
          "rather than believed.");
      return LinuxWinn3Promotion::kRefuse;
    }
    if (status.rx_packets == 0) {
      say("the Winn Protocol v3 engine reported the datapath proven while also "
          "reporting zero delivered inner packets, so the status document "
          "disagrees with itself and was refused rather than believed.");
      return LinuxWinn3Promotion::kRefuse;
    }
    if (reason != nullptr) reason->clear();
    return LinuxWinn3Promotion::kPromote;
  }

  // Wording only from here down; every branch returns the same verdict. The two
  // halves are named separately because the operator needs to know WHICH is
  // missing: a gate that never opened is a handshake problem, and an open gate
  // with no delivered packet is a return-path problem.
  if (status.gate_state != winsvpn::winn3::kCarryingGate) {
    say("the Winn Protocol v3 session gate is '" + status.gate_state +
        "', not '" + winsvpn::winn3::kCarryingGate +
        "', so no inner packet may move yet.");
  } else {
    say("the Winn Protocol v3 gate is carrying but no inner packet has reached "
        "the host device yet, so the return path is unproven.");
  }
  return LinuxWinn3Promotion::kNotYet;
}

// ---------------------------------------------------------------------------
// Posture application
// ---------------------------------------------------------------------------

LinuxWinn3PostureResult ApplyLinuxWinn3BootstrapPosture(
    const LinuxWinn3Params& params, const winsvpn::winn3::EngineStatus& status,
    const LinuxWinn3PrivilegedRunner& run, winsvpn::winn3::PosturePlan* plan) {
  LinuxWinn3PostureResult result;
  result.posture = winsvpn::winn3::Posture::kBootstrap;
  // Every early return below is kNotAttempted, and separating it from
  // kPartiallyApplied is the whole point: it means the kernel is untouched by
  // this call, so a retry is clean. The old boolean could not say that, and the
  // difference between "retry me" and "you are wedged until someone deletes a
  // route by hand" is the difference this function exists to carry.
  //
  // NOTE: no SetLinuxWinn3ResolverStatus. That publishes under the key
  // `promoted_posture`, and a bootstrap outcome published there would be a lie
  // in the one document whose value is that it can be read literally.
  // Bootstrap publishes under its OWN key so an operator can read it (see
  // LinuxWinn3BootstrapStatusJson); that is why the setter below is the
  // bootstrap one, not the resolver one.
  const auto refuse = [&result](const std::string& message) {
    result.outcome = LinuxWinn3PostureOutcome::kNotAttempted;
    result.error = message;
    SetLinuxWinn3BootstrapStatus(result);
    return result;
  };

  if (plan == nullptr) return refuse("no posture plan to fill");
  const std::string device = Trim(params.interface_name);
  if (device.empty()) {
    return refuse("the Winn v3 session names no tun interface");
  }
  if (!run) {
    return refuse(
        "no privileged executor was supplied, so the Winn v3 posture cannot be "
        "applied. This file decides and renders; it never executes.");
  }

  const winsvpn::winn3::PostureInput input = LinuxWinn3PostureInput(params);
  const std::vector<std::vector<std::string>> exclusion =
      RenderLinuxWinn3ExclusionCommands(params);
  if (exclusion.empty()) {
    // BuildBootstrapPosture would refuse the empty exclusion description a
    // moment later, but saying it here names the missing INPUT rather than the
    // missing description derived from it.
    return refuse(
        "the Winn v3 outer-socket exclusion cannot be rendered: the "
        "session needs the gateway endpoint, the physical interface it "
        "is reachable on and the next hop on that interface, read "
        "before any route is installed. There is no awg-quick fwmark "
        "to fall back on in a standalone v3 session.");
  }

  std::string build_error;
  if (!winsvpn::winn3::BuildBootstrapPosture(input, status, plan,
                                             &build_error)) {
    return refuse(build_error);
  }
  // The built object is checked rather than the builder trusted. A builder that
  // is wrong is exactly a builder whose own claim of narrowness cannot be
  // relied on.
  if (!winsvpn::winn3::VerifyBootstrapIsNarrow(*plan, &build_error)) {
    return refuse(build_error);
  }

  // The RENDERED commands, checked before one of them runs. The plan-level
  // check above cannot see a renderer that widened on its own.
  const std::vector<std::vector<std::string>> posture =
      winsvpn::winn3::RenderLinuxPostureCommands(device, *plan);
  if (!VerifyLinuxWinn3BootstrapCommandsAreNarrow(posture, &build_error)) {
    return refuse(build_error);
  }

  // THE EXCLUSION FIRST, from the FIRST posture. Installing it after the link
  // means installing it after traffic could already have been captured, and it
  // is the one command here that is about the OUTER path rather than the inner
  // one.
  std::vector<std::vector<std::string>> commands = exclusion;
  for (const std::vector<std::string>& argv : posture) {
    commands.push_back(argv);
  }

  // ===========================================================================
  // REPAIR FIRST, THEN TAKE
  // ===========================================================================
  //
  // Everything below reverses what THIS call installs. Nothing below repairs an
  // exclusion a PREVIOUS process stranded -- a session SIGKILLed after this
  // point never reaches its own rollback, and a rollback that fails returns
  // kPartiallyApplied and leaves the route where it is. Either way the next
  // bootstrap's first command is the identical `ip route add` and `ip` answers
  // EEXIST, exit 2, forever.
  //
  // So: the exclusion's own `del`, run before its `add`, best effort. This is
  // the /etc/resolv.conf mechanism's "REPAIR BEFORE BACKUP" step in its route
  // form, and it is the LAST thing before the first installing command so that
  // every early return above still means the kernel is untouched.
  //
  // THE `del` IS ALSO THE PROBE, and that is why the rule can be stated at all.
  // The runner carries no exit status and no errno, so EEXIST cannot be
  // recognised here and would not be enough if it could -- EEXIST names a taken
  // DESTINATION, not an owner. The kernel matches a `del` carrying `via` and
  // `dev` on both, so this removes the exclusion this product writes and CANNOT
  // remove a route to the same destination somebody else wrote. Its exit status
  // is therefore the only question worth asking: is the thing in the way ours?
  //
  //   it succeeded -> ours, and stranded. Removed; the add below now works.
  //   it failed    -> nothing of ours was there. The ordinary first run, and
  //                   not an error -- which is why nothing is recorded in
  //                   `applied` and no failure is reported for it.
  //
  // Safe to run speculatively because this host carries ONE session at a time
  // (StopLinuxWinn3Engine, one engine): an exact-match exclusion sitting in the
  // kernel at bootstrap time is by definition not in use by anything here.
  for (const std::vector<std::string>& argv :
       RenderLinuxWinn3ExclusionTeardown(params)) {
    std::string repair_error;
    if (!run(argv, std::string(), &repair_error)) continue;
    result.stale_exclusion_repaired = true;
  }

  // ===========================================================================
  // EXECUTION, AND WHAT IS TRUE OF THE KERNEL AT EVERY POINT IN IT
  // ===========================================================================
  //
  // Commands run in order and the first failure stops the run -- unchanged from
  // the `RunAll` helper this replaced (deleted above), and right. What changed
  // is that the prefix which already succeeded is a RECORDED FACT rather than
  // something the caller has to infer from a boolean that cannot carry it.
  for (const std::vector<std::string>& argv : commands) {
    std::string command_error;
    if (run(argv, std::string(), &command_error)) {
      result.applied.push_back(argv);
      continue;
    }
    result.failed = argv;
    result.error = "the Winn v3 posture command `" + JoinArgv(argv) +
                   "` failed: " + command_error;
    break;
  }

  if (result.failed.empty()) {
    result.outcome = LinuxWinn3PostureOutcome::kApplied;
    // Both hazard fields are asked of WHAT IS IN THE KERNEL rather than of what
    // was intended, in every outcome, so each has one meaning instead of two.
    //
    // `capturing` is structurally false here and is computed anyway: two
    // narrowness checks ran before the first command, so nothing that could
    // capture was ever in `commands`. If this ever came back true the checks
    // above have been defeated and the field is the alarm.
    std::string ignored;
    result.capturing =
        winsvpn::winn3::VerifyPromotedCommandsCapture(result.applied, &ignored);
    // TRUE on a healthy bootstrap, and that is the honest answer rather than a
    // false alarm: the exclusion is on the physical interface by design, it
    // will not go when the tun descriptor closes, and the session now owes
    // RenderLinuxWinn3TeardownCommands a call. Read it with `outcome`.
    result.exclusion_installed =
        AnyCommandOutlivesTheTun(result.applied, device);
    SetLinuxWinn3BootstrapStatus(result);
    return result;
  }

  // ===========================================================================
  // THE BLOCKED CASE: THE DESTINATION IS ROUTED BY SOMETHING WE DID NOT WRITE
  // ===========================================================================
  //
  // The exclusion is the first command, so its failure means nothing of this
  // attempt is in the kernel and there is nothing to reverse. That much looks
  // like kRolledBack and IS NOT, because the repair above has just proved
  // something kRolledBack would deny: the exact route we were about to add was
  // not there, and the add was refused anyway. The destination is taken by an
  // entry with a different next hop or a different device -- the state that
  // makes the gateway unreachable, and the one state here we cannot prove is
  // ours.
  //
  // IT IS NOT DELETED. Our teardown removes our own vector and nothing else, so
  // there is no backup to put a guessed deletion back from -- unlike the
  // resolv.conf mechanism, which may overwrite the user's file only because it
  // saved it first. A route we deleted on a guess is gone permanently and with
  // no record of what it was. It is refused instead, by name, which is the
  // difference between an unreachable session and an unreachable session whose
  // cause is on the operator's screen.
  //
  // ONE READ-ONLY PROBE FIRST, so the refusal cannot lie about the cause. A
  // missing physical interface fails this same `ip route add`, and blaming a
  // route for a mistyped interface name would be a message claiming more than
  // its evidence supports. `ip link show dev X` exits non-zero when X does not
  // exist, which is an answer the runner CAN carry.
  if (result.applied.empty() && !exclusion.empty() &&
      result.failed == exclusion.front()) {
    const std::string physical = Trim(params.physical_interface);
    if (!Probe(run, {"ip", "link", "show", "dev", physical})) {
      // A different fault entirely, and named as one. Still nothing installed
      // and nothing to reverse, so the outcome stays the retryable one: fix the
      // interface and the next attempt is clean.
      result.outcome = LinuxWinn3PostureOutcome::kRolledBack;
      result.error +=
          ". The physical interface `" + physical +
          "` does not exist on this host, so this is a session parameter that "
          "is wrong rather than a route that is in the way. Nothing was "
          "installed and a corrected retry starts clean";
      SetLinuxWinn3BootstrapStatus(result);
      return result;
    }
    const std::string family =
        exclusion.front().size() > 1 ? exclusion.front()[1] : std::string("-4");
    result.outcome = LinuxWinn3PostureOutcome::kExclusionBlocked;
    result.error +=
        ". The outer-socket exclusion `" + JoinArgv(exclusion.front()) +
        "` was REFUSED, and it is not this product's own leftover: the "
        "identical route was not in the kernel a moment earlier, because the "
        "repair that opens every bootstrap looked for exactly it and did not "
        "find it. So the destination is routed by an entry with a DIFFERENT "
        "next hop or a different device -- which is what makes the gateway "
        "unreachable -- and it is NOT REMOVED, because this host cannot tell a "
        "previous session on another network from a route the user or another "
        "tool owns, and it keeps no copy it could put back. Run `ip " +
        family +
        " route show` and remove or correct that route; retrying without doing "
        "so fails identically";
    SetLinuxWinn3BootstrapStatus(result);
    return result;
  }

  // ===========================================================================
  // THE PARTIAL CASE: PUT THE KERNEL BACK, AND SAY WHETHER THAT WORKED
  // ===========================================================================
  //
  // WHY THE EXCLUSION IS REVERSED RATHER THAN LEFT. Its whole job is to keep the
  // gateway reachable by its own physical path WHILE tunnel routes exist. The
  // bootstrap has just failed, so there are none, and it protects nothing. What
  // it does do is survive: it is the one command here on an interface that does
  // not vanish with the tun descriptor, and it is verbatim the FIRST command the
  // next bootstrap runs -- which `ip` answers with "RTNETLINK answers: File
  // exists", exit 2. Left behind, one half-applied bootstrap refuses every
  // later session on the machine.
  //
  // Reversed order, so the last thing installed is the first thing removed and
  // the exclusion goes LAST -- the same ordering, for the same reason,
  // RenderLinuxWinn3TeardownCommands gives at its own tail.
  //
  // No resolver teardown: the bootstrap posture installs no resolver, so there
  // is nothing to detach and attempting one would report as a failed rollback.
  //
  // Two outcomes, both of them values the caller receives:
  //   kRolledBack       every reversal succeeded; nothing of this attempt
  //                     outlives the process and a retry is clean.
  //   kPartiallyApplied at least one did not; `exclusion_installed` says whether
  //                     what is left is the route that wedges the next start.
  result.rollback_attempted = true;
  for (size_t i = result.applied.size(); i > 0; --i) {
    const std::vector<std::string> reversed =
        ReverseOfPostureCommand(result.applied[i - 1]);
    if (reversed.empty()) continue;
    std::string command_error;
    if (run(reversed, std::string(), &command_error)) continue;
    result.rollback_failed.push_back(reversed);
  }

  const std::vector<std::vector<std::string>> residue =
      ResidueOfAttempt(result.applied, result.rollback_failed);
  std::string ignored;
  result.capturing =
      winsvpn::winn3::VerifyPromotedCommandsCapture(residue, &ignored);
  result.exclusion_installed = AnyCommandOutlivesTheTun(residue, device);
  result.outcome = result.rollback_failed.empty()
                       ? LinuxWinn3PostureOutcome::kRolledBack
                       : LinuxWinn3PostureOutcome::kPartiallyApplied;
  if (result.outcome == LinuxWinn3PostureOutcome::kRolledBack) {
    result.error +=
        ". Every command that had succeeded was reversed, so nothing this "
        "attempt installed outlives this process and a retry starts clean";
  } else if (result.exclusion_installed) {
    result.error +=
        ". " + std::to_string(result.rollback_failed.size()) +
        " reversal(s) failed and THE OUTER-SOCKET EXCLUSION IS STILL INSTALLED"
        " on the physical interface. It will not go when this process exits, "
        "and it is the first command the next bootstrap runs, which will fail "
        "EEXIST -- so the next session cannot start until that route is "
        "removed";
  } else {
    result.error +=
        ". " + std::to_string(result.rollback_failed.size()) +
        " reversal(s) failed, so this posture is PARTIALLY APPLIED. What is "
        "left is scoped to the tun device and goes with its last descriptor, "
        "but the session must be torn down rather than left running";
  }
  SetLinuxWinn3BootstrapStatus(result);
  return result;
}

std::string DescribeLinuxWinn3PostureResult(
    const LinuxWinn3PostureResult& result) {
  const bool bootstrap = result.posture == winsvpn::winn3::Posture::kBootstrap;
  std::string text = std::string(bootstrap ? "bootstrap posture "
                                           : "promoted posture ") +
                     LinuxWinn3PostureOutcomeName(result.outcome) +
                     "; resolver mechanism " +
                     LinuxWinn3ResolverMechanismName(result.resolver_mechanism) +
                     "; " + std::to_string(result.applied.size()) +
                     " command(s) applied";
  if (result.rollback_attempted) {
    text += "; rollback attempted, " +
            std::to_string(result.rollback_failed.size()) + " reversal(s) failed";
  }
  text += result.capturing
              ? "; THE KERNEL IS CAPTURING TRAFFIC ON THIS DEVICE"
              : "; the kernel is not capturing traffic on this device";
  // Only when it is a hazard. On a bootstrap that applied it is the designed
  // state and the teardown owns it, so saying it in every healthy line would
  // teach the reader to skip the line in which it matters.
  if (result.exclusion_installed &&
      result.outcome != LinuxWinn3PostureOutcome::kApplied) {
    text += "; THE OUTER-SOCKET EXCLUSION IS STILL INSTALLED AND OUTLIVES THIS "
            "PROCESS";
  }
  // Said on a healthy run too, unlike the line above, because it is not a
  // warning about THIS session: it is the only in-band evidence that the last
  // one was killed before its teardown. A host that says it on every start is a
  // host something is killing, and that is worth seeing.
  if (result.stale_exclusion_repaired) {
    text += "; a STRANDED OUTER-SOCKET EXCLUSION left by a previous process was "
            "found and removed before this attempt";
  }
  if (result.outcome == LinuxWinn3PostureOutcome::kExclusionBlocked) {
    text += "; THE GATEWAY'S DESTINATION IS ALREADY ROUTED BY AN ENTRY THIS "
            "HOST DID NOT INSTALL AND WILL NOT REMOVE";
  }
  if (!result.failed.empty()) {
    text += "; a privileged posture command failed";
  }
  return text;
}

LinuxWinn3PostureResult ApplyLinuxWinn3PromotedPosture(
    const LinuxWinn3Params& params, const winsvpn::winn3::EngineStatus& status,
    const LinuxWinn3PrivilegedRunner& run, winsvpn::winn3::PosturePlan* plan) {
  LinuxWinn3PostureResult result;
  result.posture = winsvpn::winn3::Posture::kPromoted;
  // Every early return below is kNotAttempted, and that is the whole point of
  // separating it from kPartiallyApplied: it means the kernel is exactly as the
  // bootstrap left it, which the old boolean could not say.
  const auto refuse = [&result](const std::string& message) {
    result.outcome = LinuxWinn3PostureOutcome::kNotAttempted;
    result.error = message;
    SetLinuxWinn3ResolverStatus(result);
    return result;
  };

  if (plan == nullptr) return refuse("no posture plan to fill");
  const std::string device = Trim(params.interface_name);
  if (device.empty()) {
    return refuse("the Winn v3 session names no tun interface");
  }
  if (!run) {
    return refuse(
        "no privileged executor was supplied, so the Winn v3 posture cannot be "
        "applied. This file decides and renders; it never executes.");
  }
  const winsvpn::winn3::PostureInput input = LinuxWinn3PostureInput(params);
  std::string build_error;
  if (!winsvpn::winn3::BuildPromotedPosture(input, status, plan,
                                            &build_error)) {
    return refuse(build_error);
  }

  // ===========================================================================
  // THE RESOLVER MECHANISM IS DECIDED BEFORE A ROUTE MOVES
  // ===========================================================================
  //
  // BuildPromotedPosture refuses an empty resolver set because "the route set
  // and the resolver set have to move together or neither may move". A host
  // with no usable resolver mechanism is the same statement one layer down: the
  // resolver set CANNOT move, so the route set must not either. Detecting after
  // the /1 pair was installed is exactly the 2026-08-10 measurement -- both
  // capturing routes in the kernel, the resolver step failing, and a caller
  // told promotion had not happened.
  result.resolver_mechanism = DetectLinuxWinn3ResolverMechanism(
      params, run, &result.resolver_detail);
  if (!plan->dns_servers.empty() &&
      (result.resolver_mechanism == LinuxWinn3ResolverMechanism::kNone ||
       result.resolver_mechanism == LinuxWinn3ResolverMechanism::kUnknown)) {
    return refuse(
        "refusing to promote: this host has no usable resolver mechanism, so "
        "the resolver set cannot move and the route set must not move without "
        "it. " +
        result.resolver_detail);
  }

  // ===========================================================================
  // PROMOTION INSTALLS THE DELTA, NOT THE WHOLE POSTURE
  // ===========================================================================
  //
  // The exclusion was already not re-installed here, and the comment said why:
  // it is in place from the bootstrap and a second add fails EEXIST, turning a
  // correct promotion into an error. That reasoning was right and it was
  // applied to exactly one of the four things it is true of.
  //
  // `RenderLinuxPostureCommands` renders a WHOLE posture, and the promoted
  // posture is the bootstrap's plus the widenings -- so rendering it whole
  // re-issues `ip -4 address add 10.x/32 dev D`, which the bootstrap ran
  // minutes earlier and which `ip` answers with "RTNETLINK answers: File
  // exists". The run stops at the first failing command, so promotion would
  // fail on its FIRST command, before a single route moved.
  //
  // That is fail-closed and therefore not a leak. It is still a session that
  // bootstraps, proves its datapath, and then never widens -- the stall this
  // whole staged posture is supposed to end in only when the proof does not
  // arrive.
  //
  // So the bootstrap is rebuilt from the SAME input and status -- both builders
  // are pure, and BuildPromotedPosture builds this same object internally -- and
  // what is executed is what the promoted posture has and the bootstrap did not.
  winsvpn::winn3::PosturePlan narrow;
  if (!winsvpn::winn3::BuildBootstrapPosture(input, status, &narrow,
                                             &build_error)) {
    return refuse(build_error);
  }
  const std::vector<std::vector<std::string>> already =
      winsvpn::winn3::RenderLinuxPostureCommands(device, narrow);
  std::vector<LinuxWinn3Command> commands;
  std::vector<std::vector<std::string>> route_delta;
  for (const std::vector<std::string>& argv :
       winsvpn::winn3::RenderLinuxPostureCommands(device, *plan)) {
    bool installed = false;
    for (const std::vector<std::string>& done : already) {
      if (done == argv) installed = true;
    }
    if (installed) continue;
    LinuxWinn3Command command;
    command.argv = argv;
    commands.push_back(command);
    route_delta.push_back(argv);
  }
  for (const LinuxWinn3Command& command :
       RenderLinuxWinn3ResolverCommands(device, *plan,
                                        result.resolver_mechanism)) {
    commands.push_back(command);
  }

  // ===========================================================================
  // AND THE DELTA IS CHECKED FOR CAPTURE BEFORE ONE COMMAND RUNS
  // ===========================================================================
  //
  // The same discipline VerifyLinuxWinn3BootstrapCommandsAreNarrow applies to
  // the other posture, asking the opposite question. The plan-level predicate
  // ran inside BuildPromotedPosture; this one runs over the ARGUMENT VECTORS,
  // because the argv is what moves the user's traffic and the plan is only what
  // was intended.
  //
  // It is not redundant with the plan check. `default_route` is ONE boolean and
  // the /1 pair is TWO commands, so a renderer that emitted one of them would
  // satisfy every plan-level check in the system while leaving half the address
  // space on the physical interface -- with the plan, the status line and the
  // user all reading promoted.
  //
  // It is given the delta rather than the whole posture on purpose: the delta is
  // what executes, and a check fed a command list the caller does not run is a
  // check of a hypothetical.
  std::string capture_error;
  if (!winsvpn::winn3::VerifyPromotedCommandsCapture(route_delta,
                                                     &capture_error)) {
    return refuse(capture_error);
  }

  // ===========================================================================
  // EXECUTION, AND WHAT IS TRUE OF THE KERNEL AT EVERY POINT IN IT
  // ===========================================================================
  //
  // Commands run in order and the first failure stops the run -- unchanged, and
  // right. What changed is that the prefix that already succeeded is now a
  // recorded fact rather than something the caller has to infer from a boolean
  // that cannot carry it.
  for (const LinuxWinn3Command& command : commands) {
    std::string command_error;
    if (run(command.argv, command.stdin_bytes, &command_error)) {
      result.applied.push_back(command.argv);
      continue;
    }
    if (command.best_effort) {
      // A repair step on a machine with nothing to repair. Not a failure and
      // not something that was applied.
      continue;
    }
    result.failed = command.argv;
    result.error = "the Winn v3 posture command `" + JoinArgv(command.argv) +
                   "` failed: " + command_error;
    break;
  }

  if (result.failed.empty()) {
    result.outcome = LinuxWinn3PostureOutcome::kApplied;
    // Asked of what is in the kernel rather than of what was intended. On a
    // fully applied promotion the two agree, and asking anyway means the field
    // has one meaning in every outcome instead of two.
    std::string ignored;
    result.capturing =
        winsvpn::winn3::VerifyPromotedCommandsCapture(result.applied, &ignored);
    // Normally false: the promoted delta is entirely on the tun, which goes
    // with its last descriptor. Computed by the same rule as the bootstrap's so
    // a future promoted command on the physical interface is counted without
    // anyone remembering to count it. The OTHER thing a promotion can leave
    // behind -- a rewritten /etc/resolv.conf -- is reported by
    // `resolver_mechanism`, not by this field.
    result.exclusion_installed =
        AnyCommandOutlivesTheTun(result.applied, device);
    SetLinuxWinn3ResolverStatus(result);
    return result;
  }

  // ===========================================================================
  // THE PARTIAL CASE: PUT THE KERNEL BACK, AND SAY WHETHER THAT WORKED
  // ===========================================================================
  //
  // Reversed order, so the widest thing installed is the first thing removed.
  // The resolver step is reverted by the mechanism that installed it -- never
  // by a second detection -- and only when a resolver command actually
  // succeeded, because reverting an interface no resolver was ever attached to
  // is noise that would report as a failed rollback.
  //
  // Two outcomes, both of them values the caller receives:
  //   kRolledBack       every reversal succeeded; the kernel is back in the
  //                     narrow posture and nothing is capturing.
  //   kPartiallyApplied at least one did not; `capturing` says whether what is
  //                     left moves the user's traffic, and the session must be
  //                     torn down rather than left running.
  result.rollback_attempted = true;
  bool resolver_touched = false;
  for (const std::vector<std::string>& argv : result.applied) {
    if (!argv.empty() &&
        (argv[0] == "resolvectl" || argv[0] == "resolvconf" ||
         argv[0] == "tee" || argv[0] == "cp")) {
      resolver_touched = true;
    }
  }
  std::vector<LinuxWinn3Command> rollback;
  if (resolver_touched) {
    for (const LinuxWinn3Command& command :
         RenderLinuxWinn3ResolverTeardown(device, result.resolver_mechanism)) {
      rollback.push_back(command);
    }
  }
  for (size_t i = result.applied.size(); i > 0; --i) {
    const std::vector<std::string> reversed =
        ReverseOfPostureCommand(result.applied[i - 1]);
    if (reversed.empty()) continue;
    LinuxWinn3Command command;
    command.argv = reversed;
    rollback.push_back(command);
  }
  for (const LinuxWinn3Command& command : rollback) {
    std::string command_error;
    if (run(command.argv, command.stdin_bytes, &command_error)) continue;
    if (command.best_effort) continue;
    result.rollback_failed.push_back(command.argv);
  }

  // What is STILL installed: the applied prefix minus everything a reversal
  // removed. A reversal that failed leaves its command in the kernel, so it
  // stays in the residue and the capture predicate sees it. Shared with the
  // bootstrap applier, which asks the same question of its own residue -- one
  // definition of "what is left" rather than two that can drift apart.
  const std::vector<std::vector<std::string>> residue =
      ResidueOfAttempt(result.applied, result.rollback_failed);
  std::string ignored;
  result.capturing =
      winsvpn::winn3::VerifyPromotedCommandsCapture(residue, &ignored);
  result.exclusion_installed = AnyCommandOutlivesTheTun(residue, device);
  result.outcome = result.rollback_failed.empty()
                       ? LinuxWinn3PostureOutcome::kRolledBack
                       : LinuxWinn3PostureOutcome::kPartiallyApplied;
  if (result.outcome == LinuxWinn3PostureOutcome::kRolledBack) {
    result.error +=
        ". Every command that had succeeded was reversed, so the kernel is back "
        "in the narrow bootstrap posture and is not capturing traffic";
  } else {
    result.error += ". " + std::to_string(result.rollback_failed.size()) +
                    " reversal(s) failed, so this posture is PARTIALLY APPLIED"
                    " and the session must be torn down rather than left "
                    "running";
  }
  SetLinuxWinn3ResolverStatus(result);
  return result;
}

// ---------------------------------------------------------------------------
// The tun device
// ---------------------------------------------------------------------------

int OpenLinuxWinn3Tun(const std::string& interface_name, std::string* error) {
#ifdef __linux__
  const std::string name = Trim(interface_name);
  if (name.empty() || name.size() >= IFNAMSIZ) {
    Fail(error, "the Winn v3 tun interface name is empty or too long");
    return -1;
  }
  const int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    Fail(error, std::string("Could not open /dev/net/tun: ") +
                    std::strerror(errno) +
                    ". A Winn Protocol v3 session carries inner IP packets and "
                    "has no device without it.");
    return -1;
  }
  ifreq request{};
  // IFF_NO_PI matters and is not a preference: winn3/tun.Device's contract is
  // "an IP packet starting at its version nibble", and Linux's 4-byte
  // PACKET_INFO prefix would be read by the inner-IP validator as a malformed
  // packet. Every packet would be refused and the counter that says so is
  // tx_dropped_invalid, which reads like a source-address violation rather than
  // a framing one.
  request.ifr_flags = IFF_TUN | IFF_NO_PI;
  std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
  if (::ioctl(fd, TUNSETIFF, &request) != 0) {
    const int saved = errno;
    ::close(fd);
    Fail(error, "Could not attach the Winn v3 tun device " + name + ": " +
                    std::strerror(saved));
    return -1;
  }
  return fd;
#else
  (void)interface_name;
  Fail(error,
       "a Winn Protocol v3 tun device can only be opened on Linux; this host "
       "refuses rather than pretending to have one");
  return -1;
#endif
}

// ---------------------------------------------------------------------------
// The engine subprocess
// ---------------------------------------------------------------------------

std::vector<std::string> LinuxWinn3EngineArguments(
    const std::string& engine_path, const std::string& keys_path) {
  // `-transport stdio` is the desktop shape: a pipe, not a unix socket, because
  // nothing needs to cross this channel except frames. It also settles the
  // socket question -- a pipe cannot carry a descriptor, so the engine opens
  // the outer socket itself under allow_own_socket, which is why the exclusion
  // is mandatory and why the key document has to declare it.
  return {engine_path, "-transport", "stdio", "-winn3", "-winn3-keys",
          keys_path};
}

bool StartLinuxWinn3Engine(const std::string& engine_path, int tun_fd,
                           const LinuxWinn3Params& params,
                           winsvpn::winn3::EngineStatus* ack,
                           std::string* error) {
  if (error == nullptr) {
    if (tun_fd >= 0) close(tun_fd);
    return false;
  }
  std::lock_guard<std::mutex> guard(g_mutex);
  // The tun descriptor is adopted on EVERY outcome, not only on success, so a
  // caller has one rule to remember rather than two.
  if (g_session != nullptr) {
    if (tun_fd >= 0) close(tun_fd);
    return Fail(error, "A Winn Protocol v3 session is already running.");
  }
  if (tun_fd < 0) {
    return Fail(error, "The Winn Protocol v3 tun device is not open.");
  }

  std::string create_json;
  if (!BuildLinuxWinn3CreateJson(params, &create_json, error)) {
    close(tun_fd);
    return false;
  }
  const int path_mtu =
      params.path_mtu > 0 ? params.path_mtu : sizing::kDefaultPathMtu;
  int inner_mtu = 0;
  if (!sizing::PlanFloorInnerMtu(path_mtu, params.carrier_classes, &inner_mtu,
                                 error)) {
    close(tun_fd);
    return false;
  }

  // The key document is written HERE, before the fork, deliberately: everything
  // between fork() and execv() must be async-signal-safe, which writing a file
  // and building strings is not. The child only reads the c_str() of strings
  // the parent already owns.
  //
  // Fail-closed: a v3 session whose key document cannot be written does not
  // fall back to anything. There is nothing to fall back TO -- a v1 start in
  // its place would be the silent protocol downgrade this whole file exists to
  // make impossible.
  std::string keys_path;
  if (!WriteLinuxWinn3KeysDocument(params.keys, &keys_path, error)) {
    close(tun_fd);
    return false;
  }

  // Built BEFORE the fork, for the same reason the key document is written
  // before it: everything between fork() and execv() must be
  // async-signal-safe, and assembling a vector of strings is not. The child
  // only reads pointers into storage the parent already owns.
  const std::vector<std::string> arguments =
      LinuxWinn3EngineArguments(engine_path, keys_path);
  std::vector<const char*> argv;
  argv.reserve(arguments.size() + 1);
  for (const std::string& token : arguments) argv.push_back(token.c_str());
  argv.push_back(nullptr);

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
    close(tun_fd);
    return Fail(error, "The Winn v3 engine channel could not be created.");
  }
#ifdef F_SETPIPE_SZ
  (void)fcntl(to_engine[1], F_SETPIPE_SZ, 1024 * 1024);
  (void)fcntl(from_engine[0], F_SETPIPE_SZ, 1024 * 1024);
#endif

  const pid_t pid = fork();
  if (pid < 0) {
    for (int* pair : {to_engine, from_engine, wake}) {
      close(pair[0]);
      close(pair[1]);
    }
    close(tun_fd);
    return Fail(error, "The Winn Protocol v3 engine could not be started.");
  }
  if (pid == 0) {
    // Child. stdin/stdout carry frames; stderr is left attached so engine
    // diagnostics land in the app's own log.
    dup2(to_engine[0], STDIN_FILENO);
    dup2(from_engine[1], STDOUT_FILENO);
    close(to_engine[0]);
    close(to_engine[1]);
    close(from_engine[0]);
    close(from_engine[1]);
    close(wake[0]);
    close(wake[1]);
    close(tun_fd);
    // No positional arguments: cmd/winn-datapath treats a stray one as fatal.
    //
    // `-winn3-tun-fd` is NOT in LinuxWinn3EngineArguments and must never be: it
    // belongs to `-winn3-profile`, and in frame mode the engine refuses it
    // because THIS host owns the device. `-carrier-profile` is not there
    // either -- it is a winn/1 carrier and the engine refuses it beside
    // `-winn3` for the same reason this file is a separate translation unit.
    execv(engine_path.c_str(), const_cast<char* const*>(argv.data()));
    _exit(127);
  }

  close(to_engine[0]);
  close(from_engine[1]);

  SessionState* state = new SessionState();
  state->pid = pid;
  state->stdin_fd = to_engine[1];
  state->stdout_fd = from_engine[0];
  state->tun_fd = tun_fd;
  state->wake_fd[0] = wake[0];
  state->wake_fd[1] = wake[1];

  state->outbound = std::thread(OutboundPump, state);

  if (!WriteFrameLocked(state, Opcode::kCreate,
                        reinterpret_cast<const uint8_t*>(create_json.data()),
                        create_json.size())) {
    TeardownLocked(state);
    delete state;
    return Fail(error,
                "The Winn Protocol v3 engine did not accept its configuration.");
  }

  std::string ack_json;
  {
    std::unique_lock<std::mutex> status_guard(state->status_mutex);
    const bool acked = state->status_signal.wait_for(
        status_guard, std::chrono::milliseconds(kCreateAckTimeoutMs),
        [state] {
          return !state->last_status.empty() || !state->failure.empty();
        });
    if (!acked || !state->failure.empty()) {
      std::string reason =
          state->failure.empty()
              ? "the Winn Protocol v3 engine did not acknowledge its "
                "configuration in time"
              : state->failure;
      status_guard.unlock();
      TeardownLocked(state);
      delete state;
      return Fail(error, "Winn Protocol v3 could not start: " + reason + ".");
    }
    ack_json = state->last_status;
  }

  winsvpn::winn3::EngineStatus parsed;
  if (!winsvpn::winn3::ParseWinn3StatusLine(ack_json, &parsed)) {
    TeardownLocked(state);
    delete state;
    return Fail(error,
                "The Winn Protocol v3 engine acknowledged the session with a "
                "status document this host cannot parse, so the inner MTU it "
                "must put on the interface is unknown. Refusing rather than "
                "guessing it.");
  }
  if (parsed.inner_mtu != inner_mtu) {
    // The engine already refuses a create whose inner_mtu is not the plan floor
    // (winn3_create.go refusal 3), so reaching here means this host and the
    // engine computed the floor differently and the engine accepted anyway.
    // That is a sizing drift between sizing::PlanFloorInnerMtu and
    // driver.NewSizing, and it is exactly the 84-byte black hole those two
    // exist to prevent. Refuse loudly rather than configure the interface at a
    // width the datapath did not agree to.
    const int engine_mtu = parsed.inner_mtu;
    TeardownLocked(state);
    delete state;
    return Fail(error,
                "The Winn Protocol v3 engine reports an inner MTU of " +
                    std::to_string(engine_mtu) + " and this host computed " +
                    std::to_string(inner_mtu) +
                    ". The two plan floors have drifted, so the tunnel was "
                    "refused rather than configured at a width the datapath "
                    "did not agree to.");
  }

  state->channel_up.store(true);
  // The ring sits between the two pumps, sized from the negotiated inner MTU so
  // a slot always holds a whole packet. Started BEFORE the reader so the very
  // first burst has a consumer.
  state->ring.Init(static_cast<size_t>(inner_mtu));
  state->writer = std::thread(FrameWritePump, state);
  state->reader = std::thread(TunReadPump, state, inner_mtu);
  g_session = state;
  if (ack != nullptr) *ack = parsed;
  return true;
}

void StopLinuxWinn3Engine() {
  SessionState* state = nullptr;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    state = g_session;
    g_session = nullptr;
    if (state == nullptr) return;
    TeardownLocked(state);
  }
  delete state;
}

bool RemoveLinuxWinn3KeyFiles(std::string* error) {
  const std::string directory = PrivateWinn3StateDirectory();
  if (directory.empty()) return true;

  bool ok = true;
  for (const char* name : {
           "static.key", "gateway.pub", "admission.key",
           kDualAuthEd25519File, kDualAuthMldsa65File, kKeysFileName}) {
    const std::string path = directory + "/" + name;
    struct stat info = {};
    if (::lstat(path.c_str(), &info) != 0) {
      if (errno != ENOENT) ok = false;
      continue;
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != ::geteuid()) {
      ok = false;
      continue;
    }
    if (::unlink(path.c_str()) != 0 && errno != ENOENT) ok = false;
  }
  if (!ok && error != nullptr) {
    *error = "Temporary Winn v3 key files could not be fully removed.";
  }
  return ok;
}

void RememberLinuxWinn3Session(const LinuxWinn3Params& params) {
  std::lock_guard<std::mutex> guard(g_mutex);
  g_session_params = params;
  g_session_registered = true;
}

bool LinuxWinn3StandaloneSessionWasStarted() {
  std::lock_guard<std::mutex> guard(g_mutex);
  return g_session_registered;
}

bool StopLinuxWinn3Standalone(const LinuxWinn3PrivilegedRunner& run,
                              std::string* error) {
  // Snapshot everything first: the engine stop below takes g_mutex again, and
  // the posture flags live under their own mutex, so nothing here may hold a
  // lock across the run loop.
  LinuxWinn3Params params;
  bool registered = false;
  bool exclusion_installed = false;
  bool promoted_applied = false;
  LinuxWinn3ResolverMechanism mechanism = LinuxWinn3ResolverMechanism::kUnknown;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    registered = g_session_registered;
    params = g_session_params;
  }
  {
    std::lock_guard<std::mutex> guard(g_resolver_status_mutex);
    exclusion_installed = g_bootstrap_exclusion_installed;
    promoted_applied =
        g_promoted_outcome == LinuxWinn3PostureOutcome::kApplied;
    mechanism = g_resolver_mechanism;
  }

  // The engine first: the Close frame, the SIGTERM, the reap and the tun
  // descriptor close, which usually deletes the interface and the routes on
  // it. Idempotent when nothing is running.
  StopLinuxWinn3Engine();
  std::string key_cleanup_error;
  const bool keys_removed = RemoveLinuxWinn3KeyFiles(&key_cleanup_error);

  // Nothing was ever installed: there is nothing to reverse, and a stop that
  // cost privilege or could fail on a machine where nothing is up would be a
  // worse residue than the tunnel. Idempotency is this early return.
  if (!registered) {
    if (!keys_removed && error != nullptr) *error = key_cleanup_error;
    return keys_removed;
  }

  // Resolvers are reverted ONLY when a promotion actually applied them. The
  // mechanism says HOW, not WHETHER: a refused or rolled-back promotion
  // installed nothing, and rendering its mechanism's teardown would either be
  // noise (best effort) or a fabricated failure (the must-succeed
  // /etc/resolv.conf restore against a file that was never rewritten).
  const LinuxWinn3ResolverMechanism resolver_mechanism =
      promoted_applied ? mechanism : LinuxWinn3ResolverMechanism::kUnknown;

  std::string detail = key_cleanup_error;
  size_t failed = keys_removed ? 0 : 1;
  for (const LinuxWinn3Command& command :
       RenderLinuxWinn3TeardownCommands(params, resolver_mechanism)) {
    // An exclusion that was never installed owes no removal, and its del is
    // must-succeed: skipping it is what keeps this stop idempotent rather
    // than failing on a route that was never there.
    if (!exclusion_installed && IsExclusionRemoval(command)) continue;
    std::string command_error;
    if (run(command.argv, command.stdin_bytes, &command_error)) continue;
    if (command.best_effort) continue;
    ++failed;
    if (!command_error.empty()) {
      if (!detail.empty()) detail += "; ";
      detail += command_error;
    }
  }

  if (failed == 0) {
    // The session is fully reversed: forget it, so the next stop is a no-op,
    // and reset the posture flags so no later call renders a teardown for a
    // session that is gone.
    {
      std::lock_guard<std::mutex> guard(g_mutex);
      g_session_registered = false;
      g_session_params = LinuxWinn3Params();
    }
    {
      std::lock_guard<std::mutex> guard(g_resolver_status_mutex);
      g_bootstrap_exclusion_installed = false;
      g_promoted_outcome = LinuxWinn3PostureOutcome::kNotAttempted;
      g_resolver_mechanism = LinuxWinn3ResolverMechanism::kUnknown;
    }
    return true;
  }
  // The registration stays, deliberately: a retried stop re-runs the teardown
  // and the commands that failed get a second chance.
  if (error != nullptr) {
    *error = "The standalone Winn Protocol v3 posture could not be fully "
             "reversed (" +
             std::to_string(failed) + " teardown command(s) failed" +
             (detail.empty() ? std::string() : ": " + detail) + ").";
  }
  return false;
}

bool LinuxWinn3EngineRunning() {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_session == nullptr) return false;
  if (!g_session->channel_up.load()) return false;
  if (g_session->pid <= 0) return false;
  int status = 0;
  return waitpid(g_session->pid, &status, WNOHANG) == 0;
}

// Linux IsTunnelRunning consults this together with the `winsvpn3` link, and
// never the v1 `winsvpn` interface, while LinuxWinn3StandaloneSessionWasStarted
// is true. Process existence alone is still not a live tunnel.

std::string LinuxWinn3EngineStatusJson() {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_session == nullptr || !g_session->channel_up.load()) return "";
  SessionState* state = g_session;
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

LinuxWinn3Promotion LinuxWinn3PromotionState(
    winsvpn::winn3::EngineStatus* parsed, std::string* reason) {
  // Liveness FIRST. An engine that has exited answers with an empty document
  // forever and each ask costs up to kStatusTimeoutMs, so there is nothing to
  // buy by asking it again -- and the caller's polling budget is the user's
  // connect latency.
  if (!LinuxWinn3EngineRunning()) {
    return DecideLinuxWinn3Promotion(false, std::string(), parsed, reason);
  }
  const std::string status = LinuxWinn3EngineStatusJson();
  return DecideLinuxWinn3Promotion(true, status, parsed, reason);
}

// The promotion probe's collision refusals, as a PURE function with no socket
// and no platform header, so the test host (macOS) can prove them the way it
// proves every other decision in this file: by calling it directly. Returns
// the refusal sentence, or an empty string when the echo may proceed.
//
// THE COLLISION GUARDS. The echo's route is chosen by the OS here (a bound
// datagram socket's sendto takes the destination only), so this host must
// itself refuse the two targets whose route could leave the machine instead of
// entering the tunnel:
//
//   1. The carrier endpoint. Its /32 is pinned to the PHYSICAL interface by
//      the destination-scoped exclusion the staged posture installs, while
//      the bootstrap posture routes ONLY the inner next hop's /32 into the
//      tun. A signed descriptor that ever set inner_next_hop equal to the
//      endpoint address would make both pins describe one destination, and
//      whichever the OS chose, up to four zero-payload echoes could leave
//      the physical NIC on the censored path. Windows already refuses this
//      pair (winn3_supervisor.cpp SendInnerPromotionProbe); this host must
//      too.
//   2. This host's own inner_v4. Addressed to this device, the echo would
//      never reach the gateway to be reflected, and nothing about it would
//      be a probe.
std::string LinuxWinn3InnerPromotionProbeCollisionRefusal(
    const LinuxWinn3Params& params) {
  const std::string source_text = Trim(params.inner_address);
  const std::string target_text = Trim(params.inner_next_hop);
  uint32_t source = 0;
  uint32_t target = 0;
  if (!ParseIpv4LiteralUint32(source_text, &source) ||
      !ParseIpv4LiteralUint32(target_text, &target)) {
    // Nothing to collide yet: the Linux send path refuses an unparseable
    // address on its own (inet_pton) before any packet exists. This function
    // only decides the collisions the parser honestly CAN see.
    return std::string();
  }
  // The endpoint is parsed with the SAME parser the host already uses for it
  // (SplitLinuxWinn3Endpoint), so the guard and the exclusion renderer can
  // never disagree about which host the endpoint names. An IPv6 endpoint
  // parses here to an unusable IPv4 and simply cannot equal an IPv4 target,
  // exactly as InetPtonA behaves on the Windows side.
  std::string endpoint_host;
  std::string endpoint_port;
  uint32_t endpoint = 0;
  if (SplitLinuxWinn3Endpoint(params.gateway_endpoint, &endpoint_host,
                              &endpoint_port) &&
      ParseIpv4LiteralUint32(endpoint_host, &endpoint)) {
    if (endpoint == target) {
      return "the promotion probe's inner next hop (" + target_text +
             ") is the carrier endpoint's own address (" + endpoint_host +
             "); the endpoint's /32 is pinned to the physical interface, so "
             "the echo could leave the machine on the censored path instead "
             "of entering the tunnel";
    }
  }
  if (source == target) {
    return "the promotion probe's inner next hop (" + target_text +
           ") is this host's own inner_v4 assignment (" + source_text +
           "); an echo addressed to this device would not reach the gateway";
  }
  return std::string();
}

bool SendLinuxWinn3InnerPromotionProbe(const LinuxWinn3Params& params) {
  // Collisions FIRST, before any socket exists, and logged (the addresses are
  // closed-set values the caller already holds, as safe to log in full as the
  // resolver detail the pump stats documents). The caller keeps its 4-attempt
  // bound and its 15-second deadline unchanged: a refused probe is just one
  // advisory echo not sent.
  const std::string refusal =
      LinuxWinn3InnerPromotionProbeCollisionRefusal(params);
  if (!refusal.empty()) {
    std::fprintf(stderr, "winn3 inner promotion probe refused: %s\n",
                 refusal.c_str());
    return false;
  }
#ifdef __linux__
  // The echo is addressed to the inner next hop because that is the ONE /32 the
  // bootstrap posture routes into the tunnel; any other destination would
  // escape onto the physical route pre-promotion, which defeats the whole
  // containment this probe stays inside. The source is the session's own inner
  // assignment, because the engine's inner-IP validator refuses an inner packet
  // whose source is not the assigned address (a pre-tun kernel packet with a
  // borrowed source is the exact tx_dropped_invalid the gate already counts).
  in_addr source = {};
  in_addr target = {};
  if (inet_pton(AF_INET, params.inner_address.c_str(), &source) != 1 ||
      inet_pton(AF_INET, params.inner_next_hop.c_str(), &target) != 1) {
    return false;
  }
  // SOCK_DGRAM over IPPROTO_ICMP is the unprivileged "ping socket": no
  // CAP_NET_RAW needed, gated instead by net.ipv4.ping_group_range, which
  // systemd ships open to every user (sysctl.d/50-default.conf). A host that
  // keeps the kernel default ("1 0") refuses the socket here and the caller
  // simply keeps polling until its deadline fails closed, exactly as before
  // this probe existed.
  const int probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (probe < 0) {
    return false;
  }
  sockaddr_in bound = {};
  bound.sin_family = AF_INET;
  bound.sin_addr = source;
  if (bind(probe, reinterpret_cast<const sockaddr*>(&bound), sizeof(bound)) !=
      0) {
    close(probe);
    return false;
  }
  icmphdr echo = {};
  echo.type = ICMP_ECHO;
  echo.code = 0;
  echo.un.echo.sequence = htons(1);
  // The identifier and the checksum are the kernel's: on datagram ICMP sockets
  // it overwrites the id with the socket's port and computes the checksum over
  // the header, which is the same mechanism iputils' modern ping uses.
  sockaddr_in destination = {};
  destination.sin_family = AF_INET;
  destination.sin_addr = target;
  const ssize_t sent = sendto(
      probe, &echo, sizeof(echo), 0,
      reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
  const bool sent_fully = sent == static_cast<ssize_t>(sizeof(echo));
  if (sent_fully) {
    // Consume the reflected echo reply, briefly. Receiving it is NOT what
    // advances the gate -- the engine's rx_packets advances the moment it
    // validates and writes the reflected reply into the tun -- but a bounded
    // read hands the reflection back to a listener instead of leaving it
    // unanswered, and keeps this call inside a quarter-second of the caller's
    // promotion budget.
    timeval window = {};
    window.tv_usec = 300000;
    setsockopt(probe, SOL_SOCKET, SO_RCVTIMEO, &window, sizeof(window));
    unsigned char reply[64];
    (void)recvfrom(probe, reply, sizeof(reply), 0, nullptr, nullptr);
  }
  close(probe);
  return sent_fully;
#else
  return false;
#endif
}

std::string LinuxWinn3PumpStatsJson() {
  std::lock_guard<std::mutex> guard(g_mutex);
  if (g_session == nullptr) return "";
  SessionState* state = g_session;
  size_t queued = 0;
  {
    std::lock_guard<std::mutex> ring_guard(state->ring.mutex);
    queued = state->ring.queued;
  }
  std::ostringstream json;
  json << "{\"tun_read_packets\":" << state->counters.tun_read_packets.load()
       << ",\"tun_read_bytes\":" << state->counters.tun_read_bytes.load()
       << ",\"tun_read_oversize\":" << state->counters.tun_read_oversize.load()
       << ",\"ring_dropped\":" << state->counters.ring_dropped.load()
       << ",\"inbound_frames\":" << state->counters.inbound_frames.load()
       << ",\"inbound_write_failed\":"
       << state->counters.inbound_write_failed.load()
       << ",\"outbound_frames\":" << state->counters.outbound_frames.load()
       << ",\"tun_write_failed\":" << state->counters.tun_write_failed.load()
       << ",\"ring_slots\":" << kTunRingSlots
       << ",\"ring_queued\":" << queued;
  {
    // Not a counter, and here anyway: a mechanism that is only ever a local
    // variable is a mechanism nobody can see from outside the process, and an
    // operator looking at a machine whose name resolution is wrong needs to
    // know which of three code paths touched it. Both values are from closed
    // sets -- no path, no address, no resolver IP -- so this stays safe to log
    // in full.
    std::lock_guard<std::mutex> resolver_guard(g_resolver_status_mutex);
    json << ",\"resolver_mechanism\":\""
         << LinuxWinn3ResolverMechanismName(g_resolver_mechanism) << "\""
         << ",\"promoted_posture\":\""
         << LinuxWinn3PostureOutcomeName(g_promoted_outcome) << "\""
         << ",\"promoted_capturing\":"
         << (g_promoted_capturing ? "true" : "false")
         << ",\"bootstrap_posture\":\""
         << LinuxWinn3PostureOutcomeName(g_bootstrap_outcome) << "\""
         << ",\"bootstrap_capturing\":"
         << (g_bootstrap_capturing ? "true" : "false")
         << ",\"bootstrap_exclusion_installed\":"
         << (g_bootstrap_exclusion_installed ? "true" : "false")
         << ",\"bootstrap_stale_repaired\":"
         << (g_bootstrap_stale_repaired ? "true" : "false")
         << ",\"bootstrap_should_retry\":"
         << (LinuxWinn3PostureOutcomeShouldRetry(g_bootstrap_outcome) ? "true"
                                                                      : "false")
         << ",\"bootstrap_error_code\":\""
         << LinuxWinn3PostureOutcomeErrorCode(g_bootstrap_outcome) << "\"";
  }
  json << "}";
  return json.str();
}

void SetLinuxWinn3ResolverStatus(const LinuxWinn3PostureResult& result) {
  std::lock_guard<std::mutex> guard(g_resolver_status_mutex);
  g_resolver_mechanism = result.resolver_mechanism;
  g_promoted_outcome = result.outcome;
  g_promoted_capturing = result.capturing;
  g_resolver_detail = result.resolver_detail;
}

std::string LinuxWinn3ResolverStatusJson() {
  std::lock_guard<std::mutex> guard(g_resolver_status_mutex);
  std::ostringstream json;
  json << "{\"resolver_mechanism\":\""
       << LinuxWinn3ResolverMechanismName(g_resolver_mechanism) << "\""
       << ",\"promoted_posture\":\""
       << LinuxWinn3PostureOutcomeName(g_promoted_outcome) << "\""
       << ",\"promoted_capturing\":"
       << (g_promoted_capturing ? "true" : "false")
       << ",\"resolver_detail\":\"" << JsonEscape(g_resolver_detail) << "\"}";
  return json.str();
}

const char* LinuxWinn3PostureOutcomeErrorCode(
    LinuxWinn3PostureOutcome outcome) {
  switch (outcome) {
    case LinuxWinn3PostureOutcome::kApplied:
      return "WINN3_POSTURE_APPLIED";
    case LinuxWinn3PostureOutcome::kNotAttempted:
      return "WINN3_POSTURE_NOT_ATTEMPTED";
    case LinuxWinn3PostureOutcome::kRolledBack:
      return "WINN3_POSTURE_ROLLED_BACK";
    case LinuxWinn3PostureOutcome::kPartiallyApplied:
      return "WINN3_POSTURE_PARTIALLY_APPLIED";
    case LinuxWinn3PostureOutcome::kExclusionBlocked:
      return "LINUX_WINN3_EXCLUSION_BLOCKED";
  }
  return "WINN3_POSTURE_UNKNOWN";
}

bool LinuxWinn3PostureOutcomeShouldRetry(
    LinuxWinn3PostureOutcome outcome) {
  // Only kExclusionBlocked is NEVER retryable on a timer. It means `ip route
  // add <gw>/32 via <hop> dev <phys>` was refused and the repair that opens
  // every bootstrap proved the route in the way is NOT ours. A timer that
  // retries it spins forever -- the destination is taken by a route this host
  // will never delete. Every other outcome is either success (no retry) or a
  // transient/rolled-back state where a retry with the same parameters may
  // succeed after the underlying condition (missing tool, transient EPERM)
  // changes. kPartiallyApplied with exclusion_installed true is a distinct
  // permanent wedge too, but it is enumerated as PartiallyApplied rather than
  // ExclusionBlocked; callers must read exclusion_installed beside the outcome
  // and treat that combination as non-retryable as well.
  return outcome != LinuxWinn3PostureOutcome::kExclusionBlocked;
}

void SetLinuxWinn3BootstrapStatus(const LinuxWinn3PostureResult& result) {
  std::lock_guard<std::mutex> guard(g_resolver_status_mutex);
  g_bootstrap_outcome = result.outcome;
  g_bootstrap_capturing = result.capturing;
  g_bootstrap_exclusion_installed = result.exclusion_installed;
  g_bootstrap_stale_repaired = result.stale_exclusion_repaired;
  g_bootstrap_error = result.error;
}

std::string LinuxWinn3BootstrapStatusJson() {
  std::lock_guard<std::mutex> guard(g_resolver_status_mutex);
  std::ostringstream json;
  json << "{\"bootstrap_posture\":\""
       << LinuxWinn3PostureOutcomeName(g_bootstrap_outcome) << "\""
       << ",\"bootstrap_capturing\":"
       << (g_bootstrap_capturing ? "true" : "false")
       << ",\"bootstrap_exclusion_installed\":"
       << (g_bootstrap_exclusion_installed ? "true" : "false")
       << ",\"bootstrap_stale_repaired\":"
       << (g_bootstrap_stale_repaired ? "true" : "false")
       << ",\"bootstrap_should_retry\":"
       << (LinuxWinn3PostureOutcomeShouldRetry(g_bootstrap_outcome) ? "true"
                                                                    : "false")
       << ",\"bootstrap_error\":\"" << JsonEscape(g_bootstrap_error) << "\""
       << ",\"bootstrap_error_code\":\""
       << LinuxWinn3PostureOutcomeErrorCode(g_bootstrap_outcome) << "\"}";
  return json.str();
}

}  // namespace winsvpn::winn3host
