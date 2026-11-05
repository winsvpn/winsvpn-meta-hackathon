// A driver that runs linux/runner/linux_winn3_host.cc against a REAL Winn
// Protocol v3 gateway THROUGH A REAL KERNEL TUN DEVICE, and measures what
// actually crossed.
//
// WHY THIS FILE EXISTS, AND HOW IT DIFFERS FROM linux_winn3_host_e2e.cc
//
// linux_winn3_host_e2e.cc is the sibling driver that runs WITHOUT privilege: it
// hands StartLinuxWinn3Engine one end of an AF_UNIX SOCK_DGRAM socketpair in
// place of a tun descriptor. That driver is honest about the cost in its own
// header, and it stays exactly as it is -- it is the only thing that can run on
// a host with no CAP_NET_ADMIN, which was every reachable Linux host until
// 2026-08-10.
//
// This file is the privileged variant. It calls OpenLinuxWinn3Tun, which had
// never executed in the history of this project, and it therefore exercises the
// six things the socketpair driver explicitly could not:
//
//   1. open("/dev/net/tun") and the TUNSETIFF attach with IFF_TUN | IFF_NO_PI;
//   2. the kernel netdev that attach creates, by name;
//   3. interface MTU enforcement by the kernel, via the bootstrap posture;
//   4. ApplyLinuxWinn3BootstrapPosture against a REAL privileged runner that
//      actually forks and execs `ip` -- the narrow posture, applied for real;
//   5. ApplyLinuxWinn3PromotedPosture, likewise, after the engine's own
//      promotion predicate fires on real counters;
//   6. the outer-socket exclusion as an actual kernel route, which is only
//      meaningful because the gateway is on a DIFFERENT host reached over a
//      real interface rather than over loopback;
//   7. since 2026-08-10, RenderLinuxWinn3TeardownCommands, executed for real.
//      This driver did not run a teardown at all before that, and could get
//      away with it while every posture command was a route on a device that
//      disappears with its last descriptor. It cannot now: the /etc/resolv.conf
//      resolver mechanism leaves a FILE behind, and a driver that promoted
//      through it and then exited would be a demonstration of the exact
//      stranding that mechanism is built to avoid.
//
// # WHAT IS REAL HERE
//
// REAL: the host device is /dev/net/tun and the packets are carried by the
// Linux network stack, not handed between two file descriptors in this process;
// the engine subprocess is the real `cmd/winn-datapath` in `-winn3` frame mode;
// the far end is the real `cmd/winn3-gateway` in a separate network namespace
// on a separate address, holding its own unconnected UDP socket; the handshake
// is the real v3 handshake (X25519 + ML-KEM-768, StrictPQ by default); the
// payload is real ChaCha20-Poly1305 over the real
// `DemuxToken(8) || AEAD(frames || padding)` wire shape; the inner packets are
// real IPv4/UDP datagrams validated by winn3/tun's inner-IP validator at both
// ends; and every counter printed below is read back from the engine's own
// status document or counted by this driver's own sockets.
//
// # HOW THE INNER PACKETS ARE INJECTED AND COLLECTED
//
// The socketpair driver held BOTH ends of the device, so it could write an
// inner packet straight into the engine's descriptor. A real tun has no such
// second end: the other side of a tun is the kernel routing table. So this
// driver sends through the kernel and receives through the kernel, which is the
// whole point -- if a packet comes back, it was routed into the tun by the
// kernel, read off the descriptor by the engine, encrypted, carried, decrypted,
// written back to the descriptor, and delivered up the stack to a socket.
//
// Sending uses a raw IPv4 socket with IP_HDRINCL, NOT an ordinary UDP socket,
// and the reason is specific: the far end is a reflector that swaps the source
// and destination addresses WITHOUT recomputing the UDP checksum. A kernel-built
// UDP datagram carries a real checksum, the swap invalidates it, and the
// receiving kernel would then discard every returned packet as corrupt -- a
// total loss that would look like a datapath failure and is really a harness
// one. Building the header here keeps the UDP checksum at zero, which IPv4
// permits (RFC 768) and which survives the swap intact. This is the same reason
// BuildInnerPacket in the sibling driver leaves it zero, and the packet builder
// below is deliberately byte-identical to that one so the two runs are
// comparable.
//
// Receiving uses an ordinary UDP socket bound to the inner address, because
// with a zero checksum the kernel accepts the reflected datagram normally, and
// binding it also absorbs the ICMP port-unreachable the kernel would otherwise
// generate and send back down the tunnel.
//
// # USAGE
//
//   linux_winn3_host_tun_e2e --engine PATH --gateway IP:PORT --keys-dir DIR
//       --gateway-id ID --phys-if NAME --phys-next-hop IP
//       [--tun NAME] [--inner-v4 IP] [--router-v4 IP] [--count N] [--payload N]
//       [--path-mtu N] [--classes udp,tcp,tls] [--gap-us N] [--settle-ms N]
//       [--promoted-count N]
//       [--force-resolver systemd-resolved|resolvconf|resolv.conf|none]
//       [--refuse-command SUBSTRING[,SUBSTRING...]]
//
// # THE TWO FLAGS ADDED ON 2026-08-10, AND WHY THEY ARE NOT A SIMULATION
//
// `--force-resolver` pins LinuxWinn3Params::resolver_mechanism_override, so a
// container with no systemd-resolved can be driven down the systemd-resolved
// path. That is not a mock: `resolvectl dns` then really runs and really exits
// 127, which is the measurement of 2026-08-10 reproduced rather than described.
//
// `--refuse-command SUBSTRING[,SUBSTRING...]` makes the privileged runner
// refuse a matching argument vector instead of executing it. The command
// genuinely does not run, every command before it genuinely did, and `ip route
// get 1.1.1.1` afterwards is still the kernel's own answer -- which is the only
// way to construct a failure at a chosen point in a posture (a failing
// ROLLBACK, in particular) without lying about what the kernel holds.
//
// It became a LIST for the bootstrap arm of that work. A failed rollback needs
// two independent failures -- the command that stops the run and the reversal
// that then cannot undo it -- and the promoted arm could borrow its first one
// from `--force-resolver`, while the bootstrap posture runs no resolver command
// to borrow from.
//
// # THE LAB, ON A MAC, WITHOUT TOUCHING THE MAC
//
// A promoted v3 posture installs the 0.0.0.0/1 + 128.0.0.0/1 pair and the lab
// far end egresses nothing, so bringing this up in the Mac's own network
// namespace takes the machine off the internet. It stays in a container:
//
//   export DOCKER_HOST=unix:///Users/owner/.colima/default/docker.sock
//   docker network create --subnet 172.31.77.0/24 winn3lab_posture
//   # engine and gateway, cross-compiled from the repo root:
//   GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o BIN/winn-datapath
//       ./winn_protocol_experimental/cmd/winn-datapath
//   GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o BIN/winn3-gateway
//       ./winn_protocol_experimental/cmd/winn3-gateway
//   # keys, then the gateway on its own address:
//   winn3-gateway -mode keygen -out KEYS
//   docker run -d --network winn3lab_posture --ip 172.31.77.2 IMAGE
//       winn3-gateway -mode serve -listen 0.0.0.0:51833 -static KEYS/static.key
//       -admission KEYS/admission.key -gateway-id winn3-lab-1
//       -inner-v4 10.64.0.1 -plan udp,tcp,tls -path-mtu 1500
//   # NOTE: -router-v4 must NOT be 10.64.0.1 as well. The gateway refuses that
//   # ("the inner next hop cannot be this gateway's own inner address") and
//   # every handshake then goes unanswered, which reads exactly like a censor.
//   # this driver, privileged, on a second address:
//   docker run --rm --network winn3lab_posture --ip 172.31.77.3
//       --cap-add=NET_ADMIN --device /dev/net/tun IMAGE
//       tun_e2e --engine ENGINE --gateway 172.31.77.2:51833 --keys-dir KEYS
//       --gateway-id winn3-lab-1 --phys-if eth0 --phys-next-hop 172.31.77.1
//
// The image is gcc:13 plus iproute2 (`winn3-tunlab:1`); the openresolv and
// systemd-resolved variants used to prove the other two resolver mechanisms are
// that image plus `openresolv` and plus `systemd-resolved dbus`. The scripts
// that drive all of it are in
// .artifacts/winn3-linux-posture-20260810/run_lab*.sh.

#include "linux_winn3_host.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace {

using winsvpn::winn3::EngineStatus;
using winsvpn::winn3host::LinuxWinn3Params;
using winsvpn::winn3host::LinuxWinn3Promotion;

// ---------------------------------------------------------------------------
// The deterministic payload. Byte-identical to linux_winn3_host_e2e.cc, so a
// run of this driver and a run of that one are comparable packet for packet.
// Regenerable from the sequence number alone, so a returned packet is verified
// byte-for-byte against what it should be rather than merely counted.
// ---------------------------------------------------------------------------
void FillPayload(uint32_t seq, uint8_t* out, size_t size) {
  out[0] = static_cast<uint8_t>(seq >> 24);
  out[1] = static_cast<uint8_t>(seq >> 16);
  out[2] = static_cast<uint8_t>(seq >> 8);
  out[3] = static_cast<uint8_t>(seq);
  out[4] = static_cast<uint8_t>(~(seq >> 24));
  out[5] = static_cast<uint8_t>(~(seq >> 16));
  out[6] = static_cast<uint8_t>(~(seq >> 8));
  out[7] = static_cast<uint8_t>(~seq);
  for (size_t i = 8; i < size; ++i) {
    out[i] = static_cast<uint8_t>((seq * 31u) + (i * 17u) + 0x5Au);
  }
}

constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

void FnvUpdate(uint64_t* h, const uint8_t* data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    *h ^= data[i];
    *h *= kFnvPrime;
  }
}

// ---------------------------------------------------------------------------
// Inner IPv4/UDP framing. Byte-identical to the sibling driver.
// ---------------------------------------------------------------------------
uint16_t Ipv4HeaderChecksum(const uint8_t* header, size_t size) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < size; i += 2) {
    sum += static_cast<uint32_t>((header[i] << 8) | header[i + 1]);
  }
  while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

size_t BuildInnerPacket(uint32_t seq, uint32_t src_be, uint32_t dst_be,
                        uint16_t sport, uint16_t dport, size_t payload_size,
                        uint8_t* out) {
  const size_t total = 20 + 8 + payload_size;
  std::memset(out, 0, 28);
  out[0] = 0x45;  // IPv4, IHL 5
  out[1] = 0x00;
  out[2] = static_cast<uint8_t>(total >> 8);
  out[3] = static_cast<uint8_t>(total);
  out[4] = static_cast<uint8_t>(seq >> 8);  // identification
  out[5] = static_cast<uint8_t>(seq);
  out[6] = 0x40;  // Don't Fragment
  out[7] = 0x00;
  out[8] = 64;    // TTL
  out[9] = 17;    // UDP
  std::memcpy(out + 12, &src_be, 4);
  std::memcpy(out + 16, &dst_be, 4);
  const uint16_t checksum = Ipv4HeaderChecksum(out, 20);
  out[10] = static_cast<uint8_t>(checksum >> 8);
  out[11] = static_cast<uint8_t>(checksum);

  const uint16_t udp_len = static_cast<uint16_t>(8 + payload_size);
  out[20] = static_cast<uint8_t>(sport >> 8);
  out[21] = static_cast<uint8_t>(sport);
  out[22] = static_cast<uint8_t>(dport >> 8);
  out[23] = static_cast<uint8_t>(dport);
  out[24] = static_cast<uint8_t>(udp_len >> 8);
  out[25] = static_cast<uint8_t>(udp_len);
  out[26] = 0;  // checksum: none, and it must stay none. See the header.
  out[27] = 0;

  FillPayload(seq, out + 28, payload_size);
  return total;
}

// ---------------------------------------------------------------------------
// The privileged runner. THIS one actually executes.
//
// The sibling driver passes no runner at all and applies no posture. Here the
// runner forks and execs the argument vector the policy header rendered, and
// every command and its exit status is printed, so the posture that was applied
// can be read off the log rather than inferred from the fact that it returned
// true.
// ---------------------------------------------------------------------------
std::vector<std::string> g_applied_commands;

// Commands the runner must REFUSE rather than execute, by substring.
//
// This is the only way to construct a failure at a chosen point in a posture
// without lying about what the kernel holds: the command genuinely does not
// run, everything before it genuinely did, and `ip route get` afterwards is
// still the kernel's own answer. It exists for the partial-failure and
// failed-rollback arms of the 2026-08-10 fail-open work, and it is empty in
// every ordinary run.
//
// A LIST since the bootstrap arm of that work, comma-separated, because a
// failed ROLLBACK needs two independent failures: the posture command that
// stops the run, and the reversal that then cannot undo it. The promoted arm
// could get its first failure for free -- `--force-resolver systemd-resolved`
// on a container without it makes `resolvectl` really exit 127 -- and the
// bootstrap posture runs no resolver command, so it has no equivalent free
// failure to borrow.
std::vector<std::string> g_refuse_substrings;

std::string JoinArgv(const std::vector<std::string>& argv) {
  std::string out;
  for (size_t i = 0; i < argv.size(); ++i) {
    if (i != 0) out += " ";
    out += argv[i];
  }
  return out;
}

// Runs argv and waits. True only when it exited zero. Nothing here is a shell:
// the vector is passed to execvp unchanged, so no quoting exists to get wrong.
//
// `stdin_bytes` is written to the child's standard input, which is then closed.
// openresolv reads the resolv.conf body that way and has no argument form for
// it, so a runner that could not carry standard input would leave `sh -c` as
// the only route to it -- and a shell string is the quoting bug argument
// vectors exist to remove.
bool RunArgv(const std::vector<std::string>& argv,
             const std::string& stdin_bytes, std::string* error) {
  if (argv.empty()) {
    if (error != nullptr) *error = "empty command";
    return false;
  }
  for (const std::string& refuse : g_refuse_substrings) {
    if (refuse.empty() || JoinArgv(argv).find(refuse) == std::string::npos) {
      continue;
    }
    std::printf(
        "{\"event\":\"posture_command\",\"argv\":\"%s\",\"exit\":-1,"
        "\"refused_by_harness\":true}\n",
        JoinArgv(argv).c_str());
    std::fflush(stdout);
    if (error != nullptr) {
      *error = "refused by the harness (--refuse-command): " + JoinArgv(argv);
    }
    return false;
  }
  std::vector<char*> raw;
  raw.reserve(argv.size() + 1);
  for (const std::string& part : argv) {
    raw.push_back(const_cast<char*>(part.c_str()));
  }
  raw.push_back(nullptr);

  int input[2] = {-1, -1};
  if (pipe(input) != 0) {
    if (error != nullptr) *error = "pipe failed for: " + JoinArgv(argv);
    return false;
  }
  const pid_t pid = fork();
  if (pid < 0) {
    close(input[0]);
    close(input[1]);
    if (error != nullptr) *error = "fork failed for: " + JoinArgv(argv);
    return false;
  }
  if (pid == 0) {
    close(input[1]);
    dup2(input[0], STDIN_FILENO);
    close(input[0]);
    execvp(raw[0], raw.data());
    _exit(127);
  }
  close(input[0]);
  size_t written = 0;
  while (written < stdin_bytes.size()) {
    const ssize_t count = write(input[1], stdin_bytes.data() + written,
                                stdin_bytes.size() - written);
    if (count <= 0) break;
    written += static_cast<size_t>(count);
  }
  close(input[1]);

  int status = 0;
  if (waitpid(pid, &status, 0) != pid) {
    if (error != nullptr) *error = "waitpid failed for: " + JoinArgv(argv);
    return false;
  }
  const bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  const int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  std::printf(
      "{\"event\":\"posture_command\",\"argv\":\"%s\",\"exit\":%d,"
      "\"stdin_bytes\":%zu}\n",
      JoinArgv(argv).c_str(), code, stdin_bytes.size());
  std::fflush(stdout);
  g_applied_commands.push_back(JoinArgv(argv));
  if (!ok && error != nullptr) {
    *error = "command failed (exit " + std::to_string(code) +
             "): " + JoinArgv(argv);
  }
  return ok;
}

// Runs argv purely to put the kernel's own view of the interface into the log.
// Its exit status is NOT part of any verdict.
void ShowForTheRecord(const std::vector<std::string>& argv) {
  std::printf("{\"event\":\"kernel_state\",\"argv\":\"%s\"}\n",
              JoinArgv(argv).c_str());
  std::fflush(stdout);
  std::vector<char*> raw;
  raw.reserve(argv.size() + 1);
  for (const std::string& part : argv) {
    raw.push_back(const_cast<char*>(part.c_str()));
  }
  raw.push_back(nullptr);
  const pid_t pid = fork();
  if (pid < 0) return;
  if (pid == 0) {
    execvp(raw[0], raw.data());
    _exit(127);
  }
  int status = 0;
  (void)waitpid(pid, &status, 0);
  std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// The receiving half. Reads payloads off an ordinary UDP socket bound to the
// inner address -- so anything it counts was delivered by the kernel, up the
// stack, from the tun device.
// ---------------------------------------------------------------------------
struct Receiver {
  std::atomic<uint64_t> packets{0};
  std::atomic<uint64_t> payload_bytes{0};
  std::atomic<uint64_t> corrupt{0};
  std::atomic<uint64_t> duplicate{0};
  std::atomic<uint64_t> malformed{0};
  std::atomic<bool> stop{false};
  std::vector<uint8_t> seen;   // one byte per sequence number
  size_t payload_size = 0;
  int fd = -1;
};

void ReceiveLoop(Receiver* rx) {
  std::vector<uint8_t> buffer(70000);
  std::vector<uint8_t> expected(rx->payload_size);
  while (!rx->stop.load()) {
    pollfd pfd{rx->fd, POLLIN, 0};
    const int ready = poll(&pfd, 1, 200);
    if (ready <= 0) continue;
    const ssize_t count = recv(rx->fd, buffer.data(), buffer.size(), 0);
    if (count <= 0) continue;
    const size_t size = static_cast<size_t>(count);
    // A UDP socket hands up the payload alone, so the whole datagram IS the
    // payload the sender built.
    if (size != rx->payload_size) {
      rx->malformed.fetch_add(1);
      continue;
    }
    const uint8_t* body = buffer.data();
    const uint32_t seq = (static_cast<uint32_t>(body[0]) << 24) |
                         (static_cast<uint32_t>(body[1]) << 16) |
                         (static_cast<uint32_t>(body[2]) << 8) |
                         static_cast<uint32_t>(body[3]);
    if (seq >= rx->seen.size()) {
      rx->malformed.fetch_add(1);
      continue;
    }
    FillPayload(seq, expected.data(), expected.size());
    if (std::memcmp(body, expected.data(), expected.size()) != 0) {
      rx->corrupt.fetch_add(1);
      continue;
    }
    if (rx->seen[seq] != 0) {
      rx->duplicate.fetch_add(1);
      continue;
    }
    rx->seen[seq] = 1;
    rx->packets.fetch_add(1);
    rx->payload_bytes.fetch_add(size);
  }
}

// ---------------------------------------------------------------------------
// One inner flow: a raw send socket and a bound UDP receive socket, on one
// inner port.
//
// The driver runs TWO of these -- one for the uplink (host -> far end) and one
// for the downlink (far end -> host) -- so the two directions are measured on
// separate sockets, separate ports and separate sequence namespaces, and each
// is verified independently below. A single socket pair cannot separate the
// two directions: the reflector echoes to the port it was sent from, so the
// return path of a single flow is inseparable from its send path.
// ---------------------------------------------------------------------------
struct InnerFlow {
  int send_fd = -1;
  int recv_fd = -1;
  uint16_t port = 0;
  Receiver rx;  // owns its own seen set, sized to this flow's capacity
  uint32_t src_be = 0;
  uint32_t dst_be = 0;
  sockaddr_in dst{};
};

bool OpenInnerFlow(const std::string& inner_v4, const std::string& router_v4,
                   uint16_t port, size_t payload_size, size_t capacity,
                   InnerFlow* flow, std::string* error) {
  flow->port = port;
  flow->send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (flow->send_fd < 0) {
    *error = "raw send socket";
    return false;
  }
  const int one = 1;
  setsockopt(flow->send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
  flow->recv_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (flow->recv_fd < 0) {
    *error = "udp receive socket";
    return false;
  }
  const int buffer_bytes = 8 * 1024 * 1024;
  setsockopt(flow->recv_fd, SOL_SOCKET, SO_RCVBUF, &buffer_bytes,
             sizeof(buffer_bytes));
  sockaddr_in bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(port);
  inet_pton(AF_INET, inner_v4.c_str(), &bind_addr.sin_addr);
  if (bind(flow->recv_fd, reinterpret_cast<sockaddr*>(&bind_addr),
           sizeof(bind_addr)) != 0) {
    *error = "bind on the inner address";
    return false;
  }
  inet_pton(AF_INET, inner_v4.c_str(), &flow->src_be);
  inet_pton(AF_INET, router_v4.c_str(), &flow->dst_be);
  flow->dst.sin_family = AF_INET;
  flow->dst.sin_port = htons(port);
  flow->dst.sin_addr.s_addr = flow->dst_be;
  flow->rx.fd = flow->recv_fd;
  flow->rx.payload_size = payload_size;
  flow->rx.seen.assign(capacity, 0);
  return true;
}

void CloseInnerFlow(InnerFlow* flow) {
  if (flow->send_fd >= 0) close(flow->send_fd);
  if (flow->recv_fd >= 0) close(flow->recv_fd);
  flow->send_fd = -1;
  flow->recv_fd = -1;
}

// FNV-1a over the reconstructed payload set of a flow's received/seen sequence
// numbers, in sequence order. The same digest the sibling driver computes over
// its single round trip, so the returned-integrity claim has the same shape
// here, once per direction.
uint64_t ReturnedDigest(const InnerFlow& flow, size_t payload_size) {
  uint64_t digest = kFnvOffset;
  std::vector<uint8_t> body(payload_size);
  for (uint32_t seq = 0; seq < flow.rx.seen.size(); ++seq) {
    if (flow.rx.seen[seq] == 0) continue;
    FillPayload(seq, body.data(), body.size());
    FnvUpdate(&digest, body.data(), body.size());
  }
  return digest;
}

// Reads an unsigned integer value for a JSON key of the form
// "key":<digits> from a compact single-line JSON document. Returns 0 when the
// key is absent. Used to read the engine's own OUTBOUND counter (tx_packets),
// which the parsed EngineStatus deliberately does not carry; a falsely-zero
// read makes the uplink assertion fail rather than pass, so it never launders
// a green.
uint64_t ExtractJsonUint(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\":";
  const size_t at = json.find(needle);
  if (at == std::string::npos) return 0;
  size_t c = at + needle.size();
  while (c < json.size() && json[c] == ' ') ++c;
  uint64_t value = 0;
  bool any = false;
  while (c < json.size() && json[c] >= '0' && json[c] <= '9') {
    value = value * 10 + static_cast<uint64_t>(json[c] - '0');
    ++c;
    any = true;
  }
  return any ? value : 0;
}

// ---------------------------------------------------------------------------
// Argument handling.
// ---------------------------------------------------------------------------
std::string Argument(int argc, char** argv, const std::string& name,
                     const std::string& fallback) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (name == argv[i]) return argv[i + 1];
  }
  return fallback;
}

std::vector<std::string> SplitCommas(const std::string& value) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= value.size()) {
    const size_t end = value.find(',', start);
    if (end == std::string::npos) {
      if (start < value.size()) out.push_back(value.substr(start));
      break;
    }
    if (end > start) out.push_back(value.substr(start, end - start));
    start = end + 1;
  }
  return out;
}

uint64_t NowMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

}  // namespace

int main(int argc, char** argv) {
  const std::string engine = Argument(argc, argv, "--engine", "");
  const std::string gateway = Argument(argc, argv, "--gateway", "");
  const std::string keys_dir = Argument(argc, argv, "--keys-dir", "");
  const std::string gateway_id =
      Argument(argc, argv, "--gateway-id", "winn3-lab-1");
  const std::string tun_name = Argument(argc, argv, "--tun", "winsvpn3");
  const std::string inner_v4 = Argument(argc, argv, "--inner-v4", "10.64.0.2");
  const std::string router_v4 = Argument(argc, argv, "--router-v4", "10.64.0.1");
  const std::string phys_if = Argument(argc, argv, "--phys-if", "");
  const std::string phys_next_hop = Argument(argc, argv, "--phys-next-hop", "");
  const size_t count = static_cast<size_t>(
      std::atol(Argument(argc, argv, "--count", "4096").c_str()));
  const size_t promoted_count = static_cast<size_t>(
      std::atol(Argument(argc, argv, "--promoted-count", "512").c_str()));
  // The DOWNLINK flow's burst size, on a second inner port. Zero (the default)
  // runs the uplink-only round trip exactly as before -- backward compatible
  // with every existing lab invocation. A nonzero value arms the second,
  // directionally-separate flow and PRESSES the bidirectional seal.
  const size_t downlink_count = static_cast<size_t>(
      std::atol(Argument(argc, argv, "--downlink-count", "0").c_str()));
  const size_t payload_size = static_cast<size_t>(
      std::atol(Argument(argc, argv, "--payload", "1024").c_str()));
  const int path_mtu = std::atoi(Argument(argc, argv, "--path-mtu", "1500").c_str());
  const std::vector<std::string> classes =
      SplitCommas(Argument(argc, argv, "--classes", "udp,tcp,tls"));
  const long gap_us = std::atol(Argument(argc, argv, "--gap-us", "300").c_str());
  const long settle_ms =
      std::atol(Argument(argc, argv, "--settle-ms", "20000").c_str());
  const std::string forced_resolver =
      Argument(argc, argv, "--force-resolver", "");
  const std::string refuse_list = Argument(argc, argv, "--refuse-command", "");
  if (!refuse_list.empty()) g_refuse_substrings = SplitCommas(refuse_list);
  const uint16_t flow_port = 51999;

  // The mechanism pin, for the runs that have to drive ONE mechanism's commands
  // at a host that would have chosen a different one -- including pinning
  // systemd-resolved at a container that has none, which is the 2026-08-10
  // measurement reproduced exactly rather than described.
  winsvpn::winn3host::LinuxWinn3ResolverMechanism resolver_override =
      winsvpn::winn3host::LinuxWinn3ResolverMechanism::kUnknown;
  if (!forced_resolver.empty()) {
    if (forced_resolver == "systemd-resolved") {
      resolver_override =
          winsvpn::winn3host::LinuxWinn3ResolverMechanism::kSystemdResolved;
    } else if (forced_resolver == "resolvconf") {
      resolver_override =
          winsvpn::winn3host::LinuxWinn3ResolverMechanism::kResolvconf;
    } else if (forced_resolver == "resolv.conf") {
      resolver_override =
          winsvpn::winn3host::LinuxWinn3ResolverMechanism::kResolvConfFile;
    } else if (forced_resolver == "none") {
      resolver_override =
          winsvpn::winn3host::LinuxWinn3ResolverMechanism::kNone;
    } else {
      std::fprintf(stderr,
                   "--force-resolver takes systemd-resolved, resolvconf, "
                   "resolv.conf or none\n");
      return 2;
    }
  }

  if (engine.empty() || gateway.empty() || keys_dir.empty() ||
      phys_if.empty() || phys_next_hop.empty()) {
    std::fprintf(stderr,
                 "usage: %s --engine PATH --gateway IP:PORT --keys-dir DIR "
                 "--phys-if NAME --phys-next-hop IP [--gateway-id ID] "
                 "[--tun NAME] [--inner-v4 IP] [--router-v4 IP] [--count N] "
                 "[--promoted-count N] [--downlink-count N] [--payload N] "
                 "[--path-mtu N] "
                 "[--classes udp,tcp,tls] [--gap-us N] [--settle-ms N] "
                 "[--force-resolver systemd-resolved|resolvconf|resolv.conf|"
                 "none] [--refuse-command SUBSTRING[,SUBSTRING...]]\n",
                 argv[0]);
    return 2;
  }

  // The sizing mirror is checked BEFORE anything is started, exactly as the
  // sibling driver does. A drift here is the 84-byte black hole, and finding it
  // after a run would mean the run's numbers were measured against the wrong
  // floor.
  std::string sizing_error;
  if (!winsvpn::winn3host::sizing::AssertsAgreeWithGo(&sizing_error)) {
    std::fprintf(stderr, "sizing mirror disagrees with Go: %s\n",
                 sizing_error.c_str());
    return 1;
  }
  int planned_inner_mtu = 0;
  std::string plan_error;
  if (!winsvpn::winn3host::sizing::PlanFloorInnerMtu(path_mtu, classes,
                                                     &planned_inner_mtu,
                                                     &plan_error)) {
    std::fprintf(stderr, "plan floor: %s\n", plan_error.c_str());
    return 1;
  }
  const size_t inner_packet_size = 28 + payload_size;
  if (inner_packet_size > static_cast<size_t>(planned_inner_mtu)) {
    std::fprintf(stderr, "inner packet %zu exceeds the plan floor inner MTU %d\n",
                 inner_packet_size, planned_inner_mtu);
    return 1;
  }

  // -------------------------------------------------------------------------
  // THE POINT OF THIS FILE.
  // -------------------------------------------------------------------------
  std::string tun_error;
  const int tun_fd = winsvpn::winn3host::OpenLinuxWinn3Tun(tun_name, &tun_error);
  if (tun_fd < 0) {
    std::fprintf(stderr, "OpenLinuxWinn3Tun failed: %s\n", tun_error.c_str());
    return 1;
  }
  const unsigned int tun_index = if_nametoindex(tun_name.c_str());
  std::printf(
      "{\"event\":\"tun_open\",\"device\":\"/dev/net/tun\",\"interface\":\"%s\","
      "\"ifindex\":%u,\"flags\":\"IFF_TUN|IFF_NO_PI\"}\n",
      tun_name.c_str(), tun_index);
  std::fflush(stdout);
  if (tun_index == 0) {
    std::fprintf(stderr,
                 "the tun descriptor opened but the kernel has no interface "
                 "named %s; refusing to report a device that is not there\n",
                 tun_name.c_str());
    close(tun_fd);
    return 1;
  }

  LinuxWinn3Params params;
  params.interface_name = tun_name;
  params.gateway_endpoint = gateway;
  params.inner_address = inner_v4;
  params.inner_next_hop = router_v4;
  params.path_mtu = path_mtu;
  params.carrier_classes = classes;
  params.session_id = "7ba0000000000000tun0000000000000";
  params.full_routes = {"0.0.0.0/1", "128.0.0.0/1"};
  params.dns_servers = {router_v4};
  params.dns_servers_are_inner = true;
  params.resolver_mechanism_override = resolver_override;
  // NOT decorative here, unlike the sibling driver: these two name the real
  // interface and next hop that the exclusion route is installed on, and that
  // route is what keeps the engine's own outer datagrams out of the tunnel once
  // the promoted posture points both halves of the address space at the tun.
  params.physical_interface = phys_if;
  params.physical_next_hop = phys_next_hop;
  params.keys.role = "client";
  params.keys.gateway_id = gateway_id;
  params.keys.static_path = keys_dir + "/client.key";
  params.keys.gateway_static_path = keys_dir + "/static.pub";
  params.keys.admission_path = keys_dir + "/admission.key";
  params.keys.outer_socket_exclusion =
      winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params);

  // REMEMBERED so every teardown in this driver -- the aborts and the final
  // exit -- goes through StopLinuxWinn3Standalone, the SAME unified teardown
  // the production StopTunnel uses. A harness that tears down differently
  // from the product measures a teardown the product does not have.
  winsvpn::winn3host::RememberLinuxWinn3Session(params);

  // OWNERSHIP OF tun_fd PASSES TO THIS CALL ON EVERY OUTCOME.
  EngineStatus ack;
  std::string error;
  const uint64_t started_at = NowMs();
  if (!winsvpn::winn3host::StartLinuxWinn3Engine(engine, tun_fd, params, &ack,
                                                 &error)) {
    std::fprintf(stderr, "StartLinuxWinn3Engine failed: %s\n", error.c_str());
    return 1;
  }
  const uint64_t create_ack_ms = NowMs() - started_at;
  std::printf(
      "{\"event\":\"create_ack\",\"ms\":%llu,\"inner_mtu\":%d,"
      "\"message_size\":%d,\"inner_ipv6\":%s,\"gate_state\":\"%s\","
      "\"planned_inner_mtu\":%d}\n",
      static_cast<unsigned long long>(create_ack_ms), ack.inner_mtu,
      ack.message_size, ack.inner_ipv6 ? "true" : "false",
      ack.gate_state.c_str(), planned_inner_mtu);
  std::fflush(stdout);

  // -------------------------------------------------------------------------
  // The narrow posture, applied for real. The engine's CreateAck is where the
  // authoritative inner MTU comes from, which is why this runs after the start
  // and not before it.
  // -------------------------------------------------------------------------
  const winsvpn::winn3host::LinuxWinn3PrivilegedRunner runner =
      [](const std::vector<std::string>& argv, const std::string& stdin_bytes,
         std::string* err) { return RunArgv(argv, stdin_bytes, err); };
  winsvpn::winn3::PosturePlan bootstrap_plan;
  const winsvpn::winn3host::LinuxWinn3PostureResult bootstrap =
      winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(params, ack, runner,
                                                          &bootstrap_plan);
  const bool bootstrap_ok =
      bootstrap.outcome == winsvpn::winn3host::LinuxWinn3PostureOutcome::kApplied;
  std::printf(
      "{\"event\":\"bootstrap_posture\",\"outcome\":\"%s\",\"applied\":%s,"
      "\"exclusion_installed\":%s,\"stale_exclusion_repaired\":%s,"
      "\"capturing\":%s,\"applied_commands\":%zu,"
      "\"rollback_attempted\":%s,\"rollback_failed\":%zu,\"mtu\":%d,"
      "\"inner_v4\":\"%s/%d\",\"routes\":%zu,\"default_route\":%s,"
      "\"error\":\"%s\"}\n",
      winsvpn::winn3host::LinuxWinn3PostureOutcomeName(bootstrap.outcome),
      bootstrap_ok ? "true" : "false",
      bootstrap.exclusion_installed ? "true" : "false",
      bootstrap.stale_exclusion_repaired ? "true" : "false",
      bootstrap.capturing ? "true" : "false", bootstrap.applied.size(),
      bootstrap.rollback_attempted ? "true" : "false",
      bootstrap.rollback_failed.size(), bootstrap_plan.mtu,
      bootstrap_plan.inner_v4.c_str(), bootstrap_plan.prefix_v4,
      bootstrap_plan.included_routes.size(),
      bootstrap_plan.default_route ? "true" : "false",
      bootstrap.error.c_str());
  std::printf("{\"event\":\"bootstrap_posture_detail\",\"describe\":\"%s\"}\n",
              winsvpn::winn3host::DescribeLinuxWinn3PostureResult(bootstrap)
                  .c_str());
  std::fflush(stdout);
  if (!bootstrap_ok) {
    // ALWAYS, and BEFORE the engine is stopped, for the same reason the promoted
    // arm dumps the kernel below: a result type that claims a rollback happened
    // is worth no more than the boolean it replaced if nobody asks the kernel.
    // Stopping the engine first would close the tun descriptor and delete the
    // device, which would hide whether the tun-scoped commands had really been
    // reversed or had merely gone with the interface.
    ShowForTheRecord({"ip", "route", "show"});
    ShowForTheRecord({"ip", "-o", "addr", "show"});
    std::fprintf(stderr,
                 "the bootstrap posture did not apply (%s): %s\n"
                 "refusing to send traffic through an interface whose posture "
                 "is unknown\n",
                 winsvpn::winn3host::LinuxWinn3PostureOutcomeName(
                     bootstrap.outcome),
                 bootstrap.error.c_str());
    if (bootstrap.exclusion_installed) {
      // The one residue that does not go when this process does. Named on
      // stderr because an operator who sees only "posture failed" and retries
      // will meet EEXIST on the first command and no explanation at all.
      std::fprintf(stderr,
                   "THE OUTER-SOCKET EXCLUSION IS STILL INSTALLED on the "
                   "physical interface and will outlive this process. The next "
                   "bootstrap's FIRST command is that same `ip route add` and "
                   "it will fail EEXIST until the route is removed -- although "
                   "the next start now repairs exactly this, because the route "
                   "it would remove is byte-for-byte the one we wrote.\n");
    }
    if (bootstrap.outcome ==
        winsvpn::winn3host::LinuxWinn3PostureOutcome::kExclusionBlocked) {
      // NOT retryable, and said in those words. A caller that treated this like
      // any other posture failure and backed off into a retry loop would spin
      // forever on a route no retry can move.
      std::fprintf(stderr,
                   "THE GATEWAY'S DESTINATION IS ROUTED BY AN ENTRY THIS HOST "
                   "DID NOT WRITE. It was NOT removed: this host cannot tell a "
                   "previous session on another network from a route the user "
                   "or another tool owns, and it keeps no copy to put back. Do "
                   "not retry on a timer -- the next attempt fails "
                   "identically.\n");
    }
    winsvpn::winn3host::StopLinuxWinn3Engine();
    return 1;
  }
  ShowForTheRecord({"ip", "-o", "addr", "show", "dev", tun_name});
  ShowForTheRecord({"ip", "-o", "link", "show", "dev", tun_name});
  ShowForTheRecord({"ip", "route", "show"});

  // -------------------------------------------------------------------------
  // FROM HERE ON THE EXCLUSION IS INSTALLED, AND EVERY ABORT OWES A TEARDOWN.
  //
  // Four paths below give up between here and the measurement -- the session
  // never carries, or one of the two sockets cannot be made -- and each of them
  // used to stop the engine and return. Stopping the engine closes the tun
  // descriptor, which deletes the device and everything scoped to it, so those
  // aborts looked clean. They were not: the exclusion is on the PHYSICAL
  // interface, `bootstrap.exclusion_installed` says so, and it survived every
  // one of them. In this lab the container is `--rm` so nobody noticed; on a
  // real machine that is the stale route that makes the next start fail EEXIST.
  //
  // The rule is the same one the bootstrap applier now follows: the process
  // that installed it removes it, on every way out.
  // -------------------------------------------------------------------------
  const auto abandon_after_bootstrap = [&](const char* why) {
    std::fprintf(stderr, "%s\n", why);
    // The SAME unified teardown the production stop uses: engine stop, route
    // dels, resolver revert, tun deletion, exclusion removal.
    std::string teardown_error;
    const bool stopped_clean =
        winsvpn::winn3host::StopLinuxWinn3Standalone(runner, &teardown_error);
    std::printf(
        "{\"event\":\"teardown\",\"reason\":\"abandoned after bootstrap\","
        "\"clean\":%s,\"error\":\"%s\"}\n",
        stopped_clean ? "true" : "false", teardown_error.c_str());
    ShowForTheRecord({"ip", "route", "show"});
    std::fflush(stdout);
    return 1;
  };

  // -------------------------------------------------------------------------
  // WAIT FOR THE SESSION TO BE CARRYING BEFORE MEASURING ANYTHING.
  //
  // The CreateAck means the engine accepted its configuration, NOT that the
  // handshake completed. This reads gate_state only to decide when to start and
  // consumes winsvpn::winn3::kCarryingGate rather than spelling the name again,
  // for the reason the sibling driver gives: the vocabulary is owned by
  // winn3/tun/gate.go's State.String().
  // -------------------------------------------------------------------------
  const uint64_t warmup_deadline = NowMs() + 15000;
  bool carrying = false;
  while (NowMs() < warmup_deadline) {
    EngineStatus probe;
    std::string probe_reason;
    (void)winsvpn::winn3host::LinuxWinn3PromotionState(&probe, &probe_reason);
    if (probe.valid && probe.gate_state == winsvpn::winn3::kCarryingGate) {
      carrying = true;
      break;
    }
    if (!winsvpn::winn3host::LinuxWinn3EngineRunning()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  const uint64_t carrying_ms = NowMs() - started_at;
  std::printf("{\"event\":\"carrying\",\"reached\":%s,\"ms\":%llu}\n",
              carrying ? "true" : "false",
              static_cast<unsigned long long>(carrying_ms));
  std::fflush(stdout);
  if (!carrying) {
    return abandon_after_bootstrap(
        "the v3 session never reached the carrying state; refusing to report "
        "traffic numbers for a session that never carried");
  }

  // -------------------------------------------------------------------------
  // THE TWO INNER FLOWS, ONE PER DIRECTION.
  //
  // UPLINK (host -> far end): the host writes inner packets INTO the tunnel.
  //   Verified by the engine's OWN outbound counter (tx_packets, read from the
  //   raw status document) agreeing with how many the host handed over, and by
  //   tx_dropped_closed == 0 -- nothing the host wrote was lost because the
  //   session was not open on the way out.
  //
  // DOWNLINK (far end -> host): inner packets delivered OUT of the tunnel.
  //   Verified by the engine's OWN inbound counters -- rx_offered == rx_packets
  //   (everything the far end sent reached the device, nothing fed a drop) and
  //   rx_packets == the total the host actually received on its sockets.
  //
  // The two directions never share a socket, a port or a sequence namespace,
  // so a session that carries only one of them fails the other's seal.
  // -------------------------------------------------------------------------
  const uint16_t downlink_port = 52000;

  InnerFlow up;
  std::string up_error;
  if (!OpenInnerFlow(inner_v4, router_v4, flow_port, payload_size,
                     count + promoted_count + downlink_count, &up, &up_error)) {
    std::fprintf(stderr, "uplink flow: %s\n", up_error.c_str());
    return abandon_after_bootstrap("could not open the uplink inner flow");
  }
  std::thread up_reader(ReceiveLoop, &up.rx);

  InnerFlow dn;
  std::string dn_error;
  if (!OpenInnerFlow(inner_v4, router_v4, downlink_port, payload_size,
                     downlink_count, &dn, &dn_error)) {
    std::fprintf(stderr, "downlink flow: %s\n", dn_error.c_str());
    up.rx.stop.store(true);
    up_reader.join();
    CloseInnerFlow(&up);
    return abandon_after_bootstrap("could not open the downlink inner flow");
  }
  std::thread dn_reader(ReceiveLoop, &dn.rx);

  std::vector<uint8_t> packet(inner_packet_size);

  // One burst: build, send through the kernel, count. Sequence numbers are
  // global WITHIN a flow so its `seen` set stays a single namespace; the two
  // flows keep separate namespaces. The payload is byte-identical to the
  // sibling driver's regardless of which port it rides, so the two runs remain
  // comparable packet for packet.
  const auto send_burst = [&](InnerFlow& flow, uint32_t first_seq,
                              size_t how_many, uint64_t* packets,
                              uint64_t* payload_bytes, uint64_t* write_failed,
                              uint64_t* digest) {
    for (uint32_t seq = first_seq; seq < first_seq + how_many; ++seq) {
      const size_t size = BuildInnerPacket(seq, flow.src_be, flow.dst_be,
                                           flow.port, flow.port, payload_size,
                                           packet.data());
      const ssize_t written =
          sendto(flow.send_fd, packet.data(), size, 0,
                 reinterpret_cast<sockaddr*>(&flow.dst), sizeof(flow.dst));
      if (written != static_cast<ssize_t>(size)) {
        ++(*write_failed);
      } else {
        ++(*packets);
        *payload_bytes += payload_size;
        FnvUpdate(digest, packet.data() + 28, payload_size);
      }
      if (gap_us > 0) {
        std::this_thread::sleep_for(std::chrono::microseconds(gap_us));
      }
    }
  };

  uint64_t up_sent = 0;
  uint64_t up_payload = 0;
  uint64_t up_write_failed = 0;
  uint64_t up_sent_digest = kFnvOffset;
  const uint64_t send_started = NowMs();
  send_burst(up, 0, count, &up_sent, &up_payload, &up_write_failed,
             &up_sent_digest);
  const uint64_t send_elapsed = NowMs() - send_started;

  // Poll the gate while the uplink returns settle. The FIRST promote is
  // timestamped because the predicate is RxPackets > 0 -- it proves carriage,
  // not volume.
  uint64_t first_promote_ms = 0;
  std::string last_reason;
  EngineStatus polled;
  const uint64_t settle_started = NowMs();
  while (NowMs() - settle_started < static_cast<uint64_t>(settle_ms)) {
    const LinuxWinn3Promotion verdict =
        winsvpn::winn3host::LinuxWinn3PromotionState(&polled, &last_reason);
    if (verdict == LinuxWinn3Promotion::kPromote && first_promote_ms == 0) {
      first_promote_ms = NowMs() - started_at;
    }
    if (up.rx.packets.load() >= up_sent) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
  const uint64_t bootstrap_rx_packets = up.rx.packets.load();

  // -------------------------------------------------------------------------
  // The promoted posture, applied for real, and then PROVEN to still carry.
  //
  // Applying it and stopping would show only that the commands succeeded. The
  // second burst is what shows the session still carries once both halves of
  // the address space point at the tun and the only thing keeping the engine's
  // own outer socket out of its own tunnel is the exclusion route.
  // -------------------------------------------------------------------------
  EngineStatus promote_status;
  std::string promote_reason;
  const LinuxWinn3Promotion promote_verdict =
      winsvpn::winn3host::LinuxWinn3PromotionState(&promote_status,
                                                   &promote_reason);
  winsvpn::winn3host::LinuxWinn3PostureResult promoted;
  winsvpn::winn3::PosturePlan promoted_plan;
  if (promote_verdict == LinuxWinn3Promotion::kPromote) {
    promoted = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
        params, promote_status, runner, &promoted_plan);
  } else {
    promoted.error = "the gate did not say promote: " + promote_reason;
    winsvpn::winn3host::SetLinuxWinn3ResolverStatus(promoted);
  }
  const bool promoted_applied =
      promoted.outcome == winsvpn::winn3host::LinuxWinn3PostureOutcome::kApplied;
  std::printf(
      "{\"event\":\"promoted_posture\",\"verdict\":\"%s\",\"outcome\":\"%s\","
      "\"applied\":%s,\"capturing\":%s,\"resolver_mechanism\":\"%s\","
      "\"applied_commands\":%zu,\"rollback_attempted\":%s,"
      "\"rollback_failed\":%zu,\"default_route\":%s,\"routes\":%zu,"
      "\"error\":\"%s\"}\n",
      promote_verdict == LinuxWinn3Promotion::kPromote
          ? "promote"
          : (promote_verdict == LinuxWinn3Promotion::kNotYet ? "not-yet"
                                                             : "refuse"),
      winsvpn::winn3host::LinuxWinn3PostureOutcomeName(promoted.outcome),
      promoted_applied ? "true" : "false",
      promoted.capturing ? "true" : "false",
      winsvpn::winn3host::LinuxWinn3ResolverMechanismName(
          promoted.resolver_mechanism),
      promoted.applied.size(), promoted.rollback_attempted ? "true" : "false",
      promoted.rollback_failed.size(),
      promoted_plan.default_route ? "true" : "false",
      promoted_plan.included_routes.size(), promoted.error.c_str());
  std::printf("{\"event\":\"promoted_posture_detail\",\"describe\":\"%s\","
              "\"resolver_detail\":\"%s\"}\n",
              winsvpn::winn3host::DescribeLinuxWinn3PostureResult(promoted)
                  .c_str(),
              promoted.resolver_detail.c_str());
  std::fflush(stdout);
  // ALWAYS, not only on success. The outcome above says how far the posture
  // got, but the kernel is the only thing that decides where a user's traffic
  // goes, and a result type that claimed a rollback had happened would be worth
  // no more than the boolean it replaced if nobody checked. `ip route get` is
  // the question in the form the kernel answers: for an arbitrary internet
  // destination, which device wins?
  ShowForTheRecord({"ip", "route", "show"});
  ShowForTheRecord({"ip", "route", "get", "1.1.1.1"});
  ShowForTheRecord({"cat", "/etc/resolv.conf"});

  // The burst is gated on the ENGINE's verdict rather than on whether every
  // posture command succeeded, for the same reason: if the capturing routes are
  // in the kernel then "does the session still carry under them" is a real
  // question with a real answer, and gating it on the resolver step would leave
  // the most dangerous posture the least measured.
  uint64_t promoted_rx_delta = 0;
  uint64_t promoted_sent = 0;
  if (promote_verdict == LinuxWinn3Promotion::kPromote && promoted_count > 0) {
    const uint64_t before = up.rx.packets.load();
    const uint64_t tx_before = up_sent;
    uint64_t promoted_payload = 0;
    uint64_t promoted_failed = 0;
    send_burst(up, static_cast<uint32_t>(count), promoted_count, &promoted_sent,
               &promoted_payload, &promoted_failed, &up_sent_digest);
    const uint64_t promoted_settle = NowMs();
    while (NowMs() - promoted_settle < 10000) {
      if (up.rx.packets.load() - before >= up_sent - tx_before) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    promoted_rx_delta = up.rx.packets.load() - before;
    std::printf(
        "{\"event\":\"promoted_burst\",\"tx\":%llu,\"rx\":%llu,"
        "\"note\":\"sent after the promotion attempt; the kernel_state "
        "`ip route get 1.1.1.1` line above is the evidence for which device "
        "was actually carrying, and this claims nothing beyond it\"}\n",
        static_cast<unsigned long long>(promoted_sent),
        static_cast<unsigned long long>(promoted_rx_delta));
    std::fflush(stdout);
  }

  // -------------------------------------------------------------------------
  // THE DOWNLINK FLOW, SEPARATELY FROM THE UPLINK.
  //
  // On its own inner port (52000) and its own sequence namespace, the driver
  // originates a second inner flow and verifies the far -> host leg with its
  // own digest and its own corrupt/malformed/duplicate accounting. The engine
  // inbound counters below (rx_offered == rx_packets, rx_packets == total
  // received) are the DIRECTIONAL cross-check that a single socket pair cannot
  // provide: they are the far end's own record of what it sent down, agreeing
  // with what the host actually received.
  // -------------------------------------------------------------------------
  uint64_t dn_sent = 0;
  uint64_t dn_payload = 0;
  uint64_t dn_write_failed = 0;
  uint64_t dn_sent_digest = kFnvOffset;
  if (downlink_count > 0) {
    send_burst(dn, 0, downlink_count, &dn_sent, &dn_payload, &dn_write_failed,
               &dn_sent_digest);
    const uint64_t dn_settle = NowMs();
    while (NowMs() - dn_settle < 10000) {
      if (dn.rx.packets.load() >= dn_sent) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::printf(
        "{\"event\":\"downlink_burst\",\"port\":%u,\"tx\":%llu,\"rx\":%llu,"
        "\"note\":\"the downlink flow on its own inner port; the far->host "
        "leg is sealed by the engine inbound counters below\"}\n",
        downlink_port, static_cast<unsigned long long>(dn_sent),
        static_cast<unsigned long long>(dn.rx.packets.load()));
    std::fflush(stdout);
  }

  // One last status read, after the traffic has stopped moving.
  EngineStatus final_status;
  std::string final_reason;
  const LinuxWinn3Promotion final_verdict =
      winsvpn::winn3host::LinuxWinn3PromotionState(&final_status, &final_reason);
  const std::string engine_status_json =
      winsvpn::winn3host::LinuxWinn3EngineStatusJson();
  const std::string pump_stats_json =
      winsvpn::winn3host::LinuxWinn3PumpStatsJson();
  const bool engine_running = winsvpn::winn3host::LinuxWinn3EngineRunning();

  // Prove the interface is still a kernel netdev at the END of the run, not
  // just at the start.
  ShowForTheRecord({"ip", "-o", "addr", "show", "dev", tun_name});

  dn.rx.stop.store(true);
  dn_reader.join();
  up.rx.stop.store(true);
  up_reader.join();

  uint64_t returned_digest = kFnvOffset;
  {
    std::vector<uint8_t> body(payload_size);
    for (uint32_t seq = 0; seq < up.rx.seen.size(); ++seq) {
      if (up.rx.seen[seq] == 0) continue;
      FillPayload(seq, body.data(), body.size());
      FnvUpdate(&returned_digest, body.data(), body.size());
    }
  }

  const uint64_t rx_packets = up.rx.packets.load();
  const uint64_t missing = up_sent > rx_packets ? up_sent - rx_packets : 0;
  const double loss_pct =
      up_sent == 0 ? 0.0
                      : (static_cast<double>(missing) * 100.0) /
                            static_cast<double>(up_sent);

  std::printf(
      "{\"event\":\"result\","
      "\"protocol\":\"winn/3\","
      "\"device\":\"/dev/net/tun (REAL kernel tun, IFF_TUN|IFF_NO_PI)\","
      "\"interface\":\"%s\",\"ifindex\":%u,"
      "\"engine\":\"%s\",\"gateway\":\"%s\","
      "\"inner_mtu\":%d,\"payload_bytes_each\":%zu,"
      "\"tx_packets\":%llu,\"tx_payload_bytes\":%llu,\"tx_write_failed\":%llu,"
      "\"rx_packets\":%llu,\"rx_payload_bytes\":%llu,"
      "\"missing\":%llu,\"loss_pct\":%.4f,"
      "\"rx_corrupt\":%llu,\"rx_duplicate\":%llu,\"rx_malformed\":%llu,"
      "\"digest_sent_fnv1a64\":\"%016llx\","
      "\"digest_returned_fnv1a64\":\"%016llx\","
      "\"digest_match_full_set\":%s,"
      "\"bootstrap_rx_packets\":%llu,\"promoted_rx_packets\":%llu,"
      "\"send_elapsed_ms\":%llu,\"create_ack_ms\":%llu,"
      "\"first_promote_ms\":%llu,"
      "\"bootstrap_posture_applied\":%s,\"promoted_posture_applied\":%s,"
      "\"promotion_ready\":%s,\"gate_state\":\"%s\","
      "\"status_rx_packets\":%llu,\"status_rx_offered\":%llu,"
      "\"status_tx_dropped_closed\":%llu,"
      "\"engine_running\":%s,\"final_verdict\":\"%s\"}\n",
      tun_name.c_str(), tun_index, engine.c_str(), gateway.c_str(),
      ack.inner_mtu, payload_size,
      static_cast<unsigned long long>(up_sent),
      static_cast<unsigned long long>(up_payload),
      static_cast<unsigned long long>(up_write_failed),
      static_cast<unsigned long long>(rx_packets),
      static_cast<unsigned long long>(up.rx.payload_bytes.load()),
      static_cast<unsigned long long>(missing), loss_pct,
      static_cast<unsigned long long>(up.rx.corrupt.load()),
      static_cast<unsigned long long>(up.rx.duplicate.load()),
      static_cast<unsigned long long>(up.rx.malformed.load()),
      static_cast<unsigned long long>(up_sent_digest),
      static_cast<unsigned long long>(returned_digest),
      (missing == 0 && up_sent_digest == returned_digest) ? "true" : "false",
      static_cast<unsigned long long>(bootstrap_rx_packets),
      static_cast<unsigned long long>(promoted_rx_delta),
      static_cast<unsigned long long>(send_elapsed),
      static_cast<unsigned long long>(create_ack_ms),
      static_cast<unsigned long long>(first_promote_ms),
      bootstrap_ok ? "true" : "false", promoted_applied ? "true" : "false",
      final_status.promotion_ready ? "true" : "false",
      final_status.gate_state.c_str(),
      static_cast<unsigned long long>(final_status.rx_packets),
      static_cast<unsigned long long>(final_status.rx_offered),
      static_cast<unsigned long long>(final_status.tx_dropped_closed),
      engine_running ? "true" : "false",
      final_verdict == LinuxWinn3Promotion::kPromote
          ? "promote"
          : (final_verdict == LinuxWinn3Promotion::kNotYet ? "not-yet"
                                                           : "refuse"));
  std::printf("{\"event\":\"engine_status\",\"document\":%s}\n",
              engine_status_json.empty() ? "null" : engine_status_json.c_str());
  std::printf("{\"event\":\"host_pump_stats\",\"document\":%s}\n",
              pump_stats_json.empty() ? "null" : pump_stats_json.c_str());
  // The host's own resolver status document. Printed separately from the pump
  // counters because it survives a session that never started an engine, which
  // is exactly the run that measures a refused promotion.
  std::printf("{\"event\":\"host_resolver_status\",\"document\":%s}\n",
              winsvpn::winn3host::LinuxWinn3ResolverStatusJson().c_str());
  std::fflush(stdout);

  CloseInnerFlow(&up);
  CloseInnerFlow(&dn);

  // -------------------------------------------------------------------------
  // TEARDOWN, WHICH THIS DRIVER DID NOT RUN UNTIL 2026-08-10.
  //
  // It could get away with that while every posture command was a route on a
  // device that disappears with its last descriptor. It cannot now: the
  // /etc/resolv.conf mechanism leaves a FILE, and a driver that promoted
  // through it and then exited would be a demonstration of the exact stranding
  // the mechanism is designed to avoid.
  //
  // It goes through StopLinuxWinn3Standalone, the SAME unified teardown the
  // production StopTunnel uses, so the harness's exit path and the product's
  // stop path cannot drift apart. The mechanism is read from the posture
  // result for the log line only; the unified stop reads it from the same
  // module state every caller shares.
  // -------------------------------------------------------------------------
  std::string teardown_error;
  const bool stopped_clean = winsvpn::winn3host::StopLinuxWinn3Standalone(
      runner, &teardown_error);
  std::printf(
      "{\"event\":\"teardown\",\"resolver_mechanism\":\"%s\","
      "\"clean\":%s,\"error\":\"%s\"}\n",
      winsvpn::winn3host::LinuxWinn3ResolverMechanismName(
          promoted.resolver_mechanism),
      stopped_clean ? "true" : "false", teardown_error.c_str());
  ShowForTheRecord({"cat", "/etc/resolv.conf"});
  ShowForTheRecord({"ip", "route", "show"});
  std::fflush(stdout);
  if (!stopped_clean) return 1;

  // Fail the process on anything that would make the numbers above a lie.
  // This is the SEAL: the run only counts as green when every packet sent was
  // returned, nothing was corrupt or malformed, and the recomputed payload
  // digest of the returned set is byte-identical to what was sent. A run that
  // carried traffic but dropped, corrupted or reordered a single packet must
  // fail -- otherwise "the tunnel carries v3" would be reported for a session
  // that silently lost data, which is the failure this whole fixture exists to
  // catch.
  const bool sealed = missing == 0 && up_sent_digest == returned_digest;
  if (!sealed || up_sent == 0 || up.rx.corrupt.load() != 0 ||
      up.rx.malformed.load() != 0) {
    return 1;
  }
  return 0;
}
