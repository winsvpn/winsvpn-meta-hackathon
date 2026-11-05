// A driver that runs linux/runner/linux_winn3_host.cc against a REAL Winn
// Protocol v3 gateway and measures what actually crossed.
//
// WHY THIS FILE EXISTS
//
// Until 2026-08-09 linux_winn3_host.cc had never been compiled into anything
// and StartLinuxWinn3Engine had never been called by any program at all --
// linux_winn3_host_test.cc exercises only the pure functions (the sizing
// mirror, the key and create documents, the posture renderers, the promotion
// predicate) and never starts an engine. So the parts of that file which
// actually move bytes -- the fork/exec of `winn-datapath -winn3`, the Create /
// CreateAck exchange, TunReadPump, OutboundPump, the ring, and the frame codec
// -- had no coverage of any kind, and the only Linux datapath evidence in the
// tree came from linux_winn_host.cc, which is the winn/1 AmneziaWG relay and
// carries a different payload class to a different protocol.
//
// This driver closes that gap in the one direction that can be closed without
// privilege, and is deliberately explicit about the direction that cannot.
//
// # WHAT IS REAL HERE, AND WHAT IS NOT
//
// REAL: the engine subprocess is the real `cmd/winn-datapath` in `-winn3`
// frame mode; the far end is the real `cmd/winn3-gateway`, a separate process
// holding its own unconnected UDP socket; the handshake is the real v3
// handshake (X25519 + ML-KEM-768, StrictPQ by default); the payload is real
// ChaCha20-Poly1305 over the real `DemuxToken(8) || AEAD(frames || padding)`
// wire shape; the inner packets are real IPv4/UDP datagrams validated by
// winn3/tun's inner-IP validator at both ends; and every counter printed below
// is read back from the engine's own status document or counted by the host's
// own pumps.
//
// NOT REAL: the host device is a SOCK_DGRAM socketpair, not a kernel tun
// device. `StartLinuxWinn3Engine` takes the device descriptor as a parameter
// and never opens one itself -- `OpenLinuxWinn3Tun` is a separate call -- so
// substituting the descriptor exercises the identical pump path. A SOCK_DGRAM
// socketpair is chosen over a pipe because it preserves message boundaries
// exactly as /dev/net/tun does: TunReadPump does one read() per inner packet
// and OutboundPump does one write() per delivered packet, and on a stream both
// would silently coalesce.
//
// WHAT THAT COSTS, STATED PLAINLY: this run says nothing about TUNSETIFF, the
// IFF_TUN|IFF_NO_PI attach, interface MTU enforcement by the kernel, the
// routing posture, or the outer-socket exclusion. Those need CAP_NET_ADMIN.
// A run of this driver is NOT evidence that v3 carries traffic through a
// kernel tun device, and must never be cited as if it were.
//
// # USAGE
//
//   linux_winn3_host_e2e --engine PATH --gateway IP:PORT --keys-dir DIR
//       --gateway-id ID [--count N] [--payload N] [--path-mtu N]
//       [--classes udp,tcp,tls] [--gap-us N] [--settle-ms N]

#include "linux_winn3_host.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

using winsvpn::winn3host::LinuxWinn3Params;
using winsvpn::winn3host::LinuxWinn3Promotion;

// ---------------------------------------------------------------------------
// The deterministic payload. Regenerable from the sequence number alone, so a
// returned packet is verified byte-for-byte against what it should be rather
// than merely counted -- which is what separates "4 MiB came back" from "4 MiB
// came back INTACT".
// ---------------------------------------------------------------------------
void FillPayload(uint32_t seq, uint8_t* out, size_t size) {
  // First 8 bytes: the sequence number, big-endian, twice-wide so a truncated
  // or shifted packet cannot accidentally read as a valid neighbour.
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

// FNV-1a 64. A citable fingerprint over the payload set, in sequence order.
// Not a cryptographic claim and not used as one -- the integrity claim in this
// file is the byte-for-byte comparison above; this is the short number to quote.
constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

void FnvUpdate(uint64_t* h, const uint8_t* data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    *h ^= data[i];
    *h *= kFnvPrime;
  }
}

// ---------------------------------------------------------------------------
// Inner IPv4/UDP framing.
// ---------------------------------------------------------------------------
uint16_t Ipv4HeaderChecksum(const uint8_t* header, size_t size) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < size; i += 2) {
    sum += static_cast<uint32_t>((header[i] << 8) | header[i + 1]);
  }
  while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

// Builds one inner IPv4/UDP packet. The UDP checksum is left zero, which IPv4
// permits (RFC 768) and which keeps the reflector's address swap from
// invalidating a checksum it does not recompute.
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
  out[26] = 0;  // checksum: none
  out[27] = 0;

  FillPayload(seq, out + 28, payload_size);
  return total;
}

// ---------------------------------------------------------------------------
// The receiving half.
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
    const ssize_t count = read(rx->fd, buffer.data(), buffer.size());
    if (count <= 0) continue;
    const size_t size = static_cast<size_t>(count);
    if (size < 28 || (buffer[0] >> 4) != 4 || buffer[9] != 17) {
      rx->malformed.fetch_add(1);
      continue;
    }
    const size_t payload = size - 28;
    if (payload != rx->payload_size) {
      rx->malformed.fetch_add(1);
      continue;
    }
    const uint8_t* body = buffer.data() + 28;
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
    rx->payload_bytes.fetch_add(payload);
  }
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
  const size_t count =
      static_cast<size_t>(std::atol(Argument(argc, argv, "--count", "4096").c_str()));
  const size_t payload_size =
      static_cast<size_t>(std::atol(Argument(argc, argv, "--payload", "1024").c_str()));
  const int path_mtu = std::atoi(Argument(argc, argv, "--path-mtu", "1500").c_str());
  const std::vector<std::string> classes =
      SplitCommas(Argument(argc, argv, "--classes", "udp,tcp,tls"));
  const long gap_us = std::atol(Argument(argc, argv, "--gap-us", "120").c_str());
  const long settle_ms =
      std::atol(Argument(argc, argv, "--settle-ms", "20000").c_str());

  if (engine.empty() || gateway.empty() || keys_dir.empty()) {
    std::fprintf(stderr,
                 "usage: %s --engine PATH --gateway IP:PORT --keys-dir DIR "
                 "[--gateway-id ID] [--count N] [--payload N] [--path-mtu N] "
                 "[--classes udp,tcp,tls] [--gap-us N] [--settle-ms N]\n",
                 argv[0]);
    return 2;
  }

  // The sizing mirror is checked BEFORE anything is started. A drift here is
  // the 84-byte black hole, and discovering it after a run would mean the run's
  // numbers were measured against the wrong floor.
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
    std::fprintf(stderr,
                 "inner packet %zu exceeds the plan floor inner MTU %d\n",
                 inner_packet_size, planned_inner_mtu);
    return 1;
  }

  // The device stand-in. SOCK_DGRAM, so message boundaries survive exactly as
  // they do on /dev/net/tun.
  int sv[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
    std::perror("socketpair");
    return 1;
  }
  const int buffer_bytes = 8 * 1024 * 1024;
  for (const int fd : {sv[0], sv[1]}) {
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_bytes, sizeof(buffer_bytes));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_bytes, sizeof(buffer_bytes));
  }

  LinuxWinn3Params params;
  params.interface_name = "winsvpn3";
  params.gateway_endpoint = gateway;
  params.inner_address = "10.64.0.2";
  params.inner_next_hop = "10.64.0.1";
  params.path_mtu = path_mtu;
  params.carrier_classes = classes;
  params.session_id = "e2e0000000000000e2e0000000000000";
  params.full_routes = {"0.0.0.0/1", "128.0.0.0/1"};
  params.dns_servers = {"10.64.0.1"};
  params.dns_servers_are_inner = true;
  // Named so the create document is well formed. NOTHING privileged is executed
  // by this driver: no route is installed, no posture is applied, and the
  // engine's outer socket reaches the gateway by the host's ordinary routing.
  params.physical_interface = "lo";
  params.physical_next_hop = "127.0.0.1";
  params.keys.role = "client";
  params.keys.gateway_id = gateway_id;
  params.keys.static_path = keys_dir + "/client.key";
  params.keys.gateway_static_path = keys_dir + "/static.pub";
  params.keys.admission_path = keys_dir + "/admission.key";
  params.keys.outer_socket_exclusion =
      winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params);

  winsvpn::winn3::EngineStatus ack;
  std::string error;
  const uint64_t started_at = NowMs();
  if (!winsvpn::winn3host::StartLinuxWinn3Engine(engine, sv[1], params, &ack,
                                                 &error)) {
    std::fprintf(stderr, "StartLinuxWinn3Engine failed: %s\n", error.c_str());
    close(sv[0]);
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

  // WAIT FOR THE SESSION TO BE CARRYING BEFORE MEASURING ANYTHING.
  //
  // The CreateAck means the engine accepted its configuration, NOT that the
  // handshake has completed. Inner packets written before the session carries
  // are dropped by the engine and counted as tx_dropped_closed -- correctly, it
  // is the fail-closed direction -- but counting them as loss would blame the
  // datapath for a race in the harness. A first run of this driver sent from
  // t=0 and charged itself 6 of 64 for exactly that reason.
  //
  // This reads gate_state only to decide when to start; the string contract
  // itself belongs to the host and is not touched here. It consumes
  // winsvpn::winn3::kCarryingGate (winn3_posture.h:82, reached through
  // linux_winn3_host.h:133) rather than spelling the name again, for the same
  // reason linux_winn3_host.cc:1635 does: the vocabulary is owned by
  // winn3/tun/gate.go's State.String(), and a copy here would let a rename
  // there leave this harness waiting out its 15s warm-up and reporting that
  // the engine never carried when it did.
  const uint64_t warmup_deadline = NowMs() + 15000;
  bool carrying = false;
  while (NowMs() < warmup_deadline) {
    winsvpn::winn3::EngineStatus probe;
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
    std::fprintf(stderr,
                 "the v3 session never reached the carrying state; refusing to "
                 "report traffic numbers for a session that never carried\n");
    winsvpn::winn3host::StopLinuxWinn3Engine();
    close(sv[0]);
    return 1;
  }

  Receiver rx;
  rx.fd = sv[0];
  rx.payload_size = payload_size;
  rx.seen.assign(count, 0);
  std::thread reader(ReceiveLoop, &rx);

  uint32_t src_be = 0;
  uint32_t dst_be = 0;
  inet_pton(AF_INET, params.inner_address.c_str(), &src_be);
  inet_pton(AF_INET, params.inner_next_hop.c_str(), &dst_be);

  std::vector<uint8_t> packet(inner_packet_size);
  uint64_t sent_digest = kFnvOffset;
  uint64_t tx_packets = 0;
  uint64_t tx_payload_bytes = 0;
  uint64_t tx_write_failed = 0;

  const uint64_t send_started = NowMs();
  for (uint32_t seq = 0; seq < count; ++seq) {
    const size_t size =
        BuildInnerPacket(seq, src_be, dst_be, 51999, 51999, payload_size,
                         packet.data());
    const ssize_t written = write(sv[0], packet.data(), size);
    if (written != static_cast<ssize_t>(size)) {
      ++tx_write_failed;
    } else {
      ++tx_packets;
      tx_payload_bytes += payload_size;
      FnvUpdate(&sent_digest, packet.data() + 28, payload_size);
    }
    if (gap_us > 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(gap_us));
    }
  }
  const uint64_t send_elapsed = NowMs() - send_started;

  // Poll the gate while the returns settle. The FIRST promote is timestamped
  // because the predicate is RxPackets > 0 -- it proves carriage, not volume,
  // and it should fire long before the last packet lands.
  uint64_t first_promote_ms = 0;
  std::string last_reason;
  winsvpn::winn3::EngineStatus polled;
  const uint64_t settle_started = NowMs();
  while (NowMs() - settle_started < static_cast<uint64_t>(settle_ms)) {
    const LinuxWinn3Promotion verdict =
        winsvpn::winn3host::LinuxWinn3PromotionState(&polled, &last_reason);
    if (verdict == LinuxWinn3Promotion::kPromote && first_promote_ms == 0) {
      first_promote_ms = NowMs() - started_at;
    }
    if (rx.packets.load() >= tx_packets) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }

  // One last status read, after the traffic has stopped moving.
  winsvpn::winn3::EngineStatus final_status;
  std::string final_reason;
  const LinuxWinn3Promotion final_verdict =
      winsvpn::winn3host::LinuxWinn3PromotionState(&final_status,
                                                   &final_reason);
  const std::string engine_status_json =
      winsvpn::winn3host::LinuxWinn3EngineStatusJson();
  const std::string pump_stats_json =
      winsvpn::winn3host::LinuxWinn3PumpStatsJson();
  const bool engine_running = winsvpn::winn3host::LinuxWinn3EngineRunning();

  rx.stop.store(true);
  reader.join();

  uint64_t returned_digest = kFnvOffset;
  {
    std::vector<uint8_t> body(payload_size);
    for (uint32_t seq = 0; seq < count; ++seq) {
      if (rx.seen[seq] == 0) continue;
      FillPayload(seq, body.data(), body.size());
      FnvUpdate(&returned_digest, body.data(), body.size());
    }
  }

  const uint64_t rx_packets = rx.packets.load();
  const uint64_t missing = tx_packets > rx_packets ? tx_packets - rx_packets : 0;
  const double loss_pct =
      tx_packets == 0 ? 0.0
                      : (static_cast<double>(missing) * 100.0) /
                            static_cast<double>(tx_packets);

  std::printf(
      "{\"event\":\"result\","
      "\"protocol\":\"winn/3\","
      "\"device\":\"AF_UNIX SOCK_DGRAM socketpair (NOT a kernel tun)\","
      "\"engine\":\"%s\",\"gateway\":\"%s\","
      "\"inner_mtu\":%d,\"payload_bytes_each\":%zu,"
      "\"tx_packets\":%llu,\"tx_payload_bytes\":%llu,\"tx_write_failed\":%llu,"
      "\"rx_packets\":%llu,\"rx_payload_bytes\":%llu,"
      "\"missing\":%llu,\"loss_pct\":%.4f,"
      "\"rx_corrupt\":%llu,\"rx_duplicate\":%llu,\"rx_malformed\":%llu,"
      "\"digest_sent_fnv1a64\":\"%016llx\","
      "\"digest_returned_fnv1a64\":\"%016llx\","
      "\"digest_match_full_set\":%s,"
      "\"send_elapsed_ms\":%llu,\"create_ack_ms\":%llu,"
      "\"first_promote_ms\":%llu,"
      "\"promotion_ready\":%s,\"gate_state\":\"%s\","
      "\"status_rx_packets\":%llu,\"status_rx_offered\":%llu,"
      "\"status_tx_dropped_closed\":%llu,"
      "\"engine_running\":%s,\"final_verdict\":\"%s\"}\n",
      engine.c_str(), gateway.c_str(), ack.inner_mtu, payload_size,
      static_cast<unsigned long long>(tx_packets),
      static_cast<unsigned long long>(tx_payload_bytes),
      static_cast<unsigned long long>(tx_write_failed),
      static_cast<unsigned long long>(rx_packets),
      static_cast<unsigned long long>(rx.payload_bytes.load()),
      static_cast<unsigned long long>(missing), loss_pct,
      static_cast<unsigned long long>(rx.corrupt.load()),
      static_cast<unsigned long long>(rx.duplicate.load()),
      static_cast<unsigned long long>(rx.malformed.load()),
      static_cast<unsigned long long>(sent_digest),
      static_cast<unsigned long long>(returned_digest),
      (missing == 0 && sent_digest == returned_digest) ? "true" : "false",
      static_cast<unsigned long long>(send_elapsed),
      static_cast<unsigned long long>(create_ack_ms),
      static_cast<unsigned long long>(first_promote_ms),
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
  std::fflush(stdout);

  winsvpn::winn3host::StopLinuxWinn3Engine();
  close(sv[0]);

  // Fail the process on anything that would make the numbers above a lie.
  if (tx_packets == 0 || rx.corrupt.load() != 0 || rx.malformed.load() != 0) {
    return 1;
  }
  return 0;
}
