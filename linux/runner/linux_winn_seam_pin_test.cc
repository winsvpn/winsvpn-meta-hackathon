// Seam admission tests for the Linux Winn host (DESKTOP-R7-1).
//
// The seam used to adopt whichever loopback sender reached it first as the
// AmneziaWG peer. It is bound before awg-quick starts, so any local process
// that sends to it in that window becomes the pinned peer: AmneziaWG's own
// datagrams are then refused and the gateway's replies go to that process.
// These tests pin the replacement: the host reserves AmneziaWG's ListenPort,
// writes it into the configuration, and the seam admits only 127.0.0.1 from
// that port, from the first datagram.
//
// It includes the translation unit so the anonymous-namespace acceptance
// predicate is tested directly. Builds and runs on any POSIX host:
//
//   c++ -std=c++17 -Wall -Wextra -pthread -o /tmp/linux_winn_seam_pin_test \
//       linux/runner/linux_winn_seam_pin_test.cc && /tmp/linux_winn_seam_pin_test

#include "linux_winn_host.cc"

#include <cstdio>

namespace {

int failures = 0;

void Check(bool condition, const char* what) {
  if (!condition) {
    ++failures;
    std::fprintf(stderr, "FAIL: %s\n", what);
  }
}

sockaddr_in Loopback(uint32_t address, uint16_t port) {
  sockaddr_in sender{};
  sender.sin_family = AF_INET;
  sender.sin_addr.s_addr = htonl(address);
  sender.sin_port = htons(port);
  return sender;
}

constexpr char kConfig[] =
    "[Interface]\n"
    "PrivateKey = test-private\n"
    "Address = 10.8.0.2/32\n"
    "ListenPort = 51820\n"
    "[Peer]\n"
    "PublicKey = test-public\n"
    "Endpoint = 203.0.113.9:51820\n"
    "AllowedIPs = 0.0.0.0/0\n";

size_t Count(const std::string& haystack, const std::string& needle) {
  size_t count = 0;
  for (size_t at = haystack.find(needle); at != std::string::npos;
       at = haystack.find(needle, at + 1)) {
    ++count;
  }
  return count;
}

void TestRewritePinsListenPort() {
  using winsvpn::winn::RewriteAwgPeerEndpointToSeam;
  std::string out;
  Check(RewriteAwgPeerEndpointToSeam(kConfig, 40001, 45000, &out),
        "a config with one interface and one endpoint is rewritten");
  Check(Count(out, "ListenPort = ") == 1, "exactly one ListenPort survives");
  Check(out.find("[Interface]\nListenPort = 45000\n") != std::string::npos,
        "the reserved ListenPort sits directly under [Interface]");
  Check(out.find("ListenPort = 51820") == std::string::npos,
        "the served ListenPort is dropped");
  Check(out.find("Endpoint = 127.0.0.1:40001\n") != std::string::npos,
        "the endpoint points at the seam");
  Check(!RewriteAwgPeerEndpointToSeam(kConfig, 40001, 0, &out),
        "an unreserved ListenPort is a refusal");
  Check(!RewriteAwgPeerEndpointToSeam(
            "[Peer]\nEndpoint = 203.0.113.9:51820\n", 40001, 45000, &out),
        "a config without [Interface] is a refusal");
  Check(!RewriteAwgPeerEndpointToSeam(
            std::string(kConfig) + "[Interface]\n", 40001, 45000, &out),
        "two [Interface] sections are a refusal");
  Check(RewriteAwgPeerEndpointToSeam(
            "[ interface ]\nPrivateKey = k\n[Peer]\nEndpoint = 1.2.3.4:5\n",
            40001, 45000, &out) &&
            out.find("[ interface ]\nListenPort = 45000\n") !=
                std::string::npos,
        "a spaced, lower-case [Interface] header is recognised");
}

void TestSeamAdmitsOnlyTheReservedPort() {
  using winsvpn::winn::EngineState;
  using winsvpn::winn::SeamDatagramAccepted;
  EngineState state;
  state.awg_peer = Loopback(INADDR_LOOPBACK, 45000);
  state.awg_peer_known = true;
  Check(!SeamDatagramAccepted(&state, 1400, 100,
                              Loopback(INADDR_LOOPBACK, 45001)),
        "a hostile local sender that arrives first is refused");
  Check(state.awg_peer.sin_port == htons(45000),
        "the hostile sender is not adopted");
  Check(SeamDatagramAccepted(&state, 1400, 100,
                             Loopback(INADDR_LOOPBACK, 45000)),
        "the reserved AmneziaWG port is admitted");
  Check(!SeamDatagramAccepted(&state, 1400, 100,
                              Loopback(0x7f000002u, 45000)),
        "another loopback address on the same port is refused");
  Check(state.counters.rx_foreign_sender.load() == 2,
        "both refusals are counted as foreign senders");

  EngineState unpinned;
  Check(!SeamDatagramAccepted(&unpinned, 1400, 100,
                              Loopback(INADDR_LOOPBACK, 45000)),
        "an unpinned seam admits nothing and learns nothing");
  Check(!unpinned.awg_peer_known, "an unpinned seam stays unpinned");
}

void TestReservedPortIsFree() {
  uint16_t port = 0;
  std::string error;
  Check(winsvpn::winn::ReserveLinuxAwgListenPort(&port, &error) && port != 0,
        "a ListenPort is reserved");
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in any{};
  any.sin_family = AF_INET;
  any.sin_addr.s_addr = htonl(INADDR_ANY);
  any.sin_port = htons(port);
  Check(fd >= 0 && bind(fd, reinterpret_cast<const sockaddr*>(&any),
                        sizeof(any)) == 0,
        "the reserved port is free for AmneziaWG to bind");
  if (fd >= 0) close(fd);
}

void TestEngineRefusesAnUnreservedPort() {
  std::string error;
  uint16_t seam_port = 0;
  const int seam = winsvpn::winn::BindLinuxWinnSeam(&seam_port, &error);
  Check(seam >= 0, "the seam binds");
  winsvpn::winn::LinuxWinnParams params;
  Check(!winsvpn::winn::StartLinuxWinnEngine("/nonexistent/winn-datapath",
                                             seam, params, &error),
        "StartLinuxWinnEngine refuses awg_listen_port 0");
  Check(error.find("source port was not reserved") != std::string::npos,
        "the refusal names the missing reservation");
  Check(fcntl(seam, F_GETFD) == -1 && errno == EBADF,
        "the seam descriptor is closed on refusal");
}

void TestOversizedFirstDoesNotPoisonThePin() {
  using winsvpn::winn::EngineState;
  using winsvpn::winn::SeamDatagramAccepted;
  EngineState state;
  state.awg_peer = Loopback(INADDR_LOOPBACK, 45000);
  state.awg_peer_known = true;
  Check(!SeamDatagramAccepted(&state, 1400, 5000,
                              Loopback(INADDR_LOOPBACK, 45001)),
        "an oversized hostile first datagram is refused");
  Check(state.awg_peer.sin_port == htons(45000),
        "an oversized hostile first datagram does not move the pin");
  Check(SeamDatagramAccepted(&state, 1400, 100,
                             Loopback(INADDR_LOOPBACK, 45000)),
        "AmneziaWG's own datagram is admitted after it");
  Check(!SeamDatagramAccepted(&state, 1400, 5000,
                              Loopback(INADDR_LOOPBACK, 45000)) &&
            state.counters.rx_oversize.load() == 1 &&
            state.awg_peer.sin_port == htons(45000),
        "AmneziaWG's own oversized datagram is dropped and keeps the pin");
}

constexpr char kUdpHeader[] =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode ref pointer drops\n";

std::string UdpLine(const char* local, const char* uid) {
  return std::string("  12: ") + local +
         " 00000000:0000 07 00000000:00000000 00:00000000 00000000 " + uid +
         "        0 41234 2 0000000000000000 0\n";
}

void TestProcNetUdpHolders() {
  using winsvpn::winn::UdpPortHolders;
  // 45000 is 0xAFC8. The parser accumulates across tables, so each case
  // starts from a fresh UdpPortHolders.
  auto parse = [](const std::string& table, UdpPortHolders* holders) {
    return winsvpn::winn::ParseProcNetUdpHolders(table, 45000, holders);
  };
  const std::string header(kUdpHeader);
  UdpPortHolders root;
  Check(parse(header + UdpLine("00000000:AFC8", "0") +
                  UdpLine("0100007F:9C41", "1000"),
              &root) &&
            root.root_wildcard && !root.other_user,
        "a root wildcard socket on the port is AmneziaWG's");
  UdpPortHolders squatter;
  Check(parse(header + UdpLine("0100007F:AFC8", "1000"), &squatter) &&
            !squatter.root_wildcard && squatter.other_user,
        "another user's socket on the port is seen");
  UdpPortHolders loopback_root;
  Check(parse(header + UdpLine("0100007F:AFC8", "0"), &loopback_root) &&
            !loopback_root.root_wildcard && !loopback_root.other_user,
        "a root loopback-only socket is not the wildcard AmneziaWG binds");
  UdpPortHolders unheld;
  Check(parse(header, &unheld) && !unheld.root_wildcard && !unheld.other_user,
        "an unheld port is reported as unheld");
  UdpPortHolders refused;
  Check(!parse(UdpLine("00000000:AFC8", "0"), &refused),
        "a table without its header is refused");
  Check(!parse(header + "  12: garbage\n", &refused),
        "a short socket line is refused");
  Check(!parse(header + UdpLine("00000000:AFC8", "x"), &refused),
        "a non-decimal uid is refused");
  Check(!parse(header + UdpLine("0000:000:AFC8", "0"), &refused),
        "a malformed local address is refused");
  UdpPortHolders mapped;
  Check(parse(header +
                  UdpLine("0000000000000000FFFF00000100007F:AFC8", "1000"),
              &mapped) &&
            mapped.other_user && !mapped.root_wildcard,
        "another user's IPv6 or v4-mapped socket on the port is seen");
  UdpPortHolders both;
  Check(parse(header + UdpLine("00000000:AFC8", "0"), &both) &&
            parse(header + UdpLine("00000000000000000000000000000000:AFC8",
                                   "0"),
                  &both) &&
            both.root_wildcard && !both.other_user,
        "AmneziaWG's two root wildcard sockets are accepted across tables");
}

void TestEngineRefusesAPortAmneziaWgDoesNotHold() {
  // Nothing root-owned binds the reserved port here: on Linux the table shows
  // it unheld (or held by this test's own socket) and on any other host there
  // is no /proc/net/udp, so the start must refuse either way.
  uint16_t port = 0;
  std::string error;
  Check(winsvpn::winn::ReserveLinuxAwgListenPort(&port, &error),
        "a ListenPort is reserved for the unheld-port case");
  const int squatter = socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in loop{};
  loop.sin_family = AF_INET;
  loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  loop.sin_port = htons(port);
  Check(squatter >= 0 && bind(squatter, reinterpret_cast<const sockaddr*>(
                                            &loop),
                              sizeof(loop)) == 0,
        "an unprivileged process can take the reserved port first");
  uint16_t seam_port = 0;
  const int seam = winsvpn::winn::BindLinuxWinnSeam(&seam_port, &error);
  Check(seam >= 0, "the seam binds for the unheld-port case");
  winsvpn::winn::LinuxWinnParams params;
  params.awg_listen_port = port;
  Check(!winsvpn::winn::StartLinuxWinnEngine("/nonexistent/winn-datapath",
                                             seam, params, &error),
        "StartLinuxWinnEngine refuses a port AmneziaWG does not hold");
  Check(error.find("not held by AmneziaWG alone") != std::string::npos,
        "the refusal names the unheld port");
  Check(fcntl(seam, F_GETFD) == -1 && errno == EBADF,
        "the seam descriptor is closed on that refusal");
  if (squatter >= 0) close(squatter);
}

}  // namespace

int main() {
  TestRewritePinsListenPort();
  TestSeamAdmitsOnlyTheReservedPort();
  TestOversizedFirstDoesNotPoisonThePin();
  TestProcNetUdpHolders();
  TestReservedPortIsFree();
  TestEngineRefusesAnUnreservedPort();
  TestEngineRefusesAPortAmneziaWgDoesNotHold();
  if (failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  std::printf("linux_winn_seam_pin_test: all checks passed\n");
  return 0;
}
