// End-to-end verification of the Windows Winn Protocol v3 host, ON WINDOWS,
// against the REAL winn-datapath engine.
//
// This harness is committed rather than thrown away on purpose. The previous
// Windows lane's harness was not kept and the next lane had to rebuild it from
// scratch; the Linux lane recorded the same complaint. Everything below can be
// re-run with tools/verify_windows_winn_seam.ps1.
//
// WHAT IT PROVES, and equally what it does not.
//
// It drives the SHIPPING host entry points in windows/runner/windows_winn_engine
// .cpp -- BindWindowsWinnSeam, StartWindowsWinnEngine, the two pumps,
// WindowsWinnTransportObservedBothWays, StopWindowsWinnEngine -- in the same
// order InstallPrivilegedTunnel calls them, against the real
// cmd/winn-datapath binary, on the real operating system. It stands in for
// AmneziaWG with a plain UDP socket that speaks AmneziaWG-SHAPED datagrams:
// the classification table is real and the header words are real, but there is
// no Noise handshake and no encryption, because the point of the seam is that
// it carries opaque outer datagrams and never looks inside one.
//
// It does NOT touch a WinTun adapter, a route, DNS, or the privileged service.
// Those are exercised by InstallPrivilegedTunnel and are not reachable without
// administrator rights and the AmneziaWG payload; this harness deliberately
// needs neither, so it can be run on any Windows machine.

#include "../windows/runner/windows_winn_engine.h"

// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

void Check(bool condition, const std::string& what) {
  ++g_checks;
  if (condition) {
    std::printf("  ok   %s\n", what.c_str());
    return;
  }
  ++g_failures;
  std::printf("  FAIL %s\n", what.c_str());
}

std::string ReadWholeFile(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream out;
  out << stream.rdbuf();
  return out.str();
}

// One AmneziaWG-shaped transport-data datagram.
//
// classify() reads the header word at offset S4 (0 here, the shipping default)
// and compares it against H4, and carriesTransportPayload requires a length
// strictly greater than S4 + 32 before it will move the counters that back
// transport_observed_both_ways. So the shape below is the minimum that a
// correct engine must count, and anything smaller is deliberately NOT used --
// a harness that produced keepalive-sized datagrams would pass a gate that was
// silently broken.
std::vector<uint8_t> MakeTransportDatagram(uint32_t h4, uint16_t s4,
                                           size_t total, uint8_t seed) {
  std::vector<uint8_t> datagram(total, 0);
  for (size_t index = 0; index < total; ++index) {
    datagram[index] = static_cast<uint8_t>(seed + index);
  }
  datagram[s4 + 0] = static_cast<uint8_t>(h4 & 0xFF);
  datagram[s4 + 1] = static_cast<uint8_t>((h4 >> 8) & 0xFF);
  datagram[s4 + 2] = static_cast<uint8_t>((h4 >> 16) & 0xFF);
  datagram[s4 + 3] = static_cast<uint8_t>((h4 >> 24) & 0xFF);
  return datagram;
}

// A stand-in gateway: it answers every datagram it receives with a transport
// datagram of its own, so the RETURN direction is a real AmneziaWG-shaped one
// and rx_transport_payload_datagrams can move. Echoing the request verbatim
// would work too, but answering with distinct bytes is what lets the harness
// tell a working return path from a loopback of its own traffic.
// Shut down with WSAEventSelect plus an explicit quit event, which is the same
// mechanism the SHIPPED inbound pump uses, and it is here because the two
// obvious alternatives were both tried on this machine and both hung:
//
//   - SO_RCVTIMEO plus a polled `stop` flag, and
//   - closesocket() from another thread to release a blocked recvfrom.
//
// Each one produced the identical symptom: 46/46 checks passing,
// StopWindowsWinnEngine returning cleanly, and this thread never joining, so
// the process sat in tasklist forever. Winsock does not promise that
// closesocket releases a blocking call pending on that socket, and a receive
// timeout is only a timeout, not a wakeup. An event the closer can signal is
// the only shutdown that is actually deterministic here -- which is exactly why
// the shipped pump is written that way, and it joined on every single run.
struct StandInGateway {
  SOCKET socket_handle = INVALID_SOCKET;
  WSAEVENT readable = WSA_INVALID_EVENT;
  HANDLE quit = nullptr;
  std::atomic<uint64_t> received{0};
  std::atomic<uint64_t> sent{0};
  uint32_t h4 = 0;
  uint16_t s4 = 0;
  std::thread worker;

  bool Start(uint16_t port, uint32_t header4, uint16_t padding4) {
    h4 = header4;
    s4 = padding4;
    socket_handle = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                               WSA_FLAG_NO_HANDLE_INHERIT);
    if (socket_handle == INVALID_SOCKET) return false;
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (bind(socket_handle, reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) != 0) {
      closesocket(socket_handle);
      socket_handle = INVALID_SOCKET;
      return false;
    }
    readable = WSACreateEvent();
    quit = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (readable == WSA_INVALID_EVENT || quit == nullptr ||
        WSAEventSelect(socket_handle, readable, FD_READ) != 0) {
      Stop();
      return false;
    }
    worker = std::thread([this]() {
      std::vector<uint8_t> buffer(2048);
      const HANDLE waits[2] = {readable, quit};
      for (;;) {
        if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) !=
            WAIT_OBJECT_0) {
          return;
        }
        WSAResetEvent(readable);
        for (;;) {
          sockaddr_in sender = {};
          int sender_size = sizeof(sender);
          const int count =
              recvfrom(socket_handle, reinterpret_cast<char*>(buffer.data()),
                       static_cast<int>(buffer.size()), 0,
                       reinterpret_cast<sockaddr*>(&sender), &sender_size);
          if (count <= 0) break;
          received.fetch_add(1);
          const std::vector<uint8_t> reply =
              MakeTransportDatagram(h4, s4, 160, 0xA0);
          if (sendto(socket_handle,
                     reinterpret_cast<const char*>(reply.data()),
                     static_cast<int>(reply.size()), 0,
                     reinterpret_cast<const sockaddr*>(&sender),
                     sender_size) > 0) {
            sent.fetch_add(1);
          }
        }
      }
    });
    return true;
  }

  void Stop() {
    if (quit != nullptr) SetEvent(quit);
    if (worker.joinable()) worker.join();
    if (socket_handle != INVALID_SOCKET) {
      closesocket(socket_handle);
      socket_handle = INVALID_SOCKET;
    }
    if (readable != WSA_INVALID_EVENT) {
      WSACloseEvent(readable);
      readable = WSA_INVALID_EVENT;
    }
    if (quit != nullptr) {
      CloseHandle(quit);
      quit = nullptr;
    }
  }
};

}  // namespace

int main(int argc, char** argv) {
  // Unbuffered on purpose. The thing under test owns subprocesses, sockets and
  // two pump threads, so "where did it stop" has to be answerable from a
  // redirected log without attaching a debugger over SSH.
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  if (argc < 3) {
    std::fprintf(stderr,
                 "usage: verify_windows_winn_seam <config.ini> "
                 "<winn-datapath.exe>\n");
    return 2;
  }
  const std::string config = ReadWholeFile(argv[1]);
  const std::string engine_utf8 = argv[2];
  const std::wstring engine_path(engine_utf8.begin(), engine_utf8.end());
  if (config.empty()) {
    std::fprintf(stderr, "the configuration file is empty\n");
    return 2;
  }
  WSADATA wsa = {};
  WSAStartup(MAKEWORD(2, 2), &wsa);

  std::printf("== framing conformance ==\n");
  {
    std::string error;
    Check(winsvpn::winn::RunWindowsWinnFramingSelfTest(&error),
          "winn_frame.h self-test passes on Windows: " + error);
  }

  std::printf("== selection and parsing of the SHIPPING Dart section ==\n");
  Check(winsvpn::winn::WindowsConfigSelectsWinnProtocol(config),
        "[winn] enabled = true selects the Winn path");
  Check(!winsvpn::winn::WindowsConfigSelectsWinnProtocol(
            "[Interface]\nAddress = 10.0.0.2/32\n"),
        "a plain AmneziaWG config does not select the Winn path");
  Check(!winsvpn::winn::WindowsConfigSelectsWinnProtocol(
            "[winn]\nprotocol = winn/3\n"),
        "the retired `protocol = winn/3` key alone no longer selects anything");

  winsvpn::winn::WindowsWinnParams params;
  {
    std::string error;
    Check(winsvpn::winn::ParseWindowsWinnSection(config, &params, &error),
          "the Dart-emitted [winn] section parses: " + error);
  }
  Check(params.max_datagram == 1400, "max_datagram survives the parse");
  Check(params.h[0] == 11 && params.h[1] == 22 && params.h[2] == 33 &&
            params.h[3] == 44,
        "h1..h4 survive the parse");
  Check(params.s[0] == 16 && params.s[1] == 80 && params.s[2] == 16 &&
            params.s[3] == 0,
        "s1..s4 survive the parse");

  std::printf("== refusals ==\n");
  {
    std::string error;
    winsvpn::winn::WindowsWinnParams ignored;
    const std::string carrier_config =
        "[winn]\nenabled = true\nendpoint = 127.0.0.1:51820\n"
        "carrier = http3-connect-udp\nmasque_template = https://x/y\n";
    Check(!winsvpn::winn::ParseWindowsWinnSection(carrier_config, &ignored,
                                                  &error),
          "an http3-connect-udp carrier is refused");
    Check(error.find("http3-connect-udp") != std::string::npos,
          "the refusal names the carrier, not the first profile key");
    Check(error.find("downgrade") != std::string::npos,
          "the refusal says why: starting direct-awg instead is a downgrade");
  }
  {
    std::string error;
    winsvpn::winn::WindowsWinnParams ignored;
    Check(!winsvpn::winn::ParseWindowsWinnSection(
              "[winn]\nenabled = true\nendpoint = 127.0.0.1:51820\n"
              "nonsense = 1\n",
              &ignored, &error),
          "an unrecognised [winn] key is a refusal, never a silent drop");
    Check(!winsvpn::winn::ParseWindowsWinnSection(
              "[winn]\nenabled = true\nendpoint = gateway.example.com:51820\n",
              &ignored, &error),
          "a hostname gateway endpoint is refused");
    Check(!winsvpn::winn::ParseWindowsWinnSection(
              "[winn]\nenabled = true\nendpoint = 127.0.0.1:51820\n"
              "h1 = 11\nh2 = 22\n",
              &ignored, &error),
          "a partial h1..h4 table is refused");
    Check(!winsvpn::winn::ParseWindowsWinnSection(
              "[winn]\nenabled = true\nendpoint = 127.0.0.1:51820\n"
              "h1 = 11\nh2 = 11\nh3 = 33\nh4 = 44\n",
              &ignored, &error),
          "duplicate header types are refused");
  }

  std::printf("== the datapath.Config this host builds ==\n");
  const std::string create_json =
      winsvpn::winn::BuildWindowsWinnConfigJson(params);
  Check(create_json.find("\"contract\":\"winn-datapath/1\"") !=
            std::string::npos,
        "the Create document names the datapath contract");
  Check(create_json.find("\"payload\":\"awg-datagram\"") != std::string::npos,
        "the Create document declares awg-datagram, not ip-packet");
  Check(create_json.find("\"allow_own_socket\":true") != std::string::npos,
        "allow_own_socket is true, matching the pinned /32 exclusion");
  Check(create_json.find("PrivateKey") == std::string::npos &&
            create_json.find("privatekey") == std::string::npos,
        "NO key material crosses the boundary: the whole-INI handoff is gone");
  Check(create_json.find("\"config\"") == std::string::npos,
        "the retired {protocol,mtu,config} document is gone");
  std::printf("     %s\n", create_json.c_str());

  std::printf("== the AmneziaWG peer endpoint rewrite ==\n");
  {
    const std::string awg =
        "[Interface]\nPrivateKey = AAA\n\n[Peer]\nPublicKey = BBB\n"
        "Endpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\n";
    std::string rewritten;
    Check(winsvpn::winn::RewriteAwgPeerEndpointToSeam(awg, 40404, &rewritten),
          "exactly one Endpoint is rewritten");
    Check(rewritten.find("Endpoint = 127.0.0.1:40404") != std::string::npos,
          "the peer now points at the loopback seam");
    Check(rewritten.find("203.0.113.10") == std::string::npos,
          "the real gateway is gone from the AmneziaWG configuration");
    Check(rewritten.find("PrivateKey = AAA") != std::string::npos,
          "every other line is preserved byte for byte");
    std::string ignored;
    Check(!winsvpn::winn::RewriteAwgPeerEndpointToSeam(
              "[Peer]\nPublicKey = BBB\n", 40404, &ignored),
          "a config with no Endpoint is refused, never appended to");
    Check(!winsvpn::winn::RewriteAwgPeerEndpointToSeam(
              awg + "Endpoint = 198.51.100.7:51820\n", 40404, &ignored),
          "a config with two Endpoints is refused");
  }

  std::printf("== the carrier host the /32 pin follows ==\n");
  Check(winsvpn::winn::WindowsWinnCarrierHost(config) ==
            winsvpn::winn::WindowsWinnCarrierHost(config),
        "WindowsWinnCarrierHost is deterministic");
  {
    const std::string host = winsvpn::winn::WindowsWinnCarrierHost(config);
    Check(!host.empty(), "a winn/3 config yields a carrier host: " + host);
    Check(winsvpn::winn::WindowsWinnCarrierHost(
              "[Interface]\nAddress = 10.0.0.2/32\n")
              .empty(),
          "a non-Winn config yields none, so the peer fallback still applies");
  }

  std::printf("== LIVE: the seam, the real engine, and the promotion gate ==\n");
  std::string host;
  std::string port;
  if (!winsvpn::winn::SplitWindowsWinnEndpoint(params.endpoint, &host, &port)) {
    std::printf("  FAIL the configured endpoint is unusable\n");
    ++g_failures;
    return g_failures == 0 ? 0 : 1;
  }
  StandInGateway gateway;
  const uint16_t gateway_port =
      static_cast<uint16_t>(std::strtoul(port.c_str(), nullptr, 10));
  Check(gateway.Start(gateway_port, params.h[3], params.s[3]),
        "the stand-in gateway is listening on " + params.endpoint);

  uint16_t seam_port = 0;
  std::string error;
  const uintptr_t seam = winsvpn::winn::BindWindowsWinnSeam(&seam_port, &error);
  Check(seam != winsvpn::winn::kInvalidWinnSeam,
        "the loopback seam binds: " + error);
  Check(seam_port != 0, "the seam reports an ephemeral port");

  const bool started = winsvpn::winn::StartWindowsWinnEngine(
      engine_path, seam, params, &error);
  Check(started, "the REAL winn-datapath acknowledged Create: " + error);
  if (!started) {
    gateway.Stop();
    std::printf("\n%d/%d checks passed, %d failed\n", g_checks - g_failures,
                g_checks, g_failures);
    return 1;
  }
  Check(winsvpn::winn::WindowsWinnEngineRunning(),
        "the engine channel is up");

  // Stand in for AmneziaWG: one loopback UDP socket sending outer datagrams to
  // the seam and reading what comes back. This is exactly what the real AWG
  // engine does once its peer Endpoint has been rewritten.
  SOCKET awg = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                          WSA_FLAG_NO_HANDLE_INHERIT);
  Check(awg != INVALID_SOCKET, "the stand-in AmneziaWG socket opens");
  DWORD read_timeout = 2000;
  setsockopt(awg, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char*>(&read_timeout),
             sizeof(read_timeout));
  sockaddr_in awg_local = {};
  awg_local.sin_family = AF_INET;
  awg_local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  awg_local.sin_port = 0;
  bind(awg, reinterpret_cast<sockaddr*>(&awg_local), sizeof(awg_local));
  sockaddr_in seam_address = {};
  seam_address.sin_family = AF_INET;
  seam_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  seam_address.sin_port = htons(seam_port);

  constexpr int kDatagrams = 64;
  int delivered_back = 0;
  for (int index = 0; index < kDatagrams; ++index) {
    const std::vector<uint8_t> datagram =
        MakeTransportDatagram(params.h[3], params.s[3], 200,
                              static_cast<uint8_t>(index));
    sendto(awg, reinterpret_cast<const char*>(datagram.data()),
           static_cast<int>(datagram.size()), 0,
           reinterpret_cast<const sockaddr*>(&seam_address),
           sizeof(seam_address));
  }
  {
    std::vector<uint8_t> buffer(2048);
    for (int index = 0; index < kDatagrams; ++index) {
      const int count = recv(awg, reinterpret_cast<char*>(buffer.data()),
                             static_cast<int>(buffer.size()), 0);
      if (count <= 0) break;
      ++delivered_back;
    }
  }
  Check(gateway.received.load() == kDatagrams,
        "every datagram reached the stand-in gateway THROUGH the engine (" +
            std::to_string(gateway.received.load()) + "/" +
            std::to_string(kDatagrams) + ")");
  Check(delivered_back == kDatagrams,
        "every reply came back out of the seam to the AmneziaWG socket (" +
            std::to_string(delivered_back) + "/" +
            std::to_string(kDatagrams) + ")");

  bool observed = false;
  std::string status;
  for (int attempt = 0; attempt < 40 && !observed; ++attempt) {
    observed = winsvpn::winn::WindowsWinnTransportObservedBothWays(&status);
    if (!observed) Sleep(100);
  }
  Check(observed,
        "transport_observed_both_ways is true -- the transfer-proven half of "
        "the route-promotion gate");
  Check(status.find("\"awg_classification\":\"configured-h1h4\"") !=
            std::string::npos,
        "the engine classified with the CONFIGURED table, not the WireGuard "
        "default (a wireguard-default-1234 here means the counters are dead)");
  Check(status.find("\"tx_rejected\":0") != std::string::npos,
        "no datagram was rejected on the way out");
  Check(status.find("\"rx_foreign_sender\":0") != std::string::npos,
        "no datagram arrived from anything but the configured gateway");
  Check(status.find("\"socket_owned_by_engine\":true") != std::string::npos,
        "the engine opened its own outer socket, which is what the pinned /32 "
        "exists to keep off the tunnel");
  std::printf("     %s\n", status.c_str());

  std::printf("== a second local sender cannot inject into this tunnel ==\n");
  {
    const uint64_t before = gateway.received.load();
    SOCKET intruder = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                                 WSA_FLAG_NO_HANDLE_INHERIT);
    const std::vector<uint8_t> datagram =
        MakeTransportDatagram(params.h[3], params.s[3], 200, 0x5A);
    sendto(intruder, reinterpret_cast<const char*>(datagram.data()),
           static_cast<int>(datagram.size()), 0,
           reinterpret_cast<const sockaddr*>(&seam_address),
           sizeof(seam_address));
    Sleep(400);
    Check(gateway.received.load() == before,
          "a datagram from an unpinned local socket is dropped at the seam");
    closesocket(intruder);
  }

  std::printf("== teardown ==\n");
  std::printf("  ... StopWindowsWinnEngine\n");
  winsvpn::winn::StopWindowsWinnEngine();
  std::printf("  ... StopWindowsWinnEngine returned\n");
  Check(!winsvpn::winn::WindowsWinnEngineRunning(),
        "the engine is gone after StopWindowsWinnEngine");
  Check(winsvpn::winn::WindowsWinnEngineStatusJson().empty(),
        "no status is reported once the channel is down");
  Check(!winsvpn::winn::WindowsWinnTransportObservedBothWays(nullptr),
        "the promotion gate answers false with no engine, never stale-true");
  closesocket(awg);
  std::printf("  ... gateway.Stop\n");
  gateway.Stop();
  std::printf("  ... WSACleanup\n");
  WSACleanup();

  std::printf("\n%d/%d checks passed, %d failed\n", g_checks - g_failures,
              g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
