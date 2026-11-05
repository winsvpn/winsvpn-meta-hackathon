// Carrier-host resolution order unit test for the Windows tunnel backend.
//
// Pins the outer-socket carrier resolution in the shared routing core:
//
//   [Xray] Host  ->  WindowsWinnCarrierHost ([winn] endpoint)  ->  [Peer] Endpoint
//
// WindowsCarrierHostForConfig() returns the HOST only (brackets and port
// stripped), or "" when none of the three carriers is present. The order is
// load-bearing: it decides which address gets the owned /32 physical route pin
// (PrepareWindowsAppExclusions), and a wrong carrier pins loopback and dead
// loops the engine, or fails to exclude the real outer socket.
//
// WHY THIS FILE IS NOT IN windows/runner, LIKE ITS SIBLING ROUTEPLAN TEST.
// The function lives in the anonymous-namespace routing core of
// windows/runner/windows_split_tunnel.cpp, so the only way to exercise the REAL
// function - not a hand-rolled reimplementation that would always agree with
// itself - is to compile the real source into this TU via #include, which brings
// the anonymous-namespace member into scope by name. That #include drags in
// <windows.h> and the Windows SDK surface (IP_ADDRESS_PREFIX, Fwpm*), so it
// builds and RUNS only on the Windows target (winpc) with the MSVC toolchain,
// and is deliberately outside tools/verify_native_standalone_tests.sh's
// windows/runner glob. Same shape as windows_split_tunnel_routeplan_test.cc.
//
// Build and run on winpc (MSVC):
//
//   call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
//   cl /nologo /std:c++17 /EHsc /Gy /I..\runner ^
//        ..\test\windows_split_tunnel_carrierhost_test.cc ^
//        ..\runner\windows_winn_engine.cpp ^
//        /Fe:carrierhost_test.exe ^
//        /link advapi32.lib crypt32.lib fwpuclnt.lib iphlpapi.lib ^
//              shell32.lib ws2_32.lib user32.lib
//   carrierhost_test.exe
//
// windows_split_tunnel.cpp is pulled into this TU via the #include below, and
// windows_winn_engine.cpp is linked as its own unit because
// WindowsCarrierHostForConfig calls winsvpn::winn::WindowsWinnCarrierHost,
// which the header only declares and which lives in that file. Compiled without
// WINS_TUNNEL_SERVICE_CORE it is pure INI parsing with no <windows.h> of its
// own (windows_split_tunnel.cpp defines NOMINMAX before its <windows.h>).
//
// WHAT IT PINS, AND WHY ORDERED PAIRS ARE THE NEGATIVE CONTROLS. Each level is
// asserted to WIN when the levels below it are ALSO present, not each against an
// absent lower level. Reordering any two levels therefore flips one of these
// pairs to the lower carrier and FAILS:
//   - [Xray] Host wins with a [winn] endpoint AND a [Peer] Endpoint present.
//   - [winn] endpoint wins with a [Peer] Endpoint present and no [Xray] Host.
//   - [Peer] Endpoint is the fallback when neither higher carrier is present.
// That is the "assert the negative" shape the catalogue demands: a level whose
// priority was silently swapped cannot pass every pair.
//
// Independent literals are written out by hand ("198.51.100.10" etc.) so the
// expected hosts do not come back off the code under test.

#include <cstdio>
#include <string>

// Compile the REAL routing core into this TU so the anonymous-namespace
// WindowsCarrierHostForConfig is visible by name.
#include "windows_split_tunnel.cpp"

// ---------------------------------------------------------------------------
// Tiny assertion harness (same shape as the sibling *_test.cc files).
// ---------------------------------------------------------------------------
static int g_failures = 0;
static int g_checks = 0;

static void Check(bool cond, const char* what) {
  ++g_checks;
  if (!cond) {
    ++g_failures;
    std::fprintf(stderr, "FAIL: %s\n", what);
  }
}

// ---------------------------------------------------------------------------
// Config builder. A nullptr means "omit this section/key".
// ---------------------------------------------------------------------------
static std::string Config(const char* xray_host, bool winn_enabled,
                          const char* winn_endpoint,
                          const char* peer_endpoint) {
  std::string c = "[Interface]\nAddress = 10.0.0.2/32\n\n";
  if (xray_host != nullptr) {
    c += "[Xray]\nHost = ";
    c += xray_host;
    c += "\n\n";
  }
  if (winn_enabled || winn_endpoint != nullptr) {
    c += "[winn]\nenabled = ";
    c += (winn_enabled ? "true" : "false");
    c += "\n";
    if (winn_endpoint != nullptr) {
      c += "endpoint = ";
      c += winn_endpoint;
      c += "\n";
    }
    c += "\n";
  }
  c += "[Peer]\nPublicKey = test-public-key\n";
  if (peer_endpoint != nullptr) {
    c += "Endpoint = ";
    c += peer_endpoint;
    c += "\n";
  }
  c += "\n";
  return c;
}

// [Xray] Host wins over an equally-present [winn] endpoint and [Peer] Endpoint.
static void TestXrayHostWinsOverBoth() {
  const std::string c = Config("198.51.100.10:443", true, "198.51.100.7:443",
                               "203.0.113.9:51820");
  Check(WindowsCarrierHostForConfig(c) == "198.51.100.10",
        "[Xray] Host wins over a present [winn] endpoint and [Peer] Endpoint");
}

// No [Xray] Host, but a [winn] endpoint and a [Peer] Endpoint: the [winn]
// carrier wins.
static void TestWinnCarrierWinsOverPeer() {
  const std::string c =
      Config(nullptr, true, "198.51.100.7:443", "203.0.113.9:51820");
  Check(WindowsCarrierHostForConfig(c) == "198.51.100.7",
        "[winn] endpoint host wins over [Peer] Endpoint when [Xray] Host is "
        "absent");
}

// A [winn] section that is present but not enabled is NOT a carrier; resolution
// has to fall through to the [Peer] Endpoint.
static void TestWinnNotEnabledFallsToPeer() {
  const std::string c =
      Config(nullptr, false, "198.51.100.7:443", "203.0.113.9:51820");
  Check(WindowsCarrierHostForConfig(c) == "203.0.113.9",
        "a [winn] endpoint with enabled=false is not a carrier; [Peer] "
        "Endpoint is used");
}

// Only a [Peer] Endpoint: it is the fallback, with the trailing port stripped.
static void TestPeerEndpointFallbackStripsPort() {
  const std::string c = Config(nullptr, false, nullptr, "203.0.113.9:51820");
  Check(WindowsCarrierHostForConfig(c) == "203.0.113.9",
        "[Peer] Endpoint host is the fallback and has its port stripped");
}

// An IPv6-bracketed [Peer] Endpoint is stripped to the bare address.
static void TestPeerEndpointIpv6StripsBrackets() {
  const std::string c = Config(nullptr, false, nullptr, "[2001:db8::1]:51820");
  Check(WindowsCarrierHostForConfig(c) == "2001:db8::1",
        "an IPv6-bracketed [Peer] Endpoint is stripped to the bare host");
}

// None of the three carriers present resolves to "", never a guess.
static void TestEmptyWhenNoCarrier() {
  const std::string c = Config(nullptr, false, nullptr, nullptr);
  Check(WindowsCarrierHostForConfig(c).empty(),
        "no carrier host present resolves to empty, not a fallback guess");
}

static void TestAll() {
  TestXrayHostWinsOverBoth();
  TestWinnCarrierWinsOverPeer();
  TestWinnNotEnabledFallsToPeer();
  TestPeerEndpointFallbackStripsPort();
  TestPeerEndpointIpv6StripsBrackets();
  TestEmptyWhenNoCarrier();
}

int main() {
  TestAll();
  if (g_failures != 0) {
    std::fprintf(stderr, "%d/%d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  std::printf("all %d checks passed\n", g_checks);
  return 0;
}
