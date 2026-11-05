// Carrier-pin unit test for the Windows split-tunnel physical /32 route.
//
// WHAT IT PINS, AND WHAT IT DOES NOT.
//
// The protected physical /32 route is built in PrepareWindowsAppExclusions():
//   remote_host = WindowsCarrierHostForConfig(raw_config);   // the seam
//   ... ResolveBestInterface(remote_host, ...) -> resolved_destination
//   ... CreateOwnedCarrierRoute(resolved_destination/32, ...)  // THE /32 PIN
// So the address this suite tests is exactly the address that becomes the /32.
// Asserting on WindowsCarrierHostForConfig is asserting on the /32 pin's source;
// it is the only pure, host-independent link in that chain (the resolution and
// route creation are real-OS calls a unit test cannot run without a live VPN).
//
// THE DEFECT THIS SUITE EXISTS TO HOLD SHUT (see windows_split_tunnel.cpp, the
// comment above WindowsCarrierHostForConfig, and the catalogue warning that a
// test asserting only a POSITIVE fact with nothing asserting the negative is
// the defect shape that survives sweeps):
//
// On a winn/3 start the AmneziaWG `[Peer] Endpoint` is rewritten to the
// loopback seam 127.0.0.1:<port>, so the outer socket does NOT address the peer
// endpoint at all. If the carrier-host resolver ever fell back to that loopback
// `[Peer] Endpoint`, the /32 pin would be on 127.0.0.1 and the engine's real
// outer socket would be left to the tunnel's own default route -- a dead loop.
//
// Therefore the resolver MUST return the `[winn]` carrier host whenever a winn
// carrier is present (WindowsWinnCarrierHost), and MUST NOT return a loopback
// `[Peer] Endpoint` in that situation. Each winn case asserts BOTH directions:
// it equals the winn host (positive) and is not 127.0.0.1 and not a loopback
// peer string (negative).
//
// The resolver order is:
//   1. `[Xray] Host`            -- Xray stealth carrier edge.
//   2. WindowsWinnCarrierHost() -- `[winn] endpoint`, when [winn] is enabled.
//   3. `[Peer] Endpoint`        -- plain AmneziaWG peer, host only (port/brackets
//      stripped). This is the fallback that must never fire while (1) or (2)
//      is present.
//
// Independent literals: every expected host is written out by hand (a real
// gateway, a private test IP), never read back off the code under test, so the
// expected values do not come from the very seam being pinned.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// Compile the REAL resolver into this TU so the anonymous-namespace member
// WindowsCarrierHostForConfig is visible by name. This is the production file,
// not a copy of its logic. WindowsWinnCarrierHost is declared in the header and
// defined in windows_winn_engine.cpp, which is linked as a second TU.
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

static bool Contains(const std::string& haystack, const char* needle) {
  return haystack.find(needle) != std::string::npos;
}

// A winn/3-shaped config: [winn] enabled with a real gateway endpoint, while
// the [Peer] Endpoint has ALREADY been rewritten to the loopback seam. This is
// the exact configuration where falling back to the peer would dead-loop.
static const char* kWinnWithLoopbackPeer =
    "[Interface]\n"
    "Address = 10.5.0.2/32\n"
    "Table = off\n"
    "[Peer]\n"
    "PublicKey = <REDACTED_WG_KEY>\n"
    "AllowedIPs = 0.0.0.0/0,::/0\n"
    "Endpoint = 127.0.0.1:33184\n"
    "[winn]\n"
    "enabled = true\n"
    "endpoint = 203.0.113.119:51820\n";

// Same, but with an IPv6 `[winn]` endpoint (bracketed form) so the bracketed
// IPv6 parsing path of the seam/engine is pinned too.
static const char* kWinnIpv6WithLoopbackPeer =
    "[Interface]\n"
    "Address = 10.5.0.2/32\n"
    "Table = off\n"
    "[Peer]\n"
    "AllowedIPs = 0.0.0.0/0,::/0\n"
    "Endpoint = 127.0.0.1:51821\n"
    "[winn]\n"
    "enabled = true\n"
    "endpoint = [2001:db8::10]:51820\n";

// [winn] present, real peer endpoint that DIFFERS from the winn gateway. The
// winn host must still win: the outer socket addresses the winn gateway, not
// the peer.
static const char* kWinnWithDifferentRealPeer =
    "[Peer]\n"
    "AllowedIPs = 0.0.0.0/0,::/0\n"
    "Endpoint = 198.51.100.7:51820\n"
    "[winn]\n"
    "enabled = true\n"
    "endpoint = 203.0.113.9:51820\n";

// winn present but NOT enabled, real (non-loopback) peer endpoint: the natural
// plain-AWGN case. The resolver must fall back to the peer host.
static const char* kWindowsDisabledRealPeer =
    "[Peer]\n"
    "AllowedIPs = 0.0.0.0/0,::/0\n"
    "Endpoint = 198.51.100.7:51820\n"
    "[winn]\n"
    "enabled = false\n"
    "endpoint = 203.0.113.9:51820\n";

// winn enabled but WITHOUT an endpoint key: WindowsWinnCarrierHost returns "".
// The resolver must then fall back to the peer host (not loopback-free here --
// a real peer).
static const char* kWinnPresentNoEndpointRealPeer =
    "[Peer]\n"
    "AllowedIPs = 0.0.0.0/0,::/0\n"
    "Endpoint = 198.51.100.8:51820\n"
    "[winn]\n"
    "enabled = true\n";

// Xray steam-carrier config: `[Xray] Host` must take priority over both the
// winn host and the peer.
static const char* kXrayWithWinnAndPeer =
    "[Peer]\n"
    "AllowedIPs = 0.0.0.0/0,::/0\n"
    "Endpoint = 198.51.100.9:51820\n"
    "[winn]\n"
    "enabled = true\n"
    "endpoint = 203.0.113.10:51820\n"
    "[Xray]\n"
    "Host = 192.0.2.22\n";

// Looback peer with NO winn present: this is the one situation that legitimately
// yields the loopback, proving the fallback path genuinely exists and fires only
// when neither carrier is present. This is the negative control for the loopback
// claim: loopback must appear ONLY here, never while a winn host is available.
static const char* kLoopbackPeerNoWinn =
    "[Peer]\n"
    "AllowedIPs = 0.0.0.0/0,::/0\n"
    "Endpoint = 127.0.0.1:33184\n";

static void TestWinnHostFollowedNotLoopback() {
  const std::string host = WindowsCarrierHostForConfig(kWinnWithLoopbackPeer);
  // POSITIVE: the /32 pin follows the [winn] carrier host.
  Check(host == "203.0.113.119",
        "winn carrier present + loopback peer -> host is the [winn] endpoint "
        "203.0.113.119");
  // NEGATIVE: it must NEVER be the rewritten loopback [Peer] Endpoint.
  Check(host != "127.0.0.1",
        "winn carrier present -> the loopback [Peer] Endpoint is NOT selected");
  Check(!Contains(host, "33184"),
        "winn carrier present -> no loopback seam port leaks into the host");
  Check(!Contains(host, ":"),
        "winn carrier present -> host is bare, no port component");

  const std::string ipv6 = WindowsCarrierHostForConfig(kWinnIpv6WithLoopbackPeer);
  Check(ipv6 == "2001:db8::10",
        "bracketed IPv6 [winn] endpoint is followed (host 2001:db8::10)");
  Check(ipv6 != "127.0.0.1",
        "bracketed IPv6 [winn] endpoint -> loopback peer NOT selected");

  const std::string different_peer =
      WindowsCarrierHostForConfig(kWinnWithDifferentRealPeer);
  Check(different_peer == "203.0.113.9",
        "winn host differs from a real peer endpoint -> winn host still wins");
  Check(different_peer != "198.51.100.7",
        "winn host differs from a real peer endpoint -> peer NOT used");
}

static void TestFallbacks() {
  // winn disabled: falls back to the real peer host.
  Check(WindowsCarrierHostForConfig(kWindowsDisabledRealPeer) == "198.51.100.7",
        "winn disabled -> falls back to the real [Peer] Endpoint host");
  // winn enabled but no endpoint: WindowsWinnCarrierHost is empty, so falls back.
  Check(WindowsCarrierHostForConfig(kWinnPresentNoEndpointRealPeer) ==
            "198.51.100.8",
        "winn enabled with no endpoint -> falls back to the [Peer] Endpoint host");
  // Xray wins over both.
  Check(WindowsCarrierHostForConfig(kXrayWithWinnAndPeer) == "192.0.2.22",
        "[Xray] Host takes priority over the winn host and the peer");
}

static void TestLoopbackOnlyWhenNoCarrier() {
  // The ONE case that legitimately returns loopback: no Xray, no winn.
  Check(WindowsCarrierHostForConfig(kLoopbackPeerNoWinn) == "127.0.0.1",
        "loopback [Peer] Endpoint is selected ONLY when no Xray/winn carrier "
        "is present (negative control)");
}

static void TestNoCarrierAtAll() {
  const std::string host =
      WindowsCarrierHostForConfig("[Interface]\nAddress = 10.0.0.2/32\n");
  Check(host.empty(),
        "no Xray/[,]/[winn]/[Peer] endpoint -> resolver returns empty");
}

int main() {
  std::printf("windows_split_tunnel_carrier_pin_test\n");
  TestWinnHostFollowedNotLoopback();
  TestFallbacks();
  TestLoopbackOnlyWhenNoCarrier();
  TestNoCarrierAtAll();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  if (g_failures == 0) {
    std::printf("PASS\n");
    return 0;
  }
  std::printf("FAIL\n");
  return 1;
}
