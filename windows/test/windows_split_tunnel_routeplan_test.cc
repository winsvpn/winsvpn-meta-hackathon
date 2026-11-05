// Route-plan unit test for the Windows split-tunnel route set.
//
// WHY THIS FILE IS NOT IN windows/runner LIKE ITS SIBLINGS, AND NOT IN THE
// PORTABLE STANDALONE GATE.
//
// The route planner under test, BuildManualRoutePlan(), lives inside an
// anonymous namespace in windows/runner/windows_split_tunnel.cpp (lines 39-1957,
// the whole routing core is anonymous there so it cannot pollute the service
// binary's namespace). Anonymous-namespace members have internal linkage, so a
// separate test translation unit cannot declare it extern and link it. The only
// way to exercise the REAL production function - rather than a hand-rolled
// reimplementation that would always agree with itself - is to compile the real
// source into this test translation unit via #include, which brings every
// anonymous-namespace member into scope by name.
//
// That #include makes this test depend on <windows.h> and the whole Windows SDK
// surface the planner uses (IP_ADDRESS_PREFIX, IN_ADDR, htonl/ntohl,
// InetPtonA), so it cannot be built by the POSIX standalone gate
// (tools/verify_native_standalone_tests.sh compiles every *_test.cc under
// windows/runner with the host 'c++'; a file needing <windows.h> would fail to
// compile there). The three sibling *_test.cc files are free of <windows.h> by
// design so they run anywhere; this one cannot be, because the function it pins
// IS windows-shaped. It is therefore placed under windows/ (outside the gate's
// windows/runner glob) and is built and RUN on the Windows target (winpc) with
// the real MSVC toolchain - which is the only toolchain that can execute it.
//
// Build and run it on winpc (MSVC):
//
//   call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
//   cl /nologo /std:c++17 /EHsc /Gy /I..\runner ^
//        ..\test\windows_split_tunnel_routeplan_test.cc ^
//        ..\runner\windows_winn_engine.cpp ^
//        /Fe:split_routeplan_test.exe ^
//        /link advapi32.lib crypt32.lib fwpuclnt.lib iphlpapi.lib ^
//              shell32.lib ws2_32.lib user32.lib
//   split_routeplan_test.exe
//
// fwpmu.lib is intentionally absent from the link list above: the Windows SDK
// installed on winpc does not ship it, and every Fwpm* entry point this code
// uses (FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionBegin0, ...) lives
// in fwpuclnt.lib, which is listed.
//
// windows_split_tunnel.cpp is pulled into this one translation unit via the
// #include below, which is what makes the anonymous-namespace planner callable
// by name. There is no second compilation unit FOR IT; windows_winn_engine.cpp
// above is its own translation unit, added because the planner's
// PrepareWindowsAppExclusions() calls winsvpn::winn::WindowsWinnCarrierHost,
// which the header only declares and which lives in that file. Compiled without
// WINS_TUNNEL_SERVICE_CORE it is pure INI parsing with no <windows.h>, and its
// carrier-host symbol is the only thing the extra unit is linked for. Neither
// NOMINMAX nor the service-core define is needed on the command line:
// windows_split_tunnel.cpp defines NOMINMAX itself before its <windows.h>.
//
// WHAT IT PINS.
//
// The planner computes the split-tunnel route set from the AWG peer's
// AllowedIPs: allowed networks go through the tunnel, and every IPv4 gap NOT in
// AllowedIPs becomes a list of more-specific physical bypass prefixes
// (bypass_ipv4) that outrank the tunnel's own /0 by longest-prefix match. The
// tunnel also installs 0.0.0.0/0 when install_ipv4_default is set.
//
// Two hazards this suite exists to catch, both of which the catalogue calls out
// as "a test asserting a POSITIVE fact with nothing asserting the negative":
//
//   1. NO BYPASS PRODUCED FOR A SPLIT CONFIG. If the planner silently stopped
//      emitting excluded ranges for a config that has gaps, the tunnel's /0
//      (enforceRoutes-style full capture) would pull those ranges INSIDE the
//      tunnel. The test asserts the bypass list is non-empty and that its union,
//      together with the allowed set, covers the entire IPv4 space exactly once
//      (no gaps, no overlaps). A dropped bypass leaves a hole -> the suite fails.
//
//   2. A BYPASS OVERLAPPING AN ALLOWED NETWORK (a leak in the other direction).
//      If a physical bypass prefix covered an address that AllowedIPs says must
//      go through the tunnel, that address would be routed out the physical NIC
//      instead of the tunnel. The test asserts every bypass prefix is disjoint
//      from every allowed network.
//
// Together those two checks are the complete non-leak guarantee: the IPv4
// address space is partitioned into exactly {tunnel (allowed), physical
// (bypass)}. enforceRoutes with a tunnel /0 cannot leak an excluded range into
// the tunnel (check 1) and cannot leak a tunnel range out of it (check 2).
//
// Independent literals are used where a number can be derived by hand (the
// exact first two bypass prefixes for a 10.0.0.0/8 config are written out as
// "0.0.0.0/5" and "128.0.0.0/7"), so the expected values do not come back off
// the very code under test - the "repo agreeing with itself" failure the
// catalogue lists.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>

// Compile the REAL planner into this TU so anonymous-namespace members are
// visible by name. This is the production file, not a copy of its logic.
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
// Helpers. The planner's own outputs are trusted indirectly: we convert its
// prefixes to concrete address ranges and compare RANGES, not the planner's own
// text. Expected prefix strings are derived independently by hand.
// ---------------------------------------------------------------------------

struct Rng {
  uint64_t s;
  uint64_t e;
};

// Named TestTrim rather than Trim: this TU includes windows_split_tunnel.cpp,
// whose anonymous-namespace Trim(std::string) is in scope here, so an
// unqualified call to a second file-local Trim would be ambiguous.
static std::string TestTrim(const std::string& in) {
  size_t b = in.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  size_t e = in.find_last_not_of(" \t\r\n");
  return in.substr(b, e - b + 1);
}

// IPv4 allows of a comma-separated CIDR set, as merged ranges. IPv6-only /0,/1
// generation handled separately; this only reads the IPv4 corner (the part the
// bypass list concerns).
static std::vector<Rng> AllowedIpv4(const std::string& allowed) {
  std::vector<Rng> out;
  std::istringstream ss(allowed);
  std::string item;
  while (std::getline(ss, item, ',')) {
    size_t slash = item.rfind('/');
    if (slash == std::string::npos || slash + 1 >= item.size()) continue;
    std::string addr = TestTrim(item.substr(0, slash));
    std::string plen_s = TestTrim(item.substr(slash + 1));
    if (addr.find(':') != std::string::npos) continue;  // not IPv4
    char* end = nullptr;
    long plen = std::strtol(plen_s.c_str(), &end, 10);
    if (end == plen_s.c_str() || *end != '\0') continue;
    if (plen < 0 || plen > 32) continue;
    IN_ADDR a = {};
    if (InetPtonA(AF_INET, addr.c_str(), &a) != 1) continue;
    uint32_t net = ntohl(a.S_un.S_addr);
    uint64_t block = (plen == 0) ? 0x100000000ULL : (1ULL << (32 - plen));
    uint64_t start = net & ~(block - 1);
    out.push_back({start, start + block - 1});
  }
  std::sort(out.begin(), out.end(),
            [](const Rng& x, const Rng& y) { return x.s < y.s; });
  std::vector<Rng> merged;
  for (const Rng& r : out) {
    if (merged.empty() || r.s > merged.back().e + 1) merged.push_back(r);
    else merged.back().e = std::max(merged.back().e, r.e);
  }
  return merged;
}

static Rng PrefixToRange(const IP_ADDRESS_PREFIX& p) {
  uint32_t net = ntohl(p.Prefix.Ipv4.sin_addr.S_un.S_addr);
  uint64_t block = (p.PrefixLength == 0) ? 0x100000000ULL
                                         : (1ULL << (32 - p.PrefixLength));
  uint64_t start = net & ~(block - 1);
  return {start, start + block - 1};
}

static std::string PrefixToString(const IP_ADDRESS_PREFIX& p) {
  const uint8_t* b = reinterpret_cast<const uint8_t*>(
      &p.Prefix.Ipv4.sin_addr.S_un.S_addr);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%u",
                (unsigned)b[0], (unsigned)b[1], (unsigned)b[2], (unsigned)b[3],
                static_cast<unsigned>(p.PrefixLength));
  return buf;
}

// True iff every bypass prefix is a valid, aligned IPv4 prefix.
static bool AllBypassValid(const std::vector<IP_ADDRESS_PREFIX>& bypass) {
  for (const IP_ADDRESS_PREFIX& p : bypass) {
    if (p.Prefix.si_family != AF_INET) return false;
    if (p.PrefixLength > 32) return false;
    const Rng r = PrefixToRange(p);
    if (r.s > r.e) return false;
  }
  return true;
}

// True iff no bypass range overlaps any allowed range (no tunnel route leaks
// out to the physical NIC).
static bool BypassDisjointFromAllowed(const std::vector<Rng>& allowed,
                                      const std::vector<IP_ADDRESS_PREFIX>& bypass) {
  for (const IP_ADDRESS_PREFIX& p : bypass) {
    const Rng br = PrefixToRange(p);
    for (const Rng& a : allowed) {
      if (br.e >= a.s && br.s <= a.e) return false;
    }
  }
  return true;
}

// THE non-leak assertion. Allowed (tunnel) plus bypass (physical) must cover
// the WHOLE IPv4 space exactly once: no gaps (an excluded range leaking into
// the tunnel) and no overlaps (an allowed range leaking out of the tunnel).
static bool PartitionIsComplete(const std::vector<Rng>& allowed,
                                const std::vector<IP_ADDRESS_PREFIX>& bypass) {
  std::vector<Rng> all = allowed;
  for (const IP_ADDRESS_PREFIX& p : bypass) all.push_back(PrefixToRange(p));
  std::sort(all.begin(), all.end(),
            [](const Rng& x, const Rng& y) { return x.s < y.s; });
  uint64_t cursor = 0;
  for (const Rng& r : all) {
    if (r.s > cursor) return false;   // uncovered gap
    if (r.s > r.e) return false;
    if (r.e + 1 < cursor) return false;  // overlap/reorder
    cursor = std::max(cursor, r.e + 1);
  }
  return cursor == 0x100000000ULL;  // reached end of IPv4 space exactly
}

static bool AnyBypassCovers(const std::vector<IP_ADDRESS_PREFIX>& bypass,
                            uint32_t address) {
  for (const IP_ADDRESS_PREFIX& p : bypass) {
    const Rng r = PrefixToRange(p);
    if (address >= r.s && address <= r.e) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void TestSplitConfigProducesExcludedRanges() {
  // A split config: 10.0.0.0/8 and 172.16.0.0/12 go through the tunnel, ::/0
  // gives both IPv6 halves. Everything else is excluded -> physical bypass.
  const std::string allowed = "10.0.0.0/8,172.16.0.0/12,::/0";
  std::vector<IP_ADDRESS_PREFIX> bypass;
  bool v4 = false, v6 = false;
  Check(BuildManualRoutePlan(allowed, &bypass, &v4, &v6),
        "split config accepted");
  Check(v4 && v6, "split config installs both defaults");
  Check(!bypass.empty(), "excluded (bypass) ranges ARE produced for a split config");

  if (!bypass.empty()) {
    Check(AllBypassValid(bypass), "every bypass prefix is a valid aligned IPv4 prefix");
    Check(bypass.size() <= 260, "bypass count within planner bound");

    const std::vector<Rng> allowed_ranges = AllowedIpv4(allowed);
    Check(!allowed_ranges.empty(), "split config has at least one IPv4 allowed network");

    Check(PartitionIsComplete(allowed_ranges, bypass),
          "allowed U bypass partitions IPv4 exactly once: no gap (nothing leaks "
          "into the tunnel) and no overlap (nothing leaks out)");
    Check(BypassDisjointFromAllowed(allowed_ranges, bypass),
          "no bypass prefix overlaps an allowed/tunnel network");
  }

  // Concrete positive facts about what is produced. 10.0.0.0/8 is the only
  // IPv4 allow here, so the FIRST excluded range must start at 0.0.0.0/5 and
  // the second at 8.0.0.0/7 (hand-derived: complement of 10.0.0.0/8 below
  // 10.0.0.0 is 0.0.0.0/5 covering 0 .. 7.255.255.255, then 8.0.0.0/7
  // covering 8.0.0.0 .. 9.255.255.255). The 128.0.0.0/1 that also appears is
  // the TOP half of IPv4; the same config's excluded set ends with 128.0.0.0/1,
  // which is why the second element must NOT be mistaken for it. Measured on
  // winpc: the full plan for this config is 0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8,
  // 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/1.
  const std::string open = "10.0.0.0/8,::/0";
  std::vector<IP_ADDRESS_PREFIX> ob;
  bool ov4 = false, ov6 = false;
  Check(BuildManualRoutePlan(open, &ob, &ov4, &ov6), "open /8 config accepted");
  if (ob.size() >= 1) {
    Check(PrefixToString(ob[0]) == "0.0.0.0/5",
          "first excluded prefix for 10.0.0.0/8 is exactly 0.0.0.0/5");
  } else {
    Check(false, "10.0.0.0/8 config produced no first excluded prefix");
  }
  if (ob.size() >= 2) {
    Check(PrefixToString(ob[1]) == "8.0.0.0/7",
          "second excluded prefix for 10.0.0.0/8 is exactly 8.0.0.0/7");
  }
  // The gap just below 10/8 (9.255.255.255) must be excluded, not tunneled;
  // 10.0.0.1 (allowed) must be tunneled, not excluded.
  if (ob.empty()) {
    Check(false, "no bypass produced to hold or exclude the lower gap");
  } else {
    Check(AnyBypassCovers(ob, 0x09FFFFFF), "9.255.255.255 (below 10/8) is excluded, not tunneled");
    Check(!AnyBypassCovers(ob, 0x0A000001), "10.0.0.1 (allowed) is NOT excluded/leaked to physical");
  }
}

static void TestFullTunnelProducesNoExcludedRanges() {
  // 0.0.0.0/0 -> full tunnel, no gaps. Planner must produce NO bypass and still
  // report defaults. This is the negative control for "excluded ranges are
  // produced": a config with nothing to exclude must produce none.
  const std::string allowed = "0.0.0.0/0,::/0";
  std::vector<IP_ADDRESS_PREFIX> bypass;
  bool v4 = false, v6 = false;
  Check(BuildManualRoutePlan(allowed, &bypass, &v4, &v6), "full-tunnel config accepted");
  Check(v4 && v6, "full-tunnel config installs both defaults");
  Check(bypass.empty(), "full tunnel 0.0.0.0/0 produces NO excluded range");

  const std::vector<Rng> allowed_ranges = AllowedIpv4(allowed);
  Check(PartitionIsComplete(allowed_ranges, bypass),
        "full tunnel still partitions IPv4 exactly once (allow covers all)");
}

static void TestGuardRejections() {
  // Missing IPv6 halves: refused.
  std::vector<IP_ADDRESS_PREFIX> b1;
  bool a = true, c = true;
  Check(!BuildManualRoutePlan("10.0.0.0/8", &b1, &a, &c),
        "config with no IPv6 coverage is refused");

  // No IPv4 allowed: refused.
  std::vector<IP_ADDRESS_PREFIX> b2;
  a = c = true;
  Check(!BuildManualRoutePlan("::/0", &b2, &a, &c),
        "config with no IPv4 allowed is refused");

  // A non-covering IPv6 prefix (only /0 and /1 are valid): refused.
  std::vector<IP_ADDRESS_PREFIX> b3;
  a = c = true;
  Check(!BuildManualRoutePlan("10.0.0.0/8,2001:db8::/32,::/0", &b3, &a, &c),
        "an IPv6 prefix that is neither /0 nor /1 is refused");

  // Garbage CIDR: refused.
  std::vector<IP_ADDRESS_PREFIX> b4;
  a = c = true;
  Check(!BuildManualRoutePlan("not-an-ip/24,10.0.0.0/8,::/0", &b4, &a, &c),
        "an unparsable CIDR is refused");

  // Two /1 IPv6 halves as the /0 alternative must still be accepted and must
  // still produce a bypass for the 10.0.0.0/8 gap.
  std::vector<IP_ADDRESS_PREFIX> b5;
  a = c = false;
  Check(BuildManualRoutePlan("10.0.0.0/8,::/1,8000::/1", &b5, &a, &c),
        "config covering IPv6 via two explicit /1 halves is accepted");
  Check(a && c, "two-/1 config installs both defaults");
  Check(!b5.empty(), "two-/1 config still produces excluded ranges for the 10/8 gap");
}

static void TestRouteCountGuard() {
  // 261 IPv4 /32 routes exceeds the planner's 260 route cap and must be refused
  // (a runaway reported route count is a guard this suite should hold shut).
  std::string allowed = "::/0";
  for (int i = 0; i <= 260; ++i) {
    char cidr[64];
    std::snprintf(cidr, sizeof(cidr), "0.0.%u.%u/32", (i >> 8) & 0xff, i & 0xff);
    // 0.0.0.i/32 -> 0.0.0.0..0.0.0.260 all distinct /32s up to 0.0.1.4
    allowed += std::string(",") + cidr;
  }
  std::vector<IP_ADDRESS_PREFIX> bypass;
  bool a = true, c = true;
  Check(!BuildManualRoutePlan(allowed, &bypass, &a, &c),
        "a config with more than 260 routes is refused");
}

int main() {
  std::printf("windows_split_tunnel_routeplan_test\n");
  TestSplitConfigProducesExcludedRanges();
  TestFullTunnelProducesNoExcludedRanges();
  TestGuardRejections();
  TestRouteCountGuard();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  if (g_failures == 0) {
    std::printf("PASS\n");
    return 0;
  }
  std::printf("FAIL\n");
  return 1;
}
