// Elevated verification for the four Windows Winn Protocol v3 items that
// tools/verify_windows_winn_seam.cpp cannot reach, ON WINDOWS, WITH
// ADMINISTRATOR RIGHTS, as much as is honestly possible WITHOUT a live
// AmneziaWG gateway.
//
// tools/verify_windows_winn_seam.cpp's own header says it plainly: it "does
// NOT touch a WinTun adapter, a route, DNS, or the privileged service...
// this harness deliberately needs neither, so it can be run on any Windows
// machine." That leaves four things compiled but never executed (see
// .winn_platform_progress/windows.json and
// docs/handoff/COMBINED_HANDOFF_ALL_FIVE_20260731.md Section 10.9):
//
//   1. The pinned /32 host route on the PHYSICAL adapter LUID
//      (CreateIpForwardEntry2 in windows/runner/windows_split_tunnel.cpp)
//      surviving GetBestRoute2 after the tunnel's /0 routes are promoted.
//   2. The AmneziaWG runtime reporting 127.0.0.1:<seam port> as its peer
//      endpoint (ValidateLoadedAwgRuntime, windows_tunnel_backend.cpp).
//   3. WaitForAwgConvergence and WaitForWinnTransportConvergence both
//      passing, IN THAT ORDER, before any /0 route exists.
//   4. Killing winn-datapath.exe mid-session making IsTunnelRunning go
//      false.
//
// THIS FILE DOES NOT CLOSE ALL FOUR. It is honest about which ones a
// standalone elevated process can actually exercise and which ones
// structurally need a live AmneziaWG gateway and a live winn/3 server. Two
// tiers, and this program says on every run which one it ran:
//
//   TIER A -- needs administrator rights only, NO gateway. Runs unconditionally.
//     * Item 1, close to completely: pins a synthetic /32 on the REAL
//       physical default-route LUID, adds a competing wider route, and
//       proves GetBestRoute2 still resolves the /32 -- see "WHY A /24 ON
//       LOOPBACK, NEVER A REAL /0" below for the one deliberate difference
//       from production.
//     * Item 4, partially: starts the REAL winn-datapath.exe (same binary
//       and same shipping entry points tools/verify_windows_winn_seam.cpp
//       already drives), kills it out from under the host without going
//       through StopWindowsWinnEngine, and proves
//       winsvpn::winn::WindowsWinnEngineRunning() -- the process-liveness
//       primitive IsTunnelRunning() depends on -- goes false. It does NOT
//       run IsTunnelRunning() itself; see that section for exactly why not.
//
//   TIER B -- needs administrator rights AND a real AmneziaWG gateway AND a
//   real winn/3 server config, already connected through the shipping app.
//   This program cannot create that state (faking it would prove nothing
//   about the real AmneziaWG runtime or the real gateway), so Tier B here is
//   a READ-ONLY STATUS PROBE: it asks the ALREADY-RUNNING privileged
//   service what it currently observes, using the exact kStatus call the
//   shipping app itself uses (QueryWindowsTunnelManager in
//   windows_tunnel_service_client.cpp). If nothing is connected it says so
//   and that is reported as "skip", never as a failure -- this program did
//   not fail to start a tunnel, it was never asked to. Items 2 and 3
//   proper, and the FULL IsTunnelRunning() (which also needs
//   g_winn_tunnel_active and IsWinsAwgEngineRunning, both only set inside
//   the real privileged start path against a real gateway), stay
//   genuinely unverified until that manual step happens. See
//   tools/README_WINDOWS_ELEVATED_VERIFY.md for exactly what to do and
//   what to paste back.
//
// WHY A /24 ON LOOPBACK, NEVER A REAL /0, EVER
//
// Item 1 asks whether the pin survives after "the tunnel's /0 routes are
// promoted". This harness deliberately never creates a real 0.0.0.0/0 (or
// the 0.0.0.0/1 + 128.0.0.0/1 pair InstallWindowsTunnelConvergenceProbeRoute
// uses) anywhere, on any interface, even for a moment: on a working laptop
// actually in use, a synthetic default route that is even briefly live can
// hijack real traffic if anything about its metric or timing goes wrong,
// and the whole point of this program is to be safe to run on the owner's
// only machine. Longest-prefix-match is the mechanism that makes a /32 beat
// a /0 regardless of metric, and that exact arithmetic -- does Windows
// prefer the more specific prefix when a less specific one also matches -- is
// fully exercised by a /32 beating any prefix shorter than itself, so a /24
// that also contains the /32, confined entirely to RFC 5737 TEST-NET-3
// (203.0.113.0/24, reserved for documentation and guaranteed non-routable)
// and pointed at the loopback pseudo-interface, proves the identical
// selection logic without ever creating a route that could plausibly win a
// lookup for real traffic. If that distinction matters for a specific
// review, the owner's real winn/3 session (Tier B) exercises the actual
// 0.0.0.0/0 the shipping code installs.
//
// This also matches production's own scope, not just this test's
// convenience: ResolveBestInterface (windows_split_tunnel.cpp), which the
// real carrier pin is built from, hardcodes `hints.ai_family = AF_INET`.
// The physical carrier pin is IPv4-only in this codebase already; this
// harness does not narrow anything by staying IPv4-only too.
//
// WHY THIS CALLS CreateIpForwardEntry2/GetBestRoute2 DIRECTLY INSTEAD OF THE
// PRODUCTION FUNCTIONS
//
// windows_split_tunnel.h exports PrepareWindowsAppExclusions and
// InstallWindowsTunnelRoutes and little else; CreateOwnedRoute,
// CreateOwnedCarrierRoute and VerifyCommittedWindowsTunnelRoutes have
// internal linkage inside windows_split_tunnel.cpp and are not reachable
// from another translation unit. Calling the real PrepareWindowsAppExclusions
// would also mean standing up the signed split-tunnel driver service and
// winning ConflictingSplitTunnelActive's race against any other VPN on the
// box -- a much bigger and riskier ask for a program whose whole purpose is
// to be safe to run on a working laptop, and one this agent cannot
// compile-check on macOS in the first place. Rather than widen
// windows_split_tunnel.h's exported surface for a test -- a change to
// shipping code this agent cannot compile-check either, and a file three
// other things in this tree already warn is being concurrently edited --
// this program instead calls CreateIpForwardEntry2 / GetBestRoute2 /
// DeleteIpForwardEntry2 directly, with the IDENTICAL MIB_IPFORWARD_ROW2
// field values CreateOwnedRoute uses (compare windows_split_tunnel.cpp's
// CreateOwnedRoute, and OwnedTestRoute::Create below) and the IDENTICAL
// assertion shape VerifyCommittedWindowsTunnelRoutes makes.
//
// BE PRECISE ABOUT WHAT THAT DOES AND DOES NOT PROVE. It proves the WINDOWS
// ROUTING BEHAVIOUR the production code depends on: that a /32 created with
// these exact field values, on the real physical LUID, really does keep
// winning GetBestRoute2 once a shorter competing prefix exists. It does NOT
// execute PrepareWindowsAppExclusions or VerifyCommittedWindowsTunnelRoutes
// themselves, so a bug purely in HOW that code calls these APIs -- a wrong
// struct field, a skipped check, an argument in the wrong order -- would not
// be caught here. Closing that last gap needs either a real winn/3 session
// (Tier B) or a reviewer diffing this file's field-by-field mirror against
// windows_split_tunnel.cpp by eye.
//
// SAFETY / CLEANUP CONTRACT
//
// Every route this program creates is wrapped in OwnedTestRoute, whose
// destructor deletes it unconditionally -- true RAII, not "remember to call
// cleanup", and a deliberate escalation over verify_windows_winn_seam.cpp's
// explicit-Stop()-call style, because a stray route is a materially worse
// outcome than a stray thread. Two things are asserted, not assumed: an
// independent fresh route-table scan after cleanup finds neither synthetic
// route (see AnySyntheticRouteRemains), and a dedicated adversarial test
// creates a route and then deliberately returns WITHOUT releasing it, to
// prove the destructor -- not a caller remembering to clean up -- is what
// saves the routing table on a failure path (see
// ProvesForcedFailureCleansUp). Nothing this program creates outlives it
// under any exit path, including a failed Check().
//
// CREDENTIALS: this program never reads, requests, or prints anything key-
// shaped. The [winn] config it optionally reads (for the Tier A engine-kill
// test) is parsed only through winsvpn::winn::ParseWindowsWinnSection, which
// extracts endpoint/session_id/max_datagram/h1..h4/s1..s4 and nothing
// PrivateKey-shaped -- the same guarantee tools/verify_windows_winn_seam.cpp
// already asserts about the Create document built from it. The Tier B
// status string is exactly what PrivilegedWindowsTunnelRuntimeStatus()
// (windows_tunnel_backend.cpp) returns; that function reads the real AWG
// UAPI response into a buffer it wipes with ScopedStringWipe and returns
// only booleans, byte counts and a Unix timestamp -- never a key -- which is
// why this program prints that string verbatim without redacting it itself.
//
// BUILT BY THE AGENT THAT WROTE THIS FILE; RUN ONLY BY THE OWNER. macOS has
// no MSVC and no Windows SDK, but this repository's session gained a real
// cross-compilation toolchain partway through writing this file: Apple
// clang in `--driver-mode=cl` mode against a genuine, unmodified copy of
// Microsoft's Windows SDK + MSVC CRT headers and import libraries (an
// "xwin"-style checkout under ~/.xwin-sdk). Using that, this file --
// together with the two real, unmodified files it depends on,
// windows/runner/windows_winn_engine.cpp and
// windows/runner/windows_tunnel_service_client.cpp -- WAS ACTUALLY COMPILED
// here, from scratch, individually to object files, under the project's own
// /W4 /WX /EHsc /std:c++17 /DWINS_TUNNEL_SERVICE_CORE=1 flags, against the
// real iphlpapi.h/winsock2.h/tlhelp32.h and the real iphlpapi.lib import
// library, for BOTH x86_64-pc-windows-msvc and aarch64-pc-windows-msvc.
// Every one of those six compiles exited 0 with zero warnings; `file`
// independently confirms genuine "Intel amd64 COFF" and "Aarch64 COFF"
// object files, not placeholders. That is real, verified evidence this file
// (and its two dependencies) are well-formed against the actual Microsoft
// headers, not just self-consistent against a hand-written approximation of
// them, for both architectures this codebase cares about.
//
// BE PRECISE ABOUT THE REMAINING GAP. Two things that compile step did NOT
// reach, and nothing changes that: (1) LINKING. No COFF/PE-capable linker
// (lld-link or otherwise) exists in this environment despite an earlier
// claim that one did -- checked directly, not assumed -- so these objects
// were never linked into a runnable .exe here, and cross-file link errors
// (an unresolved symbol, an ODR mismatch) are exactly the class of problem
// this compile step cannot surface. (2) clang-cl is a close, but not
// byte-identical, approximation of real cl.exe; its warning heuristics can
// differ in edge cases. Your run, via
// tools\verify_windows_winn_elevated.ps1 on the real Windows box with real
// cl.exe and link.exe, is still the first time this file is built by the
// toolchain it actually ships against -- and, obviously, still the first
// time any of it executes, since nothing here can hold administrator rights
// or mutate a routing table. See tools/README_WINDOWS_ELEVATED_VERIFY.md,
// "Honesty about what this is", for the full, precise accounting.

#include "../windows/runner/windows_tunnel_service_client.h"
#include "../windows/runner/windows_winn_engine.h"

// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
// clang-format on

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <cwchar>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_checks = 0;
int g_failures = 0;
int g_skipped = 0;

void Check(bool condition, const std::string& what) {
  ++g_checks;
  if (condition) {
    std::printf("  ok   %s\n", what.c_str());
    return;
  }
  ++g_failures;
  std::printf("  FAIL %s\n", what.c_str());
}

void Skip(const std::string& what, const std::string& why) {
  ++g_skipped;
  std::printf("  skip %s -- %s\n", what.c_str(), why.c_str());
}

std::string ReadWholeFile(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream out;
  out << stream.rdbuf();
  return out.str();
}

// ---------------------------------------------------------------------------
// Elevation.
// ---------------------------------------------------------------------------

// Same AllocateAndInitializeSid/CheckTokenMembership pattern already proven
// in this tree (windows_tunnel_service_main.cpp's pipe-role check), applied
// to this process's own effective token instead of an impersonated one.
bool RunningElevated() {
  BOOL is_admin = FALSE;
  SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
  PSID administrators_sid = nullptr;
  if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &administrators_sid)) {
    CheckTokenMembership(nullptr, administrators_sid, &is_admin);
    FreeSid(administrators_sid);
  }
  return is_admin != FALSE;
}

// ---------------------------------------------------------------------------
// TIER A, part 1: the pinned /32 survives a competing wider route.
// ---------------------------------------------------------------------------

bool SameLuidLocal(const NET_LUID& left, const NET_LUID& right) {
  return left.Value == right.Value;
}

bool SameNextHopLocal(const SOCKADDR_INET& left, const SOCKADDR_INET& right) {
  if (left.si_family != right.si_family) return false;
  if (left.si_family == AF_INET) {
    return left.Ipv4.sin_addr.S_un.S_addr == right.Ipv4.sin_addr.S_un.S_addr;
  }
  return false;  // IPv6 is out of scope here; see the file header.
}

// Mirrors LooksLikeTunnelInterface in windows_split_tunnel.cpp, minus the
// active-tunnel-LUID branch: this program has no tunnel of its own to
// compare against, and the description/type heuristic alone is enough to
// steer this test away from a VPN adapter that happens to already be up.
bool LooksLikeTunnelAdapter(const MIB_IF_ROW2& interface_row) {
  if (interface_row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
      interface_row.Type == IF_TYPE_TUNNEL) {
    return true;
  }
  std::wstring description(interface_row.Description);
  std::transform(description.begin(), description.end(), description.begin(),
                 [](wchar_t value) {
                   return static_cast<wchar_t>(std::towlower(value));
                 });
  for (const wchar_t* marker :
       {L"amnezia", L"wireguard", L"wintun", L" tunnel", L"tap-windows"}) {
    if (description.find(marker) != std::wstring::npos) return true;
  }
  return false;
}

// A trimmed, IPv4-only mirror of FindBestPhysicalDefaultRoute
// (windows_split_tunnel.cpp): same table scan, same OperStatusUp and
// tunnel-adapter exclusion, same lowest-effective-metric selection.
bool FindPhysicalDefaultRouteV4(MIB_IPFORWARD_ROW2* best_route,
                                std::string* error) {
  PMIB_IPFORWARD_TABLE2 table = nullptr;
  if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR || table == nullptr) {
    *error = "GetIpForwardTable2 failed.";
    return false;
  }
  bool found = false;
  uint64_t best_metric = ~uint64_t{0};
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const MIB_IPFORWARD_ROW2& route = table->Table[i];
    if (route.DestinationPrefix.PrefixLength != 0 || route.Loopback ||
        route.NextHop.Ipv4.sin_family != AF_INET ||
        route.NextHop.Ipv4.sin_addr.S_un.S_addr == 0) {
      continue;
    }
    MIB_IF_ROW2 interface_row = {};
    interface_row.InterfaceLuid = route.InterfaceLuid;
    interface_row.InterfaceIndex = route.InterfaceIndex;
    if (GetIfEntry2(&interface_row) != NO_ERROR ||
        interface_row.OperStatus != IfOperStatusUp ||
        LooksLikeTunnelAdapter(interface_row)) {
      continue;
    }
    MIB_IPINTERFACE_ROW ip_interface = {};
    InitializeIpInterfaceEntry(&ip_interface);
    ip_interface.Family = AF_INET;
    ip_interface.InterfaceLuid = route.InterfaceLuid;
    ip_interface.InterfaceIndex = route.InterfaceIndex;
    if (GetIpInterfaceEntry(&ip_interface) != NO_ERROR) continue;
    const uint64_t effective_metric =
        static_cast<uint64_t>(route.Metric) + ip_interface.Metric;
    if (!found || effective_metric < best_metric) {
      *best_route = route;
      best_metric = effective_metric;
      found = true;
    }
  }
  FreeMibTable(table);
  if (!found) {
    *error =
        "No active physical network connection with a default route was "
        "found. Connect to Wi-Fi or Ethernet (and disconnect any existing "
        "VPN) and re-run.";
  }
  return found;
}

// Every Windows install carries at least one Loopback-flagged row in its
// IPv4 forwarding table unconditionally (the Loopback Pseudo-Interface).
// Reading its LUID off that row reuses fields this file already relies on
// elsewhere (MIB_IPFORWARD_ROW2::Loopback, ::InterfaceLuid) instead of
// trusting an additional, separately-sourced struct field.
bool FindLoopbackLuid(NET_LUID* luid) {
  PMIB_IPFORWARD_TABLE2 table = nullptr;
  if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR || table == nullptr) {
    return false;
  }
  bool found = false;
  for (ULONG i = 0; i < table->NumEntries && !found; ++i) {
    if (table->Table[i].Loopback) {
      *luid = table->Table[i].InterfaceLuid;
      found = true;
    }
  }
  FreeMibTable(table);
  return found;
}

// RFC 5737 TEST-NET-3. Reserved for documentation; guaranteed never to carry
// real traffic, so a mistake here cannot touch the owner's real routing.
constexpr char kSyntheticCarrierIPv4[] = "203.0.113.113";
constexpr char kSyntheticWidePrefixIPv4[] = "203.0.113.0";
constexpr uint8_t kSyntheticWidePrefixLength = 24;

// True RAII: a route this program created is removed in the destructor no
// matter how the enclosing scope is left. ReleaseAndVerify() is also callable
// explicitly so the pass/fail of a clean release is itself a counted Check(),
// not just a best-effort side effect nobody looks at.
class OwnedTestRoute {
 public:
  OwnedTestRoute() = default;
  OwnedTestRoute(const OwnedTestRoute&) = delete;
  OwnedTestRoute& operator=(const OwnedTestRoute&) = delete;
  ~OwnedTestRoute() { ReleaseAndVerify(); }

  // Field-for-field identical to CreateOwnedRoute in
  // windows_split_tunnel.cpp: same lifetimes, same MIB_IPPROTO_NETMGMT
  // protocol tag, same false/false/false/false tail. See the file header for
  // why this calls CreateIpForwardEntry2 directly rather than that function.
  bool Create(const IP_ADDRESS_PREFIX& prefix, const NET_LUID& luid,
              const SOCKADDR_INET& next_hop, std::string* error,
              DWORD* out_status = nullptr) {
    row_ = {};
    InitializeIpForwardEntry(&row_);
    row_.DestinationPrefix = prefix;
    row_.InterfaceLuid = luid;
    row_.NextHop = next_hop;
    row_.ValidLifetime = 0xffffffff;
    row_.PreferredLifetime = 0xffffffff;
    row_.Metric = 0;
    row_.Protocol = MIB_IPPROTO_NETMGMT;
    row_.Loopback = false;
    row_.AutoconfigureAddress = false;
    row_.Publish = false;
    row_.Immortal = false;
    const DWORD status = CreateIpForwardEntry2(&row_);
    if (out_status != nullptr) *out_status = status;
    if (status != NO_ERROR) {
      if (error != nullptr) {
        *error = "CreateIpForwardEntry2 failed (Win32 error " +
                 std::to_string(status) + ")";
      }
      created_ = false;
      return false;
    }
    created_ = true;
    return true;
  }

  bool created() const { return created_; }
  const MIB_IPFORWARD_ROW2& row() const { return row_; }

  bool ReleaseAndVerify() {
    if (!created_) return true;
    const DWORD status = DeleteIpForwardEntry2(&row_);
    created_ = false;
    return status == NO_ERROR || status == ERROR_NOT_FOUND ||
           status == ERROR_FILE_NOT_FOUND;
  }

 private:
  MIB_IPFORWARD_ROW2 row_{};
  bool created_ = false;
};

// Independent proof that cleanup actually happened: re-reads the live table
// rather than trusting DeleteIpForwardEntry2's return code alone. Fails
// closed -- an unreadable table counts as "not proven clean", never as pass.
bool AnySyntheticRouteRemains() {
  PMIB_IPFORWARD_TABLE2 table = nullptr;
  if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR || table == nullptr) {
    return true;
  }
  IN_ADDR carrier_addr = {};
  IN_ADDR wide_addr = {};
  InetPtonA(AF_INET, kSyntheticCarrierIPv4, &carrier_addr);
  InetPtonA(AF_INET, kSyntheticWidePrefixIPv4, &wide_addr);
  bool found = false;
  for (ULONG i = 0; i < table->NumEntries && !found; ++i) {
    const IP_ADDRESS_PREFIX& prefix = table->Table[i].DestinationPrefix;
    if (prefix.Prefix.si_family != AF_INET) continue;
    if (prefix.PrefixLength == 32 &&
        prefix.Prefix.Ipv4.sin_addr.S_un.S_addr ==
            carrier_addr.S_un.S_addr) {
      found = true;
    }
    if (prefix.PrefixLength == kSyntheticWidePrefixLength &&
        prefix.Prefix.Ipv4.sin_addr.S_un.S_addr == wide_addr.S_un.S_addr) {
      found = true;
    }
  }
  FreeMibTable(table);
  return found;
}

// The adversarial cleanup proof required by the task brief: creates a route
// and then deliberately returns WITHOUT calling ReleaseAndVerify(), the way
// a real caller would on some later, unrelated failure. Only
// ~OwnedTestRoute() firing during stack unwind is allowed to save the
// routing table here.
bool ProvesForcedFailureCleansUp(const MIB_IPFORWARD_ROW2& physical) {
  {
    OwnedTestRoute doomed;
    std::string ignored_error;
    IN_ADDR addr = {};
    InetPtonA(AF_INET, kSyntheticCarrierIPv4, &addr);
    IP_ADDRESS_PREFIX prefix = {};
    prefix.Prefix.Ipv4.sin_family = AF_INET;
    prefix.Prefix.Ipv4.sin_addr = addr;
    prefix.PrefixLength = 32;
    if (!doomed.Create(prefix, physical.InterfaceLuid, physical.NextHop,
                       &ignored_error)) {
      return false;  // Could not even stage the scenario; not proven either way.
    }
    // No ReleaseAndVerify() call here. This is the point.
  }
  return !AnySyntheticRouteRemains();
}

void RunRouteSurvivalTierA() {
  std::printf(
      "== TIER A: a pinned /32 host route survives a competing wider route "
      "==\n");
  std::printf(
      "   Mirrors CreateOwnedCarrierRoute / VerifyCommittedWindowsTunnelRoutes "
      "in\n   windows/runner/windows_split_tunnel.cpp. See this file's header "
      "comment\n   for exactly what that does and does not prove.\n");

  std::string error;
  MIB_IPFORWARD_ROW2 physical = {};
  if (!FindPhysicalDefaultRouteV4(&physical, &error)) {
    Check(false, "find the current physical IPv4 default route: " + error);
    Skip("the rest of the route-pin test",
         "no physical default route to pin against");
    return;
  }
  Check(true, "found a physical IPv4 default route to pin the synthetic "
              "carrier against");

  IN_ADDR carrier_addr = {};
  InetPtonA(AF_INET, kSyntheticCarrierIPv4, &carrier_addr);
  IP_ADDRESS_PREFIX carrier_prefix = {};
  carrier_prefix.Prefix.Ipv4.sin_family = AF_INET;
  carrier_prefix.Prefix.Ipv4.sin_addr = carrier_addr;
  carrier_prefix.PrefixLength = 32;
  SOCKADDR_INET carrier_destination = {};
  carrier_destination.Ipv4.sin_family = AF_INET;
  carrier_destination.Ipv4.sin_addr = carrier_addr;

  OwnedTestRoute carrier_pin;
  if (!carrier_pin.Create(carrier_prefix, physical.InterfaceLuid,
                          physical.NextHop, &error)) {
    Check(false,
          "pin a synthetic carrier /32 (" +
              std::string(kSyntheticCarrierIPv4) +
              ") on the physical LUID, exactly as PrepareWindowsAppExclusions "
              "pins [winn] endpoint: " +
              error);
    Skip("the rest of the route-pin test",
         "the initial pin itself failed, nothing else to test");
    return;
  }
  Check(true,
        "pinned a synthetic carrier /32 on the physical LUID, mirroring "
        "PrepareWindowsAppExclusions' pin of [winn] endpoint (NOT [Peer] "
        "Endpoint -- see windows_winn_engine.h's header comment on why)");

  {
    MIB_IPFORWARD_ROW2 selected = {};
    SOCKADDR_INET source = {};
    const bool baseline_ok =
        GetBestRoute2(nullptr, 0, nullptr, &carrier_destination, 0, &selected,
                      &source) == NO_ERROR &&
        selected.DestinationPrefix.PrefixLength == 32 &&
        SameLuidLocal(selected.InterfaceLuid, physical.InterfaceLuid);
    Check(baseline_ok,
          "GetBestRoute2 resolves the pin BEFORE any competing route exists "
          "(baseline, isolates a pre-existing problem from one caused by the "
          "competing route below)");
  }

  NET_LUID loopback_luid = {};
  const bool have_loopback = FindLoopbackLuid(&loopback_luid);
  Check(have_loopback,
        "found the loopback pseudo-interface to carry the harmless stand-in "
        "wide route");

  IN_ADDR wide_addr = {};
  InetPtonA(AF_INET, kSyntheticWidePrefixIPv4, &wide_addr);
  IP_ADDRESS_PREFIX wide_prefix = {};
  wide_prefix.Prefix.Ipv4.sin_family = AF_INET;
  wide_prefix.Prefix.Ipv4.sin_addr = wide_addr;
  wide_prefix.PrefixLength = kSyntheticWidePrefixLength;

  OwnedTestRoute wide_competitor;
  if (have_loopback) {
    SOCKADDR_INET on_link_next_hop = {};
    on_link_next_hop.si_family = AF_INET;
    Check(wide_competitor.Create(wide_prefix, loopback_luid, on_link_next_hop,
                                 &error),
          "add a wide /" + std::to_string(kSyntheticWidePrefixLength) +
              " route covering the same address, confined to TEST-NET-3 and "
              "the loopback interface -- stands in for the tunnel's own "
              "0.0.0.0/0 without ever creating one: " +
              error);
  } else {
    Skip("add the wide competing route", "no loopback LUID to carry it");
  }

  if (wide_competitor.created()) {
    MIB_IPFORWARD_ROW2 selected = {};
    SOCKADDR_INET source = {};
    const DWORD status = GetBestRoute2(nullptr, 0, nullptr,
                                       &carrier_destination, 0, &selected,
                                       &source);
    const bool still_pinned =
        status == NO_ERROR && selected.DestinationPrefix.PrefixLength == 32 &&
        SameLuidLocal(selected.InterfaceLuid, physical.InterfaceLuid) &&
        SameNextHopLocal(selected.NextHop, physical.NextHop);
    Check(still_pinned,
          "THE CORE CLAIM (item 1): GetBestRoute2 still resolves the "
          "physical /32 after a wider route was added -- it did not \"escape "
          "its captured physical /32 route\" (production's own words for "
          "this failure, windows_split_tunnel.cpp)");
  } else {
    Skip("THE CORE CLAIM (item 1)",
         "the competing wide route was never created, see the FAIL above");
  }

  {
    OwnedTestRoute duplicate;
    std::string duplicate_error;
    DWORD duplicate_status = NO_ERROR;
    const bool duplicate_created =
        duplicate.Create(carrier_prefix, physical.InterfaceLuid,
                         physical.NextHop, &duplicate_error,
                         &duplicate_status);
    Check(!duplicate_created && duplicate_status == ERROR_OBJECT_ALREADY_EXISTS,
          "creating the IDENTICAL /32 a second time is refused with "
          "ERROR_OBJECT_ALREADY_EXISTS, matching CreateOwnedRoute's own "
          "handling of that status (\"Refusing to trust a matching tunnel "
          "route not owned by this session.\")");
    Check(!duplicate.created(),
          "the refused duplicate does not believe it owns anything, so its "
          "destructor will not try to delete the route this program actually "
          "created");
    MIB_IPFORWARD_ROW2 selected = {};
    SOCKADDR_INET source = {};
    Check(GetBestRoute2(nullptr, 0, nullptr, &carrier_destination, 0,
                        &selected, &source) == NO_ERROR &&
              selected.DestinationPrefix.PrefixLength == 32,
          "the original pin is untouched after the refused duplicate "
          "attempt");
  }

  // Explicit, checked cleanup -- LIFO, wide route first (created second).
  Check(wide_competitor.ReleaseAndVerify(),
        "cleanup: the wide competing route was removed");
  Check(carrier_pin.ReleaseAndVerify(),
        "cleanup: the synthetic carrier /32 was removed");
  Check(!AnySyntheticRouteRemains(),
        "cleanup PROOF: a fresh route-table scan finds neither synthetic "
        "route (203.0.113.113/32 or 203.0.113.0/24) anywhere");
  Check(ProvesForcedFailureCleansUp(physical),
        "cleanup ON A FORCED FAILURE PATH: a helper that creates a route and "
        "then returns early WITHOUT releasing it still leaves nothing "
        "behind, because ~OwnedTestRoute() ran during stack unwind");
}

// ---------------------------------------------------------------------------
// TIER A, part 2: killing the real engine mid-session is noticed.
// ---------------------------------------------------------------------------

std::wstring CanonicalPathLocal(const std::wstring& raw) {
  if (raw.empty() || raw.size() >= 32768) return L"";
  wchar_t full[32768] = {};
  const DWORD size = GetFullPathNameW(raw.c_str(), _countof(full), full,
                                      nullptr);
  if (size == 0 || size >= _countof(full)) return L"";
  const DWORD attrs = GetFileAttributesW(full);
  if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    return L"";
  }
  return std::wstring(full, size);
}

// Finds the running process whose full image path matches canonical_path.
// Requires EXACTLY one match and refuses to guess when there are zero or
// more than one -- this is about to be handed to TerminateProcess, so an
// ambiguous match is a hard stop, not a best-effort pick.
bool FindUniqueRunningProcessByPath(const std::wstring& canonical_path,
                                    DWORD* pid, std::string* error) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    *error = "CreateToolhelp32Snapshot failed.";
    return false;
  }
  PROCESSENTRY32W entry = {};
  entry.dwSize = sizeof(entry);
  std::vector<DWORD> matches;
  if (Process32FirstW(snapshot, &entry)) {
    do {
      HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                   entry.th32ProcessID);
      if (process == nullptr) continue;
      wchar_t image[32768] = {};
      DWORD size = _countof(image);
      const bool queried =
          QueryFullProcessImageNameW(process, 0, image, &size) != 0;
      CloseHandle(process);
      if (!queried) continue;
      if (_wcsicmp(image, canonical_path.c_str()) == 0) {
        matches.push_back(entry.th32ProcessID);
      }
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  if (matches.size() != 1) {
    *error = "expected exactly one running process matching the engine path, "
             "found " +
             std::to_string(matches.size()) +
             " -- close any other winn-datapath.exe and re-run";
    return false;
  }
  *pid = matches.front();
  return true;
}

void RunEngineKillTierA(const std::string& config_path_arg,
                        const std::string& engine_path_arg) {
  std::printf(
      "== TIER A: killing the REAL winn-datapath.exe mid-session is noticed "
      "==\n");
  std::printf(
      "   This proves the process-liveness half of what IsTunnelRunning() "
      "depends\n   on -- WindowsWinnEngineRunning() in "
      "windows/runner/windows_winn_engine.cpp.\n   It does NOT run "
      "IsTunnelRunning() itself: that function also needs\n   "
      "g_winn_tunnel_active and IsWinsAwgEngineRunning, both only set by the "
      "full\n   privileged service running a real AmneziaWG session -- that "
      "is Tier B.\n");

  const std::string config = ReadWholeFile(config_path_arg);
  if (config.empty()) {
    Skip("engine-kill test", "could not read " + config_path_arg);
    return;
  }
  winsvpn::winn::WindowsWinnParams params;
  std::string parse_error;
  if (!winsvpn::winn::ParseWindowsWinnSection(config, &params, &parse_error)) {
    Skip("engine-kill test",
         "the config's [winn] section did not parse: " + parse_error);
    return;
  }

  const std::wstring engine_path(engine_path_arg.begin(),
                                 engine_path_arg.end());
  const std::wstring canonical_engine_path = CanonicalPathLocal(engine_path);
  if (canonical_engine_path.empty()) {
    Skip("engine-kill test", engine_path_arg + " does not exist");
    return;
  }

  WSADATA wsa = {};
  WSAStartup(MAKEWORD(2, 2), &wsa);
  struct WinsockGuard {
    ~WinsockGuard() { WSACleanup(); }
  } winsock_guard;
  // StopWindowsWinnEngine() is documented safe to call when nothing is
  // running, so unconditionally calling it once more on every exit path --
  // including every early `return` below -- is a correct, idempotent
  // finally-block, not a special case for the success path only.
  struct EngineGuard {
    ~EngineGuard() { winsvpn::winn::StopWindowsWinnEngine(); }
  } engine_guard;

  uint16_t seam_port = 0;
  std::string error;
  const uintptr_t seam =
      winsvpn::winn::BindWindowsWinnSeam(&seam_port, &error);
  Check(seam != winsvpn::winn::kInvalidWinnSeam,
        "the loopback seam binds for the engine-kill test: " + error);
  if (seam == winsvpn::winn::kInvalidWinnSeam) return;

  const bool started =
      winsvpn::winn::StartWindowsWinnEngine(engine_path, seam, params, &error);
  Check(started,
        "the real winn-datapath.exe acknowledged Create: " + error);
  if (!started) return;
  Check(winsvpn::winn::WindowsWinnEngineRunning(),
        "WindowsWinnEngineRunning() is true right after start");

  DWORD pid = 0;
  const bool found_unique =
      FindUniqueRunningProcessByPath(canonical_engine_path, &pid, &error);
  Check(found_unique,
        "found exactly one running process matching the engine path to "
        "kill: " +
            error);
  if (!found_unique) return;

  HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  Check(process != nullptr, "opened the engine process for termination");
  if (process == nullptr) return;
  const bool terminated = TerminateProcess(process, 1) != 0;
  CloseHandle(process);
  Check(terminated,
        "TerminateProcess on the real winn-datapath.exe succeeded "
        "(simulating it dying out from under the host, NOT a clean "
        "StopWindowsWinnEngine)");

  bool noticed = false;
  for (int attempt = 0; attempt < 40 && !noticed; ++attempt) {
    if (!winsvpn::winn::WindowsWinnEngineRunning()) {
      noticed = true;
    } else {
      Sleep(250);
    }
  }
  Check(noticed,
        "WindowsWinnEngineRunning() goes false within 10s of the process "
        "dying, with StopWindowsWinnEngine never having been called -- this "
        "is the exact correction .winn_platform_progress/windows.json "
        "records: \"IsTunnelRunning no longer accepts AWG presence as "
        "proof\" / \"channel liveness AND process liveness, never process "
        "existence alone\"");
  Check(winsvpn::winn::WindowsWinnEngineStatusJson().empty(),
        "no status is reported once the process is gone");
  Check(!winsvpn::winn::WindowsWinnTransportObservedBothWays(nullptr),
        "the promotion gate answers false, never stale-true, after the "
        "kill");
}

// ---------------------------------------------------------------------------
// TIER B: read-only status probe against an ALREADY-CONNECTED real tunnel.
// ---------------------------------------------------------------------------

void RunStatusProbeTierB() {
  std::printf(
      "== TIER B: live status probe (read-only; needs a REAL winn/3 tunnel "
      "already\n   connected through the app against a real AmneziaWG "
      "gateway) ==\n");
  std::printf(
      "   This calls QueryWindowsTunnelManager, the exact kStatus request "
      "the\n   shipping app itself sends. It never starts, stops or changes "
      "anything.\n");

  std::string status;
  std::string error;
  if (!QueryWindowsTunnelManager(&status, &error)) {
    Skip("TIER B status probe",
         "could not reach the WinsVpnTunnelManager service: " + error +
             " (expected if it is not installed, not running, or nothing is "
             "connected yet -- this is not a Tier A/B failure)");
    return;
  }
  std::printf("     raw kStatus response: %s\n", status.c_str());
  if (status.find("winn=1") == std::string::npos) {
    Skip("TIER B status probe",
         "winn=1 not present -- no winn/3 tunnel is active right now. "
         "Connect through the app with a real [winn] enabled=true config "
         "against a real AmneziaWG gateway, then re-run this program while "
         "it stays connected.");
    return;
  }
  Check(status.find("winn_engine=1") != std::string::npos,
        "TIER B (item 4, in full): the privileged service reports "
        "winn_engine=1 -- WindowsWinnEngineRunning() is true INSIDE the "
        "real elevated service, not just in this standalone process");
  Check(status.find("winn_transport=1") != std::string::npos,
        "TIER B (item 3, second half): the privileged service reports "
        "winn_transport=1 -- transport_observed_both_ways has latched");
}

}  // namespace

int main(int argc, char** argv) {
  // Unbuffered for the same reason as verify_windows_winn_seam.cpp: this
  // owns route-table mutations and a subprocess, so a redirected log has to
  // show exactly where it stopped without a debugger attached.
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);

  std::printf(
      "verify_windows_winn_elevated -- TIER A (admin, no gateway) and TIER "
      "B (admin\n+ a real AmneziaWG gateway) checks for the four items "
      "tools/verify_windows_winn_seam.cpp\ncannot reach. Read "
      "tools/README_WINDOWS_ELEVATED_VERIFY.md first.\n\n");

  if (!RunningElevated()) {
    std::fprintf(
        stderr,
        "FAIL: this process is not running elevated. Every Tier A check "
        "needs\nadministrator rights to change the routing table.\n\nClose "
        "this window. Open the Start menu, right-click \"Windows "
        "Terminal\"\nor \"PowerShell\", choose \"Run as administrator\", cd "
        "back into this\nrepository, and re-run "
        "tools\\verify_windows_winn_elevated.ps1.\n");
    return 2;
  }
  std::printf("ok   running elevated\n\n");

  if (argc != 1 && argc != 3) {
    std::fprintf(
        stderr,
        "usage: verify_windows_winn_elevated [<config.ini> "
        "<winn-datapath.exe>]\n  no arguments:  TIER A route-pin test "
        "only\n  two arguments: TIER A route-pin test AND the engine-kill "
        "test\nTIER B's status probe always runs last and needs no "
        "arguments.\n");
    return 2;
  }

  RunRouteSurvivalTierA();
  std::printf("\n");
  if (argc == 3) {
    RunEngineKillTierA(argv[1], argv[2]);
  } else {
    Skip("TIER A engine-kill test",
         "no <config.ini> <winn-datapath.exe> given on the command line -- "
         "pass both to also run it");
  }
  std::printf("\n");
  RunStatusProbeTierB();

  std::printf("\n%d/%d checks passed, %d failed, %d skipped\n",
              g_checks - g_failures, g_checks, g_failures, g_skipped);
  return g_failures == 0 ? 0 : 1;
}
