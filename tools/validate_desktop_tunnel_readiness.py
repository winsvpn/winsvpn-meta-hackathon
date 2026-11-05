#!/usr/bin/env python3
"""Fail-closed source contract for native VPN connectivity proof."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

LINUX_V1_TUNNEL_INTERFACE = "winsvpn"
LINUX_V3_TUNNEL_INTERFACE = "winsvpn3"
LINUX_TUNNEL_INTERFACE_BY_PROTOCOL = {
    "v1": LINUX_V1_TUNNEL_INTERFACE,
    "v3": LINUX_V3_TUNNEL_INTERFACE,
}
LINUX_ALLOWED_TUNNEL_INTERFACES = frozenset(
    LINUX_TUNNEL_INTERFACE_BY_PROTOCOL.values()
)
LINUX_V1_INTERFACE_CONSTANT = "kTunnelName"
LINUX_V3_INTERFACE_CONSTANT = "kLinuxWinn3InterfaceName"
LINUX_ROUTE_PROBE_PROTOCOL_EVIDENCE = "LinuxWinn3StandaloneSessionWasStarted()"
LINUX_PROBE_INTERNET_START = "FlValue* ProbeInternetValue() {"
LINUX_PROBE_INTERNET_END = (
    "\nbool WinnDatapathIsCarrying(const std::string& status) {"
)
LINUX_ROUTE_PROBE_PATTERN_TERNARY = (
    'v3 ? " dev winsvpn3( |$)" : " dev winsvpn( |$)"'
)
LINUX_ROUTE_PROBE_INTERFACE_TERNARY = (
    "v3 ? winsvpn::winn3host::kLinuxWinn3InterfaceName : kTunnelName"
)
LINUX_LOOSE_ROUTE_PROBE_NEEDLES = (
    (
        "dev winsvpn.*",
        "Linux route probe must not use a prefix regex",
    ),
    (
        "winsvpn(3)?",
        "Linux route probe must not use an optional-digit regex that accepts both names",
    ),
    (
        "winsvpn(3|)",
        "Linux route probe must not use an unbound alternation for the interface name",
    ),
    (
        "ip route get 1.1.1.1 | grep -Eq ' dev winsvpn( |$)'",
        "Linux route probe must not hardcode only the v1 interface",
    ),
    (
        "curl -fsS --max-time 4 --interface winsvpn",
        "Linux internet probe must not hardcode only the v1 interface",
    ),
)
WINDOWS_TUNNEL_INTERFACE_PROBE_START = (
    "bool TunnelInterfaceIpv4(IN_ADDR* address, NET_IFINDEX* interface_index) {"
)
WINDOWS_TUNNEL_INTERFACE_PROBE_END = "\nbool WaitForSocketReady("


def require(source: str, needle: str, message: str) -> None:
    if needle not in source:
        raise SystemExit(f"desktop tunnel readiness validation failed: {message}")


def forbid(source: str, needle: str, message: str) -> None:
    if needle in source:
        raise SystemExit(f"desktop tunnel readiness validation failed: {message}")


def require_order(source: str, first: str, second: str, message: str) -> None:
    first_index = source.find(first)
    second_index = source.find(second, first_index + len(first))
    if first_index < 0 or second_index < 0 or first_index >= second_index:
        raise SystemExit(f"desktop tunnel readiness validation failed: {message}")


def linux_tunnel_interface_for_protocol(protocol: str) -> str:
    try:
        return LINUX_TUNNEL_INTERFACE_BY_PROTOCOL[protocol]
    except KeyError as exc:
        raise ValueError(
            f"unsupported Linux tunnel protocol: {protocol!r}"
        ) from exc


def linux_route_probe_ere(interface: str) -> str:
    if interface not in LINUX_ALLOWED_TUNNEL_INTERFACES:
        raise ValueError(f"unsupported Linux tunnel interface: {interface!r}")
    # grep -E: the space-or-end terminator rejects winsvpn-attacker and
    # similarly prefixed names such as winsvpn3 when the selected name is
    # winsvpn.
    return f" dev {interface}( |$)"


def linux_route_probe_ere_for_protocol(protocol: str) -> str:
    return linux_route_probe_ere(linux_tunnel_interface_for_protocol(protocol))


def linux_route_uses_intended_interface(route_text: str, protocol: str) -> bool:
    pattern = linux_route_probe_ere_for_protocol(protocol)
    return re.search(pattern, route_text, flags=re.MULTILINE) is not None


def linux_probe_internet_source(linux: str) -> str:
    start = linux.find(LINUX_PROBE_INTERNET_START)
    if start < 0:
        raise SystemExit(
            "desktop tunnel readiness validation failed: Linux ProbeInternetValue is missing"
        )
    end = linux.find(LINUX_PROBE_INTERNET_END, start)
    if end < 0:
        raise SystemExit(
            "desktop tunnel readiness validation failed: Linux ProbeInternetValue is unbounded"
        )
    return linux[start:end]


def validate_linux_route_probe_contract(probe_source: str) -> None:
    require(
        probe_source,
        LINUX_ROUTE_PROBE_PROTOCOL_EVIDENCE,
        "Linux route probe must select the interface from Winn v3 session evidence",
    )
    require(
        probe_source,
        LINUX_ROUTE_PROBE_INTERFACE_TERNARY,
        "Linux route probe must bind the selected interface to protocol evidence",
    )
    require(
        probe_source,
        LINUX_ROUTE_PROBE_PATTERN_TERNARY,
        "Linux route probe must match exactly v1 winsvpn or v3 winsvpn3",
    )
    require(
        probe_source,
        linux_route_probe_ere_for_protocol("v1"),
        "Linux v1 route probe must use the exact winsvpn interface ERE",
    )
    require(
        probe_source,
        linux_route_probe_ere_for_protocol("v3"),
        "Linux v3 route probe must use the exact winsvpn3 interface ERE",
    )
    require(
        probe_source,
        '"ip route get 1.1.1.1 2>/dev/null | grep -Eq \\"$1\\""',
        "Linux route probe must apply the protocol-selected interface ERE",
    )
    require(
        probe_source,
        '"winsvpn-net-check", {tun}',
        "Linux internet probe must pass the protocol-selected interface as an argv entry",
    )
    require(
        probe_source,
        '"curl -fsS --max-time 4 --interface \\"$1\\" "',
        "Linux internet probe must bind curl to the protocol-selected interface",
    )
    require_order(
        probe_source,
        LINUX_ROUTE_PROBE_PROTOCOL_EVIDENCE,
        LINUX_V3_INTERFACE_CONSTANT,
        "Linux v3 interface selection must follow protocol evidence",
    )
    require_order(
        probe_source,
        LINUX_ROUTE_PROBE_PROTOCOL_EVIDENCE,
        LINUX_V1_INTERFACE_CONSTANT,
        "Linux v1 interface selection must follow protocol evidence",
    )
    require_order(
        probe_source,
        LINUX_ROUTE_PROBE_PROTOCOL_EVIDENCE,
        LINUX_ROUTE_PROBE_PATTERN_TERNARY,
        "Linux route-probe ERE must follow protocol evidence",
    )
    require_order(
        probe_source,
        LINUX_ROUTE_PROBE_INTERFACE_TERNARY,
        '"winsvpn-net-check", {tun}',
        "Linux curl bind must use the protocol-selected interface",
    )
    for needle, message in LINUX_LOOSE_ROUTE_PROBE_NEEDLES:
        forbid(probe_source, needle, message)


def validate_linux_no_shell_composition(linux_source: str) -> None:
    """B-APP-004 regression pin: the Linux backend must never compose a shell
    command STRING out of dynamic values again.

    The 2026-08-28 argv-form rewrite (RunArgv / RunShScript) removed
    ShellQuote/RunCommand/CommandOutput/CommandSucceeds and every popen and
    std::system call site. A single reintroduced helper would quietly reopen
    the entire injection surface, so the primitives are required and the
    shell-composition helpers are forbidden, on the full backend source.
    """
    require(
        linux_source,
        "ProcResult RunArgv(",
        "Linux backend must define the argv-form process helper RunArgv",
    )
    require(
        linux_source,
        "ProcResult RunShScript(",
        "Linux backend must define the literal-script helper RunShScript",
    )
    for needle, message in (
        (
            "ShellQuote(",
            "Linux backend must not reintroduce ShellQuote: dynamic values "
            "cross as argv entries, never as quoted shell text (B-APP-004)",
        ),
        (
            "popen(",
            "Linux backend must not reintroduce popen: use RunArgv / "
            "RunShScript so no shell re-parses a composed command string",
        ),
        (
            "std::system(",
            "Linux backend must not reintroduce std::system: use RunArgv / "
            "RunShScript so no shell re-parses a composed command string",
        ),
    ):
        forbid(linux_source, needle, message)


def validate_linux_tunnel_interface_evidence(
    linux_source: str, winn3_header: str
) -> None:
    require(
        linux_source,
        (
            f'constexpr char {LINUX_V1_INTERFACE_CONSTANT}[] = '
            f'"{LINUX_V1_TUNNEL_INTERFACE}";'
        ),
        "Linux v1 tunnel interface evidence must be exactly winsvpn",
    )
    require(
        winn3_header,
        (
            f"inline constexpr char {LINUX_V3_INTERFACE_CONSTANT}[] = "
            f'"{LINUX_V3_TUNNEL_INTERFACE}";'
        ),
        "Linux v3 tunnel interface evidence must be exactly winsvpn3",
    )
    validate_linux_route_probe_contract(linux_probe_internet_source(linux_source))
    validate_linux_no_shell_composition(linux_source)


def windows_tunnel_interface_probe_source(windows: str) -> str:
    start = windows.find(WINDOWS_TUNNEL_INTERFACE_PROBE_START)
    if start < 0:
        raise SystemExit(
            "desktop tunnel readiness validation failed: Windows tunnel interface probe is missing"
        )
    end = windows.find(WINDOWS_TUNNEL_INTERFACE_PROBE_END, start)
    if end < 0:
        raise SystemExit(
            "desktop tunnel readiness validation failed: Windows tunnel interface probe is unbounded"
        )
    return windows[start:end]


def validate_windows_tunnel_interface_probe_contract(probe_source: str) -> None:
    for status_key in ("winn3", "winn3_datapath", "winn3_promoted", "winn"):
        require(
            probe_source,
            f'ParseTunnelManagerUnsigned(manager_status, "{status_key}",',
            f"Windows tunnel probe must bind manager status key {status_key}",
        )
    require(
        probe_source,
        "IsExpectedCommittedManagerStatus(manager_status)",
        "Windows v1 probe evidence must require committed manager status",
    )
    for field in ("v3_active", "v3_running", "v3_promoted", "v1_running"):
        require(
            probe_source,
            f"snapshot.{field} =",
            f"Windows tunnel probe snapshot must bind {field}",
        )
    require(
        probe_source,
        "ClassifyWindowsTunnelProbeAlias(",
        "Windows tunnel probe must classify the v3 or v1 adapter from runtime proof",
    )
    require(
        probe_source,
        "WindowsTunnelProbeAlias::kRefuse",
        "Windows tunnel probe must fail closed on ambiguous adapter proof",
    )
    require(
        probe_source,
        "WindowsTunnelProbeAliasName(alias)",
        "Windows tunnel probe must derive the adapter alias from the classification",
    )
    require(
        probe_source,
        "ConvertInterfaceAliasToLuid(alias_wide.c_str(), &tunnel_luid)",
        "Windows tunnel probe must resolve the classified adapter alias",
    )
    forbid(
        probe_source,
        "ConvertInterfaceAliasToLuid(kTunnelName",
        "Windows tunnel probe must not hardcode the v1 adapter for Winn v3",
    )
    require(
        probe_source,
        "GetUnicastIpAddressTable(AF_INET, &table)",
        "Windows tunnel probe must enumerate IPv4 addresses for the classified adapter",
    )
    require(
        probe_source,
        "row.InterfaceLuid.Value != tunnel_luid.Value",
        "Windows tunnel probe must bind the address to the classified adapter LUID",
    )
    require(
        probe_source,
        "row.DadState != IpDadStatePreferred",
        "Windows tunnel probe must require a preferred interface address",
    )
    require_order(
        probe_source,
        "ClassifyWindowsTunnelProbeAlias(",
        "ConvertInterfaceAliasToLuid(alias_wide.c_str(), &tunnel_luid)",
        "Windows adapter classification must precede interface resolution",
    )


def without_if_zero_blocks(source: str) -> str:
    """Return the source that can reach the compiler with hard #if 0 blocks removed."""
    output: list[str] = []
    disabled_depth = 0
    for line in source.splitlines(keepends=True):
        directive = line.lstrip()
        if disabled_depth:
            if directive.startswith("#if"):
                disabled_depth += 1
            elif directive.startswith("#endif"):
                disabled_depth -= 1
            continue
        if directive.startswith("#if 0"):
            disabled_depth = 1
            continue
        output.append(line)
    if disabled_depth:
        raise SystemExit(
            "desktop tunnel readiness validation failed: unterminated #if 0 block"
        )
    return "".join(output)


# Helpers end. Remaining statements are the source contract.
windows = (ROOT / "windows/runner/windows_tunnel_backend.cpp").read_text(
    encoding="utf-8"
)
windows_split = (ROOT / "windows/runner/windows_split_tunnel.cpp").read_text(
    encoding="utf-8"
)
windows_split_active = without_if_zero_blocks(windows_split)
windows_service = (
    ROOT / "windows/runner/windows_tunnel_service_main.cpp"
).read_text(encoding="utf-8")
require(
    windows_service,
    "SERVICE_DELAYED_AUTO_START_INFO delayed = {FALSE};",
    "Windows tunnel manager must be available before an auto-starting GUI can connect after sign-in",
)
require_order(
    windows_split,
    "WSAStartup(MAKEWORD(2, 2)",
    "GetAddrInfoW",
    "Windows split routing must initialize Winsock before resolving the physical interface",
)
require_order(
    windows_split,
    "FreeAddrInfoW(result);",
    "WSACleanup();",
    "Windows split routing must release Winsock after resolving the physical interface",
)
windows_installer = (ROOT / "installer/windows/winsvpn.iss").read_text(
    encoding="utf-8"
)
windows_prepare_install = windows_installer[
    windows_installer.index("function PrepareToInstall(") :
    windows_installer.index("\nprocedure CurStepChanged(")
]
windows_main = (ROOT / "windows/runner/main.cpp").read_text(encoding="utf-8")
windows_builder = (ROOT / "installer/windows/build_installer.ps1").read_text(
    encoding="utf-8"
)
windows_cmake = (ROOT / "windows/runner/CMakeLists.txt").read_text(encoding="utf-8")
windows_root_cmake = (ROOT / "windows/CMakeLists.txt").read_text(encoding="utf-8")
windows_service = (
    ROOT / "windows/runner/windows_tunnel_service_main.cpp"
).read_text(encoding="utf-8")
windows_service_client = (
    ROOT / "windows/runner/windows_tunnel_service_client.cpp"
).read_text(encoding="utf-8")
windows_service_read_exact = windows_service_client[
    windows_service_client.index("bool ReadPipeExact(") :
    windows_service_client.index(
        "\nbool CallTunnelManager(",
        windows_service_client.index("bool ReadPipeExact("),
    )
]
windows_service_protocol = (
    ROOT / "windows/runner/windows_tunnel_service_protocol.h"
).read_text(encoding="utf-8")
windows_live_cycle = (
    ROOT / "tools/windows_interactive_live_cycle.ps1"
).read_text(encoding="utf-8")
require(
    windows_live_cycle,
    "$expectedRoutePrefixes = @(",
    "Windows live proof must derive its expected manual routes from the exact runtime config",
)
require(
    windows_live_cycle,
    "$actualRoutePrefixes -notcontains $_",
    "Windows live proof must require every configured manual IPv4 route",
)
require(
    windows_live_cycle,
    "$fullTunnelRoutePresent = $null -ne $route -or $configuredRoutesPresent",
    "Windows live proof must accept either canonical or exact manual route coverage",
)
require(
    windows_live_cycle,
    "'--ipv4', '--fail'",
    "Windows excluded-app proof must test the registered physical IPv4 path deterministically",
)
require(
    windows_live_cycle,
    "'--max-time', '15', '--resolve'",
    "Windows excluded-app proof must resolve canaries before the protected route is installed",
)
require(
    windows_live_cycle,
    "-InterfaceAddress $physicalInterfaceAddress",
    "Windows excluded-app proof must distinguish driver failure from physical-route failure",
)
linux = (ROOT / "linux/runner/linux_tunnel_backend.cc").read_text(encoding="utf-8")
linux_bpf = (ROOT / "linux/runner/winsvpn_bypass_bpf.cc").read_text(
    encoding="utf-8"
)
linux_cmake = (ROOT / "linux/CMakeLists.txt").read_text(encoding="utf-8")
linux_runner_cmake = (ROOT / "linux/runner/CMakeLists.txt").read_text(
    encoding="utf-8"
)
linux_installer = (ROOT / "linux/packaging/install.sh").read_text(
    encoding="utf-8"
)
linux_uid_test = (ROOT / "tools/test_linux_installer_uid_selection.sh").read_text(
    encoding="utf-8"
)
linux_fresh_install_test = (
    ROOT / "tools/test_linux_fresh_install_collision.sh"
).read_text(encoding="utf-8")
linux_split_canary = (ROOT / "tools/linux_split_tunnel_live_canary.sh").read_text(
    encoding="utf-8"
)
linux_live_assertions = (
    ROOT / "tools/linux_live_tunnel_assertions.sh"
).read_text(encoding="utf-8")
linux_live_split_assertions = (
    ROOT / "tools/linux_live_split_assertions.sh"
).read_text(encoding="utf-8")
linux_live_teardown_assertions = (
    ROOT / "tools/linux_live_tunnel_teardown_assertions.sh"
).read_text(encoding="utf-8")
linux_winn3_host_header = (ROOT / "linux/runner/linux_winn3_host.h").read_text(
    encoding="utf-8"
)
android = (
    ROOT / "android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt"
).read_text(encoding="utf-8")
flutter = (ROOT / "lib/main.dart").read_text(encoding="utf-8")
connectivity_probe_budget = (
    ROOT / "lib/connectivity_probe_budget.dart"
).read_text(encoding="utf-8")
tunnel_readiness = (ROOT / "lib/tunnel_readiness.dart").read_text(encoding="utf-8")

for source, platform in ((windows, "Windows"), (linux, "Linux")):
    require(
        source,
        '"vpn_internet"',
        f"{platform} readiness must expose vpn_internet",
    )
    require(
        source,
        '"vpn_validated"',
        f"{platform} readiness must expose vpn_validated",
    )

require(
    windows,
    'readiness[flutter::EncodableValue("vpn_internet")] =\n      flutter::EncodableValue(false);',
    "Windows service presence must not claim internet access",
)
require(
    windows,
    'readiness[flutter::EncodableValue("vpn_validated")] =\n      flutter::EncodableValue(false);',
    "Windows service presence must not claim validation",
)
validate_windows_tunnel_interface_probe_contract(
    windows_tunnel_interface_probe_source(windows)
)
require(
    windows,
    "bind(socket_handle, reinterpret_cast<SOCKADDR*>(&local)",
    "Windows internet probe must bind its socket to the tunnel address",
)
require(
    windows,
    "IP_UNICAST_IF",
    "Windows internet probe must pin the outgoing tunnel interface",
)
require(
    windows,
    "GET /cdn-cgi/trace HTTP/1.1",
    "Windows internet probe must validate an application-layer response",
)
require(
    windows,
    'response[flutter::EncodableValue("bound_to_tunnel")]',
    "Windows probe must report tunnel binding",
)
forbid(
    windows,
    'response[flutter::EncodableValue("bound_to_tunnel")] =\n      flutter::EncodableValue(active);',
    "Windows must not infer tunnel binding from service activity",
)
require(
    windows,
    'PositiveIntValue(section, "port", 80)',
    "Windows Xray must default to the explicit port-80 plaintext route",
)
require(
    windows,
    'LowerAscii(SectionValue(section, "security", "none"))',
    "Windows Xray security must be normalized independently of its port",
)
require(
    windows,
    'if (security == "tls")',
    "Windows Xray must add TLS settings only for explicit TLS transports",
)
require(
    windows,
    r'\"allowInsecure\":false',
    "Windows Xray TLS must verify the server certificate",
)
require(
    windows,
    'security != "none" && security != "tls"',
    "Windows Xray must reject unknown security modes",
)
require(
    windows,
    'Xray stealth AWG destination must remain loopback-only.',
    "Windows Xray must reject non-loopback AWG relay destinations",
)
for literal, explanation in (
    # 2026-08-07: was `JsonEscape(host)` with the rationale "retain the
    # prevalidated carrier address". The carrier ADDRESS handed to Xray is now
    # a prevalidated IPv4 literal, never the name -- that is the DNS-egress
    # fix. The name survives only as SNI and as the WebSocket Host header,
    # which is asserted separately below.
    ('JsonEscape(transport_ipv4s[i])', "hand Xray prevalidated IPv4 literals, never a name"),
    ('ResolvePublicIpv4Addresses(host)', "resolve the carrier in app code before Xray starts"),
    # 2026-08-07: the rationale on this line used to be "keep outer DNS on
    # IPv4". THAT WAS FALSE AND MEASURED FALSE. With a hostname address,
    # localdns.LookupIP calls net.LookupIP, which asks for BOTH families and
    # filters the result: 52 A and 52 AAAA queries observed in a single
    # ten-second run on the pinned engine build. The string is still required,
    # but for what it actually does -- pick the IPv4 socket family for the dial
    # -- and the outer DNS question is now settled by there being no name left
    # to look up.
    ('\\"domainStrategy\\":\\"UseIPv4\\"', "select the IPv4 socket family for the outer dial"),
    ('\\"tcpUserTimeout\\":15000', "bound stalled outer TCP sessions"),
    # `targetStrategy` was asserted here as "select IPv4 VLESS targets". It
    # never did: it is a *freedom* outbound field (infra/conf/freedom.go), this
    # is a *vless* outbound, and upstream has no DisallowUnknownFields, so it
    # was parsed and silently discarded. Removed from the generator; the
    # assertion is inverted below so it cannot come back.
    ('\\"headers\\":{\\"Host\\":\\"', "preserve the proven WebSocket Host header"),
    ('\\"enabled\\":false', "use Xray's native bounded VLESS UDP-over-TCP path"),
    ('\\"concurrency\\":0', "disable generic mux explicitly"),
    ('\\"xudpConcurrency\\":0', "disable XUDP aggregation explicitly"),
    ('\\"xudpProxyUDP443\\":\\"skip\\"', "prevent UDP 443 proxy rewriting"),
):
    require(windows, literal, f"Windows Xray must {explanation}")
forbid(
    windows,
    '\\"targetStrategy\\"',
    "Windows Xray must not reintroduce targetStrategy, which a vless outbound silently discards",
)
forbid(
    windows,
    'JsonEscape(host)\n       << "\\",\\"port\\"',
    "Windows Xray must never place the carrier hostname in vnext.address",
)
forbidden_ws_field = '\\"heartbeatPeriod\\":15'
forbid(
    windows,
    forbidden_ws_field,
    "Windows production Xray must preserve the proven WebSocket shape",
)
windows_xray_start = windows[windows.index("bool StartXrayIfNeeded") :]
require_order(
    windows_xray_start,
    "StopXrayProcess();",
    "WriteBytesSecureAtomic(",
    "Windows must stop the old Xray process before writing its replacement config",
)
require_order(
    windows_xray_start,
    "WriteBytesSecureAtomic(",
    "ScopedFileDelete delete_xray_config(config_path);",
    "Windows must arm RAII deletion after securely writing the credential-bearing Xray config",
)

for withdrawn_runtime_token in (
    "MULLVADSPLITTUNNEL",
    "mullvad-split-tunnel.sys",
    "WinsVPNSplitTunnel",
    "kWfpProvider",
    "IOCTL_INITIALIZE",
    "IOCTL_REGISTER_PROCESSES",
    "IOCTL_REGISTER_IP_ADDRESSES",
    "IOCTL_SET_CONFIGURATION",
    "IOCTL_RESET",
    "SERVICE_KERNEL_DRIVER",
):
    forbid(
        windows_split_active,
        withdrawn_runtime_token,
        f"Windows shipping runtime must compile out withdrawn split-driver token {withdrawn_runtime_token}",
    )
for entry_point in ("PrepareWindowsAppExclusions", "StartWindowsAppExclusions"):
    body = windows_split_active[
        windows_split_active.index(f"bool {entry_point}(") :
        windows_split_active.index("\n}", windows_split_active.index(f"bool {entry_point}(") ) + 2
    ]
    require(
        body,
        "Windows per-app split tunneling is unsupported; only ",
        f"{entry_point} must reject non-empty per-app selections explicitly",
    )

require(
    flutter,
    "final tableLine = windowsManualRouting ? 'Table = off' : '';",
    "Windows app exclusions and stealth carriers must disable AmneziaWG automatic route ownership",
)
require(
    flutter,
    "Platform.isWindows && windowsRequiresManualTunnelRoutes()",
    "The Windows product engine must engage owned routes for every transport mode",
)
require(
    flutter,
    "..['windows_transport_bypass_ipv4'] = boundedAddresses",
    "Windows must pass a bounded prevalidated carrier-address set to privileged routing",
)
require(
    flutter,
    "..['host'] = boundedAddresses.first",
    "Windows Xray must pin the runtime carrier to an address protected by a physical /32",
)
require(
    windows,
    'LowerAscii(SectionValue(ParseSection(raw_config, "interface"), "table")) ==',
    "Windows must derive manual-route mode from the validated Table=off directive",
)
require(
    windows_split,
    "CreateIpForwardEntry2(&route)",
    "Windows per-app split tunneling must install validated tunnel routes with IP Helper",
)
require(
    windows_split,
    "ParsePrivateTunnelGatewayIpv4(",
    "Windows per-app split tunneling must validate the hub-advertised private tunnel gateway",
)
require(
    windows_split,
    'SectionValue(raw_config, "WinsApp", "TunnelGatewayIPv4")',
    "Windows per-app split tunneling must consume the explicit dynamic tunnel gateway",
)
require(
    windows_split,
    "A layer-3 tunnel route is on-link.",
    "Windows must keep the Wintun IPv4 default route on-link",
)
require(
    windows_split,
    "next_hop.si_family = AF_INET;",
    "Windows must build a zero IPv4 next hop for the Wintun default route",
)
require(
    windows_split,
    "CreateOwnedRoute(prefix, tunnel_luid, next_hop, error)",
    "Windows must install the on-link default through the owned-route helper",
)
require(
    flutter,
    "TunnelGatewayIPv4 = ${_windowsTunnelGatewayIpv4(config)}",
    "Windows per-app split tunneling must pass the control-plane gateway into the privileged config",
)
require(
    flutter,
    "raw, ['tunnel_gateway_ipv4', 'tunnelgatewayipv4']",
    "VPN config normalization must preserve the dynamic control-plane tunnel gateway",
)
forbid(
    flutter,
    "return '${parts[0]}.${parts[1]}.${parts[2]}.1';",
    "Windows must not infer tunnel topology from a client address",
)
require(
    windows_split,
    "BuildManualRoutePlan(allowed, &bypass_ipv4, &install_ipv4_default,",
    "Windows must collapse full tunnel coverage to source-bind-compatible manual defaults",
)
require(
    windows_split,
    "GetBestRoute2(&prepared_internet_route.InterfaceLuid, 0, nullptr,",
    "Windows must resolve every AllowedIPs gap through the prepared physical interface",
)
require(
    windows_split,
    "Track only rows created by this process.",
    "Windows disconnect must not delete a pre-existing user or system route",
)
require_order(
    windows_live_cycle,
    "if (-not $liveCyclePassed)",
    "Stop-Process -Force -ErrorAction SilentlyContinue",
    "A failed Windows live test must terminate the still-failing UI before privileged recovery",
)
require_order(
    windows_live_cycle,
    "Stop-Process -Force -ErrorAction SilentlyContinue",
    "$managerCleanupEvidence = Restore-TunnelManagerRunning",
    "A failed Windows live test must recover and verify the privileged manager after terminating the failing UI",
)
require(
    windows_split,
    "DeleteIpForwardEntry2(&*route)",
    "Windows per-app split tunneling must remove every owned manual tunnel route",
)
require_order(
    windows,
    "StartWindowsAppExclusions(excluded_apps, raw_config, error)",
    "InstallWindowsTunnelRoutes(raw_config, error)",
    "Windows must engage per-app exclusions on interface-up before adding tunnel routes",
)
require(
    windows_split,
    "MIB_IPFORWARD_ROW2 prepared_internet_route = g_prepared_internet_route;",
    "Windows route installation must consume the pre-VPN physical route snapshot after driver engagement",
)
require_order(
    windows,
    "StopWindowsAppExclusions();\n  RemoveWindowsTunnelRoutes();",
    "RemoveTunnelService(amneziawg)",
    "Windows disconnect must stop exclusions and remove owned routes before deleting the tunnel",
)

require(
    windows,
    'The Win\'s VPN product engine requires owned Windows routes.',
    "The Windows service must reject automatic route ownership for its setconf engine",
)
require(
    windows_split,
    "endpoint_bypass.PrefixLength = 32;",
    "Windows must dynamically protect the resolved direct-AWG or Xray endpoint",
)
forbid(
    windows,
    "excluded_apps.push_back(xray_exe)",
    "Windows must not process-exclude Xray because that also captures its loopback AWG downlink",
)
for literal, explanation in (
    ("Ipv4PrefixContains(", "validate that the resolved carrier is inside a physical bypass prefix"),
    ("The physical carrier address is not excluded from the tunnel routes.", "fail closed when the carrier /32 is missing"),
    ("Destination-based split tunneling owns only explicit physical bypass", "preserve route-only physical bypass ownership"),
    ("route.physical_bypass", "monitor route-only physical bypass ownership"),
):
    require(
        windows_split,
        literal,
        f"Windows carrier routing must {explanation}",
    )
require(
    flutter,
    "Platform.isWindows && stealthActive",
    "Windows stealth must exclude carrier /32 addresses even with no user-selected app",
)
forbid(
    windows_main,
    "--winsvpn-uninstall-cleanup",
    "the ordinary Windows UI must not expose a privileged cleanup argument",
)
forbid(
    windows_main,
    "ES_SYSTEM_REQUIRED",
    "the Windows UI must request sleep suppression only while a tunnel is active",
)

windows_install = windows[windows.index("bool InstallTunnel") :]
require(
    windows,
    'if (call.method_name() == "getTunnelActivity")',
    "Windows must expose Xray-or-AWG activity separately for cancellation settlement",
)
windows_connected_state = windows[
    windows.index('if (call.method_name() == "getTunnelState")') :
    windows.index('if (call.method_name() == "getTunnelActivity")')
]
forbid(
    windows_connected_state,
    "IsXrayProcessRunning()",
    "Windows connected state must not promote an orphan Xray carrier to a VPN",
)
windows_activity_state = windows[
    windows.index('if (call.method_name() == "getTunnelActivity")') :
    windows.index('if (call.method_name() == "getTunnelActivitySnapshot")')
]
require(
    windows_activity_state,
    "IsTunnelRunning()",
    "Windows cancellation activity must include AWG",
)
require(
    windows_activity_state,
    "IsXrayProcessRunning()",
    "Windows cancellation activity must include Xray",
)
require_order(
    windows_install,
    "StartXrayIfNeeded(raw_config, error)",
    "StartWindowsTunnelThroughService(",
    "Windows must start its user-mode Xray carrier before requesting privileged AWG routing",
)
require_order(
    windows_install,
    "StartWindowsTunnelThroughService(",
    "EnableTunnelPowerProtection()",
    "Windows must request sleep suppression only after the privileged tunnel starts",
)
windows_uninstall = windows[
    windows.index("bool UninstallTunnel(") :
    windows.index("#endif", windows.index("bool UninstallTunnel("))
]
require_order(
    windows_uninstall,
    "StopWindowsTunnelThroughService(&service_error)",
    "StopXrayProcess()",
    "Windows disconnect must request privileged cleanup before local carrier cleanup",
)
require_order(
    windows_uninstall,
    "StopXrayProcess()",
    "if (!service_stopped)",
    "Windows disconnect must remove Xray even when the privileged manager fails",
)
for literal, explanation in (
    ("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "kill the Xray carrier if the UI exits unexpectedly"),
    ("CREATE_NO_WINDOW | CREATE_SUSPENDED", "suspend Xray until its lifetime boundary is installed"),
    ("AssignProcessToJobObject", "bind Xray and its descendants to the UI lifetime"),
    ("g_xray_process.dwProcessId", "identify the exact Xray process to the tunnel manager"),
):
    require(windows, literal, f"Windows must {explanation}")
windows_privileged_install = windows[windows.index("bool InstallPrivilegedTunnel") :]
require_order(
    windows_privileged_install,
    "PrepareWindowsAppExclusions(excluded_apps, raw_config, error)",
    "WriteBytesSecureAtomic(",
    "Windows must capture physical app-exclusion routing before changing the VPN route",
)
require_order(
    windows_privileged_install,
    "ValidateLoadedAwgRuntime(raw_config, winn_seam_endpoint, error)",
    "StartWindowsAppExclusions(excluded_apps, raw_config, error)",
    "Windows must start per-app filtering only after protected AWG runtime validation",
)
require(
    windows_privileged_install,
    "if (!RemoveTunnelService(amneziawg))",
    "Windows must fail closed unless the previous tunnel service is removed",
)
require(
    windows_privileged_install,
    "StartWinsAwgEngine(config_path, error)",
    "Windows must require product-engine startup before filtering traffic",
)
require(
    windows,
    "sc.exe stop ",
    "Windows tunnel cleanup must stop a stale service before retrying vendor removal",
)
require_order(
    windows,
    "const bool engine_stopped = StopWinsAwgEngine();",
    "DeleteFileW(config_path.c_str());",
    "Windows disconnect must stop the product engine before deleting its private config",
)
for literal, explanation in (
    ("config.size() > 512 * 1024", "bound privileged configuration size"),
    ("line_count > 512", "bound privileged directive count"),
    ('{"interface",', "allow only reviewed AWG interface keys"),
    ('{"peer",', "allow only reviewed AWG peer keys"),
    ('{"xray",', "allow only reviewed Xray carrier keys"),
    ("unknown or duplicate section", "reject section smuggling"),
    ("unsafe, empty, or duplicate directive", "reject script and duplicate directives"),
    ("RunPrivilegedWindowsTunnelValidationSelfTest", "exercise the validator without privileged side effects"),
    ("optional_empty_app_value", "allow empty defaults only for reviewed app-exclusion fields"),
    ("Empty optional app exclusions failed validation", "test the default no-exclusion connection path"),
    ("empty required directive", "prove empty cryptographic or route directives remain rejected"),
    ("PostUp = powershell.exe -Command whoami", "prove script directives are rejected"),
    ("oversized input", "prove oversized requests are rejected"),
    ("embedded NUL", "prove binary-smuggling requests are rejected"),
):
    require(windows, literal, f"Windows must {explanation}")

require(
    windows_installer,
    "PrivilegesRequired=admin",
    "Windows installer must request administrator access for native drivers and services",
)
for affected_driver_file in (
    "mullvad-split-tunnel.sys",
    "mullvad-split-tunnel.cat",
    "mullvad-split-tunnel.inf",
):
    forbid(
        windows_installer.lower(),
        affected_driver_file,
        "Windows installer source must not reference withdrawn Mullvad SYS/CAT/INF payloads",
    )
require(
    windows_installer,
    "--uninstall",
    "Windows uninstaller must invoke fail-closed privileged service and driver cleanup",
)
require(
    windows_installer,
    "RaiseException(",
    "Windows uninstaller must stop before deleting a live driver payload",
)
require(
    windows_service,
    "return cleaned && deleted ? 0 : 5;",
    "Windows privileged uninstaller must return failure when verified tunnel or WFP cleanup fails",
)
require(
    windows_installer,
    "or (ResultCode <> 0) then\n      RaiseException(",
    "Windows package uninstall must propagate privileged cleanup failure before deleting payload files",
)
require(
    windows_installer,
    "SignedUninstaller=yes",
    "Windows production installer must Authenticode-sign its generated uninstaller",
)
require_order(
    windows_prepare_install,
    "Installing Microsoft Visual C++ Runtime",
    "Installing AmneziaWG Windows tunnel engine",
    "Windows setup must install the VC runtime before the tunnel engine",
)
require_order(
    windows_prepare_install,
    "Installing AmneziaWG Windows tunnel engine",
    "if not AmneziaWgRuntimeInstalled then",
    "Windows setup must verify the installed shared tunnel runtime after MSI completion",
)
require_order(
    windows_prepare_install,
    "if not AmneziaWgRuntimeInstalled then",
    "Validating the new protected tunnel manager",
    "Windows setup must validate the staged replacement after shared prerequisites",
)
require_order(
    windows_prepare_install,
    "Validating the new protected tunnel manager",
    "RemovePreviousTunnelManagerForUpgrade(Result)",
    "Windows upgrades must prove prerequisite and replacement readiness before stopping the old manager",
)
require_order(
    windows_installer,
    "RemovePreviousTunnelManagerForUpgrade(Result)",
    "Installing the protected Win''s VPN tunnel manager",
    "Windows setup must transition the old manager only immediately before registering the replacement",
)
require(
    windows_installer,
    "if CurStep <> ssPostInstall then",
    "Windows setup must wait until installed payload files exist before registering the replacement service",
)
require(
    windows_installer,
    "function PrepareToInstall(var NeedsRestart: Boolean): String;",
    "Windows setup must finish prerequisite/readiness checks before the privileged upgrade transition",
)
require(
    windows_installer,
    "function RestorePreviousTunnelManager: Boolean;",
    "Windows setup must retain a fail-closed rollback path for an interrupted service upgrade",
)
require(
    windows_installer,
    "procedure DeinitializeSetup;",
    "Windows setup must restore the previous manager if installation aborts after transition",
)
require(
    windows_installer,
    "Retaining shared prerequisites: Microsoft VC runtime and AmneziaWG MSI.",
    "Windows uninstall must explicitly retain prerequisites it does not exclusively own",
)
require(
    windows_installer,
    "A failed start must not leave a partially registered privileged service.",
    "Windows setup must clean a partially registered tunnel manager",
)
require(
    windows_cmake,
    "/MANIFESTUAC:level='asInvoker' uiAccess='false'",
    "the Windows Flutter UI must run at ordinary user integrity",
)
forbid(
    windows_cmake,
    "/MANIFESTUAC:level='requireAdministrator'",
    "the whole Windows Flutter UI must not run elevated",
)
require(
    windows_cmake,
    "add_executable(wins_vpn_tunnel_service",
    "Windows must isolate privileged routing in a dedicated service binary",
)
require(
    windows_root_cmake,
    "install(TARGETS wins_vpn_tunnel_service",
    "Windows release output must contain the privileged service beside the UI",
)
for literal, explanation in (
    ("PIPE_REJECT_REMOTE_CLIENTS", "reject remote named-pipe clients"),
    ("FILE_FLAG_FIRST_PIPE_INSTANCE", "prevent pipe squatting by a second server"),
    ("GetNamedPipeClientProcessId", "bind requests to a concrete client process"),
    ("WTSGetActiveConsoleSessionId", "restrict requests to the active console session"),
    ('JoinPath(ModuleDirectory(), L"wins_vpn.exe")', "require the co-installed UI executable path"),
    ('JoinPath(ModuleDirectory(), L"xray.exe")', "require the co-installed Xray carrier path"),
    ("OpenVerifiedCarrierProcess", "verify the Xray PID before accepting a fallback route"),
    ("StopTunnelAfterCarrierExit", "remove privileged routing when the Xray carrier exits"),
    ("ImpersonateNamedPipeClient(pipe)", "inspect the actual pipe client token"),
    ("WinLocalSystemSid", "reject LocalSystem as an interactive client identity"),
    ("WinLocalServiceSid", "reject LocalService as an interactive client identity"),
    ("WinNetworkServiceSid", "reject NetworkService as an interactive client identity"),
    ("PIPE_TYPE_MESSAGE", "use message-framed local IPC"),
    ("header.payload_size > winsvpn::tunnel_service::kMaxRequestBytes", "bound pipe payloads before allocation"),
    ("payload.find('\\0')", "reject NUL-bearing pipe payloads"),
    ('L"LocalSystem"', "declare the narrow service host explicitly"),
    ("SERVICE_CONFIG_DELAYED_AUTO_START_INFO", "delay tunnel-manager startup during boot"),
    ("SERVICE_CONFIG_FAILURE_ACTIONS", "restart the tunnel manager after unexpected failure"),
    ("RunPrivilegedWindowsTunnelValidationSelfTest", "run config rejection tests in the service self-test"),
    ("CleanupPrivilegedWindowsTunnel(&cleanup_error)", "remove stale AWG and split-driver state before service installation"),
    (
        "kServiceDeletionRetryTimeoutMilliseconds",
        "bound the SCM pending-deletion upgrade wait",
    ),
    (
        "if (*create_error != ERROR_SERVICE_MARKED_FOR_DELETE)",
        "retry service creation only for the transient SCM deletion state",
    ),
    (
        "CreateTunnelManagerService(manager, binary_path, &create_error)",
        "use the bounded pending-deletion path for replacement and rollback installation",
    ),
    ("ControlService(service, SERVICE_CONTROL_STOP", "stop an existing manager before reconfiguring it"),
    ("WaitForServiceState(service, SERVICE_STOPPED, 180000)", "confirm the old manager stopped before restart"),
    ("GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST", "distinguish an absent service from access or SCM failures"),
    ("IsCurrentProcessElevated() ? InstallService()", "require an elevated installer before privileged mutation"),
    ("IsCurrentProcessElevated() ? UninstallService()", "require an elevated uninstaller before privileged cleanup"),
):
    require(windows_service, literal, f"Windows service must {explanation}")
require(
    windows_service,
    'L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"',
    "Windows service pipe ACL must grant only system, administrators, and interactive users",
)
for literal, explanation in (
    ("WaitNamedPipeW", "wait for the protected manager without polling shell tools"),
    ("SECURITY_IDENTIFICATION", "cap server impersonation at identity inspection"),
    ("kMaxRequestBytes", "bound outbound requests"),
    ("carrier_pid", "send the exact Xray carrier PID only in start requests"),
    ("response.magic", "validate response protocol magic"),
    ("response.version", "validate response protocol version"),
    ("kMaxResponseBytes", "bound service responses before allocation"),
):
    require(windows_service_client, literal, f"Windows service client must {explanation}")
require_order(
    windows_service,
    "FlushPipeBounded(pipe);",
    "DisconnectNamedPipe(pipe);",
    "Windows tunnel responses must be boundedly consumed before the message pipe is disconnected",
)
require(
    windows_service,
    "CancelSynchronousIo(thread);",
    "Windows service must cancel a client-abandoned response flush before reusing its pipe",
)
require_order(
    windows_service_read_exact,
    "if (read > 0)",
    "if (total == bytes)",
    "Windows tunnel clients must account for completed bytes before accepting a complete frame",
)
require_order(
    windows_service_read_exact,
    "if (total == bytes)",
    "if (read == 0 || !more_data)",
    "Windows tunnel clients must accept a complete frame before interpreting a closing pipe status",
)
require(
    windows_service_protocol,
    "static_assert(sizeof(RequestHeader) == 24",
    "Windows tunnel protocol must pin request framing at compile time",
)
require(
    windows_service_protocol,
    "static_assert(sizeof(ResponseHeader) == 12",
    "Windows tunnel protocol must pin response framing at compile time",
)
require(
    windows_builder,
    "$affectedSplitTunnelDriverNames = @(",
    "Windows release builder must enumerate known-affected split-driver payloads",
)
require(
    windows_builder,
    "function Assert-InnoStagingContainsNoWithdrawnMullvadPayloads {",
    "Windows release builder must recursively inspect Inno staging for withdrawn split-driver payloads",
)
require(
    windows_builder,
    "withdrawn kernel split-tunnel bytes, including when renamed",
    "Windows release builder must reject withdrawn split-driver bytes even when renamed",
)
require(
    windows_builder,
    "Known-affected Mullvad split-tunnel driver 1.3.0.0 must not",
    "Windows release builder must fail closed if the affected driver enters staging",
)
require_order(
    windows_builder,
    "Assert-InnoStagingContainsNoWithdrawnMullvadPayloads",
    "& $iscc @innoArguments",
    "Windows Inno packaging must reject withdrawn Mullvad payloads before ISCC",
)
require(
    windows_builder,
    "$TunnelServiceArtifact --protocol-self-test",
    "Windows release builder must execute the service protocol and config self-test",
)

require(
    linux,
    'readiness, "vpn_internet", fl_value_new_bool(false)',
    "Linux interface presence must not claim internet access",
)
require(
    linux,
    'readiness, "vpn_validated", fl_value_new_bool(false)',
    "Linux interface presence must not claim validation",
)
validate_linux_tunnel_interface_evidence(linux, linux_winn3_host_header)
require(
    linux,
    'fl_value_set_string_take(response, "bound_to_tunnel"',
    "Linux probe must report tunnel binding",
)
for literal, explanation in (
    ("configure_kill_switch()", "install a physical-interface escape guard"),
    ("cleanup_kill_switch()", "roll that guard back on every disconnect"),
    ("KS_CHAIN=WINSVPN_KS", "isolate owned rules in a dedicated chain"),
    ("kill-switch-active", "record root-owned firewall lifecycle state"),
    ("refused to modify an unowned Linux firewall chain", "fail closed on firewall collisions"),
    ('key != "allowedips"', "derive protection from the dynamic peer route set"),
    ('-A WINSVPN_KS -o "$NAME"', "allow traffic already using the tunnel"),
    ('--mark "$ROUTING_MARK"', "preserve AWG, Xray, and selected-app outer routing"),
    ('-d "$CIDR" -m addrtype', "reject only destinations assigned to the tunnel"),
    ("! --dst-type LOCAL", "preserve loopback and local destinations"),
    ("--comment winsvpn-killswitch", "make owned rules auditable"),
    ("-j REJECT", "block an explicit physical-interface escape"),
):
    require(linux, literal, f"Linux kill switch must {explanation}")
require(
    linux,
    'if (security == "tls")',
    "Linux Xray must add TLS settings only for explicit TLS transports",
)
require(
    linux,
    r'\"tlsSettings\": {\"serverName\": \"',
    "Linux Xray TLS must send the advertised SNI server name",
)
require(
    linux,
    r'\"host\": \"',
    "Linux Xray WebSocket must set Xray's independent virtual-host field",
)
require(
    linux,
    r'\"headers\": {\"Host\": \"',
    "Linux Xray WebSocket must retain the compatible virtual-host header",
)
require(
    linux,
    r'\"allowInsecure\": false',
    "Linux Xray TLS must verify the server certificate",
)
require(
    linux,
    'LowerAscii(SectionValue(section, "security", "tls"))',
    "Linux Xray security must default to TLS and be normalized independently of its port",
)
require(
    linux,
    'security != "none" && security != "tls"',
    "Linux Xray must reject unknown security modes",
)
require(
    linux,
    'SectionBool(section, "allowplaintexttransport")',
    "Linux Xray must only allow security=none behind the explicit plaintext-transport compatibility flag",
)
require(
    linux,
    'Xray stealth AWG destination must remain loopback-only.',
    "Linux Xray must reject non-loopback AWG relay destinations",
)
for literal, explanation in (
    ('--comment winsvpn-app-bypass', "mark only the selected launcher cgroup for bypass"),
    ('--comment winsvpn-app-bypass-dns-clear', "clear the selected app socket mark only for DNS"),
    ('--comment winsvpn-app-bypass-dns-return', "stop DNS before the general cgroup mark"),
    ('-p "$PROTO" --dport 53', "recognize both UDP and TCP resolver traffic"),
    ('--comment winsvpn-app-bypass-dns-clear -j MARK --set-mark 0', "keep resolver traffic on the protected VPN route"),
    ('--comment winsvpn-app-bypass-connmark', "preserve bypass marks for strict reverse-path filtering"),
    ('winsvpn-bypass-bpf', "attach the bypass mark before the first socket route lookup"),
    ('"/usr/bin/sleep",', "keep the verified bypass cgroup alive while the tunnel is active"),
):
    require(linux, literal, f"Linux per-app split tunneling must {explanation}")
for source, literal, explanation in (
    (linux_bpf, "BPF_PROG_TYPE_CGROUP_SOCK", "load only a cgroup socket program"),
    (linux_bpf, "BPF_CGROUP_INET_SOCK_CREATE", "mark sockets before initial route selection"),
    (linux_bpf, "BPF_LINK_CREATE", "use an fd-owned fail-safe BPF link"),
    (linux_bpf, "offsetof(struct bpf_sock, mark)", "write only the verified socket mark field"),
    (linux_bpf, "PR_SET_NO_NEW_PRIVS", "forbid privilege regain after setup"),
    (linux_bpf, "setuid(nobody->pw_uid)", "drop the BPF holder to the locked nobody identity"),
    (linux_bpf, "__NR_pidfd_open", "bind link lifetime to the exact GUI process"),
    (linux_bpf, "close(link_fd);", "detach bypass immediately on cleanup or GUI exit"),
    (linux_runner_cmake, "add_executable(winsvpn-bypass-bpf", "build the first-party BPF holder"),
    (linux_cmake, "install(TARGETS winsvpn-bypass-bpf", "install the BPF holder in the exact bundle"),
    (
        linux_installer,
        '"$stage/wins_vpn" "$stage/winsvpn-bypass-bpf" "$stage/install.sh"',
        "require the BPF holder during fresh installation",
    ),
    (
        linux_installer,
        "for required_executable in xray awg awg-quick amneziawg-go winn-datapath; do",
        "require the standalone Winn v3 engine during fresh installation",
    ),
):
    require(source, literal, f"Linux per-app split tunneling must {explanation}")
for source, literal, explanation in (
    (linux_installer, "firewall_references_uid", "inspect existing owner-based firewall rules"),
    (linux_installer, "select_unreferenced_system_uid", "select a collision-free service identity"),
    (linux_installer, 'useradd --system --uid "$xray_install_uid"', "pin the verified service UID"),
    (linux_uid_test, "Combined account, iptables, and nftables collision test failed.", "simulate mixed UID collisions"),
    (linux_uid_test, "iptables UID-range collision test failed.", "simulate owner-rule UID ranges"),
):
    require(source, literal, f"The Linux fresh installer must {explanation}")
for literal, explanation in (
    ("winsvpn-bypass.slice", "prove the launcher cgroup"),
    ("socket.SO_MARK", "read the kernel-assigned socket mark"),
    ("chmod 600", "keep canary evidence private"),
    ("sleep 120", "remain alive for cross-machine inspection"),
):
    require(linux_split_canary, literal, f"The Linux split canary must {explanation}")
for forbidden in ("curl", "wget", "http://", "https://"):
    if forbidden in linux_split_canary:
        raise AssertionError(
            f"The Linux split canary must remain zero-network; found {forbidden!r}"
        )
for source, literal, explanation in (
    (linux_fresh_install_test, 'EXPECTED_DISTRO="${WINS_FRESH_INSTALL_TEST_DISTRO:-WinsVPN-Rehearsal-Noble}"', "guard destructive fresh-install rehearsals"),
    (linux_fresh_install_test, "ORIGINAL_FIREWALL_RULE_PRESERVED=PASS", "prove preexisting firewall state survives"),
    (linux_live_assertions, "XRAY_CURRENT_AND_COMPAT_HOST_FIELDS=PASS", "prove both Xray WebSocket host fields at runtime"),
    (linux_live_assertions, "PUBLIC_IPV6_LEAK_BLOCKED=PASS", "prove the IPv4-only tunnel has no public IPv6 escape"),
    (linux_live_split_assertions, 'find /run/user -mindepth 2 -maxdepth 2 -type f', "discover the active desktop runtime across per-user tmpfs mounts without assuming a user name"),
    (linux_live_split_assertions, 'desktop_uid="${BASH_REMATCH[1]}"', "derive the desktop UID from the owner-only canary path"),
    (linux_live_split_assertions, '"${desktop_uid}:600"', "verify the discovered canary owner and mode"),
    (linux_live_split_assertions, "BPF_FAIL_SAFE_HELPER_RUNNING=PASS", "prove the launcher-scoped BPF holder"),
    (linux_live_teardown_assertions, "OWNER_ONLY_RUNTIME_STATE_EMPTY=PASS", "prove disconnect removes privileged state"),
):
    require(source, literal, f"The Linux exact-candidate harness must {explanation}")
if "/run/user/1001" in linux_live_split_assertions:
    raise AssertionError("The Linux split assertion harness must not hardcode a user ID")
for literal, explanation in (
    ('transport_ipv4s[i]', "supply every prevalidated IPv4 edge without runtime DNS"),
    ('\\"tag\\": \\"vless-ws-edge-', "create one valid VLESS outbound per edge"),
    ('\\"balancerTag\\": \\"vless-ws-balancer\\"', "route AWG packets through the edge balancer"),
    ('\\"strategy\\": {\\"type\\": \\"roundRobin\\"}', "retry edge choices deterministically"),
    # 2026-08-07: the rationale here used to be "keep outer DNS on IPv4". THAT
    # WAS FALSE AND MEASURED FALSE -- see the identical correction on the
    # Windows block above. 52 A and 52 AAAA queries were observed from a
    # hostname config carrying exactly this string. Linux never had the leak
    # because it hands Xray literals, not because of this setting.
    ('\\"domainStrategy\\": \\"UseIPv4\\"', "select the IPv4 socket family for the outer dial"),
    ('\\"tcpUserTimeout\\": 15000', "bound stalled outer TCP sessions"),
    ('IsIpv4Literal(hostname)', "skip the resolver entirely for an IP-pinned carrier"),
    ('\\"xudpProxyUDP443\\": \\"skip\\"', "disable muxed UDP for the AWG carrier"),
):
    require(linux, literal, f"Linux Xray must {explanation}")
forbid(
    linux,
    '\\"targetStrategy\\"',
    "Linux Xray must not reintroduce targetStrategy, which a vless outbound silently discards",
)
require(
    linux,
    "ResolvePublicIpv4Addresses(host)",
    "Linux Xray must validate every current IPv4 transport edge before the kill switch",
)
linux_xray_start = linux[linux.index("bool StartXrayTransportIfNeeded") :]
require_order(
    linux_xray_start,
    "StopXrayProcess();",
    "BuildXrayConfig(section, transport_ipv4s, security)",
    "Linux must stop the old Xray process before writing its replacement config",
)
for literal, explanation in (
    ("ResolvePublicIpv4Addresses(host)", "resolve every dynamic Xray edge before route capture"),
    ("winsvpn-xray", "use the locked Xray transport identity"),
    ("uidrange", "exempt only the Xray service identity from recursive routing"),
    ('priority 1 uidrange', "place the Xray identity route directly after the local-table rule"),
    ('rejected a recursive Xray transport route', "verify the resolved Xray socket route before launch"),
    ('--comment winsvpn-xray-bypass', "mark only the locked Xray identity's outer packets"),
    ('--comment winsvpn-xray-connmark', "preserve that mark across Xray connections"),
    ('CONNMARK --save-mark', "save the Xray mark for strict reverse-path filtering"),
    ('CONNMARK --restore-mark', "restore the Xray mark before reverse-path validation"),
    ("setpriv --reuid=", "drop all root privileges before Xray starts"),
    ("--no-new-privs", "prevent the Xray subprocess from gaining privileges"),
    ('RunArgv({sudo, "-n", "true"}, ProcOutput::kSuppress)', "detect a pre-authorized minimal-session privilege path"),
):
    require(linux, literal, f"Linux must {explanation}")
if "xray-transport-ipv4" in linux:
    raise AssertionError(
        "Linux must not bypass every process sharing the Xray destination IP"
    )
linux_helper_start = linux[linux.index('case "${1:-}" in') :]
require_order(
    linux_helper_start,
    '"$TOOL" up "$CONF_DST"',
    'configure_kill_switch "$CONF_DST"',
    "Linux must bring AWG up before deriving its dynamic kill-switch mark and routes",
)
require_order(
    linux_helper_start,
    'configure_kill_switch "$CONF_DST"',
    "activate_xray_transport",
    "Linux must install kill-switch rules before selecting the Xray UID-route priority",
)
linux_xray_activation = linux[linux.index("activate_xray_transport()") :]
require_order(
    linux_xray_activation,
    "CONNMARK --restore-mark",
    'setpriv --reuid="$xray_uid"',
    "Linux must install strict-rpfilter-compatible connection marking before Xray starts",
)
linux_privilege_start = linux[linux.index("std::vector<std::string> PrivilegedRunner()") :]
require_order(
    linux_privilege_start,
    'RunArgv({sudo, "-n", "true"}, ProcOutput::kSuppress)',
    'const std::string pkexec = Which("pkexec")',
    "Linux must prefer an already-authorized sudo policy before interactive PolicyKit",
)

require(
    android,
    '"bound_to_tunnel" to false',
    "Android probe must fail closed before VPN-network selection",
)
require(
    android,
    'response["bound_to_tunnel"] = true',
    "Android probe must record explicit VPN-network binding",
)
require(
    android,
    "vpnNetwork.openConnection(URL(probeUrl))",
    "Android probes must use the selected VPN Network",
)

require(
    flutter,
    "_isApplePlatform || result?['bound_to_tunnel'] == true",
    "non-Apple probe success must require native tunnel-binding proof",
)
require(
    flutter,
    "hasUserVisibleTunnelProtectionProof(",
    "desktop readiness must use the explicit user-visible protection contract",
)
require(
    connectivity_probe_budget,
    "if (platform == 'linux') return stealthActive ? 6 : 4;",
    "Linux UDP-to-TCP failover must use a bounded retry budget",
)
require(
    connectivity_probe_budget,
    "if (platform == 'windows') return stealthActive ? 3 : 2;",
    "Windows UDP-to-TCP failover must use a compact retry budget",
)
require(
    flutter,
    "Duration(seconds: Platform.isWindows ? 9 : 10)",
    "Windows Dart probe timeout must exceed its bounded native timeout",
)
require(
    windows,
    "kEndpointTimeoutMilliseconds = 3000",
    "Windows native probe must keep each tunnel-bound connect compact",
)
require(
    windows,
    "kProbeBudgetMilliseconds = 7000",
    "Windows native probe command must finish before the Dart timeout",
)
for literal in (
    "active: active",
    "engineReady: engineReady",
    "vpnPresent: vpnPresent",
    "boundVpnProbeSucceeded: boundVpnProbeSucceeded",
):
    require(
        flutter,
        literal,
        "desktop readiness must pass every protection input to the explicit contract",
    )
require(
    tunnel_readiness,
    "active && engineReady && vpnPresent && boundVpnProbeSucceeded",
    "desktop readiness must require active engine, VPN presence, and explicit probe",
)
require(
    flutter,
    "The previous VPN route could not be removed safely. Restart the app before retrying.",
    "fallback switching must stop when the prior native route cannot be removed",
)
require(
    flutter,
    "The failed VPN route could not be removed safely. Restart the app before retrying.",
    "failed fallback cleanup must stop the route loop instead of stacking services",
)

print("desktop tunnel readiness validation passed")
