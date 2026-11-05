#!/usr/bin/env python3
"""Regression contract for the withdrawn Windows per-app split driver."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "windows/runner/windows_split_tunnel.cpp"
HEADER = ROOT / "windows/runner/windows_split_tunnel.h"
PROTOCOL = ROOT / "windows/runner/windows_tunnel_service_protocol.h"
INSTALLER = ROOT / "installer/windows/winsvpn.iss"
BUILDER = ROOT / "installer/windows/build_installer.ps1"
CLIENT = ROOT / "lib/main.dart"
CMAKE = ROOT / "windows/runner/CMakeLists.txt"
SERVICE = ROOT / "windows/runner/windows_tunnel_service_main.cpp"


def without_if_zero_blocks(source: str) -> str:
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
    assert disabled_depth == 0, "unterminated #if 0 block"
    return "".join(output)


def function_body(source: str, name: str, next_name: str) -> str:
    start = source.index(name)
    return source[start : source.index(next_name, start)]


def main() -> None:
    raw = SOURCE.read_text(encoding="utf-8")
    active = without_if_zero_blocks(raw)
    header = HEADER.read_text(encoding="utf-8")
    protocol = PROTOCOL.read_text(encoding="utf-8")

    for token in (
        "MULLVADSPLITTUNNEL",
        "mullvad-split-tunnel.sys",
        "WinsVPNSplitTunnel",
        "ToDevicePath(",
        "kWfpProvider",
        "IOCTL_INITIALIZE",
        "IOCTL_REGISTER_PROCESSES",
        "IOCTL_REGISTER_IP_ADDRESSES",
        "IOCTL_SET_CONFIGURATION",
        "IOCTL_RESET",
        "SERVICE_KERNEL_DRIVER",
    ):
        assert token not in active, f"withdrawn runtime token is compiled: {token}"

    prepare = function_body(
        active, "bool PrepareWindowsAppExclusions(", "void StopWindowsAppExclusions()"
    )
    start = function_body(
        active, "bool StartWindowsAppExclusions(", "bool PrepareWindowsAppExclusions("
    )
    for body in (prepare, start):
        assert "if (!executable_paths.empty())" in body
        assert "Windows per-app split tunneling is unsupported" in body
        assert "return false;" in body

    for route_token in (
        "BuildManualRoutePlan(",
        "endpoint_bypass.PrefixLength = 32;",
        "CreateOwnedCarrierRoute(",
        "InstallWindowsTunnelRoutes(",
        "RefreshOwnedPhysicalBypassRoutes(",
        "DeleteIpForwardEntry2(",
    ):
        assert route_token in active, f"destination routing regressed: {route_token}"

    assert "per-app split is\n// explicitly unsupported" in header
    assert "kSplitDriverServiceWaitMilliseconds" not in protocol
    assert "kSplitDriverIoTimeoutMilliseconds" not in protocol

    installer = INSTALLER.read_text(encoding="utf-8").casefold()
    builder = BUILDER.read_text(encoding="utf-8")
    for suffix in ("sys", "cat", "inf"):
        filename = f"mullvad-split-tunnel.{suffix}"
        assert filename not in installer
        assert filename in builder.casefold()
    assert "$affectedSplitTunnelDriverNames = @(" in builder
    assert "function Assert-InnoStagingContainsNoWithdrawnMullvadPayloads {" in builder
    assert "function Get-ContainedInnoStagingFiles {" in builder
    assert "withdrawn kernel split-tunnel bytes, including when renamed" in builder
    assert "Known-affected Mullvad split-tunnel driver 1.3.0.0 must not" in builder
    walker = builder[
        builder.index("function Get-ContainedInnoStagingFiles {") : builder.index(
            "function Assert-InnoStagingPayloadAllowed {"
        )
    ]
    assert "-Recurse" not in walker
    assert "ReparsePoint" in walker

    client = CLIENT.read_text(encoding="utf-8")
    assert "Platform.isWindows\n            ? const <String>[]\n            : _excludedVpnPackages" in client
    cmake = CMAKE.read_text(encoding="utf-8")
    assert '"../test/windows_split_tunnel_carrier_pin_test.cc"' in cmake
    assert "NAME windows_split_tunnel_carrier_pin_test" in cmake
    service = SERVICE.read_text(encoding="utf-8")
    assert "owned route operations" in service
    assert "signed split-driver operations" not in service

    print("Windows withdrawn split-driver policy: PASS")


if __name__ == "__main__":
    main()
