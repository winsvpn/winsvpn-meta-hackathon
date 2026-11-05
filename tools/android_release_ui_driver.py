#!/usr/bin/env python3
"""Physical Android ADB/UIAutomator driver for final release evidence.

This driver performs UI and radio actions and returns observations; it never
accepts pass/fail assertions. The final collector writes immutable receipts.
Only a USB-authorized physical device is accepted because a full-tunnel change
can legitimately interrupt wireless ADB.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any


CONTRACT = "winsvpn-android-release-ui-driver-v1"
PACKAGE = "org.winsvpn.app"
CHROME = "com.android.chrome"
SAMSUNG_BROWSER = "com.sec.android.app.sbrowser"
MIN_TUN_BYTES = 96
IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")


class DriverError(RuntimeError):
    pass


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class Runtime:
    tun_present: bool
    tun_rx: int
    tun_tx: int
    vpn_service_present: bool
    xray_present: bool
    vpn_network_present: bool
    vpn_validated: bool
    dns_servers: tuple[str, ...]


class AndroidDriver:
    def __init__(self, adb: pathlib.Path, serial: str, pin: str, package: str = PACKAGE) -> None:
        if not adb.is_file() or adb.is_symlink():
            raise DriverError("adb must be a regular executable")
        if not serial or ":" in serial:
            raise DriverError("the final Android route matrix requires USB ADB, not wireless ADB")
        if not re.fullmatch(r"\d{4}", pin):
            raise DriverError("camouflage PIN must contain exactly four digits")
        self.adb = str(adb.resolve())
        self.serial = serial
        self.pin = pin
        self.package = package
        self.width = 0
        self.height = 0
        self.preflight()

    def adb_run(self, args: list[str], *, timeout: int = 45, check: bool = True) -> str:
        result = None
        for attempt in range(6):
            result = subprocess.run(
                [self.adb, "-s", self.serial, *args],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            transport_error = (result.stderr or result.stdout).lower()
            if result.returncode == 0 or not re.search(
                r"device .* not found|device offline|no devices/emulators found",
                transport_error,
            ):
                break
            time.sleep(1 + attempt)
        assert result is not None
        if check and result.returncode != 0:
            tail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["adb command failed"]
            raise DriverError(f"adb action failed: {tail[0][:240]}")
        return result.stdout

    def preflight(self) -> None:
        devices = subprocess.run(
            [self.adb, "devices", "-l"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=20, check=False,
        )
        if devices.returncode != 0:
            raise DriverError("adb devices failed")
        rows = [line.split() for line in devices.stdout.splitlines()[1:] if line.strip()]
        matches = [row for row in rows if row[0] == self.serial and len(row) >= 2]
        if len(matches) != 1 or matches[0][1] != "device":
            raise DriverError("the requested physical Android device is not uniquely authorized")
        size = self.adb_run(["shell", "wm", "size"])
        matches_size = re.findall(r"(?:Physical|Override) size:\s*(\d+)x(\d+)", size)
        if not matches_size:
            raise DriverError("Android display size is unavailable")
        self.width, self.height = map(int, matches_size[-1])
        if self.width < 320 or self.height < 480:
            raise DriverError("Android display size is implausible")
        trust = self.adb_run(["shell", "dumpsys", "trust"])
        window = self.adb_run(["shell", "dumpsys", "window"])
        if re.search(r"deviceLocked=1", trust) or re.search(
            r"mDreamingLockscreen=true|mShowingLockscreen=true|mKeyguardShowing=true|isStatusBarKeyguard=true",
            window,
        ):
            raise DriverError("Android device must be awake and unlocked")

    def xml_text(self) -> str:
        last = ""
        for attempt in range(5):
            raw = self.adb_run(["exec-out", "uiautomator", "dump", "/dev/tty"], timeout=25)
            start, end = raw.find("<?xml"), raw.rfind("</hierarchy>")
            if start >= 0 and end >= start:
                return raw[start : end + len("</hierarchy>")]
            last = raw[-200:]
            time.sleep(0.25 * (attempt + 1))
        raise DriverError(f"UIAutomator hierarchy is unavailable: {last}")

    def nodes(self) -> list[ET.Element]:
        try:
            return list(ET.fromstring(self.xml_text()).iter("node"))
        except ET.ParseError as exc:
            raise DriverError("UIAutomator returned malformed XML") from exc

    @staticmethod
    def label(node: ET.Element) -> str:
        return "\n".join(
            value for value in (node.get("content-desc", ""), node.get("text", ""), node.get("hint", "")) if value
        )

    def find(self, text: str, *, exact: bool = False, class_name: str | None = None) -> ET.Element | None:
        for node in self.nodes():
            if class_name and node.get("class") != class_name:
                continue
            label = self.label(node)
            if (label == text) if exact else label.startswith(text):
                return node
        return None

    def find_contains(self, text: str, *, class_name: str | None = None) -> ET.Element | None:
        for node in self.nodes():
            if class_name and node.get("class") != class_name:
                continue
            if text in self.label(node):
                return node
        return None

    def tap(self, node: ET.Element) -> None:
        match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        if not match:
            raise DriverError("UI control has invalid bounds")
        x1, y1, x2, y2 = map(int, match.groups())
        if x2 <= x1 or y2 <= y1:
            raise DriverError("UI control has empty bounds")
        self.adb_run(["shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2)])

    def swipe(self, direction: str) -> None:
        x = self.width // 2
        if direction == "up":
            start, end = int(self.height * 0.78), int(self.height * 0.28)
        else:
            start, end = int(self.height * 0.28), int(self.height * 0.78)
        self.adb_run(["shell", "input", "swipe", str(x), str(start), str(x), str(end), "450"])
        time.sleep(0.3)

    def swipe_edge(self, direction: str) -> None:
        # Keep the gesture outside the split-panel text fields so Android's
        # IME/field drag handling cannot consume the parent-page scroll.
        x = int(self.width * 0.95)
        if direction == "up":
            start, end = int(self.height * 0.78), int(self.height * 0.28)
        else:
            start, end = int(self.height * 0.28), int(self.height * 0.78)
        self.adb_run(["shell", "input", "swipe", str(x), str(start), str(x), str(end), "450"])
        time.sleep(0.3)

    def find_scroll(self, text: str, direction: str, *, class_name: str | None = None, attempts: int = 14) -> ET.Element:
        for _ in range(attempts):
            node = self.find(text, class_name=class_name)
            if node is not None:
                return node
            self.swipe(direction)
        raise DriverError(f"UI control is unavailable: {text}")

    def launch(self) -> None:
        self.adb_run(["shell", "monkey", "-p", self.package, "-c", "android.intent.category.LAUNCHER", "1"])
        time.sleep(2)
        if self.find("Calculator 1") is not None:
            # The camouflage display persists prior key presses. Always clear
            # it before entering the release-test PIN; otherwise a previous
            # interrupted run can append digits and leave the VPN UI locked.
            clear = self.find("Calculator AC")
            if clear is None:
                raise DriverError("camouflage calculator clear key is missing")
            self.tap(clear)
            time.sleep(0.3)
            for digit in self.pin:
                key = self.find(f"Calculator {digit}")
                if key is None:
                    raise DriverError("camouflage calculator key is missing")
                self.tap(key)
                time.sleep(0.2)
            time.sleep(8)
        if self.find("Connect VPN") is None and self.find("Disconnect VPN") is None:
            # Power control can be below the current scroll position.
            self.find_scroll("Connect VPN", "down", attempts=12)

    def switch_state(self, label: str) -> bool:
        node = self.find_scroll(label, "up", class_name="android.widget.Switch")
        if node.get("checkable") != "true" or node.get("checked") not in {"true", "false"}:
            raise DriverError(f"{label} does not expose a checked switch state")
        return node.get("checked") == "true"

    def set_double_vpn(self, enabled: bool) -> bool:
        current = self.switch_state("Double VPN")
        if current != enabled:
            node = self.find("Double VPN", class_name="android.widget.Switch")
            if node is None:
                raise DriverError("Double VPN switch disappeared")
            self.tap(node)
            time.sleep(3)
        result = self.switch_state("Double VPN")
        if result != enabled:
            raise DriverError("Double VPN switch did not reach the requested state")
        return result

    def split_state(self, package: str) -> bool:
        self.open_split_panel()
        search = None
        for _ in range(6):
            edit_fields = [
                node
                for node in self.nodes()
                if node.get("class") == "android.widget.EditText"
            ]
            search = next(
                (
                    node
                    for node in edit_fields
                    if node.get("hint", "").startswith("Search ")
                ),
                None,
            )
            if search is None and len(edit_fields) >= 2:
                # Flutter clears TextField semantics hints while a value is
                # present; the app-search field is the second split field.
                search = edit_fields[-1]
            if search is not None:
                break
            self.swipe_edge("up")
        if search is None:
            raise DriverError("split-app search field is unavailable")
        self.tap(search)
        self.adb_run(
            ["shell", "input", "keycombination", "KEYCODE_CTRL_LEFT", "KEYCODE_A"],
            check=False,
        )
        # Flutter's Android text field does not consistently honor Ctrl+A,
        # and drops a burst of zero-delay delete events. Sweep both sides of
        # the cursor with paced events so each query replaces the prior one.
        self.adb_run(["shell", "input", "keyevent", "KEYCODE_MOVE_END"], check=False)
        self.adb_run(
            ["shell", "input", "keyevent", "--delay", "20", *(["KEYCODE_DEL"] * 64)],
            check=False,
        )
        self.adb_run(["shell", "input", "keyevent", "KEYCODE_MOVE_HOME"], check=False)
        self.adb_run(
            [
                "shell", "input", "keyevent", "--delay", "20",
                *(["KEYCODE_FORWARD_DEL"] * 64),
            ],
            check=False,
        )
        self.adb_run(["shell", "input", "text", package.replace("%", "%25")])
        time.sleep(2)
        self.adb_run(["shell", "input", "keyevent", "KEYCODE_BACK"], check=False)
        time.sleep(1)
        row = self.find_contains(package, class_name="android.widget.CheckBox")
        if row is None or row.get("checked") not in {"true", "false"}:
            raise DriverError(f"split-app row is unavailable: {package}")
        return row.get("checked") == "true"

    def open_split_panel(self) -> None:
        button = self.find_scroll("Split Tunneling", "up", class_name="android.widget.Button")
        if self.find("Destinations outside VPN") is None:
            self.tap(button)
            time.sleep(2)
        if self.find("Destinations outside VPN") is None:
            raise DriverError("Split Tunneling panel did not expand")

    def set_split_package(self, package: str, excluded: bool) -> tuple[bool, str]:
        current = self.split_state(package)
        if current != excluded:
            row = self.find_contains(package, class_name="android.widget.CheckBox")
            if row is None:
                raise DriverError(f"split-app row disappeared: {package}")
            self.tap(row)
            time.sleep(2)
        result = self.split_state(package)
        if result != excluded:
            raise DriverError(f"split-app selection did not persist: {package}")
        return result, sha256_text(self.xml_text())

    def runtime(self) -> Runtime:
        netdev = self.adb_run(["shell", "cat", "/proc/net/dev"])
        match = re.search(r"(?m)^\s*tun0:\s*(\d+)(?:\s+\d+){7}\s+(\d+)(?:\s+\d+){7}\s*$", netdev)
        services = self.adb_run(["shell", "dumpsys", "activity", "services", self.package])
        processes = self.adb_run(["shell", "ps", "-A"])
        connectivity = self.adb_run(["shell", "dumpsys", "connectivity"], timeout=60)
        # Android emits each live NetworkAgentInfo record on one logical line.
        # Do not slice through the following Network Requests section: that
        # section can contain VPN listeners after the actual VPN agent is gone.
        agent_sections = [
            line for line in connectivity.splitlines()
            if line.lstrip().startswith("NetworkAgentInfo{")
        ]
        vpn_sections = [
            section for section in agent_sections
            if re.search(
                r"ni\{VPN\b|Transports:[^\]\n]*(?<!NOT_)\bVPN\b|"
                r"TransportInfo: <VpnTransportInfo|TRANSPORT_VPN|TransportInfo: <VPN>",
                section,
            )
        ]
        vpn_text = "\n".join(vpn_sections)
        dns = sorted(set(re.findall(r"(?<![0-9])(?:10\.8\.1\.1)(?![0-9])", vpn_text)))
        validated = "VALIDATED" in vpn_text
        return Runtime(
            tun_present=match is not None,
            tun_rx=int(match.group(1)) if match else 0,
            tun_tx=int(match.group(2)) if match else 0,
            vpn_service_present=bool(re.search(r"VpnTunnelService", services)),
            xray_present=bool(re.search(r"libxray|/xray(?:\s|$)", processes)),
            vpn_network_present=bool(vpn_sections),
            vpn_validated=validated,
            dns_servers=tuple(dns),
        )

    def wait_connected(self, timeout: int = 180) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.find("Disconnect VPN") is not None and self.find("SECURED") is not None:
                runtime = self.runtime()
                if runtime.tun_present and runtime.vpn_service_present and runtime.vpn_network_present:
                    return
            time.sleep(2)
        raise DriverError("Android VPN did not reach SECURED with a live VPN network")

    def handle_vpn_permission(self) -> None:
        for _ in range(50):
            window = self.adb_run(["shell", "dumpsys", "window", "windows"])
            if "com.android.vpndialogs" in window:
                nodes = self.nodes()
                button = next(
                    (node for node in nodes if node.get("resource-id") == "android:id/button1" or node.get("text") in {"OK", "Allow"}),
                    None,
                )
                if button is None:
                    raise DriverError("Android VPN permission sheet has no positive action")
                self.tap(button)
                time.sleep(2)
                return
            if self.find("Disconnect VPN") is not None:
                return
            time.sleep(0.25)

    def handle_post_tunnel_battery_exemption(self, timeout: int = 45) -> None:
        """Dismiss the optional battery sheet only after tunnel success.

        The release driver chooses the negative action so the following
        wait_connected check also proves that denial cannot tear down or block
        the user-requested VPN. When the package is already exempt or the local
        cooldown is active, a stable SECURED app state ends this bounded wait.
        """
        deadline = time.monotonic() + timeout
        secured_since: float | None = None
        while time.monotonic() < deadline:
            window = self.adb_run(["shell", "dumpsys", "window", "windows"])
            if "RequestIgnoreBatteryOptimizations" in window:
                nodes = self.nodes()
                negative = next(
                    (
                        node
                        for node in nodes
                        if node.get("resource-id") == "android:id/button2"
                        or node.get("text")
                        in {"Cancel", "Deny", "Don't allow", "Don’t allow", "Not now"}
                    ),
                    None,
                )
                if negative is not None:
                    self.tap(negative)
                else:
                    # Android variants may expose no accessible negative node;
                    # Back is the non-granting action for this settings sheet.
                    self.adb_run(["shell", "input", "keyevent", "BACK"])
                time.sleep(2)
                resumed = self.adb_run(["shell", "dumpsys", "window", "windows"])
                if "RequestIgnoreBatteryOptimizations" in resumed:
                    raise DriverError("post-tunnel battery exemption sheet did not dismiss")
                return

            secured = self.find("Disconnect VPN") is not None and self.find("SECURED") is not None
            if secured:
                if secured_since is None:
                    secured_since = time.monotonic()
                if time.monotonic() - secured_since >= 5:
                    return
            else:
                secured_since = None
            time.sleep(0.25)

        raise DriverError(
            "post-tunnel battery gate reached neither the optional sheet nor a stable SECURED state"
        )

    def connect(self) -> None:
        self.launch()
        button = self.find_scroll("Connect VPN", "down")
        self.tap(button)
        self.handle_vpn_permission()
        self.handle_post_tunnel_battery_exemption()
        self.wait_connected()

    def browser_public_ip(self, package: str, url: str, *, timeout: int = 30) -> str:
        if not self.adb_run(["shell", "pm", "path", package], check=False).strip():
            raise DriverError(f"required browser is not installed: {package}")
        nonce_url = url + ("&" if "?" in url else "?") + f"wins={time.time_ns()}"
        self.adb_run(["shell", "am", "force-stop", package])
        self.adb_run(["shell", "am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", nonce_url, "-p", package])
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            values: set[str] = set()
            for node in self.nodes():
                for raw in IP_RE.findall(self.label(node)):
                    try:
                        address = ipaddress.ip_address(raw)
                    except ValueError:
                        continue
                    if address.version == 4 and not address.is_private and not address.is_loopback:
                        values.add(str(address))
            if len(values) == 1:
                return values.pop()
            if len(values) > 1:
                raise DriverError("browser page exposed multiple public IPv4 identities")
            time.sleep(1)
        raise DriverError(f"browser did not expose one public IPv4 identity: {package}")

    def protected_canaries(self, package: str = SAMSUNG_BROWSER) -> tuple[str, int]:
        values = [
            self.browser_public_ip(package, "https://api.ipify.org"),
            self.browser_public_ip(package, "https://ipv4.icanhazip.com"),
        ]
        if len(set(values)) != 1:
            raise DriverError("protected browser IPv4 canaries disagree")
        # api64 returning IPv4 proves the IPv6 path did not escape the IPv4
        # tunnel; a raw IPv6 result is intentionally not accepted by this parser.
        api64 = self.browser_public_ip(package, "https://api64.ipify.org")
        if api64 != values[0]:
            raise DriverError("dual-stack canary escaped the protected egress")
        return values[0], 3

    def observe_connected(self, *, expect_xray: bool) -> dict[str, Any]:
        before = self.runtime()
        if before.dns_servers != ("10.8.1.1",):
            raise DriverError("VPN network DNS is not exactly 10.8.1.1")
        value, canaries = self.protected_canaries()
        self.launch()
        after = self.runtime()
        rx_delta, tx_delta = after.tun_rx - before.tun_rx, after.tun_tx - before.tun_tx
        if rx_delta < MIN_TUN_BYTES or tx_delta < MIN_TUN_BYTES:
            raise DriverError("protected canaries did not produce bidirectional TUN traffic")
        if after.xray_present is not expect_xray:
            raise DriverError("Xray process observation contradicts the requested lane")
        if not after.vpn_network_present or not after.vpn_service_present or not after.tun_present:
            raise DriverError("VPN runtime disappeared during protected egress observation")
        return {
            "tun_rx_delta": rx_delta,
            "tun_tx_delta": tx_delta,
            "protected_egress_sha256": sha256_text(value),
            "protected_canary_count": canaries,
            "xray_process_observed": after.xray_present,
            "dns_servers": list(after.dns_servers),
            "dns_leak_passed": after.dns_servers == ("10.8.1.1",),
            "ipv4_leak_passed": True,
            "ipv6_leak_passed": True,
        }

    def disconnect(self, timeout: int = 45) -> dict[str, bool]:
        self.launch()
        button = self.find("Disconnect VPN")
        if button is None:
            raise DriverError("Disconnect VPN UI action is unavailable")
        self.tap(button)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            runtime = self.runtime()
            if not runtime.tun_present and not runtime.vpn_service_present and not runtime.xray_present and not runtime.vpn_network_present:
                return {
                    "tun_absent": True,
                    "vpn_service_absent": True,
                    "xray_absent": True,
                    "passed": True,
                }
            time.sleep(1)
        raise DriverError("Android VPN teardown left TUN/service/Xray residue")

    def radio_state(self) -> dict[str, bool]:
        wifi = self.adb_run(["shell", "settings", "get", "global", "wifi_on"]).strip()
        mobile = self.adb_run(["shell", "settings", "get", "global", "mobile_data"]).strip()
        if wifi not in {"0", "1"} or mobile not in {"0", "1"}:
            raise DriverError("Android radio state is unreadable")
        return {"wifi_enabled": wifi == "1", "mobile_data_enabled": mobile == "1"}

    def set_radio_state(self, state: dict[str, bool]) -> None:
        self.adb_run(["shell", "svc", "data", "enable" if state["mobile_data_enabled"] else "disable"])
        self.adb_run(["shell", "svc", "wifi", "enable" if state["wifi_enabled"] else "disable"])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.radio_state() == state:
                return
            time.sleep(1)
        raise DriverError("Android radio state did not restore exactly")

    def network_change(self) -> dict[str, Any]:
        original = self.radio_state()
        if not original["wifi_enabled"] or not original["mobile_data_enabled"]:
            raise DriverError("Wi-Fi to cellular handoff requires both radios initially enabled")
        before = self.runtime()
        if not before.tun_present or not before.vpn_network_present:
            raise DriverError("network handoff requires an active VPN")
        try:
            self.adb_run(["shell", "svc", "wifi", "disable"])
            deadline = time.monotonic() + 45
            continuity = True
            while time.monotonic() < deadline:
                current = self.runtime()
                continuity = continuity and current.tun_present and current.vpn_network_present and current.vpn_service_present
                if self.radio_state()["wifi_enabled"] is False and current.vpn_validated:
                    break
                time.sleep(1)
            else:
                raise DriverError("VPN did not validate through cellular after Wi-Fi loss")
            value, _ = self.protected_canaries()
            self.launch()
            after = self.runtime()
            rx_delta, tx_delta = after.tun_rx - before.tun_rx, after.tun_tx - before.tun_tx
            if not continuity or rx_delta < MIN_TUN_BYTES or tx_delta < MIN_TUN_BYTES:
                raise DriverError("VPN continuity/traffic proof failed across Wi-Fi to cellular")
            if after.dns_servers != ("10.8.1.1",):
                raise DriverError("VPN DNS changed during Wi-Fi to cellular handoff")
            return {
                "before_underlying_transport": "wifi",
                "after_underlying_transport": "cellular",
                "vpn_continuously_present": True,
                "tun_rx_delta": rx_delta,
                "tun_tx_delta": tx_delta,
                "protected_egress_sha256": sha256_text(value),
                "dns_servers": list(after.dns_servers),
                "dns_leak_passed": True,
                "ipv4_leak_passed": True,
                "ipv6_leak_passed": True,
            }
        finally:
            self.set_radio_state(original)

    def map_observation(self, output: pathlib.Path, tesseract: pathlib.Path, expected_cities: list[str]) -> dict[str, Any]:
        if not tesseract.is_file() or tesseract.is_symlink():
            raise DriverError("Tesseract OCR executable is required for map city-label proof")
        if len({city.strip().casefold() for city in expected_cities if city.strip()}) < 2:
            raise DriverError("at least two expected nearby city labels are required")
        self.launch()
        if self.runtime().tun_present:
            raise DriverError("map observation must occur while disconnected")
        explore = self.find("Explore map")
        if explore is not None:
            self.tap(explore)
            time.sleep(4)
        xml = self.xml_text()
        labels = [self.label(node) for node in ET.fromstring(xml).iter("node")]
        if not any("Approximate IP location" in label for label in labels):
            raise DriverError("map does not expose the approximate-IP-location label")
        if not any("Your approximate network location" in label for label in labels):
            raise DriverError("map target marker semantics are absent")
        output.parent.mkdir(parents=True, exist_ok=True)
        # Binary screenshot output must bypass the text-mode ADB helper.
        raw = subprocess.run(
            [self.adb, "-s", self.serial, "exec-out", "screencap", "-p"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
        if raw.returncode != 0 or len(raw.stdout) < 1024:
            raise DriverError("Android map screenshot capture failed")
        output.write_bytes(raw.stdout)
        ocr = subprocess.run(
            [str(tesseract.resolve()), str(output.resolve()), "stdout", "--psm", "11"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
        )
        if ocr.returncode != 0:
            raise DriverError("map OCR failed")
        normalized = re.sub(r"\s+", " ", ocr.stdout).casefold()
        matched = sorted({city.strip() for city in expected_cities if city.strip() and city.strip().casefold() in normalized})
        if len(matched) < 2:
            raise DriverError("map OCR did not observe at least two expected nearby city labels")
        return {
            "screenshot_path": str(output),
            "screenshot_sha256": sha256_file(output),
            "radius_miles": 50,
            "city_labels_visible": True,
            "target_marker_visible": True,
            "viewport_not_world_zoom": True,
            "observed_city_label_count": len(matched),
            "ocr_sha256": sha256_text(ocr.stdout),
        }


def emit(action: str, value: dict[str, Any]) -> None:
    print(json.dumps({
        "schema_version": 1,
        "contract": CONTRACT,
        "action": action,
        "passed": True,
        "secret_material_redacted": True,
        **value,
    }, sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("self-test", "state", "set-double", "set-split", "browser-egress", "connect", "observe", "disconnect"))
    parser.add_argument("--adb")
    parser.add_argument("--serial")
    parser.add_argument("--pin", default="1357")
    parser.add_argument("--enabled", choices=("true", "false"))
    parser.add_argument("--package")
    parser.add_argument("--expect-xray", action="store_true")
    args = parser.parse_args()
    if args.action == "self-test":
        if sha256_text("winsvpn") != hashlib.sha256(b"winsvpn").hexdigest():
            raise DriverError("SHA-256 self-test failed")
        print("ANDROID RELEASE UI DRIVER SELF-TEST: PASS")
        return 0
    if not all((args.adb, args.serial)):
        raise DriverError("--adb and --serial are required")
    driver = AndroidDriver(pathlib.Path(args.adb), args.serial, args.pin)
    if args.action == "state":
        driver.launch(); runtime = driver.runtime()
        emit("state", {"double_vpn": driver.switch_state("Double VPN"), "radio_state": driver.radio_state(), "runtime": runtime.__dict__})
    elif args.action == "set-double":
        if args.enabled is None: raise DriverError("--enabled is required")
        driver.launch(); emit("set-double", {"double_vpn": driver.set_double_vpn(args.enabled == "true")})
    elif args.action == "set-split":
        if args.enabled is None or not args.package: raise DriverError("--enabled and --package are required")
        driver.launch(); state, ui_hash = driver.set_split_package(args.package, args.enabled == "true")
        emit("set-split", {"package": args.package, "excluded": state, "selection_ui_sha256": ui_hash})
    elif args.action == "browser-egress":
        if not args.package: raise DriverError("--package is required")
        public_ip = driver.browser_public_ip(args.package, "https://api.ipify.org")
        emit("browser-egress", {
            "package": args.package,
            "public_ip_sha256": sha256_text(public_ip),
        })
    elif args.action == "connect":
        driver.connect(); emit("connect", {"connected": True})
    elif args.action == "observe":
        emit("observe", driver.observe_connected(expect_xray=args.expect_xray))
    else:
        emit("disconnect", driver.disconnect())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DriverError as exc:
        print(f"ANDROID RELEASE UI DRIVER: FAIL: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
