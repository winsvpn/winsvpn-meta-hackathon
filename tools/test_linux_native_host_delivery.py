#!/usr/bin/env python3
"""Isolated Linux native-messaging delivery contracts.

Proves executable mode, exact installed host paths, Chrome/Edge/Firefox
registration through the authenticated installed host, distinct recorded
Edge identity (refused if absent or reused), fail-closed rollback,
uninstall of system and per-user Edge destinations, and wrong-path rejection
without touching the live machine, network, or stores.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = pathlib.Path(__file__).resolve().parent
INSTALLER = ROOT / "linux/packaging/install.sh"
BOOTSTRAP = ROOT / "linux/packaging/install-winsvpn-linux.sh"
NATIVE_INSTALLER = ROOT / "tools/native_messaging/install_native_host.sh"
PRODUCER = ROOT / "tools/build_linux_release.sh"
GATE = ROOT / "tools/linux_cross_store_artifact_gate.py"
CHROME_ID = "abcdefghijklmnopabcdefghijklmnop"
EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
SYSTEM_EDGE_DIR = "/etc/opt/edge/native-messaging-hosts"
USER_EDGE_REL = ".config/microsoft-edge/NativeMessagingHosts"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import tools.linux_cross_store_artifact_gate as gate


PRODUCER_SOURCE_PATHS = (
    "extension/manifest/firefox.jsonc",
    "extension/tools/jsonc.py",
    "lib/browser_bridge_app_ipc.dart",
    "lib/browser_bridge_framing.dart",
    "lib/browser_bridge_protocol.dart",
    "lib/browser_bridge_proxy.dart",
    "lib/vpn_config_validation.dart",
    "lib/windows_system_executable.dart",
    "lib/winn_carrier_profile_keys.dart",
    "lib/winn_protocol_dispatch.dart",
    "tools/native_messaging/host/bin/wins_bridge_host.dart",
    "tools/native_messaging/host/pubspec.lock",
    "tools/native_messaging/host/pubspec.yaml",
    "tools/native_messaging/install_native_host.sh",
    "tools/native_messaging/manifests/store_ids.json",
    "tools/native_messaging/native_host_layout.py",
    "tools/native_messaging/render_host_manifest.py",
)


def _packaged_native_tree(root: pathlib.Path, store_ids: dict[str, str] | None) -> pathlib.Path:
    """Copy the packaged native-host tools with a chosen store id record."""
    packaged = root / "pkg"
    native = packaged / "tools/native_messaging"
    (native / "host").mkdir(parents=True)
    (native / "manifests").mkdir()
    (packaged / "extension/tools").mkdir(parents=True)
    (packaged / "extension/manifest").mkdir(parents=True)
    for name in (
        "install_native_host.sh",
        "native_host_layout.py",
        "render_host_manifest.py",
    ):
        (native / name).write_bytes((ROOT / "tools/native_messaging" / name).read_bytes())
    (native / "install_native_host.sh").chmod(0o755)
    for relative in ("extension/tools/jsonc.py", "extension/manifest/firefox.jsonc"):
        (packaged / relative).write_bytes((ROOT / relative).read_bytes())
    for directory in (native, native / "manifests"):
        directory.chmod(0o755)
    if store_ids is not None:
        record = native / "manifests/store_ids.json"
        record.write_text(json.dumps(store_ids, sort_keys=True) + "\n", encoding="ascii")
        record.chmod(0o644)
    return native / "install_native_host.sh"


def _run_native_installer(
    installer: pathlib.Path, root: pathlib.Path, browser: str, manifests: pathlib.Path
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("WINSVPN_CHROME_STORE_ID", None)
    env.pop("WINSVPN_EDGE_STORE_ID", None)
    host = root / "wins_bridge_host"
    if not host.exists():
        host.write_text(
            "#!/bin/sh\n"
            "exec python3 -c "
            "'import json,struct,sys;"
            "header=sys.stdin.buffer.read(4);"
            "n=struct.unpack(\"<I\",header)[0] if len(header)==4 else 0;"
            "sys.stdin.buffer.read(n);"
            "body=json.dumps({\"type\":\"hello\",\"protocolVersion\":1,"
            "\"platform\":\"test\",\"status\":\"app_not_running\"}).encode();"
            "sys.stdout.buffer.write(struct.pack(\"<I\",len(body))+body)'\n",
            encoding="ascii",
        )
        host.chmod(0o755)
    manifests.mkdir(parents=True, exist_ok=True)
    (root / "lib").mkdir(exist_ok=True)
    return subprocess.run(
        [
            "bash",
            str(installer),
            "--host-path",
            str(host),
            "--dest-dir",
            str(root / "lib"),
            "--manifest-dir",
            str(manifests),
            browser,
        ],
        cwd=root,
        env=env,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _producer_source_paths() -> tuple[str, ...]:
    source = PRODUCER.read_text(encoding="utf-8")
    function = source.split("native_host_source_paths() {", 1)[1].split("\n}", 1)[0]
    paths = tuple(
        sorted(re.findall(r"\s+((?:extension|lib|tools)/[^ \\\n]+)", function))
    )
    return paths


def _producer_closure_pin() -> str:
    source = PRODUCER.read_text(encoding="utf-8")
    match = re.search(
        r'^NATIVE_HOST_SOURCE_CLOSURE_SHA256="([0-9a-f]{64})"$',
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError("Linux producer is missing the native-host source-closure pin")
    return match.group(1)


def _live_source_closure() -> tuple[str, list[dict[str, object]]]:
    records = []
    for relative in _producer_source_paths():
        payload = (ROOT / relative).read_bytes()
        records.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    encoded = (
        json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest(), records


class LinuxNativeHostSourceClosureTests(unittest.TestCase):
    def test_producer_and_verifier_source_closures_match_exactly(self) -> None:
        producer_paths = _producer_source_paths()
        verifier_paths = gate.native_host_source_paths()
        self.assertEqual(producer_paths, PRODUCER_SOURCE_PATHS)
        self.assertEqual(verifier_paths, PRODUCER_SOURCE_PATHS)
        self.assertIn("extension/manifest/firefox.jsonc", verifier_paths)
        self.assertIn("extension/tools/jsonc.py", verifier_paths)
        self.assertIn(
            "tools/native_messaging/manifests/store_ids.json", verifier_paths
        )
        digest, _records = _live_source_closure()
        live_gate = gate.compute_native_host_source_closure()
        self.assertEqual(live_gate[0], digest)
        self.assertEqual(
            [record["path"] for record in live_gate[1]], list(PRODUCER_SOURCE_PATHS)
        )
        # Pack-time pin refresh is a separate freeze lane. Do not compare
        # _producer_closure_pin() to the live digest here.

    def test_gate_refuses_to_hardcode_the_producer_pin(self) -> None:
        gate_source = GATE.read_text(encoding="utf-8")
        self.assertNotIn(_producer_closure_pin(), gate_source)
        self.assertIn("extension/manifest/firefox.jsonc", gate_source)
        self.assertIn("extension/tools/jsonc.py", gate_source)

    def test_packaged_store_identity_inputs_remain_mandatory(self) -> None:
        self.assertIn(
            "tools/native_messaging/manifests/store_ids.json",
            gate.NATIVE_HOST_PACKAGED_ASSETS,
        )
        self.assertIn(
            "tools/native_messaging/manifests/store_ids.json",
            gate.NATIVE_HOST_PACKAGED_IDENTITY_INPUTS,
        )
        self.assertIn("extension/manifest/firefox.jsonc", gate.NATIVE_HOST_PACKAGED_ASSETS)
        self.assertIn("extension/tools/jsonc.py", gate.NATIVE_HOST_PACKAGED_ASSETS)
        producer = PRODUCER.read_text(encoding="utf-8")
        self.assertIn('recorded-id --browser chrome', producer)
        self.assertIn('recorded-id --browser edge', producer)
        self.assertIn("org.winsvpn.bridge.edge.json", producer)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('chrome "$chrome_id" || {', installer)
        self.assertIn('edge "$edge_id" || {', installer)
        self.assertIn('firefox || {', installer)
        chrome_register = installer.index('chrome "$chrome_id" || {')
        edge_register = installer.index('edge "$edge_id" || {')
        firefox_register = installer.index('firefox || {')
        self.assertLess(chrome_register, edge_register)
        self.assertLess(edge_register, firefox_register)
        self.assertIn("NATIVE_HOST_EDGE_MANIFEST_DIR=/etc/opt/edge/native-messaging-hosts", installer)
        self.assertIn(USER_EDGE_REL, installer)
        self.assertIn("org.winsvpn.bridge.edge.json", installer)
        self.assertIn("owner-blocked", installer)
        self.assertIn("must be distinct", installer)
        self.assertIn('edge "$edge_id" || {', installer)
        self.assertIn("--manifest-dir \"$edge_dir\" edge \"$edge_id\"", installer)


class LinuxNativeHostIsolatedInstallTests(unittest.TestCase):
    def test_install_sh_isolated_filesystem_delivery(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-native-host-delivery-") as raw:
            prefix = pathlib.Path(raw)
            completed = subprocess.run(
                [
                    "bash",
                    str(INSTALLER),
                    "--self-test-native-host-delivery",
                    str(prefix),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("NATIVE-HOST DELIVERY SELF-TEST: PASS", completed.stdout)
        self.assertIn("executable mode restored", completed.stdout)
        self.assertIn("Chrome, Firefox, and Edge registered", completed.stdout)
        self.assertIn("native-host rollback restored previous registration", completed.stdout)
        self.assertIn("wrong packaged host path was rejected", completed.stdout)
        self.assertIn("required installed path", completed.stdout)
        self.assertIn("native-host rollback failed closed", completed.stdout)
        self.assertIn("missing Edge store identity was owner-blocked", completed.stdout)
        self.assertIn("reused Chrome/Edge store identity was owner-blocked", completed.stdout)
        self.assertIn("owner-blocked missing Edge identity left host and manifests untouched", completed.stdout)
        self.assertIn("owner-blocked reused Edge identity left host and manifests untouched", completed.stdout)
        self.assertIn("placeholder Edge store identity was owner-blocked", completed.stdout)
        self.assertIn("extra JSON keys in store identity were rejected", completed.stdout)
        self.assertIn("duplicate JSON keys in store identity were rejected", completed.stdout)
        self.assertIn("native-host rollback restored the Firefox manifest", completed.stdout)
        self.assertIn("native-host rollback restored a mid-Edge failure", completed.stdout)
        self.assertIn("preexisting native-host symlink dest was refused", completed.stdout)
        self.assertIn("preexisting native-host directory dest was refused", completed.stdout)
        self.assertIn("overlay inner symlink dests were refused", completed.stdout)
        self.assertIn("symlink overlay prefix with /. was refused", completed.stdout)
        self.assertIn("inner-symlink/.. overlay prefix was refused", completed.stdout)
        self.assertIn("root overlay prefix / was refused", completed.stdout)
        self.assertIn("hardlinked rollback destination was refused", completed.stdout)
        self.assertIn("overlay native-host delivery verified", completed.stdout)
        self.assertIn("per-user Edge registered", completed.stdout)
        self.assertIn("native-host uninstall removed system and per-user Edge registration", completed.stdout)
        self.assertIn("native-host uninstall removed system and per-user Chrome, Firefox, and Edge registration", completed.stdout)
        self.assertIn(USER_EDGE_REL, completed.stdout)

    def test_install_native_host_rejects_wrong_required_path_without_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-native-host-require-") as raw:
            root = pathlib.Path(raw)
            host = root / "wins_bridge_host"
            host.write_text(
                "#!/bin/sh\n"
                "exec python3 -c "
                "'import json,struct,sys;"
                "header=sys.stdin.buffer.read(4);"
                "n=struct.unpack(\"<I\",header)[0] if len(header)==4 else 0;"
                "sys.stdin.buffer.read(n);"
                "body=json.dumps({\"type\":\"hello\",\"protocolVersion\":1,"
                "\"platform\":\"test\",\"status\":\"app_not_running\"}).encode();"
                "sys.stdout.buffer.write(struct.pack(\"<I\",len(body))+body)'\n",
                encoding="ascii",
            )
            host.chmod(0o755)
            dest = root / "wrong-lib"
            manifests = root / "chrome"
            dest.mkdir()
            manifests.mkdir()
            completed = subprocess.run(
                [
                    "bash",
                    str(NATIVE_INSTALLER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(dest),
                    "--manifest-dir",
                    str(manifests),
                    "--require-installed-path",
                    str(root / "usr/lib/wins-vpn/wins_bridge_host"),
                    "chrome",
                    CHROME_ID,
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("required installed path", completed.stderr)
            self.assertEqual(list(dest.iterdir()), [])
            self.assertEqual(list(manifests.iterdir()), [])

    def test_missing_firefox_fragment_fails_closed_before_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-native-host-firefox-") as raw:
            root = pathlib.Path(raw)
            packaged = root / "pkg"
            native = packaged / "tools/native_messaging"
            native.mkdir(parents=True)
            (packaged / "extension/tools").mkdir(parents=True)
            (packaged / "extension/manifest").mkdir(parents=True)
            (native / "host").mkdir()
            (native / "manifests").mkdir()
            for name in (
                "install_native_host.sh",
                "native_host_layout.py",
                "render_host_manifest.py",
            ):
                (native / name).write_bytes((ROOT / "tools/native_messaging" / name).read_bytes())
            (native / "install_native_host.sh").chmod(0o755)
            (packaged / "extension/tools/jsonc.py").write_bytes(
                (ROOT / "extension/tools/jsonc.py").read_bytes()
            )
            host = native / "host/wins_bridge_host"
            host.write_bytes((ROOT / "tools/test_linux_native_host_delivery.py").read_bytes()[:0])
            host.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            host.chmod(0o755)
            dest = root / "lib"
            manifests = root / "firefox"
            dest.mkdir()
            manifests.mkdir()
            completed = subprocess.run(
                [
                    "bash",
                    str(native / "install_native_host.sh"),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(dest),
                    "--manifest-dir",
                    str(manifests),
                    "firefox",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("firefox.jsonc", completed.stderr)
            self.assertEqual(list(dest.iterdir()), [])
            self.assertEqual(list(manifests.iterdir()), [])

    def test_missing_chrome_store_identity_fails_closed_before_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-native-host-chrome-id-") as raw:
            root = pathlib.Path(raw)
            installer = _packaged_native_tree(root, {"edge": EDGE_ID})
            manifests = root / "chrome"
            completed = _run_native_installer(installer, root, "chrome", manifests)
            self.assertEqual(completed.returncode, 78, completed.stderr)
            self.assertIn("chrome store-listing id is missing", completed.stderr)
            self.assertIn("manifests/store_ids.json", completed.stderr)
            self.assertEqual(list((root / "lib").iterdir()), [])
            self.assertEqual(list(manifests.iterdir()), [])

    def test_missing_edge_store_identity_fails_closed_before_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-native-host-edge-id-") as raw:
            root = pathlib.Path(raw)
            installer = _packaged_native_tree(root, {"chrome": CHROME_ID})
            manifests = root / "edge"
            completed = _run_native_installer(installer, root, "edge", manifests)
            self.assertEqual(completed.returncode, 78, completed.stderr)
            self.assertIn("edge store-listing id is missing", completed.stderr)
            self.assertIn("manifests/store_ids.json", completed.stderr)
            self.assertEqual(list((root / "lib").iterdir()), [])
            self.assertEqual(list(manifests.iterdir()), [])

    def test_absent_edge_id_still_registers_chrome_and_firefox(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-native-host-partial-id-") as raw:
            root = pathlib.Path(raw)
            installer = _packaged_native_tree(root, {"chrome": CHROME_ID})
            chrome = _run_native_installer(installer, root, "chrome", root / "chrome")
            self.assertEqual(chrome.returncode, 0, chrome.stderr)
            payload = json.loads(
                (root / "chrome/org.winsvpn.bridge.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["allowed_origins"], [f"chrome-extension://{CHROME_ID}/"])
            firefox = _run_native_installer(installer, root, "firefox", root / "firefox")
            self.assertEqual(firefox.returncode, 0, firefox.stderr)
            payload = json.loads(
                (root / "firefox/org.winsvpn.bridge.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["allowed_extensions"], ["companion@winsvpn.org"])
            edge = _run_native_installer(installer, root, "edge", root / "edge")
            self.assertEqual(edge.returncode, 78, edge.stderr)
            self.assertIn("edge store-listing id is missing", edge.stderr)
            self.assertEqual(list((root / "edge").iterdir()), [])

    def test_unsafe_packaged_store_id_record_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-native-host-unsafe-id-") as raw:
            root = pathlib.Path(raw)
            installer = _packaged_native_tree(root, {"chrome": CHROME_ID, "edge": EDGE_ID})
            record = installer.parent / "manifests/store_ids.json"
            record.chmod(0o666)
            completed = _run_native_installer(installer, root, "chrome", root / "chrome")
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("group- or world-writable", completed.stderr)
            self.assertEqual(list((root / "lib").iterdir()), [])
            self.assertEqual(list((root / "chrome").iterdir()), [])

    def test_linux_install_restores_executable_mode_after_chmod_0644(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        chmod_all = installer.index('find "$stage" -type f -exec chmod 0644')
        restore = installer.index("restore_native_host_executable_modes \"$stage\"")
        self.assertLess(chmod_all, restore)
        self.assertIn("restore_native_host_executable_modes \"$stage\"", installer)
        self.assertIn("NATIVE_HOST_BUNDLE_REL=tools/native_messaging/host/wins_bridge_host", installer)
        self.assertIn("NATIVE_HOST_SYSTEM_PATH=/usr/lib/wins-vpn/wins_bridge_host", installer)
        self.assertEqual(gate.NATIVE_HOST_INSTALLED_PATH, "/usr/lib/wins-vpn/wins_bridge_host")
        producer = PRODUCER.read_text(encoding="utf-8")
        self.assertIn('"$PACKAGE_ROOT/tools/native_messaging/host/wins_bridge_host"', producer)
        self.assertIn('"$PACKAGE_ROOT/tools/native_messaging/install_native_host.sh"', producer)
        self.assertTrue(NATIVE_INSTALLER.stat().st_mode & stat.S_IXUSR)
        self.assertIn("rollback_failed=1", installer)
        self.assertIn("installation rollback failed closed", installer)
        self.assertIn("--require-installed-path", installer)
        self.assertIn("--host-path \"$host_path\"", installer)
        self.assertIn("NATIVE_HOST_EDGE_MANIFEST_DIR=/etc/opt/edge/native-messaging-hosts", installer)
        self.assertIn("--uninstall-native-host", installer)
        self.assertIn("--verify-native-host-delivery", installer)
        self.assertIn('verify_installed_linux_native_messaging "${2:-}"', installer)
        self.assertIn("NATIVE_HOST_USER_HOST_REL=.local/lib/wins-vpn/wins_bridge_host", installer)
        self.assertNotEqual(CHROME_ID, EDGE_ID)
        production, _sep, self_test = installer.partition("run_native_host_delivery_self_test()")
        self.assertIsNone(re.search(r"[a-p]{32}", production))
        self.assertNotIn("PLACEHOLDER", production)
        self.assertNotIn("bind_owner_identity", production)
        self.assertIn("duplicate JSON key", production)
        self.assertIn("extra JSON keys", production)
        self.assertIn("recorded-id --browser chrome", producer)
        self.assertIn("recorded-id --browser edge", producer)
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn(SYSTEM_EDGE_DIR, bootstrap)
        self.assertIn(USER_EDGE_REL, bootstrap)
        self.assertIn("--uninstall", bootstrap)
        self.assertIn("--verify-native-host-delivery", bootstrap)
        self.assertIn("Microsoft Edge", bootstrap)
        self.assertIn('exec /bin/bash "$(linux_packaging_install_sh)" --verify-native-host-delivery', bootstrap)


if __name__ == "__main__":
    unittest.main()
