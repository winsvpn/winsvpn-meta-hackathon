#!/usr/bin/env python3
"""Linux native-host packaging: Edge delivery, identity, dests, uninstall."""

from __future__ import annotations

import contextlib
import io
import os
import pathlib
import re
import socket
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
INSTALLER = ROOT / "linux/packaging/install.sh"
BOOTSTRAP = ROOT / "linux/packaging/install-winsvpn-linux.sh"
LAYOUT = ROOT / "tools/native_messaging/native_host_layout.py"
SYSTEM_EDGE_DIR = pathlib.Path("/etc/opt/edge/native-messaging-hosts")
USER_EDGE_REL = pathlib.Path(".config/microsoft-edge/NativeMessagingHosts")
HOST_NAME = "org.winsvpn.bridge"

if str(LAYOUT.parent) not in sys.path:
    sys.path.insert(0, str(LAYOUT.parent))

import native_host_layout as layout  # noqa: E402


def _overlay_helper_source() -> str:
    source = INSTALLER.read_text(encoding="utf-8")
    marker = "  python3 - \"$@\" <<'PY'\n"
    start = source.index(marker) + len(marker)
    end = source.index("\nPY\n}", start)
    return source[start:end]


def _run_overlay_helper(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-", *args],
        cwd=str(ROOT),
        input=_overlay_helper_source(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=8,
    )


def _overlay_helper_ns() -> dict[str, object]:
    ns: dict[str, object] = {"__name__": "overlay_helper"}
    exec(_overlay_helper_source(), ns)
    return ns


def _open_fd_set() -> set[int]:
    for directory in ("/dev/fd", "/proc/self/fd"):
        if os.path.isdir(directory):
            return {int(name) for name in os.listdir(directory) if name.isdigit()}
    raise unittest.SkipTest("descriptor listing directory is unavailable")


def _restore_inprocess(
    ns: dict[str, object], overlay: str, dest: str, backup: str
) -> None:
    session_cls = ns["Session"]
    session_restore = ns["session_restore"]
    session = session_cls(overlay)
    try:
        try:
            session_restore(session, dest, backup)
        except SystemExit:
            return
    finally:
        session.close()


class LinuxNativeHostPackagingTests(unittest.TestCase):
    @unittest.skipIf(pathlib.Path("/opt/wins-vpn").exists(), "/opt/wins-vpn is installed")
    def test_live_uninstall_uses_installed_copy(self) -> None:
        result = subprocess.run(
            ["bash", str(BOOTSTRAP), "--uninstall"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertIn("not installed at /opt/wins-vpn", result.stderr)

    @unittest.skipIf(pathlib.Path("/opt/wins-vpn").exists(), "/opt/wins-vpn is installed")
    def test_live_uninstall_never_reaches_sudo(self) -> None:
        # The bootstrap calls an absolute /usr/bin/sudo, so a PATH shim cannot
        # see it. Run a byte-for-byte copy whose only change is that path, and
        # prove the recorder works before relying on its silence.
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            log = work / "sudo.log"
            recorder = work / "sudo"
            recorder.write_text(
                f'#!/bin/sh\nprintf \'%s\\n\' "$*" >> {log}\nexit 97\n',
                encoding="utf-8",
            )
            recorder.chmod(0o755)
            original = BOOTSTRAP.read_text(encoding="utf-8")
            self.assertEqual(original.count("/usr/bin/sudo --"), 1)
            copy = work / BOOTSTRAP.name
            copy.write_text(
                original.replace("/usr/bin/sudo --", f"{recorder} --"),
                encoding="utf-8",
            )

            control = subprocess.run(
                [str(recorder), "--", "control"], check=False, timeout=10
            )
            self.assertEqual(control.returncode, 97)
            self.assertEqual(log.read_text(encoding="utf-8"), "-- control\n")
            log.unlink()

            result = subprocess.run(
                ["bash", str(copy), "--uninstall"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 65, result.stderr)
            self.assertIn("not installed at /opt/wins-vpn", result.stderr)
            self.assertFalse(
                log.exists(),
                f"sudo was invoked: {log.read_text(encoding='utf-8') if log.exists() else ''}",
            )

    def test_scripts_are_valid_posix(self) -> None:
        for path in (INSTALLER, BOOTSTRAP):
            completed = subprocess.run(
                ["/bin/bash", "-n", str(path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_edge_destinations_match_layout_system_and_per_user(self) -> None:
        home = pathlib.Path("/tmp/winsvpn-home")
        self.assertEqual(
            layout.unix_manifest_dir("edge", "Linux", system=True, home=home),
            SYSTEM_EDGE_DIR,
        )
        self.assertEqual(
            layout.unix_manifest_dir("edge", "Linux", system=False, home=home),
            home / USER_EDGE_REL,
        )
        installer = INSTALLER.read_text(encoding="utf-8")
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn(f"NATIVE_HOST_EDGE_MANIFEST_DIR={SYSTEM_EDGE_DIR}", installer)
        self.assertIn(f"NATIVE_HOST_EDGE_USER_REL={USER_EDGE_REL}", installer)
        self.assertIn(str(SYSTEM_EDGE_DIR), bootstrap)
        self.assertIn(str(USER_EDGE_REL), bootstrap)
        self.assertIn("NATIVE_HOST_NAME=org.winsvpn.bridge", bootstrap)

    def test_packaged_edge_identity_is_distinct_and_not_invented(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        production, _sep, self_test = installer.partition(
            "run_native_host_delivery_self_test()"
        )
        self.assertTrue(self_test)
        self.assertIsNone(re.search(r"[a-p]{32}", production))
        self.assertNotIn("PLACEHOLDER", production)
        self.assertNotIn("bind_owner_identity", production)
        self.assertIn("owner-blocked", production)
        self.assertIn("refusing to invent", production.lower())
        self.assertIn("must be distinct", production)
        self.assertIn("duplicate JSON key", production)
        self.assertIn("extra JSON keys", production)
        self.assertIn("org.winsvpn.bridge.edge.json", production)
        self.assertIn("NATIVE_HOST_STORE_IDS_REL=tools/native_messaging/manifests/store_ids.json", production)
        self.assertIn("missing-edge-id", production)
        self.assertNotIn("edge_origin_id = edge_id or chrome_id", production)
        chrome_id = re.search(r'chrome_id="([a-p]{32})"', self_test)
        edge_id = re.search(r'edge_id="([a-p]{32})"', self_test)
        self.assertIsNotNone(chrome_id)
        self.assertIsNotNone(edge_id)
        self.assertNotEqual(chrome_id.group(1), edge_id.group(1))
        self.assertIn("PLACEHOLDER_EDGE_EXTENSION_ID", self_test)
        self.assertIn("duplicate JSON key", self_test)

    def test_rollback_uninstall_and_package_verification_cover_edge(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("native_host_backup/edge.json", installer)
        self.assertIn("native_host_host_backup", installer)
        self.assertIn("native_host_chrome_backup", installer)
        self.assertIn("native_host_firefox_backup", installer)
        self.assertIn("native_host_edge_backup", installer)
        self.assertIn("native-host backup is missing", installer)
        self.assertIn("restore_linux_native_messaging", installer)
        helper = _overlay_helper_source()
        self.assertIn("native-host backup is missing", helper)
        self.assertNotIn("except Exception", helper)
        self.assertIn("--uninstall-native-host", installer)
        self.assertIn("--verify-native-host-delivery", installer)
        self.assertIn("uninstall_linux_native_host_user_manifests", installer)
        self.assertIn("NATIVE_HOST_USER_HOST_REL=.local/lib/wins-vpn/wins_bridge_host", installer)
        self.assertIn("assert_overlay_path_safe", installer)
        self.assertIn("refusing intermediate symlink", installer)
        self.assertIn("refusing overlay prefix /", installer)
        self.assertIn("O_NOFOLLOW", installer)
        self.assertIn("refusing hardlinked native-host rollback destination", installer)
        self.assertIn("--uninstall", bootstrap)
        self.assertIn("--verify-native-host-delivery", bootstrap)
        self.assertIn("Microsoft Edge", bootstrap)
        self.assertIn('exec /bin/bash "$(linux_packaging_install_sh)" --verify-native-host-delivery', bootstrap)

    def test_isolated_delivery_and_bootstrap_forwarding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-linux-edge-packaging-") as raw:
            prefix = pathlib.Path(raw) / "overlay"
            forwarded = subprocess.run(
                [
                    "bash",
                    str(BOOTSTRAP),
                    "--self-test-native-host-delivery",
                    str(prefix),
                ],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(forwarded.returncode, 0, forwarded.stderr)
            self.assertIn("NATIVE-HOST DELIVERY SELF-TEST: PASS", forwarded.stdout)
            self.assertIn("Chrome, Firefox, and Edge registered", forwarded.stdout)
            self.assertIn("owner-blocked", forwarded.stdout)
            self.assertIn("owner-blocked missing Edge identity left host and manifests untouched", forwarded.stdout)
            self.assertIn("owner-blocked reused Edge identity left host and manifests untouched", forwarded.stdout)
            self.assertIn("placeholder Edge store identity was owner-blocked", forwarded.stdout)
            self.assertIn("extra JSON keys in store identity were rejected", forwarded.stdout)
            self.assertIn("duplicate JSON keys in store identity were rejected", forwarded.stdout)
            self.assertIn("native-host rollback restored the Firefox manifest", forwarded.stdout)
            self.assertIn("native-host rollback restored a mid-Edge failure", forwarded.stdout)
            self.assertIn("preexisting native-host symlink dest was refused", forwarded.stdout)
            self.assertIn("preexisting native-host directory dest was refused", forwarded.stdout)
            self.assertIn("overlay inner symlink dests were refused", forwarded.stdout)
            self.assertIn("symlink overlay prefix with /. was refused", forwarded.stdout)
            self.assertIn("inner-symlink/.. overlay prefix was refused", forwarded.stdout)
            self.assertIn("root overlay prefix / was refused", forwarded.stdout)
            self.assertIn("hardlinked rollback destination was refused", forwarded.stdout)
            self.assertIn("overlay native-host delivery verified", forwarded.stdout)
            self.assertIn("native-host uninstall removed system and per-user Chrome, Firefox, and Edge registration", forwarded.stdout)
            self.assertIn(str(USER_EDGE_REL), forwarded.stdout)

            live = pathlib.Path(raw) / "fake-live"
            (live / "usr/lib/wins-vpn").mkdir(parents=True)
            (live / "etc/opt/edge/native-messaging-hosts").mkdir(parents=True)
            (live / "etc/opt/chrome/native-messaging-hosts").mkdir(parents=True)
            (live / "usr/lib/mozilla/native-messaging-hosts").mkdir(parents=True)
            (live / "usr/lib/wins-vpn/wins_bridge_host").write_text(
                "LIVE-HOST\n", encoding="ascii"
            )
            (live / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json").write_text(
                "LIVE-EDGE\n", encoding="ascii"
            )
            (live / f"etc/opt/chrome/native-messaging-hosts/{HOST_NAME}.json").write_text(
                "LIVE-CHROME\n", encoding="ascii"
            )
            (live / f"usr/lib/mozilla/native-messaging-hosts/{HOST_NAME}.json").write_text(
                "LIVE-FIREFOX\n", encoding="ascii"
            )
            linked = pathlib.Path(raw) / "symlink-overlay"
            linked.mkdir()
            (linked / "usr").symlink_to(live / "usr")
            (linked / "etc").symlink_to(live / "etc")
            refused = subprocess.run(
                ["bash", str(BOOTSTRAP), "--uninstall", str(linked)],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stdout)
            self.assertIn("intermediate symlink", refused.stderr)
            self.assertEqual(
                (live / "usr/lib/wins-vpn/wins_bridge_host").read_text(encoding="ascii"),
                "LIVE-HOST\n",
            )
            self.assertEqual(
                (live / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json").read_text(
                    encoding="ascii"
                ),
                "LIVE-EDGE\n",
            )

            verify_overlay = prefix / "verify-overlay"
            verified = subprocess.run(
                [
                    "bash",
                    str(INSTALLER),
                    "--verify-native-host-delivery",
                    str(verify_overlay),
                ],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("overlay", verified.stdout)
            self.assertIn("native-host delivery verified", verified.stdout)

            remove = pathlib.Path(raw) / "uninstall-overlay"
            (remove / "etc/opt/edge/native-messaging-hosts").mkdir(parents=True)
            (remove / "etc/opt/chrome/native-messaging-hosts").mkdir(parents=True)
            (remove / "usr/lib/mozilla/native-messaging-hosts").mkdir(parents=True)
            (remove / "usr/lib/wins-vpn").mkdir(parents=True)
            user_chrome = remove / "home" / ".config/google-chrome/NativeMessagingHosts"
            user_firefox = remove / "home" / ".mozilla/native-messaging-hosts"
            user_edge = remove / "home" / USER_EDGE_REL
            user_host_dir = remove / "home" / ".local/lib/wins-vpn"
            user_chrome.mkdir(parents=True)
            user_firefox.mkdir(parents=True)
            user_edge.mkdir(parents=True)
            user_host_dir.mkdir(parents=True)
            payload = '{"path":"/usr/lib/wins-vpn/wins_bridge_host"}\n'
            (remove / f"etc/opt/chrome/native-messaging-hosts/{HOST_NAME}.json").write_text(
                payload, encoding="ascii"
            )
            (remove / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json").write_text(
                payload, encoding="ascii"
            )
            (remove / f"usr/lib/mozilla/native-messaging-hosts/{HOST_NAME}.json").write_text(
                payload, encoding="ascii"
            )
            (remove / f"etc/opt/edge/native-messaging-hosts/other.json").write_text(
                '{"path":"/keep-me"}\n', encoding="ascii"
            )
            (user_chrome / f"{HOST_NAME}.json").write_text(payload, encoding="ascii")
            (user_firefox / f"{HOST_NAME}.json").write_text(payload, encoding="ascii")
            (user_edge / f"{HOST_NAME}.json").write_text(payload, encoding="ascii")
            (user_host_dir / "wins_bridge_host").write_text("user-host\n", encoding="ascii")
            (remove / "usr/lib/wins-vpn/wins_bridge_host").write_text(
                "#!/bin/sh\nexit 0\n", encoding="ascii"
            )
            uninstalled = subprocess.run(
                ["bash", str(BOOTSTRAP), "--uninstall", str(remove)],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(uninstalled.returncode, 0, uninstalled.stderr)
            self.assertFalse(
                (remove / f"etc/opt/chrome/native-messaging-hosts/{HOST_NAME}.json").exists()
            )
            self.assertFalse(
                (remove / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json").exists()
            )
            self.assertFalse(
                (remove / f"usr/lib/mozilla/native-messaging-hosts/{HOST_NAME}.json").exists()
            )
            self.assertTrue(
                (remove / "etc/opt/edge/native-messaging-hosts/other.json").exists()
            )
            self.assertFalse((user_chrome / f"{HOST_NAME}.json").exists())
            self.assertFalse((user_firefox / f"{HOST_NAME}.json").exists())
            self.assertFalse((user_edge / f"{HOST_NAME}.json").exists())
            self.assertFalse((user_host_dir / "wins_bridge_host").exists())
            self.assertFalse((remove / "usr/lib/wins-vpn/wins_bridge_host").exists())

    def test_hostile_overlay_prefix_identity_and_hardlink_rollback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-linux-hostile-overlay-") as raw:
            root = pathlib.Path(raw)
            live = root / "live"
            (live / "usr/lib/wins-vpn").mkdir(parents=True)
            (live / "etc/opt/edge/native-messaging-hosts").mkdir(parents=True)
            (live / "etc/opt/chrome/native-messaging-hosts").mkdir(parents=True)
            (live / "usr/lib/mozilla/native-messaging-hosts").mkdir(parents=True)
            (live / "usr/lib/wins-vpn/wins_bridge_host").write_text(
                "LIVE-HOST\n", encoding="ascii"
            )
            (live / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json").write_text(
                "LIVE-EDGE\n", encoding="ascii"
            )
            (live / f"etc/opt/chrome/native-messaging-hosts/{HOST_NAME}.json").write_text(
                "LIVE-CHROME\n", encoding="ascii"
            )
            (live / f"usr/lib/mozilla/native-messaging-hosts/{HOST_NAME}.json").write_text(
                "LIVE-FIREFOX\n", encoding="ascii"
            )

            linked = root / "symlink-prefix"
            linked.mkdir()
            (linked / "target").symlink_to(live)
            slash_dot = subprocess.run(
                ["bash", str(BOOTSTRAP), "--uninstall", str(linked / "target" / ".")],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(slash_dot.returncode, 0, slash_dot.stdout)
            self.assertTrue(
                "dot" in slash_dot.stderr or "symlink" in slash_dot.stderr,
                slash_dot.stderr,
            )
            self.assertEqual(
                (live / "usr/lib/wins-vpn/wins_bridge_host").read_text(
                    encoding="ascii"
                ),
                "LIVE-HOST\n",
            )

            escape = root / "escape"
            outside = root / "outside"
            (escape / "inside").mkdir(parents=True)
            (outside / "usr/lib/wins-vpn").mkdir(parents=True)
            (outside / "etc/opt/edge/native-messaging-hosts").mkdir(parents=True)
            (outside / "etc/opt/chrome/native-messaging-hosts").mkdir(parents=True)
            (outside / "usr/lib/mozilla/native-messaging-hosts").mkdir(parents=True)
            (outside / "usr/lib/wins-vpn/wins_bridge_host").write_text(
                "OUTSIDE-HOST\n", encoding="ascii"
            )
            (outside / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json").write_text(
                "OUTSIDE-EDGE\n", encoding="ascii"
            )
            (escape / "inside" / "link").symlink_to(outside)
            inner = subprocess.run(
                [
                    "bash",
                    str(BOOTSTRAP),
                    "--uninstall",
                    str(escape / "inside" / "link" / ".."),
                ],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(inner.returncode, 0, inner.stdout)
            self.assertIn("dot-dot", inner.stderr)
            self.assertEqual(
                (outside / "usr/lib/wins-vpn/wins_bridge_host").read_text(
                    encoding="ascii"
                ),
                "OUTSIDE-HOST\n",
            )
            self.assertEqual(
                (outside / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json").read_text(
                    encoding="ascii"
                ),
                "OUTSIDE-EDGE\n",
            )

            root_prefix = subprocess.run(
                ["bash", str(INSTALLER), "--uninstall-native-host", "/"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(root_prefix.returncode, 0, root_prefix.stdout)
            self.assertIn("refusing overlay prefix /", root_prefix.stderr)

            hard = root / "hardlink"
            (hard / "usr/lib/wins-vpn").mkdir(parents=True)
            victim = root / "hardlink-victim"
            dest = hard / "usr/lib/wins-vpn/wins_bridge_host"
            victim.write_text("HARD-LINK-VICTIM\n", encoding="ascii")
            os.link(victim, dest)
            backup = hard / "backup-host"
            backup.write_text("HARD-LINK-BACKUP\n", encoding="ascii")
            restore = _run_overlay_helper(
                "restore",
                str(hard),
                str(dest),
                str(backup),
            )
            self.assertNotEqual(restore.returncode, 0, restore.stdout)
            self.assertIn("hardlinked native-host rollback destination", restore.stderr)
            self.assertEqual(victim.read_text(encoding="ascii"), "HARD-LINK-VICTIM\n")
            self.assertEqual(dest.read_text(encoding="ascii"), "HARD-LINK-VICTIM\n")

            live2 = root / "live2"
            (live2 / "heldchild").mkdir(parents=True)
            (live2 / "heldchild" / "marker").write_text("LIVE2\n", encoding="ascii")
            decoy = root / "decoy-prefix"
            decoy.mkdir()
            (decoy / "link").symlink_to(live2)
            intermediate = _run_overlay_helper(
                "bind-prefix", str(decoy / "link" / "heldchild")
            )
            self.assertNotEqual(intermediate.returncode, 0, intermediate.stdout)
            self.assertIn("symlink", intermediate.stderr)
            self.assertEqual(
                (live2 / "heldchild" / "marker").read_text(encoding="ascii"), "LIVE2\n"
            )

            original = root / "held-prefix"
            (original / "usr/lib/wins-vpn").mkdir(parents=True)
            dest_host = original / "usr/lib/wins-vpn/wins_bridge_host"
            dest_host.write_text("SEQ-NEW\n", encoding="ascii")
            backup = original / "backup-host"
            backup.write_text("SEQ-BACKUP\n", encoding="ascii")
            lexical_dest = str(dest_host)
            lexical_backup = str(backup)
            ns = {"__name__": "overlay_helper"}
            exec(_overlay_helper_source(), ns)
            session = ns["Session"](str(original))
            try:
                aside = root / "held-prefix-aside"
                original.rename(aside)
                replacement = root / "held-prefix"
                (replacement / "usr/lib/wins-vpn").mkdir(parents=True)
                replacement_host = (
                    replacement / "usr/lib/wins-vpn/wins_bridge_host"
                )
                replacement_host.write_text("SEQ-VICTIM\n", encoding="ascii")
                (replacement / "backup-host").write_text("SEQ-EVIL\n", encoding="ascii")
                ns["session_restore"](
                    session,
                    lexical_dest,
                    lexical_backup,
                )
            finally:
                session.close()
            self.assertEqual(
                (aside / "usr/lib/wins-vpn/wins_bridge_host").read_text(
                    encoding="ascii"
                ),
                "SEQ-BACKUP\n",
            )
            self.assertEqual(replacement_host.read_text(encoding="ascii"), "SEQ-VICTIM\n")
            self.assertEqual(
                (replacement / "backup-host").read_text(encoding="ascii"),
                "SEQ-EVIL\n",
            )

            missing_home = root / "missing-user"
            (missing_home / "usr/lib/wins-vpn").mkdir(parents=True)
            (missing_home / "etc/opt/chrome/native-messaging-hosts").mkdir(parents=True)
            (missing_home / "etc/opt/edge/native-messaging-hosts").mkdir(parents=True)
            (missing_home / "usr/lib/mozilla/native-messaging-hosts").mkdir(parents=True)
            (missing_home / "home").mkdir()
            (missing_home / "usr/lib/wins-vpn/wins_bridge_host").write_text(
                "KEEP-SYSTEM-HOST\n", encoding="ascii"
            )
            (
                missing_home / f"etc/opt/chrome/native-messaging-hosts/{HOST_NAME}.json"
            ).write_text("KEEP-SYSTEM-CHROME\n", encoding="ascii")
            (
                missing_home / f"etc/opt/edge/native-messaging-hosts/{HOST_NAME}.json"
            ).write_text("KEEP-SYSTEM-EDGE\n", encoding="ascii")
            (
                missing_home
                / f"usr/lib/mozilla/native-messaging-hosts/{HOST_NAME}.json"
            ).write_text("KEEP-SYSTEM-FIREFOX\n", encoding="ascii")
            refused_home = subprocess.run(
                ["bash", str(BOOTSTRAP), "--uninstall", str(missing_home)],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(refused_home.returncode, 0, refused_home.stdout)
            self.assertEqual(
                (missing_home / "usr/lib/wins-vpn/wins_bridge_host").read_text(
                    encoding="ascii"
                ),
                "KEEP-SYSTEM-HOST\n",
            )
            self.assertEqual(
                (
                    missing_home
                    / f"etc/opt/chrome/native-messaging-hosts/{HOST_NAME}.json"
                ).read_text(encoding="ascii"),
                "KEEP-SYSTEM-CHROME\n",
            )

            fifo_root = root / "fifo-overlay"
            (fifo_root / "usr/lib/wins-vpn").mkdir(parents=True)
            os.mkfifo(fifo_root / "usr/lib/wins-vpn/wins_bridge_host")
            fifo_backup = fifo_root / "backup-host"
            fifo_backup.write_text("FIFO-BACKUP\n", encoding="ascii")
            fifo_restore = _run_overlay_helper(
                "restore",
                str(fifo_root),
                str(fifo_root / "usr/lib/wins-vpn/wins_bridge_host"),
                str(fifo_backup),
            )
            self.assertNotEqual(fifo_restore.returncode, 0, fifo_restore.stdout)
            self.assertTrue(
                "special" in fifo_restore.stderr or "non-regular" in fifo_restore.stderr,
                fifo_restore.stderr,
            )
            self.assertTrue(
                stat.S_ISFIFO(
                    (fifo_root / "usr/lib/wins-vpn/wins_bridge_host").lstat().st_mode
                )
            )

            with tempfile.TemporaryDirectory(prefix="wvsock-", dir="/tmp") as sock_raw:
                sock_root = pathlib.Path(sock_raw)
                (sock_root / "d").mkdir()
                sock_path = sock_root / "d" / "h"
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.bind(str(sock_path))
                finally:
                    sock.close()
                sock_backup = sock_root / "backup-host"
                sock_backup.write_text("SOCK-BACKUP\n", encoding="ascii")
                sock_restore = _run_overlay_helper(
                    "restore",
                    str(sock_root),
                    str(sock_path),
                    str(sock_backup),
                )
                self.assertNotEqual(sock_restore.returncode, 0, sock_restore.stdout)
                self.assertTrue(
                    "special" in sock_restore.stderr
                    or "non-regular" in sock_restore.stderr,
                    sock_restore.stderr,
                )
                self.assertTrue(stat.S_ISSOCK(sock_path.lstat().st_mode))
                self.assertEqual(
                    sock_backup.read_text(encoding="ascii"), "SOCK-BACKUP\n"
                )

    def test_missing_named_backup_preserves_live_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-linux-missing-backup-") as raw:
            root = pathlib.Path(raw)
            overlay = root / "overlay"
            (overlay / "usr/lib/wins-vpn").mkdir(parents=True)
            dest = overlay / "usr/lib/wins-vpn/wins_bridge_host"
            dest.write_text("MISSING-BACKUP-VICTIM\n", encoding="ascii")
            named_backup = overlay / "backup-host-absent"
            self.assertFalse(named_backup.exists())
            refused = _run_overlay_helper(
                "restore",
                str(overlay),
                str(dest),
                str(named_backup),
            )
            self.assertNotEqual(refused.returncode, 0, refused.stdout)
            self.assertIn("native-host backup is missing", refused.stderr)
            self.assertTrue(dest.exists())
            self.assertEqual(dest.read_text(encoding="ascii"), "MISSING-BACKUP-VICTIM\n")

            new_dest_root = root / "explicit-empty"
            (new_dest_root / "usr/lib/wins-vpn").mkdir(parents=True)
            new_dest = new_dest_root / "usr/lib/wins-vpn/wins_bridge_host"
            new_dest.write_text("NEW-DEST\n", encoding="ascii")
            unlinked = _run_overlay_helper(
                "restore",
                str(new_dest_root),
                str(new_dest),
                "",
            )
            self.assertEqual(unlinked.returncode, 0, unlinked.stderr)
            self.assertFalse(new_dest.exists())

    def test_overlay_helper_refuse_paths_do_not_leak_fds(self) -> None:
        ns = _overlay_helper_ns()
        with tempfile.TemporaryDirectory(prefix="winsvpn-linux-fd-leak-") as raw:
            root = pathlib.Path(raw)
            missing_overlay = root / "missing-backup"
            (missing_overlay / "usr/lib/wins-vpn").mkdir(parents=True)
            missing_dest = missing_overlay / "usr/lib/wins-vpn/wins_bridge_host"
            missing_dest.write_text("MISSING-BACKUP-VICTIM\n", encoding="ascii")
            missing_backup = missing_overlay / "backup-host-absent"

            fifo_root = root / "fifo-overlay"
            (fifo_root / "usr/lib/wins-vpn").mkdir(parents=True)
            fifo_dest = fifo_root / "usr/lib/wins-vpn/wins_bridge_host"
            os.mkfifo(fifo_dest)
            fifo_backup = fifo_root / "backup-host"
            fifo_backup.write_text("FIFO-BACKUP\n", encoding="ascii")

            symlink_root = root / "symlink-dest"
            (symlink_root / "usr/lib/wins-vpn").mkdir(parents=True)
            symlink_target = root / "symlink-target"
            symlink_target.write_text("SYMLINK-TARGET\n", encoding="ascii")
            symlink_dest = symlink_root / "usr/lib/wins-vpn/wins_bridge_host"
            symlink_dest.symlink_to(symlink_target)
            symlink_backup = symlink_root / "backup-host"
            symlink_backup.write_text("SYMLINK-BACKUP\n", encoding="ascii")

            live = root / "live-prefix"
            (live / "heldchild").mkdir(parents=True)
            (live / "heldchild" / "marker").write_text("LIVE\n", encoding="ascii")
            decoy = root / "decoy-prefix"
            decoy.mkdir()
            (decoy / "link").symlink_to(live)
            symlink_prefix = decoy / "link" / "heldchild"

            before = _open_fd_set()
            bind_overlay = ns["bind_overlay"]
            open_regular = ns["open_regular"]
            with contextlib.redirect_stderr(io.StringIO()):
                for _ in range(32):
                    _restore_inprocess(
                        ns, str(missing_overlay), str(missing_dest), str(missing_backup)
                    )
                    _restore_inprocess(
                        ns, str(fifo_root), str(fifo_dest), str(fifo_backup)
                    )
                    _restore_inprocess(
                        ns, str(symlink_root), str(symlink_dest), str(symlink_backup)
                    )
                    try:
                        bind_overlay(str(symlink_prefix))
                    except SystemExit:
                        pass
                    try:
                        open_regular(
                            str(fifo_dest),
                            label="native-host dest",
                            refuse_hardlink=False,
                        )
                    except SystemExit:
                        pass
            after = _open_fd_set()
            self.assertEqual(
                before,
                after,
                "leaked descriptors: %r" % (sorted(after - before),),
            )
            self.assertEqual(
                missing_dest.read_text(encoding="ascii"), "MISSING-BACKUP-VICTIM\n"
            )
            self.assertTrue(stat.S_ISFIFO(fifo_dest.lstat().st_mode))
            self.assertTrue(symlink_dest.is_symlink())
            self.assertEqual(symlink_target.read_text(encoding="ascii"), "SYMLINK-TARGET\n")
            self.assertEqual(
                (live / "heldchild" / "marker").read_text(encoding="ascii"), "LIVE\n"
            )


if __name__ == "__main__":
    unittest.main()
