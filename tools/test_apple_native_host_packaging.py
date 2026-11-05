#!/usr/bin/env python3
"""Focused Apple native-host packaging, gate, and registration tests."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_cross_store_artifact_gate as apple_gate
import release_obfuscation_contract as obfuscation


HELPER = ROOT / "tools/native_messaging/install_macos_native_host.sh"
BUILDER = ROOT / "tools/native_messaging/build_native_host.sh"
PRODUCER = ROOT / "tools/build_apple_release_candidates.sh"
LAYOUT = ROOT / "tools/native_messaging/native_host_layout.py"
OWNER_CHROME_ID = "abcdefghijklmnopabcdefghijklmnop"
OWNER_EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
INSTALLED_PATH = apple_gate.MACOS_NATIVE_HOST_SYSTEM_PATH


def _thin_mh_execute(cputype: int) -> bytes:
    data = bytearray(obfuscation._minimal_macho64(dwarf=False))
    struct.pack_into("<I", data, 4, cputype)
    struct.pack_into("<I", data, 12, apple_gate.MH_EXECUTE)
    return bytes(data)


def _universal_mh_execute() -> bytes:
    arm = _thin_mh_execute(apple_gate.CPU_TYPE_ARM64)
    x86 = _thin_mh_execute(apple_gate.CPU_TYPE_X86_64)
    header_len = 8 + 20 * 2
    arm_off = header_len
    x86_off = arm_off + len(arm)
    blob = bytearray(x86_off + len(x86))
    struct.pack_into(">II", blob, 0, 0xCAFEBABE, 2)
    struct.pack_into(">IIIII", blob, 8, apple_gate.CPU_TYPE_ARM64, 0, arm_off, len(arm), 2)
    struct.pack_into(">IIIII", blob, 28, apple_gate.CPU_TYPE_X86_64, 3, x86_off, len(x86), 2)
    blob[arm_off : arm_off + len(arm)] = arm
    blob[x86_off : x86_off + len(x86)] = x86
    return bytes(blob)


def _firefox_manifest(host_path: str) -> dict[str, object]:
    return {
        "name": "org.winsvpn.bridge",
        "description": "Win's VPN browser bridge",
        "path": host_path,
        "type": "stdio",
        "allowed_extensions": ["companion@winsvpn.org"],
    }


def _chrome_manifest(host_path: str, chrome_id: str) -> dict[str, object]:
    return {
        "name": "org.winsvpn.bridge",
        "description": "Win's VPN browser bridge",
        "path": host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{chrome_id}/"],
    }


def _edge_manifest(host_path: str, edge_id: str) -> dict[str, object]:
    return {
        "name": "org.winsvpn.bridge",
        "description": "Win's VPN browser bridge",
        "path": host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{edge_id}/"],
    }


def _identity_python_env(site_dir: pathlib.Path, *, owner_ids: bool = True) -> dict[str, str]:
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / "sitecustomize.py").write_text(
        "\n".join(
            [
                "import sys",
                f"sys.path.insert(0, {str(ROOT / 'tools' / 'native_messaging')!r})",
                "import render_host_manifest as renderer",
                f"CHROME = {OWNER_CHROME_ID if owner_ids else None!r}",
                f"EDGE = {OWNER_EDGE_ID if owner_ids else None!r}",
                "def _ids():",
                "    return {'chrome': CHROME, 'edge': EDGE}",
                "renderer.owner_issued_chromium_ids = _ids",
                "renderer.recorded_store_ids = _ids",
                "renderer.recorded_extension_id = lambda browser: {",
                "    'chrome': CHROME,",
                "    'edge': EDGE,",
                "    'firefox': 'companion@winsvpn.org',",
                "}[browser]",
                "",
            ]
        ),
        encoding="ascii",
    )
    env = dict(os.environ)
    env["PYTHON_BIN"] = sys.executable
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(site_dir) if not existing else str(site_dir) + ":" + existing
    env["WINSVPN_CHROME_STORE_ID"] = ""
    env["WINSVPN_EDGE_STORE_ID"] = ""
    env["WINSVPN_BROWSER_EXTENSION_IDENTITY_RECEIPT"] = ""
    return env


def _write_json(path: pathlib.Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )


@contextlib.contextmanager
def _synthetic_host_authentication(expected_sha256: str):
    """Mock trust only for one generated fixture; this is not signing evidence."""
    verify_binary = apple_gate.verify_macos_native_host_binary

    def verify(path, **requirements):
        result = verify_binary(path)
        if result["sha256"] != expected_sha256:
            raise apple_gate.AppleArtifactGateError("synthetic host fixture bytes changed")
        if any(requirements.values()):
            if requirements != {
                "require_signature": True,
                "require_notarization": True,
                "require_source_closure": True,
            }:
                raise AssertionError(f"incomplete handshake trust requirements: {requirements}")
            result.update(
                source_closure_sha256=hashlib.sha256(b"synthetic-host-source").hexdigest(),
                team_id=apple_gate.TEAM_ID,
                notarized=True,
            )
        return result

    def fixture_boundary(argv):
        if len(argv) != 1 or hashlib.sha256(pathlib.Path(argv[0]).read_bytes()).hexdigest() != expected_sha256:
            raise AssertionError("synthetic boundary is restricted to the exact fixture executable")
        return list(argv)

    with mock.patch.object(apple_gate, "verify_macos_native_host_binary", side_effect=verify), mock.patch.object(
        apple_gate, "_macos_descendant_boundary_argv", side_effect=fixture_boundary
    ):
        yield


def _synthetic_host_python(root: pathlib.Path, host: pathlib.Path) -> str:
    """Use the same narrowly scoped trust fixture in helper subprocesses."""
    wrapper = root / "fixture-python"
    digest = hashlib.sha256(host.read_bytes()).hexdigest()
    wrapper.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        f"gate_path = {str(ROOT / 'tools/apple_cross_store_artifact_gate.py')!r}\n"
        "if len(sys.argv) > 1 and str(pathlib.Path(sys.argv[1]).resolve()) == gate_path:\n"
        f"    sys.path.insert(0, {str(ROOT / 'tools')!r})\n"
        "    import test_apple_native_host_packaging as fixture\n"
        f"    with fixture._synthetic_host_authentication({digest!r}):\n"
        "        raise SystemExit(fixture.apple_gate.main(sys.argv[2:]))\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n",
        encoding="ascii",
    )
    wrapper.chmod(0o700)
    return str(wrapper)


def _compile_handshake_host(destination: pathlib.Path, *, silent: bool = False) -> pathlib.Path:
    source = destination.with_suffix(".c")
    source.write_text(
        r"""#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0) return 0;
    unsigned char hdr[4];
    if (fread(hdr, 1, 4, stdin) != 4) return 1;
    uint32_t n = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                 ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (n < 2 || n > 65536u) return 1;
    char *body = (char *)malloc(n + 32u);
    if (body == NULL) return 1;
    if (fread(body, 1, n, stdin) != n || body[n - 1] != '}') {
        free(body);
        return 1;
    }
    if (SILENT_FIXTURE) { free(body); return 0; }
    /* The gate supplies the exact request; echo its binding and nonce. */
    const char suffix[] = ",\"accepted\":true}";
    memcpy(body + n - 1, suffix, sizeof(suffix) - 1);
    uint32_t len = n - 1 + sizeof(suffix) - 1;
    unsigned char out[4] = {len & 0xffu, (len >> 8) & 0xffu,
                            (len >> 16) & 0xffu, (len >> 24) & 0xffu};
    int ok = fwrite(out, 1, 4, stdout) == 4 && fwrite(body, 1, len, stdout) == len;
    free(body);
    return ok ? 0 : 1;
}
""".replace("SILENT_FIXTURE", "1" if silent else "0"),
        encoding="ascii",
    )
    completed = subprocess.run(
        ["/usr/bin/clang", "-arch", "arm64", "-Os", "-o", str(destination), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    destination.chmod(0o755)
    return destination


class AppleNativeHostPackagingTests(unittest.TestCase):
    def test_producer_builds_universal_companion_and_documents_app_store_gap(self) -> None:
        producer = PRODUCER.read_text(encoding="ascii")
        builder = BUILDER.read_text(encoding="ascii")
        helper = HELPER.read_text(encoding="ascii")
        self.assertIn("build_native_host.sh", producer)
        # Owner ruling 2026-10-16: the 1.0.16 companion is Apple silicon only;
        # the builder keeps its --universal mode for later releases.
        self.assertNotIn("--universal", producer)
        self.assertIn('[[ "$(/usr/bin/uname -m)" == "arm64" ]]', producer)
        self.assertIn("owner ruling 2026-10-16", producer)
        self.assertIn("native-host verify-binary", producer)
        self.assertIn("native-host scope", producer)
        self.assertIn("native-host refuse-packaged --artifact", producer)
        self.assertIn("chrome-owner-blocked.txt", producer)
        self.assertIn("Chrome native-host recorded-id lookup failed", producer)
        self.assertIn("install_macos_native_host.sh", producer)
        self.assertNotIn(
            "tools/native_messaging/install_macos_native_host.sh --", producer
        )
        self.assertIn("macOS App Store cannot deliver wins_bridge_host", producer)
        self.assertIn(INSTALLED_PATH, producer)
        self.assertIn("companion@winsvpn.org", helper)
        self.assertIn("--target-os=macos --target-arch=arm64", builder)
        self.assertIn("--target-os=macos --target-arch=x64", builder)
        self.assertIn("/usr/bin/lipo -create", builder)
        self.assertIn('chmod 0755 "${TEMPORARY}"', builder)
        self.assertNotIn("chmod 0755 --", builder)

    def test_helper_is_macos_only_and_rolls_back(self) -> None:
        helper = HELPER.read_text(encoding="ascii")
        self.assertIn('[[ "$(uname -s)" == "Darwin" ]]', helper)
        self.assertIn("rollback_install", helper)
        self.assertIn("uninstall-manifest", helper)
        self.assertIn("--remove-host", helper)
        self.assertIn("refusing TCC-protected", helper)
        self.assertIn("refusing sandboxed-app", helper)
        self.assertIn("gate_cmd handshake", helper)
        self.assertIn("handshake --host", helper)
        self.assertIn("owner_issued_chromium_ids", helper)
        self.assertEqual(helper.count("owner_issued_chromium_ids"), 1)
        self.assertNotIn("recorded-id --browser chrome", helper)
        self.assertNotIn("recorded-id --browser edge", helper)
        self.assertIn("--edge-manifest-dir", helper)
        self.assertIn("owner-blocked", helper)
        self.assertIn("owner identity snapshot failed", helper)
        self.assertIn("ast.parse", helper)
        self.assertIn("owner_edge_id", helper)
        self.assertNotIn("PLACEHOLDER", helper)
        self.assertIn("canonical_home", helper)
        self.assertIn(".mutated", helper)
        self.assertIn(".backup-state", helper)
        self.assertIn("rollback copy failed", helper)
        self.assertIn("rollback could not restore", helper)
        self.assertIn("refusing hardlinked native-host source", helper)
        host_mutation = helper.index(
            'HOST_PREVIOUS="$(layout_cmd install-host --source "${HOST_PATH}"'
        )
        self.assertLess(helper.rindex("mark_mutated host.bin", 0, host_mutation), host_mutation)
        for name, install_needle in (
            ("firefox.json", "--browser firefox"),
            ("chrome.json", "--browser chrome"),
            ("edge.json", "--browser edge"),
        ):
            install_at = helper.index(install_needle)
            self.assertLess(helper.rindex(f"mark_mutated {name}", 0, install_at), install_at)
        rollback_start = helper.index("rollback_install()")
        set_plus = helper.index("set +e", rollback_start)
        restore = helper.index("restore_rollback", rollback_start)
        self.assertLess(set_plus, restore)
        self.assertTrue(os.access(HELPER, os.X_OK))
        self.assertTrue(os.access(BUILDER, os.X_OK))

    def test_app_store_scope_is_fail_closed_and_not_delivered(self) -> None:
        scope = apple_gate.macos_native_messaging_packaging_scope("macos-app-store-pkg")
        self.assertIs(scope["delivered"], False)
        self.assertIs(scope["incompatible"], True)
        self.assertEqual(scope["installed_host_path"], INSTALLED_PATH)
        self.assertTrue(any("sandboxed" in reason for reason in scope["reasons"]))
        self.assertTrue(any("Inner payload schema" in reason for reason in scope["reasons"]))
        self.assertTrue(
            any("Mac App Store installation cannot register" in reason for reason in scope["reasons"])
        )
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/apple_cross_store_artifact_gate.py"), "native-host", "scope"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual(document["target_id"], "macos-app-store-pkg")
        self.assertIs(document["delivered"], False)

    def test_packaged_host_inside_or_beside_the_app_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            app = root / "Payload" / "Applications" / "Win's VPN.app" / "Contents" / "MacOS"
            app.mkdir(parents=True)
            (app / "wins_bridge_host").write_bytes(_universal_mh_execute())
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "cannot deliver wins_bridge_host"
            ):
                apple_gate.reject_packaged_native_messaging_host(root)
            beside = root / "Payload" / "wins_bridge_host"
            for child in app.iterdir():
                child.unlink()
            beside.write_bytes(_universal_mh_execute())
            with self.assertRaisesRegex(
                apple_gate.AppleArtifactGateError, "packaged path"
            ):
                apple_gate.reject_packaged_native_messaging_host(root)

    def test_absent_host_is_documented_not_pretended(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "Payload" / "Applications" / "Win's VPN.app" / "Contents").mkdir(parents=True)
            (root / "Payload" / "Applications" / "Win's VPN.app" / "Contents" / "Info.plist").write_text(
                "plist\n", encoding="ascii"
            )
            apple_gate.reject_packaged_native_messaging_host(root)
            self.assertEqual(apple_gate.packaged_native_messaging_paths(root), [])

    def test_firefox_manifest_is_exact_and_chrome_stays_owner_blocked(self) -> None:
        apple_gate.verify_macos_native_host_manifests(
            host_path=INSTALLED_PATH,
            firefox=_firefox_manifest(INSTALLED_PATH),
            chrome=None,
            owner_chrome_id=None,
        )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "owner-blocked"):
            apple_gate.verify_macos_native_host_manifests(
                host_path=INSTALLED_PATH,
                firefox=_firefox_manifest(INSTALLED_PATH),
                chrome=_chrome_manifest(INSTALLED_PATH, OWNER_CHROME_ID),
                owner_chrome_id=None,
            )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "not exact"):
            apple_gate.verify_macos_native_host_manifests(
                host_path=INSTALLED_PATH,
                firefox=_firefox_manifest("/tmp/wrong"),
                chrome=None,
                owner_chrome_id=None,
            )

    def test_chrome_manifest_requires_owner_id_and_exact_path(self) -> None:
        apple_gate.verify_macos_native_host_manifests(
            host_path=INSTALLED_PATH,
            firefox=_firefox_manifest(INSTALLED_PATH),
            chrome=_chrome_manifest(INSTALLED_PATH, OWNER_CHROME_ID),
            owner_chrome_id=OWNER_CHROME_ID,
        )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "not exact"):
            apple_gate.verify_macos_native_host_manifests(
                host_path=INSTALLED_PATH,
                firefox=_firefox_manifest(INSTALLED_PATH),
                chrome=_chrome_manifest(INSTALLED_PATH, "aaaabbbbccccddddeeeeffffgggghhhh"),
                owner_chrome_id=OWNER_CHROME_ID,
            )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "placeholder"):
            apple_gate.verify_macos_native_host_manifests(
                host_path=INSTALLED_PATH,
                firefox=_firefox_manifest("PLACEHOLDER_ABSOLUTE_PATH_TO_HOST"),
                chrome=None,
                owner_chrome_id=None,
            )

    def test_macho_slices_require_universal_execute(self) -> None:
        archs = apple_gate.verify_macos_native_host_slices(_universal_mh_execute())
        self.assertEqual(set(archs), {"arm64", "x86_64"})
        thin_arm64 = _thin_mh_execute(apple_gate.CPU_TYPE_ARM64)
        with mock.patch.object(apple_gate, "native_host_release_line", return_value="1.0.18"):
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "universal"):
                apple_gate.verify_macos_native_host_slices(thin_arm64)

    def test_release_1_0_16_accepts_an_arm64_host_under_the_owner_ruling(self) -> None:
        # Owner ruling 2026-10-16: the 1.0.16 companion is Apple silicon only; it
        # carries over to the 1.0.17 line.
        self.assertEqual(apple_gate.NATIVE_HOST_ARM64_ONLY_OWNER_RULING_DATE, "2026-10-16")
        self.assertEqual(apple_gate.NATIVE_HOST_ARM64_ONLY_RELEASE_LINES, frozenset({"1.0.16", "1.0.17"}))
        self.assertEqual(apple_gate.native_host_release_line(), "1.0.17")
        thin_arm64 = _thin_mh_execute(apple_gate.CPU_TYPE_ARM64)
        with mock.patch.object(apple_gate, "native_host_release_line", return_value="1.0.16"):
            self.assertEqual(apple_gate.verify_macos_native_host_slices(thin_arm64), ("arm64",))
            self.assertEqual(
                set(apple_gate.verify_macos_native_host_slices(_universal_mh_execute())),
                {"arm64", "x86_64"},
            )
            with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "owner ruling of 2026-10-16"):
                apple_gate.verify_macos_native_host_slices(
                    _thin_mh_execute(apple_gate.CPU_TYPE_X86_64)
                )
        with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "MH_EXECUTE"):
            apple_gate.verify_macos_native_host_slices(
                obfuscation._minimal_macho64(dwarf=False)
            )

    def test_app_store_signer_cannot_cover_out_of_app_host(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = pathlib.Path(raw) / "wins_bridge_host"
            host.write_bytes(_universal_mh_execute())
            host.chmod(0o755)
            details = subprocess.CompletedProcess(
                ["/usr/bin/codesign", "-d", "--verbose=4"],
                0,
                "",
                "Authority=Apple Distribution: Win's VPN Inc (5YT8H4U72M)\n"
                "TeamIdentifier=5YT8H4U72M\n",
            )
            with mock.patch.object(apple_gate, "_run_on_path", return_value=details):
                with self.assertRaisesRegex(
                    apple_gate.AppleArtifactGateError, "App Store signing cannot"
                ):
                    apple_gate.verify_macos_native_host_binary(
                        host, require_signature=True
                    )

    def test_developer_id_signer_and_team_are_required_when_signature_is_gated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = pathlib.Path(raw) / "wins_bridge_host"
            host.write_bytes(_universal_mh_execute())
            host.chmod(0o755)
            details = subprocess.CompletedProcess(
                ["/usr/bin/codesign", "-d", "--verbose=4"],
                0,
                "",
                "Authority=Developer ID Application: Win's VPN Inc (5YT8H4U72M)\n"
                "TeamIdentifier=5YT8H4U72M\n",
            )

            def run_on_path(argv, path, label, **kwargs):
                del path, label, kwargs
                if argv[0] == "/usr/bin/codesign":
                    return details
                raise AssertionError(argv)

            with mock.patch.object(apple_gate, "_run_on_path", side_effect=run_on_path):
                record = apple_gate.verify_macos_native_host_binary(
                    host, require_signature=True
                )
            self.assertEqual(record["team_id"], apple_gate.TEAM_ID)
            self.assertEqual(set(record["architectures"]), {"arm64", "x86_64"})

    def test_source_closure_skips_missing_store_ids_and_binds_current_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = pathlib.Path(raw)
            for relative in apple_gate.macos_native_host_source_paths():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative == apple_gate.OPTIONAL_NATIVE_HOST_SOURCE:
                    continue
                if path.suffix == ".dart" or path.name.endswith(".py") or path.name.endswith(".sh"):
                    path.write_text(f"{relative}\n", encoding="ascii")
                else:
                    path.write_text(f"{relative}\n", encoding="ascii")
            with mock.patch.object(apple_gate, "ORIGIN_ROOT", repo):
                digest, records = apple_gate.compute_macos_native_host_source_closure()
            paths = [str(item["path"]) for item in records]
            self.assertNotIn(apple_gate.OPTIONAL_NATIVE_HOST_SOURCE, paths)
            self.assertIn("tools/native_messaging/host/bin/wins_bridge_host.dart", paths)
            self.assertIn("tools/native_messaging/build_native_host.sh", paths)
            self.assertIn("tools/native_messaging/install_macos_native_host.sh", paths)
            self.assertEqual(len(digest), 64)

    def test_handshake_accepts_hello_and_rejects_silence(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("Apple native-host handshake compile requires Darwin")
        with tempfile.TemporaryDirectory() as raw:
            host = _compile_handshake_host(pathlib.Path(raw) / "wins_bridge_host")
            with _synthetic_host_authentication(hashlib.sha256(host.read_bytes()).hexdigest()):
                reply = apple_gate.macos_native_host_handshake(host)
            self.assertEqual(reply["type"], "hello")
            self.assertIs(reply["accepted"], True)
            self.assertEqual(reply["candidate_binding"]["architectures"], ["arm64"])
            silent = _compile_handshake_host(pathlib.Path(raw) / "silent", silent=True)
            with _synthetic_host_authentication(hashlib.sha256(silent.read_bytes()).hexdigest()):
                with self.assertRaisesRegex(apple_gate.AppleArtifactGateError, "handshake"):
                    apple_gate.macos_native_host_handshake(silent)

    def test_helper_install_rollback_uninstall_and_chrome_owner_block(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            host = _compile_handshake_host(root / "wins_bridge_host")
            dest = root / "Application Support" / "Win's VPN" / "NativeMessagingHost"
            firefox_dir = root / "Mozilla" / "NativeMessagingHosts"
            chrome_dir = root / "Google" / "Chrome" / "NativeMessagingHosts"
            edge_dir = root / "Microsoft" / "Edge" / "NativeMessagingHosts"
            env = _identity_python_env(root / "site", owner_ids=False)
            env["PYTHON_BIN"] = _synthetic_host_python(root, host)
            installed = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(dest),
                    "--firefox-manifest-dir",
                    str(firefox_dir),
                    "--chrome-manifest-dir",
                    str(chrome_dir),
                    "--edge-manifest-dir",
                    str(edge_dir),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr + installed.stdout)
            self.assertIn("owner-blocked", installed.stdout)
            self.assertIn("chrome: owner-blocked", installed.stdout)
            self.assertIn("edge: owner-blocked", installed.stdout)
            firefox = json.loads((firefox_dir / "org.winsvpn.bridge.json").read_text(encoding="utf-8"))
            self.assertEqual(firefox["path"], os.path.realpath(dest / "wins_bridge_host"))
            self.assertEqual(firefox["allowed_extensions"], ["companion@winsvpn.org"])
            self.assertFalse((chrome_dir / "org.winsvpn.bridge.json").exists())
            self.assertFalse((edge_dir / "org.winsvpn.bridge.json").exists())
            original = (dest / "wins_bridge_host").read_bytes()

            broken = root / "broken-host"
            broken.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
            broken.chmod(0o755)
            failed = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(broken),
                    "--dest-dir",
                    str(dest),
                    "--firefox-manifest-dir",
                    str(firefox_dir),
                    "--chrome-manifest-dir",
                    str(chrome_dir),
                    "--edge-manifest-dir",
                    str(edge_dir),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(failed.returncode, 0, failed.stdout)
            restored = json.loads((firefox_dir / "org.winsvpn.bridge.json").read_text(encoding="utf-8"))
            self.assertEqual(restored["path"], os.path.realpath(dest / "wins_bridge_host"))
            self.assertEqual((dest / "wins_bridge_host").read_bytes(), original)
            self.assertFalse((edge_dir / "org.winsvpn.bridge.json").exists())

            removed = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--uninstall",
                    "--remove-host",
                    "--dest-dir",
                    str(dest),
                    "--firefox-manifest-dir",
                    str(firefox_dir),
                    "--chrome-manifest-dir",
                    str(chrome_dir),
                    "--edge-manifest-dir",
                    str(edge_dir),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse((firefox_dir / "org.winsvpn.bridge.json").exists())
            self.assertFalse((dest / "wins_bridge_host").exists())

    def test_helper_refuses_tcc_and_sandboxed_app_destinations(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            host = _compile_handshake_host(root / "wins_bridge_host")
            app_dest = root / "Win's VPN.app" / "Contents" / "MacOS"
            env = dict(os.environ)
            env["PYTHON_BIN"] = sys.executable
            refused = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(app_dest),
                    "--firefox-manifest-dir",
                    str(root / "firefox"),
                    "--chrome-manifest-dir",
                    str(root / "chrome"),
                    "--edge-manifest-dir",
                    str(root / "edge"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("sandboxed-app", refused.stderr)

    def test_helper_canonical_home_refuses_tcc_protected_documents(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            host = _compile_handshake_host(root / "wins_bridge_host")
            home = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-native-host-home-"))
            self.addCleanup(shutil.rmtree, home, True)
            dest = home / "Documents" / "nativehost"
            env = dict(os.environ)
            env["PYTHON_BIN"] = sys.executable
            env["HOME"] = str(home)
            refused = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(dest),
                    "--firefox-manifest-dir",
                    str(root / "firefox"),
                    "--chrome-manifest-dir",
                    str(root / "chrome"),
                    "--edge-manifest-dir",
                    str(root / "edge"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("TCC-protected", refused.stderr)
            self.assertFalse(dest.exists())
            self.assertFalse((home / "Documents").exists())

    def test_helper_refuses_symlink_dotdot_and_preplanted_staging(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            host = _compile_handshake_host(root / "wins_bridge_host")
            env = dict(os.environ)
            env["PYTHON_BIN"] = _synthetic_host_python(root, host)
            docs = pathlib.Path.home() / "Documents"
            link = root / "edge-link"
            link.symlink_to(docs)
            linked = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(root / "lib"),
                    "--firefox-manifest-dir",
                    str(root / "firefox"),
                    "--chrome-manifest-dir",
                    str(root / "chrome"),
                    "--edge-manifest-dir",
                    str(link),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn("symlink", linked.stderr)
            self.assertFalse((root / "lib" / "wins_bridge_host").exists())
            self.assertFalse((docs / "org.winsvpn.bridge.json").exists())

            dotdot = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    os.path.join(str(root), "notdocs", "..", "Documents"),
                    "--firefox-manifest-dir",
                    str(root / "firefox"),
                    "--chrome-manifest-dir",
                    str(root / "chrome"),
                    "--edge-manifest-dir",
                    "/tmp/.." + str(docs),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(dotdot.returncode, 0)
            self.assertTrue(
                "dot-dot" in dotdot.stderr or "TCC-protected" in dotdot.stderr,
                dotdot.stderr,
            )
            self.assertFalse((root / "Documents" / "wins_bridge_host").exists())
            self.assertFalse((docs / "org.winsvpn.bridge.json").exists())

            dest = root / "lib2"
            dest.mkdir()
            planted = dest / "wins_bridge_host.new"
            evil = root / "evil-host"
            evil.write_text("pwned\n", encoding="ascii")
            planted.symlink_to(evil)
            staged = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(dest),
                    "--firefox-manifest-dir",
                    str(root / "firefox2"),
                    "--chrome-manifest-dir",
                    str(root / "chrome2"),
                    "--edge-manifest-dir",
                    str(root / "edge2"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(staged.returncode, 0, staged.stderr + staged.stdout)
            self.assertEqual(evil.read_text(encoding="ascii"), "pwned\n")
            self.assertFalse(planted.exists())
            self.assertTrue((dest / "wins_bridge_host").is_file())
            self.assertFalse((dest / "wins_bridge_host").is_symlink())

    def test_helper_installs_edge_and_does_not_treat_generic_gate_as_sufficient(
        self,
    ) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS native-host helper requires Darwin")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            host = _compile_handshake_host(root / "wins_bridge_host")
            dest = root / "NativeMessagingHost"
            firefox_dir = root / "firefox"
            chrome_dir = root / "chrome"
            edge_dir = root / "edge"
            env = _identity_python_env(root / "site")
            env["PYTHON_BIN"] = _synthetic_host_python(root, host)
            installed = subprocess.run(
                [
                    "bash",
                    str(HELPER),
                    "--host-path",
                    str(host),
                    "--dest-dir",
                    str(dest),
                    "--firefox-manifest-dir",
                    str(firefox_dir),
                    "--chrome-manifest-dir",
                    str(chrome_dir),
                    "--edge-manifest-dir",
                    str(edge_dir),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr + installed.stdout)
            self.assertNotIn("owner-blocked", installed.stdout)
            self.assertIn("edge manifest:", installed.stdout)
            edge_path = edge_dir / "org.winsvpn.bridge.json"
            chrome_path = chrome_dir / "org.winsvpn.bridge.json"
            firefox_path = firefox_dir / "org.winsvpn.bridge.json"
            edge = json.loads(edge_path.read_text(encoding="utf-8"))
            chrome = json.loads(chrome_path.read_text(encoding="utf-8"))
            self.assertEqual(
                edge["allowed_origins"],
                [f"chrome-extension://{OWNER_EDGE_ID}/"],
            )
            self.assertEqual(
                chrome["allowed_origins"],
                [f"chrome-extension://{OWNER_CHROME_ID}/"],
            )
            self.assertNotEqual(chrome, edge)
            generic = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/apple_cross_store_artifact_gate.py"),
                    "native-host",
                    "verify-manifests",
                    "--host-path",
                    os.path.realpath(dest / "wins_bridge_host"),
                    "--firefox",
                    str(firefox_path),
                    "--chrome",
                    str(chrome_path),
                    "--owner-chrome-id",
                    OWNER_CHROME_ID,
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(generic.returncode, 0, generic.stderr)
            self.assertIn("APPLE NATIVE-HOST MANIFESTS: PASS", generic.stdout)
            helper = HELPER.read_text(encoding="ascii")
            self.assertIn("verify_chromium_manifest edge", helper)
            self.assertIn("ast.parse", helper)
            unsupported = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/apple_cross_store_artifact_gate.py"),
                    "native-host",
                    "verify-manifests",
                    "--host-path",
                    os.path.realpath(dest / "wins_bridge_host"),
                    "--firefox",
                    str(firefox_path),
                    "--edge",
                    str(edge_path),
                    "--owner-edge-id",
                    OWNER_EDGE_ID,
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(unsupported.returncode, 0)
            self.assertIn("arguments are invalid", unsupported.stderr)

    def test_cli_verify_manifests_owner_block_and_exact_chrome(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            firefox = root / "firefox.json"
            chrome = root / "chrome.json"
            _write_json(firefox, _firefox_manifest(INSTALLED_PATH))
            _write_json(chrome, _chrome_manifest(INSTALLED_PATH, OWNER_CHROME_ID))
            blocked = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/apple_cross_store_artifact_gate.py"),
                    "native-host",
                    "verify-manifests",
                    "--host-path",
                    INSTALLED_PATH,
                    "--firefox",
                    str(firefox),
                    "--chrome",
                    str(chrome),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("owner-blocked", blocked.stderr)
            passed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/apple_cross_store_artifact_gate.py"),
                    "native-host",
                    "verify-manifests",
                    "--host-path",
                    INSTALLED_PATH,
                    "--firefox",
                    str(firefox),
                    "--chrome",
                    str(chrome),
                    "--owner-chrome-id",
                    OWNER_CHROME_ID,
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(passed.returncode, 0, passed.stderr)

    def test_signature_pass_requires_documented_incompatibility(self) -> None:
        artifact = ROOT / "tools" / "apple_cross_store_artifact_gate.py"
        inner = {
            "inner_payload_sha256": "a" * 64,
            "app": "Win's VPN.app",
            "aot": {"sha256": "b" * 64},
        }
        with self.assertRaisesRegex(
            apple_gate.AppleArtifactGateError, "cannot deliver wins_bridge_host"
        ):
            apple_gate._print_signature_pass(
                "macos-app-store-pkg",
                artifact,
                inner,
                artifact_sha256="c" * 64,
            )
        inner["native_messaging"] = apple_gate.macos_native_messaging_packaging_scope(
            "macos-app-store-pkg"
        )
        stdout = []

        def capture(message: str) -> None:
            stdout.append(message)

        with mock.patch.object(apple_gate, "print", side_effect=capture):
            apple_gate._print_signature_pass(
                "macos-app-store-pkg",
                artifact,
                inner,
                artifact_sha256="c" * 64,
            )
        self.assertTrue(any("native_messaging=incompatible" in line for line in stdout))

    def test_signature_usage_contract_still_accepts_three_arguments(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/apple_cross_store_artifact_gate.py")],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("signature|privacy", completed.stderr)


if __name__ == "__main__":
    unittest.main()
