#!/usr/bin/env python3
"""Offline mutation tests for the macOS native-messaging companion PKG."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import verify_macos_native_host_companion_pkg as companion


PRODUCER = TOOLS / "build_macos_native_host_companion_pkg.sh"
VERIFIER = TOOLS / "verify_macos_native_host_companion_pkg.py"
README = ROOT / "tools/native_messaging/README-macos-companion-pkg.md"
OPERATOR_HELPER = ROOT / "tools/native_messaging/install_macos_native_host.sh"
FIXTURE_CHROME_ID = "abcdefghijklmnopabcdefghijklmnop"
FIXTURE_EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
OTHER_CHROME_ID = "cccccccccccccccccccccccccccccccc"


def _thin_mh_execute(cputype: int) -> bytes:
    data = bytearray(32 + 72 + 80)
    data[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", data, 4, cputype)
    struct.pack_into("<I", data, 12, companion.MH_EXECUTE)
    struct.pack_into("<I", data, 16, 1)
    struct.pack_into("<I", data, 20, 72 + 80)
    struct.pack_into("<I", data, 32, 0x19)
    struct.pack_into("<I", data, 36, 72 + 80)
    data[40:47] = b"__TEXT\x00"
    struct.pack_into("<I", data, 32 + 64, 1)
    data[32 + 72 : 32 + 77] = b"__text"
    data[32 + 88 : 32 + 95] = b"__TEXT\x00"
    return bytes(data)


def _with_build_version(data: bytes, version: tuple[int, int, int]) -> bytes:
    """Rewrite every slice's first load command into an LC_BUILD_VERSION."""

    encoded = (version[0] << 16) | (version[1] << 8) | version[2]
    blob = bytearray(data)

    def patch(offset: int) -> None:
        # The fixture's first load command is a 152-byte LC_SEGMENT_64; turn
        # it into LC_BUILD_VERSION(platform=macOS, minos) of the same size.
        struct.pack_into("<IIIIII", blob, offset + 32, companion.LC_BUILD_VERSION, 72 + 80, 1, encoded, encoded, 0)

    if blob[:4] == b"\xca\xfe\xba\xbe":
        count = struct.unpack_from(">I", blob, 4)[0]
        for index in range(count):
            offset = struct.unpack_from(">I", blob, 8 + index * 20 + 8)[0]
            patch(offset)
    else:
        patch(0)
    return bytes(blob)


def _universal_mh_execute() -> bytes:
    arm = _thin_mh_execute(companion.CPU_TYPE_ARM64)
    x86 = _thin_mh_execute(companion.CPU_TYPE_X86_64)
    header_len = 8 + 20 * 2
    arm_off = header_len
    x86_off = arm_off + len(arm)
    blob = bytearray(x86_off + len(x86))
    struct.pack_into(">II", blob, 0, 0xCAFEBABE, 2)
    struct.pack_into(">IIIII", blob, 8, companion.CPU_TYPE_ARM64, 0, arm_off, len(arm), 2)
    struct.pack_into(">IIIII", blob, 28, companion.CPU_TYPE_X86_64, 3, x86_off, len(x86), 2)
    blob[arm_off : arm_off + len(arm)] = arm
    blob[x86_off : x86_off + len(x86)] = x86
    return bytes(blob)


def _extract_heredoc(source: str, marker: str) -> str:
    start = f"<<'{marker}'\n"
    begin = source.index(start) + len(start)
    end = f"\n{marker}\n"
    finish = source.index(end, begin)
    return source[begin:finish]


def _firefox_manifest(host_path: str = companion.INSTALLED_HOST_PATH) -> dict[str, object]:
    return {
        "name": companion.HOST_NAME,
        "description": companion.HOST_DESCRIPTION,
        "path": host_path,
        "type": "stdio",
        "allowed_extensions": [companion.FIREFOX_EXTENSION_ID],
    }


def _chrome_manifest(
    chrome_id: str = FIXTURE_CHROME_ID,
    host_path: str = companion.INSTALLED_HOST_PATH,
) -> dict[str, object]:
    return {
        "name": companion.HOST_NAME,
        "description": companion.HOST_DESCRIPTION,
        "path": host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{chrome_id}/"],
    }


def _edge_manifest(
    edge_id: str = FIXTURE_EDGE_ID,
    host_path: str = companion.INSTALLED_HOST_PATH,
) -> dict[str, object]:
    return {
        "name": companion.HOST_NAME,
        "description": companion.HOST_DESCRIPTION,
        "path": host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{edge_id}/"],
    }


def _object_shaped_list(value: str) -> dict[str, object]:
    return {"0": value, "length": 1}


def _write_json(path: pathlib.Path, document: dict[str, object]) -> None:
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )
    path.chmod(0o644)


def _receipt_document(
    chrome_id: str = FIXTURE_CHROME_ID,
    edge_id: str = FIXTURE_EDGE_ID,
) -> dict[str, object]:
    return {
        "chrome_extension_id": chrome_id,
        "edge_extension_id": edge_id,
        "firefox_extension_id": companion.FIREFOX_EXTENSION_ID,
    }


def _bind_incoming_receipt(incoming: pathlib.Path) -> None:
    inner = []
    for name in ("wins_bridge_host", "firefox.json", "chrome.json", "edge.json", "uninstall.sh"):
        path = incoming / name
        payload = path.read_bytes()
        inner.append(
            {
                "path": f"{companion.INCOMING_RELATIVE}/{name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    document = _receipt_document()
    document["inner_files"] = inner
    _write_json(incoming / "receipt.json", document)


def _codesign_process(
    argv: list[str],
    *,
    returncode: int = 0,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, "", stderr)


def _valid_codesign_text() -> str:
    return (
        "Authority=Developer ID Application: Win's VPN Inc "
        f"({companion.TEAM_ID})\n"
        f"TeamIdentifier={companion.TEAM_ID}\n"
        "CodeDirectory v=20400 flags=0x10000(runtime)\n"
    )


def _entitlements_xml(document: dict[str, object] | None = None) -> str:
    import plistlib

    payload = dict(companion.REQUIRED_HOST_ENTITLEMENTS) if document is None else document
    return plistlib.dumps(payload).decode("utf-8")


def _entitlements_process(
    argv: list[str], document: dict[str, object] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, 0, _entitlements_xml(document), "")


GOLDEN_BOM_ROWS = (
    (".", "40755", "0", "0", ""),
    ("./._Library", "40755", "0", "0", "0"),
    ("./Library", "40755", "0", "0", ""),
    ("./Library/Application Support", "40755", "0", "0", ""),
    ("./Library/Application Support/Win's VPN", "40755", "0", "0", ""),
    ("./Library/Application Support/Win's VPN/NativeMessagingHost", "40755", "0", "0", ""),
    ("./" + companion.INCOMING_RELATIVE, "40755", "0", "0", ""),
    ("./" + companion.INCOMING_RELATIVE + "/._wins_bridge_host", "100755", "0", "0", "0"),
    ("./" + companion.INCOMING_RELATIVE + "/chrome.json", "100644", "0", "0", "275"),
    ("./" + companion.INCOMING_RELATIVE + "/wins_bridge_host", "100755", "0", "0", "6373824"),
)


def _bom_process(argv: list[str], rows=GOLDEN_BOM_ROWS) -> subprocess.CompletedProcess[str]:
    text = "".join("\t".join(row) + "\n" for row in rows)
    return subprocess.CompletedProcess(argv, 0, text, "")


def _patch_codesign(
    stderr: str | None = None,
    returncode: int = 0,
    entitlements: dict[str, object] | None = None,
    bom_rows=GOLDEN_BOM_ROWS,
) -> mock._patch:
    text = _valid_codesign_text() if stderr is None else stderr

    def run(argv, **_kwargs):
        if argv[0] == "/usr/bin/lsbom":
            return _bom_process(argv, bom_rows)
        if argv[0] != "/usr/bin/codesign":
            raise AssertionError(argv)
        if "--entitlements" in argv:
            return _entitlements_process(argv, entitlements)
        return _codesign_process(argv, returncode=returncode, stderr=text)

    return mock.patch.object(companion, "_run", side_effect=run)


class ProducerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.producer = PRODUCER.read_text(encoding="ascii")
        cls.readme = README.read_text(encoding="ascii")

    def test_producer_is_macos_operator_only_and_executable(self) -> None:
        self.assertTrue(PRODUCER.is_file())
        self.assertTrue(os.access(PRODUCER, os.X_OK))
        self.assertIn('[[ "$(uname -s)" == "Darwin" ]]', self.producer)
        self.assertIn("owner_block", self.producer)
        self.assertIn(str(companion.OWNER_BLOCK_EXIT), self.producer)
        self.assertIn("Developer ID Installer", self.producer)
        self.assertIn(companion.TEAM_ID, self.producer)
        self.assertIn(companion.INSTALLED_HOST_PATH, self.producer)
        self.assertIn(companion.FIREFOX_EXTENSION_ID, self.producer)
        self.assertIn("refusing to invent", self.producer)
        self.assertIn("--check-only", self.producer)
        self.assertIn("refusing to write a companion PKG into the repository", self.producer)
        completed = subprocess.run(
            ["/bin/bash", "-n", str(PRODUCER)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_producer_binds_distribution_to_host_facts_and_owner_ruling(self) -> None:
        self.assertIn("owner ruling 2026-10-16", self.producer.lower())
        self.assertIn("host-facts --host", self.producer)
        self.assertIn('hostArchitectures="${HOST_ARCHITECTURES}"', self.producer)
        self.assertIn('<os-version min="${HOST_MINIMUM_MACOS}"/>', self.producer)
        self.assertNotIn('hostArchitectures="arm64,x86_64"', self.producer)
        self.assertNotIn('<os-version min="11.0"/>', self.producer)
        self.assertIn('/bin/chmod 0755 "${PAYLOAD}" "${PAYLOAD}/Library"', self.producer)
        facts = self.producer.index("host-facts --host")
        self.assertLess(facts, self.producer.index("/usr/bin/pkgbuild"))
        self.assertLess(facts, self.producer.index("notarytool submit"))

    def test_signing_helper_and_entitlements_match_the_verifier(self) -> None:
        import plistlib

        helper = (ROOT / "tools/native_messaging/sign_macos_native_host.sh").read_text(
            encoding="ascii"
        )
        self.assertTrue(os.access(ROOT / "tools/native_messaging/sign_macos_native_host.sh", os.X_OK))
        for needle in (
            "--options runtime",
            "--timestamp",
            '--entitlements "${ENTITLEMENTS}"',
            "Developer ID Application:",
            'TEAM_ID="5YT8H4U72M"',
            "--selftest",
        ):
            self.assertIn(needle, helper)
        entitlements = plistlib.loads(
            (ROOT / "tools/native_messaging/macos_native_host.entitlements").read_bytes()
        )
        self.assertEqual(entitlements, companion.REQUIRED_HOST_ENTITLEMENTS)
        self.assertIn("tools/native_messaging/sign_macos_native_host.sh", companion.SOURCE_CLOSURE_PATHS)
        self.assertIn(
            "tools/native_messaging/macos_native_host.entitlements", companion.SOURCE_CLOSURE_PATHS
        )

    def test_host_facts_reports_policy_and_refuses_unsafe_hosts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-facts-") as raw:
            host = pathlib.Path(raw) / "wins_bridge_host"
            host.write_bytes(_with_build_version(_thin_mh_execute(companion.CPU_TYPE_ARM64), (14, 0, 0)))
            host.chmod(0o755)
            with _patch_codesign(), mock.patch("sys.stdout") as stdout:
                self.assertEqual(
                    companion.main(["host-facts", "--host", str(host), "--package-version", "1.0.16"]),
                    0,
                )
            written = "".join(call.args[0] for call in stdout.write.call_args_list)
            self.assertIn("host_architectures arm64\n", written)
            self.assertIn("minimum_macos 14.0\n", written)
            with _patch_codesign(), mock.patch("sys.stderr"):
                self.assertEqual(
                    companion.main(["host-facts", "--host", str(host), "--package-version", "1.0.18"]),
                    1,
                )
            with _patch_codesign(entitlements={}), mock.patch("sys.stderr"):
                self.assertEqual(
                    companion.main(["host-facts", "--host", str(host), "--package-version", "1.0.16"]),
                    1,
                )
            host.write_bytes(_with_build_version(_universal_mh_execute(), (14, 0, 0)))
            with _patch_codesign(), mock.patch("sys.stdout") as stdout:
                self.assertEqual(
                    companion.main(["host-facts", "--host", str(host), "--package-version", "1.0.18"]),
                    0,
                )
            written = "".join(call.args[0] for call in stdout.write.call_args_list)
            self.assertIn("host_architectures arm64,x86_64\n", written)

    def test_producer_does_not_invent_chrome_ids_or_skip_gates(self) -> None:
        self.assertNotIn("PLACEHOLDER", self.producer)
        self.assertIsNone(re.search(r"[a-p]{32}", self.producer))
        self.assertIn("owner_issued_chromium_ids", self.producer)
        self.assertEqual(self.producer.count("owner_issued_chromium_ids"), 1)
        self.assertNotIn("recorded-id --browser chrome", self.producer)
        self.assertNotIn("recorded-id --browser edge", self.producer)
        self.assertIn("--edge-id", self.producer)
        self.assertIn("must be distinct", self.producer)
        installer = self.producer.index("Developer ID Installer identity for team")
        pkgbuild = self.producer.index("/usr/bin/pkgbuild")
        productbuild = self.producer.index("/usr/bin/productbuild")
        stapler = self.producer.index("/usr/bin/stapler staple")
        self.assertLess(installer, pkgbuild)
        self.assertLess(pkgbuild, productbuild)
        self.assertLess(productbuild, stapler)
        self.assertIn("--sign \"${INSTALLER_IDENTITY}\"", self.producer)
        self.assertIn("notarytool submit", self.producer)
        self.assertNotIn("--allow-unsigned", self.producer)

    def test_consumer_scripts_are_static_posix_with_rollback(self) -> None:
        preinstall = _extract_heredoc(self.producer, "PREINSTALL")
        postinstall = _extract_heredoc(self.producer, "POSTINSTALL")
        uninstall = _extract_heredoc(self.producer, "UNINSTALL")
        companion.verify_scripts(preinstall, postinstall, uninstall)
        self.assertTrue(preinstall.startswith("#!/bin/sh\n"))
        self.assertTrue(postinstall.startswith("#!/bin/sh\n"))
        self.assertIn("fail before mutation", postinstall)
        self.assertIn("restore_rollback", postinstall)
        self.assertIn("/bin/mv -h", postinstall)
        self.assertIn(".winsvpn-stage", postinstall)
        self.assertIn("wins_bridge_host.new", postinstall)
        self.assertIn("cleanup_install_temps", postinstall)
        self.assertIn("exec 3<>", postinstall)
        self.assertIn("/dev/fd/3", postinstall)
        self.assertIn("held_stage_replace", postinstall)
        self.assertIn("bind_rollback_dir", postinstall)
        self.assertIn("stat -f %i /dev/fd/3", postinstall)
        self.assertIn("stat -f %HT /dev/fd/3", postinstall)
        self.assertIn("stat -f %l /dev/fd/3", postinstall)
        self.assertNotIn("stat -f '%d:%i' /dev/fd/3", postinstall)
        self.assertIn("bind_dest_parent", postinstall)
        self.assertIn("refuse_held_leaf", postinstall)
        self.assertIn("refuse_live_leaf", postinstall)
        self.assertIn("durably before any live", postinstall)
        self.assertIn("/bin/sync", postinstall)
        self.assertIn("conv=notrunc,fsync", postinstall)
        atomic_start = postinstall.index("atomic_install() {")
        verify_call = postinstall.index("verify_incoming || exit 1")
        atomic = postinstall[atomic_start:verify_call]
        self.assertLess(
            atomic.index('mark_mutated "${name}"'),
            atomic.index('held_stage_replace "${leaf}"'),
        )
        mark_fn = postinstall[
            postinstall.index("mark_mutated() {") : postinstall.index("restore_one() {")
        ]
        self.assertIn("/bin/sync", mark_fn)
        self.assertIn("refusing symlink native-host path", postinstall)
        self.assertIn("refusing special native-host path", postinstall)
        self.assertIn("refusing hardlinked native-host path", postinstall)
        self.assertNotIn('/bin/mv -f "${tmp}" "${dest}"', postinstall)
        self.assertNotIn('/bin/mv -f "${ROLLBACK}/${name}" "${dest}"', postinstall)
        self.assertNotIn('/bin/cp "${source}" "${tmp}"', postinstall)
        self.assertNotIn('/bin/cat "${source}" > "${tmp}"', postinstall)
        self.assertNotIn('"${HOST_DIR}"/.winsvpn-stage.*', postinstall)
        self.assertNotIn("${HOST_DIR}/.winsvpn-json", postinstall)
        self.assertIn(companion.EDGE_MANIFEST_PATH, preinstall)
        self.assertIn(companion.EDGE_MANIFEST_PATH, postinstall)
        self.assertIn(companion.EDGE_MANIFEST_PATH, uninstall)
        self.assertIn("must be distinct", postinstall)
        self.assertIn("chrome_extension_id", postinstall)
        self.assertIn("edge_extension_id", postinstall)
        self.assertIn("duplicate JSON key", postinstall)
        self.assertIn("json_flatten", postinstall)
        self.assertIn("inner_files", postinstall)
        self.assertIn("receipt inner_files is not exact", postinstall)
        self.assertNotIn(
            'json_has "${receipt_flat}" "inner_files.length"',
            postinstall,
        )
        self.assertIn("emit(prefix, \"array\", \"\")", postinstall)
        self.assertIn('if (prefix != "") emit(prefix, "object", "")', postinstall)
        self.assertIn('[ "${firefox_ext_type}" = "array" ]', postinstall)
        self.assertIn('[ "${chrome_origin_type}" = "array" ]', postinstall)
        self.assertIn('[ "${edge_origin_type}" = "array" ]', postinstall)
        self.assertIn('[ "${inner_type}" = "array" ]', postinstall)
        self.assertIn('[ "${inner_len}" = "5" ]', postinstall)
        self.assertNotIn('[ "${inner_len}" -ge 1 ]', postinstall)
        self.assertIn('[ "${seen_host}" = "0" ]', postinstall)
        self.assertIn('[ "${seen_firefox}" = "0" ]', postinstall)
        self.assertIn('[ "${seen_chrome}" = "0" ]', postinstall)
        self.assertIn('[ "${seen_edge}" = "0" ]', postinstall)
        self.assertIn('[ "${seen_uninstall}" = "0" ]', postinstall)
        self.assertIn('actual_bytes="$(/usr/bin/stat -f %z "${target}")"', postinstall)
        self.assertIn('[ "${actual_bytes}" = "${bytes}" ]', postinstall)
        self.assertIn("receipt-bound inner bytes do not match", postinstall)
        self.assertIn(".mutated", postinstall)
        self.assertIn("rollback could not restore", postinstall)
        self.assertNotIn("/usr/bin/grep -F", postinstall)
        self.assertIn("refusing symlink parent", preinstall)
        self.assertIn("refusing symlink parent", postinstall)
        self.assertNotIn("python3", preinstall.lower())
        self.assertNotIn("python3", postinstall.lower())
        self.assertNotIn("python3", uninstall.lower())
        self.assertNotIn("/usr/bin/python", preinstall.lower())
        self.assertNotIn("/usr/bin/python", postinstall.lower())
        self.assertNotIn("native_host_layout", preinstall)
        self.assertNotIn("native_host_layout", postinstall)
        self.assertIn("explicit", uninstall)
        self.assertIn(companion.PACKAGE_IDENTIFIER, uninstall)
        self.assertIn("bind_dest_parent", uninstall)
        self.assertIn("remove_held_leaf", uninstall)
        self.assertIn("uninstall could not remove every exact file", uninstall)
        self.assertIn("./.winsvpn-stage.*", uninstall)
        self.assertNotIn("${ROLLBACK}/.winsvpn-stage.", uninstall)
        self.assertNotIn('"${HOST_DIR}"/.winsvpn-stage.', uninstall)
        self.assertNotIn('/bin/rm -f "${path}"', uninstall)

    def test_readme_states_app_store_gap_and_missing_installer_cert(self) -> None:
        self.assertTrue(README.is_file())
        self.assertIn("install_macos_native_host.sh", self.readme)
        self.assertIn("Python", self.readme)
        self.assertIn("Mac App Store", self.readme)
        self.assertIn("Developer ID Installer", self.readme)
        self.assertIn(companion.TEAM_ID, self.readme)
        self.assertIn("owner-blocked", self.readme)
        self.assertIn("does not emit a public PKG", self.readme)
        self.assertIn("Edge", self.readme)
        self.assertIn("/Library/Microsoft/Edge/NativeMessagingHosts/org.winsvpn.bridge.json", self.readme)
        self.assertNotIn("PLACEHOLDER", self.readme)
        helper = OPERATOR_HELPER.read_text(encoding="ascii")
        self.assertIn("python3", helper.lower())

    def test_producer_reads_chrome_and_edge_from_one_identity_snapshot(self) -> None:
        self.assertIn("owner_issued_chromium_ids", self.producer)
        self.assertEqual(self.producer.count("owner_issued_chromium_ids"), 1)
        chrome_lookup = self.producer.find("recorded-id --browser chrome")
        edge_lookup = self.producer.find("recorded-id --browser edge")
        self.assertEqual(chrome_lookup, -1)
        self.assertEqual(edge_lookup, -1)
        self.assertIn("owner identity snapshot failed", self.producer)


EXPECTED_POSTINSTALL_SHORT_NEEDLES = (
    '[ "${firefox_ext_type}" = "array" ]',
    '[ "${chrome_origin_type}" = "array" ]',
    '[ "${edge_origin_type}" = "array" ]',
    '[ "${inner_type}" = "array" ]',
    '[ "${inner_len}" = "5" ]',
    '[ "${seen_host}" = "0" ]',
    '[ "${seen_firefox}" = "0" ]',
    '[ "${seen_chrome}" = "0" ]',
    '[ "${seen_edge}" = "0" ]',
    '[ "${seen_uninstall}" = "0" ]',
    '/usr/bin/stat -f %z',
    '[ "${actual_bytes}" = "${bytes}" ]',
    "receipt-bound inner bytes do not match",
    "exec 3<>",
    "/dev/fd/3",
    "cleanup_install_temps",
    "bind_rollback_dir",
    "held_stage_replace",
    "stat -f %i /dev/fd/3",
    "stat -f %HT /dev/fd/3",
    "stat -f %l /dev/fd/3",
    "/bin/sync",
    "conv=notrunc,fsync",
    "durably before any live",
)
EXPECTED_POSTINSTALL_CONTRACT_LINES = (
    '[ "${firefox_ext_type}" = "array" ] || fail "Firefox native-host manifest is not exact"',
    '[ "${chrome_origin_type}" = "array" ] || fail "Chrome native-host manifest is not exact"',
    '[ "${edge_origin_type}" = "array" ] || fail "Edge native-host manifest is not exact"',
    '[ "${inner_type}" = "array" ] || fail "receipt inner_files is not exact"',
    '[ "${inner_len}" = "5" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_host}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_firefox}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_chrome}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_edge}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_uninstall}" = "0" ] || fail "receipt inner_files is not exact"',
    'actual_bytes="$(/usr/bin/stat -f %z "${target}")"',
    '[ "${actual_bytes}" = "${bytes}" ] || fail "receipt-bound inner bytes do not match"',
)


def _companion_scripts() -> tuple[str, str, str]:
    producer = PRODUCER.read_text(encoding="ascii")
    return (
        _extract_heredoc(producer, "PREINSTALL"),
        _extract_heredoc(producer, "POSTINSTALL"),
        _extract_heredoc(producer, "UNINSTALL"),
    )


def _weaken_contract_line(line: str) -> str:
    if " || fail " in line:
        return line.split(" || fail ", 1)[0] + " || true"
    if line.startswith("actual_bytes="):
        return 'actual_bytes="0"'
    raise AssertionError(f"no reviewed weakening for {line!r}")


class ScriptSelfIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.preinstall, self.postinstall, self.uninstall = _companion_scripts()

    def test_generated_scripts_still_pass_verify_scripts(self) -> None:
        companion.verify_scripts(self.preinstall, self.postinstall, self.uninstall)

    def test_verifier_locks_array_length_uniqueness_and_stat_needles(self) -> None:
        locked_needles = frozenset(companion.REQUIRED_SCRIPT_NEEDLES)
        missing_needles = [
            needle
            for needle in EXPECTED_POSTINSTALL_SHORT_NEEDLES
            if needle not in locked_needles
        ]
        self.assertEqual(missing_needles, [])
        locked_lines = frozenset(companion.REQUIRED_POSTINSTALL_ACTIVE_LINES)
        missing_lines = [
            line
            for line in EXPECTED_POSTINSTALL_CONTRACT_LINES
            if line not in locked_lines
        ]
        self.assertEqual(missing_lines, [])
        self.assertIn(
            '[ "${inner_len}" -ge 1 ]',
            {needle for needle, _message in companion.FORBIDDEN_POSTINSTALL_NEEDLES},
        )

    def test_removing_each_required_postinstall_line_is_refused(self) -> None:
        for line in EXPECTED_POSTINSTALL_CONTRACT_LINES:
            with self.subTest(mutation="remove", line=line):
                self.assertEqual(self.postinstall.count(line), 1, line)
                mutated = self.postinstall.replace(line, "", 1)
                self.assertNotEqual(mutated, self.postinstall)
                with self.assertRaises(companion.CompanionPkgError):
                    companion.verify_scripts(self.preinstall, mutated, self.uninstall)

    def test_commenting_each_required_postinstall_line_is_refused(self) -> None:
        for line in EXPECTED_POSTINSTALL_CONTRACT_LINES:
            with self.subTest(mutation="comment", line=line):
                self.assertEqual(self.postinstall.count(line), 1, line)
                mutated = self.postinstall.replace(line, "# " + line, 1)
                self.assertNotEqual(mutated, self.postinstall)
                with self.assertRaises(companion.CompanionPkgError):
                    companion.verify_scripts(self.preinstall, mutated, self.uninstall)

    def test_weakening_each_required_postinstall_line_is_refused(self) -> None:
        for line in EXPECTED_POSTINSTALL_CONTRACT_LINES:
            with self.subTest(mutation="weaken", line=line):
                self.assertEqual(self.postinstall.count(line), 1, line)
                mutated = self.postinstall.replace(line, _weaken_contract_line(line), 1)
                self.assertNotEqual(mutated, self.postinstall)
                with self.assertRaises(companion.CompanionPkgError):
                    companion.verify_scripts(self.preinstall, mutated, self.uninstall)

    def test_required_postinstall_line_cannot_live_only_in_preinstall(self) -> None:
        for line in EXPECTED_POSTINSTALL_CONTRACT_LINES:
            with self.subTest(mutation="preinstall-only", line=line):
                mutated_post = self.postinstall.replace(line, "", 1)
                mutated_pre = self.preinstall + "\n" + line + "\n"
                self.assertNotEqual(mutated_post, self.postinstall)
                with self.assertRaises(companion.CompanionPkgError):
                    companion.verify_scripts(mutated_pre, mutated_post, self.uninstall)

    def test_weaker_inner_files_length_minimum_is_refused(self) -> None:
        exact = '[ "${inner_len}" = "5" ] || fail "receipt inner_files is not exact"'
        weaker = '[ "${inner_len}" -ge 1 ] || fail "receipt inner_files is not exact"'
        self.assertEqual(self.postinstall.count(exact), 1)
        replaced = self.postinstall.replace(exact, weaker, 1)
        with self.assertRaises(companion.CompanionPkgError):
            companion.verify_scripts(self.preinstall, replaced, self.uninstall)
        both = self.postinstall.replace(exact, exact + "\n  " + weaker, 1)
        with self.assertRaisesRegex(
            companion.CompanionPkgError, "minimum, not exact"
        ):
            companion.verify_scripts(self.preinstall, both, self.uninstall)

    def test_pathname_stage_write_and_cleanup_glob_are_refused(self) -> None:
        forbidden = {needle for needle, _message in companion.FORBIDDEN_POSTINSTALL_NEEDLES}
        self.assertIn('/bin/cat "${source}" > "${tmp}"', forbidden)
        self.assertIn('"${HOST_DIR}"/.winsvpn-stage.*', forbidden)
        self.assertIn("${HOST_DIR}/.winsvpn-json", forbidden)
        self.assertIn("stat -f '%d:%i' /dev/fd/3", forbidden)
        injected = self.postinstall.replace(
            "held_stage_replace",
            'held_stage_replace\n  /bin/cat "${source}" > "${tmp}"',
            1,
        )
        with self.assertRaisesRegex(companion.CompanionPkgError, "staging pathname"):
            companion.verify_scripts(self.preinstall, injected, self.uninstall)
        globbed = self.postinstall.replace(
            "cleanup_install_temps",
            'cleanup_install_temps\n  /bin/rm -f "${HOST_DIR}"/.winsvpn-stage.*',
            1,
        )
        with self.assertRaisesRegex(companion.CompanionPkgError, "cleanup glob"):
            companion.verify_scripts(self.preinstall, globbed, self.uninstall)
        leaked = self.postinstall.replace(
            "json_flatten",
            'json_flatten\n  scratch="${HOST_DIR}/.winsvpn-json.scratch"',
            1,
        )
        with self.assertRaisesRegex(companion.CompanionPkgError, "JSON parse scratch"):
            companion.verify_scripts(self.preinstall, leaked, self.uninstall)
        fdesc_dev = self.postinstall.replace(
            "held_stage_replace",
            "held_stage_replace\n  /usr/bin/stat -f '%d:%i' /dev/fd/3",
            1,
        )
        with self.assertRaisesRegex(companion.CompanionPkgError, "fdesc device"):
            companion.verify_scripts(self.preinstall, fdesc_dev, self.uninstall)
        pathname_rm = self.uninstall.replace(
            "remove_held_leaf",
            'remove_held_leaf\n  /bin/rm -f "${path}"',
            1,
        )
        with self.assertRaisesRegex(companion.CompanionPkgError, "mutable pathname"):
            companion.verify_scripts(self.preinstall, self.postinstall, pathname_rm)
        swapped_journal = self.postinstall.replace(
            'mark_mutated "${name}"\n  if ! (',
            'if ! (\n    held_stage_replace "${leaf}" "${mode}" < "${source}" || exit 1\n'
            '  ); then\n    fail "atomic replace failed for ${dest}"\n  fi\n'
            '  mark_mutated "${name}"\n  if ! (',
            1,
        )
        self.assertNotEqual(swapped_journal, self.postinstall)
        with self.assertRaisesRegex(
            companion.CompanionPkgError, "mutation state after live replace"
        ):
            companion.verify_scripts(self.preinstall, swapped_journal, self.uninstall)
        missing_sync = self.postinstall.replace("/bin/sync || exit 1", "true || exit 1", 1)
        self.assertNotEqual(missing_sync, self.postinstall)
        # The identity issuance also syncs, so the journal-specific check is
        # the one that fires once the mark_mutated sync is gone.
        with self.assertRaisesRegex(
            companion.CompanionPkgError, r"/bin/sync|durable mutation journal sync"
        ):
            companion.verify_scripts(self.preinstall, missing_sync, self.uninstall)
        missing_stage = self.uninstall.replace("./.winsvpn-stage.*", "./.winsvpn-absent.*")
        self.assertNotEqual(missing_stage, self.uninstall)
        with self.assertRaisesRegex(
            companion.CompanionPkgError, r"leftover stage cleanup|\./\.winsvpn-stage\.\*"
        ):
            companion.verify_scripts(self.preinstall, self.postinstall, missing_stage)
        pathname_glob = self.uninstall.replace(
            "remove_held_named_dir",
            'remove_held_named_dir\n  /bin/rm -f "${ROLLBACK}/.winsvpn-stage."*',
            1,
        )
        with self.assertRaisesRegex(companion.CompanionPkgError, "cleanup glob"):
            companion.verify_scripts(self.preinstall, self.postinstall, pathname_glob)


class SourceClosureTests(unittest.TestCase):
    def test_source_closure_binds_producer_verifier_and_readme(self) -> None:
        digest, records = companion.compute_source_closure()
        paths = tuple(item["path"] for item in records)
        self.assertEqual(paths, companion.SOURCE_CLOSURE_PATHS)
        self.assertIn("tools/build_macos_native_host_companion_pkg.sh", paths)
        self.assertIn("tools/verify_macos_native_host_companion_pkg.py", paths)
        self.assertIn("tools/native_messaging/README-macos-companion-pkg.md", paths)
        self.assertIn("pubspec.yaml", paths)
        self.assertEqual(len(digest), 64)
        self.assertNotIn("tools/test_macos_native_host_companion_pkg.py", paths)
        self.assertNotIn("tools/native_messaging/manifests/store_ids.json", paths)
        for relative in (
            "lib/browser_bridge_app_ipc.dart",
            "lib/browser_bridge_framing.dart",
            "lib/browser_bridge_protocol.dart",
            "lib/winn_protocol_dispatch.dart",
        ):
            self.assertIn(relative, paths)
        for link in (ROOT / "tools/native_messaging/host/lib").iterdir():
            resolved = os.path.normpath(os.path.join("tools/native_messaging/host/lib", os.readlink(link)))
            self.assertIn(resolved, paths, link.name)

    def test_producer_refuses_native_host_source_drift_from_the_reviewed_pin(self) -> None:
        producer = PRODUCER.read_text(encoding="ascii")
        self.assertIn("bind_macos_native_host_source_freeze()", producer)
        self.assertIn("does not match the reviewed macOS pin", producer)
        self.assertLess(
            producer.index("bind_macos_native_host_source_freeze()"),
            producer.index("/usr/bin/pkgbuild"),
        )


class ExpandedPayloadMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-macos-companion-"))
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.expanded = self.temp / "expanded"
        self._write_golden()

    def _write_golden(
        self,
        *,
        host_bytes: bytes | None = None,
        chrome_id: str = FIXTURE_CHROME_ID,
        edge_id: str = FIXTURE_EDGE_ID,
        firefox: dict[str, object] | None = None,
        chrome: dict[str, object] | None = None,
        edge: dict[str, object] | None = None,
        host_architectures: str = "arm64,x86_64",
        minimum_macos: str = "14.0",
    ) -> pathlib.Path:
        pkg = (
            self.expanded
            / "org.winsvpn.bridge.nativemessaginghost.pkg"
        )
        package_version = companion.release_version(repo=ROOT)
        (self.expanded / "Distribution").parent.mkdir(parents=True, exist_ok=True)
        (self.expanded / "Distribution").write_text(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<installer-gui-script minSpecVersion=\"2\">\n"
            "  <options customize=\"never\" require-scripts=\"true\" "
            f"hostArchitectures=\"{host_architectures}\"/>\n"
            "  <volume-check><allowed-os-versions>"
            f"<os-version min=\"{minimum_macos}\"/>"
            "</allowed-os-versions></volume-check>\n"
            f"  <choice id=\"{companion.PACKAGE_IDENTIFIER}\">"
            f"<pkg-ref id=\"{companion.PACKAGE_IDENTIFIER}\"/></choice>\n"
            f"  <pkg-ref id=\"{companion.PACKAGE_IDENTIFIER}\" "
            f"version=\"{package_version}\" onConclusion=\"none\">"
            f"{companion.PACKAGE_IDENTIFIER}.pkg</pkg-ref>\n"
            "</installer-gui-script>\n",
            encoding="ascii",
        )
        incoming = pkg.joinpath(
            *pathlib.PurePosixPath(companion.INCOMING_RELATIVE).parts
        )
        scripts = pkg / "Scripts"
        incoming.mkdir(parents=True)
        scripts.mkdir(parents=True)
        (pkg / "Bom").write_bytes(b"BOMStore-fixture\n")
        (pkg / "PackageInfo").write_text(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            f"<pkg-info identifier=\"{companion.PACKAGE_IDENTIFIER}\" "
            f"version=\"{package_version}\" auth=\"root\"/>\n",
            encoding="ascii",
        )
        producer = PRODUCER.read_text(encoding="ascii")
        (scripts / "preinstall").write_text(
            _extract_heredoc(producer, "PREINSTALL") + "\n", encoding="ascii"
        )
        (scripts / "postinstall").write_text(
            _extract_heredoc(producer, "POSTINSTALL") + "\n", encoding="ascii"
        )
        (scripts / "preinstall").chmod(0o755)
        (scripts / "postinstall").chmod(0o755)
        host = incoming / "wins_bridge_host"
        host.write_bytes(host_bytes if host_bytes is not None else _universal_mh_execute())
        host.chmod(0o755)
        _write_json(incoming / "firefox.json", firefox or _firefox_manifest())
        _write_json(incoming / "chrome.json", chrome or _chrome_manifest(chrome_id))
        _write_json(incoming / "edge.json", edge or _edge_manifest(edge_id))
        (incoming / "uninstall.sh").write_text(
            _extract_heredoc(producer, "UNINSTALL") + "\n", encoding="ascii"
        )
        (incoming / "uninstall.sh").chmod(0o755)
        companion.write_receipt(
            payload_root=pkg,
            scripts_dir=scripts,
            chrome_id=chrome_id,
            edge_id=edge_id,
            output=incoming / "receipt.json",
            repo=ROOT,
        )
        return pkg

    def _pkg(self) -> pathlib.Path:
        return self.expanded / "org.winsvpn.bridge.nativemessaginghost.pkg"

    def _incoming(self) -> pathlib.Path:
        return self._pkg().joinpath(
            *pathlib.PurePosixPath(companion.INCOMING_RELATIVE).parts
        )

    def _scripts(self) -> pathlib.Path:
        return self._pkg() / "Scripts"

    def test_golden_expanded_payload_passes_inner_checks(self) -> None:
        with _patch_codesign():
            record = companion.verify_expanded_root(self.expanded)
        self.assertEqual(record["team_id"], companion.TEAM_ID)
        self.assertEqual(set(record["architectures"]), {"arm64", "x86_64"})
        self.assertEqual(record["chrome_extension_id"], FIXTURE_CHROME_ID)
        self.assertEqual(record["edge_extension_id"], FIXTURE_EDGE_ID)
        self.assertEqual(record["installed_host_path"], companion.INSTALLED_HOST_PATH)

    def test_unsigned_host_is_refused(self) -> None:
        with _patch_codesign(stderr="code object is not signed at all\n", returncode=1):
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "cryptographically invalid"
            ):
                companion.verify_expanded_root(self.expanded)

    def test_cryptographically_invalid_host_signature_is_refused(self) -> None:
        def run(argv, **_kwargs):
            if argv[0] == "/usr/bin/lsbom":
                return _bom_process(argv)
            if argv[:2] == ["/usr/bin/codesign", "--verify"]:
                return _codesign_process(
                    argv, returncode=1, stderr="code object is not signed at all\n"
                )
            if "--entitlements" in argv:
                return _entitlements_process(argv)
            return _codesign_process(argv, stderr=_valid_codesign_text())

        with mock.patch.object(companion, "_run", side_effect=run):
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "cryptographically invalid"
            ):
                companion.verify_expanded_root(self.expanded)

    def test_one_missing_architecture_is_refused(self) -> None:
        shutil.rmtree(self.expanded)
        self._write_golden(
            host_bytes=_thin_mh_execute(companion.CPU_TYPE_ARM64),
            host_architectures="arm64",
        )
        # Outside the owner-ruled 1.0.16 and 1.0.17 lines an arm64-only host is refused.
        with mock.patch.object(companion, "ARM64_ONLY_RELEASE_LINES", frozenset()):
            with _patch_codesign():
                with self.assertRaisesRegex(companion.CompanionPkgError, "universal"):
                    companion.verify_expanded_root(self.expanded)

    def test_release_1_0_16_accepts_arm64_host_under_owner_ruling(self) -> None:
        self.assertEqual(companion.ARM64_ONLY_OWNER_RULING_DATE, "2026-10-16")
        self.assertEqual(companion.ARM64_ONLY_RELEASE_LINES, frozenset({"1.0.16", "1.0.17"}))
        shutil.rmtree(self.expanded)
        self._write_golden(
            host_bytes=_thin_mh_execute(companion.CPU_TYPE_ARM64),
            host_architectures="arm64",
        )
        receipt = json.loads((self._incoming() / "receipt.json").read_text(encoding="ascii"))
        self.assertEqual(receipt["package_version"], "1.0.17")
        with _patch_codesign():
            record = companion.verify_expanded_root(self.expanded)
        self.assertEqual(record["architectures"], ["arm64"])
        self.assertEqual(
            companion.accepted_architecture_sets("1.0.16"),
            [companion.REQUIRED_ARCHITECTURES, companion.ARM64_ONLY_ARCHITECTURES],
        )
        self.assertEqual(
            companion.accepted_architecture_sets("1.0.17"),
            [companion.REQUIRED_ARCHITECTURES, companion.ARM64_ONLY_ARCHITECTURES],
        )
        self.assertEqual(
            companion.accepted_architecture_sets("1.0.18"), [companion.REQUIRED_ARCHITECTURES]
        )

    def test_arm64_host_with_universal_distribution_is_refused(self) -> None:
        shutil.rmtree(self.expanded)
        self._write_golden(
            host_bytes=_thin_mh_execute(companion.CPU_TYPE_ARM64),
            host_architectures="arm64,x86_64",
        )
        with mock.patch.object(companion, "ARM64_ONLY_RELEASE_LINES", frozenset({companion.release_version(repo=ROOT)})):
            with _patch_codesign():
                with self.assertRaisesRegex(companion.CompanionPkgError, "hostArchitectures"):
                    companion.verify_expanded_root(self.expanded)

    def test_x86_64_only_host_is_refused_even_under_the_ruling(self) -> None:
        shutil.rmtree(self.expanded)
        self._write_golden(
            host_bytes=_thin_mh_execute(companion.CPU_TYPE_X86_64),
            host_architectures="x86_64",
        )
        with mock.patch.object(companion, "ARM64_ONLY_RELEASE_LINES", frozenset({companion.release_version(repo=ROOT)})):
            with _patch_codesign():
                with self.assertRaisesRegex(companion.CompanionPkgError, "owner ruling"):
                    companion.verify_expanded_root(self.expanded)

    def test_distribution_older_than_host_minimum_macos_is_refused(self) -> None:
        shutil.rmtree(self.expanded)
        self._write_golden(
            host_bytes=_with_build_version(_universal_mh_execute(), (14, 0, 0)),
            minimum_macos="11.0",
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "older than the host's minimum 14.0"):
                companion.verify_expanded_root(self.expanded)
        shutil.rmtree(self.expanded)
        self._write_golden(
            host_bytes=_with_build_version(_universal_mh_execute(), (14, 0, 0)),
            minimum_macos="14.0",
        )
        with _patch_codesign():
            record = companion.verify_expanded_root(self.expanded)
        self.assertEqual(record["minimum_macos"], "14.0")

    def test_missing_distribution_options_are_refused(self) -> None:
        distribution = self.expanded / "Distribution"
        text = distribution.read_text(encoding="ascii")
        start = text.index("  <options")
        end = text.index("\n", start) + 1
        distribution.write_text(text[:start] + text[end:], encoding="ascii")
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "options are not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_productbuild_hash_component_reference_is_accepted(self) -> None:
        distribution = self.expanded / "Distribution"
        text = distribution.read_text(encoding="ascii")
        bare = f">{companion.PACKAGE_IDENTIFIER}.pkg</pkg-ref>"
        self.assertIn(bare, text)
        distribution.write_text(
            text.replace(bare, f">#{companion.PACKAGE_IDENTIFIER}.pkg</pkg-ref>"), encoding="ascii"
        )
        with _patch_codesign():
            companion.verify_expanded_root(self.expanded)
        distribution.write_text(
            text.replace(bare, f">#other.component.pkg</pkg-ref>"), encoding="ascii"
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "package identity|payload is not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_component_bom_ownership_modes_and_appledouble_are_exact(self) -> None:
        rows = list(GOLDEN_BOM_ROWS)
        with _patch_codesign(bom_rows=tuple(rows)):
            self.assertEqual(companion.verify_component_bom(self._pkg()), len(rows))
        cases = (
            ((".", "40700", "0", "0", ""), "not 0755"),
            (("./Library", "40775", "0", "0", ""), "group/other-writable"),
            (("./Library", "40755", "501", "0", ""), "root:wheel"),
            (("./Library/._Application Support", "40755", "0", "0", "82"), "AppleDouble"),
        )
        for row, message in cases:
            mutated = [r for r in rows if r[0] != row[0]] + [row]
            with _patch_codesign(bom_rows=tuple(mutated)):
                with self.assertRaisesRegex(companion.CompanionPkgError, message):
                    companion.verify_expanded_root(self.expanded)
        with _patch_codesign(bom_rows=tuple(r for r in rows if r[0] != ".")):
            with self.assertRaisesRegex(companion.CompanionPkgError, "no payload root"):
                companion.verify_expanded_root(self.expanded)
        (self._pkg() / "Bom").unlink()
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "Bom is missing"):
                companion.verify_expanded_root(self.expanded)

    def test_host_entitlements_must_be_exact(self) -> None:
        with _patch_codesign(entitlements={}):
            with self.assertRaisesRegex(companion.CompanionPkgError, "entitlements are not exact"):
                companion.verify_expanded_root(self.expanded)
        for extra in (
            "com.apple.security.cs.allow-jit",
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.app-sandbox",
        ):
            document = dict(companion.REQUIRED_HOST_ENTITLEMENTS)
            document[extra] = True
            with _patch_codesign(entitlements=document):
                with self.assertRaisesRegex(companion.CompanionPkgError, "entitlements are not exact"):
                    companion.verify_expanded_root(self.expanded)
        wrong_group = dict(companion.REQUIRED_HOST_ENTITLEMENTS)
        wrong_group["com.apple.security.application-groups"] = ["ABCD123456.group.org.winsvpn.app"]
        with _patch_codesign(entitlements=wrong_group):
            with self.assertRaisesRegex(companion.CompanionPkgError, "entitlements are not exact"):
                companion.verify_expanded_root(self.expanded)

        def run(argv, **_kwargs):
            if argv[0] == "/usr/bin/lsbom":
                return _bom_process(argv)
            if "--entitlements" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            return _codesign_process(argv, stderr=_valid_codesign_text())

        with mock.patch.object(companion, "_run", side_effect=run):
            with self.assertRaisesRegex(companion.CompanionPkgError, "carries no entitlements"):
                companion.verify_expanded_root(self.expanded)

    def test_wrong_team_is_refused(self) -> None:
        text = (
            "Authority=Developer ID Application: Other Org (ABCD123456)\n"
            "TeamIdentifier=ABCD123456\n"
            "CodeDirectory v=20400 flags=0x10000(runtime)\n"
        )
        with _patch_codesign(stderr=text):
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "team identity is not release-valid"
            ):
                companion.verify_expanded_root(self.expanded)

    def test_wrong_component_identifier_is_refused(self) -> None:
        package_info = self._pkg() / "PackageInfo"
        package_info.write_text(
            package_info.read_text(encoding="ascii").replace(
                companion.PACKAGE_IDENTIFIER, "org.attacker.bridge", 1
            ),
            encoding="ascii",
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "PackageInfo identity"):
                companion.verify_expanded_root(self.expanded)

    def test_wrong_distribution_version_is_refused(self) -> None:
        distribution = self.expanded / "Distribution"
        distribution.write_text(
            distribution.read_text(encoding="ascii").replace(
                f'version=\"{companion.release_version(repo=ROOT)}\"',
                'version=\"999.0.0\"',
            ),
            encoding="ascii",
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "version or payload"):
                companion.verify_expanded_root(self.expanded)

    def test_extra_product_component_is_refused(self) -> None:
        (self.expanded / "attacker.pkg").mkdir()
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "top-level identity"):
                companion.verify_expanded_root(self.expanded)

    def test_extra_receipt_field_is_refused(self) -> None:
        receipt_path = self._incoming() / "receipt.json"
        document = json.loads(receipt_path.read_text(encoding="ascii"))
        document["ignored_security_claim"] = True
        _write_json(receipt_path, document)
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "field set is not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_app_store_signer_is_refused(self) -> None:
        text = (
            "Authority=Apple Distribution: Win's VPN Inc "
            f"({companion.TEAM_ID})\n"
            f"TeamIdentifier={companion.TEAM_ID}\n"
            "CodeDirectory v=20400 flags=0x10000(runtime)\n"
        )
        with _patch_codesign(stderr=text):
            with self.assertRaisesRegex(companion.CompanionPkgError, "App Store signing"):
                companion.verify_expanded_root(self.expanded)

    def test_wrong_path_is_refused(self) -> None:
        _write_json(
            self._incoming() / "firefox.json",
            _firefox_manifest("/tmp/wrong/wins_bridge_host"),
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_python_dependent_scripts_are_refused(self) -> None:
        post = self._scripts() / "postinstall"
        post.write_text(post.read_text(encoding="ascii") + "python3 -c 'pass'\n", encoding="ascii")
        companion.write_receipt(
            payload_root=self._pkg(),
            scripts_dir=self._scripts(),
            chrome_id=FIXTURE_CHROME_ID,
            edge_id=FIXTURE_EDGE_ID,
            output=self._incoming() / "receipt.json",
            repo=ROOT,
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "Python-dependent"):
                companion.verify_expanded_root(self.expanded)

    def test_symlink_payload_is_refused(self) -> None:
        host = self._incoming() / "wins_bridge_host"
        payload = host.read_bytes()
        host.unlink()
        target = self.temp / "outside-host"
        target.write_bytes(payload)
        os.symlink(target, host)
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "symlink"):
                companion.verify_expanded_root(self.expanded)

    def test_writable_files_are_refused(self) -> None:
        firefox = self._incoming() / "firefox.json"
        firefox.chmod(0o666)
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "writable"):
                companion.verify_expanded_root(self.expanded)

    def test_missing_extension_ids_are_refused(self) -> None:
        document = _chrome_manifest()
        del document["allowed_origins"]
        _write_json(self._incoming() / "chrome.json", document)
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_wrong_extension_ids_are_refused(self) -> None:
        _write_json(
            self._incoming() / "chrome.json",
            _chrome_manifest(OTHER_CHROME_ID),
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "not exact"):
                companion.verify_expanded_root(self.expanded)
        _write_json(self._incoming() / "chrome.json", _chrome_manifest())
        _write_json(self._incoming() / "edge.json", _edge_manifest(OTHER_CHROME_ID))
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "not exact"):
                companion.verify_expanded_root(self.expanded)
        _write_json(self._incoming() / "edge.json", _edge_manifest())
        wrong_firefox = _firefox_manifest()
        wrong_firefox["allowed_extensions"] = ["wrong@example.org"]
        _write_json(self._incoming() / "firefox.json", wrong_firefox)
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_swapped_chrome_and_edge_identity_is_refused(self) -> None:
        _write_json(self._incoming() / "edge.json", _edge_manifest(FIXTURE_CHROME_ID))
        with _patch_codesign():
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "reuses the Chrome identity"
            ):
                companion.verify_expanded_root(self.expanded)
        _write_json(self._incoming() / "edge.json", _edge_manifest())
        _write_json(self._incoming() / "chrome.json", _chrome_manifest(FIXTURE_EDGE_ID))
        with _patch_codesign():
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "reuses the Edge identity"
            ):
                companion.verify_expanded_root(self.expanded)

    def test_reused_chrome_and_edge_identity_is_refused(self) -> None:
        _write_json(self._incoming() / "edge.json", _edge_manifest(FIXTURE_CHROME_ID))
        with self.assertRaisesRegex(companion.OwnerBlocked, "distinct"):
            companion.write_receipt(
                payload_root=self._pkg(),
                scripts_dir=self._scripts(),
                chrome_id=FIXTURE_CHROME_ID,
                edge_id=FIXTURE_CHROME_ID,
                output=self._incoming() / "receipt.json",
                repo=ROOT,
            )
        with _patch_codesign():
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "reuses the Chrome identity"
            ):
                companion.verify_expanded_root(self.expanded)

    def test_placeholder_edge_id_is_refused(self) -> None:
        with self.assertRaisesRegex(companion.OwnerBlocked, "invent"):
            companion.write_receipt(
                payload_root=self._pkg(),
                scripts_dir=self._scripts(),
                chrome_id=FIXTURE_CHROME_ID,
                edge_id="PLACEHOLDER_EDGE_EXTENSION_ID",
                output=self._incoming() / "receipt.json",
                repo=ROOT,
            )
        _write_json(
            self._incoming() / "edge.json",
            _edge_manifest("PLACEHOLDER_EDGE_EXTENSION_ID"),
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "placeholder"):
                companion.verify_expanded_root(self.expanded)

    def test_missing_edge_manifest_is_refused(self) -> None:
        (self._incoming() / "edge.json").unlink()
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "file set is not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_rollback_omission_is_refused(self) -> None:
        post = self._scripts() / "postinstall"
        body = post.read_text(encoding="ascii").replace("restore_rollback", "noop_restore")
        post.write_text(body, encoding="ascii")
        companion.write_receipt(
            payload_root=self._pkg(),
            scripts_dir=self._scripts(),
            chrome_id=FIXTURE_CHROME_ID,
            edge_id=FIXTURE_EDGE_ID,
            output=self._incoming() / "receipt.json",
            repo=ROOT,
        )
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "rollback"):
                companion.verify_expanded_root(self.expanded)

    def test_missing_receipt_is_refused(self) -> None:
        (self._incoming() / "receipt.json").unlink()
        with _patch_codesign():
            with self.assertRaisesRegex(companion.CompanionPkgError, "file set is not exact"):
                companion.verify_expanded_root(self.expanded)

    def test_wrong_inner_byte_counts_fail_verifier(self) -> None:
        receipt_path = self._incoming() / "receipt.json"
        document = json.loads(receipt_path.read_text(encoding="ascii"))
        inner = document["inner_files"]
        self.assertIsInstance(inner, list)
        self.assertGreaterEqual(len(inner), 1)
        for item in inner:
            self.assertIsInstance(item, dict)
            item["bytes"] = int(item["bytes"]) + 999
        _write_json(receipt_path, document)
        with _patch_codesign():
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "receipt-bound inner bytes do not match"
            ):
                companion.verify_expanded_root(self.expanded)


class PkgIdentityMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-macos-companion-pkg-"))
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.pkg = self.temp / "companion.pkg"
        self.pkg.write_bytes(b"synthetic-companion-pkg\n")

    def _run_map(self, mapping: dict[str, subprocess.CompletedProcess[str]]):
        def run(argv, **_kwargs):
            key = argv[0]
            if key not in mapping:
                raise AssertionError(argv)
            result = mapping[key]
            return subprocess.CompletedProcess(argv, result.returncode, result.stdout, result.stderr)

        return mock.patch.object(companion, "_run", side_effect=run)

    def _signed_installer(self) -> str:
        return (
            "Package \"companion.pkg\":\n"
            "   Status: signed by a developer certificate issued by Apple for distribution\n"
            "   Certificate Chain:\n"
            "    1. Developer ID Installer: Win's VPN Inc "
            f"({companion.TEAM_ID})\n"
        )

    def test_unsigned_pkg_is_refused(self) -> None:
        mapping = {
            "/usr/sbin/pkgutil": _codesign_process(
                ["/usr/sbin/pkgutil"],
                stderr="Package \"companion.pkg\":\n   Status: no signature\n",
            )
        }
        with self._run_map(mapping):
            with self.assertRaisesRegex(companion.CompanionPkgError, "unsigned"):
                companion.verify_pkg_identity(self.pkg)

    def test_wrong_installer_team_is_refused(self) -> None:
        mapping = {
            "/usr/sbin/pkgutil": _codesign_process(
                ["/usr/sbin/pkgutil"],
                stderr=(
                    "Status: signed by a developer certificate issued by Apple for distribution\n"
                    "1. Developer ID Installer: Other Org (ABCD123456)\n"
                ),
            )
        }
        with self._run_map(mapping):
            with self.assertRaisesRegex(
                companion.CompanionPkgError, "Developer ID Installer team"
            ):
                companion.verify_pkg_identity(self.pkg)

    def test_unstapled_ticket_is_refused(self) -> None:
        mapping = {
            "/usr/sbin/pkgutil": _codesign_process(
                ["/usr/sbin/pkgutil"], stderr=self._signed_installer()
            ),
            "/usr/bin/stapler": _codesign_process(
                ["/usr/bin/stapler"],
                returncode=1,
                stderr="Processing: companion.pkg\nerror: The ticket is missing.\n",
            ),
        }
        with self._run_map(mapping):
            with self.assertRaisesRegex(companion.CompanionPkgError, "not stapled"):
                companion.verify_pkg_identity(self.pkg)

    def test_signed_stapled_notarized_pkg_identity_passes(self) -> None:
        mapping = {
            "/usr/sbin/pkgutil": _codesign_process(
                ["/usr/sbin/pkgutil"], stderr=self._signed_installer()
            ),
            "/usr/bin/stapler": _codesign_process(
                ["/usr/bin/stapler"], stderr="Processing: companion.pkg\nThe validate action worked!\n"
            ),
            "/usr/sbin/spctl": _codesign_process(
                ["/usr/sbin/spctl"],
                stderr="accepted\nsource=Notarized Developer ID\n",
            ),
        }
        with self._run_map(mapping):
            record = companion.verify_pkg_identity(self.pkg)
        self.assertEqual(record["team_id"], companion.TEAM_ID)
        self.assertEqual(record["installer"], "Developer ID Installer")


class PkgByteCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-pkg-custody-"))
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.pkg = self.temp / "caller.pkg"
        self.original = b"signed-original-companion-package\n"
        self.pkg.write_bytes(self.original)

    def _inner_record(self) -> dict[str, object]:
        return {
            "installed_host_path": companion.INSTALLED_HOST_PATH,
            "team_id": companion.TEAM_ID,
        }

    def test_all_tools_receive_one_bound_snapshot(self) -> None:
        observed: list[pathlib.Path] = []

        def identity(snapshot: pathlib.Path) -> dict[str, str]:
            observed.append(snapshot)
            self.assertNotEqual(snapshot, self.pkg)
            self.assertEqual(snapshot.read_bytes(), self.original)
            self.pkg.write_bytes(b"attacker replacement\n")
            return {"team_id": companion.TEAM_ID, "installer": "Developer ID Installer"}

        def expand(snapshot: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
            observed.append(snapshot)
            self.assertEqual(snapshot.read_bytes(), self.original)
            destination.mkdir()
            return destination

        with mock.patch.object(companion, "verify_pkg_identity", side_effect=identity), mock.patch.object(
            companion, "expand_pkg", side_effect=expand
        ), mock.patch.object(companion, "verify_expanded_root", return_value=self._inner_record()):
            record = companion.verify_companion_pkg(self.pkg)
        self.assertEqual(len(set(observed)), 1)
        self.assertEqual(record["package_sha256"], hashlib.sha256(self.original).hexdigest())
        self.assertEqual(record["package_bytes"], len(self.original))

    def test_hardlinked_caller_pkg_is_refused(self) -> None:
        alias = self.temp / "alias.pkg"
        os.link(self.pkg, alias)
        with self.assertRaisesRegex(companion.CompanionPkgError, "unaliased regular file"):
            companion.verify_companion_pkg(self.pkg)

    def test_snapshot_mutation_during_tooling_is_refused(self) -> None:
        def identity(snapshot: pathlib.Path) -> dict[str, str]:
            os.chmod(snapshot, 0o600)
            snapshot.write_bytes(b"mutated custody bytes\n")
            return {"team_id": companion.TEAM_ID, "installer": "Developer ID Installer"}

        def expand(_snapshot: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
            destination.mkdir()
            return destination

        with mock.patch.object(companion, "verify_pkg_identity", side_effect=identity), mock.patch.object(
            companion, "expand_pkg", side_effect=expand
        ), mock.patch.object(companion, "verify_expanded_root", return_value=self._inner_record()):
            with self.assertRaisesRegex(companion.CompanionPkgError, "custody snapshot changed"):
                companion.verify_companion_pkg(self.pkg)


class ProducerOwnerBlockTests(unittest.TestCase):
    def test_producer_owner_blocks_and_does_not_write_a_pkg(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-run-") as raw:
            root = pathlib.Path(raw)
            host = root / "wins_bridge_host"
            host.write_bytes(_universal_mh_execute())
            host.chmod(0o755)
            output = root / "companion.pkg"
            completed = subprocess.run(
                [
                    "/bin/bash",
                    str(PRODUCER),
                    "--host",
                    str(host),
                    "--output",
                    str(output),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, companion.OWNER_BLOCK_EXIT, completed.stderr)
            self.assertIn("owner gate", completed.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_suffix(".pkg.new").exists())
            check_only = subprocess.run(
                [
                    "/bin/bash",
                    str(PRODUCER),
                    "--host",
                    str(host),
                    "--output",
                    str(output),
                    "--check-only",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(check_only.returncode, companion.OWNER_BLOCK_EXIT, check_only.stderr)
            self.assertFalse(output.exists())

    def test_producer_refuses_repository_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-repo-") as raw:
            host = pathlib.Path(raw) / "wins_bridge_host"
            host.write_bytes(_universal_mh_execute())
            host.chmod(0o755)
            output = ROOT / "companion-must-not-exist.pkg"
            completed = subprocess.run(
                [
                    "/bin/bash",
                    str(PRODUCER),
                    "--host",
                    str(host),
                    "--output",
                    str(output),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("repository", completed.stderr)
            self.assertFalse(output.exists())


class ScriptBehaviorTests(unittest.TestCase):
    def test_extracted_scripts_fail_before_mutation_and_roll_back(self) -> None:
        producer = PRODUCER.read_text(encoding="ascii")
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-scripts-") as raw:
            work = pathlib.Path(raw)
            preinstall = work / "preinstall"
            postinstall = work / "postinstall"
            uninstall = work / "uninstall.sh"
            preinstall.write_text(_extract_heredoc(producer, "PREINSTALL") + "\n", encoding="ascii")
            postinstall.write_text(_extract_heredoc(producer, "POSTINSTALL") + "\n", encoding="ascii")
            uninstall.write_text(_extract_heredoc(producer, "UNINSTALL") + "\n", encoding="ascii")
            for path in (preinstall, postinstall, uninstall):
                path.chmod(0o755)

            volume = work / "vol"
            library = volume / "Library"
            library.mkdir(parents=True)
            host_dir = (
                volume
                / "Library"
                / "Application Support"
                / "Win's VPN"
                / "NativeMessagingHost"
            )
            firefox_dir = (
                volume
                / "Library"
                / "Application Support"
                / "Mozilla"
                / "NativeMessagingHosts"
            )
            chrome_dir = volume / "Library" / "Google" / "Chrome" / "NativeMessagingHosts"
            edge_dir = volume / "Library" / "Microsoft" / "Edge" / "NativeMessagingHosts"
            host_dir.mkdir(parents=True)
            firefox_dir.mkdir(parents=True)
            chrome_dir.mkdir(parents=True)
            edge_dir.mkdir(parents=True)
            live_host = host_dir / "wins_bridge_host"
            live_firefox = firefox_dir / "org.winsvpn.bridge.json"
            live_chrome = chrome_dir / "org.winsvpn.bridge.json"
            live_edge = edge_dir / "org.winsvpn.bridge.json"
            live_host.write_text("old-host\n", encoding="ascii")
            live_host.chmod(0o755)
            live_firefox.write_text("old-firefox\n", encoding="ascii")
            live_chrome.write_text("old-chrome\n", encoding="ascii")
            live_edge.write_text("old-edge\n", encoding="ascii")

            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)

            missing = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(live_host.read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(live_firefox.read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(live_edge.read_text(encoding="ascii"), "old-edge\n")

            incoming = host_dir / "Incoming"
            incoming.mkdir()
            (incoming / "wins_bridge_host").write_bytes(_universal_mh_execute())
            (incoming / "wins_bridge_host").chmod(0o755)
            _write_json(incoming / "firefox.json", _firefox_manifest())
            _write_json(incoming / "chrome.json", _chrome_manifest())
            shutil.copy2(incoming / "chrome.json", incoming / "edge.json")
            _write_json(incoming / "receipt.json", _receipt_document())
            shutil.copy2(uninstall, incoming / "uninstall.sh")
            (incoming / "uninstall.sh").chmod(0o755)

            reused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(reused.returncode, 0)
            self.assertIn("must be distinct", reused.stderr)
            self.assertEqual(live_host.read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(live_edge.read_text(encoding="ascii"), "old-edge\n")

            shutil.copy2(incoming / "chrome.json", incoming / "edge.json")
            _write_json(incoming / "chrome.json", _edge_manifest())
            swapped = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(swapped.returncode, 0)
            self.assertTrue(
                "not exact" in swapped.stderr or "reuses" in swapped.stderr,
                swapped.stderr,
            )
            self.assertEqual(live_host.read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(live_firefox.read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(live_chrome.read_text(encoding="ascii"), "old-chrome\n")
            self.assertEqual(live_edge.read_text(encoding="ascii"), "old-edge\n")

            _write_json(incoming / "chrome.json", _chrome_manifest())
            _write_json(
                incoming / "edge.json",
                _edge_manifest("PLACEHOLDER_EDGE_EXTENSION_ID"),
            )
            placeholder = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(placeholder.returncode, 0)
            self.assertTrue(
                "placeholder" in placeholder.stderr.lower()
                or "not exact" in placeholder.stderr,
                placeholder.stderr,
            )
            self.assertEqual(live_edge.read_text(encoding="ascii"), "old-edge\n")

            _write_json(incoming / "edge.json", _edge_manifest())
            fuzzy = _firefox_manifest()
            fuzzy["allowed_extensions"] = ["companion@winsvpnXorg"]
            _write_json(incoming / "firefox.json", fuzzy)
            firefox_regex = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(firefox_regex.returncode, 0)
            self.assertIn("Firefox extension id is not exact", firefox_regex.stderr)
            self.assertEqual(live_firefox.read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(live_edge.read_text(encoding="ascii"), "old-edge\n")

            _write_json(incoming / "firefox.json", _firefox_manifest())
            _write_json(incoming / "edge.json", _edge_manifest())
            _bind_incoming_receipt(incoming)

            subprocess.run(
                ["/usr/bin/chflags", "uchg", str(live_chrome)],
                check=True,
                capture_output=True,
                text=True,
            )
            failed = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            subprocess.run(
                ["/usr/bin/chflags", "nouchg", str(live_chrome)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(failed.returncode, 0, failed.stderr)
            self.assertEqual(live_host.read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(live_firefox.read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(live_chrome.read_text(encoding="ascii"), "old-chrome\n")
            self.assertEqual(live_edge.read_text(encoding="ascii"), "old-edge\n")

            installed = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertNotEqual(live_host.read_bytes(), b"old-host\n")
            self.assertEqual(
                json.loads(live_firefox.read_text(encoding="ascii"))["path"],
                companion.INSTALLED_HOST_PATH,
            )
            self.assertEqual(
                json.loads(live_edge.read_text(encoding="ascii"))["allowed_origins"],
                [f"chrome-extension://{FIXTURE_EDGE_ID}/"],
            )
            self.assertFalse(incoming.exists())

            removed = subprocess.run(
                ["/bin/sh", str(uninstall), str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(live_host.exists())
            self.assertFalse(live_firefox.exists())
            self.assertFalse(live_chrome.exists())
            self.assertFalse(live_edge.exists())

    def test_preinstall_refuses_symlink_microsoft_parent(self) -> None:
        producer = PRODUCER.read_text(encoding="ascii")
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-symlink-") as raw:
            work = pathlib.Path(raw)
            preinstall = work / "preinstall"
            preinstall.write_text(_extract_heredoc(producer, "PREINSTALL") + "\n", encoding="ascii")
            preinstall.chmod(0o755)
            volume = work / "vol"
            library = volume / "Library"
            library.mkdir(parents=True)
            (library / "Application Support").mkdir()
            (library / "Google").mkdir()
            evil = work / "evil-microsoft"
            evil.mkdir()
            (library / "Microsoft").symlink_to(evil)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(volume)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(prepared.returncode, 0, prepared.stderr)
            self.assertIn("symlink", prepared.stderr)
            self.assertFalse((evil / "Edge").exists())
            self.assertFalse((volume / "Library" / "Microsoft" / "Edge" / "NativeMessagingHosts").is_dir())


    def _extract_companion_scripts(self, work: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        producer = PRODUCER.read_text(encoding="ascii")
        preinstall = work / "preinstall"
        postinstall = work / "postinstall"
        uninstall = work / "uninstall.sh"
        preinstall.write_text(_extract_heredoc(producer, "PREINSTALL") + "\n", encoding="ascii")
        postinstall.write_text(_extract_heredoc(producer, "POSTINSTALL") + "\n", encoding="ascii")
        uninstall.write_text(_extract_heredoc(producer, "UNINSTALL") + "\n", encoding="ascii")
        for path in (preinstall, postinstall, uninstall):
            path.chmod(0o755)
        return preinstall, postinstall, uninstall

    def _prepared_companion_volume(self, work: pathlib.Path) -> dict[str, pathlib.Path]:
        volume = work / "vol"
        library = volume / "Library"
        library.mkdir(parents=True)
        host_dir = (
            volume
            / "Library"
            / "Application Support"
            / "Win's VPN"
            / "NativeMessagingHost"
        )
        firefox_dir = (
            volume
            / "Library"
            / "Application Support"
            / "Mozilla"
            / "NativeMessagingHosts"
        )
        chrome_dir = volume / "Library" / "Google" / "Chrome" / "NativeMessagingHosts"
        edge_dir = volume / "Library" / "Microsoft" / "Edge" / "NativeMessagingHosts"
        host_dir.mkdir(parents=True)
        firefox_dir.mkdir(parents=True)
        chrome_dir.mkdir(parents=True)
        edge_dir.mkdir(parents=True)
        live_host = host_dir / "wins_bridge_host"
        live_firefox = firefox_dir / "org.winsvpn.bridge.json"
        live_chrome = chrome_dir / "org.winsvpn.bridge.json"
        live_edge = edge_dir / "org.winsvpn.bridge.json"
        live_host.write_text("old-host\n", encoding="ascii")
        live_host.chmod(0o755)
        live_firefox.write_text("old-firefox\n", encoding="ascii")
        live_chrome.write_text("old-chrome\n", encoding="ascii")
        live_edge.write_text("old-edge\n", encoding="ascii")
        return {
            "volume": volume,
            "host_dir": host_dir,
            "live_host": live_host,
            "live_firefox": live_firefox,
            "live_chrome": live_chrome,
            "live_edge": live_edge,
            "incoming": host_dir / "Incoming",
            "rollback": host_dir / ".winsvpn-native-host-rollback",
        }

    def _write_incoming(
        self,
        incoming: pathlib.Path,
        uninstall: pathlib.Path,
        *,
        firefox: dict[str, object] | None = None,
        chrome: dict[str, object] | None = None,
        edge: dict[str, object] | None = None,
        bind_hashes: bool = True,
    ) -> None:
        incoming.mkdir(parents=True, exist_ok=True)
        (incoming / "wins_bridge_host").write_bytes(_universal_mh_execute())
        (incoming / "wins_bridge_host").chmod(0o755)
        _write_json(incoming / "firefox.json", firefox or _firefox_manifest())
        _write_json(incoming / "chrome.json", chrome or _chrome_manifest())
        _write_json(incoming / "edge.json", edge or _edge_manifest())
        shutil.copy2(uninstall, incoming / "uninstall.sh")
        (incoming / "uninstall.sh").chmod(0o755)
        if bind_hashes:
            _bind_incoming_receipt(incoming)
        else:
            _write_json(incoming / "receipt.json", _receipt_document())

    def _assert_live_untouched(self, paths: dict[str, pathlib.Path]) -> None:
        self.assertEqual(paths["live_host"].read_text(encoding="ascii"), "old-host\n")
        self.assertEqual(paths["live_firefox"].read_text(encoding="ascii"), "old-firefox\n")
        self.assertEqual(paths["live_chrome"].read_text(encoding="ascii"), "old-chrome\n")
        self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")

    def test_postinstall_issues_keeps_and_refuses_the_bridge_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-identity-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            volume = paths["volume"]
            identity = volume.joinpath(
                *pathlib.PurePosixPath(companion.IDENTITY_RECEIPT_PATH).parts[1:]
            )

            def run(script: pathlib.Path, *args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["/bin/sh", str(script), *args],
                    capture_output=True,
                    text=True,
                    check=False,
                )

            pkg_args = (str(work / "pkg.pkg"), "/", str(volume))
            self.assertEqual(run(preinstall, *pkg_args).returncode, 0)
            self._write_incoming(paths["incoming"], uninstall)
            installed = run(postinstall, *pkg_args)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertTrue(identity.is_file())
            info = identity.lstat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o444)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(stat.S_IMODE(identity.parent.lstat().st_mode), 0o755)
            first = identity.read_bytes()
            document = json.loads(first)
            self.assertEqual(set(document), {"v", "secret"})
            self.assertEqual(document["v"], 1)
            self.assertRegex(document["secret"], r"^[0-9a-f]{64}$")
            self.assertNotIn(document["secret"], installed.stdout + installed.stderr)
            self.assertEqual(
                [p.name for p in identity.parent.iterdir()], ["browser_bridge.identity"]
            )

            # A second install keeps the valid receipt byte for byte.
            self.assertEqual(run(preinstall, *pkg_args).returncode, 0)
            self._write_incoming(paths["incoming"], uninstall)
            again = run(postinstall, *pkg_args)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertEqual(identity.read_bytes(), first)

            # A malformed receipt is left untouched and nothing is mutated.
            identity.chmod(0o644)
            identity.write_text('{"v":1,"secret":"short"}\n', encoding="ascii")
            identity.chmod(0o444)
            live_before = paths["live_host"].read_bytes()
            self.assertEqual(run(preinstall, *pkg_args).returncode, 0)
            self._write_incoming(paths["incoming"], uninstall)
            refused = run(postinstall, *pkg_args)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("fail before mutation", refused.stderr)
            self.assertEqual(paths["live_host"].read_bytes(), live_before)
            self.assertEqual(identity.read_text(encoding="ascii"), '{"v":1,"secret":"short"}\n')

            # A group-writable or symlinked receipt is refused the same way.
            identity.chmod(0o664)
            refused_mode = run(postinstall, *pkg_args)
            self.assertNotEqual(refused_mode.returncode, 0)
            self.assertIn("browser bridge identity", refused_mode.stderr)
            identity.chmod(0o644)
            identity.unlink()
            identity.symlink_to(work / "elsewhere")
            refused_link = run(postinstall, *pkg_args)
            self.assertNotEqual(refused_link.returncode, 0)
            self.assertIn("browser bridge identity", refused_link.stderr)
            self.assertFalse((work / "elsewhere").exists())
            identity.unlink()
            identity.write_text(first.decode("ascii"), encoding="ascii")
            identity.chmod(0o444)

            removed = run(uninstall, str(volume))
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(identity.exists())
            self.assertFalse(identity.parent.exists())

    def test_extra_origin_is_refused_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-extra-origin-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            extra = _chrome_manifest()
            extra["allowed_origins"] = [
                f"chrome-extension://{FIXTURE_CHROME_ID}/",
                f"chrome-extension://{OTHER_CHROME_ID}/",
            ]
            self._write_incoming(paths["incoming"], uninstall, chrome=extra)
            refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("not exact", refused.stderr)
            self._assert_live_untouched(paths)

    def test_description_smuggling_is_refused_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-smuggle-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            smuggled = _chrome_manifest()
            smuggled["description"] = f"chrome-extension://{FIXTURE_CHROME_ID}/"
            smuggled["allowed_origins"] = [f"chrome-extension://{OTHER_CHROME_ID}/"]
            self._write_incoming(paths["incoming"], uninstall, chrome=smuggled)
            refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("not exact", refused.stderr)
            self._assert_live_untouched(paths)

    def test_firefox_suffix_id_is_refused_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-fx-suffix-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            suffix = _firefox_manifest()
            suffix["allowed_extensions"] = ["companion@winsvpn.org.evil"]
            self._write_incoming(paths["incoming"], uninstall, firefox=suffix)
            refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("Firefox extension id is not exact", refused.stderr)
            self._assert_live_untouched(paths)

    def test_rollback_failure_is_surfaced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-rollback-fail-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            rollback_host = paths["rollback"] / "host.bin"
            self.assertTrue(rollback_host.is_file())
            alias = paths["rollback"] / "host.bin.alias"
            os.link(rollback_host, alias)
            subprocess.run(
                ["/usr/bin/chflags", "uchg", str(paths["live_chrome"])],
                check=True,
                capture_output=True,
                text=True,
            )
            try:
                failed = subprocess.run(
                    ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            finally:
                subprocess.run(
                    ["/usr/bin/chflags", "nouchg", str(paths["live_chrome"])],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if alias.exists() or alias.is_symlink():
                    alias.unlink()
            self.assertNotEqual(failed.returncode, 0, failed.stderr)
            self.assertIn("rollback could not restore", failed.stderr)
            self.assertNotEqual(paths["live_host"].read_bytes(), b"old-host\n")
            self.assertEqual(paths["live_firefox"].read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(paths["live_chrome"].read_text(encoding="ascii"), "old-chrome\n")
            self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")

    def test_omitted_or_object_inner_files_cannot_mutate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-inner-files-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)

            self._write_incoming(paths["incoming"], uninstall, bind_hashes=False)
            omitted = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(omitted.returncode, 0, omitted.stderr)
            self.assertIn("receipt inner_files is not exact", omitted.stderr)
            self._assert_live_untouched(paths)

            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            receipt_path = paths["incoming"] / "receipt.json"
            document = json.loads(receipt_path.read_text(encoding="ascii"))
            inner = document["inner_files"]
            self.assertIsInstance(inner, list)
            self.assertGreaterEqual(len(inner), 1)
            document["inner_files"] = inner[0]
            _write_json(receipt_path, document)
            as_object = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(as_object.returncode, 0, as_object.stderr)
            self.assertIn("receipt inner_files is not exact", as_object.stderr)
            self._assert_live_untouched(paths)

    def test_object_shaped_origin_and_extension_lists_cannot_mutate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-object-list-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)

            chrome_object = _chrome_manifest()
            chrome_origins = chrome_object["allowed_origins"]
            self.assertEqual(chrome_origins, [f"chrome-extension://{FIXTURE_CHROME_ID}/"])
            chrome_object["allowed_origins"] = _object_shaped_list(
                f"chrome-extension://{FIXTURE_CHROME_ID}/"
            )
            self._write_incoming(paths["incoming"], uninstall, chrome=chrome_object)
            chrome_refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(chrome_refused.returncode, 0, chrome_refused.stderr)
            self.assertIn("Chrome native-host manifest is not exact", chrome_refused.stderr)
            self._assert_live_untouched(paths)

            edge_object = _edge_manifest()
            edge_origins = edge_object["allowed_origins"]
            self.assertEqual(edge_origins, [f"chrome-extension://{FIXTURE_EDGE_ID}/"])
            edge_object["allowed_origins"] = _object_shaped_list(
                f"chrome-extension://{FIXTURE_EDGE_ID}/"
            )
            self._write_incoming(paths["incoming"], uninstall, edge=edge_object)
            edge_refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(edge_refused.returncode, 0, edge_refused.stderr)
            self.assertIn("Edge native-host manifest is not exact", edge_refused.stderr)
            self._assert_live_untouched(paths)

            firefox_object = _firefox_manifest()
            firefox_ids = firefox_object["allowed_extensions"]
            self.assertEqual(firefox_ids, [companion.FIREFOX_EXTENSION_ID])
            firefox_object["allowed_extensions"] = _object_shaped_list(
                companion.FIREFOX_EXTENSION_ID
            )
            self._write_incoming(paths["incoming"], uninstall, firefox=firefox_object)
            firefox_refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(firefox_refused.returncode, 0, firefox_refused.stderr)
            self.assertIn("Firefox native-host manifest is not exact", firefox_refused.stderr)
            self._assert_live_untouched(paths)

    def test_duplicate_allowed_inner_files_cannot_mutate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-dup-inner-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            receipt_path = paths["incoming"] / "receipt.json"
            document = json.loads(receipt_path.read_text(encoding="ascii"))
            inner = document["inner_files"]
            self.assertIsInstance(inner, list)
            self.assertEqual(len(inner), 5)
            duplicate = dict(inner[0])
            self.assertEqual(duplicate["sha256"], inner[0]["sha256"])
            self.assertEqual(duplicate["bytes"], inner[0]["bytes"])
            document["inner_files"] = inner + [duplicate]
            _write_json(receipt_path, document)
            extra = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(extra.returncode, 0, extra.stderr)
            self.assertIn("receipt inner_files is not exact", extra.stderr)
            self._assert_live_untouched(paths)

            document["inner_files"] = [inner[0], dict(inner[0]), inner[1], inner[2], inner[3]]
            self.assertEqual(len(document["inner_files"]), 5)
            self.assertEqual(document["inner_files"][0]["sha256"], document["inner_files"][1]["sha256"])
            self.assertEqual(document["inner_files"][0]["bytes"], document["inner_files"][1]["bytes"])
            _write_json(receipt_path, document)
            refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("receipt inner_files is not exact", refused.stderr)
            self._assert_live_untouched(paths)

    def test_extra_empty_object_key_is_refused_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-empty-object-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            extra = _chrome_manifest()
            extra["x"] = {}
            self._write_incoming(paths["incoming"], uninstall, chrome=extra)
            refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("not exact", refused.stderr)
            self._assert_live_untouched(paths)

    def test_duplicate_json_key_is_still_refused_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-dup-key-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall)
            chrome = paths["incoming"] / "chrome.json"
            body = chrome.read_text(encoding="ascii")
            injected = body.replace(
                '"name": "org.winsvpn.bridge"',
                '"name": "org.winsvpn.bridge",\n  "name": "org.winsvpn.bridge"',
                1,
            )
            self.assertNotEqual(injected, body)
            chrome.write_text(injected, encoding="ascii")
            _bind_incoming_receipt(paths["incoming"])
            refused = subprocess.run(
                ["/bin/sh", str(postinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("duplicate JSON key", refused.stderr)
            self._assert_live_untouched(paths)

    def _held_replace_functions(self, postinstall: str) -> str:
        start = postinstall.index("bind_dest_parent()")
        end = postinstall.index("verify_incoming()")
        return postinstall[start:end]

    def _write_keep_victim(self, work: pathlib.Path) -> pathlib.Path:
        victim = work / "victim"
        victim.mkdir()
        (victim / "keep.txt").write_text("KEEP-VICTIM\n", encoding="ascii")
        return victim

    def _assert_victim_untouched(self, victim: pathlib.Path) -> None:
        names = sorted(path.name for path in victim.iterdir())
        self.assertEqual(names, ["keep.txt"], names)
        self.assertEqual((victim / "keep.txt").read_text(encoding="ascii"), "KEEP-VICTIM\n")
        self.assertFalse((victim / "org.winsvpn.bridge.json.new").exists())
        self.assertFalse((victim / "chrome.json").exists())
        self.assertFalse((victim / "firefox.json").exists())
        self.assertFalse((victim / "edge.json").exists())
        self.assertFalse((victim / "wins_bridge_host").exists())
        self.assertFalse((victim / "receipt.json").exists())
        self.assertFalse((victim / "uninstall.sh").exists())

    def _swap_leaf_to_victim_dir(self, leaf: pathlib.Path, victim: pathlib.Path) -> None:
        if leaf.is_symlink() or leaf.exists():
            leaf.unlink()
        leaf.symlink_to(victim)

    def _run_postinstall(
        self,
        postinstall: pathlib.Path,
        pkg: pathlib.Path,
        volume: pathlib.Path,
        *,
        timeout: int = 8,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", str(postinstall), str(pkg), "/", str(volume)],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    def test_chrome_leaf_symlink_to_dir_after_preinstall_does_not_write_victim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-chrome-swap-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            victim = self._write_keep_victim(work)
            self._swap_leaf_to_victim_dir(paths["live_chrome"], victim)
            refused = self._run_postinstall(postinstall, work / "pkg.pkg", paths["volume"])
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("symlink", refused.stderr)
            self._assert_victim_untouched(victim)
            self.assertTrue(paths["live_chrome"].is_symlink())
            self.assertEqual(paths["live_host"].read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(paths["live_firefox"].read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")
            self.assertFalse(any(paths["host_dir"].glob(".winsvpn-stage.*")))
            self.assertFalse(any(paths["live_chrome"].parent.glob(".winsvpn-stage.*")))

    def test_host_firefox_chrome_edge_leaf_symlink_to_dir_does_not_write_victim(self) -> None:
        cases = (
            ("live_host", "old-host\n"),
            ("live_firefox", "old-firefox\n"),
            ("live_chrome", "old-chrome\n"),
            ("live_edge", "old-edge\n"),
        )
        for leaf_key, _old in cases:
            with self.subTest(leaf=leaf_key):
                with tempfile.TemporaryDirectory(
                    prefix=f"winsvpn-macos-companion-{leaf_key}-swap-"
                ) as raw:
                    work = pathlib.Path(raw)
                    preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
                    paths = self._prepared_companion_volume(work)
                    prepared = subprocess.run(
                        [
                            "/bin/sh",
                            str(preinstall),
                            str(work / "pkg.pkg"),
                            "/",
                            str(paths["volume"]),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(prepared.returncode, 0, prepared.stderr)
                    self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
                    victim = self._write_keep_victim(work)
                    self._swap_leaf_to_victim_dir(paths[leaf_key], victim)
                    refused = self._run_postinstall(
                        postinstall, work / "pkg.pkg", paths["volume"]
                    )
                    self.assertNotEqual(refused.returncode, 0, refused.stderr)
                    self.assertIn("symlink", refused.stderr)
                    self._assert_victim_untouched(victim)
                    self.assertTrue(paths[leaf_key].is_symlink())
                    for other_key, other_old in cases:
                        if other_key == leaf_key:
                            continue
                        self.assertEqual(
                            paths[other_key].read_text(encoding="ascii"),
                            other_old,
                        )

    def test_leaf_fifo_socket_hardlink_and_path_swap_do_not_hang_or_write_victim(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="w") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            pkg = work / "pkg.pkg"
            leaves = ("live_host", "live_firefox", "live_chrome", "live_edge")

            def prepare() -> dict[str, pathlib.Path]:
                if work.joinpath("vol").exists():
                    shutil.rmtree(work / "vol")
                paths = self._prepared_companion_volume(work)
                prepared = subprocess.run(
                    ["/bin/sh", str(preinstall), str(pkg), "/", str(paths["volume"])],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(prepared.returncode, 0, prepared.stderr)
                self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
                return paths

            victim = self._write_keep_victim(work)

            for leaf_key in leaves:
                with self.subTest(kind="fifo", leaf=leaf_key):
                    paths = prepare()
                    leaf = paths[leaf_key]
                    leaf.unlink()
                    os.mkfifo(leaf)
                    refused = self._run_postinstall(postinstall, pkg, paths["volume"])
                    self.assertNotEqual(refused.returncode, 0, refused.stderr)
                    self.assertIn("special", refused.stderr)
                    self.assertTrue(stat.S_ISFIFO(leaf.lstat().st_mode))
                    self._assert_victim_untouched(victim)

                with self.subTest(kind="socket", leaf=leaf_key):
                    paths = prepare()
                    leaf = paths[leaf_key]
                    leaf.unlink()
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        sock.bind(str(leaf))
                    finally:
                        sock.close()
                    refused = self._run_postinstall(postinstall, pkg, paths["volume"])
                    self.assertNotEqual(refused.returncode, 0, refused.stderr)
                    self.assertIn("special", refused.stderr)
                    self.assertTrue(stat.S_ISSOCK(leaf.lstat().st_mode))
                    self._assert_victim_untouched(victim)

                with self.subTest(kind="hardlink", leaf=leaf_key):
                    paths = prepare()
                    leaf = paths[leaf_key]
                    alias = leaf.parent / (leaf.name + ".alias")
                    if alias.exists() or alias.is_symlink():
                        alias.unlink()
                    os.link(leaf, alias)
                    refused = self._run_postinstall(postinstall, pkg, paths["volume"])
                    self.assertNotEqual(refused.returncode, 0, refused.stderr)
                    self.assertIn("hardlinked", refused.stderr)
                    self.assertEqual(leaf.stat().st_nlink, 2)
                    self.assertEqual(alias.read_bytes(), leaf.read_bytes())
                    self._assert_victim_untouched(victim)
                    alias.unlink()

                with self.subTest(kind="path-swap", leaf=leaf_key):
                    paths = prepare()
                    leaf = paths[leaf_key]
                    self._swap_leaf_to_victim_dir(leaf, victim)
                    refused = self._run_postinstall(postinstall, pkg, paths["volume"])
                    self.assertNotEqual(refused.returncode, 0, refused.stderr)
                    self.assertIn("symlink", refused.stderr)
                    self.assertTrue(leaf.is_symlink())
                    self._assert_victim_untouched(victim)

    def test_intermediate_chrome_parent_swap_does_not_write_victim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-parent-swap-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            victim = self._write_keep_victim(work)
            lookalike = victim / "Chrome" / "NativeMessagingHosts"
            lookalike.mkdir(parents=True)
            (lookalike / "keep-nested.txt").write_text("KEEP-NESTED\n", encoding="ascii")
            chrome_root = paths["volume"] / "Library" / "Google" / "Chrome"
            displaced = work / "displaced-chrome"
            chrome_root.rename(displaced)
            chrome_root.symlink_to(victim / "Chrome")
            refused = self._run_postinstall(postinstall, work / "pkg.pkg", paths["volume"])
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("symlink", refused.stderr)
            self.assertEqual((victim / "keep.txt").read_text(encoding="ascii"), "KEEP-VICTIM\n")
            self.assertEqual(
                (lookalike / "keep-nested.txt").read_text(encoding="ascii"), "KEEP-NESTED\n"
            )
            nested_names = sorted(path.name for path in lookalike.iterdir())
            self.assertEqual(nested_names, ["keep-nested.txt"], nested_names)
            self.assertFalse((lookalike / "org.winsvpn.bridge.json").exists())
            self.assertFalse((lookalike / "org.winsvpn.bridge.json.new").exists())
            self.assertFalse((lookalike / "chrome.json").exists())
            self.assertFalse((victim / "org.winsvpn.bridge.json.new").exists())
            self.assertFalse((victim / "chrome.json").exists())
            self.assertEqual(paths["live_host"].read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(paths["live_firefox"].read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")

    def test_restore_refuses_symlink_and_still_restores_later_leaves(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-restore-swap-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            incoming = paths["incoming"]
            shutil.copy2(incoming / "wins_bridge_host", paths["live_host"])
            shutil.copy2(incoming / "firefox.json", paths["live_firefox"])
            shutil.copy2(incoming / "chrome.json", paths["live_chrome"])
            shutil.copy2(incoming / "edge.json", paths["live_edge"])
            rollback = paths["rollback"]
            for name in ("host.bin", "firefox.json", "chrome.json", "edge.json"):
                (rollback / f"{name}.mutated").write_text("mutated\n", encoding="ascii")
            victim = self._write_keep_victim(work)
            self._swap_leaf_to_victim_dir(paths["live_chrome"], victim)
            producer = PRODUCER.read_text(encoding="ascii")
            post_text = _extract_heredoc(producer, "POSTINSTALL")
            driver = work / "restore-only.sh"
            driver.write_text(
                "\n".join(
                    [
                        "#!/bin/sh",
                        "set -eu",
                        f'PREFIX="{paths["volume"]}"',
                        f'HOST_PATH="{paths["live_host"]}"',
                        f'FIREFOX_PATH="{paths["live_firefox"]}"',
                        f'CHROME_PATH="{paths["live_chrome"]}"',
                        f'EDGE_PATH="{paths["live_edge"]}"',
                        f'RECEIPT_PATH="{paths["host_dir"] / "macos-native-host-companion-receipt.json"}"',
                        f'UNINSTALL_PATH="{paths["host_dir"] / "uninstall-winsvpn-native-host.sh"}"',
                        f'ROLLBACK="{rollback}"',
                        self._held_replace_functions(post_text),
                        "restore_rollback",
                        "",
                    ]
                ),
                encoding="ascii",
            )
            driver.chmod(0o755)
            restored = subprocess.run(
                ["/bin/sh", str(driver)],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            self.assertNotEqual(restored.returncode, 0, restored.stderr)
            self.assertIn("rollback could not restore", restored.stderr)
            self.assertIn("symlink", restored.stderr)
            self.assertEqual(paths["live_host"].read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(paths["live_firefox"].read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")
            self.assertTrue(paths["live_chrome"].is_symlink())
            self._assert_victim_untouched(victim)

    def test_restore_refuses_fifo_socket_hardlink_without_victim_write(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="w") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            incoming = paths["incoming"]
            rollback = paths["rollback"]
            producer = PRODUCER.read_text(encoding="ascii")
            post_text = _extract_heredoc(producer, "POSTINSTALL")
            functions = self._held_replace_functions(post_text)
            victim = self._write_keep_victim(work)
            driver = work / "restore-hostile.sh"
            driver.write_text(
                "\n".join(
                    [
                        "#!/bin/sh",
                        "set -eu",
                        f'PREFIX="{paths["volume"]}"',
                        f'HOST_PATH="{paths["live_host"]}"',
                        f'FIREFOX_PATH="{paths["live_firefox"]}"',
                        f'CHROME_PATH="{paths["live_chrome"]}"',
                        f'EDGE_PATH="{paths["live_edge"]}"',
                        f'RECEIPT_PATH="{paths["host_dir"] / "macos-native-host-companion-receipt.json"}"',
                        f'UNINSTALL_PATH="{paths["host_dir"] / "uninstall-winsvpn-native-host.sh"}"',
                        f'ROLLBACK="{rollback}"',
                        functions,
                        "restore_rollback",
                        "",
                    ]
                ),
                encoding="ascii",
            )
            driver.chmod(0o755)

            def reset_mutated_regular_leaves() -> None:
                shutil.copy2(incoming / "wins_bridge_host", paths["live_host"])
                shutil.copy2(incoming / "firefox.json", paths["live_firefox"])
                shutil.copy2(incoming / "edge.json", paths["live_edge"])
                (rollback / "host.bin").write_bytes(b"old-host\n")
                (rollback / "firefox.json").write_bytes(b"old-firefox\n")
                (rollback / "chrome.json").write_bytes(b"old-chrome\n")
                (rollback / "edge.json").write_bytes(b"old-edge\n")
                for name in ("host.bin", "firefox.json", "chrome.json", "edge.json"):
                    (rollback / f"{name}.mutated").write_text("mutated\n", encoding="ascii")

            def clear_chrome_leaf() -> None:
                if paths["live_chrome"].is_symlink() or paths["live_chrome"].exists():
                    paths["live_chrome"].unlink()

            reset_mutated_regular_leaves()
            clear_chrome_leaf()
            os.mkfifo(paths["live_chrome"])
            fifo_run = subprocess.run(
                ["/bin/sh", str(driver)],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            self.assertNotEqual(fifo_run.returncode, 0, fifo_run.stderr)
            self.assertIn("special", fifo_run.stderr)
            self.assertIn("rollback could not restore", fifo_run.stderr)
            self.assertEqual(paths["live_host"].read_text(encoding="ascii"), "old-host\n")
            self.assertEqual(paths["live_firefox"].read_text(encoding="ascii"), "old-firefox\n")
            self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")
            self.assertTrue(stat.S_ISFIFO(paths["live_chrome"].lstat().st_mode))
            self._assert_victim_untouched(victim)

            reset_mutated_regular_leaves()
            clear_chrome_leaf()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(str(paths["live_chrome"]))
            finally:
                sock.close()
            sock_run = subprocess.run(
                ["/bin/sh", str(driver)],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            self.assertNotEqual(sock_run.returncode, 0, sock_run.stderr)
            self.assertIn("special", sock_run.stderr)
            self.assertTrue(stat.S_ISSOCK(paths["live_chrome"].lstat().st_mode))
            self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")
            self._assert_victim_untouched(victim)

            reset_mutated_regular_leaves()
            clear_chrome_leaf()
            shutil.copy2(incoming / "chrome.json", paths["live_chrome"])
            alias = paths["live_chrome"].parent / "chrome.alias"
            if alias.exists() or alias.is_symlink():
                alias.unlink()
            os.link(paths["live_chrome"], alias)
            hard_run = subprocess.run(
                ["/bin/sh", str(driver)],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            self.assertNotEqual(hard_run.returncode, 0, hard_run.stderr)
            self.assertIn("hardlinked", hard_run.stderr)
            self.assertEqual(alias.read_bytes(), paths["live_chrome"].read_bytes())
            self.assertEqual(paths["live_edge"].read_text(encoding="ascii"), "old-edge\n")
            self._assert_victim_untouched(victim)
            alias.unlink()

    def _install_companion(
        self,
        preinstall: pathlib.Path,
        postinstall: pathlib.Path,
        uninstall: pathlib.Path,
        paths: dict[str, pathlib.Path],
        pkg: pathlib.Path,
        *,
        host_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[str]:
        prepared = subprocess.run(
            ["/bin/sh", str(preinstall), str(pkg), "/", str(paths["volume"])],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
        if host_bytes is not None:
            (paths["incoming"] / "wins_bridge_host").write_bytes(host_bytes)
            (paths["incoming"] / "wins_bridge_host").chmod(0o755)
            _bind_incoming_receipt(paths["incoming"])
        return self._run_postinstall(postinstall, pkg, paths["volume"], timeout=30)

    def test_stage_tempfile_unlink_symlink_race_does_not_write_victim(self) -> None:
        payload = _universal_mh_execute() + (b"H" * 1500000)
        hits = 0
        for trial in range(8):
            with tempfile.TemporaryDirectory(
                prefix=f"winsvpn-macos-companion-stage-race-{trial}-"
            ) as raw:
                work = pathlib.Path(raw)
                preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
                paths = self._prepared_companion_volume(work)
                victim = self._write_keep_victim(work)
                keep = victim / "keep.txt"
                stop = threading.Event()

                def race() -> None:
                    host_dir = paths["host_dir"]
                    while not stop.is_set():
                        for staged in host_dir.glob(".winsvpn-stage.*"):
                            try:
                                if staged.exists() or staged.is_symlink():
                                    staged.unlink()
                                staged.symlink_to(keep)
                            except OSError:
                                pass

                worker = threading.Thread(target=race, daemon=True)
                worker.start()
                try:
                    completed = self._install_companion(
                        preinstall,
                        postinstall,
                        uninstall,
                        paths,
                        work / "pkg.pkg",
                        host_bytes=payload,
                    )
                finally:
                    stop.set()
                    worker.join(timeout=2)
                if keep.read_bytes() != b"KEEP-VICTIM\n":
                    hits += 1
                self.assertEqual(keep.read_bytes(), b"KEEP-VICTIM\n")
                self.assertFalse((victim / "wins_bridge_host").exists())
                names = sorted(path.name for path in victim.iterdir())
                self.assertEqual(names, ["keep.txt"], names)
                if completed.returncode == 0:
                    self.assertEqual(paths["live_host"].read_bytes(), payload)
        self.assertEqual(hits, 0)

    def test_failure_cleanup_does_not_glob_delete_through_swapped_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-trap-glob-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            victim = self._write_keep_victim(work)
            lookalike = victim / "Chrome" / "NativeMessagingHosts"
            lookalike.mkdir(parents=True)
            planted = lookalike / ".winsvpn-stage.PLANTED"
            planted.write_text("PLANTED\n", encoding="ascii")
            (lookalike / "keep-nested.txt").write_text("KEEP-NESTED\n", encoding="ascii")
            chrome_root = paths["volume"] / "Library" / "Google" / "Chrome"
            displaced = work / "displaced-chrome"
            chrome_root.rename(displaced)
            chrome_root.symlink_to(victim / "Chrome")
            refused = self._run_postinstall(postinstall, work / "pkg.pkg", paths["volume"])
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self.assertIn("symlink", refused.stderr)
            self.assertTrue(planted.is_file())
            self.assertEqual(planted.read_text(encoding="ascii"), "PLANTED\n")
            self.assertEqual(
                (lookalike / "keep-nested.txt").read_text(encoding="ascii"), "KEEP-NESTED\n"
            )
            self.assertEqual((victim / "keep.txt").read_text(encoding="ascii"), "KEEP-VICTIM\n")

    def test_json_scratch_is_not_left_in_host_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-json-scratch-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            installed = self._install_companion(
                preinstall, postinstall, uninstall, paths, work / "pkg.pkg"
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            leftovers = list(paths["host_dir"].glob(".winsvpn-json*"))
            self.assertEqual(leftovers, [])
            self.assertFalse(any(paths["host_dir"].glob(".winsvpn-stage.*")))
            removed = subprocess.run(
                ["/bin/sh", str(uninstall), str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(paths["live_host"].exists())
            self.assertFalse(paths["host_dir"].exists())

    def test_uninstall_does_not_follow_swapped_chrome_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-uninst-parent-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            installed = self._install_companion(
                preinstall, postinstall, uninstall, paths, work / "pkg.pkg"
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            victim = self._write_keep_victim(work)
            lookalike = victim / "Chrome" / "NativeMessagingHosts"
            lookalike.mkdir(parents=True)
            decoy = lookalike / "org.winsvpn.bridge.json"
            decoy.write_text("DECOY-LIVE\n", encoding="ascii")
            chrome_root = paths["volume"] / "Library" / "Google" / "Chrome"
            displaced = work / "displaced-chrome"
            chrome_root.rename(displaced)
            chrome_root.symlink_to(victim / "Chrome")
            removed = subprocess.run(
                ["/bin/sh", str(uninstall), str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(removed.returncode, 0, removed.stderr)
            self.assertIn("symlink", removed.stderr)
            self.assertTrue(decoy.is_file())
            self.assertEqual(decoy.read_text(encoding="ascii"), "DECOY-LIVE\n")
            self.assertEqual((victim / "keep.txt").read_text(encoding="ascii"), "KEEP-VICTIM\n")
            self.assertFalse(paths["live_host"].exists())
            self.assertFalse(paths["live_firefox"].exists())
            self.assertFalse(paths["live_edge"].exists())
            displaced_json = displaced / "NativeMessagingHosts" / "org.winsvpn.bridge.json"
            self.assertTrue(displaced_json.is_file())

    def test_uninstall_continues_after_chrome_leaf_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-uninst-leaf-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            installed = self._install_companion(
                preinstall, postinstall, uninstall, paths, work / "pkg.pkg"
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            victim = self._write_keep_victim(work)
            self._swap_leaf_to_victim_dir(paths["live_chrome"], victim)
            removed = subprocess.run(
                ["/bin/sh", str(uninstall), str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(removed.returncode, 0, removed.stderr)
            self.assertIn("symlink", removed.stderr)
            self.assertFalse(paths["live_host"].exists())
            self.assertFalse(paths["live_firefox"].exists())
            self.assertFalse(paths["live_edge"].exists())
            self.assertTrue(paths["live_chrome"].is_symlink())
            self._assert_victim_untouched(victim)

    def test_restore_fails_closed_when_rollback_dir_is_swapped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-rollback-swap-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            incoming = paths["incoming"]
            shutil.copy2(incoming / "wins_bridge_host", paths["live_host"])
            shutil.copy2(incoming / "firefox.json", paths["live_firefox"])
            shutil.copy2(incoming / "chrome.json", paths["live_chrome"])
            shutil.copy2(incoming / "edge.json", paths["live_edge"])
            rollback = paths["rollback"]
            for name in ("host.bin", "firefox.json", "chrome.json", "edge.json"):
                (rollback / f"{name}.mutated").write_text("mutated\n", encoding="ascii")
            victim = self._write_keep_victim(work)
            lookalike = victim / "NativeMessagingHost"
            lookalike.mkdir()
            (lookalike / "keep-nested.txt").write_text("KEEP-NESTED\n", encoding="ascii")
            host_parent = paths["host_dir"].parent
            displaced = work / "displaced-native-host"
            paths["host_dir"].rename(displaced)
            swapped_host_dir = host_parent / "NativeMessagingHost"
            swapped_host_dir.symlink_to(lookalike)
            producer = PRODUCER.read_text(encoding="ascii")
            post_text = _extract_heredoc(producer, "POSTINSTALL")
            driver = work / "restore-rollback-swap.sh"
            driver.write_text(
                "\n".join(
                    [
                        "#!/bin/sh",
                        "set -eu",
                        f'PREFIX="{paths["volume"]}"',
                        f'HOST_PATH="{swapped_host_dir / "wins_bridge_host"}"',
                        f'FIREFOX_PATH="{paths["live_firefox"]}"',
                        f'CHROME_PATH="{paths["live_chrome"]}"',
                        f'EDGE_PATH="{paths["live_edge"]}"',
                        f'RECEIPT_PATH="{swapped_host_dir / "macos-native-host-companion-receipt.json"}"',
                        f'UNINSTALL_PATH="{swapped_host_dir / "uninstall-winsvpn-native-host.sh"}"',
                        f'ROLLBACK="{swapped_host_dir / ".winsvpn-native-host-rollback"}"',
                        self._held_replace_functions(post_text),
                        "restore_rollback",
                        "",
                    ]
                ),
                encoding="ascii",
            )
            driver.chmod(0o755)
            restored = subprocess.run(
                ["/bin/sh", str(driver)],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            self.assertNotEqual(restored.returncode, 0, restored.stderr)
            self.assertIn("rollback could not restore", restored.stderr)
            self.assertIn("symlink", restored.stderr)
            self.assertEqual(
                json.loads(paths["live_firefox"].read_text(encoding="ascii"))["path"],
                companion.INSTALLED_HOST_PATH,
            )
            self.assertEqual(
                json.loads(paths["live_chrome"].read_text(encoding="ascii"))["allowed_origins"],
                [f"chrome-extension://{FIXTURE_CHROME_ID}/"],
            )
            self.assertEqual(
                json.loads(paths["live_edge"].read_text(encoding="ascii"))["allowed_origins"],
                [f"chrome-extension://{FIXTURE_EDGE_ID}/"],
            )
            self.assertEqual((lookalike / "keep-nested.txt").read_text(encoding="ascii"), "KEEP-NESTED\n")
            self.assertEqual((victim / "keep.txt").read_text(encoding="ascii"), "KEEP-VICTIM\n")

    def test_crash_after_live_replace_rolls_back_from_journaled_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-journal-crash-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            body = postinstall.read_text(encoding="ascii")
            needle = 'held_stage_replace "${leaf}" "${mode}" < "${source}" || exit 1'
            self.assertEqual(body.count(needle), 1)
            crashed = body.replace(needle, needle + "\n    exit 99", 1)
            self.assertNotEqual(crashed, body)
            postinstall.write_text(crashed, encoding="ascii")
            refused = self._run_postinstall(
                postinstall, work / "pkg.pkg", paths["volume"], timeout=30
            )
            self.assertNotEqual(refused.returncode, 0, refused.stderr)
            self._assert_live_untouched(paths)

    def test_orphan_stage_file_in_rollback_does_not_wedge_uninstall(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-orphan-stage-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            orphan = paths["rollback"] / ".winsvpn-stage.ORPHAN"
            orphan.write_text("ORPHAN-STAGE\n", encoding="ascii")
            orphan.chmod(0o600)
            removed = subprocess.run(
                ["/bin/sh", str(uninstall), str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(orphan.exists())
            self.assertFalse(paths["rollback"].exists())
            self.assertFalse(paths["live_host"].exists())
            self.assertFalse(paths["live_firefox"].exists())
            self.assertFalse(paths["live_chrome"].exists())
            self.assertFalse(paths["live_edge"].exists())
            self.assertFalse(paths["host_dir"].exists())

    def test_orphan_stage_specials_in_rollback_do_not_wedge_uninstall(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-orphan-special-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            stagedir = paths["rollback"] / ".winsvpn-stage.DIR"
            stagedir.mkdir()
            keep = stagedir / "keep.txt"
            keep.write_text("KEEP-STAGE-DIR\n", encoding="ascii")
            fifo = paths["rollback"] / ".winsvpn-stage.FIFO"
            os.mkfifo(fifo)
            removed = subprocess.run(
                ["/bin/sh", str(uninstall), str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(paths["live_host"].exists())
            self.assertFalse(paths["live_firefox"].exists())
            self.assertFalse(paths["live_chrome"].exists())
            self.assertFalse(paths["live_edge"].exists())
            self.assertTrue(stagedir.is_dir())
            self.assertEqual(keep.read_text(encoding="ascii"), "KEEP-STAGE-DIR\n")
            self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))

    def test_orphan_stage_symlink_in_rollback_does_not_write_victim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-macos-companion-orphan-link-") as raw:
            work = pathlib.Path(raw)
            preinstall, postinstall, uninstall = self._extract_companion_scripts(work)
            paths = self._prepared_companion_volume(work)
            prepared = subprocess.run(
                ["/bin/sh", str(preinstall), str(work / "pkg.pkg"), "/", str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self._write_incoming(paths["incoming"], uninstall, bind_hashes=True)
            victim = self._write_keep_victim(work)
            orphan = paths["rollback"] / ".winsvpn-stage.LINK"
            orphan.symlink_to(victim / "keep.txt")
            removed = subprocess.run(
                ["/bin/sh", str(uninstall), str(paths["volume"])],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(orphan.exists())
            self.assertFalse(orphan.is_symlink())
            self._assert_victim_untouched(victim)
            self.assertFalse(paths["live_host"].exists())
            self.assertFalse(paths["live_firefox"].exists())
            self.assertFalse(paths["live_chrome"].exists())
            self.assertFalse(paths["live_edge"].exists())


if __name__ == "__main__":
    unittest.main()
