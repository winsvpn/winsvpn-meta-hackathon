#!/usr/bin/env python3
"""Reproduced P1 bypasses for release-artifact privacy scanning."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
import zlib
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import release_secret_inventory as inventory
import validate_release_artifact_privacy as privacy


SYNTHETIC_ALPHA = "synthetic-inventory-secret-alpha-0001"
SYNTHETIC_BETA = "synthetic-inventory-secret-beta-0002"


def _assert_undisclosed(test: unittest.TestCase, text: str, *values: str) -> None:
    for value in values:
        test.assertNotIn(value, text)
        test.assertNotIn(hashlib.sha256(value.encode("utf-8")).hexdigest(), text)


def _churn_tempdir_siblings(tag: str) -> None:
    root = pathlib.Path(tempfile.gettempdir())
    sibling = root / f"wins-relpriv-churn-{os.getpid()}-{tag}-{time.time_ns()}"
    sibling.mkdir()
    try:
        (sibling / "nlink").mkdir()
        try:
            os.utime(root, None)
        except OSError:
            pass
    finally:
        shutil.rmtree(sibling, ignore_errors=True)


def _churn_bound_ancestors(path: pathlib.Path, index: int) -> None:
    _churn_tempdir_siblings(f"{path.name}-{index}")
    parent = path.parent
    local = parent / f"wins-local-churn-{index}-{time.time_ns()}"
    local.mkdir()
    try:
        (local / "nlink").mkdir()
    finally:
        shutil.rmtree(local, ignore_errors=True)
    bound = pathlib.Path(*path.parts[: index + 1])
    try:
        os.utime(bound, None)
    except OSError:
        pass


def _write_inventory(path: pathlib.Path, secrets: dict[str, str] | None = None) -> pathlib.Path:
    payload = {
        "schema_version": 1,
        "revision": "rev-p1-1",
        "secrets": secrets or {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
    }
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)
    return path


def _zip_payload(root: pathlib.Path, payload: bytes, name: str = "client.bin") -> pathlib.Path:
    path = root / "artifact.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, payload)
    return path


def _tar_payload(root: pathlib.Path, payload: bytes, name: str = "client.bin") -> pathlib.Path:
    path = root / "artifact.tar.gz"
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(info, io.BytesIO(payload))
    return path


def _named_artifact(root: pathlib.Path, name: str, kind: str) -> pathlib.Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("client.bin", b"clean-fixture")
    elif kind == "exe":
        path.write_bytes(b"MZ" + b"\0" * 64)
    elif kind == "targz":
        payload = b"clean-fixture"
        info = tarfile.TarInfo("client.bin")
        info.size = len(payload)
        with tarfile.open(path, "w:gz") as archive:
            archive.addfile(info, io.BytesIO(payload))
    elif kind == "json":
        path.write_text("{}", encoding="utf-8")
    elif kind == "yaml":
        path.write_text("name: winsvpn\n", encoding="utf-8")
    else:
        path.write_bytes(b"clean-fixture")
    return path


REPRODUCED_PRIVACY_TARGET_SWAPS = (
    ("app-tv-release.apk", "zip", "android-phone-tablet-apk"),
    ("app-phone-release.aab", "zip", "android-tv-aab"),
    ("app-release.aab", "zip", "wear-os-aab"),
    ("WinsVPN-Setup.exe", "exe", "windows-arm64-installer"),
)

CANONICAL_PRIVACY_BINDINGS = (
    ("android-phone-tablet-apk", "app-phone-release.apk", "zip"),
    ("android-phone-tablet-apk", "app-release.apk", "zip"),
    ("android-phone-tablet-aab", "app-phone-release.aab", "zip"),
    ("android-phone-tablet-aab", "app-release.aab", "zip"),
    ("android-tv-apk", "app-tv-release.apk", "zip"),
    ("android-tv-aab", "app-tv-release.aab", "zip"),
    ("wear-os-aab", "wear_os/app-release.aab", "zip"),
    ("ios-app-store-ipa", "WinsVPN.ipa", "zip"),
    ("macos-developer-id-app", "WinsVPN.app.zip", "zip"),
    ("windows-x64-installer", "WinsVPN-Setup.exe", "exe"),
    ("windows-x64-installer", "WinsVPN-UNSIGNED-LOCAL-Setup.exe", "exe"),
    ("windows-x64-partner-center", "WinsVPN-PartnerCenter.exe", "exe"),
    ("windows-arm64-installer", "WinsVPN-Setup-arm64.exe", "exe"),
    ("windows-arm64-installer", "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe", "exe"),
    ("windows-arm64-partner-center", "WinsVPN-PartnerCenter-arm64.exe", "exe"),
    ("linux-x64-package", "wins-vpn-linux-x64.tar.gz", "targz"),
    ("linux-arm64-package", "wins-vpn-linux-arm64.tar.gz", "targz"),
    ("linux-flathub-manifest", "org.winsvpn.app.json", "json"),
    ("linux-snap-manifest", "snapcraft.yaml", "yaml"),
    ("chrome-extension-package", "wins-vpn-companion-chrome.zip", "zip"),
    ("edge-extension-package", "wins-vpn-companion-edge.zip", "zip"),
    ("firefox-extension-package", "wins-vpn-companion-firefox.zip", "zip"),
)

ADJACENT_PRIVACY_TARGET_SWAPS = (
    ("app-phone-release.apk", "zip", "android-tv-apk"),
    ("app-tv-release.aab", "zip", "android-phone-tablet-aab"),
    ("app-release.aab", "zip", "android-tv-aab"),
    ("wear_os/app-release.aab", "zip", "android-phone-tablet-aab"),
    ("WinsVPN-Setup.exe", "exe", "windows-x64-partner-center"),
    ("WinsVPN-PartnerCenter.exe", "exe", "windows-x64-installer"),
    ("WinsVPN-Setup-arm64.exe", "exe", "windows-x64-installer"),
    ("WinsVPN-UNSIGNED-LOCAL-Setup.exe", "exe", "windows-arm64-installer"),
    ("WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe", "exe", "windows-x64-installer"),
    ("WinsVPN-PartnerCenter-arm64.exe", "exe", "windows-arm64-installer"),
    ("wins-vpn-linux-x64.tar.gz", "targz", "linux-arm64-package"),
    ("wins-vpn-linux-arm64.tar.gz", "targz", "linux-x64-package"),
    ("org.winsvpn.app.json", "json", "linux-snap-manifest"),
    ("snapcraft.yaml", "yaml", "linux-flathub-manifest"),
    ("wins-vpn-companion-firefox.zip", "zip", "chrome-extension-package"),
    ("WinsVPN.ipa", "zip", "macos-app-store-pkg"),
    ("WinsVPN.pkg", "bytes", "macos-developer-id-app"),
    ("WinsVPN.app.zip", "zip", "macos-app-store-pkg"),
)


class ReleaseArtifactPrivacyP1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="wins-privacy-p1-")
        self.base = pathlib.Path(self._temp.name)
        self.release_values_patcher = mock.patch.object(
            privacy,
            "release_secret_values",
            side_effect=lambda loaded: loaded._stream_secret_values(),
        )
        self.release_values = self.release_values_patcher.start()

    def tearDown(self) -> None:
        self.release_values_patcher.stop()
        self._temp.cleanup()

    def inventory(self, secrets: dict[str, str] | None = None):
        path = _write_inventory(self.base / "inventory.json", secrets)
        return inventory.load_secret_inventory(path, repository_root=ROOT)

    def test_javascript_reconstruction_is_bounded_on_large_scanner_source(self) -> None:
        source = pathlib.Path(privacy.__file__).read_bytes()
        self.assertLess(len(source), 4 * 1024 * 1024)
        privacy.javascript_concatenated_blobs(source)
        privacy.javascript_array_join_blobs(source)

    def test_utf32_le_and_be_are_matched_and_redacted(self) -> None:
        loaded = self.inventory()
        for encoding in ("utf-32-le", "utf-32-be"):
            with self.subTest(encoding=encoding):
                artifact = _zip_payload(
                    self.base, SYNTHETIC_ALPHA.encode(encoding), f"{encoding}.bin"
                )
                result = privacy.scan_release_artifacts((artifact,), loaded)
                self.assertFalse(result.passed, encoding)
                self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
                _assert_undisclosed(
                    self, privacy.format_inventory_scan_report(result), SYNTHETIC_ALPHA
                )

    def test_utf32_bom_and_reversible_encodings_are_matched(self) -> None:
        loaded = self.inventory()
        raw = SYNTHETIC_ALPHA.encode("utf-8")
        encodings = {
            "utf-32-le-bom": b"\xff\xfe\x00\x00" + SYNTHETIC_ALPHA.encode("utf-32-le"),
            "utf-32-be-bom": b"\x00\x00\xfe\xff" + SYNTHETIC_ALPHA.encode("utf-32-be"),
            "base32": base64.b32encode(raw),
            "quoted-printable": __import__("binascii").b2a_qp(raw),
            "js-hex": "".join(f"\\x{byte:02x}" for byte in raw).encode("ascii"),
            "hex-colon": raw.hex(":").encode("ascii"),
            "sha256": hashlib.sha256(raw).hexdigest().encode("ascii"),
        }
        for name, payload in encodings.items():
            with self.subTest(encoding=name):
                artifact = _zip_payload(self.base, payload, f"{name}.bin")
                result = privacy.scan_release_artifacts((artifact,), loaded)
                self.assertFalse(result.passed, name)
                self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
                report = privacy.format_inventory_scan_report(result)
                _assert_undisclosed(self, report, SYNTHETIC_ALPHA)

    def test_secret_derived_revision_field_is_matched(self) -> None:
        loaded = self.inventory()
        digest = hashlib.sha256(SYNTHETIC_ALPHA.encode("utf-8")).hexdigest()
        payload = json.dumps({"revision": digest, "ok": True}).encode("utf-8")
        artifact = _zip_payload(self.base, payload, "manifest.json")
        result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
        _assert_undisclosed(
            self, privacy.format_inventory_scan_report(result), SYNTHETIC_ALPHA
        )
        self.assertNotIn(digest, privacy.format_inventory_scan_report(result))

    def test_zip_trailer_is_scanned(self) -> None:
        loaded = self.inventory()
        artifact = _zip_payload(self.base, b"clean-fixture")
        artifact.write_bytes(artifact.read_bytes() + SYNTHETIC_ALPHA.encode("utf-8"))
        result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

    def test_tar_uname_gname_and_pax_are_scanned(self) -> None:
        loaded = self.inventory()
        payload = b"clean-fixture"
        uname = self.base / "uname.tar.gz"
        info = tarfile.TarInfo("client.bin")
        info.size = len(payload)
        info.uname = SYNTHETIC_ALPHA
        with tarfile.open(uname, "w:gz") as archive:
            archive.addfile(info, io.BytesIO(payload))
        result = privacy.scan_release_artifacts((uname,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

        gname = self.base / "gname.tar.gz"
        info = tarfile.TarInfo("client.bin")
        info.size = len(payload)
        info.gname = SYNTHETIC_ALPHA
        with tarfile.open(gname, "w:gz") as archive:
            archive.addfile(info, io.BytesIO(payload))
        result = privacy.scan_release_artifacts((gname,), loaded)
        self.assertFalse(result.passed)

        pax = self.base / "pax.tar.gz"
        info = tarfile.TarInfo("client.bin")
        info.size = len(payload)
        info.pax_headers["comment"] = SYNTHETIC_ALPHA
        with tarfile.open(pax, "w:gz") as archive:
            archive.addfile(info, io.BytesIO(payload))
        result = privacy.scan_release_artifacts((pax,), loaded)
        self.assertFalse(result.passed)
        _assert_undisclosed(
            self, privacy.format_inventory_scan_report(result), SYNTHETIC_ALPHA
        )

    def test_tar_residual_bytes_are_scanned(self) -> None:
        # Payload padding, a block before the end blocks, and bytes after the
        # end blocks are not member payloads, but every reader of the stream
        # sees them (R22 Y3-01).
        loaded = self.inventory()
        secret = SYNTHETIC_ALPHA.encode("utf-8")

        def plain_tar() -> bytes:
            stream = io.BytesIO()
            info = tarfile.TarInfo("client.bin")
            info.size = 5
            with tarfile.open(fileobj=stream, mode="w") as archive:
                archive.addfile(info, io.BytesIO(b"hello"))
            return stream.getvalue()

        def in_padding() -> bytes:
            raw = bytearray(plain_tar())
            raw[512 + 5 : 512 + 5 + len(secret)] = secret
            return bytes(raw)

        def before_end_blocks() -> bytes:
            raw = plain_tar()
            return raw[:1024] + secret.ljust(512, b"\0") + raw[1024:]

        def after_end_blocks() -> bytes:
            return plain_tar() + secret.ljust(512, b"\0")

        def top_level(name: str, payload: bytes) -> pathlib.Path:
            path = self.base / name
            path.write_bytes(payload)
            return path

        containers = {
            "artifact.tar": lambda root, raw: top_level(f"{root.name}.tar", raw),
            "artifact.tar.gz": lambda root, raw: top_level(
                f"{root.name}.tar.gz", gzip.compress(raw, mtime=0)
            ),
            "artifact.tar.xz": lambda root, raw: top_level(
                f"{root.name}.tar.xz", lzma.compress(raw)
            ),
            "nested x.tgz": lambda root, raw: _zip_payload(
                root, gzip.compress(raw, mtime=0), "x.tgz"
            ),
            "nested tar-shaped NOTICES.Z": lambda root, raw: _zip_payload(
                root, gzip.compress(raw, mtime=0), "assets/flutter_assets/NOTICES.Z"
            ),
        }
        for place, build in (
            ("padding", in_padding),
            ("before-end-blocks", before_end_blocks),
            ("after-end-blocks", after_end_blocks),
        ):
            for container, wrap in containers.items():
                with self.subTest(place=place, container=container):
                    root = self.base / f"{place}-{container.replace(' ', '-')}"
                    root.mkdir()
                    artifact = wrap(root, build())
                    result = privacy.scan_release_artifacts((artifact,), loaded)
                    self.assertFalse(result.passed)
                    self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
                    _assert_undisclosed(
                        self, privacy.format_inventory_scan_report(result), SYNTHETIC_ALPHA
                    )
        for container, wrap in containers.items():
            with self.subTest(clean=container):
                root = self.base / f"clean-{container.replace(' ', '-')}"
                root.mkdir()
                artifact = wrap(root, plain_tar())
                self.assertTrue(privacy.scan_release_artifacts((artifact,), loaded).passed)

    def test_top_level_gzip_tar_header_fields_and_trailer_are_covered(self) -> None:
        loaded = self.inventory()
        secret = SYNTHETIC_ALPHA.encode("utf-8")
        stream = io.BytesIO()
        info = tarfile.TarInfo("client.bin")
        info.size = 5
        with tarfile.open(fileobj=stream, mode="w") as archive:
            archive.addfile(info, io.BytesIO(b"hello"))
        raw = stream.getvalue()
        deflate = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        body = deflate.compress(raw) + deflate.flush()
        trailer = (
            (zlib.crc32(raw) & 0xFFFFFFFF).to_bytes(4, "little")
            + len(raw).to_bytes(4, "little")
        )
        headers = {
            "FEXTRA": b"\x1f\x8b\x08\x04\0\0\0\0\x00\xff"
            + len(secret).to_bytes(2, "little")
            + secret,
            "FNAME": b"\x1f\x8b\x08\x08\0\0\0\0\x00\xff" + secret + b"\0",
            "FCOMMENT": b"\x1f\x8b\x08\x10\0\0\0\0\x00\xff" + secret + b"\0",
        }
        for field, header in headers.items():
            with self.subTest(field=field):
                artifact = self.base / f"{field}.tar.gz"
                artifact.write_bytes(header + body + trailer)
                result = privacy.scan_release_artifacts((artifact,), loaded)
                self.assertFalse(result.passed)
                self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
        for name, payload in (
            ("raw-trailer", gzip.compress(raw, mtime=0) + secret),
            ("second-member", gzip.compress(raw, mtime=0) + gzip.compress(secret, mtime=0)),
        ):
            with self.subTest(case=name):
                artifact = self.base / f"{name}.tar.gz"
                artifact.write_bytes(payload)
                with self.assertRaisesRegex(privacy.PrivacyError, "not inspectable") as raised:
                    privacy.scan_release_artifacts((artifact,), loaded)
                _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)

    def test_zip_bytes_outside_member_payloads_are_scanned(self) -> None:
        # Bytes between entries (where an APK Signing Block sits) and before the
        # central directory are not member payloads but are in the file (R22
        # Y3-01, zip sibling of the tar residual).
        loaded = self.inventory()
        secret = SYNTHETIC_ALPHA.encode("utf-8")

        def two_entry_zip() -> bytes:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("a.bin", b"clean-a")
                archive.writestr("b.bin", b"clean-b")
            return stream.getvalue()

        def insert_gap(raw: bytes, at: int, gap: bytes) -> bytes:
            eocd = raw.rfind(b"PK\x05\x06")
            cd_size = int.from_bytes(raw[eocd + 12 : eocd + 16], "little")
            cd_offset = int.from_bytes(raw[eocd + 16 : eocd + 20], "little")
            central = bytearray(raw[cd_offset : cd_offset + cd_size])
            cursor = 0
            while cursor < len(central):
                local = int.from_bytes(central[cursor + 42 : cursor + 46], "little")
                if local >= at:
                    central[cursor + 42 : cursor + 46] = (local + len(gap)).to_bytes(4, "little")
                lengths = (
                    int.from_bytes(central[cursor + 28 : cursor + 30], "little")
                    + int.from_bytes(central[cursor + 30 : cursor + 32], "little")
                    + int.from_bytes(central[cursor + 32 : cursor + 34], "little")
                )
                cursor += 46 + lengths
            tail = bytearray(raw[eocd:])
            tail[16:20] = (cd_offset + len(gap)).to_bytes(4, "little")
            return raw[:at] + gap + raw[at:cd_offset] + bytes(central) + raw[cd_offset + cd_size : eocd] + bytes(tail)

        raw = two_entry_zip()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            second = archive.getinfo("b.bin").header_offset
        cd_offset = int.from_bytes(raw[raw.rfind(b"PK\x05\x06") + 16 :][:4], "little")
        variants = {
            "between entries": insert_gap(raw, second, secret),
            "before central directory": insert_gap(raw, cd_offset, secret),
        }
        for place, payload in variants.items():
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                self.assertIsNone(archive.testzip())
            for container in ("top-level", "nested"):
                with self.subTest(place=place, container=container):
                    root = self.base / f"{place.replace(' ', '-')}-{container}"
                    root.mkdir()
                    if container == "top-level":
                        artifact = root / "artifact.zip"
                        artifact.write_bytes(payload)
                    else:
                        artifact = _zip_payload(root, payload, "inner.zip")
                    result = privacy.scan_release_artifacts((artifact,), loaded)
                    self.assertFalse(result.passed)
                    self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
        clean = self.base / "clean.zip"
        clean.write_bytes(insert_gap(raw, second, b"\0" * 64))
        self.assertTrue(privacy.scan_release_artifacts((clean,), loaded).passed)

    def test_tar_residual_keeps_reviewed_vendor_member_exemption(self) -> None:
        # Payloads stay out of the residual blob, so a reviewed vendor binary
        # (the Linux Xray executables carry upstream public-IP URIs) is judged
        # by its own digest and not by the digest of the whole stream.
        loaded = self.inventory()
        vendor = b"\x00vendor table https://203.0.113.7/resolve\x00" * 4
        stream = io.BytesIO()
        info = tarfile.TarInfo("xray")
        info.size = len(vendor)
        info.mode = 0o755
        with tarfile.open(fileobj=stream, mode="w") as archive:
            archive.addfile(info, io.BytesIO(vendor))
        artifact = self.base / "vendor.tar.gz"
        artifact.write_bytes(gzip.compress(stream.getvalue(), mtime=0))
        with self.assertRaisesRegex(privacy.PrivacyError, "public-IP URI"):
            privacy.scan_release_artifacts((artifact,), loaded)
        approved = {hashlib.sha256(vendor).hexdigest()}
        with mock.patch.object(privacy, "APPROVED_VENDOR_BINARY_SHA256", approved):
            self.assertTrue(privacy.scan_release_artifacts((artifact,), loaded).passed)

    def test_awg_cli_symbol_table_is_exempt_only_for_its_two_pinned_builds(self) -> None:
        import release_obfuscation_contract as obfuscation

        payload = obfuscation._minimal_elf64(".text", ".symtab")
        with self.assertRaisesRegex(privacy.PrivacyError, "unstripped native debug sections"):
            privacy.reject_unstripped_native_library("awg", payload)
        approved = {"awg": frozenset({hashlib.sha256(payload).hexdigest()})}
        with mock.patch.object(privacy, "APPROVED_VENDOR_DEBUG_METADATA_SHA256", approved):
            privacy.reject_unstripped_native_library("awg", payload)
            privacy.reject_unstripped_native_library("./bin/awg", payload)
            # The exception is bound to the exact basename and the exact bytes.
            with self.assertRaisesRegex(privacy.PrivacyError, "unstripped native debug sections"):
                privacy.reject_unstripped_native_library("xray", payload)
            with self.assertRaisesRegex(privacy.PrivacyError, "unstripped native debug sections"):
                privacy.reject_unstripped_native_library("awg", payload + b"\0")

    def test_awg_exemption_digests_are_exactly_the_linux_producer_pins(self) -> None:
        producer = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
        pins = {
            re.search(rf'^{name}="([0-9a-f]{{64}})"$', producer, re.MULTILINE).group(1)
            for name in ("AWG_BINARY_SHA256", "AWG_BINARY_SHA256_ARM64")
        }
        self.assertEqual(set(privacy.APPROVED_VENDOR_DEBUG_METADATA_SHA256["awg"]), pins)

    def test_javascript_split_values_reach_every_pattern_scan(self) -> None:
        # R23 W1-03: the joined JavaScript views fed only the exact-secret
        # scan; a value split across "..." + "..." or [...].join("") passed
        # the private-key, token, credential and forbidden-literal scans.
        cases = {
            "reusable secret category private_key_material": (
                b"-----BEGIN P", b"RIVATE KEY-----",
            ),
            "reusable secret category github_token": (
                b"ghp_SSSSSS", b"S" * 30,
            ),
            "forbidden client literal category plaintext_hub_hostname": (
                b"http://hub.", b"winsvpn.org",
            ),
            "reusable secret category credential_assignment": (
                b"api_key='SYNTH", b"ETICONLYNOTAREALVALUE0123'",
            ),
        }
        for message, (first, second) in cases.items():
            forms = {
                "contiguous control": b'var k="' + first + second + b'";',
                "concatenated": b'var k="' + first + b'"+"' + second + b'";',
                "array join": b'var k=["' + first + b'","' + second + b'"].join("");',
            }
            for form, payload in forms.items():
                with self.subTest(category=message, form=form):
                    with self.assertRaisesRegex(privacy.PrivacyError, message):
                        privacy.check_blob("bundle.js", payload, {})
        # Ordinary bundle text that joins harmless strings still passes.
        privacy.check_blob(
            "bundle.js", b'var a="Hello, "+"world";var b=["x","y"].join("-");', {}
        )

    def test_javascript_split_forms_keep_the_code_around_the_value(self) -> None:
        # R24 V2 F-01: the joined views hold only the joined value, so a name that
        # sits in code beside a split value, a template literal, a parenthesized or
        # .concat() join, and an array join over 256 pieces all passed.
        cases = (
            ("credential_assignment", b'var api_key="SYNTH"+"ETICVALUE0123456789ABCDEF";'),
            ("credential_assignment", b'var api_key=["SYNTH","ETICVALUE0123456789ABCDEF"].join("");'),
            ("credential_assignment", b'o={api_key:`SYNTH`+`ETICVALUE0123456789ABCDEF`};'),
            ("credential_assignment", b'var api_key="SYNTH".concat("ETICVALUE0123456789ABCDEF");'),
            ("google_service_account_json", b'var j={"type":"service_"+"account","private_key_id":"x"};'),
            ("private_key_material", b'x=`-----BEGIN PRI`+`VATE KEY-----`;'),
            ("private_key_material", b'x=("-----BEGIN PRI")+("VATE KEY-----");'),
            ("private_key_material", b'x="-----BEGIN PRI".concat("VATE KEY-----");'),
            ("private_key_material", b'x="-----BEGIN ".concat("PRI","VATE"," KEY-----");'),
            ("private_key_material", b'x="-----BEGIN ".concat("PRI") + "VATE KEY-----";'),
        )
        for category, payload in cases:
            with self.subTest(category=category, payload=payload[:40]):
                with self.assertRaisesRegex(privacy.PrivacyError, category):
                    privacy.check_blob("bundle.js", payload, {})
        secret = "SYNTHSECRETVALUE0123456789abcdef" * 10
        forms = {
            "array join over 256 pieces": "x=[%s].join('');" % ",".join(f'"{c}"' for c in secret),
            "template literal pieces": "x=%s;" % "+".join(f"`{c}`" for c in secret),
            "parenthesized pieces": "x=%s;" % "+".join(f'("{c}")' for c in secret),
        }
        for form, text in forms.items():
            with self.subTest(form=form):
                with self.assertRaisesRegex(privacy.PrivacyError, "exact known-server-secret"):
                    privacy.check_blob("bundle.js", text.encode(), {"SYNTHETIC": secret})
        # A harmless join that merely sits near a credential-looking name passes.
        privacy.check_blob(
            "bundle.js",
            b'var password="ab"+"cd";var api_key=process.env.API_KEY;'
            b'var u=["https:","","example.com"].join("/");',
            {},
        )
        # Long whitespace and parenthesis runs next to a string token stay linear
        # (an unbounded \s*\)?\s* around the token backtracks quadratically).
        for blob in (
            b'"a"' + b" " * (1 << 20) + b"z",
            b'"a"' + b" " * (1 << 20) + b"+",
            b'("a" ' + b") " * (1 << 19) + b"(",
        ):
            privacy.check_blob("bundle.js", blob, {})

    def test_a_join_is_bounded_by_its_output_not_its_piece_count(self) -> None:
        pieces = ",".join('"x"' for _ in range(5000))
        source = f"[{pieces}].join('')".encode()
        self.assertEqual(privacy.javascript_array_join_blobs(source), (b"x" * 5000,))
        # A separator repeated per piece is the amplifying form and is skipped.
        amplified = f"[{pieces}].join('{'s' * 400}')".encode()
        self.assertEqual(privacy.javascript_array_join_blobs(amplified), ())
        self.assertEqual(privacy.javascript_join_views(amplified), ((), None))

    def test_forbidden_client_literals_are_refused_in_utf16_like_ascii(self) -> None:
        # R24 V2 F-13: Windows wide strings carry the same names. The single-byte
        # scan missed them although the public-IP URI and IPv4 scans already read
        # the wide forms.
        for name, literal in privacy.FORBIDDEN_CLIENT_LITERALS.items():
            text = literal.decode("ascii")
            forms = {
                "ascii": text.encode("ascii"),
                "utf-16-le": text.encode("utf-16-le"),
                "utf-16-be": text.encode("utf-16-be"),
                "utf-16-le lower": text.lower().encode("utf-16-le"),
            }
            wide_expected = len(literal) >= privacy.UTF16_MIN_LITERAL_BYTES
            for form, payload in forms.items():
                with self.subTest(category=name, form=form):
                    padded = b"\x00\x00noise\x00" + payload + b"\x00tail"
                    if form == "ascii" or wide_expected:
                        with self.assertRaisesRegex(
                            privacy.PrivacyError, f"forbidden client literal category {name}"
                        ):
                            privacy.check_blob("app.exe", padded, {})
                    else:
                        privacy.check_blob("app.exe", padded, {})
        # Ordinary wide text that merely sits near interleaved NULs still passes.
        privacy.check_blob("app.exe", "hello world, plain wide text".encode("utf-16-le"), {})

    def test_utf16_public_ip_uri_is_refused_like_ascii(self) -> None:
        # R23 W1-14: wide-string public-IP URIs (Windows native code) passed.
        uri = "https://203.0.113.10:8443/api/v1"
        for label, payload in (
            ("ascii", b"\x00" + uri.encode("ascii") + b"\x00"),
            ("utf-16-le", b"\x00\x01" + uri.encode("utf-16-le") + b"\x00\x00"),
            ("utf-16-le odd offset", b"\x07" + uri.encode("utf-16-le") + b"\x00\x00"),
            ("utf-16-be", b"\x00\x00" + uri.encode("utf-16-be") + b"\x00\x00"),
        ):
            with self.subTest(form=label):
                with self.assertRaisesRegex(privacy.PrivacyError, "public-IP URI"):
                    privacy.check_blob("runner.exe", payload, {})
        # The approved digest is the digest of the URI text in every encoding.
        wide = b"\x00" + uri.encode("utf-16-le") + b"\x00\x00"
        approved = {hashlib.sha256(uri.encode("ascii")).hexdigest()}
        with mock.patch.object(privacy, "APPROVED_THIRD_PARTY_IP_URI_SHA256", approved):
            privacy.check_blob("runner.exe", wide, {})
        # A hostname route in UTF-16 is still allowed.
        privacy.check_blob(
            "runner.exe", "https://sync.winsvpn.org/api".encode("utf-16-le"), {}
        )

    def test_macos_pkg_payload_and_scripts_are_expanded_and_scanned(self) -> None:
        # R22 Y3-05: PKG members get the same nested-archive recursion as zip,
        # tar and directory members (a gzip NOTICES.Z in the app bundle, and
        # the gzip cpio Scripts archive of a component package).
        pkgbuild = pathlib.Path("/usr/bin/pkgbuild")
        if sys.platform != "darwin" or not pkgbuild.is_file():
            self.skipTest("pkgbuild is unavailable")
        if shutil.which("bsdtar") is None and shutil.which("tar") is None:
            self.skipTest("bsdtar/tar is unavailable")
        loaded = self.inventory()
        secret = SYNTHETIC_ALPHA.encode("utf-8")

        def build(name: str, notices: bytes, script: bytes | None = None) -> pathlib.Path:
            root = self.base / f"{name}-root"
            resources = root / "Fixture.app" / "Contents" / "Resources"
            resources.mkdir(parents=True)
            (resources / "NOTICES.Z").write_bytes(notices)
            command = [
                str(pkgbuild),
                "--quiet",
                "--root",
                str(root),
                "--identifier",
                "org.example.fixture",
                "--version",
                "1",
                "--install-location",
                "/Applications",
            ]
            if script is not None:
                scripts = self.base / f"{name}-scripts"
                scripts.mkdir()
                postinstall = scripts / "postinstall"
                postinstall.write_bytes(b"#!/bin/sh\n" + script + b"\n")
                postinstall.chmod(0o755)
                command += ["--scripts", str(scripts)]
            package = self.base / f"{name}.pkg"
            completed = subprocess.run(
                [*command, str(package)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
            return package

        clean = build("clean", gzip.compress(b"third-party notices " * 64, mtime=0))
        self.assertTrue(privacy.scan_release_artifacts((clean,), loaded).passed)
        for name, notices, script in (
            ("payload-notices", gzip.compress(b"notice " + secret, mtime=0), None),
            ("scripts", gzip.compress(b"third-party notices", mtime=0), b"echo " + secret),
        ):
            with self.subTest(case=name):
                result = privacy.scan_release_artifacts((build(name, notices, script),), loaded)
                self.assertFalse(result.passed)
                self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
                _assert_undisclosed(
                    self, privacy.format_inventory_scan_report(result), SYNTHETIC_ALPHA
                )

    def test_zstd_tar_secret_is_detected_or_fails_closed(self) -> None:
        zstd = shutil.which("zstd")
        if zstd is None:
            self.skipTest("zstd is unavailable")
        payload = io.BytesIO()
        secret = SYNTHETIC_ALPHA.encode("utf-8")
        info = tarfile.TarInfo("client.bin")
        info.size = len(secret)
        with tarfile.open(fileobj=payload, mode="w") as archive:
            archive.addfile(info, io.BytesIO(secret))
        artifact = self.base / "artifact.tar.zst"
        completed = subprocess.run(
            [zstd, "-q", "-c"],
            input=payload.getvalue(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
        artifact.write_bytes(completed.stdout)
        loaded = self.inventory()
        if "zst" not in tarfile.TarFile.OPEN_METH:
            with self.assertRaises(privacy.PrivacyError) as raised:
                privacy.scan_release_artifacts((artifact,), loaded)
            _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)
            return
        result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

    def test_gzip_member_that_is_not_a_tarball_is_expanded_and_scanned(self) -> None:
        # Flutter ships assets/flutter_assets/NOTICES.Z, a gzip stream that is
        # not a tarball. It must be expanded and scanned, not refused.
        loaded = self.inventory()
        name = "assets/flutter_assets/NOTICES.Z"
        clean_root = self.base / "clean"
        clean_root.mkdir()
        clean = _zip_payload(clean_root, gzip.compress(b"third-party notices " * 64), name)
        self.assertTrue(privacy.scan_release_artifacts((clean,), loaded).passed)

        dirty_root = self.base / "dirty"
        dirty_root.mkdir()
        hidden = gzip.compress(b"notice " + SYNTHETIC_ALPHA.encode("utf-8"))
        dirty = _zip_payload(dirty_root, hidden, name)
        result = privacy.scan_release_artifacts((dirty,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

        corrupt_root = self.base / "corrupt"
        corrupt_root.mkdir()
        corrupt = _zip_payload(corrupt_root, hidden[:-12], name)
        with self.assertRaisesRegex(privacy.PrivacyError, "not inspectable"):
            privacy.scan_release_artifacts((corrupt,), loaded)

    def test_gzip_member_naming_and_tarball_claims(self) -> None:
        self.assertEqual(privacy._gunzip_member_name("assets/flutter_assets/NOTICES.Z"), "assets/flutter_assets/NOTICES")
        self.assertEqual(privacy._gunzip_member_name("a/key.json.gz"), "a/key.json")
        self.assertEqual(privacy._gunzip_member_name("a/bundle.tgz"), "a/bundle.tar")
        loaded = self.inventory()
        fake_root = self.base / "fake-tgz"
        fake_root.mkdir()
        fake = _zip_payload(fake_root, gzip.compress(b"not a tar stream at all " * 8), "payload.tgz")
        with self.assertRaisesRegex(privacy.PrivacyError, "not inspectable"):
            privacy.scan_release_artifacts((fake,), loaded)
        inner = io.BytesIO()
        info = tarfile.TarInfo("client.bin")
        secret = SYNTHETIC_ALPHA.encode("utf-8")
        info.size = len(secret)
        with tarfile.open(fileobj=inner, mode="w:gz") as archive:
            archive.addfile(info, io.BytesIO(secret))
        tar_root = self.base / "nested-tgz"
        tar_root.mkdir()
        nested = _zip_payload(tar_root, inner.getvalue(), "inner.tar.gz")
        result = privacy.scan_release_artifacts((nested,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

    def test_nested_zip_and_tar_are_scanned_with_depth_limit(self) -> None:
        loaded = self.inventory()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("client.bin", SYNTHETIC_ALPHA.encode("utf-8"))
        outer = self.base / "nested.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("inner.zip", inner.getvalue())
        result = privacy.scan_release_artifacts((outer,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

        inner_tar = io.BytesIO()
        info = tarfile.TarInfo("client.bin")
        secret = SYNTHETIC_ALPHA.encode("utf-8")
        info.size = len(secret)
        with tarfile.open(fileobj=inner_tar, mode="w") as archive:
            archive.addfile(info, io.BytesIO(secret))
        outer_tar = _tar_payload(self.base, inner_tar.getvalue(), "inner.tar")
        result = privacy.scan_release_artifacts((outer_tar,), loaded)
        self.assertFalse(result.passed)

        with mock_nest_depth(0):
            with self.assertRaisesRegex(privacy.PrivacyError, "nested-archive"):
                privacy.scan_release_artifacts((outer,), loaded)

    def test_nested_zstd_is_recognized_and_unsupported_runtime_fails_closed(self) -> None:
        zstd = shutil.which("zstd")
        if zstd is None:
            self.skipTest("zstd is unavailable")
        inner_tar = io.BytesIO()
        info = tarfile.TarInfo("client.bin")
        secret = SYNTHETIC_ALPHA.encode("utf-8")
        info.size = len(secret)
        with tarfile.open(fileobj=inner_tar, mode="w") as archive:
            archive.addfile(info, io.BytesIO(secret))
        compressed = subprocess.run(
            [zstd, "-q", "-c"],
            input=inner_tar.getvalue(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        outer = self.base / "nested-zstd.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("inner.tar.zst", compressed)
        loaded = self.inventory()
        real_open = privacy.tarfile.open

        def unsupported_zstd(*args, **kwargs):
            if kwargs.get("mode") == "r:zst":
                raise tarfile.CompressionError("zstandard unsupported")
            return real_open(*args, **kwargs)

        with mock.patch.object(
            privacy.tarfile, "open", side_effect=unsupported_zstd
        ):
            with self.assertRaises(privacy.PrivacyError):
                privacy.scan_release_artifacts((outer,), loaded)

    def test_explicit_cli_artifact_requires_exact_target(self) -> None:
        artifact = _zip_payload(self.base, b"clean-fixture")
        loaded = self.inventory()
        with mock.patch.object(
            privacy,
            "load_authenticated_secret_inventory",
            return_value=loaded,
        ):
            with self.assertRaisesRegex(privacy.PrivacyError, "require --target"):
                privacy.main(["--artifacts", "--artifact", str(artifact)])

    def test_parser_exceptions_become_redacted_privacy_errors(self) -> None:
        loaded = self.inventory()
        truncated = self.base / "truncated.zip"
        truncated.write_bytes(b"PK\x03\x04" + SYNTHETIC_ALPHA.encode("utf-8"))
        with self.assertRaises(privacy.PrivacyError) as raised:
            privacy.scan_release_artifacts((truncated,), loaded)
        self.assertIsNone(raised.exception.__cause__)
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)
        self.assertIn("inspectable", str(raised.exception))

    def test_symlink_fifo_hardlink_and_unsafe_mode_are_rejected(self) -> None:
        loaded = self.inventory()
        directory = self.base / "tree"
        directory.mkdir()
        (directory / "ok.bin").write_bytes(b"clean-fixture")
        linked = directory / "link.bin"
        linked.symlink_to(directory / "ok.bin")
        with self.assertRaisesRegex(privacy.PrivacyError, "non-symlink"):
            privacy.scan_release_artifacts((directory,), loaded)

        fifo_dir = self.base / "fifo-tree"
        fifo_dir.mkdir()
        (fifo_dir / "ok.bin").write_bytes(b"clean-fixture")
        os.mkfifo(fifo_dir / "pipe.bin")
        with self.assertRaisesRegex(privacy.PrivacyError, "special file"):
            privacy.scan_release_artifacts((fifo_dir,), loaded)

        hard_dir = self.base / "hard-tree"
        hard_dir.mkdir()
        regular = hard_dir / "ok.bin"
        regular.write_bytes(b"clean-fixture")
        os.link(regular, hard_dir / "alias.bin")
        with self.assertRaisesRegex(privacy.PrivacyError, "link count 1"):
            privacy.scan_release_artifacts((hard_dir,), loaded)

        unsafe = self.base / "unsafe.bin"
        unsafe.write_bytes(b"clean-fixture")
        unsafe.chmod(0o666)
        with self.assertRaisesRegex(privacy.PrivacyError, "unsafe mode"):
            privacy.scan_release_artifacts((unsafe,), loaded)

        fifo = self.base / "pipe-root.bin"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(privacy.PrivacyError, "special file"):
            privacy.scan_release_artifacts((fifo,), loaded)

    def test_unknown_target_id_fails_and_required_coverage_is_exact(self) -> None:
        loaded = self.inventory()
        artifact = _zip_payload(self.base, b"clean-fixture")
        with self.assertRaisesRegex(privacy.PrivacyError, "known release target"):
            privacy.scan_release_artifacts(
                (artifact,), loaded, target_id="not-a-real-target"
            )
        self.assertEqual(len(privacy.REQUIRED_PRIVACY_TARGET_IDS), 18)
        self.assertEqual(
            set(privacy.REQUIRED_PRIVACY_TARGET_IDS),
            set(privacy.DEFAULT_TARGET_RELATIVE_PATHS)
            | {"ios-app-store-ipa", "macos-app-store-pkg"},
        )
        self.assertEqual(
            set(privacy.TARGET_ARTIFACT_SUFFIXES) - privacy.OPTIONAL_PRIVACY_TARGET_IDS,
            set(privacy.REQUIRED_PRIVACY_TARGET_IDS),
        )
        privacy._assert_canonical_filename_tables()
        self.assertEqual(
            set(privacy.TARGET_CANONICAL_FILENAMES),
            set(privacy.KNOWN_PRIVACY_TARGET_IDS),
        )
        self.assertEqual(
            privacy.TARGET_ARTIFACT_SUFFIXES["macos-developer-id-app"],
            (".app.zip",),
        )
        for target_id, relative in privacy.DEFAULT_TARGET_RELATIVE_PATHS.items():
            path = pathlib.Path(relative)
            self.assertIn(
                path.name.casefold(),
                privacy.TARGET_CANONICAL_FILENAMES[target_id],
                target_id,
            )
            self.assertTrue(privacy._path_markers_match(target_id, path), target_id)
        for target_id in (
            "chrome-extension-package",
            "edge-extension-package",
            "firefox-extension-package",
        ):
            self.assertIn(target_id, privacy.REQUIRED_PRIVACY_TARGET_IDS)
            self.assertIn(target_id, privacy.EXTENSION_CROSS_STORE_TARGETS)

    def test_exact_extension_target_rejects_another_browsers_canonical_name(self) -> None:
        artifact = self.base / "wins-vpn-companion-chrome.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("background.js", b"const ok=true;")
        with self.assertRaisesRegex(
            privacy.PrivacyError, "exact extension artifact filename"
        ):
            privacy.scan_release_artifacts(
                (artifact,),
                self.inventory(),
                target_id="edge-extension-package",
                require_target=True,
            )

    def test_apple_manifest_rejects_bool_as_int_and_unknown_keys(self) -> None:
        ipa = self.base / "WinsVPN.ipa"
        pkg = self.base / "WinsVPN.pkg"
        ipa.write_bytes(b"test-ipa")
        pkg.write_bytes(b"test-pkg")
        manifest = self.base / "release_candidate.json"
        payload = {
            "artifacts": [
                {
                    "platform": "ios",
                    "path": ipa.name,
                    "size_bytes": True,
                    "sha256": hashlib.sha256(ipa.read_bytes()).hexdigest(),
                },
                {
                    "platform": "macos",
                    "path": pkg.name,
                    "size_bytes": pkg.stat().st_size,
                    "sha256": hashlib.sha256(pkg.read_bytes()).hexdigest(),
                },
            ]
        }
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(privacy.PrivacyError, "bool-as-int"):
            privacy.apple_default_artifacts(manifest, self.base)

        payload["artifacts"][0]["size_bytes"] = ipa.stat().st_size
        payload["schema_version"] = True
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(privacy.PrivacyError, "bool-as-int"):
            privacy.apple_default_artifacts(manifest, self.base)
        del payload["schema_version"]

        payload["artifacts"][0]["size_bytes"] = ipa.stat().st_size
        payload["unexpected"] = {"nested": True}
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(privacy.PrivacyError, "recursively exact"):
            privacy.apple_default_artifacts(manifest, self.base)

        del payload["unexpected"]
        payload["artifacts"][0]["extra_nested"] = {"nope": 1}
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(privacy.PrivacyError, "recursively exact"):
            privacy.apple_default_artifacts(manifest, self.base)

        del payload["artifacts"][0]["extra_nested"]
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        apple = privacy.apple_default_artifacts(manifest, self.base)
        self.assertEqual([path.suffix.lower() for path in apple], [".ipa", ".pkg"])

    def test_unrelated_tempdir_sibling_churn_is_not_substitution(self) -> None:
        artifact = _zip_payload(self.base, b"clean-fixture")
        stop = threading.Event()
        errors: list[BaseException] = []
        cycles = {"n": 0}

        def worker() -> None:
            try:
                while not stop.is_set():
                    _churn_tempdir_siblings(f"p1-{cycles['n']}")
                    cycles["n"] += 1
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        inventory._POST_PARENT_BIND_HOOK = _churn_bound_ancestors
        privacy._POST_PARENT_BIND_HOOK = _churn_bound_ancestors
        try:
            for _ in range(8):
                loaded = self.inventory()
                result = privacy.scan_release_artifacts((artifact,), loaded)
                self.assertTrue(result.passed)
                self.assertEqual(result.matched_labels, ())
        finally:
            inventory._POST_PARENT_BIND_HOOK = None
            privacy._POST_PARENT_BIND_HOOK = None
            stop.set()
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertGreater(cycles["n"], 0)

    def test_parent_path_swap_is_rejected(self) -> None:
        nested = self.base / "nested"
        nested.mkdir()
        other = self.base / "other"
        other.mkdir()
        artifact = _zip_payload(nested, b"clean-fixture")
        _zip_payload(other, b"clean-fixture-other")
        loaded = self.inventory()
        file_index = len(artifact.parts) - 2

        def swap_parent(_path, index):
            if index != file_index:
                return
            os.rename(nested, self.base / "nested-old")
            os.rename(other, nested)

        privacy._POST_PARENT_BIND_HOOK = swap_parent
        try:
            with self.assertRaisesRegex(privacy.PrivacyError, "replaced"):
                privacy.scan_release_artifacts((artifact,), loaded)
        finally:
            privacy._POST_PARENT_BIND_HOOK = None

    def test_parent_swap_restore_is_rejected(self) -> None:
        nested = self.base / "nested"
        nested.mkdir()
        other = self.base / "other"
        other.mkdir()
        artifact = _zip_payload(nested, b"clean-fixture")
        _zip_payload(other, SYNTHETIC_ALPHA.encode("utf-8"))
        loaded = self.inventory()
        nested_old = self.base / "nested-old"
        parent_index = len(artifact.parts) - 3
        file_index = len(artifact.parts) - 2

        def swap_restore(_path, index):
            if index == parent_index:
                os.rename(nested, nested_old)
                os.rename(other, nested)
            elif index == file_index:
                os.rename(nested, other)
                os.rename(nested_old, nested)

        privacy._POST_PARENT_BIND_HOOK = swap_restore
        try:
            with self.assertRaisesRegex(privacy.PrivacyError, "replaced"):
                privacy.scan_release_artifacts((artifact,), loaded)
        finally:
            privacy._POST_PARENT_BIND_HOOK = None

    def test_parent_symlink_replacement_is_rejected(self) -> None:
        nested = self.base / "nested"
        nested.mkdir()
        other = self.base / "other"
        other.mkdir()
        artifact = _zip_payload(nested, b"clean-fixture")
        _zip_payload(other, b"clean-fixture-other")
        loaded = self.inventory()
        file_index = len(artifact.parts) - 2

        def replace_with_symlink(_path, index):
            if index != file_index:
                return
            os.rename(nested, self.base / "nested-old")
            os.symlink(other, nested)

        privacy._POST_PARENT_BIND_HOOK = replace_with_symlink
        try:
            with self.assertRaisesRegex(privacy.PrivacyError, "replaced"):
                privacy.scan_release_artifacts((artifact,), loaded)
        finally:
            privacy._POST_PARENT_BIND_HOOK = None

    def test_external_parent_substitution_is_rejected(self) -> None:
        nested = self.base / "nested"
        nested.mkdir()
        artifact = _zip_payload(nested, b"clean-fixture")
        outside = pathlib.Path(tempfile.mkdtemp(prefix="wins-ext-art-parent-"))
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        _zip_payload(outside, b"clean-fixture-outside")
        loaded = self.inventory()
        file_index = len(artifact.parts) - 2

        def substitute(_path, index):
            if index != file_index:
                return
            os.rename(nested, self.base / "nested-old")
            os.rename(outside, nested)

        privacy._POST_PARENT_BIND_HOOK = substitute
        try:
            with self.assertRaisesRegex(privacy.PrivacyError, "replaced"):
                privacy.scan_release_artifacts((artifact,), loaded)
        finally:
            privacy._POST_PARENT_BIND_HOOK = None

    def test_reproduced_canonical_filename_swaps_are_rejected(self) -> None:
        loaded = self.inventory()
        self.assertEqual(len(REPRODUCED_PRIVACY_TARGET_SWAPS), 4)
        for name, kind, target_id in REPRODUCED_PRIVACY_TARGET_SWAPS:
            with self.subTest(swap=f"{name}->{target_id}"):
                artifact = _named_artifact(self.base / "reproduced", name, kind)
                with self.assertRaisesRegex(
                    privacy.PrivacyError, "exact canonical artifact filename"
                ):
                    privacy.scan_release_artifacts(
                        (artifact,),
                        loaded,
                        target_id=target_id,
                        require_target=True,
                    )

    def test_adjacent_privacy_target_matrix_is_exclusive(self) -> None:
        loaded = self.inventory()
        for name, kind, target_id in ADJACENT_PRIVACY_TARGET_SWAPS:
            with self.subTest(swap=f"{name}->{target_id}"):
                artifact = _named_artifact(self.base / "adjacent", name, kind)
                with self.assertRaisesRegex(
                    privacy.PrivacyError,
                    "exact (?:canonical|extension) artifact filename|artifact type",
                ):
                    privacy.scan_release_artifacts(
                        (artifact,),
                        loaded,
                        target_id=target_id,
                        require_target=True,
                    )

    def test_canonical_filenames_bind_their_own_targets(self) -> None:
        loaded = self.inventory()
        for target_id, name, kind in CANONICAL_PRIVACY_BINDINGS:
            with self.subTest(binding=f"{target_id}:{name}"):
                artifact = _named_artifact(self.base / "bound", name, kind)
                result = privacy.scan_release_artifacts(
                    (artifact,),
                    loaded,
                    target_id=target_id,
                    require_target=True,
                )
                self.assertTrue(result.passed, f"{target_id}:{name}")
                self.assertEqual(result.matched_labels, ())
                self.assertEqual(result.target_id, target_id)

    def test_exact_target_rejects_directory_artifacts(self) -> None:
        directory = self.base / "tree"
        directory.mkdir()
        (directory / "ok.bin").write_bytes(b"clean-fixture")
        with self.assertRaisesRegex(privacy.PrivacyError, "artifact type"):
            privacy.scan_release_artifacts(
                (directory,),
                self.inventory(),
                target_id="android-phone-tablet-apk",
                require_target=True,
            )

    def test_explicit_cli_swapped_artifact_is_rejected(self) -> None:
        artifact = _named_artifact(self.base, "app-tv-release.apk", "zip")
        loaded = self.inventory()
        with mock.patch.object(
            privacy,
            "load_authenticated_secret_inventory",
            return_value=loaded,
        ):
            with self.assertRaisesRegex(
                privacy.PrivacyError, "exact canonical artifact filename"
            ):
                privacy.main(
                    [
                        "--artifacts",
                        "--artifact",
                        str(artifact),
                        "--target",
                        "android-phone-tablet-apk",
                    ]
                )

    def test_unsigned_arm64_installer_name_keeps_architecture(self) -> None:
        source = (ROOT / "installer" / "windows" / "build_installer.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("'WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe'", source)
        self.assertIn("'WinsVPN-UNSIGNED-LOCAL-PartnerCenter-arm64.exe'", source)
        self.assertGreaterEqual(
            source.count(
                "WinsVPN-UNSIGNED-LOCAL-Setup$installerArchitectureSuffix.exe"
            ),
            2,
        )
        self.assertGreaterEqual(
            source.count(
                "WinsVPN-UNSIGNED-LOCAL-PartnerCenter$installerArchitectureSuffix.exe"
            ),
            2,
        )
        unsigned_arm64 = _named_artifact(
            self.base,
            "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe",
            "exe",
        )
        result = privacy.scan_release_artifacts(
            (unsigned_arm64,),
            self.inventory(),
            target_id="windows-arm64-installer",
            require_target=True,
        )
        self.assertTrue(result.passed)


class _NestDepth:
    def __init__(self, depth: int) -> None:
        self.depth = depth
        self.previous = 0

    def __enter__(self) -> None:
        self.previous = privacy.MAX_ARCHIVE_NEST_DEPTH
        privacy.MAX_ARCHIVE_NEST_DEPTH = self.depth
        return None

    def __exit__(self, *args: object) -> None:
        privacy.MAX_ARCHIVE_NEST_DEPTH = self.previous


def mock_nest_depth(depth: int) -> _NestDepth:
    return _NestDepth(depth)


class ReleaseArtifactPrivacyP1LaneModuleTests(unittest.TestCase):
    """Runtime coverage for the lane-owned release_artifact_privacy_p1 module."""

    def setUp(self) -> None:
        import release_artifact_privacy_p1 as p1

        self.p1 = p1
        self._temp = tempfile.TemporaryDirectory(prefix="wins-p1-lane-")
        self.base = pathlib.Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_lane_module_reexports_complete_scanner_surface(self) -> None:
        for name in (
            "PrivacyError",
            "scan_release_artifacts",
            "validate_artifacts",
            "format_inventory_scan_report",
            "apple_default_artifacts",
            "main",
            "REQUIRED_PRIVACY_TARGET_IDS",
            "OPTIONAL_PRIVACY_TARGET_IDS",
            "KNOWN_PRIVACY_TARGET_IDS",
            "DEFAULT_TARGET_RELATIVE_PATHS",
            "TARGET_ARTIFACT_SUFFIXES",
            "TARGET_CANONICAL_FILENAMES",
            "EXTENSION_CROSS_STORE_TARGETS",
            "MAX_ARCHIVE_NEST_DEPTH",
            "_POST_PARENT_BIND_HOOK",
        ):
            self.assertTrue(hasattr(self.p1, name), name)

    def test_lane_module_cross_target_collision_audit_passes(self) -> None:
        self.p1.assert_no_cross_target_collision()

    def test_lane_module_audit_binds_clean_canonical_target(self) -> None:
        for target_id, name, kind in CANONICAL_PRIVACY_BINDINGS:
            with self.subTest(binding=f"{target_id}:{name}"):
                artifact = _named_artifact(self.base / "bound", name, kind)
                verdict = self.p1.audit_canonical_binding(
                    target_id, artifact, exact_target=True
                )
                self.assertTrue(verdict.passed, f"{target_id}:{name}")
                self.assertEqual(verdict.target_id, target_id)

    def test_lane_module_audit_rejects_cross_target_swap(self) -> None:
        for name, kind, target_id in REPRODUCED_PRIVACY_TARGET_SWAPS:
            with self.subTest(swap=f"{name}->{target_id}"):
                artifact = _named_artifact(self.base / "reproduced", name, kind)
                verdict = self.p1.audit_canonical_binding(
                    target_id, artifact, exact_target=True
                )
                self.assertFalse(verdict.passed, f"{name}->{target_id}")
                self.assertIn("exact canonical artifact filename", verdict.reason)

    def test_lane_module_audit_rejects_adjacent_swap(self) -> None:
        for name, kind, target_id in ADJACENT_PRIVACY_TARGET_SWAPS:
            with self.subTest(swap=f"{name}->{target_id}"):
                artifact = _named_artifact(self.base / "adjacent", name, kind)
                verdict = self.p1.audit_canonical_binding(
                    target_id, artifact, exact_target=True
                )
                self.assertFalse(verdict.passed, f"{name}->{target_id}")

    def test_lane_module_audit_requires_exact_target(self) -> None:
        artifact = _zip_payload(self.base, b"clean-fixture")
        verdict = self.p1.audit_canonical_binding("", artifact, exact_target=True)
        self.assertFalse(verdict.passed)
        self.assertIn("exact target", verdict.reason)

    def test_lane_module_audit_empty_target_non_exact_returns_verdict(self) -> None:
        artifact = _zip_payload(self.base, b"clean-fixture")
        verdict = self.p1.audit_canonical_binding("", artifact, exact_target=False)
        self.assertFalse(verdict.passed)
        self.assertIn("exact target", verdict.reason)

    def test_lane_module_audit_unknown_target_returns_verdict(self) -> None:
        artifact = _zip_payload(self.base, b"clean-fixture")
        verdict = self.p1.audit_canonical_binding(
            "not-a-real-target", artifact, exact_target=True
        )
        self.assertFalse(verdict.passed)
        self.assertIn("known release target", verdict.reason)

    def test_lane_module_audit_rejects_canonical_name_with_wrong_container(self) -> None:
        wrong = self.base / "WinsVPN-Setup.exe"
        with zipfile.ZipFile(wrong, "w") as archive:
            archive.writestr("client.bin", b"not an executable container")
        verdict = self.p1.audit_canonical_binding(
            "windows-x64-installer", wrong, exact_target=True
        )
        self.assertFalse(verdict.passed)
        self.assertIn("artifact type", verdict.reason)
        real = _named_artifact(self.base / "bound", "WinsVPN-Setup.exe", "exe")
        bound = self.p1.audit_canonical_binding(
            "windows-x64-installer", real, exact_target=True
        )
        self.assertTrue(bound.passed)

    def test_lane_module_audit_missing_artifact_is_fail_closed(self) -> None:
        missing = self.base / "app-release.apk"
        self.assertFalse(missing.exists())
        verdict = self.p1.audit_canonical_binding(
            "android-phone-tablet-apk", missing, exact_target=True
        )
        self.assertFalse(verdict.passed)
        self.assertIn("does not exist", verdict.reason)

    def test_lane_module_audit_symlink_artifact_is_fail_closed(self) -> None:
        real = _zip_payload(self.base, b"clean-fixture")
        link = self.base / "winsvpn.ipa"
        try:
            link.symlink_to(real)
        except OSError:
            self.skipTest("symlinks unavailable on this filesystem")
        verdict = self.p1.audit_canonical_binding(
            "ios-app-store-ipa", link, exact_target=True
        )
        self.assertFalse(verdict.passed)
        self.assertIn("regular non-symlink", verdict.reason)

    def test_lane_module_audit_hardlink_artifact_is_fail_closed(self) -> None:
        artifact = _named_artifact(
            self.base / "hardlink", "WinsVPN-Setup.exe", "exe"
        )
        os.link(artifact, self.base / "hardlink" / "alias.exe")
        verdict = self.p1.audit_canonical_binding(
            "windows-x64-installer", artifact, exact_target=True
        )
        self.assertFalse(verdict.passed)
        self.assertIn("link count 1", verdict.reason)

    def test_lane_module_rejects_replacement_after_snapshot(self) -> None:
        artifact = _named_artifact(
            self.base / "live", "WinsVPN-Setup.exe", "exe"
        )
        replacement = _named_artifact(
            self.base / "replacement", "alternate.exe", "exe"
        )
        original = self.base / "original.exe"
        real_assert = self.p1._assert_target_artifact_type

        def replace_after_type(*args, **kwargs):
            real_assert(*args, **kwargs)
            os.replace(artifact, original)
            os.replace(replacement, artifact)

        with mock.patch.object(
            self.p1,
            "_assert_target_artifact_type",
            side_effect=replace_after_type,
        ):
            verdict = self.p1.audit_canonical_binding(
                "windows-x64-installer", artifact, exact_target=True
            )
        self.assertFalse(verdict.passed)
        self.assertIn("replaced after", verdict.reason)

    def test_lane_module_rejects_ancestor_replacement_after_snapshot(self) -> None:
        live_parent = self.base / "live-parent"
        other_parent = self.base / "other-parent"
        artifact = _named_artifact(live_parent, "WinsVPN-Setup.exe", "exe")
        _named_artifact(other_parent, "WinsVPN-Setup.exe", "exe")
        old_parent = self.base / "old-parent"
        real_assert = self.p1._assert_target_artifact_type

        def replace_parent_after_type(*args, **kwargs):
            real_assert(*args, **kwargs)
            os.replace(live_parent, old_parent)
            os.replace(other_parent, live_parent)

        with mock.patch.object(
            self.p1,
            "_assert_target_artifact_type",
            side_effect=replace_parent_after_type,
        ):
            verdict = self.p1.audit_canonical_binding(
                "windows-x64-installer", artifact, exact_target=True
            )
        self.assertFalse(verdict.passed)
        self.assertIn("replaced after", verdict.reason)

    def test_lane_module_reexport_scan_rejects_utf32_secret(self) -> None:
        secret = SYNTHETIC_ALPHA.encode("utf-32-le")
        artifact = _zip_payload(self.base, secret, "utf32.bin")
        with self.assertRaisesRegex(self.p1.PrivacyError, "SYNTHETIC_ALPHA"):
            self.p1.validate_artifacts(
                (artifact,), {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA}
            )


class DeferredSecretScanCommandTests(unittest.TestCase):
    """validate_release_artifact_privacy.py --defer-secret-scan-to-release-host."""

    ARGUMENTS = [
        "--artifacts",
        "--target", "windows-x64-installer",
        "--artifact", "build/windows-installer/WinsVPN-UNSIGNED-LOCAL-Setup.exe",
        "--defer-secret-scan-to-release-host", "REMOTE_INPUT.json",
    ]

    def _run(self, arguments: list[str], *, authorized: bool = True) -> tuple[int, str]:
        import contextlib

        def forbidden(*_args, **_kwargs):
            raise AssertionError("a deferred scan must not load the inventory")

        output = io.StringIO()
        replacement = (
            mock.Mock(return_value=None)
            if authorized
            else mock.Mock(side_effect=privacy.ObfuscationError("not a Windows build host"))
        )
        with mock.patch.object(privacy, "require_secret_scan_deferral", replacement), \
                mock.patch.object(privacy, "load_authenticated_secret_inventory", side_effect=forbidden), \
                contextlib.redirect_stdout(output):
            code = privacy.main(arguments)
        return code, output.getvalue()

    def test_defers_one_named_installer_scan_without_loading_the_inventory(self) -> None:
        code, text = self._run(self.ARGUMENTS)
        self.assertEqual(code, 0)
        self.assertIn("DEFERRED TO THE RELEASE HOST", text)
        self.assertNotIn("RELEASE ARTIFACT PRIVACY: PASS", text)

    def test_refuses_anything_wider_than_one_named_installer_scan(self) -> None:
        for label, arguments in {
            "no target": [a for a in self.ARGUMENTS if a not in ("--target", "windows-x64-installer")],
            "other platform name": ["--artifacts", "--target", "windows-x64-installer",
                                    "--artifact", "wins-vpn-linux-x64.tar.gz",
                                    "--defer-secret-scan-to-release-host", "REMOTE_INPUT.json"],
            "wrong architecture name": ["--artifacts", "--target", "windows-x64-installer",
                                        "--artifact", "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe",
                                        "--defer-secret-scan-to-release-host", "REMOTE_INPUT.json"],
            "two artifacts": self.ARGUMENTS + ["--artifact", "other.exe"],
            "stdin secrets": self.ARGUMENTS + ["--secrets-stdin"],
            "env secrets": self.ARGUMENTS + ["--secret-env", "X"],
            "authenticated inventory": self.ARGUMENTS + ["--authenticated-inventory"],
            "no scan": ["--target", "windows-x64-installer",
                        "--defer-secret-scan-to-release-host", "REMOTE_INPUT.json"],
        }.items():
            with self.subTest(label=label), self.assertRaises((privacy.PrivacyError, SystemExit)):
                self._run(arguments)

    def test_only_the_four_windows_installer_targets_can_defer(self) -> None:
        # The authorization is a valid Windows input record (mocked as granted), so the
        # only thing left to refuse a non-Windows scan is the target itself.
        windows = {
            "windows-x64-installer",
            "windows-x64-partner-center",
            "windows-arm64-installer",
            "windows-arm64-partner-center",
        }
        self.assertEqual(
            {target for target in privacy.TARGET_CANONICAL_FILENAMES if target.startswith("windows-")},
            windows,
        )
        for target, names in sorted(privacy.TARGET_CANONICAL_FILENAMES.items()):
            for name in sorted(names):
                arguments = [
                    "--artifacts", "--target", target,
                    "--artifact", f"build/{name}",
                    "--defer-secret-scan-to-release-host", "REMOTE_INPUT.json",
                ]
                with self.subTest(target=target, artifact=name):
                    if target in windows:
                        code, text = self._run(arguments)
                        self.assertEqual(code, 0)
                        self.assertIn("DEFERRED TO THE RELEASE HOST", text)
                    else:
                        with self.assertRaisesRegex(privacy.PrivacyError, "Windows installer"):
                            self._run(arguments)

    def test_refuses_when_the_host_may_not_defer(self) -> None:
        with self.assertRaisesRegex(privacy.PrivacyError, "not a Windows build host"):
            self._run(self.ARGUMENTS, authorized=False)

    def test_real_authorization_refuses_a_posix_host(self) -> None:
        with mock.patch.object(privacy.os, "name", "posix"):
            with self.assertRaises(privacy.ObfuscationError):
                privacy.require_secret_scan_deferral(pathlib.Path("REMOTE_INPUT.json"))


if __name__ == "__main__":
    unittest.main()
