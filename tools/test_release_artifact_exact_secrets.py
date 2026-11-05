#!/usr/bin/env python3
"""Exact known-server-secret matching, encodings, archives, and redaction."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.parse
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import release_secret_inventory as inventory
import validate_release_artifact_privacy as privacy


SYNTHETIC_ALPHA = "synthetic-inventory-secret-alpha-0001"
SYNTHETIC_BETA = "synthetic-inventory-secret-beta-0002"
SYNTHETIC_SHARED = "synthetic-inventory-secret-shared-0003"
SYNTHETIC_ENCODED = "synthetic/+exact-secret=value 0001???"
SYNTHETIC_MULTILINE = (
    "synthetic-multiline-secret-line1\nsynthetic-multiline-secret-line2"
)
SYNTHETIC_LONG = "synthetic-wrapped-base64-secret-value-" + ("W" * 80)
SYNTHETIC_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "SYNTHETICONLYNOTAREALPRIVATEKEYMATERIALFORTESTSXX\n"
    "-----END PRIVATE KEY-----\n"
)
SCANNER = ROOT / "tools" / "validate_release_artifact_privacy.py"


def _unicode_escape(text: str, *, uppercase: bool = False) -> bytes:
    spec = "04X" if uppercase else "04x"
    return "".join("\\u" + format(ord(character), spec) for character in text).encode(
        "ascii"
    )


def _mixed_percent_hex(encoded: str) -> str:
    chars: list[str] = []
    index = 0
    upper = True
    while index < len(encoded):
        if encoded[index] == "%" and index + 2 < len(encoded):
            first = encoded[index + 1]
            second = encoded[index + 2]
            if upper:
                chars.append("%" + first.upper() + second.lower())
            else:
                chars.append("%" + first.lower() + second.upper())
            upper = not upper
            index += 3
            continue
        chars.append(encoded[index])
        index += 1
    return "".join(chars)


def _wrap_base64(encoded: bytes, width: int = 64, newline: bytes = b"\n") -> bytes:
    parts = [encoded[index : index + width] for index in range(0, len(encoded), width)]
    return newline.join(parts)


def _lower_percent_hex(encoded: str) -> str:
    chars: list[str] = []
    index = 0
    while index < len(encoded):
        if encoded[index] == "%" and index + 2 < len(encoded):
            chars.append("%" + encoded[index + 1 : index + 3].lower())
            index += 3
            continue
        chars.append(encoded[index])
        index += 1
    return "".join(chars)


def _write_inventory(
    path: pathlib.Path,
    *,
    revision: str = "rev-scan-1",
    secrets: dict[str, str] | None = None,
    mode: int = 0o600,
) -> pathlib.Path:
    payload = {
        "schema_version": 1,
        "revision": revision,
        "secrets": secrets or {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA},
    }
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    path.chmod(mode)
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


def _assert_undisclosed(test: unittest.TestCase, text: str, *values: str) -> None:
    for value in values:
        test.assertNotIn(value, text)
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        test.assertNotIn(digest, text)
        raw = value.encode("utf-8")
        test.assertNotIn(base64.b64encode(raw).decode("ascii"), text)
        test.assertNotIn(base64.urlsafe_b64encode(raw).decode("ascii"), text)


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


class ReleaseArtifactExactSecretTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="wins-exact-secrets-")
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

    def inventory(self, secrets: dict[str, str] | None = None) -> inventory.SecretInventory:
        path = _write_inventory(self.base / "inventory.json", secrets=secrets)
        return inventory.load_secret_inventory(path, repository_root=ROOT)

    def synthetic_scanner_inventory(
        self, secrets: dict[str, str] | None = None
    ) -> inventory.SecretInventory:
        return self.inventory(secrets)

    def test_generic_leak_scanning_is_preserved_without_inventory(self) -> None:
        artifact = _zip_payload(
            self.base,
            b"const routingKey = 'AIza" + (b"A" * 35) + b"';\n",
        )
        with self.assertRaisesRegex(privacy.PrivacyError, "google_api_key"):
            privacy.validate_artifacts((artifact,), {})

    def test_only_exact_named_upstream_wintun_binaries_may_keep_vendor_debug_metadata(self) -> None:
        dependencies = ROOT / "installer" / "windows" / "dependencies"
        for source_name in ("wintun.dll", "wintun-arm64.dll"):
            data = (dependencies / source_name).read_bytes()
            self.assertTrue(
                privacy.is_approved_vendor_debug_metadata(
                    "payload/wintun.dll", data
                )
            )
            privacy._inspect_member("payload/wintun.dll", data, {}, {}, set())

            self.assertFalse(
                privacy.is_approved_vendor_debug_metadata(
                    "payload/not-wintun.dll", data
                )
            )
            with self.assertRaisesRegex(privacy.PrivacyError, "local user-home path"):
                privacy._inspect_member(
                    "payload/not-wintun.dll", data, {}, {}, set()
                )

            mutated = bytearray(data)
            mutated[-1] ^= 1
            self.assertFalse(
                privacy.is_approved_vendor_debug_metadata(
                    "payload/wintun.dll", bytes(mutated)
                )
            )
            with self.assertRaisesRegex(privacy.PrivacyError, "local user-home path"):
                privacy._inspect_member(
                    "payload/wintun.dll", bytes(mutated), {}, {}, set()
                )

    def test_clean_artifact_passes_inventory_scan(self) -> None:
        artifact = _zip_payload(self.base, b"https://sync.app-cloud-sync.net/nodes")
        loaded = self.inventory()
        result = privacy.scan_release_artifacts(
            (artifact,), loaded, target_id="chrome-extension-package"
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.matched_labels, ())
        self.assertEqual(result.revision, "rev-scan-1")
        self.assertEqual(result.labels, ("SYNTHETIC_ALPHA",))
        self.assertEqual(result.target_id, "chrome-extension-package")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        self.assertEqual(result.artifact_identity, digest)
        self.assertNotIn(str(artifact), result.artifact_identity)
        self.assertNotIn(str(artifact.resolve()), result.artifact_identity)
        report = privacy.format_inventory_scan_report(result)
        _assert_undisclosed(self, report, SYNTHETIC_ALPHA)
        self.assertIn("RELEASE ARTIFACT PRIVACY: PASS", report)
        self.assertNotIn(str(artifact), report)

    def test_javascript_array_join_cannot_reconstruct_inventory_secret(self) -> None:
        # An inventory value with no reusable-secret shape is matched by label
        # in the joined view.
        secret = "SyntheticJoinedInventoryValue" + ("Q" * 12)
        loaded = self.synthetic_scanner_inventory({"SYNTHETIC_JOINED_VALUE": secret})
        artifact = _zip_payload(
            self.base,
            (
                "const key=['"
                + secret[:19]
                + "','"
                + secret[19:]
                + "'].join('');\n"
            ).encode("ascii"),
            "probe.js",
        )
        result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_JOINED_VALUE",))
        _assert_undisclosed(self, privacy.format_inventory_scan_report(result), secret)
        # A Google-key-shaped value joined the same way is refused outright by
        # the reusable-secret scan, as the contiguous key is (R23 W1-03).
        google = "AIza" + ("Q" * 35)
        loaded = self.synthetic_scanner_inventory({"SYNTHETIC_GOOGLE_KEY": google})
        artifact = _zip_payload(
            self.base,
            (
                "const key=['"
                + google[:19]
                + "','"
                + google[19:]
                + "'].join('');\n"
            ).encode("ascii"),
            "probe-google.js",
        )
        with self.assertRaisesRegex(
            privacy.PrivacyError, "reusable secret category google_api_key"
        ) as refused:
            privacy.scan_release_artifacts((artifact,), loaded)
        _assert_undisclosed(self, str(refused.exception), google)

    def test_all_encodings_are_matched_and_redacted(self) -> None:
        loaded = self.inventory({"SYNTHETIC_ENCODED": SYNTHETIC_ENCODED})
        raw = SYNTHETIC_ENCODED.encode("utf-8")
        encodings = {
            "utf-8": raw,
            "utf-16-le": SYNTHETIC_ENCODED.encode("utf-16-le"),
            "utf-16-be": SYNTHETIC_ENCODED.encode("utf-16-be"),
            "utf-16-le-bom": b"\xff\xfe" + SYNTHETIC_ENCODED.encode("utf-16-le"),
            "utf-16-be-bom": b"\xfe\xff" + SYNTHETIC_ENCODED.encode("utf-16-be"),
            "b64": base64.b64encode(raw),
            "b64-unpadded": base64.b64encode(raw).rstrip(b"="),
            "b64url": base64.urlsafe_b64encode(raw),
            "b64url-unpadded": base64.urlsafe_b64encode(raw).rstrip(b"="),
            "percent": urllib.parse.quote(SYNTHETIC_ENCODED, safe="").encode("ascii"),
            "percent-slash-safe": urllib.parse.quote(
                SYNTHETIC_ENCODED, safe="/"
            ).encode("ascii"),
            "percent-plus": urllib.parse.quote_plus(SYNTHETIC_ENCODED).encode("ascii"),
            "percent-lower": _lower_percent_hex(
                urllib.parse.quote(SYNTHETIC_ENCODED, safe="")
            ).encode("ascii"),
            "percent-mixed": _mixed_percent_hex(
                urllib.parse.quote(SYNTHETIC_ENCODED, safe="")
            ).encode("ascii"),
            "hex-lower": SYNTHETIC_ENCODED.encode("utf-8").hex().encode("ascii"),
            "hex-upper": SYNTHETIC_ENCODED.encode("utf-8").hex().upper().encode("ascii"),
            "json": json.dumps(SYNTHETIC_ENCODED, ensure_ascii=True).encode("utf-8"),
            "json-inner": json.dumps(SYNTHETIC_ENCODED, ensure_ascii=True)[1:-1].encode(
                "utf-8"
            ),
            "unicode-lower": _unicode_escape(SYNTHETIC_ENCODED),
            "unicode-upper": _unicode_escape(SYNTHETIC_ENCODED, uppercase=True),
        }
        self.assertNotEqual(encodings["b64"], encodings["b64url"])
        self.assertNotEqual(encodings["percent"], encodings["percent-plus"])
        self.assertNotEqual(encodings["percent"], encodings["percent-mixed"])
        self.assertNotEqual(encodings["percent-lower"], encodings["percent-mixed"])
        for name, payload in encodings.items():
            with self.subTest(encoding=name):
                artifact = _zip_payload(self.base, payload, f"{name}.bin")
                result = privacy.scan_release_artifacts((artifact,), loaded)
                self.assertFalse(result.passed, name)
                self.assertEqual(result.matched_labels, ("SYNTHETIC_ENCODED",))
                report = privacy.format_inventory_scan_report(result)
                _assert_undisclosed(self, report, SYNTHETIC_ENCODED)
                with self.assertRaises(privacy.PrivacyError) as raised:
                    privacy.validate_artifacts(
                        (artifact,), {"SYNTHETIC_ENCODED": SYNTHETIC_ENCODED}
                    )
                _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ENCODED)

    def test_escaped_multiline_and_synthetic_private_key_forms(self) -> None:
        loaded = self.inventory(
            {
                "SYNTHETIC_MULTILINE": SYNTHETIC_MULTILINE,
                "SYNTHETIC_PEM": SYNTHETIC_PEM,
            }
        )
        escaped_multiline = SYNTHETIC_MULTILINE.replace("\n", "\\n").encode("utf-8")
        crlf_multiline = SYNTHETIC_MULTILINE.replace("\n", "\r\n").encode("utf-8")
        escaped_pem = SYNTHETIC_PEM.replace("\n", "\\n").encode("utf-8")
        unicode_pem = _unicode_escape(SYNTHETIC_PEM)
        cases = (
            ("escaped-multiline", escaped_multiline, "SYNTHETIC_MULTILINE"),
            ("crlf-multiline", crlf_multiline, "SYNTHETIC_MULTILINE"),
            ("unicode-pem", unicode_pem, "SYNTHETIC_PEM"),
        )
        for name, payload, label in cases:
            with self.subTest(name=name):
                artifact = _zip_payload(self.base, payload, f"{name}.bin")
                result = privacy.scan_release_artifacts((artifact,), loaded)
                self.assertFalse(result.passed, name)
                self.assertIn(label, result.matched_labels)
                report = privacy.format_inventory_scan_report(result)
                _assert_undisclosed(self, report, SYNTHETIC_MULTILINE, SYNTHETIC_PEM)
        raw_pem = _zip_payload(self.base, SYNTHETIC_PEM.encode("utf-8"), "raw.pem")
        with self.assertRaisesRegex(privacy.PrivacyError, "private_key_material"):
            privacy.validate_artifacts((raw_pem,), {})
        escaped_artifact = _zip_payload(self.base, escaped_pem, "escaped.pem")
        with self.assertRaisesRegex(privacy.PrivacyError, "private_key_material"):
            privacy.validate_artifacts((escaped_artifact,), {})

    def test_archive_member_names_are_matched_and_redacted(self) -> None:
        loaded = self.inventory()
        zip_path = self.base / "named.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr(SYNTHETIC_ALPHA + ".txt", b"clean-fixture")
        zip_result = privacy.scan_release_artifacts((zip_path,), loaded)
        self.assertFalse(zip_result.passed)
        self.assertEqual(zip_result.matched_labels, ("SYNTHETIC_ALPHA",))
        report = privacy.format_inventory_scan_report(zip_result)
        _assert_undisclosed(self, report, SYNTHETIC_ALPHA)

        encoded_name = base64.b64encode(SYNTHETIC_ALPHA.encode("utf-8")).decode("ascii")
        b64_zip = self.base / "named-b64.zip"
        with zipfile.ZipFile(b64_zip, "w") as archive:
            archive.writestr(encoded_name, b"clean-fixture")
        b64_result = privacy.scan_release_artifacts((b64_zip,), loaded)
        self.assertFalse(b64_result.passed)
        self.assertEqual(b64_result.matched_labels, ("SYNTHETIC_ALPHA",))
        _assert_undisclosed(
            self, privacy.format_inventory_scan_report(b64_result), SYNTHETIC_ALPHA
        )

        tar_path = self.base / "named.tar.gz"
        payload = b"clean-fixture"
        info = tarfile.TarInfo(SYNTHETIC_ALPHA)
        info.size = len(payload)
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.addfile(info, io.BytesIO(payload))
        tar_result = privacy.scan_release_artifacts((tar_path,), loaded)
        self.assertFalse(tar_result.passed)
        self.assertEqual(tar_result.matched_labels, ("SYNTHETIC_ALPHA",))
        _assert_undisclosed(
            self, privacy.format_inventory_scan_report(tar_result), SYNTHETIC_ALPHA
        )

        unsafe = self.base / "unsafe-name.zip"
        with zipfile.ZipFile(unsafe, "w") as archive:
            archive.writestr("../" + SYNTHETIC_ALPHA, b"clean-fixture")
        with self.assertRaises(privacy.PrivacyError) as raised:
            privacy.validate_artifacts((unsafe,), {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA})
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)
        self.assertNotIn(SYNTHETIC_ALPHA, str(raised.exception))
        self.assertNotIn("../", str(raised.exception))

    def test_duplicate_values_report_every_matching_label(self) -> None:
        loaded = self.inventory(
            {
                "SYNTHETIC_ALPHA": SYNTHETIC_SHARED,
                "SYNTHETIC_BETA": SYNTHETIC_SHARED,
            }
        )
        artifact = _zip_payload(self.base, SYNTHETIC_SHARED.encode("utf-8"))
        result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA", "SYNTHETIC_BETA"))
        self.assertEqual(result.unique_value_count, 1)
        self.assertEqual(result.label_count, 2)
        _assert_undisclosed(
            self, privacy.format_inventory_scan_report(result), SYNTHETIC_SHARED
        )

    def test_cli_inventory_scan_redacts_output_and_logs(self) -> None:
        artifact = _zip_payload(self.base, SYNTHETIC_ALPHA.encode("utf-8"))
        inventory_path = _write_inventory(self.base / "cli-inventory.json")
        for mode in ("--authenticated-inventory", "--artifacts"):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-S",
                        str(SCANNER),
                        mode,
                        "--artifact",
                        str(artifact),
                        "--target",
                        "chrome-extension-package",
                    ],
                    cwd=str(ROOT),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env={
                        "HOME": str(self.base),
                        "TMPDIR": str(self.base),
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONNOUSERSITE": "1",
                    },
                )
                output = completed.stdout + completed.stderr
                self.assertEqual(completed.returncode, 1, output)
                self.assertIn(
                    "secret inventory is not configured: set "
                    "WINS_RELEASE_SECRET_INVENTORY",
                    output,
                )
                _assert_undisclosed(self, output, SYNTHETIC_ALPHA)
                self.assertNotIn(str(inventory_path), completed.stdout)
                self.assertNotIn(str(artifact), output)
                self.assertNotIn(str(artifact.resolve()), output)

    def test_cli_environment_inventory_scans_exact_release_artifact(self) -> None:
        inventory_path = _write_inventory(self.base / "env-inventory.json")
        leak_dir = self.base / "leak"
        clean_dir = self.base / "clean"
        leak_dir.mkdir()
        clean_dir.mkdir()
        name = "wins-vpn-companion-chrome.zip"
        leaked = leak_dir / name
        with zipfile.ZipFile(leaked, "w") as archive:
            archive.writestr("client.bin", b"x" + SYNTHETIC_ALPHA.encode("utf-8") + b"y")
        clean = clean_dir / name
        with zipfile.ZipFile(clean, "w") as archive:
            archive.writestr("client.bin", b"clean-fixture")
        for mode in ("--authenticated-inventory", "--artifacts"):
            for artifact, expected_code, verdict in (
                (leaked, 1, "RELEASE ARTIFACT PRIVACY: FAIL"),
                (clean, 0, "RELEASE ARTIFACT PRIVACY: PASS"),
            ):
                with self.subTest(mode=mode, artifact=artifact.parent.name):
                    completed = subprocess.run(
                        [
                            sys.executable,
                            "-S",
                            str(SCANNER),
                            mode,
                            "--artifact",
                            str(artifact),
                            "--target",
                            "chrome-extension-package",
                        ],
                        cwd=str(ROOT),
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        env={
                            "HOME": str(self.base),
                            "TMPDIR": str(self.base),
                            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                            "PYTHONDONTWRITEBYTECODE": "1",
                            "PYTHONNOUSERSITE": "1",
                            "WINS_RELEASE_SECRET_INVENTORY": str(inventory_path),
                        },
                    )
                    output = completed.stdout + completed.stderr
                    self.assertEqual(completed.returncode, expected_code, output)
                    self.assertIn(verdict, output)
                    expected_labels = (
                        "SYNTHETIC_ALPHA" if expected_code else ""
                    )
                    self.assertIn("matched_labels=" + expected_labels + "\n", output)
                    _assert_undisclosed(self, output, SYNTHETIC_ALPHA)
                    self.assertNotIn(str(inventory_path), output)
                    # The report names the authenticated inventory file it loaded by the
                    # digest of that file, so a receipt can bind which inventory scanned.
                    self.assertIn(
                        "inventory_sha256="
                        + hashlib.sha256(inventory_path.read_bytes()).hexdigest()
                        + "\n",
                        output,
                    )

    def test_cli_rejects_arbitrary_secret_inventory_path(self) -> None:
        artifact = _zip_payload(self.base, b"clean-fixture")
        inventory_path = _write_inventory(self.base / "candidate-inventory.json")
        completed = subprocess.run(
            [
                sys.executable,
                "-S",
                str(SCANNER),
                "--artifact",
                str(artifact),
                "--secret-inventory",
                str(inventory_path),
            ],
            cwd=str(ROOT),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                "HOME": str(self.base),
                "TMPDIR": str(self.base),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            },
        )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 2, output)
        self.assertIn("unrecognized arguments: --secret-inventory", output)
        _assert_undisclosed(self, output, SYNTHETIC_ALPHA)

    def test_encoded_form_expansion_is_bounded(self) -> None:
        forms = privacy.encoded_forms(SYNTHETIC_ENCODED.encode("utf-8"))
        self.assertLessEqual(len(forms), privacy.MAX_ENCODED_SECRET_FORMS)
        self.assertGreaterEqual(len(forms), 8)
        self.assertEqual(len(forms), len(set(forms)))
        raw = SYNTHETIC_ENCODED.encode("utf-8")
        self.assertIn(raw.hex().encode("ascii"), forms)
        self.assertIn(raw.hex().upper().encode("ascii"), forms)
        mime = base64.encodebytes(raw)
        self.assertIn(mime, forms)

    def test_wrapped_base64_is_matched_without_truncation(self) -> None:
        loaded = self.inventory({"SYNTHETIC_LONG": SYNTHETIC_LONG})
        raw = SYNTHETIC_LONG.encode("utf-8")
        encoded = base64.b64encode(raw)
        wrapped = _wrap_base64(encoded, 64, b"\n")
        self.assertIn(b"\n", wrapped)
        forms = privacy.encoded_forms(raw)
        self.assertIn(wrapped, forms)
        self.assertLessEqual(len(forms), privacy.MAX_ENCODED_SECRET_FORMS)
        artifact = _zip_payload(self.base, wrapped)
        result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_LONG",))
        _assert_undisclosed(
            self, privacy.format_inventory_scan_report(result), SYNTHETIC_LONG
        )

    def test_tar_utf16_payload_is_matched(self) -> None:
        loaded = self.inventory()
        artifact = _tar_payload(
            self.base, SYNTHETIC_ALPHA.encode("utf-16-le"), "client.bin"
        )
        result = privacy.scan_release_artifacts(
            (artifact,), loaded, target_id="linux-x64-package"
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

    def test_target_is_bound_to_artifact_type(self) -> None:
        loaded = self.inventory()
        zip_artifact = _zip_payload(self.base, b"clean-fixture")
        with self.assertRaisesRegex(privacy.PrivacyError, "artifact type"):
            privacy.scan_release_artifacts(
                (zip_artifact,), loaded, target_id="linux-x64-package"
            )
        tar_artifact = _tar_payload(self.base, b"clean-fixture")
        result = privacy.scan_release_artifacts(
            (tar_artifact,), loaded, target_id="linux-x64-package"
        )
        self.assertTrue(result.passed)

    def test_swap_restore_cannot_replace_authenticated_snapshot(self) -> None:
        secret_zip = io.BytesIO()
        with zipfile.ZipFile(secret_zip, "w") as archive:
            archive.writestr("client.bin", SYNTHETIC_ALPHA.encode("utf-8"))
        clean_zip = io.BytesIO()
        with zipfile.ZipFile(clean_zip, "w") as archive:
            archive.writestr("client.bin", b"clean-fixture")
        secret_bytes = secret_zip.getvalue()
        clean_bytes = clean_zip.getvalue()
        artifact = self.base / "artifact.zip"
        artifact.write_bytes(secret_bytes)
        artifact_abs = os.path.abspath(artifact)
        opens = {"count": 0}
        zip_files: list[object] = []
        real_os_open = os.open
        real_zipfile = privacy.zipfile.ZipFile

        def _is_artifact(path_obj: object) -> bool:
            try:
                return os.path.abspath(os.fspath(path_obj)) == artifact_abs
            except TypeError:
                return False

        def _replace(data: bytes) -> None:
            fd = real_os_open(artifact_abs, os.O_WRONLY | os.O_TRUNC)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)

        def swapping_os_open(path, flags, *args, **kwargs):
            if _is_artifact(path):
                opens["count"] += 1
                if opens["count"] >= 2:
                    _replace(clean_bytes)
                    try:
                        return real_os_open(path, flags, *args, **kwargs)
                    finally:
                        _replace(secret_bytes)
            return real_os_open(path, flags, *args, **kwargs)

        class TrackingZipFile(real_zipfile):
            def __init__(self, file, *args, **kwargs):
                zip_files.append(file)
                super().__init__(file, *args, **kwargs)

        loaded = self.inventory()
        with mock.patch.object(privacy.os, "open", swapping_os_open):
            with mock.patch.object(privacy.zipfile, "ZipFile", TrackingZipFile):
                result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertEqual(opens["count"], 1)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
        self.assertTrue(zip_files)
        for handle in zip_files:
            self.assertFalse(_is_artifact(handle))
        self.assertEqual(artifact.read_bytes(), secret_bytes)

    def test_unrelated_tempdir_sibling_churn_is_not_substitution(self) -> None:
        artifact = _zip_payload(self.base, b"https://sync.app-cloud-sync.net/nodes")
        stop = threading.Event()
        errors: list[BaseException] = []
        cycles = {"n": 0}

        def worker() -> None:
            try:
                while not stop.is_set():
                    _churn_tempdir_siblings(f"exact-{cycles['n']}")
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
                result = privacy.scan_release_artifacts(
                    (artifact,), loaded, target_id="chrome-extension-package"
                )
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

    def test_diagnostics_redact_member_names_and_local_paths(self) -> None:
        loaded = self.inventory()
        member = "Users/release-builder/Downloads/" + SYNTHETIC_ALPHA + ".txt"
        artifact = self.base / "named-local.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(member, b"clean-fixture")
        result = privacy.scan_release_artifacts((artifact,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))
        report = privacy.format_inventory_scan_report(result)
        _assert_undisclosed(self, report, SYNTHETIC_ALPHA)
        self.assertNotIn("/Users/", report)
        self.assertNotIn("release-builder", report)
        self.assertNotIn(str(artifact), report)
        self.assertNotIn(str(artifact.resolve()), report)
        with self.assertRaises(privacy.PrivacyError) as raised:
            privacy.validate_artifacts(
                (artifact,), {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA}
            )
        message = str(raised.exception)
        _assert_undisclosed(self, message, SYNTHETIC_ALPHA)
        self.assertNotIn(str(artifact), message)
        self.assertNotIn(member, message)

    def test_archive_bounds_reject_before_allocation(self) -> None:
        loaded = self.inventory()
        deep = "/".join(["d"] * (privacy.MAX_ARCHIVE_PATH_DEPTH + 1)) + "/client.bin"
        deep_zip = self.base / "deep.zip"
        with zipfile.ZipFile(deep_zip, "w") as archive:
            archive.writestr(deep, b"clean-fixture")
        with self.assertRaisesRegex(privacy.PrivacyError, "depth"):
            privacy.scan_release_artifacts((deep_zip,), loaded)

        many = self.base / "many.zip"
        with zipfile.ZipFile(many, "w") as archive:
            archive.writestr("one.bin", b"clean-fixture-one")
            archive.writestr("two.bin", b"clean-fixture-two")
        with mock.patch.object(privacy, "MAX_ARCHIVE_MEMBER_COUNT", 1):
            with self.assertRaisesRegex(privacy.PrivacyError, "member-count"):
                privacy.scan_release_artifacts((many,), loaded)

        oversized_member = self.base / "member.zip"
        with zipfile.ZipFile(oversized_member, "w") as archive:
            archive.writestr("client.bin", b"0123456789abcdef")
        with mock.patch.object(privacy, "MAX_ARCHIVE_MEMBER_EXPANDED_BYTES", 4):
            with self.assertRaisesRegex(privacy.PrivacyError, "expanded-size"):
                privacy.scan_release_artifacts((oversized_member,), loaded)

        zeros = self.base / "ratio.zip"
        with zipfile.ZipFile(zeros, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("zeros.bin", b"\x00" * 4096)
        with mock.patch.object(privacy, "MAX_ARCHIVE_COMPRESSION_RATIO", 2):
            with self.assertRaisesRegex(privacy.PrivacyError, "compression-ratio"):
                privacy.scan_release_artifacts((zeros,), loaded)

        outer = self.base / "outer.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("client.bin", b"clean-fixture")
        with mock.patch.object(privacy, "MAX_ARCHIVE_INPUT_BYTES", 8):
            with self.assertRaisesRegex(privacy.PrivacyError, "outside the accepted bound"):
                privacy.scan_release_artifacts((outer,), loaded)


    def test_unauthenticated_inventory_is_not_release_coverage(self) -> None:
        loaded = self.inventory()
        self.assertFalse(loaded.authenticated)
        with self.assertRaisesRegex(inventory.InventoryError, "not release coverage"):
            list(inventory.release_secret_values(loaded))
        with self.assertRaisesRegex(
            inventory.InventoryError, "requires load_authenticated_secret_inventory"
        ):
            inventory.load_secret_inventory(
                self.base / "inventory.json",
                repository_root=ROOT,
                require_authenticated=True,
            )

    def test_test_scoped_synthetic_inventory_matches_and_redacts_leak(self) -> None:
        loaded = self.synthetic_scanner_inventory()
        self.assertFalse(loaded.authenticated)
        leaked = _zip_payload(self.base, SYNTHETIC_ALPHA.encode("utf-8"))
        secrets = dict(loaded._stream_secret_values())
        with self.assertRaisesRegex(privacy.PrivacyError, "SYNTHETIC_ALPHA") as raised:
            privacy.validate_artifacts((leaked,), secrets)
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)
        result = privacy.scan_release_artifacts((leaked,), loaded)
        self.assertFalse(result.passed)
        self.assertEqual(result.matched_labels, ("SYNTHETIC_ALPHA",))

    def test_negative_mutation_inserts_known_secret_into_clean_artifact(self) -> None:
        loaded = self.synthetic_scanner_inventory()
        clean = _zip_payload(self.base, b"https://sync.app-cloud-sync.net/nodes")
        result = privacy.scan_release_artifacts(
            (clean,), loaded, target_id="chrome-extension-package"
        )
        self.assertTrue(result.passed)
        mutated = _zip_payload(
            self.base, b"token=" + SYNTHETIC_ALPHA.encode("utf-8")
        )
        mutated_result = privacy.scan_release_artifacts(
            (mutated,), loaded, target_id="chrome-extension-package"
        )
        self.assertFalse(mutated_result.passed)
        self.assertEqual(mutated_result.matched_labels, ("SYNTHETIC_ALPHA",))
        _assert_undisclosed(
            self,
            privacy.format_inventory_scan_report(mutated_result),
            SYNTHETIC_ALPHA,
        )


class ReleaseArtifactExactSecretsLaneModuleTests(unittest.TestCase):
    """Runtime coverage for the lane-owned release_artifact_exact_secrets module."""

    def setUp(self) -> None:
        import release_artifact_exact_secrets as exact_secrets

        self.exact = exact_secrets
        self._temp = tempfile.TemporaryDirectory(prefix="wins-exact-lane-")
        self.base = pathlib.Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_lane_module_reexports_complete_scanner_surface(self) -> None:
        for name in (
            "PrivacyError",
            "scan_release_artifacts",
            "validate_artifacts",
            "format_inventory_scan_report",
            "encoded_forms",
            "exact_secret_labels",
            "redact_diagnostic",
            "_inspect_member",
            "is_approved_vendor_debug_metadata",
            "MAX_ENCODED_SECRET_FORMS",
            "MAX_ARCHIVE_NEST_DEPTH",
            "_POST_PARENT_BIND_HOOK",
        ):
            self.assertTrue(hasattr(self.exact, name), name)

    def test_member_name_leak_category_relative_user_home(self) -> None:
        self.assertEqual(
            self.exact.member_name_leak_category(
                "home/release-builder/Downloads/tool/release.sh"
            ),
            "local-user-home-path",
        )
        self.assertEqual(
            self.exact.member_name_leak_category(
                "users/builder/Downloads/tool/release.sh"
            ),
            "local-user-home-path",
        )

    def test_member_name_leak_category_relative_source_tree(self) -> None:
        self.assertEqual(
            self.exact.member_name_leak_category(
                "release-builder/Downloads/wins_vpn/lib/main.dart"
            ),
            "local-source-tree-path",
        )
        self.assertEqual(
            self.exact.member_name_leak_category(
                "scratch/wins-vpn/tools/release_builder.py"
            ),
            "local-source-tree-path",
        )
        self.assertEqual(
            self.exact.member_name_leak_category(
                "tmp/wins-vpn-master/tools/release.py"
            ),
            "local-source-tree-path",
        )
        self.assertEqual(
            self.exact.member_name_leak_category(
                "builder/wins_vpn-0.9.1/lib/main.dart"
            ),
            "local-source-tree-path",
        )
        self.assertEqual(
            self.exact.member_name_leak_category(
                "builder/wins_vpn0.9.1/lib/main.dart"
            ),
            "local-source-tree-path",
        )
        self.assertEqual(
            self.exact.member_name_leak_category(
                "scratch/wins-vpn2/tools/release.py"
            ),
            "local-source-tree-path",
        )

    def test_member_name_leak_category_clean_is_none(self) -> None:
        for name in (
            "assets/config.bin",
            "lib/arm64-v8a/libapp.so",
            "base/lib/arm64-v8a/libapp.so",
            "Payload/Runner.app/Frameworks/libwg-go.dylib",
            "background.js",
            "org/winsvpn/app/MainActivity.kt",
            "Users/JohnDoe",
            "homepage/index.html",
        ):
            self.assertIsNone(self.exact.member_name_leak_category(name), name)

    def test_reject_unsafe_archive_member_names(self) -> None:
        with self.assertRaisesRegex(
            self.exact.PrivacyError, "build-path material"
        ):
            self.exact.reject_unsafe_archive_member_names(
                ["clean.bin", "release-builder/Downloads/wins_vpn/lib/main.dart"]
            )
        self.exact.reject_unsafe_archive_member_names(
            ["clean.bin", "assets/config.bin"]
        )

    def test_lane_module_validate_artifacts_detects_base64_secret_and_redacts(self) -> None:
        artifact = _zip_payload(
            self.base, base64.b64encode(SYNTHETIC_ALPHA.encode("utf-8"))
        )
        secrets = {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA}
        with self.assertRaises(self.exact.PrivacyError) as raised:
            self.exact.validate_artifacts((artifact,), secrets)
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)

    def test_lane_module_validate_artifacts_detects_nested_secret(self) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("client.bin", SYNTHETIC_ALPHA.encode("utf-8"))
        outer = self.base / "nested-lane.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("inner.zip", inner.getvalue())
        secrets = {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA}
        with self.assertRaises(self.exact.PrivacyError) as raised:
            self.exact.validate_artifacts((outer,), secrets)
        message = str(raised.exception)
        self.assertIn("SYNTHETIC_ALPHA", message)
        _assert_undisclosed(self, message, SYNTHETIC_ALPHA)

    def test_lane_module_encoded_forms_and_redaction_are_bounded(self) -> None:
        forms = self.exact.encoded_forms(SYNTHETIC_ENCODED.encode("utf-8"))
        self.assertLessEqual(len(forms), self.exact.MAX_ENCODED_SECRET_FORMS)
        compiled = self.exact.compile_exact_secret_forms(
            {"SYNTHETIC_ENCODED": SYNTHETIC_ENCODED}
        )
        redacted = self.exact.redact_diagnostic(
            "prefix " + SYNTHETIC_ENCODED + " suffix", compiled
        )
        _assert_undisclosed(self, redacted, SYNTHETIC_ENCODED)

    def test_lane_rejects_live_path_replacement_after_snapshot(self) -> None:
        artifact = self.base / "artifact.bin"
        replacement = self.base / "replacement.bin"
        original = self.base / "original.bin"
        artifact.write_bytes(b"clean-fixture")
        replacement.write_bytes(
            b'activation_secret="embedded-release-secret-value-0001"'
        )
        real_iter = self.exact._iter_snapshot

        def replace_after_snapshot(snapshot):
            os.replace(artifact, original)
            os.replace(replacement, artifact)
            yield from real_iter(snapshot)

        with mock.patch.object(
            self.exact, "_iter_snapshot", side_effect=replace_after_snapshot
        ):
            with self.assertRaisesRegex(self.exact.PrivacyError, "replaced after"):
                self.exact.validate_artifacts((artifact,), {})
        self.assertIn(b"activation_secret", artifact.read_bytes())

    def test_lane_rejects_directory_change_after_scanning(self) -> None:
        artifact = self.base / "tree"
        artifact.mkdir()
        live = artifact / "client.bin"
        replacement = self.base / "replacement.bin"
        live.write_bytes(b"clean-fixture")
        replacement.write_bytes(
            b'activation_secret="embedded-release-secret-value-0001"'
        )
        real_iter = self.exact._iter_directory

        def replace_after_directory_scan(path):
            yield from real_iter(path)
            os.replace(replacement, live)

        with mock.patch.object(
            self.exact,
            "_iter_directory",
            side_effect=replace_after_directory_scan,
        ):
            with self.assertRaisesRegex(self.exact.PrivacyError, "directory changed"):
                self.exact.validate_artifacts((artifact,), {})
        self.assertIn(b"activation_secret", live.read_bytes())

    def test_lane_exact_target_refuses_cross_candidate_result(self) -> None:
        first_root = self.base / "first"
        second_root = self.base / "second"
        first_root.mkdir()
        second_root.mkdir()
        first = _zip_payload(first_root, b"clean-fixture")
        second = _zip_payload(second_root, b"clean-fixture")
        first = first.rename(first_root / "app-release.apk")
        second = second.rename(second_root / "app-phone-release.apk")
        loaded = inventory.load_secret_inventory(
            _write_inventory(self.base / "inventory.json"), repository_root=ROOT
        )
        with mock.patch.object(
            self.exact,
            "release_secret_values",
            side_effect=lambda candidate: candidate._stream_secret_values(),
        ):
            with self.assertRaisesRegex(
                self.exact.PrivacyError, "one artifact candidate"
            ):
                self.exact.scan_release_artifacts(
                    (first, second),
                    loaded,
                    target_id="android-phone-tablet-apk",
                    require_target=True,
                )

    def test_lane_secret_stdin_is_bounded_and_strict_json(self) -> None:
        class GuardedBuffer(io.BytesIO):
            def __init__(self, payload: bytes) -> None:
                super().__init__(payload)
                self.read_sizes: list[int] = []

            def read(self, size: int = -1) -> bytes:
                self.read_sizes.append(size)
                if size < 0:
                    raise AssertionError("stdin read must be bounded")
                return super().read(size)

        class FakeStdin:
            def __init__(self, payload: bytes) -> None:
                self.buffer = GuardedBuffer(payload)

        valid = FakeStdin(
            b'{"SYNTHETIC_ALPHA":"synthetic-secret-value-0001"}'
        )
        with mock.patch.object(self.exact.sys, "stdin", valid):
            parsed = self.exact.read_secrets_stdin()
        self.assertEqual(parsed["SYNTHETIC_ALPHA"], "synthetic-secret-value-0001")
        self.assertEqual(
            valid.buffer.read_sizes,
            [self.exact.MAX_SECRET_STDIN_BYTES + 1],
        )

        oversized = FakeStdin(b"x" * (self.exact.MAX_SECRET_STDIN_BYTES + 1))
        with mock.patch.object(self.exact.sys, "stdin", oversized):
            with self.assertRaisesRegex(self.exact.PrivacyError, "size"):
                self.exact.read_secrets_stdin()

        hostile = (
            b'{"SYNTHETIC_ALPHA":"synthetic-secret-value-0001",'
            b'"SYNTHETIC_ALPHA":"synthetic-secret-value-0002"}',
            b'{"SYNTHETIC_ALPHA":NaN}',
            b'{"SYNTHETIC_ALPHA":Infinity}',
            b'{"SYNTHETIC_ALPHA":-Infinity}',
            b'{"SYNTHETIC_ALPHA":1e400}',
        )
        for payload in hostile:
            with self.subTest(payload=payload):
                candidate = FakeStdin(payload)
                with mock.patch.object(self.exact.sys, "stdin", candidate):
                    with self.assertRaises(self.exact.PrivacyError):
                        self.exact.read_secrets_stdin()

    def test_lane_obfuscated_names_do_not_hide_sensitive_payloads(self) -> None:
        (self.base / "secret").mkdir()
        secret_artifact = _zip_payload(
            self.base / "secret",
            base64.b64encode(SYNTHETIC_ALPHA.encode("utf-8")),
            name="a/b.bin",
        )
        with self.assertRaisesRegex(self.exact.PrivacyError, "SYNTHETIC_ALPHA"):
            self.exact.validate_artifacts(
                (secret_artifact,), {"SYNTHETIC_ALPHA": SYNTHETIC_ALPHA}
            )

        (self.base / "path").mkdir()
        path_artifact = _zip_payload(
            self.base / "path",
            b"/Users/release-builder/Downloads/wins_vpn/lib/main.dart",
            name="c/d.bin",
        )
        with self.assertRaises(self.exact.PrivacyError):
            self.exact.validate_artifacts((path_artifact,), {})

    def test_lane_validate_artifacts_rejects_member_name_source_tree_path(self) -> None:
        leaked = _zip_payload(
            self.base, b"clean payload", name="wins_vpn/macos/tools/leak.txt"
        )
        with self.assertRaisesRegex(
            self.exact.PrivacyError, "name contains local-source-tree-path"
        ):
            self.exact.validate_artifacts((leaked,), {})

    def test_lane_validate_artifacts_rejects_member_name_user_home_path(self) -> None:
        leaked = _zip_payload(
            self.base, b"clean payload", name="users/builder/Downloads/tool/release.sh"
        )
        with self.assertRaisesRegex(
            self.exact.PrivacyError, "name contains local-user-home-path"
        ):
            self.exact.validate_artifacts((leaked,), {})

    def test_lane_scan_release_artifacts_rejects_member_name_path_leak(self) -> None:
        leaked = _zip_payload(
            self.base, b"clean payload", name="wins_vpn/lib/main.dart"
        )
        inventory_path = _write_inventory(self.base / "inventory.json")
        loaded = inventory.load_secret_inventory(inventory_path, repository_root=ROOT)
        with mock.patch.object(
            self.exact,
            "release_secret_values",
            side_effect=lambda loaded: loaded._stream_secret_values(),
        ):
            with self.assertRaisesRegex(
                self.exact.PrivacyError, "name contains local-source-tree-path"
            ):
                self.exact.scan_release_artifacts((leaked,), loaded)

    def test_lane_clean_member_name_passes_validate_artifacts(self) -> None:
        clean = _zip_payload(self.base, b"clean payload", name="assets/config.bin")
        blobs = self.exact.validate_artifacts((clean,), {})
        self.assertGreaterEqual(blobs, 1)

    def test_lane_scan_entrypoints_are_rebound_to_exact_globals(self) -> None:
        self.assertIsNot(self.exact.main.__globals__, privacy.main.__globals__)
        self.assertIsNot(
            self.exact.canonical_extension_gate_verify.__globals__,
            privacy.canonical_extension_gate_verify.__globals__,
        )

    def test_lane_main_routes_through_exact_member_name_rejection(self) -> None:
        leaked = self.base / "wins-vpn-companion-chrome.zip"
        with zipfile.ZipFile(leaked, "w") as archive:
            archive.writestr("wins_vpn/lib/main.dart", b"clean payload")
        inventory_path = _write_inventory(self.base / "inventory.json")
        loaded = inventory.load_secret_inventory(inventory_path, repository_root=ROOT)
        with mock.patch.object(
            self.exact,
            "load_authenticated_secret_inventory",
            return_value=loaded,
        ):
            with mock.patch.object(
                self.exact,
                "release_secret_values",
                side_effect=lambda loaded: loaded._stream_secret_values(),
            ):
                with self.assertRaisesRegex(
                    self.exact.PrivacyError, "local-source-tree-path"
                ) as raised:
                    self.exact.main(
                        [
                            "--artifacts",
                            "--artifact",
                            str(leaked),
                            "--target",
                            "chrome-extension-package",
                        ]
                    )
        _assert_undisclosed(self, str(raised.exception), SYNTHETIC_ALPHA)


if __name__ == "__main__":
    unittest.main()
