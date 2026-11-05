#!/usr/bin/env python3
"""Adapter regressions for test/web_download_artifact_gate.py.

These tests prove the G19 harness delegates to tools.website_security_audit
and fail-closes. They do not duplicate that module's selftests; they bind a
temporary public web tree and assert the adapter surfaces the authoritative
non-PASS findings.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "test" / "web_download_artifact_gate.py"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_SPEC = importlib.util.spec_from_file_location("web_download_artifact_gate", GATE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(GATE)

LIVE_MANIFEST = ROOT / "web" / "releases" / "downloads.json"
LIVE_INDEX = ROOT / "web" / "index.html"
LIVE_HEADERS = ROOT / "web" / "_headers"
LINUX_FILENAME = "wins-vpn-linux-x64.tar.gz"
LINUX_BYTES = b"wins-vpn-linux-adapter-candidate\n"


def pending_manifest() -> dict[str, object]:
    return json.loads(LIVE_MANIFEST.read_text(encoding="utf-8"))


def hosted_receipt(
    kind: str,
    schema: str,
    filename: str,
    digest: str,
    payload: bytes,
    architecture: list[str],
    extra: dict[str, object] | None = None,
) -> tuple[bytes, str]:
    body: dict[str, object] = {
        "schema": schema,
        "kind": kind,
        "canonical_release": "1.0.15+30",
        "platform_id": "linux-x64",
        "artifact_filename": filename,
        "artifact_sha256": digest,
        "artifact_bytes": len(payload),
        "package_identity": "org.winsvpn.app",
        "architecture": architecture,
        "version": "1.0.15",
    }
    evidence_key = {
        "release_artifact_privacy_receipt_v1": "scan",
        "release_publication_receipt_v1": "build",
        "website_download_winn_provenance_receipt_v1": "engine_release",
    }.get(kind)
    if evidence_key:
        body[evidence_key] = {"fixture": True}
    if extra:
        body.update(extra)
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    return raw, hashlib.sha256(raw).hexdigest()


def linux_hosted_receipts(
    filename: str = LINUX_FILENAME,
    payload: bytes = LINUX_BYTES,
    architecture: list[str] | None = None,
) -> tuple[dict[str, bytes], str, str, str, str]:
    digest = hashlib.sha256(payload).hexdigest()
    arch = ["x64"] if architecture is None else architecture
    privacy_raw, privacy_sha = hosted_receipt(
        "release_artifact_privacy_receipt_v1",
        "winsvpn-web-download-privacy-receipt-v1",
        filename,
        digest,
        payload,
        arch,
    )
    release_raw, release_sha = hosted_receipt(
        "release_publication_receipt_v1",
        "winsvpn-web-download-release-receipt-v1",
        filename,
        digest,
        payload,
        arch,
    )
    winn_raw, winn_sha = hosted_receipt(
        "website_download_winn_provenance_receipt_v1",
        "winsvpn-website-download-winn-provenance-v1",
        filename,
        digest,
        payload,
        arch,
        extra={
            "primary": "winn/3",
            "fallback": "winn/1",
            "fallback_order": ["awg", "xray"],
        },
    )
    publication_raw, publication_sha = hosted_receipt(
        "website_download_publication_receipt_v1",
        "winsvpn-website-download-publication-receipt-v1",
        filename,
        digest,
        payload,
        arch,
    )
    return (
        {
            f"{filename}.privacy.json": privacy_raw,
            f"{filename}.release.json": release_raw,
            f"{filename}.winn.json": winn_raw,
            f"{filename}.publication.json": publication_raw,
        },
        privacy_sha,
        release_sha,
        winn_sha,
        publication_sha,
    )


def linux_available_manifest(
    filename: str = LINUX_FILENAME,
    payload: bytes = LINUX_BYTES,
    *,
    extra_direct: dict[str, object] | None = None,
) -> dict[str, object]:
    body = pending_manifest()
    body["release_id"] = "v1.0.15+30"
    digest = hashlib.sha256(payload).hexdigest()
    architecture = ["x64"]
    _, privacy_sha, release_sha, winn_sha, publication_sha = linux_hosted_receipts(
        filename, payload, architecture
    )
    body["artifacts"][3] = {
        "id": "linux-x64",
        "label": "Linux x64",
        "status": "available",
        "delivery": {"kind": "direct", "url": f"https://winsvpn.org/downloads/{filename}"},
        "artifact": {
            "filename": filename,
            "sha256": digest,
            "bytes": len(payload),
            "canonical_release": "1.0.15+30",
            "package_identity": "org.winsvpn.app",
            "version": "1.0.15",
            "architecture": architecture,
            "signature": {"kind": "publication_signature_sha256", "sha256": "c" * 64},
            "winn_provenance": {
                "kind": "website_download_winn_provenance_receipt_v1",
                "receipt_filename": f"{filename}.winn.json",
                "receipt_sha256": winn_sha,
                "primary": "winn/3",
                "fallback": "winn/1",
                "fallback_order": ["awg", "xray"],
            },
            "privacy": {
                "kind": "release_artifact_privacy_receipt_v1",
                "receipt_filename": f"{filename}.privacy.json",
                "receipt_sha256": privacy_sha,
            },
            "release_receipt": {
                "kind": "release_publication_receipt_v1",
                "receipt_filename": f"{filename}.release.json",
                "receipt_sha256": release_sha,
            },
            "publication_receipt": {
                "kind": "website_download_publication_receipt_v1",
                "receipt_filename": f"{filename}.publication.json",
                "receipt_sha256": publication_sha,
            },
        },
    }
    if extra_direct is not None:
        body["artifacts"][2] = extra_direct
    return body


def seed_web(directory: Path, manifest: dict[str, object] | None = None) -> Path:
    (directory / "releases").mkdir(parents=True)
    shutil.copyfile(LIVE_INDEX, directory / "index.html")
    shutil.copyfile(LIVE_HEADERS, directory / "_headers")
    (directory / "releases" / "downloads.json").write_text(
        json.dumps(manifest if manifest is not None else pending_manifest()),
        encoding="utf-8",
    )
    return directory


def write_direct_artifact(
    web: Path,
    filename: str,
    payload: bytes,
    *,
    sidecar: bytes | None = None,
    symlink_to: Path | None = None,
) -> None:
    downloads = web / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    artifact = downloads / filename
    if symlink_to is not None:
        artifact.symlink_to(symlink_to)
    else:
        artifact.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    sidecar_path = downloads / f"{filename}.sha256"
    sidecar_path.write_bytes(
        sidecar if sidecar is not None else f"{digest}  {filename}\n".encode("utf-8")
    )
    receipts, _, _, _, _ = linux_hosted_receipts(filename, payload)
    for name, raw in receipts.items():
        (downloads / name).write_bytes(raw)


class WebDownloadArtifactGateAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def _results(self, web: Path) -> list[object]:
        audit = GATE.load_audit_module()
        original_markers = audit.public_download_marker_errors
        with (
            mock.patch.object(audit, "WEB", web),
            mock.patch.object(audit, "DOWNLOAD_MANIFEST", web / "releases" / "downloads.json"),
            mock.patch.object(
                audit,
                "public_download_marker_errors",
                lambda web_root=web: original_markers(web_root),
            ),
        ):
            return GATE.collect_audit_results(audit)

    def _report(self, results: list[object]) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = GATE.report(results)
        return code, buffer.getvalue()

    def test_binds_authoritative_website_security_audit(self) -> None:
        self.assertEqual(
            GATE.AUDIT_MODULE_PATH,
            ROOT / "tools" / "website_security_audit.py",
        )
        self.assertEqual(
            GATE.AUTHORITATIVE_AUDITS,
            (
                "audit_public_download_regressions",
                "audit_downloads",
                "audit_download_manifest",
            ),
        )
        module = GATE.load_audit_module()
        self.assertEqual(
            Path(module.__file__).resolve(), GATE.AUDIT_MODULE_PATH.resolve()
        )
        for name in GATE.AUTHORITATIVE_AUDITS:
            self.assertTrue(callable(getattr(module, name)))

    def test_regular_tools_package_cannot_shadow_authoritative_audit(self) -> None:
        shadow_root = Path(self.temp.name) / "shadow"
        shadow_tools = shadow_root / "tools"
        shadow_tools.mkdir(parents=True)
        (shadow_tools / "__init__.py").write_text("", encoding="ascii")
        (shadow_tools / "website_security_audit.py").write_text(
            "raise RuntimeError('shadow auditor executed')\n", encoding="ascii"
        )
        with mock.patch.object(sys, "path", [str(shadow_root), *sys.path]):
            module = GATE.load_audit_module()
        self.assertEqual(
            Path(module.__file__).resolve(), GATE.AUDIT_MODULE_PATH.resolve()
        )

    def test_live_all_pending_and_absent_downloads_pass(self) -> None:
        downloads = ROOT / "web" / "downloads"
        self.assertFalse(downloads.is_dir() and any(downloads.iterdir()))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = GATE.main()
        self.assertEqual(code, 0, buffer.getvalue())
        self.assertTrue(buffer.getvalue().startswith("PASS "))

    def test_warn_skip_and_unknown_status_fail_closed(self) -> None:
        fake = SimpleNamespace(
            audit_public_download_regressions=lambda: [("WARN", "soft finding")],
            audit_downloads=lambda: [("SKIP", "not proven")],
            audit_download_manifest=lambda: [("OTHER", "not a pass")],
        )
        code, output = self._report(GATE.collect_audit_results(fake))
        self.assertEqual(code, 1)
        self.assertIn("WARN: soft finding", output)
        self.assertIn("SKIP: not proven", output)
        self.assertIn("OTHER: not a pass", output)

    def test_empty_or_malformed_audit_output_fail_closed(self) -> None:
        empty = SimpleNamespace(
            audit_public_download_regressions=lambda: [],
            audit_downloads=lambda: [("PASS", "ok")],
            audit_download_manifest=lambda: [("PASS", "ok")],
        )
        code, output = self._report(GATE.collect_audit_results(empty))
        self.assertEqual(code, 1)
        self.assertIn("returned no findings", output)

        malformed = SimpleNamespace(
            audit_public_download_regressions=lambda: [("PASS", "ok")],
            audit_downloads=lambda: ["not-a-tuple"],
            audit_download_manifest=lambda: [("PASS", "ok")],
        )
        code, output = self._report(GATE.collect_audit_results(malformed))
        self.assertEqual(code, 1)
        self.assertIn("malformed audit result", output)

        code, output = self._report([])
        self.assertEqual(code, 1)
        self.assertIn("returned no findings", output)

    def test_absent_available_artifact_fails(self) -> None:
        web = seed_web(Path(self.temp.name) / "absent", linux_available_manifest())
        code, output = self._report(self._results(web))
        self.assertEqual(code, 1)
        self.assertIn("manifest-bound direct artifacts are missing", output)

    def test_duplicate_filename_fails(self) -> None:
        digest = hashlib.sha256(LINUX_BYTES).hexdigest()
        extra = {
            "id": "android",
            "label": "Android",
            "status": "available",
            "delivery": {"kind": "direct", "url": f"https://winsvpn.org/downloads/{LINUX_FILENAME}"},
            "artifact": {
                "filename": LINUX_FILENAME,
                "sha256": digest,
                "bytes": len(LINUX_BYTES),
                "canonical_release": "1.0.15+30",
                "package_identity": "org.winsvpn.app",
                "version": "1.0.15",
                "architecture": ["arm64-v8a", "armeabi-v7a", "x86_64"],
                "signature": {
                    "kind": "apk_signer_certificate_sha256",
                    "sha256": "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee",
                },
                "winn_provenance": {
                    "kind": "website_download_winn_provenance_receipt_v1",
                    "receipt_filename": f"{LINUX_FILENAME}.winn.json",
                    "receipt_sha256": "f" * 64,
                    "primary": "winn/3",
                    "fallback": "winn/1",
                    "fallback_order": ["awg", "xray"],
                },
                "privacy": {
                    "kind": "release_artifact_privacy_receipt_v1",
                    "receipt_filename": f"{LINUX_FILENAME}.privacy.json",
                    "receipt_sha256": "d" * 64,
                },
                "release_receipt": {
                    "kind": "release_publication_receipt_v1",
                    "receipt_filename": f"{LINUX_FILENAME}.release.json",
                    "receipt_sha256": "e" * 64,
                },
                "publication_receipt": {
                    "kind": "website_download_publication_receipt_v1",
                    "receipt_filename": f"{LINUX_FILENAME}.publication.json",
                    "receipt_sha256": "a" * 64,
                },
            },
        }
        web = seed_web(
            Path(self.temp.name) / "duplicate",
            linux_available_manifest(extra_direct=extra),
        )
        write_direct_artifact(web, LINUX_FILENAME, LINUX_BYTES)
        code, output = self._report(self._results(web))
        self.assertEqual(code, 1)
        self.assertIn("duplicates a direct artifact filename", output)

    def test_stale_id_hash_url_and_mutable_route_fail(self) -> None:
        web = seed_web(Path(self.temp.name) / "stale", pending_manifest())
        (web / "poison.txt").write_text(
            "\n".join(
                (
                    "com.example.wins_vpn",
                    "89e8ba316dd2a041bde8d019fd407aebf6250a1840a73c98f053e0b6b4621d0f",
                    "winsvpn-downloads/releases/download/v1.0.0/wins-vpn-android.apk",
                    "/releases/latest/download/",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        code, output = self._report(self._results(web))
        self.assertEqual(code, 1)
        self.assertIn("stale Android debug application ID", output)
        self.assertIn("stale Android debug APK digest", output)
        self.assertIn("obsolete Android immutable download URL", output)
        self.assertIn("mutable latest-release download URL", output)

    def test_unbound_file_fails(self) -> None:
        web = seed_web(Path(self.temp.name) / "unbound", pending_manifest())
        downloads = web / "downloads"
        downloads.mkdir()
        (downloads / "orphan.bin").write_bytes(b"not-in-manifest")
        code, output = self._report(self._results(web))
        self.assertEqual(code, 1)
        self.assertIn("manifest-unbound files", output)

    def test_symlink_size_digest_and_sidecar_mismatch_fail(self) -> None:
        cases = (
            (
                "symlink",
                lambda web, outside: write_direct_artifact(
                    web,
                    LINUX_FILENAME,
                    LINUX_BYTES,
                    symlink_to=outside,
                ),
                "symlink",
            ),
            (
                "size",
                lambda web, _outside: write_direct_artifact(
                    web, LINUX_FILENAME, LINUX_BYTES + b"extra"
                ),
                "byte count mismatch",
            ),
            (
                "digest",
                lambda web, _outside: write_direct_artifact(
                    web,
                    LINUX_FILENAME,
                    bytes(byte ^ 1 for byte in LINUX_BYTES),
                ),
                "SHA-256 mismatch",
            ),
            (
                "sidecar",
                lambda web, _outside: write_direct_artifact(
                    web,
                    LINUX_FILENAME,
                    LINUX_BYTES,
                    sidecar=b"deadbeef  wrong-name.bin\n",
                ),
                "sidecar does not exactly bind",
            ),
        )
        for name, mutate, needle in cases:
            with self.subTest(name=name):
                web = seed_web(
                    Path(self.temp.name) / name, linux_available_manifest()
                )
                outside = Path(self.temp.name) / f"{name}-outside.bin"
                outside.write_bytes(LINUX_BYTES)
                mutate(web, outside)
                code, output = self._report(self._results(web))
                self.assertEqual(code, 1, output)
                self.assertIn(needle, output)


if __name__ == "__main__":
    unittest.main()
