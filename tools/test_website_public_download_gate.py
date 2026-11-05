#!/usr/bin/env python3
"""Adversarial regressions for public Android and Windows download custody."""

from __future__ import annotations

import importlib.util
import io
import json
import struct
import tempfile
import unittest
import hashlib
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "website_security_audit.py"
SPEC = importlib.util.spec_from_file_location("website_security_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def signed_pe_fixture() -> bytes:
    data = bytearray(0x210)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x80 + 20, 0xF0)
    optional = 0x80 + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + (4 * 8), 0x200, 16)
    struct.pack_into("<IHH", data, 0x200, 16, 0x0200, 0x0002)
    data[0x208:0x210] = b"PKCS7FIX"
    return bytes(data)


WINDOWS_FILENAME = "WinsVPN-Setup.exe"


def android_engine_apk(
    engine_root: Path,
    *,
    stale_abi: str | None = None,
    missing: str | None = None,
    extra_member: str | None = None,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for abi in sorted(AUDIT.PLATFORM_ARCHITECTURES["android"]):
            current = f"current-winn3-{abi}".encode("ascii")
            directory = engine_root / abi
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "libwinnengine.so").write_bytes(current)
            for engine in sorted(AUDIT.ANDROID_REQUIRED_ENGINE_BASENAMES):
                member = f"lib/{abi}/{engine}"
                if member == missing:
                    continue
                payload = current if engine == "libwinnengine.so" else f"engine-{abi}-{engine}".encode("ascii")
                if engine == "libwinnengine.so" and abi == stale_abi:
                    payload = b"stale-winn3-engine"
                archive.writestr(member, payload)
        if extra_member is not None:
            archive.writestr(extra_member, b"unexpected-engine")
    return output.getvalue()


def hosted_receipt_payload(
    *,
    kind: str,
    schema: str,
    platform_id: str,
    filename: str,
    digest: str,
    byte_count: int,
    architecture: list[str],
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": schema,
        "kind": kind,
        "canonical_release": AUDIT.CANONICAL_RELEASE,
        "platform_id": platform_id,
        "artifact_filename": filename,
        "artifact_sha256": digest,
        "artifact_bytes": byte_count,
        "package_identity": AUDIT.PUBLIC_PACKAGE_IDENTITY,
        "architecture": architecture,
        "version": AUDIT.CANONICAL_VERSION_NAME,
    }
    # The audit binds the closed key set; tools/website_download_custody.py
    # validates the contents of each evidence object.
    evidence_key = {
        AUDIT.PRIVACY_RECEIPT_KIND: "scan",
        AUDIT.RELEASE_RECEIPT_KIND: "build",
        AUDIT.WINN_PROVENANCE_KIND: "engine_release",
    }.get(kind)
    if evidence_key:
        payload[evidence_key] = {"fixture": True}
    if extra:
        payload.update(extra)
    return payload


def write_hosted_receipts(
    downloads: Path,
    *,
    platform_id: str,
    filename: str,
    digest: str,
    byte_count: int,
    architecture: list[str],
) -> tuple[str, str, str, str]:
    extra = {
        "primary": AUDIT.WINN_PRIMARY,
        "fallback": AUDIT.WINN_FALLBACK,
        "fallback_order": list(AUDIT.WINN_FALLBACK_ORDER),
    }
    privacy = json.dumps(
        hosted_receipt_payload(
            kind=AUDIT.PRIVACY_RECEIPT_KIND,
            schema=AUDIT.PRIVACY_RECEIPT_SCHEMA,
            platform_id=platform_id,
            filename=filename,
            digest=digest,
            byte_count=byte_count,
            architecture=architecture,
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    release = json.dumps(
        hosted_receipt_payload(
            kind=AUDIT.RELEASE_RECEIPT_KIND,
            schema=AUDIT.RELEASE_RECEIPT_SCHEMA,
            platform_id=platform_id,
            filename=filename,
            digest=digest,
            byte_count=byte_count,
            architecture=architecture,
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    winn = json.dumps(
        hosted_receipt_payload(
            kind=AUDIT.WINN_PROVENANCE_KIND,
            schema=AUDIT.WINN_PROVENANCE_SCHEMA,
            platform_id=platform_id,
            filename=filename,
            digest=digest,
            byte_count=byte_count,
            architecture=architecture,
            extra=extra,
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    (downloads / f"{filename}.privacy.json").write_bytes(privacy)
    (downloads / f"{filename}.release.json").write_bytes(release)
    (downloads / f"{filename}.winn.json").write_bytes(winn)
    publication = json.dumps(
        {
            "schema": AUDIT.PUBLICATION_RECEIPT_SCHEMA,
            "kind": AUDIT.PUBLICATION_RECEIPT_KIND,
            "canonical_release": AUDIT.CANONICAL_RELEASE,
            "artifact_filename": filename,
            "artifact_sha256": digest,
            "artifact_bytes": byte_count,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    (downloads / f"{filename}.publication.json").write_bytes(publication)
    return (
        hashlib.sha256(privacy).hexdigest(),
        hashlib.sha256(release).hexdigest(),
        hashlib.sha256(winn).hexdigest(),
        hashlib.sha256(publication).hexdigest(),
    )


def custody_bindings(
    filename: str,
    privacy_sha256: str,
    release_sha256: str,
    winn_sha256: str,
    publication_sha256: str,
) -> dict[str, object]:
    return {
        "winn_provenance": {
            "kind": AUDIT.WINN_PROVENANCE_KIND,
            "receipt_filename": f"{filename}.winn.json",
            "receipt_sha256": winn_sha256,
            "primary": AUDIT.WINN_PRIMARY,
            "fallback": AUDIT.WINN_FALLBACK,
            "fallback_order": list(AUDIT.WINN_FALLBACK_ORDER),
        },
        "privacy": {
            "kind": AUDIT.PRIVACY_RECEIPT_KIND,
            "receipt_filename": f"{filename}.privacy.json",
            "receipt_sha256": privacy_sha256,
        },
        "release_receipt": {
            "kind": AUDIT.RELEASE_RECEIPT_KIND,
            "receipt_filename": f"{filename}.release.json",
            "receipt_sha256": release_sha256,
        },
        "publication_receipt": {
            "kind": AUDIT.PUBLICATION_RECEIPT_KIND,
            "receipt_filename": f"{filename}.publication.json",
            "receipt_sha256": publication_sha256,
        },
    }


def windows_direct_payload(
    base: dict[str, object],
    artifact_bytes: bytes,
    receipt_bytes: bytes,
    *,
    privacy_sha256: str,
    release_sha256: str,
    winn_sha256: str,
    publication_sha256: str,
) -> dict[str, object]:
    payload = json.loads(json.dumps(base))
    filename = WINDOWS_FILENAME
    payload["release_id"] = "v1.0.16+33"
    payload["artifacts"][0] = {
        "id": "windows-x64",
        "label": "Windows x64",
        "status": "available",
        "delivery": {
            "kind": "direct",
            "url": f"https://winsvpn.org/downloads/{filename}",
        },
        "artifact": {
            "filename": filename,
            "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "bytes": len(artifact_bytes),
            "canonical_release": "1.0.16+33",
            "package_identity": "org.winsvpn.app",
            "version": "1.0.16",
            "architecture": ["x64"],
            "signature": {
                "kind": "authenticode_signer_certificate_sha256",
                "sha256": "b" * 64,
            },
            **custody_bindings(
                filename,
                privacy_sha256,
                release_sha256,
                winn_sha256,
                publication_sha256,
            ),
            "windows_verification": {
                "kind": "winverifytrust_receipt_v1",
                "receipt_filename": f"{filename}.authenticode.json",
                "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                "approved_signer_subject": "CN=Win's VPN, O=Win's VPN LLC, C=US",
                "approved_signer_certificate_sha256": "b" * 64,
            },
        },
    }
    return payload


def js_function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing JavaScript function {signature}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"unterminated JavaScript function {signature}")
    depth = 0
    for index, char in enumerate(source[brace:], brace):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated JavaScript function {signature}")


def verified_download_toctou_errors(website: str) -> list[str]:
    """Static checks that verified direct bytes are saved locally, not re-fetched."""
    errors: list[str] = []
    try:
        verify_body = js_function_body(website, "async function verifyPinnedSha256(entry)")
        download_body = js_function_body(website, "function beginDownload(entry, verifiedBytes)")
        then_body = js_function_body(website, "async function verifyThenDownload(entry, option)")
    except AssertionError as exc:
        return [str(exc)]

    if 'redirect: "error"' not in verify_body:
        errors.append("verified fetch must refuse redirects")
    if "cache: \"no-store\"" not in verify_body:
        errors.append("verified fetch must not reuse cached artifact bytes")
    if "new Uint8Array(entry.bytes)" not in verify_body:
        errors.append("verified fetch must preallocate the pinned byte count")
    if "const chunks = []" in verify_body:
        errors.append("verified fetch must not buffer an unbounded chunk list")
    if "total + chunk.length > entry.bytes" not in verify_body:
        errors.append("verified fetch must abort when streamed bytes exceed the pin")
    if "reader.cancel()" not in verify_body:
        errors.append("oversize artifact streams must be cancelled")
    if "bytes: joined" not in verify_body:
        errors.append("verified fetch must return the hashed bytes")
    if "beginDownload" in verify_body:
        errors.append("hashing must not start a download")

    if "URL.createObjectURL" not in download_body:
        errors.append("verified download must use the hashed object URL")
    if "URL.revokeObjectURL" not in download_body:
        errors.append("verified object URL must be revoked")
    if "new Blob(" not in download_body:
        errors.append("verified download must wrap the hashed bytes")
    if "entry.url" in download_body:
        errors.append("verified download must not issue a second network GET")
    if "fetch(" in download_body:
        errors.append("verified download must not fetch again")

    if "beginDownload(entry, result.bytes)" not in then_body:
        errors.append("success path must download the hashed bytes")
    if "beginDownload(entry);" in then_body:
        errors.append("success path must not download by URL")
    blocked_branch = then_body.partition('} else if (result.reason === "blocked") {')[2].partition(
        "} else {"
    )[0]
    if not blocked_branch or "beginDownload" in blocked_branch:
        errors.append("blocked byte verification must never start a download")
    return errors


def winverifytrust_receipt(artifact_bytes: bytes) -> dict[str, object]:
    return {
        "schema": "winsvpn-windows-publication-winverifytrust-v1",
        "artifact_filename": WINDOWS_FILENAME,
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "artifact_bytes": len(artifact_bytes),
        "winverifytrust_status": 0,
        "authenticode_status": "Valid",
        "signature_verified": True,
        "timestamp_verified": True,
        "signer_subject": "CN=Win's VPN, O=Win's VPN LLC, C=US",
        "signer_certificate_sha256": "b" * 64,
        "timestamp_certificate_sha256": "c" * 64,
        "timestamp_utc": "2026-01-01T12:00:00Z",
    }


class PublicDownloadGateTests(unittest.TestCase):
    def test_current_android_and_windows_entries_are_fail_closed(self) -> None:
        payload = json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))
        for platform_id in ("windows-x64", "windows-arm64", "android"):
            entry = next(item for item in payload["artifacts"] if item["id"] == platform_id)
            self.assertEqual(entry["status"], "verification_pending")
            self.assertIsNone(entry["delivery"]["url"])
            self.assertEqual(
                entry["artifact"],
                {"filename": None, "sha256": None, "bytes": None},
            )
        self.assertEqual(AUDIT.public_download_marker_errors(), [])

    def test_stale_debug_identity_and_obsolete_urls_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            web = Path(temporary)
            (web / "index.html").write_text(
                "com.example.wins_vpn "
                "https://github.com/winsvpn/winsvpn-downloads/releases/"
                "download/v1.0.0/wins-vpn-android.apk",
                encoding="utf-8",
            )
            errors = AUDIT.public_download_marker_errors(web)
        self.assertTrue(any("stale Android debug application ID" in item for item in errors))
        self.assertTrue(any("obsolete Android immutable download URL" in item for item in errors))

    def test_static_apk_aab_and_windows_installer_links_cannot_bypass_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            web = Path(temporary)
            (web / "index.html").write_text(
                "\n".join(
                    (
                        '<a href="/downloads/fresh.apk">APK</a>',
                        '<a href="/downloads/app-release.aab">AAB</a>',
                        '<a href="https://winsvpn.org/downloads/Fresh-Setup.exe">Windows</a>',
                        '<a href="#get">Safe navigation</a>',
                    )
                ),
                encoding="utf-8",
            )
            errors = AUDIT.static_public_binary_link_errors(web)
        self.assertEqual(len(errors), 3)
        self.assertTrue(any("fresh.apk" in error for error in errors))
        self.assertTrue(any("app-release.aab" in error for error in errors))
        self.assertTrue(any("Fresh-Setup.exe" in error for error in errors))

    def test_android_requires_production_id_release_scheme_and_reviewed_signer(self) -> None:
        valid_signature = (
            "Verified using v2 scheme (APK Signature Scheme v2): true\n"
            "Number of signers: 1\n"
            "Signer #1 certificate SHA-256 digest: "
            f"{AUDIT.ANDROID_PUBLIC_SIGNER_SHA256}\n"
        )
        self.assertEqual(
            AUDIT.android_public_artifact_errors("org.winsvpn.app\n", valid_signature),
            [],
        )
        stale_id = AUDIT.android_public_artifact_errors(
            "com.example.wins_vpn\n", valid_signature
        )
        self.assertTrue(any("production org.winsvpn.app" in item for item in stale_id))
        debug_signature = valid_signature.replace(
            AUDIT.ANDROID_PUBLIC_SIGNER_SHA256, "d" * 64
        )
        self.assertTrue(
            any(
                "reviewed production upload certificate" in item
                for item in AUDIT.android_public_artifact_errors(
                    "org.winsvpn.app\n", debug_signature
                )
            )
        )
        self.assertTrue(
            AUDIT.android_public_artifact_errors(
                "org.winsvpn.app\n", "DOES NOT VERIFY\n", signature_returncode=1
            )
        )
        self.assertTrue(
            any(
                "1.0.16+33 release identity" in item
                for item in AUDIT.android_public_artifact_errors(
                    "org.winsvpn.app\n",
                    valid_signature,
                    version_name_output="1.0.14\n",
                    version_code_output="29\n",
                )
            )
        )
        self.assertEqual(
            AUDIT.android_public_artifact_errors(
                "org.winsvpn.app\n",
                valid_signature,
                version_name_output="1.0.16\n",
                version_code_output="33\n",
            ),
            [],
        )

    def test_android_public_apk_binds_exact_current_winn3_engine_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine_root = Path(temporary) / "release-engines"
            current = android_engine_apk(engine_root)
            self.assertEqual(
                AUDIT.android_engine_provenance_errors(
                    current, release_engine_root=engine_root
                ),
                [],
            )

            stale = android_engine_apk(engine_root, stale_abi="arm64-v8a")
            self.assertTrue(
                any(
                    "not the exact current release payload" in error
                    for error in AUDIT.android_engine_provenance_errors(
                        stale, release_engine_root=engine_root
                    )
                )
            )

            missing = android_engine_apk(
                engine_root, missing="lib/x86_64/libwinnengine.so"
            )
            self.assertTrue(
                any(
                    "one safe non-empty lib/x86_64/libwinnengine.so" in error
                    for error in AUDIT.android_engine_provenance_errors(
                        missing, release_engine_root=engine_root
                    )
                )
            )

            aab_layout = android_engine_apk(
                engine_root,
                missing="lib/arm64-v8a/libwinnengine.so",
                extra_member="base/lib/arm64-v8a/libwinnengine.so",
            )
            aab_errors = AUDIT.android_engine_provenance_errors(
                aab_layout, release_engine_root=engine_root
            )
            self.assertTrue(any("outside the exact current ABI inventory" in error for error in aab_errors))
            self.assertTrue(any("lib/arm64-v8a/libwinnengine.so" in error for error in aab_errors))

            forbidden_xray = android_engine_apk(
                engine_root,
                extra_member="lib/arm64-v8a/libxray.so",
            )
            xray_errors = AUDIT.android_engine_provenance_errors(
                forbidden_xray, release_engine_root=engine_root
            )
            self.assertTrue(any("lib/arm64-v8a/libxray.so" in error for error in xray_errors))

    def test_windows_unsigned_or_malformed_pe_is_rejected(self) -> None:
        unsigned = bytearray(signed_pe_fixture())
        optional = 0x80 + 24
        struct.pack_into("<II", unsigned, optional + 112 + (4 * 8), 0, 0)
        self.assertTrue(AUDIT.windows_pe_certificate_table_errors(bytes(unsigned)))
        self.assertTrue(AUDIT.windows_pe_certificate_table_errors(b"not-a-pe"))
        self.assertEqual(AUDIT.windows_pe_certificate_table_errors(signed_pe_fixture()), [])

    def test_windows_requires_current_version_and_cryptographic_authenticode(self) -> None:
        artifact = {
            "signature": {
                "kind": "authenticode_signer_certificate_sha256",
                "sha256": "b" * 64,
            },
            "windows_verification": {
                "approved_signer_certificate_sha256": "b" * 64,
            },
        }

        class GoodGate:
            @staticmethod
            def canonical_windows_release() -> str:
                return "1.0.16+33"

            @staticmethod
            def pe_version_info(_name: str, _data: bytes) -> dict[str, str]:
                return {"ProductVersion": "1.0.16", "FileVersion": "1.0.16.33"}

            @staticmethod
            def authenticode_leaf_identity(_name: str, _data: bytes) -> dict[str, str]:
                return {"sha256": "b" * 64}

            @staticmethod
            def authenticode_custody_policy(_name: str, _data: bytes, leaf: dict[str, str]):
                return leaf

            @staticmethod
            def _verify_outer_pe_authenticode(
                _name: str, _data: bytes, _policy: object
            ) -> dict[str, str]:
                return {"sha256": "b" * 64}

        self.assertEqual(
            AUDIT.windows_authenticode_cryptographic_errors(
                WINDOWS_FILENAME,
                signed_pe_fixture(),
                artifact,
                gate_module=GoodGate,
            ),
            [],
        )

        class StaleVersionGate(GoodGate):
            @staticmethod
            def pe_version_info(_name: str, _data: bytes) -> dict[str, str]:
                return {"ProductVersion": "1.0.14", "FileVersion": "1.0.14.29"}

        self.assertTrue(
            any(
                "VERSIONINFO is not 1.0.16.33" in error
                for error in AUDIT.windows_authenticode_cryptographic_errors(
                    WINDOWS_FILENAME,
                    signed_pe_fixture(),
                    artifact,
                    gate_module=StaleVersionGate,
                )
            )
        )

        fake_pkcs7_errors = AUDIT.windows_authenticode_cryptographic_errors(
            WINDOWS_FILENAME, signed_pe_fixture(), artifact
        )
        self.assertTrue(
            any("Authenticode cryptographic verification failed" in error for error in fake_pkcs7_errors)
        )

    def test_fake_pkcs7_cannot_publish_without_winverifytrust_receipt(self) -> None:
        artifact_bytes = signed_pe_fixture()
        pending = json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))
        receipt_bytes = json.dumps(winverifytrust_receipt(artifact_bytes), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as temporary:
            downloads = Path(temporary)
            digest = hashlib.sha256(artifact_bytes).hexdigest()
            privacy_sha, release_sha, winn_sha, publication_sha = write_hosted_receipts(
                downloads,
                platform_id="windows-x64",
                filename=WINDOWS_FILENAME,
                digest=digest,
                byte_count=len(artifact_bytes),
                architecture=["x64"],
            )
            payload = windows_direct_payload(
                pending,
                artifact_bytes,
                receipt_bytes,
                privacy_sha256=privacy_sha,
                release_sha256=release_sha,
                winn_sha256=winn_sha,
                publication_sha256=publication_sha,
            )
            filename = payload["artifacts"][0]["artifact"]["filename"]
            (downloads / filename).write_bytes(artifact_bytes)
            (downloads / f"{filename}.sha256").write_text(
                f"{digest}  {filename}\n", encoding="utf-8"
            )
            errors = AUDIT.direct_download_binding_errors(payload, downloads)
        self.assertTrue(any("WinVerifyTrust receipt is missing" in item for item in errors))

    def test_winverifytrust_receipt_binds_hash_signer_and_timestamp(self) -> None:
        artifact_bytes = signed_pe_fixture()
        pending = json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))

        def run(
            receipt: dict[str, object],
            *,
            published_bytes: bytes = artifact_bytes,
            corrupt_receipt_after_binding: bool = False,
        ) -> list[str]:
            receipt_bytes = json.dumps(receipt, sort_keys=True).encode()
            with tempfile.TemporaryDirectory() as temporary:
                downloads = Path(temporary)
                digest = hashlib.sha256(artifact_bytes).hexdigest()
                privacy_sha, release_sha, winn_sha, publication_sha = write_hosted_receipts(
                    downloads,
                    platform_id="windows-x64",
                    filename=WINDOWS_FILENAME,
                    digest=digest,
                    byte_count=len(artifact_bytes),
                    architecture=["x64"],
                )
                payload = windows_direct_payload(
                    pending,
                    artifact_bytes,
                    receipt_bytes,
                    privacy_sha256=privacy_sha,
                    release_sha256=release_sha,
                    winn_sha256=winn_sha,
                    publication_sha256=publication_sha,
                )
                entry = payload["artifacts"][0]
                filename = entry["artifact"]["filename"]
                (downloads / filename).write_bytes(published_bytes)
                (downloads / f"{filename}.sha256").write_text(
                    f"{digest}  {filename}\n", encoding="utf-8"
                )
                receipt_name = entry["artifact"]["windows_verification"]["receipt_filename"]
                (downloads / receipt_name).write_bytes(
                    receipt_bytes + (b" " if corrupt_receipt_after_binding else b"")
                )
                with mock.patch.object(
                    AUDIT,
                    "windows_authenticode_cryptographic_errors",
                    return_value=[],
                ):
                    return AUDIT.direct_download_binding_errors(payload, downloads)

        valid = winverifytrust_receipt(artifact_bytes)
        self.assertEqual(run(valid), [])

        tampered = bytearray(artifact_bytes)
        tampered[0x100] ^= 1
        self.assertTrue(any("SHA-256 mismatch" in item for item in run(valid, published_bytes=bytes(tampered))))

        wrong_hash = dict(valid)
        wrong_hash["artifact_sha256"] = "d" * 64
        self.assertTrue(any("exact artifact" in item for item in run(wrong_hash)))

        self.assertTrue(
            any(
                "receipt hash mismatch" in item
                for item in run(valid, corrupt_receipt_after_binding=True)
            )
        )

        wrong_signer = dict(valid)
        wrong_signer["signer_certificate_sha256"] = "e" * 64
        self.assertTrue(any("manifest-approved signer" in item for item in run(wrong_signer)))

        missing_timestamp = dict(valid)
        missing_timestamp["timestamp_verified"] = False
        self.assertTrue(any("trusted timestamp" in item for item in run(missing_timestamp)))

    def test_browser_rejects_mutated_github_authority_and_blocked_verification(self) -> None:
        source = (ROOT / "web/index.html").read_text(encoding="utf-8")
        self.assertIn(
            "GitHub is backup-only and is not website publication authority",
            source,
        )
        self.assertNotIn(
            "GitHub is backup-only and is not Android or Windows publication authority",
            source,
        )
        self.assertIn("No unverified download was started", source)
        blocked_branch = source.split('} else if (result.reason === "blocked") {', 1)[1].split(
            "} else {", 1
        )[0]
        self.assertNotIn("beginDownload(entry)", blocked_branch)
        self.assertNotIn("winsVerifyDone", source)
        self.assertEqual(AUDIT.browser_download_contract_errors(source), [])

        served_manifest_bypass = source.replace(
            "GitHub is backup-only and is not website publication authority",
            "GitHub release URL is allowed for Linux",
            1,
        )
        self.assertTrue(
            any(
                "GitHub branch" in item
                for item in AUDIT.browser_download_contract_errors(served_manifest_bypass)
            )
        )

        csp_blocked_fetch_bypass = source.replace(
            '"Download stopped: this browser could not fetch and verify the exact bytes. No unverified download was started. Contact support or use an approved app store."\n          );',
            '"Download stopped: this browser could not fetch and verify the exact bytes. No unverified download was started. Contact support or use an approved app store."\n          );\n          beginDownload(entry);',
            1,
        )
        self.assertTrue(
            any(
                "blocked byte verification" in item
                for item in AUDIT.browser_download_contract_errors(csp_blocked_fetch_bypass)
            )
        )

    def test_verified_download_uses_hashed_bytes_not_second_get(self) -> None:
        source = (ROOT / "web/index.html").read_text(encoding="utf-8")
        self.assertEqual(verified_download_toctou_errors(source), [])
        self.assertEqual(AUDIT.browser_download_contract_errors(source), [])

        second_get = source.replace("anchor.href = objectUrl;", "anchor.href = entry.url;", 1)
        self.assertTrue(
            any("second network GET" in item for item in verified_download_toctou_errors(second_get))
        )

        no_revoke = source.replace("URL.revokeObjectURL(objectUrl);", "void objectUrl;", 1)
        self.assertTrue(
            any("revoked" in item for item in verified_download_toctou_errors(no_revoke))
        )

        unbounded = source.replace(
            "if (total + chunk.length > entry.bytes) {",
            "if (false) {",
            1,
        )
        self.assertTrue(
            any("exceed the pin" in item for item in verified_download_toctou_errors(unbounded))
        )

        hashed_then_refetch = source.replace(
            "beginDownload(entry, result.bytes);",
            "beginDownload(entry);",
            1,
        )
        self.assertTrue(
            any("hashed bytes" in item for item in verified_download_toctou_errors(hashed_then_refetch))
        )

    def test_android_and_windows_github_binary_links_are_not_publication_authority(self) -> None:
        pending = json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))
        for index, platform_id, filename in (
            (0, "windows-x64", "WinsVPN-Setup.exe"),
            (2, "android", "wins-vpn-android.apk"),
            (3, "linux-x64", "wins-vpn-linux-x64.tar.gz"),
        ):
            candidate = json.loads(json.dumps(pending))
            candidate["release_id"] = "v1.0.16+33"
            candidate["artifacts"][index] = {
                "id": platform_id,
                "label": (
                    "Windows x64"
                    if platform_id == "windows-x64"
                    else "Android"
                    if platform_id == "android"
                    else "Linux x64"
                ),
                "status": "available",
                "delivery": {
                    "kind": "github_release",
                    "url": (
                        "https://github.com/winsvpn/winsvpn-downloads/releases/"
                        f"download/v1.0.16+33/{filename}"
                    ),
                },
                "artifact": {"filename": filename, "sha256": "a" * 64, "bytes": 1},
            }
            errors = AUDIT.download_manifest_errors(candidate)
            self.assertTrue(
                any(
                    "GitHub is backup-only and is not website publication authority" in item
                    for item in errors
                )
            )

    def test_available_requires_current_release_identity_architecture_and_receipts(self) -> None:
        pending = json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))
        incomplete = json.loads(json.dumps(pending))
        incomplete["artifacts"][2] = {
            "id": "android",
            "label": "Android",
            "status": "available",
            "delivery": {
                "kind": "direct",
                "url": "/downloads/wins-vpn-android-20260824.apk",
            },
            "artifact": {
                "filename": "wins-vpn-android-20260824.apk",
                "sha256": AUDIT.STALE_ANDROID_DEBUG_SHA256,
                "bytes": 68984768,
            },
        }
        errors = AUDIT.download_manifest_errors(incomplete)
        self.assertTrue(any("1.0.16+33 custody metadata" in item for item in errors))

        wrong_release = json.loads(json.dumps(pending))
        wrong_release["release_id"] = "v1.0.14+29"
        self.assertTrue(
            any(
                "release_id is not the current 1.0.16+33 website release" in item
                for item in AUDIT.download_manifest_errors(wrong_release)
            )
        )

        debug_identity = json.loads(json.dumps(pending))
        debug_identity["artifacts"][2] = {
            "id": "android",
            "label": "Android",
            "status": "available",
            "delivery": {
                "kind": "direct",
                "url": "/downloads/wins-vpn-android.apk",
            },
            "artifact": {
                "filename": "wins-vpn-android.apk",
                "sha256": "a" * 64,
                "bytes": 2,
                "canonical_release": "1.0.16+33",
                "package_identity": "com.example.wins_vpn",
                "version": "1.0.16",
                "architecture": ["arm64-v8a", "armeabi-v7a", "x86_64"],
                "signature": {
                    "kind": "apk_signer_certificate_sha256",
                    "sha256": AUDIT.ANDROID_PUBLIC_SIGNER_SHA256,
                },
                "winn_provenance": {
                    "kind": AUDIT.WINN_PROVENANCE_KIND,
                    "receipt_filename": "wins-vpn-android.apk.winn.json",
                    "receipt_sha256": "f" * 64,
                    "primary": AUDIT.WINN_PRIMARY,
                    "fallback": AUDIT.WINN_FALLBACK,
                    "fallback_order": list(AUDIT.WINN_FALLBACK_ORDER),
                },
                "privacy": {
                    "kind": AUDIT.PRIVACY_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-android.apk.privacy.json",
                    "receipt_sha256": "b" * 64,
                },
                "release_receipt": {
                    "kind": AUDIT.RELEASE_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-android.apk.release.json",
                    "receipt_sha256": "c" * 64,
                },
                "publication_receipt": {
                    "kind": AUDIT.PUBLICATION_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-android.apk.publication.json",
                    "receipt_sha256": "d" * 64,
                },
            },
        }
        debug_errors = AUDIT.download_manifest_errors(debug_identity)
        self.assertTrue(any("stale Android debug application ID" in item for item in debug_errors))
        self.assertTrue(any("org.winsvpn.app" in item for item in debug_errors))

        stale_apk = json.loads(json.dumps(debug_identity))
        stale_apk["artifacts"][2]["artifact"]["package_identity"] = "org.winsvpn.app"
        stale_apk["artifacts"][2]["artifact"]["sha256"] = AUDIT.STALE_ANDROID_DEBUG_SHA256
        self.assertTrue(
            any(
                "stale Android debug APK digest" in item
                for item in AUDIT.download_manifest_errors(stale_apk)
            )
        )

        unsigned_windows = json.loads(json.dumps(pending))
        unsigned_windows["artifacts"][0] = {
            "id": "windows-x64",
            "label": "Windows x64",
            "status": "available",
            "delivery": {
                "kind": "direct",
                "url": "/downloads/WinsVPN-Setup.exe",
            },
            "artifact": {
                "filename": "WinsVPN-Setup.exe",
                "sha256": AUDIT.STALE_WINDOWS_UNSIGNED_SHA256,
                "bytes": 57358281,
                "canonical_release": "1.0.16+33",
                "package_identity": "org.winsvpn.app",
                "version": "1.0.16",
                "architecture": ["x64"],
                "signature": {
                    "kind": "authenticode_signer_certificate_sha256",
                    "sha256": "b" * 64,
                },
                "winn_provenance": {
                    "kind": AUDIT.WINN_PROVENANCE_KIND,
                    "receipt_filename": "WinsVPN-Setup.exe.winn.json",
                    "receipt_sha256": "f" * 64,
                    "primary": AUDIT.WINN_PRIMARY,
                    "fallback": AUDIT.WINN_FALLBACK,
                    "fallback_order": list(AUDIT.WINN_FALLBACK_ORDER),
                },
                "privacy": {
                    "kind": AUDIT.PRIVACY_RECEIPT_KIND,
                    "receipt_filename": "WinsVPN-Setup.exe.privacy.json",
                    "receipt_sha256": "b" * 64,
                },
                "release_receipt": {
                    "kind": AUDIT.RELEASE_RECEIPT_KIND,
                    "receipt_filename": "WinsVPN-Setup.exe.release.json",
                    "receipt_sha256": "c" * 64,
                },
                "publication_receipt": {
                    "kind": AUDIT.PUBLICATION_RECEIPT_KIND,
                    "receipt_filename": "WinsVPN-Setup.exe.publication.json",
                    "receipt_sha256": "e" * 64,
                },
                "windows_verification": {
                    "kind": "winverifytrust_receipt_v1",
                    "receipt_filename": "WinsVPN-Setup.exe.authenticode.json",
                    "receipt_sha256": "d" * 64,
                    "approved_signer_subject": "CN=Win's VPN, O=Win's VPN LLC, C=US",
                    "approved_signer_certificate_sha256": "b" * 64,
                },
            },
        }
        windows_errors = AUDIT.download_manifest_errors(unsigned_windows)
        self.assertTrue(
            any("stale unsigned Windows installer digest" in item for item in windows_errors)
        )

        stale_linux_arch = json.loads(json.dumps(pending))
        stale_linux_arch["artifacts"][3] = {
            "id": "linux-x64",
            "label": "Linux x64",
            "status": "available",
            "delivery": {"kind": "direct", "url": "/downloads/wins-vpn-linux-x64.tar.gz"},
            "artifact": {
                "filename": "wins-vpn-linux-x64.tar.gz",
                "sha256": "a" * 64,
                "bytes": 2,
                "canonical_release": "1.0.16+33",
                "package_identity": "org.winsvpn.app",
                "version": "1.0.16",
                "architecture": ["x86_64"],
                "signature": {"kind": "publication_signature_sha256", "sha256": "c" * 64},
                "winn_provenance": {
                    "kind": AUDIT.WINN_PROVENANCE_KIND,
                    "receipt_filename": "wins-vpn-linux-x64.tar.gz.winn.json",
                    "receipt_sha256": "f" * 64,
                    "primary": AUDIT.WINN_PRIMARY,
                    "fallback": AUDIT.WINN_FALLBACK,
                    "fallback_order": list(AUDIT.WINN_FALLBACK_ORDER),
                },
                "privacy": {
                    "kind": AUDIT.PRIVACY_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-linux-x64.tar.gz.privacy.json",
                    "receipt_sha256": "b" * 64,
                },
                "release_receipt": {
                    "kind": AUDIT.RELEASE_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-linux-x64.tar.gz.release.json",
                    "receipt_sha256": "c" * 64,
                },
                "publication_receipt": {
                    "kind": AUDIT.PUBLICATION_RECEIPT_KIND,
                    "receipt_filename": "wins-vpn-linux-x64.tar.gz.publication.json",
                    "receipt_sha256": "d" * 64,
                },
            },
        }
        self.assertTrue(
            any(
                "stale architecture artifact" in item
                for item in AUDIT.download_manifest_errors(stale_linux_arch)
            )
        )



def unsigned_windows_entry(**artifact_changes: object) -> dict[str, object]:
    filename = "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
    artifact = AUDIT._selftest_available_artifact(
        "windows-x64",
        filename,
        "a" * 64,
        1000,
        ["x64"],
        signer_sha256="9" * 64,
        privacy_sha256="d" * 64,
        release_sha256="e" * 64,
        winn_sha256="f" * 64,
    )
    artifact["signature"] = {"kind": "unsigned_owner_waiver", "sha256": "9" * 64}
    artifact["unsigned_waiver"] = {
        "label": "Unsigned",
        "waiver_filename": "download-unsigned-waiver.json",
        "waiver_sha256": "9" * 64,
    }
    artifact.update(artifact_changes)
    return {
        "id": "windows-x64",
        "label": "Windows x64",
        "status": "available",
        "delivery": {"kind": "direct", "url": f"https://winsvpn.org/downloads/{filename}"},
        "artifact": artifact,
    }


class PerArchitectureAuditTests(unittest.TestCase):
    def pending(self) -> dict[str, object]:
        return json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))

    def test_owner_waived_unsigned_windows_is_a_valid_manifest_entry(self) -> None:
        payload = self.pending()
        payload["artifacts"][0] = unsigned_windows_entry()
        self.assertEqual(AUDIT.download_manifest_errors(payload), [])

    def test_unsigned_windows_needs_the_visible_label(self) -> None:
        payload = self.pending()
        payload["artifacts"][0] = unsigned_windows_entry(
            unsigned_waiver={
                "label": "Verified",
                "waiver_filename": "download-unsigned-waiver.json",
                "waiver_sha256": "9" * 64,
            }
        )
        errors = AUDIT.download_manifest_errors(payload)
        self.assertTrue(any("labelled Unsigned" in item for item in errors), errors)

    def test_unsigned_kind_is_windows_only_and_keeps_unsigned_name(self) -> None:
        payload = self.pending()
        entry = unsigned_windows_entry(filename="WinsVPN-Setup.exe")
        entry["delivery"]["url"] = "https://winsvpn.org/downloads/WinsVPN-Setup.exe"
        payload["artifacts"][0] = entry
        self.assertTrue(
            any("canonical target filename" in item for item in AUDIT.download_manifest_errors(payload))
        )
        linux = self.pending()
        linux_entry = unsigned_windows_entry(filename="wins-vpn-linux-x64.tar.gz")
        linux_entry.update({"id": "linux-x64", "label": "Linux x64"})
        linux_entry["delivery"]["url"] = "https://winsvpn.org/downloads/wins-vpn-linux-x64.tar.gz"
        linux["artifacts"][3] = linux_entry
        self.assertTrue(
            any("only Windows" in item for item in AUDIT.download_manifest_errors(linux))
        )

    def test_store_pending_only_on_app_store_entries_and_v1_refused(self) -> None:
        payload = self.pending()
        payload["artifacts"][3]["status"] = "store_pending"
        self.assertTrue(
            any("store_pending is valid only" in item for item in AUDIT.download_manifest_errors(payload))
        )
        v1 = self.pending()
        v1["schema"] = "winsvpn-download-manifest-v1"
        self.assertEqual(AUDIT.download_manifest_errors(v1), ["unsupported manifest schema"])

    def test_unsigned_label_is_refused_for_bytes_with_a_certificate_table(self) -> None:
        signed_bytes = signed_pe_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            downloads = Path(temporary)
            entry = unsigned_windows_entry(
                sha256=hashlib.sha256(signed_bytes).hexdigest(), bytes=len(signed_bytes)
            )
            (downloads / entry["artifact"]["filename"]).write_bytes(signed_bytes)
            payload = {"artifacts": [entry]}
            errors = AUDIT.direct_download_binding_errors(payload, downloads)
        self.assertTrue(
            any("certificate table but is labelled Unsigned" in item for item in errors), errors
        )

    def test_live_menu_and_strip_list_every_architecture_entry(self) -> None:
        results = AUDIT.audit_download_manifest()
        self.assertEqual([status for status, _ in results], ["PASS"], results)
        website = (ROOT / "web/index.html").read_text(encoding="utf-8")
        for marker in (
            '"unsigned_owner_waiver"',
            'unsignedWaiver.label !== "Unsigned"',
            '(entry.status === "store_pending" && platform.kind === "store")',
        ):
            mutated = website.replace(marker, "", 1)
            self.assertTrue(AUDIT.browser_download_contract_errors(mutated), marker)



PINNED_GITHUB = "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/"


class PinnedGithubReleaseAuditTests(unittest.TestCase):
    def pending(self) -> dict[str, object]:
        return json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))

    def linux_github_entry(self, url: str | None = None, entry_id: str = "linux-x64") -> dict[str, object]:
        filename = "wins-vpn-linux-x64.tar.gz"
        return {
            "id": entry_id,
            "label": "Linux x64",
            "status": "available",
            "delivery": {"kind": "github_release", "url": url or PINNED_GITHUB + filename},
            "artifact": AUDIT._selftest_available_artifact(
                "linux-x64",
                filename,
                "a" * 64,
                1000,
                ["x64"],
                signer_sha256="c" * 64,
                privacy_sha256="d" * 64,
                release_sha256="e" * 64,
                winn_sha256="f" * 64,
            ),
        }

    def test_pinned_release_asset_is_a_valid_published_entry(self) -> None:
        payload = self.pending()
        payload["artifacts"][3] = self.linux_github_entry()
        self.assertEqual(AUDIT.download_manifest_errors(payload), [])

    def test_lookalike_github_urls_are_backup_only(self) -> None:
        filename = "wins-vpn-linux-x64.tar.gz"
        for url in (
            PINNED_GITHUB.replace("v1.0.16-33", "v1.0.16+33") + filename,
            PINNED_GITHUB.replace("v1.0.16-33", "v1.0.0") + filename,
            PINNED_GITHUB.replace("github.com", "github.com.evil.example") + filename,
            PINNED_GITHUB.replace("winsvpn-downloads", "winsvpn-downloads2") + filename,
            PINNED_GITHUB + "WinsVPN-Setup.exe",
        ):
            payload = self.pending()
            payload["artifacts"][3] = self.linux_github_entry(url)
            errors = AUDIT.download_manifest_errors(payload)
            self.assertTrue(any("backup-only" in item for item in errors), (url, errors))

    def test_marker_scan_exempts_only_the_pinned_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            web = Path(temporary)
            (web / "pinned.json").write_text(PINNED_GITHUB + "wins-vpn-linux-x64.tar.gz", encoding="utf-8")
            self.assertEqual(AUDIT.public_download_marker_errors(web), [])
            (web / "stale.json").write_text(
                "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.15-30/x.exe",
                encoding="utf-8",
            )
            errors = AUDIT.public_download_marker_errors(web)
        self.assertTrue(any("stale.json" in item for item in errors), errors)

    def test_local_bytes_of_a_github_entry_are_still_measured(self) -> None:
        payload = {"artifacts": [self.linux_github_entry()]}
        with tempfile.TemporaryDirectory() as temporary:
            downloads = Path(temporary)
            (downloads / "wins-vpn-linux-x64.tar.gz").write_bytes(b"not the manifest bytes")
            errors = AUDIT.direct_download_binding_errors(payload, downloads)
        self.assertTrue(any("SHA-256 mismatch" in item for item in errors), errors)



class ReleaseScopeAuditTests(unittest.TestCase):
    """Sol review round 1 DLP-05: availability limited to the owner ruling."""

    def test_android_and_signed_windows_are_refused_for_this_release(self) -> None:
        payload = json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))
        payload["artifacts"][2] = {
            "id": "android",
            "label": "Android",
            "status": "available",
            "delivery": {"kind": "direct", "url": "https://winsvpn.org/downloads/wins-vpn-android.apk"},
            "artifact": AUDIT._selftest_available_artifact(
                "android", "wins-vpn-android.apk", "a" * 64, 10,
                sorted(AUDIT.PLATFORM_ARCHITECTURES["android"]),
                signer_sha256=AUDIT.ANDROID_PUBLIC_SIGNER_SHA256,
                privacy_sha256="d" * 64, release_sha256="e" * 64, winn_sha256="f" * 64,
            ),
        }
        errors = AUDIT.download_manifest_errors(payload)
        self.assertIn("artifact android is outside the owner-authorized 1.0.16+33 desktop launch", errors)
        signed = json.loads((ROOT / "web/releases/downloads.json").read_text(encoding="utf-8"))
        artifact = AUDIT._selftest_available_artifact(
            "windows-x64", "WinsVPN-Setup.exe", "a" * 64, 10, ["x64"],
            signer_sha256="b" * 64, privacy_sha256="d" * 64, release_sha256="e" * 64, winn_sha256="f" * 64,
        )
        artifact["windows_verification"] = {
            "kind": "winverifytrust_receipt_v1",
            "receipt_filename": "WinsVPN-Setup.exe.authenticode.json",
            "receipt_sha256": "d" * 64,
            "approved_signer_subject": "CN=Win's VPN",
            "approved_signer_certificate_sha256": "b" * 64,
        }
        signed["artifacts"][0] = {
            "id": "windows-x64",
            "label": "Windows x64",
            "status": "available",
            "delivery": {"kind": "direct", "url": "https://winsvpn.org/downloads/WinsVPN-Setup.exe"},
            "artifact": artifact,
        }
        self.assertIn(
            "artifact windows-x64 must use the recorded Unsigned owner waiver",
            AUDIT.download_manifest_errors(signed),
        )



class PublishedRecordSecretScanTests(unittest.TestCase):
    """Argon F-4: release records and receipts are part of the secret scan."""

    def test_secret_in_a_release_or_receipt_json_fails_the_scan(self) -> None:
        for relative in ("releases/extra.json", "downloads/x.tar.gz.release.json"):
            with tempfile.TemporaryDirectory() as temporary:
                web = Path(temporary)
                for name in ("index.html", "_worker.js"):
                    (web / name).write_text("clean", encoding="utf-8")
                target = web / relative
                target.parent.mkdir(parents=True)
                target.write_text('{"note": "sk-' + "A" * 24 + '"}', encoding="utf-8")
                with (
                    mock.patch.object(AUDIT, "WEB", web),
                    mock.patch.object(AUDIT, "ROOT", web.parent),
                    mock.patch.object(AUDIT, "DEPLOYMENT_SCRIPTS", ()),
                    mock.patch.object(AUDIT, "CLIENT_SECRET_SOURCES", ()),
                ):
                    results = AUDIT.audit_secrets()
            self.assertTrue(
                any(status == "FAIL" and relative in message for status, message in results),
                (relative, results),
            )


if __name__ == "__main__":
    unittest.main()
