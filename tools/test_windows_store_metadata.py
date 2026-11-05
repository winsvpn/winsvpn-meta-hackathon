#!/usr/bin/env python3
"""Windows x64 store metadata honesty and 1.0.17+34 Partner Center contracts."""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
import sys

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import release_obfuscation_contract as obfuscation
import windows_cross_store_artifact_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKET = ROOT / "app_store/windows"
IDENTITY_MAP = ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
PUBSPEC = ROOT / "pubspec.yaml"
RUNNER_RC = ROOT / "windows/runner/Runner.rc"
OWNER_BLOCKED_ABSENT = "OWNER-BLOCKED: ABSENT"
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PLACEHOLDER_MARKERS = (
    "[provide",
    "[attach",
    "TODO",
    "TBD",
    "FIXME",
    "<insert",
    "your-hash-here",
    "example.com",
    "REPLACE_ME",
)
FALSE_GREEN_LISTING = (
    "Install the signed",
    "current signed installer is attached",
    "download WinsVPN-Setup.exe",
    "no logs",
)
OWNER_STATE_FIELDS = (
    "owner_state",
    "authenticode_leaf_sha256",
    "partner_center_enrollment",
    "reviewer_account",
    "reviewer_routes",
    "versioned_https_url",
    "installer_sha256",
    "export_compliance",
    "age_rating",
)


class WindowsStoreMetadataHonestyError(ValueError):
    """Raised when Windows store metadata claims an owner-free green."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WindowsStoreMetadataHonestyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: pathlib.Path) -> dict[str, object]:
    try:
        payload = json.loads(
            path.read_text(encoding="ascii"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsStoreMetadataHonestyError(
            f"{path.as_posix()} is not readable ASCII JSON: {exc}"
        ) from exc
    if type(payload) is not dict:
        raise WindowsStoreMetadataHonestyError(
            f"{path.as_posix()} must contain one JSON object"
        )
    return payload


def _require_ascii_file(path: pathlib.Path) -> str:
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise WindowsStoreMetadataHonestyError(
            f"{path.as_posix()} must be ASCII"
        ) from exc
    if raw.decode("ascii") != text:
        raise WindowsStoreMetadataHonestyError(
            f"{path.as_posix()} must be ASCII"
        )
    return text


def current_windows_identity() -> dict[str, str]:
    pubspec = PUBSPEC.read_text(encoding="ascii")
    match = re.search(r"^version:\s*([0-9]+\.[0-9]+\.[0-9]+\+[0-9]+)\s*$", pubspec, re.M)
    if match is None:
        raise WindowsStoreMetadataHonestyError("pubspec.yaml has no canonical version")
    canonical = match.group(1)
    marketing, build = canonical.split("+", 1)
    four_part = f"{marketing}.{build}"
    ruling = _load_json(IDENTITY_MAP)
    windows = ruling["platform_mappings"]["windows"]
    if (
        ruling["canonical_release"] != canonical
        or windows["product_version"] != marketing
        or windows["four_part_version"] != four_part
    ):
        raise WindowsStoreMetadataHonestyError(
            "release identity map is not the current Windows 1.0.17+34 identity"
        )
    runner = RUNNER_RC.read_text(encoding="ascii")
    if (
        f'#define WINS_PRODUCT_VERSION_STRING "{marketing}"' not in runner
        or f'#define WINS_FILE_VERSION_STRING "{four_part}"' not in runner
    ):
        raise WindowsStoreMetadataHonestyError(
            "windows/runner/Runner.rc is not the current Windows 1.0.17+34 identity"
        )
    return {
        "canonical_release": canonical,
        "product_version": marketing,
        "four_part_version": four_part,
        "pubspec_version": canonical,
        "identity_map": "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json",
        "product_name": "Win's VPN",
    }


def _require_identity(payload: dict[str, object], identity: dict[str, str], label: str) -> None:
    for key in (
        "canonical_release",
        "product_version",
        "four_part_version",
        "pubspec_version",
        "identity_map",
    ):
        if payload.get(key) != identity[key]:
            raise WindowsStoreMetadataHonestyError(
                f"{label} {key} is not the current Windows identity"
            )


def _require_owner_blocked(value: object, label: str) -> None:
    if value != OWNER_BLOCKED_ABSENT:
        raise WindowsStoreMetadataHonestyError(
            f"{label} must be {OWNER_BLOCKED_ABSENT}"
        )


def _require_absent_artifact(record: dict[str, object], label: str) -> None:
    if (
        record.get("produced") is not False
        or record.get("upload_performed") is not False
        or record.get("publication_authorized") is not False
        or record.get("sha256") != ""
        or record.get("size_bytes") != 0
        or record.get("artifact_status")
        not in {"no_current_candidate", "not_an_upload_target"}
        or record.get("authenticode") != OWNER_BLOCKED_ABSENT
    ):
        raise WindowsStoreMetadataHonestyError(
            f"{label} claims current candidate bytes or signing"
        )
    digest = record.get("sha256")
    if type(digest) is str and SHA256_RE.fullmatch(digest):
        raise WindowsStoreMetadataHonestyError(
            f"{label} records an installer hash without owner evidence"
        )


def require_honest_windows_store_packet(
    packet: pathlib.Path, identity: dict[str, str]
) -> None:
    if not packet.is_dir():
        raise WindowsStoreMetadataHonestyError("Windows store packet is missing")
    for path in packet.rglob("*"):
        if path.is_file():
            text = _require_ascii_file(path)
            for marker in PLACEHOLDER_MARKERS:
                if marker in text:
                    raise WindowsStoreMetadataHonestyError(
                        f"{path.as_posix()} contains unresolved placeholder {marker}"
                    )
            if "1.0.14+29" in text and path.name not in {
                "release_candidate.json",
                "export_compliance_facts.txt",
            }:
                raise WindowsStoreMetadataHonestyError(
                    f"{path.as_posix()} treats 1.0.14+29 as current"
                )

    listing = _require_ascii_file(packet / "metadata/en-US/full_description.txt")
    notes = _require_ascii_file(packet / "review/partner_center_notes.txt")
    short = _require_ascii_file(packet / "metadata/en-US/short_description.txt").strip()
    title = _require_ascii_file(packet / "metadata/en-US/title.txt").strip()
    whats_new = _require_ascii_file(packet / "metadata/en-US/whats_new.txt")
    features = _require_ascii_file(packet / "metadata/en-US/features.txt")
    search_terms = _require_ascii_file(packet / "metadata/en-US/search_terms.txt")
    readme = _require_ascii_file(packet / "README.md")
    export_facts = _require_ascii_file(
        packet / "review/export_compliance_facts.txt"
    )
    for required in ("Winn v3", "AWG then Xray"):
        if required not in listing or required not in notes or required not in short:
            raise WindowsStoreMetadataHonestyError(
                "listing copy must name Winn v3 primary and AWG then Xray fallback"
            )
    if title != identity["product_name"]:
        raise WindowsStoreMetadataHonestyError("Windows listing title is not Win's VPN")
    if "Calculator" in listing:
        raise WindowsStoreMetadataHonestyError(
            "Windows listing must refuse calculator camouflage"
        )
    if "not an MSIX package" not in listing:
        raise WindowsStoreMetadataHonestyError("Windows listing must name that it is not MSIX")
    if "separate x64" not in listing:
        raise WindowsStoreMetadataHonestyError("Windows listing must name separate x64 artifacts")
    if identity["canonical_release"] not in whats_new + notes:
        raise WindowsStoreMetadataHonestyError(
            "listing notes must name the current canonical release"
        )
    for phrase in FALSE_GREEN_LISTING:
        if phrase in listing or phrase in features or phrase in search_terms:
            raise WindowsStoreMetadataHonestyError(
                f"listing copy claims owner-free green {phrase!r}"
            )
    if "no logs" in search_terms:
        raise WindowsStoreMetadataHonestyError(
            "search terms must not overclaim no logs"
        )
    if "no browsing history" not in search_terms:
        raise WindowsStoreMetadataHonestyError(
            "search terms must name no browsing history"
        )
    if "Signed x64 offline" in features:
        raise WindowsStoreMetadataHonestyError(
            "features claim a current signed installer"
        )
    if OWNER_BLOCKED_ABSENT not in notes or OWNER_BLOCKED_ABSENT not in readme:
        raise WindowsStoreMetadataHonestyError(
            "review notes and README must keep OWNER-BLOCKED: ABSENT"
        )
    if notes.count(OWNER_BLOCKED_ABSENT) < 8:
        raise WindowsStoreMetadataHonestyError(
            "Partner Center notes omit required OWNER-BLOCKED: ABSENT fields"
        )
    notes_without_version = notes.replace(identity["four_part_version"], "")
    if SHA256_RE.search(notes) is not None or IPV4_RE.search(notes_without_version) is not None:
        raise WindowsStoreMetadataHonestyError(
            "Partner Center notes must not invent installer hashes or node addresses"
        )
    if "This package never uploads" not in notes:
        raise WindowsStoreMetadataHonestyError("Partner Center notes claim upload")
    if "fail-closed" not in notes:
        raise WindowsStoreMetadataHonestyError(
            "Partner Center notes must keep production MSIX fail-closed"
        )
    if OWNER_BLOCKED_ABSENT not in export_facts:
        raise WindowsStoreMetadataHonestyError(
            "export facts must stay OWNER-BLOCKED: ABSENT"
        )
    if "The app uses encryption" not in export_facts:
        raise WindowsStoreMetadataHonestyError(
            "export facts must record that the app uses encryption"
        )
    if 'Do not claim "no encryption"' not in export_facts:
        raise WindowsStoreMetadataHonestyError(
            "export facts must refuse a no-encryption claim"
        )

    privacy = _load_json(packet / "review/privacy_label_manifest.json")
    signoff = _load_json(packet / "review/owner_signoff.json")
    candidate = _load_json(packet / "artifacts/release_candidate.json")
    export_status = _load_json(packet / "review/export_compliance_status.json")
    age = _load_json(packet / "review/age_rating_status.json")
    for payload, label in (
        (privacy, "privacy label"),
        (signoff, "owner signoff"),
        (candidate, "release candidate"),
        (export_status, "export-compliance status"),
        (age, "age rating"),
    ):
        _require_identity(payload, identity, label)
    if (
        privacy.get("listing_screenshot_inventory") != "owner-blocked"
        or privacy.get("tracking") is not False
        or privacy.get("data_shared") is not False
        or privacy.get("msix_upload_target") is not False
        or privacy.get("private_symbols_uploaded") is not False
        or privacy.get("camouflage") is not False
    ):
        raise WindowsStoreMetadataHonestyError(
            "privacy label claims completed screenshots, tracking, sharing, or MSIX upload"
        )
    _require_owner_blocked(privacy.get("owner_state"), "privacy owner_state")
    _require_owner_blocked(privacy.get("export_compliance"), "privacy export_compliance")
    _require_owner_blocked(privacy.get("age_rating"), "privacy age_rating")
    if (
        signoff.get("submission_approved") is not False
        or signoff.get("upload_authorized") is not False
        or signoff.get("msix_upload_authorized") is not False
        or signoff.get("listing_screenshot_inventory") != "owner-blocked"
        or signoff.get("blockers") != gate.WINDOWS_OWNER_SIGNOFF_BLOCKERS
    ):
        raise WindowsStoreMetadataHonestyError(
            "owner signoff claims submission, upload, or a completed blocker set"
        )
    for field in OWNER_STATE_FIELDS:
        _require_owner_blocked(signoff.get(field), f"owner signoff {field}")
    if (
        candidate.get("candidate_set_status") != "no_current_candidate"
        or candidate.get("upload_status") != "not_uploaded"
        or candidate.get("submission_package_validation_status")
        != "no_current_candidate"
        or candidate.get("arm64_targets_status") != "pending-owner-evidence"
        or candidate["private_symbols"].get("uploaded") is not False
        or candidate["msix"].get("upload_target") is not False
        or candidate["msix"].get("production_allowed") is not False
        or candidate["msix"].get("development_identity_only") is not True
        or candidate["msix"].get("filename") != gate.WINDOWS_MSIX_PACKAGE_FILENAME
    ):
        raise WindowsStoreMetadataHonestyError(
            "release candidate claims a current uploadable set"
        )
    _require_owner_blocked(candidate.get("owner_state"), "candidate owner_state")
    _require_owner_blocked(
        candidate.get("authenticode_leaf_sha256"), "candidate authenticode"
    )
    _require_owner_blocked(candidate.get("installer_sha256"), "candidate installer hash")
    _require_owner_blocked(
        candidate.get("versioned_https_url"), "candidate versioned URL"
    )
    if OWNER_BLOCKED_ABSENT not in str(candidate.get("notes")):
        raise WindowsStoreMetadataHonestyError(
            "candidate notes omit OWNER-BLOCKED: ABSENT"
        )
    if candidate.get("historical_non_authoritative", {}).get("retired_release") != (
        "1.0.14+29"
    ):
        raise WindowsStoreMetadataHonestyError(
            "candidate must retire 1.0.14+29 instead of presenting it as current"
        )
    for target, record in candidate["targets"].items():
        _require_absent_artifact(record, target)
    for target, record in candidate["pending_required_targets"].items():
        _require_absent_artifact(record, target)
        if record.get("status") != "pending-owner-evidence":
            raise WindowsStoreMetadataHonestyError(
                f"{target} is not pending-owner-evidence"
            )
    _require_absent_artifact(candidate["msix"], "msix")
    if (
        export_status.get("status") != "pending_owner_legal"
        or export_status.get("uses_encryption") is not True
        or export_status.get("exemption_claimed") is not False
        or export_status.get("partner_center_declaration_approved") is not False
        or export_status.get("unsigned_artifact_may_carry_declaration") is not False
    ):
        raise WindowsStoreMetadataHonestyError(
            "export-compliance status is an owner-free green"
        )
    _require_owner_blocked(export_status.get("owner_state"), "export owner_state")
    if (
        age.get("status") != OWNER_BLOCKED_ABSENT
        or age.get("iarc_completed") is not False
        or age.get("partner_center_rating_approved") is not False
        or age.get("rating_value") != ""
    ):
        raise WindowsStoreMetadataHonestyError("age rating is an owner-free green")


class WindowsStoreMetadataTests(unittest.TestCase):
    def test_store_packet_is_ascii_and_canonical(self) -> None:
        self.assertTrue(PACKET.is_dir())
        for path in PACKET.rglob("*"):
            if path.is_file():
                path.read_bytes().decode("ascii")
        reviewed = gate._reviewed_store_metadata("windows-x64-installer")
        self.assertEqual(reviewed["canonical_release"], "1.0.17+34")
        self.assertEqual(reviewed["product_version"], "1.0.17")
        self.assertEqual(reviewed["four_part_version"], "1.0.17.34")
        self.assertEqual(reviewed["form"], "windows-x64")
        self.assertFalse(reviewed["submission_approved"])
        self.assertFalse(reviewed["upload_authorized"])
        self.assertFalse(reviewed["msix_upload_target"])
        self.assertFalse(reviewed["private_symbols_uploaded"])
        self.assertEqual(reviewed["tunnel_protocol"]["primary"], "winn-v3")
        self.assertEqual(reviewed["tunnel_protocol"]["fallback"], ["awg", "xray"])
        partner = gate._reviewed_store_metadata("windows-x64-partner-center")
        self.assertEqual(reviewed["sha256"], partner["sha256"])
        self.assertIn(
            "app_store/windows/review/privacy_label_manifest.json", reviewed["files"]
        )
        self.assertIn(
            "installer/windows/store/certification-notes.md", reviewed["files"]
        )
        self.assertIn(
            "app_store/windows/metadata/en-US/whats_new.txt", reviewed["files"]
        )
        self.assertEqual(
            reviewed["obfuscation_receipts"]["windows-x64-installer"],
            gate.obfuscation_receipt_relative("windows-x64-installer"),
        )
        self.assertEqual(
            reviewed["obfuscation_receipts"]["windows-x64-partner-center"],
            gate.obfuscation_receipt_relative("windows-x64-partner-center"),
        )

    def test_listing_and_notes_name_protocol_and_x64_filenames(self) -> None:
        listing = (
            PACKET / "metadata/en-US/full_description.txt"
        ).read_text(encoding="ascii")
        notes = (
            PACKET / "review/partner_center_notes.txt"
        ).read_text(encoding="ascii")
        short = (
            PACKET / "metadata/en-US/short_description.txt"
        ).read_text(encoding="ascii").strip()
        title = (
            PACKET / "metadata/en-US/title.txt"
        ).read_text(encoding="ascii").strip()
        whats_new = (
            PACKET / "metadata/en-US/whats_new.txt"
        ).read_text(encoding="ascii")
        copyright_line = (
            PACKET / "metadata/en-US/copyright.txt"
        ).read_text(encoding="ascii").strip()
        self.assertEqual(title, "Win's VPN")
        self.assertLessEqual(len(title), gate.WINDOWS_TITLE_MAX)
        self.assertLessEqual(len(short), gate.WINDOWS_SHORT_DESCRIPTION_MAX)
        self.assertLessEqual(len(listing), gate.WINDOWS_FULL_DESCRIPTION_MAX)
        self.assertLessEqual(len(whats_new), gate.WINDOWS_WHATS_NEW_MAX)
        self.assertIn("Winn v3", listing)
        self.assertIn("AWG then Xray", listing)
        self.assertIn("separate x64", listing)
        self.assertIn("not an MSIX package", listing)
        self.assertIn("WinsVPN-Setup.exe", notes)
        self.assertIn("WinsVPN-PartnerCenter.exe", notes)
        self.assertIn("Winn v3", notes)
        self.assertIn("AWG then Xray", notes)
        self.assertIn("fail-closed", notes)
        self.assertIn("Winn v3", short)
        self.assertIn("AWG then Xray", short)
        self.assertNotIn("Calculator", listing)
        self.assertIn("1.0.17+34", whats_new + notes)
        self.assertEqual(copyright_line, gate.WINDOWS_COPYRIGHT)
        self.assertEqual(
            (PACKET / "metadata/en-US/privacy_url.txt")
            .read_text(encoding="ascii")
            .strip(),
            gate.WINDOWS_PRIVACY_POLICY_URL,
        )
        self.assertEqual(
            (PACKET / "metadata/en-US/support_url.txt")
            .read_text(encoding="ascii")
            .strip(),
            gate.WINDOWS_SUPPORT_URL,
        )
        self.assertEqual(
            (PACKET / "metadata/en-US/website_url.txt")
            .read_text(encoding="ascii")
            .strip(),
            gate.WINDOWS_WEBSITE_URL,
        )

    def test_owner_signoff_and_candidate_remain_unuploaded(self) -> None:
        signoff = json.loads(
            (PACKET / "review/owner_signoff.json").read_text(encoding="ascii")
        )
        candidate = json.loads(
            (PACKET / "artifacts/release_candidate.json").read_text(encoding="ascii")
        )
        self.assertFalse(signoff["submission_approved"])
        self.assertFalse(signoff["upload_authorized"])
        self.assertFalse(signoff["msix_upload_authorized"])
        self.assertEqual(signoff["canonical_release"], "1.0.17+34")
        self.assertEqual(signoff["blockers"], gate.WINDOWS_OWNER_SIGNOFF_BLOCKERS)
        self.assertEqual(candidate["candidate_set_status"], "no_current_candidate")
        self.assertFalse(candidate["private_symbols"]["uploaded"])
        self.assertFalse(candidate["msix"]["upload_target"])
        self.assertFalse(candidate["msix"]["production_allowed"])
        self.assertEqual(candidate["msix"]["package_version"], "1.0.17.34")
        self.assertEqual(
            candidate["msix"]["filename"], gate.WINDOWS_MSIX_PACKAGE_FILENAME
        )
        self.assertEqual(
            candidate["private_symbols"]["x64"],
            ".artifacts/private-release-symbols/windows/x64/1.0.17+34",
        )
        for target in ("windows-x64-installer", "windows-x64-partner-center"):
            record = candidate["targets"][target]
            self.assertFalse(record["produced"])
            self.assertFalse(record["upload_performed"])
            self.assertFalse(record["publication_authorized"])
            self.assertEqual(record["architecture"], "x64")
            self.assertEqual(
                candidate["obfuscation_receipts"][target],
                gate.obfuscation_receipt_relative(target),
            )
        self.assertEqual(
            candidate["required_upload_targets"],
            [
                "windows-x64-installer",
                "windows-x64-partner-center",
                "windows-arm64-installer",
                "windows-arm64-partner-center",
            ],
        )
        self.assertEqual(candidate["arm64_targets_status"], "pending-owner-evidence")
        for target, filename, surface in (
            (
                "windows-arm64-installer",
                "WinsVPN-Setup-arm64.exe",
                "website",
            ),
            (
                "windows-arm64-partner-center",
                "WinsVPN-PartnerCenter-arm64.exe",
                "partner-center",
            ),
        ):
            record = candidate["pending_required_targets"][target]
            self.assertEqual(record["filename"], filename)
            self.assertEqual(record["architecture"], "arm64")
            self.assertEqual(record["surface"], surface)
            self.assertFalse(record["produced"])
            self.assertFalse(record["upload_performed"])
            self.assertFalse(record["publication_authorized"])
            self.assertEqual(record["status"], "pending-owner-evidence")

    def test_obfuscation_receipt_paths_match_contract_layout(self) -> None:
        for target_id in (
            "windows-x64-installer",
            "windows-x64-partner-center",
            "windows-arm64-installer",
            "windows-arm64-partner-center",
        ):
            layout = obfuscation.exact_obfuscation_layout(target_id)
            expected = pathlib.Path(str(layout["manifest"])).relative_to(
                obfuscation.ROOT
            ).as_posix()
            self.assertEqual(gate.obfuscation_receipt_relative(target_id), expected)

    def test_store_metadata_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-store-") as name:
            repo = pathlib.Path(name)
            shutil.copytree(ROOT / "app_store/windows", repo / "app_store/windows")
            shutil.copytree(
                ROOT / "installer/windows/store", repo / "installer/windows/store"
            )
            gate.ROOT = repo
            try:
                signoff = repo / "app_store/windows/review/owner_signoff.json"
                payload = json.loads(signoff.read_text(encoding="utf-8"))
                payload["upload_authorized"] = True
                signoff.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, "owner signoff"
                ):
                    gate._reviewed_store_metadata("windows-x64-installer")
                payload["upload_authorized"] = False
                payload["canonical_release"] = "9.9.9+1"
                signoff.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, "owner signoff"
                ):
                    gate._reviewed_store_metadata("windows-x64-installer")
                signoff.write_bytes(
                    (PACKET / "review/owner_signoff.json").read_bytes()
                )
                listing = (
                    repo / "app_store/windows/metadata/en-US/full_description.txt"
                )
                listing.write_text(
                    "Windows VPN app without a protocol.\n", encoding="ascii"
                )
                with self.assertRaisesRegex(gate.WindowsArtifactGateError, "Winn v3"):
                    gate._reviewed_store_metadata("windows-x64-installer")
                listing.write_text(
                    "Winn v3 primary and AWG then Xray fallback as MSIX.\n",
                    encoding="ascii",
                )
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, "not MSIX"
                ):
                    gate._reviewed_store_metadata("windows-x64-installer")
            finally:
                gate.ROOT = ROOT

    def test_arm64_store_metadata_remains_owner_blocked(self) -> None:
        with self.assertRaisesRegex(
            gate.WindowsArtifactGateError,
            r"owner/environment blocker:.*ARM64",
        ):
            gate._reviewed_store_metadata("windows-arm64-installer")

    def test_certification_notes_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-notes-") as name:
            repo = pathlib.Path(name)
            shutil.copytree(ROOT / "app_store/windows", repo / "app_store/windows")
            shutil.copytree(
                ROOT / "installer/windows/store", repo / "installer/windows/store"
            )
            gate.ROOT = repo
            try:
                notes = repo / "installer/windows/store/certification-notes.md"
                notes.write_bytes(
                    notes.read_bytes().replace(
                        b"OWNER-BLOCKED: ABSENT", b"owner supplied"
                    )
                )
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, "certification notes"
                ):
                    gate._reviewed_store_metadata("windows-x64-installer")
            finally:
                gate.ROOT = ROOT


class WindowsStoreMetadataHonestyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = current_windows_identity()

    def test_live_packet_matches_current_identity_and_stays_owner_blocked(self) -> None:
        require_honest_windows_store_packet(PACKET, self.identity)
        self.assertEqual(self.identity["canonical_release"], "1.0.17+34")
        self.assertEqual(self.identity["product_version"], "1.0.17")
        self.assertEqual(self.identity["four_part_version"], "1.0.17.34")

    def test_listing_false_greens_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-listing-") as name:
            packet = pathlib.Path(name) / "app_store/windows"
            shutil.copytree(PACKET, packet)
            listing = packet / "metadata/en-US/full_description.txt"
            listing.write_text(
                listing.read_text(encoding="ascii").replace(
                    "This listing does not\nattach a current 1.0.17+34 signed installer.",
                    "Install the signed x64 offline Win32 installer.",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "Install the signed"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            listing.write_bytes(
                (PACKET / "metadata/en-US/full_description.txt").read_bytes()
            )
            search = packet / "metadata/en-US/search_terms.txt"
            search.write_text(
                search.read_text(encoding="ascii").replace(
                    "no browsing history", "no logs"
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "no logs"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            search.write_bytes(
                (PACKET / "metadata/en-US/search_terms.txt").read_bytes()
            )
            features = packet / "metadata/en-US/features.txt"
            features.write_text(
                features.read_text(encoding="ascii").replace(
                    "Offline x64 Win32 installer with one UAC prompt",
                    "Signed x64 offline Win32 installer with one UAC prompt",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "current signed installer"
            ):
                require_honest_windows_store_packet(packet, self.identity)

    def test_candidate_hash_and_produced_false_greens_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-candidate-") as name:
            packet = pathlib.Path(name) / "app_store/windows"
            shutil.copytree(PACKET, packet)
            path = packet / "artifacts/release_candidate.json"
            payload = _load_json(path)
            fake = "a" * 64
            payload["targets"]["windows-x64-installer"]["sha256"] = fake
            payload["targets"]["windows-x64-installer"]["size_bytes"] = 12
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "current candidate bytes"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            payload = _load_json(PACKET / "artifacts/release_candidate.json")
            payload["targets"]["windows-x64-installer"]["produced"] = True
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "current candidate bytes"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            payload = _load_json(PACKET / "artifacts/release_candidate.json")
            payload["installer_sha256"] = fake
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "OWNER-BLOCKED: ABSENT"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            payload = _load_json(PACKET / "artifacts/release_candidate.json")
            payload["canonical_release"] = "1.0.14+29"
            payload["pubspec_version"] = "1.0.14+29"
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "current Windows identity"
            ):
                require_honest_windows_store_packet(packet, self.identity)

    def test_export_and_age_false_greens_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-export-") as name:
            packet = pathlib.Path(name) / "app_store/windows"
            shutil.copytree(PACKET, packet)
            export_path = packet / "review/export_compliance_status.json"
            payload = _load_json(export_path)
            payload["exemption_claimed"] = True
            payload["status"] = "approved"
            export_path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "export-compliance status"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            payload = _load_json(PACKET / "review/export_compliance_status.json")
            payload["uses_encryption"] = False
            export_path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "export-compliance status"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            export_path.write_bytes(
                (PACKET / "review/export_compliance_status.json").read_bytes()
            )
            age_path = packet / "review/age_rating_status.json"
            age = _load_json(age_path)
            age["status"] = "approved"
            age["iarc_completed"] = True
            age["rating_value"] = "Everyone"
            age_path.write_text(json.dumps(age) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "age rating"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            signoff_path = packet / "review/owner_signoff.json"
            age_path.write_bytes(
                (PACKET / "review/age_rating_status.json").read_bytes()
            )
            signoff = _load_json(signoff_path)
            signoff["owner_state"] = "owner supplied"
            signoff_path.write_text(json.dumps(signoff) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "OWNER-BLOCKED: ABSENT"
            ):
                require_honest_windows_store_packet(packet, self.identity)

    def test_notes_invented_hash_or_missing_owner_blocked_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="windows-notes-") as name:
            packet = pathlib.Path(name) / "app_store/windows"
            shutil.copytree(PACKET, packet)
            notes = packet / "review/partner_center_notes.txt"
            notes.write_bytes(
                notes.read_bytes().replace(
                    b"OWNER-BLOCKED: ABSENT", b"owner supplied"
                )
            )
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "OWNER-BLOCKED: ABSENT"
            ):
                require_honest_windows_store_packet(packet, self.identity)
            notes.write_bytes(
                (PACKET / "review/partner_center_notes.txt").read_bytes()
            )
            text = notes.read_text(encoding="ascii")
            notes.write_text(
                text.replace(
                    "Exact installer SHA-256: OWNER-BLOCKED: ABSENT",
                    "Exact installer SHA-256: "
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                WindowsStoreMetadataHonestyError, "installer hashes"
            ):
                require_honest_windows_store_packet(packet, self.identity)


class WindowsAppxManifestGuardTests(unittest.TestCase):
    MANIFEST = ROOT / "installer/windows/store/AppxManifest.xml.template"

    def setUp(self) -> None:
        self.raw = self.MANIFEST.read_bytes()
        self.text = self.raw.decode("ascii")

    def test_manifest_is_ascii_and_never_a_store_upload_target(self) -> None:
        self.assertEqual(self.raw.decode("ascii"), self.text)
        self.assertIn("never a Store upload target", self.text)
        self.assertIn("Non-production compatibility experiment", self.text)
        self.assertIn("Authenticode-signed", self.text)

    def test_manifest_description_names_winn_v3_primary_awg_then_xray(self) -> None:
        self.assertIn("Winn Protocol v3", self.text)
        self.assertIn("Winn v1 AmneziaWG then Xray fallback", self.text)
        self.assertNotIn("AmneziaWG and Xray VPN connectivity", self.text)

    def test_manifest_does_not_hardcode_a_single_architecture(self) -> None:
        self.assertIn("@PROCESSOR_ARCHITECTURE@", self.text)
        self.assertNotIn('ProcessorArchitecture="x64"', self.text)

    def test_manifest_keeps_restricted_capability_truthfulness_note(self) -> None:
        self.assertIn('<rescap:Capability Name="runFullTrust" />', self.text)
        self.assertIn('<rescap:Capability Name="allowElevation" />', self.text)
        self.assertIn(
            "Both restricted capabilities require truthful Partner Center notes",
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
