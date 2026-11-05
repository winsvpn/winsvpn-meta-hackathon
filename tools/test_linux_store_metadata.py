#!/usr/bin/env python3
"""Linux x64 store metadata and 1.0.17+34 distribution contracts."""

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

import linux_cross_store_artifact_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]


class LinuxStoreMetadataTests(unittest.TestCase):
    def test_store_packet_is_ascii_and_canonical(self) -> None:
        packet = ROOT / "app_store/linux"
        self.assertTrue(packet.is_dir())
        for path in packet.rglob("*"):
            if path.is_file():
                path.read_bytes().decode("ascii")
        reviewed = gate._reviewed_store_metadata("linux-x64-package")
        self.assertEqual(reviewed["canonical_release"], "1.0.17+34")
        self.assertEqual(reviewed["appstream_version"], "1.0.17")
        self.assertEqual(reviewed["debian_version"], "1.0.17-34")
        self.assertEqual(reviewed["form"], "linux-x64")
        self.assertFalse(reviewed["submission_approved"])
        self.assertFalse(reviewed["upload_authorized"])
        self.assertFalse(reviewed["private_symbols_uploaded"])
        self.assertFalse(reviewed["appimage_upload_target"])
        self.assertEqual(reviewed["listing_screenshot_inventory"], "owner-blocked")
        self.assertEqual(reviewed["tunnel_protocol"]["primary"], "winn-v3")
        self.assertEqual(reviewed["tunnel_protocol"]["fallback"], ["awg", "xray"])
        self.assertIn("winn-datapath", reviewed["tunnel_protocol"]["required_local_engines"])
        self.assertEqual(
            reviewed["tunnel_protocol"]["required_native_host"],
            "tools/native_messaging/host/wins_bridge_host",
        )
        flathub = gate._reviewed_store_metadata("linux-flathub-manifest")
        snap = gate._reviewed_store_metadata("linux-snap-manifest")
        self.assertEqual(reviewed["sha256"], flathub["sha256"])
        self.assertEqual(reviewed["sha256"], snap["sha256"])
        self.assertIn(
            "app_store/linux/review/privacy_label_manifest.json", reviewed["files"]
        )
        self.assertIn("linux/packaging/org.winsvpn.app.metainfo.xml", reviewed["files"])
        self.assertIn("linux/packaging/org.winsvpn.app.desktop", reviewed["files"])
        self.assertEqual(
            reviewed["obfuscation_receipts"]["linux-x64-package"],
            gate.obfuscation_receipt_relative("linux-x64-package"),
        )

    def test_listing_and_notes_name_protocol_and_x64_filenames(self) -> None:
        listing = (
            ROOT / "app_store/linux/metadata/en-US/full_description.txt"
        ).read_text(encoding="ascii")
        notes = (
            ROOT / "app_store/linux/review/distribution_notes.txt"
        ).read_text(encoding="ascii")
        short = (
            ROOT / "app_store/linux/metadata/en-US/short_description.txt"
        ).read_text(encoding="ascii").strip()
        title = (
            ROOT / "app_store/linux/metadata/en-US/title.txt"
        ).read_text(encoding="ascii").strip()
        self.assertEqual(title, "Win's VPN")
        self.assertIn("Winn v3", listing)
        self.assertIn("AWG then Xray", listing)
        self.assertIn("not an AppImage", listing)
        self.assertIn("native tarball", listing)
        self.assertIn("dual-arch", listing)
        search_terms = (
            ROOT / "app_store/linux/metadata/en-US/search_terms.txt"
        ).read_text(encoding="ascii")
        self.assertNotIn("no logs", search_terms)
        self.assertIn("no browsing history", search_terms)
        self.assertIn("wins-vpn-linux-x64.tar.gz", notes)
        self.assertIn("wins-vpn_1.0.17-34_amd64.deb", notes)
        self.assertIn("wins-vpn-1.0.17-x86_64.AppImage", notes)
        self.assertIn("winn-datapath", notes)
        self.assertIn("Winn v3", notes)
        self.assertIn("AWG then Xray", short)

    def test_cosign_trust_anchor_claims_follow_the_gate_pin(self) -> None:
        # The ceremony key is pinned (aca7fea); the packet must not still call
        # the trust anchor absent, and the notes stay free of digests.
        self.assertFalse(gate.owner_cosign_trust_anchor_blocked())
        anchor = gate.TRUSTED_LOCAL_COSIGN_KEY.as_posix()
        notes = (
            ROOT / "app_store/linux/review/distribution_notes.txt"
        ).read_text(encoding="ascii")
        readme = " ".join(
            (ROOT / "app_store/linux/README.md").read_text(encoding="ascii").split()
        )
        self.assertNotIn(
            "Local cosign/Sigstore trust anchor: OWNER-BLOCKED: ABSENT", notes
        )
        self.assertIn(f"Local cosign/Sigstore trust anchor: committed as {anchor}", notes)
        self.assertNotIn("the local cosign/Sigstore identity, and Flathub", readme)
        self.assertIn(f"trust anchor is committed at `{anchor}`", readme)

    def test_owner_signoff_and_candidate_remain_unuploaded(self) -> None:
        signoff = json.loads(
            (ROOT / "app_store/linux/review/owner_signoff.json").read_text(
                encoding="ascii"
            )
        )
        candidate = json.loads(
            (
                ROOT / "app_store/linux/artifacts/release_candidate.json"
            ).read_text(encoding="ascii")
        )
        self.assertFalse(signoff["submission_approved"])
        self.assertFalse(signoff["upload_authorized"])
        self.assertFalse(signoff["appimage_upload_authorized"])
        self.assertEqual(signoff["canonical_release"], "1.0.17+34")
        self.assertEqual(signoff["debian_version"], "1.0.17-34")
        self.assertEqual(candidate["candidate_set_status"], "no_current_candidate")
        self.assertFalse(candidate["private_symbols"]["uploaded"])
        self.assertFalse(candidate["appimage"]["upload_target"])
        self.assertFalse(candidate["deb"]["upload_target"])
        self.assertEqual(candidate["deb"]["filename"], "wins-vpn_1.0.17-34_amd64.deb")
        self.assertEqual(
            candidate["private_symbols"]["x64"],
            ".artifacts/private-release-symbols/linux/x64/1.0.17+34",
        )
        for target in (
            "linux-x64-package",
            "linux-flathub-manifest",
            "linux-snap-manifest",
        ):
            record = candidate["targets"][target]
            self.assertFalse(record["produced"])
            self.assertFalse(record["upload_performed"])
            self.assertFalse(record["publication_authorized"])
            self.assertEqual(record["architecture"], "x64")
        self.assertEqual(
            candidate["required_upload_targets"],
            [
                "linux-x64-package",
                "linux-arm64-package",
                "linux-flathub-manifest",
                "linux-snap-manifest",
            ],
        )
        self.assertEqual(candidate["required_artifact_kinds"]["linux-x64-package"], "tarball")
        self.assertEqual(candidate["required_artifact_kinds"]["linux-arm64-package"], "tarball")
        self.assertNotEqual(candidate["required_artifact_kinds"]["linux-x64-package"], "DEB")
        self.assertEqual(
            candidate["required_artifact_kinds"]["linux-flathub-manifest"],
            "flatpak-manifest",
        )
        self.assertEqual(
            candidate["required_artifact_kinds"]["linux-snap-manifest"],
            "snap-manifest",
        )
        self.assertNotEqual(
            candidate["required_artifact_kinds"]["linux-flathub-manifest"], "DEB"
        )
        self.assertNotEqual(
            candidate["required_artifact_kinds"]["linux-snap-manifest"], "tarball"
        )
        self.assertEqual(candidate["targets"]["linux-x64-package"]["kind"], "tarball")
        self.assertEqual(
            candidate["targets"]["linux-flathub-manifest"]["required_architectures"],
            ["x64", "arm64"],
        )
        self.assertEqual(
            candidate["targets"]["linux-snap-manifest"]["required_architectures"],
            ["x64", "arm64"],
        )
        self.assertEqual(candidate["arm64_targets_status"], "pending-owner-evidence")
        arm64 = candidate["pending_required_targets"]["linux-arm64-package"]
        self.assertEqual(arm64["kind"], "tarball")
        self.assertEqual(arm64["filename"], "wins-vpn-linux-arm64.tar.gz")
        self.assertFalse(arm64["produced"])
        self.assertFalse(arm64["upload_performed"])
        self.assertFalse(arm64["publication_authorized"])
        self.assertEqual(arm64["status"], "pending-owner-evidence")

    def test_store_metadata_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-store-") as name:
            repo = pathlib.Path(name)
            shutil.copytree(ROOT / "app_store/linux", repo / "app_store/linux")
            for relative in (
                "linux/packaging/org.winsvpn.app.metainfo.xml",
                "linux/packaging/org.winsvpn.app.desktop",
            ):
                destination = repo / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            gate.ROOT = repo
            try:
                signoff = repo / "app_store/linux/review/owner_signoff.json"
                payload = json.loads(signoff.read_text(encoding="utf-8"))
                payload["upload_authorized"] = True
                signoff.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, "owner signoff"
                ):
                    gate._reviewed_store_metadata("linux-x64-package")
                payload["upload_authorized"] = False
                payload["canonical_release"] = "9.9.9+1"
                signoff.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    gate.LinuxArtifactGateError, "owner signoff"
                ):
                    gate._reviewed_store_metadata("linux-x64-package")
                signoff.write_bytes(
                    (
                        ROOT / "app_store/linux/review/owner_signoff.json"
                    ).read_bytes()
                )
                listing = (
                    repo / "app_store/linux/metadata/en-US/full_description.txt"
                )
                listing.write_text(
                    "Linux VPN app without a protocol.\n", encoding="ascii"
                )
                with self.assertRaisesRegex(gate.LinuxArtifactGateError, "Winn v3"):
                    gate._reviewed_store_metadata("linux-x64-package")
            finally:
                gate.ROOT = ROOT

    def test_appimage_and_invented_deb_targets_remain_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            "unsupported exact Linux package/upload target",
        ):
            gate._reviewed_store_metadata("linux-x64-appimage")
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            "unsupported exact Linux package/upload target",
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-deb",
                {},
                artifact_sha256="0" * 64,
                artifact_bytes=1,
            )


PACKET = ROOT / "app_store/linux"
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
    "signed x64 tarball",
    "current signed Flatpak",
    "current signed Snap",
    "screenshots approved",
    "no logs",
)
FLATHUB_SNAP_LIVE_GREENS = (
    "Flathub listing is live",
    "Snap listing is live",
    "Flathub screenshots are uploaded",
    "Snap screenshots are uploaded",
    "Flathub is submitted",
    "Snap is submitted",
)
REQUIRED_OWNER_BLOCKED_NOTES = (
    "Flathub listing: OWNER-BLOCKED: ABSENT",
    "Snap listing: OWNER-BLOCKED: ABSENT",
    "Flathub screenshots: OWNER-BLOCKED: ABSENT",
    "Snap screenshots: OWNER-BLOCKED: ABSENT",
    "Flathub privacy and review: OWNER-BLOCKED: ABSENT",
    "Snap privacy and review: OWNER-BLOCKED: ABSENT",
    "Flathub exact release declaration: OWNER-BLOCKED: ABSENT",
    "Snap exact release declaration: OWNER-BLOCKED: ABSENT",
)


class LinuxStoreMetadataHonestyError(ValueError):
    """Raised when Linux store metadata claims an owner-free green."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LinuxStoreMetadataHonestyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: pathlib.Path) -> dict[str, object]:
    try:
        payload = json.loads(
            path.read_text(encoding="ascii"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LinuxStoreMetadataHonestyError(
            f"{path.as_posix()} is not readable ASCII JSON: {exc}"
        ) from exc
    if type(payload) is not dict:
        raise LinuxStoreMetadataHonestyError(
            f"{path.as_posix()} must contain one JSON object"
        )
    return payload


def _require_ascii_file(path: pathlib.Path) -> str:
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise LinuxStoreMetadataHonestyError(
            f"{path.as_posix()} must be ASCII"
        ) from exc
    if raw.decode("ascii") != text:
        raise LinuxStoreMetadataHonestyError(
            f"{path.as_posix()} must be ASCII"
        )
    return text


def _require_absent_artifact(record: dict[str, object], label: str) -> None:
    if (
        record.get("produced") is not False
        or record.get("upload_performed") is not False
        or record.get("publication_authorized") is not False
    ):
        raise LinuxStoreMetadataHonestyError(
            f"{label} claims current candidate bytes or authorization"
        )


def require_honest_linux_store_packet(packet: pathlib.Path) -> None:
    if not packet.is_dir():
        raise LinuxStoreMetadataHonestyError("Linux store packet is missing")
    for path in packet.rglob("*"):
        if path.is_file():
            text = _require_ascii_file(path)
            for marker in PLACEHOLDER_MARKERS:
                if marker in text:
                    raise LinuxStoreMetadataHonestyError(
                        f"{path.as_posix()} contains unresolved placeholder {marker}"
                    )
            if "1.0.14+29" in text and path.name not in {
                "release_candidate.json"
            }:
                raise LinuxStoreMetadataHonestyError(
                    f"{path.as_posix()} treats 1.0.14+29 as current"
                )

    listing = _require_ascii_file(packet / "metadata/en-US/full_description.txt")
    notes = _require_ascii_file(packet / "review/distribution_notes.txt")
    short = _require_ascii_file(
        packet / "metadata/en-US/short_description.txt"
    ).strip()
    title = _require_ascii_file(packet / "metadata/en-US/title.txt").strip()
    whats_new = _require_ascii_file(packet / "metadata/en-US/whats_new.txt")
    features = _require_ascii_file(packet / "metadata/en-US/features.txt")
    search_terms = _require_ascii_file(
        packet / "metadata/en-US/search_terms.txt"
    )
    readme = _require_ascii_file(packet / "README.md")
    for required in ("Winn v3", "AWG then Xray"):
        if (
            required not in listing
            or required not in notes
            or required not in short
        ):
            raise LinuxStoreMetadataHonestyError(
                "listing copy must name Winn v3 primary and AWG then Xray fallback"
            )
    if title != "Win's VPN":
        raise LinuxStoreMetadataHonestyError("Linux listing title is not Win's VPN")
    if "not an AppImage" not in listing:
        raise LinuxStoreMetadataHonestyError(
            "Linux listing must refuse AppImage identity"
        )
    if "native tarball" not in listing:
        raise LinuxStoreMetadataHonestyError(
            "Linux listing must name the native tarball website kind"
        )
    if "dual-arch" not in listing:
        raise LinuxStoreMetadataHonestyError(
            "Linux listing must name dual-arch Flathub and Snap manifests"
        )
    if "screenshots remain owner-blocked" not in listing:
        raise LinuxStoreMetadataHonestyError(
            "Linux listing must declare Flathub and Snap screenshots owner-blocked"
        )
    if "1.0.17+34" not in whats_new + notes:
        raise LinuxStoreMetadataHonestyError(
            "listing notes must name the current canonical release"
        )
    combined_listing = listing + features + whats_new
    combined_casefold = combined_listing.casefold()
    for phrase in FALSE_GREEN_LISTING:
        if phrase.casefold() in combined_casefold:
            raise LinuxStoreMetadataHonestyError(
                f"listing copy claims owner-free green {phrase!r}"
            )
    for phrase in FLATHUB_SNAP_LIVE_GREENS:
        if phrase.casefold() in combined_casefold:
            raise LinuxStoreMetadataHonestyError(
                f"listing copy claims a live Flathub or Snap surface {phrase!r}"
            )
    if "no logs" in search_terms:
        raise LinuxStoreMetadataHonestyError(
            "search terms must not overclaim no logs"
        )
    if "no browsing history" not in search_terms:
        raise LinuxStoreMetadataHonestyError(
            "search terms must name no browsing history"
        )
    if "This package never uploads" not in notes:
        raise LinuxStoreMetadataHonestyError("distribution notes claim upload")
    if OWNER_BLOCKED_ABSENT not in notes or OWNER_BLOCKED_ABSENT not in readme:
        raise LinuxStoreMetadataHonestyError(
            "review notes and README must keep OWNER-BLOCKED: ABSENT"
        )
    for required in REQUIRED_OWNER_BLOCKED_NOTES:
        if required not in notes:
            raise LinuxStoreMetadataHonestyError(
                f"distribution notes omit required owner-blocked field {required!r}"
            )
    if SHA256_RE.search(notes) is not None or IPV4_RE.search(notes) is not None:
        raise LinuxStoreMetadataHonestyError(
            "distribution notes must not invent tarball hashes or node addresses"
        )
    if notes.count(OWNER_BLOCKED_ABSENT) < 12:
        raise LinuxStoreMetadataHonestyError(
            "distribution notes omit required OWNER-BLOCKED: ABSENT fields"
        )

    privacy = _load_json(packet / "review/privacy_label_manifest.json")
    signoff = _load_json(packet / "review/owner_signoff.json")
    candidate = _load_json(packet / "artifacts/release_candidate.json")
    for payload, label in (
        (privacy, "privacy label"),
        (signoff, "owner signoff"),
        (candidate, "release candidate"),
    ):
        if (
            payload.get("canonical_release") != "1.0.17+34"
            or payload.get("appstream_version") != "1.0.17"
            or payload.get("debian_version") != "1.0.17-34"
        ):
            raise LinuxStoreMetadataHonestyError(
                f"{label} is not the current Linux identity"
            )
    if (
        privacy.get("listing_screenshot_inventory") != "owner-blocked"
        or privacy.get("tracking") is not False
        or privacy.get("data_shared") is not False
        or privacy.get("appimage_upload_target") is not False
        or privacy.get("private_symbols_uploaded") is not False
        or privacy.get("camouflage") is not False
    ):
        raise LinuxStoreMetadataHonestyError(
            "privacy label claims completed screenshots, tracking, sharing, or upload"
        )
    for field in ("flathub_listing_status", "snap_listing_status"):
        if privacy.get(field) not in (None, "owner-blocked"):
            raise LinuxStoreMetadataHonestyError(
                f"privacy label {field} is an owner-free green"
            )
    if (
        signoff.get("submission_approved") is not False
        or signoff.get("upload_authorized") is not False
        or signoff.get("appimage_upload_authorized") is not False
        or signoff.get("listing_screenshot_inventory") != "owner-blocked"
        or signoff.get("blockers") != gate.LINUX_OWNER_SIGNOFF_BLOCKERS
    ):
        raise LinuxStoreMetadataHonestyError(
            "owner signoff claims submission, upload, or a completed blocker set"
        )
    if (
        candidate.get("candidate_set_status") != "no_current_candidate"
        or candidate.get("arm64_targets_status") != "pending-owner-evidence"
        or candidate["private_symbols"].get("uploaded") is not False
        or candidate["deb"].get("produced") is not False
        or candidate["deb"].get("upload_performed") is not False
        or candidate["deb"].get("publication_authorized") is not False
        or candidate["appimage"].get("upload_target") is not False
        or candidate["appimage"].get("production_allowed") is not False
    ):
        raise LinuxStoreMetadataHonestyError(
            "release candidate claims a current uploadable set"
        )
    for key, label in (
        ("linux-x64-package", "linux-x64-package"),
        ("linux-flathub-manifest", "Flathub exact release declaration"),
        ("linux-snap-manifest", "Snap exact release declaration"),
    ):
        record = candidate["targets"].get(key)
        if type(record) is not dict:
            raise LinuxStoreMetadataHonestyError(
                f"{label} is missing from the release candidate"
            )
        _require_absent_artifact(record, label)
    for key, label in (
        ("linux-arm64-package", "linux-arm64-package"),
    ):
        record = candidate["pending_required_targets"].get(key)
        if type(record) is not dict or record.get("status") != "pending-owner-evidence":
            raise LinuxStoreMetadataHonestyError(
                f"{label} is not pending-owner-evidence"
            )
        _require_absent_artifact(record, label)


class LinuxStoreMetadataHonestyTests(unittest.TestCase):
    def test_live_packet_stays_owner_blocked_and_honest(self) -> None:
        require_honest_linux_store_packet(PACKET)

    def test_listing_false_greens_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-listing-") as name:
            packet = pathlib.Path(name) / "app_store/linux"
            shutil.copytree(PACKET, packet)
            listing = packet / "metadata/en-US/full_description.txt"
            listing.write_text(
                listing.read_text(encoding="ascii").replace(
                    "Install the x64 native tarball",
                    "Install the signed x64 tarball",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "Install the signed"
            ):
                require_honest_linux_store_packet(packet)
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
                LinuxStoreMetadataHonestyError, "no logs"
            ):
                require_honest_linux_store_packet(packet)
            search.write_bytes(
                (PACKET / "metadata/en-US/search_terms.txt").read_bytes()
            )
            features = packet / "metadata/en-US/features.txt"
            features.write_text(
                features.read_text(encoding="ascii").replace(
                    "Native x64 tarball",
                    "Signed x64 tarball",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "signed x64 tarball"
            ):
                require_honest_linux_store_packet(packet)

    def test_flathub_and_snap_surface_greens_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-flathub-") as name:
            packet = pathlib.Path(name) / "app_store/linux"
            shutil.copytree(PACKET, packet)
            listing = packet / "metadata/en-US/full_description.txt"
            listing.write_text(
                listing.read_text(encoding="ascii")
                + "Flathub listing is live with screenshots uploaded.\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "Flathub listing is live"
            ):
                require_honest_linux_store_packet(packet)
            listing.write_bytes(
                (PACKET / "metadata/en-US/full_description.txt").read_bytes()
            )
            notes = packet / "review/distribution_notes.txt"
            notes.write_bytes(
                notes.read_bytes().replace(
                    b"Flathub exact release declaration: OWNER-BLOCKED: ABSENT",
                    b"Flathub exact release declaration: approved",
                )
            )
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "Flathub exact release"
            ):
                require_honest_linux_store_packet(packet)
            notes.write_bytes(
                (PACKET / "review/distribution_notes.txt").read_bytes()
            )
            privacy = packet / "review/privacy_label_manifest.json"
            payload = _load_json(privacy)
            payload["listing_screenshot_inventory"] = "submitted"
            privacy.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "screenshots"
            ):
                require_honest_linux_store_packet(packet)

    def test_candidate_exact_release_declaration_greens_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-candidate-") as name:
            packet = pathlib.Path(name) / "app_store/linux"
            shutil.copytree(PACKET, packet)
            path = packet / "artifacts/release_candidate.json"
            payload = _load_json(path)
            payload["targets"]["linux-flathub-manifest"]["produced"] = True
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "Flathub exact release"
            ):
                require_honest_linux_store_packet(packet)
            payload = _load_json(PACKET / "artifacts/release_candidate.json")
            payload["targets"]["linux-snap-manifest"]["publication_authorized"] = True
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "Snap exact release"
            ):
                require_honest_linux_store_packet(packet)
            payload = _load_json(PACKET / "artifacts/release_candidate.json")
            payload["private_symbols"]["uploaded"] = True
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "uploadable set"
            ):
                require_honest_linux_store_packet(packet)
            payload = _load_json(PACKET / "artifacts/release_candidate.json")
            payload["targets"]["linux-x64-package"]["upload_performed"] = True
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "linux-x64-package"
            ):
                require_honest_linux_store_packet(packet)

    def test_notes_invented_hash_or_missing_owner_blocked_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="linux-notes-") as name:
            packet = pathlib.Path(name) / "app_store/linux"
            shutil.copytree(PACKET, packet)
            notes = packet / "review/distribution_notes.txt"
            notes.write_bytes(
                notes.read_bytes().replace(
                    b"OWNER-BLOCKED: ABSENT", b"owner supplied"
                )
            )
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "OWNER-BLOCKED: ABSENT"
            ):
                require_honest_linux_store_packet(packet)
            notes.write_bytes(
                (PACKET / "review/distribution_notes.txt").read_bytes()
            )
            text = notes.read_text(encoding="ascii")
            notes.write_text(
                text.replace(
                    "Current signed x64 tarball: OWNER-BLOCKED: ABSENT",
                    "Current signed x64 tarball: "
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                LinuxStoreMetadataHonestyError, "tarball hashes"
            ):
                require_honest_linux_store_packet(packet)


if __name__ == "__main__":
    unittest.main()
