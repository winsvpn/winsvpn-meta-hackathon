#!/usr/bin/env python3
"""Regressions for tools/website_download_publication.py (the receipt producer).

The producer must copy every receipt field from a record it has checked, and
its output must satisfy tools/website_download_custody.py. These tests build a
synthetic Windows evidence directory with the same record shapes as the real
p5cbb83b7 BUILD_RECEIPT.json; the signed Winn release verifier is stubbed
because its key is the owner's release authority.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "website_download_publication", ROOT / "tools" / "website_download_publication.py"
)
assert SPEC is not None and SPEC.loader is not None
PUB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PUB
SPEC.loader.exec_module(PUB)
CUSTODY = PUB.CUSTODY

FILENAME = "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe"
ARTIFACT = b"MZ" + bytes(range(256)) * 8
RULINGS = (
    "# Owner rulings\n"
    '- Windows: "Ship unsigned". Windows x64 and ARM64 installers ship unsigned from the website.\n'
    '- Website downloads: "Publish now": publish the verified desktop downloads.\n'
    '- Website download gates (2026-10-25): "Build it properly": a recorded owner waiver that labels Windows "Unsigned".\n'
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_receipt(*, signing: str = "unsigned", scan_result: str = "pass", target: str = "windows-arm64-inno-unsigned") -> dict[str, Any]:
    artifact = {"name": FILENAME, "sha256": sha(ARTIFACT), "size_bytes": len(ARTIFACT)}
    scan = {
        "record": {
            "artifact": dict(artifact),
            "contract": "winsvpn-release-host-secret-scan-v2",
            "inventory": {
                "label_count": 56,
                "revision": "r3-1.0.16+33-local-20261015",
                "sha256": "4" * 64,
                "unique_value_count": 56,
            },
            "matched_labels": [],
            "platform": "windows",
            "result": scan_result,
            "scanned_utc": "2026-10-25T07:47:43.731457Z",
            "target_id": "windows-arm64-installer",
        },
        "sha256": "5" * 64,
    }
    return {
        "artifact": {**artifact, "modified_time_ns": 1},
        "build_attempt": {"claim_record": {"release_host_secret_scan": scan}},
        "contract": "winsvpn-build-receipt-v1",
        "finished_utc": "2026-10-25T07:50:01.123456Z",
        "platform": "windows",
        "producer": {"path": "installer/windows/build_installer.ps1", "sha256": "6" * 64},
        "release": "1.0.16+33",
        "remote_attestation": {
            "run_record": {
                "record": {
                    "artifact": dict(artifact),
                    "remote_system": {"machine": "AMD64", "system": "Windows"},
                    "signing": signing,
                }
            }
        },
        "shared_revision": "7" * 40,
        "toolchain": {"name": "Flutter", "target": target, "version": "3.47.6"},
    }


def write_evidence(directory: Path, receipt: dict[str, Any], *, artifact: bytes = ARTIFACT) -> None:
    directory.mkdir(parents=True)
    raw = json.dumps(receipt, indent=2).encode("ascii")
    (directory / "BUILD_RECEIPT.json").write_bytes(raw)
    (directory / "BUILD_RECEIPT.json.sha256").write_text(f"{sha(raw)}  BUILD_RECEIPT.json\n", encoding="ascii")
    (directory / FILENAME).write_bytes(artifact)
    (directory / "build-p5-windows-arm64.guest.log").write_bytes(
        b"Verifying Winn release E:\\d21\\winn-release-windows\r\n"
        b"Staged the release-verified, role-checked Winn Protocol v3 datapath and relay for arm64.\r\n"
    )


def fake_winn_release(_release_dir: Path) -> tuple[dict[str, Any], str, str]:
    manifest = {
        "artifacts": [
            {"target": "datapath-windows-arm64", "sha256": "8" * 64},
            {"target": "winn3-relay-windows-arm64", "sha256": "9" * 64},
        ],
        "source": {"commit": "b556f47f985250af862d1d712de032d99edd614c", "tree_sha256": "a" * 64},
    }
    return manifest, "b" * 64, CUSTODY.pinned_winn_authority_key()


class PublicationProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "repo"
        (self.root / "web" / "releases").mkdir(parents=True)
        shutil.copy2(ROOT / "web" / ".assetsignore", self.root / "web" / ".assetsignore")
        for name in ("downloads.json", "download-custody.json"):
            shutil.copy2(ROOT / "web" / "releases" / name, self.root / "web" / "releases" / name)
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "web"], check=True)
        self.evidence = base / "evidence" / "windows-arm64"
        self.rulings = base / "owner_rulings_release_targets_20261021.md"
        self.rulings.write_text(RULINGS, encoding="utf-8")
        self.ledger_dir = base / "ledger"
        previous_ledger = os.environ.get(CUSTODY.RELEASE_LEDGER_ENV)
        os.environ[CUSTODY.RELEASE_LEDGER_ENV] = str(self.ledger_dir / "download-custody-consumed.jsonl")
        self.addCleanup(
            lambda: os.environ.pop(CUSTODY.RELEASE_LEDGER_ENV, None)
            if previous_ledger is None
            else os.environ.__setitem__(CUSTODY.RELEASE_LEDGER_ENV, previous_ledger)
        )
        self.real_winn = PUB.verified_winn_release
        PUB.verified_winn_release = fake_winn_release
        self.addCleanup(setattr, PUB, "verified_winn_release", self.real_winn)

    def run_tool(self, *args: str) -> int:
        return PUB.main(["--root", str(self.root), *args])

    def prepare(self) -> int:
        return self.run_tool(
            "prepare",
            "--evidence", f"windows-arm64={self.evidence}",
            "--winn-release-windows", str(self.root / "unused-winn"),
            "--rulings", str(self.rulings),
        )

    def test_prepare_output_satisfies_custody_receipt_and_owner_rules(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.assertEqual(self.run_tool("challenge"), 0)
        self.assertEqual(self.prepare(), 0)
        manifest = json.loads((self.root / CUSTODY.MANIFEST_RELATIVE).read_text("ascii"))
        entries = {entry["id"]: entry for entry in manifest["artifacts"]}
        self.assertEqual(manifest["schema"], "winsvpn-download-manifest-v2")
        self.assertEqual(entries["macos"]["status"], "store_pending")
        self.assertEqual(entries["windows-x64"]["status"], "verification_pending")
        artifact = entries["windows-arm64"]["artifact"]
        self.assertEqual(artifact["unsigned_waiver"]["label"], "Unsigned")
        self.assertEqual(artifact["filename"], FILENAME)
        prefix = "artifact windows-arm64"
        self.assertEqual(CUSTODY.available_artifact_schema_errors("windows-arm64", artifact, prefix), [])
        self.assertEqual(
            CUSTODY.artifact_hosted_receipt_file_errors(self.root, "windows-arm64", artifact, prefix), []
        )
        now = datetime.now(timezone.utc)
        owner, owner_sha = CUSTODY.load_owner_evidence(self.root, now=now)
        waiver, waiver_sha = CUSTODY.load_unsigned_waiver(self.root)
        self.assertEqual(artifact["signature"]["sha256"], waiver_sha)
        self.assertEqual(waiver["entries"], ["windows-arm64"])
        challenge = CUSTODY.load_challenge(self.root, now=now)
        publication = json.loads(
            (self.root / "web" / "downloads" / f"{FILENAME}.publication.json").read_text("ascii")
        )
        self.assertEqual(
            CUSTODY.publication_receipt_errors(
                publication,
                platform_id="windows-arm64",
                artifact=artifact,
                owner=owner,
                owner_sha256=owner_sha,
                owner_platform=owner["platforms"][0],
                challenge=challenge,
                now=now,
                prefix=prefix,
            ),
            [],
        )
        release = json.loads((self.root / "web" / "downloads" / f"{FILENAME}.release.json").read_text("ascii"))
        receipt_raw = (self.evidence / "BUILD_RECEIPT.json").read_bytes()
        self.assertEqual(release["build"]["receipt_sha256"], sha(receipt_raw))
        self.assertEqual(release["build"]["toolchain_target"], "windows-arm64-inno-unsigned")
        privacy = json.loads((self.root / "web" / "downloads" / f"{FILENAME}.privacy.json").read_text("ascii"))
        self.assertEqual(privacy["scan"]["record_sha256"], "5" * 64)
        self.assertNotIn("downloads/", (self.root / "web" / ".assetsignore").read_text("utf-8").splitlines())

    def test_bytes_that_do_not_match_the_build_receipt_are_refused(self) -> None:
        write_evidence(self.evidence, build_receipt(), artifact=ARTIFACT + b"x")
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 1)
        self.assertFalse((self.root / "web" / "downloads").exists())

    def test_signed_build_record_cannot_be_published_as_unsigned(self) -> None:
        write_evidence(self.evidence, build_receipt(signing="authenticode"))
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 1)

    def test_failed_privacy_scan_is_refused(self) -> None:
        write_evidence(self.evidence, build_receipt(scan_result="fail"))
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 1)

    def test_wrong_architecture_target_is_refused(self) -> None:
        write_evidence(self.evidence, build_receipt(target="windows-x64-inno-unsigned"))
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 1)

    def test_anchor_mismatch_is_refused(self) -> None:
        write_evidence(self.evidence, build_receipt())
        (self.evidence / "BUILD_RECEIPT.json.sha256").write_text("0" * 64 + "  BUILD_RECEIPT.json\n", encoding="ascii")
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 1)

    def test_missing_owner_ruling_is_refused(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.rulings.write_text("# nothing approved\n", encoding="utf-8")
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 1)

    def test_prepare_requires_a_fresh_verifier_challenge(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.assertEqual(self.prepare(), 1)

    def test_stage_splits_r2_objects_from_the_pages_upload(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        real_gate = PUB.load_public_gate
        PUB.load_public_gate = lambda: SimpleNamespace(
            evaluate_tree=lambda root: SimpleNamespace(status="ready", summary="READY synthetic gate")
        )
        self.addCleanup(setattr, PUB, "load_public_gate", real_gate)
        out = Path(self.temp.name) / "stage"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 0)
        plan = json.loads((out / "r2-upload-plan.json").read_text("ascii"))
        key = f"downloads/sha256/{sha(ARTIFACT)}"
        self.assertEqual([item["key"] for item in plan["objects"]], [key])
        self.assertEqual((out / "r2" / key).read_bytes(), ARTIFACT)
        self.assertFalse((out / "pages" / "downloads" / FILENAME).exists())
        self.assertTrue((out / "pages" / "downloads" / f"{FILENAME}.release.json").is_file())
        self.assertTrue((out / "pages" / "releases" / "download-unsigned-waiver.json").is_file())
        self.assertFalse((out / "pages" / "releases" / "owner-publication-evidence.json").exists())
        self.assertFalse((out / "pages" / ".assetsignore").exists())
        self.assertIn("wrangler r2 object put winsvpn-website-downloads/" + key, plan["objects"][0]["upload"])

    def test_stage_refuses_untracked_public_file(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        (self.root / "web" / "credentials.txt").write_text("AUDIT_CANARY", encoding="ascii")
        out = Path(self.temp.name) / "stage"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 1)
        self.assertFalse((out / "r2-upload-plan.json").exists())


    def stub_gate(self, status: str = "ready") -> list[Path]:
        calls: list[Path] = []
        real_gate = PUB.load_public_gate

        def evaluate(root: Path) -> SimpleNamespace:
            calls.append(root)
            return SimpleNamespace(status=status, summary=f"{status.upper()} synthetic gate")

        PUB.load_public_gate = lambda: SimpleNamespace(evaluate_tree=evaluate)
        self.addCleanup(setattr, PUB, "load_public_gate", real_gate)
        return calls

    def test_waiver_publishes_no_private_ruling_text(self) -> None:
        # DLP-06: the marker lines may carry private context; only the fixed
        # public marker, record name and digest may reach the public waiver.
        self.rulings.write_text(
            RULINGS.replace('"Ship unsigned".', '"Ship unsigned". PRIVATE_CANARY=123'), encoding="utf-8"
        )
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        waiver_raw = (self.root / CUSTODY.UNSIGNED_WAIVER_RELATIVE).read_text("ascii")
        self.assertNotIn("PRIVATE_CANARY", waiver_raw)
        self.assertNotIn("Publish now", waiver_raw)
        self.assertNotIn("Ship unsigned", waiver_raw)
        self.assertNotIn(self.rulings.name, waiver_raw)
        waiver = json.loads(waiver_raw)
        self.assertEqual(
            waiver["owner_ruling"],
            {"reference": CUSTODY.UNSIGNED_WAIVER_PUBLIC_REFERENCE},
        )
        CUSTODY.load_unsigned_waiver(self.root)

    def test_stage_runs_the_final_gate_after_copying_and_stops_unless_ready(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        calls = self.stub_gate("blocked")
        out = Path(self.temp.name) / "stage-blocked"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 1)
        self.assertEqual(calls, [self.root.resolve()])
        self.assertFalse((out / "r2-upload-plan.json").exists())

    def test_stage_refuses_output_inside_the_checkout_and_malformed_manifest(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        self.stub_gate()
        self.assertEqual(self.run_tool("stage", "--out", str(self.root / "stage")), 1)
        (self.root / CUSTODY.MANIFEST_RELATIVE).write_text('{"schema":"bad","artifacts":[]}', encoding="ascii")
        self.assertEqual(self.run_tool("stage", "--out", str(Path(self.temp.name) / "stage-bad")), 1)

    def test_prepare_refuses_a_challenge_that_was_already_consumed(self) -> None:
        # Argon F-2: re-running prepare under a consumed challenge must stop
        # before writing anything.
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        challenge = CUSTODY.load_challenge(self.root, now=datetime.now(timezone.utc))
        CUSTODY.consume_replay(
            self.root,
            issuance_id="1" * 32,
            nonce="2" * 32,
            challenge_nonce=challenge["nonce"],
            owner_evidence_sha256="3" * 64,
            artifact_sha256=sha(ARTIFACT),
            now=datetime.now(timezone.utc),
        )
        self.assertEqual(self.prepare(), 1)
        self.assertFalse((self.root / "web" / "downloads").exists())
        self.assertFalse((self.root / CUSTODY.OWNER_EVIDENCE_RELATIVE).exists())

    def test_prepare_refuses_a_challenge_recorded_in_the_durable_ledger(self) -> None:
        # DLP-04 cross-clone: another clone already published with this challenge.
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        challenge = CUSTODY.load_challenge(self.root, now=datetime.now(timezone.utc))
        CUSTODY.consume_release_ledger(
            issuance_id="1" * 32,
            challenge_nonce=challenge["nonce"],
            owner_evidence_sha256="3" * 64,
            nonces=["2" * 32],
            artifact_sha256s=[sha(ARTIFACT)],
            now=datetime.now(timezone.utc),
        )
        self.assertFalse((self.root / "web" / "releases" / "download-custody-consumed.jsonl").exists())
        self.assertEqual(self.prepare(), 1)
        self.assertFalse((self.root / "web" / "downloads").exists())

    def test_stage_refuses_ruling_text_or_local_paths_in_public_files(self) -> None:
        # DLP-06 round 2: grep every staged public file before the one-use gate.
        for leak in ('Owner ruling: "Ship unsigned"', "see /Users/owner/xprize/notes"):
            with self.subTest(leak=leak):
                root_name = "leak-" + str(abs(hash(leak)))
                write_evidence(self.evidence, build_receipt()) if not self.evidence.exists() else None
                if (self.root / "web" / "downloads").exists():
                    shutil.rmtree(self.root / "web" / "downloads")
                for relative in (CUSTODY.OWNER_EVIDENCE_RELATIVE, CUSTODY.UNSIGNED_WAIVER_RELATIVE, CUSTODY.CHALLENGE_RELATIVE):
                    (self.root / relative).unlink(missing_ok=True)
                self.run_tool("challenge")
                self.assertEqual(self.prepare(), 0)
                public = self.root / "web" / "support" / "notes.txt"
                public.parent.mkdir(parents=True, exist_ok=True)
                public.write_text(leak + "\n", encoding="utf-8")
                subprocess.run(["git", "-C", str(self.root), "add", "web/support/notes.txt"], check=True)
                calls = self.stub_gate()
                out = Path(self.temp.name) / root_name
                self.assertEqual(self.run_tool("stage", "--out", str(out)), 1)
                self.assertEqual(calls, [])
                self.assertFalse((out / "r2-upload-plan.json").exists())

    def test_stage_refuses_private_ruling_digest_in_public_file(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        public = self.root / "web" / "support" / "notes.txt"
        public.parent.mkdir(parents=True, exist_ok=True)
        public.write_text(sha(self.rulings.read_bytes()) + "\n", encoding="ascii")
        subprocess.run(["git", "-C", str(self.root), "add", "web/support/notes.txt"], check=True)
        calls = self.stub_gate()
        out = Path(self.temp.name) / "stage-private-digest"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 1)
        self.assertEqual(calls, [])

    def test_stage_refuses_lowercase_private_ruling_quote(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        public = self.root / "web" / "support" / "notes.txt"
        public.parent.mkdir(parents=True, exist_ok=True)
        public.write_text('owner ruling: "ship unsigned"\n', encoding="ascii")
        subprocess.run(["git", "-C", str(self.root), "add", "web/support/notes.txt"], check=True)
        calls = self.stub_gate()
        out = Path(self.temp.name) / "stage-lowercase-ruling"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 1)
        self.assertEqual(calls, [])

    def test_github_notes_and_sums_carry_no_private_text(self) -> None:
        self.rulings.write_text(
            RULINGS + "- Desktop download hosting (2026-10-25): host on the public repo winsvpn/winsvpn-downloads.\n",
            encoding="utf-8",
        )
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare_github(), 0)
        self.stub_gate()
        out = Path(self.temp.name) / "stage-github-leakcheck"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 0)
        public_text = "".join(
            path.read_text("utf-8", errors="replace")
            for path in [out / "github-release-notes.md", out / "github" / "SHA256SUMS", *sorted((out / "pages").rglob("*.json"))]
        )
        for marker in PUB.PUBLIC_LEAK_MARKERS:
            self.assertNotIn(marker, public_text)
        self.assertNotIn(self.rulings.name, public_text)
        self.assertNotIn(sha(self.rulings.read_bytes()), public_text)

    def test_stage_commands_are_shell_quoted(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare(), 0)
        self.stub_gate()
        out = Path(self.temp.name) / "it's; touch PWNED"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 0)
        plan = json.loads((out / "r2-upload-plan.json").read_text("ascii"))
        import shlex

        argv = shlex.split(plan["objects"][0]["upload"])
        self.assertEqual(argv[argv.index("--file") + 1], plan["objects"][0]["local_path"])
        self.assertEqual(shlex.split(plan["pages_deploy"])[4], str(out.resolve() / "pages"))

    def prepare_github(self) -> int:
        return self.run_tool(
            "prepare",
            "--delivery", "github",
            "--evidence", f"windows-arm64={self.evidence}",
            "--winn-release-windows", str(self.root / "unused-winn"),
            "--rulings", str(self.rulings),
        )

    def test_github_delivery_requires_the_recorded_repo_ruling(self) -> None:
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare_github(), 1)
        self.assertFalse((self.root / "web" / "downloads").exists())
        self.assertFalse((self.root / CUSTODY.UNSIGNED_WAIVER_RELATIVE).exists())

    def test_github_delivery_pins_the_release_asset_and_stages_it(self) -> None:
        self.rulings.write_text(
            RULINGS + "- Desktop downloads (2026-10-25): host the binaries on the public repo winsvpn/winsvpn-downloads.\n",
            encoding="utf-8",
        )
        write_evidence(self.evidence, build_receipt())
        self.run_tool("challenge")
        self.assertEqual(self.prepare_github(), 0)
        manifest = json.loads((self.root / CUSTODY.MANIFEST_RELATIVE).read_text("ascii"))
        entry = {item["id"]: item for item in manifest["artifacts"]}["windows-arm64"]
        pinned = "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/" + FILENAME
        self.assertEqual(entry["delivery"], {"kind": "github_release", "url": pinned})
        owner, _ = CUSTODY.load_owner_evidence(self.root, now=datetime.now(timezone.utc))
        self.assertTrue(any("winsvpn/winsvpn-downloads" in line for line in owner["owner_ruling"]["lines"]))
        private_readme = self.root / "web" / "releases" / "README.md"
        private_readme.write_text('Owner ruling: "Ship unsigned" PRIVATE_CANARY=123\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "web/releases/README.md"], check=True)
        self.stub_gate()
        out = Path(self.temp.name) / "stage-github"
        self.assertEqual(self.run_tool("stage", "--out", str(out)), 0)
        plan = json.loads((out / "r2-upload-plan.json").read_text("ascii"))
        self.assertEqual(plan["objects"], [])
        release = plan["github_release"]
        self.assertEqual((release["repo"], release["tag"]), ("winsvpn/winsvpn-downloads", "v1.0.16-33"))
        self.assertEqual(release["assets"][0]["url"], pinned)
        self.assertEqual((out / "github" / FILENAME).read_bytes(), ARTIFACT)
        self.assertEqual(
            (out / "github" / "SHA256SUMS").read_text("ascii"), f"{sha(ARTIFACT)}  {FILENAME}\n"
        )
        self.assertIn("gh release create v1.0.16-33 --repo winsvpn/winsvpn-downloads", release["create"])
        self.assertIn("Unsigned", (out / "github-release-notes.md").read_text("ascii"))
        self.assertFalse((out / "pages" / "downloads" / FILENAME).exists())
        self.assertTrue((out / "pages" / "downloads" / f"{FILENAME}.sha256").is_file())
        self.assertFalse((out / "pages" / "releases" / "README.md").exists())


if __name__ == "__main__":
    unittest.main()
