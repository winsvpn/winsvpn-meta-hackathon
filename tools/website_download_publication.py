#!/usr/bin/env python3
"""Produce the website download publication tree from real build evidence.

Owner ruling 2026-10-25 ("Build it properly"): large desktop artifacts are
hosted in Cloudflare R2 and served only through the Worker's manifest gate,
one manifest entry per architecture, Windows ships under a recorded owner
waiver labelled "Unsigned", and Apple stays store_pending.

This tool writes the files tools/website_download_custody.py and
tools/verify_website_public_download_gate.py demand. Every receipt field is
copied from a record it reads and checks first; nothing is invented:

* artifact bytes, size, SHA-256: the exact producer output, re-hashed here and
  matched against BUILD_RECEIPT.json (whose .sha256 anchor is checked);
* <artifact>.privacy.json: the release-host secret scan inside
  BUILD_RECEIPT.json (Windows) or MAC_REAL_INVENTORY_SCAN.txt (Linux);
* <artifact>.release.json: BUILD_RECEIPT.json (producer, toolchain target,
  signing mode, shared revision, remote machine);
* <artifact>.winn.json: the signed Winn engine release, verified by
  tools/winn_release.py verify; Linux engines are measured inside the tarball,
  Windows engines are bound to the producer log line that staged them;
* download-unsigned-waiver.json and owner-publication-evidence.json: the
  quoted owner ruling lines and the SHA-256 of the rulings record;
* <artifact>.publication.json: the owner evidence, the verifier challenge and
  the manifest binding.

Delivery: --delivery r2 (default) binds /downloads/<file> served from R2;
--delivery github (owner update 2026-10-25, Workers Free plan) binds the pinned
public release asset https://github.com/winsvpn/winsvpn-downloads/releases/
download/v1.0.16-33/<file> and requires the rulings record to name that repo.

Subcommands (run from a clean clone; nothing here uploads, deploys or reads
credentials):

  challenge   issue the one-use verifier challenge
  prepare     write artifacts, sidecars, receipts, waiver, owner evidence and
              the available manifest for the named entries
  stage       after the final gate PASSes, split the tree into the Pages upload
              directory and the content-addressed R2 objects plus an upload plan
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import secrets
import shlex
import stat
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CUSTODY_PATH = ROOT / "tools" / "website_download_custody.py"
PAGES_MAX_ASSET_BYTES = 25 * 1024 * 1024
R2_BUCKET = "winsvpn-website-downloads"
R2_BINDING = "DOWNLOADS_BUCKET"
LINUX_WINN_MEMBER = "./winn-datapath"
SCAN_TEXT_CONTRACT = "winsvpn-release-artifact-privacy-scan-text-v1"
SCAN_V2_CONTRACT = "winsvpn-release-host-secret-scan-v2"
# Build-time files that live in web/ but are never part of the Pages upload.
STAGE_EXCLUDED_NAMES = frozenset(
    {
        "wrangler.jsonc",
        "update_style_csp.py",
        "verify_inline_csp.py",
        "winn3-dev-override.ini",
        "winn3-dev-override.json",
        ".assetsignore",
        "__pycache__",
        ".DS_Store",
    }
)
# Local custody records: the gates read them before deploy, the Worker and the
# page never do, and the owner evidence quotes internal ruling text, so they
# stay out of the public upload. The unsigned waiver is public on purpose: the
# public manifest binds its SHA-256 next to the Unsigned label.
# DLP-06: nothing that reaches Pages or GitHub may quote the private rulings
# record or name a local path. Stage refuses before the one-use gate runs.
PUBLIC_LEAK_MARKERS = (
    "Ship unsigned",
    "Publish now",
    "Build it properly",
    "Desktop download hosting",
    "owner in chat",
    "owner_rulings",
    "rulings_release_targets",
    ".agent/debates",
    "/Users/",
    "/Volumes/",
    "/private/",
    "/home/",
    "xprize",
)
STAGE_EXCLUDED_RELATIVE = frozenset(
    {
        "i18n/major.json",
        "releases/README.md",
        "releases/owner-publication-evidence.json",
        "releases/download-custody-challenge.json",
        "releases/download-custody-consumed.jsonl",
        ".well-known/refresh_security_txt.sh",
    }
)


class PublicationError(RuntimeError):
    """Fail-closed publication producer refusal."""


def load_custody() -> Any:
    spec = importlib.util.spec_from_file_location("winsvpn_publication_custody", CUSTODY_PATH)
    if spec is None or spec.loader is None:
        raise PublicationError("tools/website_download_custody.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CUSTODY = load_custody()


def load_public_gate() -> Any:
    path = ROOT / "tools" / "verify_website_public_download_gate.py"
    spec = importlib.util.spec_from_file_location("winsvpn_publication_gate", path)
    if spec is None or spec.loader is None:
        raise PublicationError("public download gate cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_regular(path: Path, label: str, *, max_bytes: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PublicationError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PublicationError(f"{label} must be a regular file: {path}")
    if info.st_size > max_bytes:
        raise PublicationError(f"{label} exceeds {max_bytes} bytes: {path}")
    data = path.read_bytes()
    if len(data) != info.st_size:
        raise PublicationError(f"{label} changed while it was read: {path}")
    return data


def load_json_file(path: Path, label: str) -> dict[str, Any]:
    raw = read_regular(path, label, max_bytes=4 * 1024 * 1024)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationError(f"{label} is not JSON: {exc}") from exc
    if type(payload) is not dict:
        raise PublicationError(f"{label} must be a JSON object")
    return payload


def write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise PublicationError(f"refusing to overwrite {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def receipt_bytes(payload: dict[str, Any]) -> bytes:
    return CUSTODY.canonical_json(payload) + b"\n"


# ---------------------------------------------------------------- evidence --


class EntryEvidence:
    """Everything one manifest entry needs, read from one evidence directory."""

    def __init__(self, entry_id: str, directory: Path) -> None:
        if entry_id not in CUSTODY.ENTRY_ARCHITECTURES:
            raise PublicationError(f"{entry_id} is not a direct per-architecture entry")
        self.entry_id = entry_id
        self.platform = CUSTODY.PLATFORM_TARGETS[entry_id]
        self.arch = CUSTODY.ENTRY_ARCHITECTURES[entry_id]
        self.directory = directory
        self.unsigned = self.platform == "windows"
        self.filename = (
            CUSTODY.UNSIGNED_CANONICAL_FILENAMES[entry_id]
            if self.unsigned
            else CUSTODY.CANONICAL_FILENAMES[entry_id]
        )
        receipt_path = directory / "BUILD_RECEIPT.json"
        self.receipt_raw = read_regular(receipt_path, "BUILD_RECEIPT.json", max_bytes=1024 * 1024)
        self.receipt_sha256 = sha256_bytes(self.receipt_raw)
        anchor = read_regular(
            directory / "BUILD_RECEIPT.json.sha256", "BUILD_RECEIPT.json.sha256", max_bytes=4096
        ).decode("ascii")
        if anchor != f"{self.receipt_sha256}  BUILD_RECEIPT.json\n":
            raise PublicationError(f"{entry_id} BUILD_RECEIPT.json does not match its .sha256 anchor")
        self.receipt = json.loads(self.receipt_raw)
        self.artifact_path = directory / self.filename
        self.data = read_regular(
            self.artifact_path, f"{entry_id} artifact", max_bytes=CUSTODY.MAX_ARTIFACT_BYTES
        )
        self.sha256 = sha256_bytes(self.data)
        self.bytes = len(self.data)
        recorded = self.receipt.get("artifact") or {}
        if (
            self.receipt.get("contract") != CUSTODY.BUILD_RECEIPT_CONTRACT
            or self.receipt.get("release") != CUSTODY.CANONICAL_RELEASE
            or self.receipt.get("platform") != self.platform
            or recorded.get("name") != self.filename
            or recorded.get("sha256") != self.sha256
            or recorded.get("size_bytes") != self.bytes
        ):
            raise PublicationError(
                f"{entry_id} artifact bytes, name or release do not match BUILD_RECEIPT.json"
            )
        toolchain = self.receipt.get("toolchain") or {}
        expected_target = (
            f"windows-{self.arch}-inno-unsigned" if self.unsigned else f"{self.platform}-{self.arch}"
        )
        if toolchain.get("target") != expected_target:
            raise PublicationError(
                f"{entry_id} BUILD_RECEIPT.json toolchain target is {toolchain.get('target')!r}, "
                f"expected {expected_target!r}"
            )
        run = ((self.receipt.get("remote_attestation") or {}).get("run_record") or {}).get("record") or {}
        self.signing = run.get("signing")
        if self.unsigned and self.signing != "unsigned":
            raise PublicationError(f"{entry_id} build record is not the unsigned build")
        if not self.unsigned and self.signing == "unsigned":
            raise PublicationError(f"{entry_id} build record is unsigned")
        self.remote_machine = (run.get("remote_system") or {}).get("machine")
        if not isinstance(self.remote_machine, str) or not self.remote_machine:
            raise PublicationError(f"{entry_id} build record has no remote machine")
        if run.get("artifact", {}).get("sha256") != self.sha256:
            raise PublicationError(f"{entry_id} remote run record does not bind the artifact")

    # privacy -------------------------------------------------------------
    def privacy_scan(self) -> dict[str, Any]:
        if self.platform == "windows":
            claim = (self.receipt.get("build_attempt") or {}).get("claim_record") or {}
            scan = claim.get("release_host_secret_scan") or {}
            record = scan.get("record") or {}
            inventory = record.get("inventory") or {}
            if (
                record.get("contract") != SCAN_V2_CONTRACT
                or record.get("result") != "pass"
                or record.get("matched_labels") != []
                or record.get("artifact")
                != {"name": self.filename, "sha256": self.sha256, "size_bytes": self.bytes}
            ):
                raise PublicationError(f"{self.entry_id} release-host secret scan did not pass")
            return {
                "contract": SCAN_V2_CONTRACT,
                "record_filename": "BUILD_RECEIPT.json",
                "record_sha256": scan.get("sha256"),
                "result": "pass",
                "matched_labels": [],
                "inventory_revision": inventory.get("revision"),
                "inventory_sha256": inventory.get("sha256"),
                "label_count": inventory.get("label_count"),
                "target_id": record.get("target_id"),
            }
        path = self.directory / "MAC_REAL_INVENTORY_SCAN.txt"
        raw = read_regular(path, "MAC_REAL_INVENTORY_SCAN.txt", max_bytes=65536)
        lines = raw.decode("utf-8").splitlines()
        if not lines or lines[0] != "RELEASE ARTIFACT PRIVACY: PASS":
            raise PublicationError(f"{self.entry_id} release artifact privacy scan did not pass")
        fields: dict[str, str] = {}
        for line in lines[1:]:
            key, sep, value = line.partition("=")
            if sep:
                fields[key] = value
        if (
            fields.get("rc") != "0"
            or fields.get("matched_labels") != ""
            or fields.get("artifact") != self.sha256
        ):
            raise PublicationError(f"{self.entry_id} privacy scan does not bind the artifact")
        return {
            "contract": SCAN_TEXT_CONTRACT,
            "record_filename": path.name,
            "record_sha256": sha256_bytes(raw),
            "result": "pass",
            "matched_labels": [],
            "inventory_revision": fields.get("revision"),
            "inventory_sha256": fields.get("inventory_sha256"),
            "label_count": int(fields.get("label_count", "0")),
            "target_id": fields.get("target"),
        }

    # release -------------------------------------------------------------
    def build(self) -> dict[str, Any]:
        producer = self.receipt.get("producer") or {}
        return {
            "receipt_contract": self.receipt.get("contract"),
            "receipt_filename": "BUILD_RECEIPT.json",
            "receipt_sha256": self.receipt_sha256,
            "shared_revision": self.receipt.get("shared_revision"),
            "producer_path": producer.get("path"),
            "producer_sha256": producer.get("sha256"),
            "toolchain_target": (self.receipt.get("toolchain") or {}).get("target"),
            "signing": self.signing,
            "remote_machine": self.remote_machine,
            "source_artifact_name": self.filename,
            "finished_utc": str(self.receipt.get("finished_utc", "")).split(".")[0].rstrip("Z") + "Z",
        }

    # signature -----------------------------------------------------------
    def linux_bundle(self) -> bytes:
        bundle = read_regular(
            self.directory / f"{self.filename}.sigstore.json", "Sigstore bundle", max_bytes=65536
        )
        signing = load_json_file(self.directory / "MAC_SIGNING.json", "MAC_SIGNING.json")
        trusted = read_regular(
            ROOT / CUSTODY.TRUSTED_COSIGN_KEY_RELATIVE, "trusted cosign key", max_bytes=65536
        )
        if (
            signing.get("archive_sha256") != self.sha256
            or signing.get("bundle_sha256") != sha256_bytes(bundle)
            or signing.get("public_key_sha256") != sha256_bytes(trusted)
            or signing.get("public_key_pinned") is not True
        ):
            raise PublicationError(
                f"{self.entry_id} MAC_SIGNING.json does not bind the archive, bundle and pinned key"
            )
        return bundle


def verified_winn_release(release_dir: Path) -> tuple[dict[str, Any], str, str]:
    """Run the reviewed verifier and return (manifest, manifest sha256, public key)."""
    completed = subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools" / "winn_release.py"), "verify",
         "--release", str(release_dir), "--print-manifest"],
        capture_output=True,
        check=False,
        cwd=str(ROOT),
        timeout=600,
    )
    if completed.returncode != 0:
        raise PublicationError(
            f"tools/winn_release.py verify refused {release_dir}: "
            f"{completed.stderr.decode('utf-8', 'replace').strip()}"
        )
    manifest_bytes = completed.stdout
    manifest = json.loads(manifest_bytes)
    signature = load_json_file(release_dir / "manifest.sig.json", "Winn manifest signature")
    manifest_sha256 = sha256_bytes(manifest_bytes)
    if signature.get("manifest_sha256") != manifest_sha256:
        raise PublicationError("verified Winn manifest bytes do not match manifest.sig.json")
    return manifest, manifest_sha256, str(signature.get("public_key"))


def winn_engine(evidence: EntryEvidence, release_dir: Path) -> dict[str, Any]:
    manifest, manifest_sha256, public_key = verified_winn_release(release_dir)
    if public_key != CUSTODY.pinned_winn_authority_key():
        raise PublicationError("Winn release is not signed by the pinned release authority")
    targets = CUSTODY.expected_winn_targets(evidence.entry_id)
    by_target = {item.get("target"): item for item in manifest.get("artifacts", [])}
    if targets is None or any(target not in by_target for target in targets):
        raise PublicationError(f"Winn release lacks the {evidence.entry_id} engines {targets}")
    source = manifest.get("source") or {}
    if evidence.platform == "linux":
        datapath = by_target[targets[0]]
        raw = CUSTODY.gunzip_limited(evidence.data, CUSTODY.MAX_LINUX_UNCOMPRESSED)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            member = archive.getmember(LINUX_WINN_MEMBER)
            extracted = archive.extractfile(member)
            measured = sha256_bytes(extracted.read() if extracted else b"")
        if measured != datapath.get("sha256"):
            raise PublicationError(
                f"{evidence.entry_id} tarball {LINUX_WINN_MEMBER} is not the signed {targets[0]}"
            )
        binding = {
            "kind": "measured_member_sha256",
            "member": LINUX_WINN_MEMBER,
            "sha256": measured,
            "target": targets[0],
        }
    else:
        logs = sorted(evidence.directory.glob("build-*.guest.log"))
        if len(logs) != 1:
            raise PublicationError(f"{evidence.entry_id} needs exactly one producer guest log")
        log_raw = read_regular(logs[0], "producer guest log", max_bytes=16 * 1024 * 1024)
        line = (
            "Staged the release-verified, role-checked Winn Protocol v3 datapath and "
            f"relay for {evidence.arch}."
        )
        if line.encode("ascii") not in log_raw.split(b"\r\n") and line.encode("ascii") not in log_raw.splitlines():
            raise PublicationError(f"{evidence.entry_id} producer log does not stage the Winn engines")
        binding = {
            "kind": "producer_log",
            "log_filename": logs[0].name,
            "log_sha256": sha256_bytes(log_raw),
            "line": line,
        }
    return {
        "manifest_sha256": manifest_sha256,
        "signature_public_key": public_key,
        "verified_by": CUSTODY.WINN_RELEASE_VERIFIER,
        "source_commit": source.get("commit"),
        "tree_sha256": source.get("tree_sha256"),
        "targets": targets,
        "binding": binding,
    }


def owner_ruling(rulings_path: Path, markers: tuple[str, ...]) -> dict[str, Any]:
    raw = read_regular(rulings_path, "owner rulings record", max_bytes=1024 * 1024)
    text = raw.decode("utf-8")
    lines: list[str] = []
    for marker in markers:
        found = [line.strip() for line in text.splitlines() if marker in line]
        if not found:
            raise PublicationError(f"owner rulings record does not contain {marker!r}")
        for line in found:
            if line not in lines:
                lines.append(line)
    return {"record": rulings_path.name, "record_sha256": sha256_bytes(raw), "lines": lines}


# --------------------------------------------------------------- commands --


def command_challenge(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    path = root / CUSTODY.CHALLENGE_RELATIVE
    challenge = {
        "schema": CUSTODY.CHALLENGE_SCHEMA,
        "nonce": secrets.token_hex(16),
        "issued_utc": utc_text(datetime.now(timezone.utc)),
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
    }
    write_bytes(path, receipt_bytes(challenge), mode=0o644)
    print(f"challenge {challenge['nonce']} written to {path.relative_to(root)}")
    return 0


def identity_receipt(
    evidence: EntryEvidence, kind: str, schema: str, extra: dict[str, Any]
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": schema,
        "kind": kind,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "platform_id": evidence.entry_id,
        "artifact_filename": evidence.filename,
        "artifact_sha256": evidence.sha256,
        "artifact_bytes": evidence.bytes,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
        "architecture": [evidence.arch],
        "version": CUSTODY.CANONICAL_VERSION,
    }
    payload.update(extra)
    return payload


def command_prepare(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    web = root / "web"
    downloads = root / CUSTODY.DOWNLOADS_RELATIVE
    if downloads.exists() and any(downloads.iterdir()):
        raise PublicationError("web/downloads already holds files; start from a clean clone")
    for relative in (CUSTODY.OWNER_EVIDENCE_RELATIVE, CUSTODY.UNSIGNED_WAIVER_RELATIVE):
        if (root / relative).exists():
            raise PublicationError(f"{relative} already exists; start from a clean clone")
    now = datetime.now(timezone.utc)
    challenge = CUSTODY.load_challenge(root, now=now)
    # Argon F-2 / DLP-04: a consumed challenge cannot be reused by re-running
    # prepare, in this clone or (through the durable release ledger) any other.
    if any(
        record.get("challenge_nonce") == challenge["nonce"]
        for record in CUSTODY.load_replay_log(root).values()
    ) or any(
        record["challenge_nonce"] == challenge["nonce"]
        for record in CUSTODY.release_ledger_records()
    ):
        raise PublicationError("the verifier challenge was already consumed; issue a new one")
    rulings_path = Path(args.rulings).resolve()
    github = args.delivery == "github"
    owner_markers: tuple[str, ...] = (CUSTODY.OWNER_PUBLICATION_RULING_MARKER,)
    if github:
        owner_markers += (CUSTODY.GITHUB_HOSTING_RULING_MARKER,)
    # Refuse before writing anything: a missing ruling must leave the tree clean.
    owner_ruling_record = owner_ruling(rulings_path, owner_markers)

    evidences: list[EntryEvidence] = []
    seen: set[str] = set()
    for item in args.evidence:
        entry_id, sep, directory = item.partition("=")
        if not sep or entry_id in seen:
            raise PublicationError(f"--evidence must be ENTRY=DIR once per entry: {item}")
        seen.add(entry_id)
        evidences.append(EntryEvidence(entry_id, Path(directory).resolve()))
    order = {entry: index for index, (entry, _label, _kind) in enumerate(CUSTODY.PLATFORM_CONTRACT)}
    evidences.sort(key=lambda item: order[item.entry_id])
    winn_dirs = {"windows": args.winn_release_windows, "linux": args.winn_release_linux}

    waiver_sha256 = None
    unsigned_entries = [item.entry_id for item in evidences if item.unsigned]
    if unsigned_entries:
        owner_ruling(
            rulings_path,
            (CUSTODY.UNSIGNED_WAIVER_RULING_MARKER, 'labels Windows "Unsigned"'),
        )
        waiver = {
            "schema": CUSTODY.UNSIGNED_WAIVER_SCHEMA,
            "release_id": CUSTODY.CANONICAL_WEBSITE_RELEASE_ID,
            "canonical_release": CUSTODY.CANONICAL_RELEASE,
            "platform": CUSTODY.UNSIGNED_WAIVER_PLATFORM,
            "entries": unsigned_entries,
            "architectures": [CUSTODY.ENTRY_ARCHITECTURES[entry] for entry in unsigned_entries],
            "public_label": CUSTODY.UNSIGNED_PUBLIC_LABEL,
            "user_notice": (
                "Unsigned installer: it has no Authenticode signature, so Windows SmartScreen "
                "reports an unknown publisher. Check the SHA-256 shown on the download button."
            ),
            # Public file (review DLP-06): never copy private ruling lines.
            # The source markers are checked locally; publish only an opaque
            # release-scoped reference, never ruling text or record metadata.
            "owner_ruling": {
                "reference": CUSTODY.UNSIGNED_WAIVER_PUBLIC_REFERENCE,
            },
        }
        waiver_raw = (json.dumps(waiver, indent=2) + "\n").encode("ascii")
        write_bytes(root / CUSTODY.UNSIGNED_WAIVER_RELATIVE, waiver_raw)
        waiver_sha256 = sha256_bytes(waiver_raw)

    issuance_id = secrets.token_hex(16)
    issued_utc = utc_text(now)
    owner_platforms: list[dict[str, Any]] = []
    artifacts: dict[str, dict[str, Any]] = {}
    for evidence in evidences:
        if not winn_dirs.get(evidence.platform):
            raise PublicationError(f"--winn-release-{evidence.platform} is required")
        write_bytes(downloads / evidence.filename, evidence.data, mode=0o644)
        write_bytes(
            downloads / f"{evidence.filename}.sha256",
            f"{evidence.sha256}  {evidence.filename}\n".encode("ascii"),
        )
        if evidence.platform == "linux":
            write_bytes(downloads / f"{evidence.filename}.sigstore.json", evidence.linux_bundle())
            signature = {
                "kind": CUSTODY.SIGNATURE_KINDS["linux"],
                "sha256": sha256_bytes(evidence.linux_bundle()),
            }
        else:
            signature = {"kind": CUSTODY.UNSIGNED_SIGNATURE_KIND, "sha256": waiver_sha256}
        privacy = receipt_bytes(identity_receipt(
            evidence, CUSTODY.PRIVACY_RECEIPT_KIND, CUSTODY.PRIVACY_RECEIPT_SCHEMA,
            {CUSTODY.PRIVACY_EVIDENCE_KEY: evidence.privacy_scan()},
        ))
        release = receipt_bytes(identity_receipt(
            evidence, CUSTODY.RELEASE_RECEIPT_KIND, CUSTODY.RELEASE_RECEIPT_SCHEMA,
            {CUSTODY.RELEASE_EVIDENCE_KEY: evidence.build()},
        ))
        winn = receipt_bytes(identity_receipt(
            evidence, CUSTODY.WINN_PROVENANCE_KIND, CUSTODY.WINN_PROVENANCE_SCHEMA,
            {
                "primary": CUSTODY.WINN_PRIMARY,
                "fallback": CUSTODY.WINN_FALLBACK,
                "fallback_order": list(CUSTODY.WINN_FALLBACK_ORDER),
                CUSTODY.WINN_EVIDENCE_KEY: winn_engine(evidence, Path(winn_dirs[evidence.platform])),
            },
        ))
        for suffix, body in ((".privacy.json", privacy), (".release.json", release), (".winn.json", winn)):
            write_bytes(downloads / f"{evidence.filename}{suffix}", body)
        nonce = secrets.token_hex(16)
        owner_platforms.append({
            "id": evidence.entry_id,
            "target": evidence.platform,
            "version": CUSTODY.CANONICAL_VERSION,
            "architecture": [evidence.arch],
            "artifact_filename": evidence.filename,
            "artifact_sha256": evidence.sha256,
            "artifact_bytes": evidence.bytes,
            "signature_kind": signature["kind"],
            "signature_sha256": signature["sha256"],
            "nonce": nonce,
            "receipt_filename": f"{evidence.filename}.publication.json",
        })
        artifact: dict[str, Any] = {
            "filename": evidence.filename,
            "sha256": evidence.sha256,
            "bytes": evidence.bytes,
            "canonical_release": CUSTODY.CANONICAL_RELEASE,
            "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
            "version": CUSTODY.CANONICAL_VERSION,
            "architecture": [evidence.arch],
            "signature": signature,
            "winn_provenance": {
                "kind": CUSTODY.WINN_PROVENANCE_KIND,
                "receipt_filename": f"{evidence.filename}.winn.json",
                "receipt_sha256": sha256_bytes(winn),
                "primary": CUSTODY.WINN_PRIMARY,
                "fallback": CUSTODY.WINN_FALLBACK,
                "fallback_order": list(CUSTODY.WINN_FALLBACK_ORDER),
            },
            "privacy": {
                "kind": CUSTODY.PRIVACY_RECEIPT_KIND,
                "receipt_filename": f"{evidence.filename}.privacy.json",
                "receipt_sha256": sha256_bytes(privacy),
            },
            "release_receipt": {
                "kind": CUSTODY.RELEASE_RECEIPT_KIND,
                "receipt_filename": f"{evidence.filename}.release.json",
                "receipt_sha256": sha256_bytes(release),
            },
        }
        if evidence.unsigned:
            artifact["unsigned_waiver"] = {
                "label": CUSTODY.UNSIGNED_PUBLIC_LABEL,
                "waiver_filename": CUSTODY.UNSIGNED_WAIVER_RELATIVE.name,
                "waiver_sha256": waiver_sha256,
            }
        artifacts[evidence.entry_id] = artifact

    owner = {
        "schema": CUSTODY.OWNER_EVIDENCE_SCHEMA,
        "issued_utc": issued_utc,
        "issuance_id": issuance_id,
        "canonical_release": CUSTODY.CANONICAL_RELEASE,
        "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
        "challenge_nonce": challenge["nonce"],
        "owner_ruling": owner_ruling_record,
        "platforms": owner_platforms,
    }
    owner_raw = (json.dumps(owner, indent=2) + "\n").encode("ascii")
    write_bytes(root / CUSTODY.OWNER_EVIDENCE_RELATIVE, owner_raw)
    owner_sha256 = sha256_bytes(owner_raw)

    manifest_entries: list[dict[str, Any]] = []
    for entry_id, label, kind in CUSTODY.PLATFORM_CONTRACT:
        if entry_id in artifacts:
            owner_item = next(item for item in owner_platforms if item["id"] == entry_id)
            artifact = artifacts[entry_id]
            publication = receipt_bytes({
                "schema": CUSTODY.PUBLICATION_RECEIPT_SCHEMA,
                "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
                "issuance_id": issuance_id,
                "issued_utc": issued_utc,
                "nonce": owner_item["nonce"],
                "canonical_release": CUSTODY.CANONICAL_RELEASE,
                "package_identity": CUSTODY.PUBLIC_PACKAGE_IDENTITY,
                "platform_id": entry_id,
                "target": owner_item["target"],
                "version": CUSTODY.CANONICAL_VERSION,
                "architecture": owner_item["architecture"],
                "artifact_filename": artifact["filename"],
                "artifact_sha256": artifact["sha256"],
                "artifact_bytes": artifact["bytes"],
                "signature_kind": owner_item["signature_kind"],
                "signature_sha256": owner_item["signature_sha256"],
                "challenge_nonce": challenge["nonce"],
                "owner_evidence_sha256": owner_sha256,
            })
            write_bytes(downloads / owner_item["receipt_filename"], publication)
            artifact["publication_receipt"] = {
                "kind": CUSTODY.PUBLICATION_RECEIPT_KIND,
                "receipt_filename": owner_item["receipt_filename"],
                "receipt_sha256": sha256_bytes(publication),
            }
            manifest_entries.append({
                "id": entry_id,
                "label": label,
                "status": CUSTODY.AVAILABLE_STATUS,
                "delivery": (
                    {"kind": "github_release", "url": CUSTODY.github_release_url(artifact["filename"])}
                    if github
                    else {"kind": "direct", "url": CUSTODY.production_direct_url(artifact["filename"])}
                ),
                "artifact": artifact,
            })
        else:
            manifest_entries.append({
                "id": entry_id,
                "label": label,
                "status": CUSTODY.STORE_PENDING_STATUS if kind == "store" else CUSTODY.PENDING_STATUS,
                "delivery": {"kind": kind, "url": None},
                "artifact": {"filename": None, "sha256": None, "bytes": None},
            })
    manifest = {
        "schema": CUSTODY.MANIFEST_SCHEMA,
        "release_id": CUSTODY.CANONICAL_WEBSITE_RELEASE_ID,
        "artifacts": manifest_entries,
    }
    manifest_path = root / CUSTODY.MANIFEST_RELATIVE
    manifest_path.write_bytes((json.dumps(manifest, indent=2) + "\n").encode("ascii"))
    custody = CUSTODY.pending_custody_document()
    custody["status"] = CUSTODY.AVAILABLE_STATUS
    custody["owner_evidence_filename"] = CUSTODY.OWNER_EVIDENCE_RELATIVE.name
    (root / CUSTODY.CUSTODY_RELATIVE).write_bytes((json.dumps(custody, indent=2) + "\n").encode("ascii"))
    assetsignore = web / ".assetsignore"
    text = assetsignore.read_text(encoding="utf-8")
    kept = [line for line in text.splitlines() if line.strip() != "downloads/"]
    assetsignore.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print(
        "prepared "
        + ", ".join(f"{item.entry_id}={item.filename} {item.sha256} {item.bytes}B" for item in evidences)
        + f"; owner evidence {owner_sha256}; manifest {sha256_bytes(manifest_path.read_bytes())}"
    )
    return 0


def public_leak_errors(
    paths: list[Path], data: bytes | None = None, *,
    markers: tuple[str, ...] = PUBLIC_LEAK_MARKERS,
) -> list[str]:
    """Grep the public files (text only; binaries are reviewed artifacts)."""
    errors: list[str] = []
    for path in paths:
        if path.suffix.lower() in {".exe", ".gz", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".woff", ".woff2", ".mp4", ".pdf"}:
            continue
        payload = data if data is not None else path.read_bytes()
        text = payload.decode("utf-8", errors="replace").casefold()
        for marker in markers:
            if marker.casefold() in text:
                errors.append(f"{path.name} contains {marker!r}")
    return errors


def stage_allowlist(root: Path, manifest: dict[str, Any]) -> set[str]:
    """Reviewed public files: tracked web/ files plus the manifest-bound outputs.

    Review DLP-03: an untracked file under web/ (a stray credential, a debug
    note) must never reach the Pages upload just because it sits in the tree.
    """
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "web"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if tracked.returncode != 0:
        raise PublicationError("stage requires the reviewed Git checkout")
    allowed = {
        Path(os.fsdecode(item)).relative_to("web").as_posix()
        for item in tracked.stdout.split(b"\0")
        if item
    }
    for entry in manifest.get("artifacts", []):
        if entry.get("status") != CUSTODY.AVAILABLE_STATUS:
            continue
        artifact = entry["artifact"]
        filename = artifact["filename"]
        allowed.update({f"downloads/{filename}", f"downloads/{filename}.sha256"})
        if str(entry["id"]).startswith("linux-"):
            allowed.add(f"downloads/{filename}.sigstore.json")
        if str(entry["id"]).startswith("windows-"):
            allowed.add(f"releases/{CUSTODY.UNSIGNED_WAIVER_RELATIVE.name}")
        for field in ("privacy", "release_receipt", "winn_provenance", "publication_receipt"):
            allowed.add(f"downloads/{artifact[field]['receipt_filename']}")
    return allowed


def command_stage(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    if out == root or root in out.parents:
        raise PublicationError("stage output must be outside the source checkout")
    if out.exists():
        raise PublicationError(f"{out} already exists")
    manifest = json.loads((root / CUSTODY.MANIFEST_RELATIVE).read_bytes())
    if type(manifest) is not dict or manifest.get("schema") != CUSTODY.MANIFEST_SCHEMA:
        raise PublicationError("stage refuses a manifest outside the reviewed v2 schema")
    r2_names: dict[str, dict[str, Any]] = {}
    github_names: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("artifacts", []):
        if entry.get("status") != CUSTODY.AVAILABLE_STATUS:
            continue
        kind = entry.get("delivery", {}).get("kind")
        artifact = entry["artifact"]
        if kind == "direct":
            r2_names[artifact["filename"]] = artifact
        elif kind == "github_release":
            if entry["delivery"].get("url") != CUSTODY.github_release_url(artifact["filename"]):
                raise PublicationError(f"{entry['id']} GitHub URL is not the pinned release asset")
            github_names[artifact["filename"]] = artifact
        else:
            raise PublicationError(f"{entry.get('id')} has an unsupported delivery kind")
    allowed = stage_allowlist(root, manifest)
    github_files: list[dict[str, Any]] = []
    copied: list[tuple[Path, Path]] = []
    web = root / "web"
    pages = out / "pages"
    plan: list[dict[str, Any]] = []
    for path in sorted(web.rglob("*")):
        relative = path.relative_to(web)
        if path.is_symlink():
            raise PublicationError(f"web/{relative} is a symlink")
        if any(part in STAGE_EXCLUDED_NAMES for part in relative.parts):
            continue
        if relative.as_posix() in STAGE_EXCLUDED_RELATIVE or path.is_dir():
            continue
        if relative.as_posix() not in allowed:
            raise PublicationError(f"unreviewed public web file: web/{relative}")
        if relative.parts[0] == "downloads" and path.name in github_names:
            artifact = github_names[path.name]
            data = read_regular(path, path.name, max_bytes=CUSTODY.MAX_ARTIFACT_BYTES)
            if sha256_bytes(data) != artifact["sha256"] or len(data) != artifact["bytes"]:
                raise PublicationError(f"{path.name} no longer matches the manifest")
            target = out / "github" / path.name
            write_bytes(target, data, mode=0o444)
            copied.append((path, target))
            github_files.append(
                {"name": path.name, "sha256": artifact["sha256"], "bytes": artifact["bytes"],
                 "url": CUSTODY.github_release_url(path.name)}
            )
            continue
        if (
            relative.parts[0] == "downloads"
            and path.name.endswith(".sigstore.json")
            and path.name[: -len(".sigstore.json")] in github_names
        ):
            target = out / "github" / path.name
            write_bytes(target, path.read_bytes(), mode=0o444)
            copied.append((path, target))
        if relative.parts[0] == "downloads" and path.name in r2_names:
            artifact = r2_names[path.name]
            data = read_regular(path, path.name, max_bytes=CUSTODY.MAX_ARTIFACT_BYTES)
            if sha256_bytes(data) != artifact["sha256"] or len(data) != artifact["bytes"]:
                raise PublicationError(f"{path.name} no longer matches the manifest")
            key = f"{CUSTODY.R2_OBJECT_PREFIX}{artifact['sha256']}"
            target = out / "r2" / key
            write_bytes(target, data, mode=0o444)
            copied.append((path, target))
            plan.append({
                "key": key,
                "local_path": str(target),
                "published_path": f"/downloads/{path.name}",
                "sha256": artifact["sha256"],
                "bytes": artifact["bytes"],
                "upload": (
                    f"npx wrangler r2 object put {shlex.quote(f'{R2_BUCKET}/{key}')} --remote --file "
                    f"{shlex.quote(str(target))} --content-type application/octet-stream"
                ),
            })
            continue
        data = path.read_bytes()
        if len(data) > PAGES_MAX_ASSET_BYTES:
            raise PublicationError(f"web/{relative} exceeds the Pages 25 MiB asset limit")
        target = pages / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        copied.append((path, target))
    if len(plan) != len(r2_names) or len(github_files) != len(github_names):
        raise PublicationError("not every available artifact was found under web/downloads")
    leak_markers = PUBLIC_LEAK_MARKERS
    if any(entry.get("status") == CUSTODY.AVAILABLE_STATUS for entry in manifest["artifacts"]):
        owner, _owner_sha256 = CUSTODY.load_owner_evidence(root, now=datetime.now(timezone.utc))
        ruling = owner["owner_ruling"]
        leak_markers += (ruling["record"], ruling["record_sha256"], *ruling["lines"])
    leaks = public_leak_errors([target for _source, target in copied], markers=leak_markers)
    if leaks:
        raise PublicationError("public stage carries private ruling text or local paths: " + "; ".join(leaks))
    # Review DLP-03: the one-use final gate runs here, after the copy, and the
    # staged bytes must still equal the gated source; a PASS consumes the
    # challenge, so a retry needs a fresh clone and challenge.
    gate = load_public_gate().evaluate_tree(root)
    if gate.status != "ready":
        raise PublicationError(f"final gate refused the staged source: {gate.summary}")
    print("READY")
    print(gate.summary)
    for source, target in copied:
        if source.read_bytes() != target.read_bytes():
            raise PublicationError(f"staged file changed across the final gate: {source}")
    plan_doc = {
        "bucket": R2_BUCKET,
        "binding": R2_BINDING,
        "manifest_sha256": sha256_bytes((root / CUSTODY.MANIFEST_RELATIVE).read_bytes()),
        "gate_summary": gate.summary,
        "objects": plan,
        "pages_directory": str(pages),
        "pages_deploy": (
            f"npx wrangler pages deploy {shlex.quote(str(pages))} --project-name winsvpn --branch main"
        ),
    }
    if github_files:
        github_files.sort(key=lambda item: item["name"])
        sums = "".join(f"{item['sha256']}  {item['name']}\n" for item in github_files)
        write_bytes(out / "github" / "SHA256SUMS", sums.encode("ascii"), mode=0o444)
        uploads = sorted(child.name for child in (out / "github").iterdir())
        plan_doc["github_release"] = {
            "repo": CUSTODY.GITHUB_RELEASE_OWNER_REPO,
            "tag": CUSTODY.GITHUB_RELEASE_TAG,
            "directory": str(out / "github"),
            "assets": github_files,
            "uploads": uploads,
            "create": " ".join(
                [
                    "gh", "release", "create", CUSTODY.GITHUB_RELEASE_TAG,
                    "--repo", CUSTODY.GITHUB_RELEASE_OWNER_REPO,
                    "--title", shlex.quote("Win's VPN 1.0.16+33 desktop"),
                    "--notes-file", shlex.quote(str(out / "github-release-notes.md")),
                ]
                + [shlex.quote(str(out / "github" / name)) for name in uploads]
            ),
        }
        notes = (
            "Win's VPN 1.0.16+33 desktop installers, published through https://winsvpn.org.\n\n"
            "The Windows x64 and ARM64 installers are Unsigned (no Authenticode signature): "
            "Windows SmartScreen reports an unknown publisher. The Linux tarballs are signed "
            "with the Win's VPN Cosign key (.sigstore.json bundles). Verify every file with "
            "SHA256SUMS before installing:\n\n```\n" + sums + "```\n"
        )
        leaks = public_leak_errors([out / "github-release-notes.md"], notes.encode("ascii"), markers=leak_markers)
        leaks += public_leak_errors([out / "github" / "SHA256SUMS"], sums.encode("ascii"), markers=leak_markers)
        if leaks:
            raise PublicationError("GitHub release text carries private ruling text or local paths: " + "; ".join(leaks))
        write_bytes(out / "github-release-notes.md", notes.encode("ascii"))
    write_bytes(out / "r2-upload-plan.json", (json.dumps(plan_doc, indent=2) + "\n").encode("ascii"))
    print(json.dumps(plan_doc, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=str(ROOT))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("challenge")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--evidence", action="append", required=True, metavar="ENTRY=DIR")
    prepare.add_argument("--winn-release-windows")
    prepare.add_argument("--winn-release-linux")
    prepare.add_argument("--rulings", required=True)
    prepare.add_argument("--delivery", choices=("r2", "github"), default="r2")
    stage = sub.add_parser("stage")
    stage.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "challenge":
            return command_challenge(args)
        if args.command == "prepare":
            return command_prepare(args)
        return command_stage(args)
    except (PublicationError, CUSTODY.WebsiteDownloadCustodyError, OSError, KeyError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
