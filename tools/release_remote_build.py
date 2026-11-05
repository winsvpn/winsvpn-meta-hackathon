#!/usr/bin/env python3
"""Mac orchestrator for remote-attested Windows and Linux release receipts.

The authenticated dependency-freeze worker starts only on the macOS release
host, so a Windows or Linux build receipt is made in two Mac steps around the
remote producer run. Both steps go through tools/release_freeze_client.py, which
launches the reviewed parent tools/run_release_dependency_freeze.sh and requires
the authenticated result envelope.

  prepare  begin-build --remote-host: the worker verifies the release index,
           writes SOURCE.tar (every tracked file of the frozen revision, each
           checked against its Git blob, every manifest file checked against
           the tar) and binds its digest in BUILD_BEGIN.json. This step then
           writes REMOTE_INPUT.json for the remote host.
  finish   finish-build --remote-host: the worker re-hashes SOURCE.tar,
           validates the copied-back artifact bytes and binds them, with
           REMOTE_RUN.json, to the begin record; then verify-receipt.

Windows secret scan: a Windows build host cannot load the authenticated secret
inventory, so its producer defers the scan and records secret_scan=deferred-to-
release-host in REMOTE_RUN.json. finish then hands the inventory path (named by
WINS_RELEASE_SECRET_INVENTORY, never read by this tool) to the authenticated
dependency-freeze worker, which runs the exact scanner on the installer bytes it
holds and binds the scanner closure, the inventory digest, the artifact, the
target and the verdict into its claim. This tool neither runs the scan nor
accepts a scan result: there is no argument that could carry one.

Linux signing (round R11a) happens here, never on a build host: the remote
run sets WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR=1, stops before its
signing step and records signing=orchestrator; finish --sign then signs the
copied-back archive with tools/linux_release_signing.py run-sign-verify
(offline, --tlog-upload=false) using the key paths in WINS_LINUX_COSIGN_KEY and
WINS_LINUX_COSIGN_PUBKEY. Signing is the LAST step, after finish-build and
verify-receipt have bound and re-checked these exact bytes, and the artifact is
re-hashed against the verified digest immediately before the key is used:
cosign writes a sidecar bundle and never rewrites the archive, so nothing the
receipt bound changes by signing it. The public key must equal
LINUX_COSIGN_PUBLIC_KEY_SHA256 in tools/build_linux_release.sh; while that pin
is empty only --allow-unpinned-rehearsal-key (a throwaway rehearsal key) signs.

Between the two steps the operator ships SOURCE.tar, REMOTE_INPUT.json and the
release index directory to the remote host, extracts and checks them with
tools/release_remote_attestation_check.py extract-source, runs the producer
with WINS_REMOTE_ATTESTATION_INPUT set, and copies the artifact and
REMOTE_RUN.json back into the run directory. The transport is not trusted for
bytes: every byte that matters is re-hashed on the Mac by the worker. It is
still trusted for one claim, because nothing authenticates it. REMOTE_RUN.json
is unsigned JSON composed on the remote host, so a substituted artifact plus a
matching substituted run record passes every field and digest check the worker
performs. `remote-attested` therefore names how the receipt was produced, not a
proof that the reviewed producer ran. finish refuses without
--accept-remote-self-reported-execution and writes REMOTE_EXECUTION_EVIDENCE.json
recording exactly which claims the Mac proved and which it did not. A
host-authenticated execution proof is the replacement for that acceptance.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import release_freeze_client as client  # noqa: E402
import release_remote_run_record_signature as signatures  # noqa: E402

INPUT_CONTRACT = "winsvpn-remote-attestation-input-v1"
EXECUTION_EVIDENCE_CONTRACT = "winsvpn-remote-execution-evidence-v1"
EXECUTION_EVIDENCE_CLASS_SELF_REPORTED = "remote_self_reported"
EXECUTION_EVIDENCE_CLASS_HOST_SIGNED = "remote_host_signed"
REMOTE_PRODUCERS = {
    ("linux", "linux"): "tools/build_linux_release.sh",
    ("windows", "windows"): "installer/windows/build_installer.ps1",
}
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SIGNING_TOOL = "tools/linux_release_signing.py"
# A Windows build host cannot load the authenticated secret inventory (it has no
# descriptor-relative open), so the authenticated worker runs the exact secret scan
# during finish-build and this tool only names the inventory by path.
SECRET_SCAN_INVENTORY_ENV = "WINS_RELEASE_SECRET_INVENTORY"
TRUST_ANCHOR_ROUTE = "/etc/winsvpn/release-signing/cosign.pub"
PUBLIC_KEY_PIN = re.compile(r'^LINUX_COSIGN_PUBLIC_KEY_SHA256="([0-9a-f]{64}|)"$', re.MULTILINE)

# What a remote-attested receipt does prove, and what it does not. Recorded
# verbatim into every run so no reader has to infer it from the word
# "attested". The Mac re-hashes and re-compares every byte it holds; nothing
# here authenticates the remote execution that produced those bytes.
EXECUTION_PROVEN_ON_MAC = (
    "the copied-back artifact bytes are bound by SHA-256 to the begin record",
    "the frozen SOURCE.tar still matches the digest the begin record bound",
    "the shipped producer bytes match the digest the begin record bound",
    "every REMOTE_RUN.json field agrees with the begin record and the artifact",
)
EXECUTION_NOT_PROVEN = (
    "the reviewed producer script executed on the named remote host",
    "the artifact bytes are the output of that producer run",
    "the recorded toolchain is the toolchain that ran",
    "the remote host, and not the transport, wrote REMOTE_RUN.json",
)
# A host key signature removes the last of those four and nothing else. Root on
# the pinned host can still sign a run record for an artifact no producer built.
EXECUTION_NOT_PROVEN_HOST_SIGNED = (
    "the reviewed producer script executed on the named remote host",
    "the artifact bytes are the output of that producer run",
    "the recorded toolchain is the toolchain that ran",
)


class RemoteBuildError(Exception):
    """The orchestrator refused."""


def _repo_relative(repo: pathlib.Path, path: pathlib.Path) -> str:
    try:
        return path.resolve(strict=True).relative_to(repo).as_posix()
    except (OSError, ValueError) as exc:
        raise RemoteBuildError(f"path is not inside the repository: {path}") from exc


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _private_snapshot(source: pathlib.Path, destination: pathlib.Path) -> str:
    """Copy source into a new owner-only file and return the copied bytes' digest."""

    digest = hashlib.sha256()
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            while True:
                block = os.read(source_fd, 4 * 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                view = memoryview(block)
                while view:
                    view = view[os.write(destination_fd, view):]
            os.fsync(destination_fd)
            os.fchmod(destination_fd, 0o400)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    return digest.hexdigest()


def _run_dir(repo: pathlib.Path, run_id: str, create: bool) -> pathlib.Path:
    if RUN_ID.fullmatch(run_id) is None:
        raise RemoteBuildError("run id is unsafe")
    parent = repo / ".artifacts" / "remote-builds"
    run = parent / run_id
    if create:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise RemoteBuildError("remote build parent is unsafe")
        run.mkdir(mode=0o700)
    elif run.is_symlink() or not run.is_dir():
        raise RemoteBuildError(f"remote build run directory is missing: {run}")
    return run


def prepare(repo: pathlib.Path, index: pathlib.Path, platform: str, remote_host: str, run_id: str) -> dict[str, object]:
    producer = REMOTE_PRODUCERS.get((platform, remote_host))
    if producer is None:
        raise RemoteBuildError(f"{platform} has no remote-attested producer on {remote_host}")
    run = _run_dir(repo, run_id, create=True)
    begin = run / "BUILD_BEGIN.json"
    archive = run / "SOURCE.tar"
    client.run_build_step(
        repo,
        [
            "begin-build",
            "--index", str(index),
            "--platform", platform,
            "--output", str(begin),
            "--remote-host", remote_host,
            "--source-archive", str(archive),
        ],
    )
    record = json.loads(begin.read_text(encoding="utf-8"))
    remote = record["remote_attestation"]
    index_record = json.loads(index.read_text(encoding="utf-8"))
    index_dir = index.parent
    shared = index_record["shared_manifest"]
    platform_manifest = index_record["platform_manifests"][platform]
    remote_input = {
        "contract": INPUT_CONTRACT,
        "release": record["release"],
        "platform": platform,
        "remote_host": remote_host,
        "build_begin_sha256": _sha256(begin),
        "release_input_index": {
            "path": _repo_relative(repo, index),
            "sha256": record["release_input_index"]["sha256"],
        },
        "shared_manifest": {
            "path": _repo_relative(repo, index_dir / shared["path"]),
            "sha256": shared["sha256"],
        },
        "platform_manifest": {
            "path": _repo_relative(repo, index_dir / platform_manifest["path"]),
            "sha256": platform_manifest["sha256"],
        },
        "source_archive": remote["source_archive"],
        "producer": remote["producer"],
    }
    if remote_input["platform_manifest"]["path"] != record["platform_manifest"]["path"]:
        raise RemoteBuildError("platform manifest path differs from the begin record")
    target = run / "REMOTE_INPUT.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(remote_input, indent=2, sort_keys=True) + "\n")
    return {
        "ok": True,
        "run_directory": _repo_relative(repo, run),
        "begin": _repo_relative(repo, begin),
        "source_archive": remote["source_archive"],
        "remote_input": _repo_relative(repo, target),
        "ship_index_directory": _repo_relative(repo, index_dir),
    }


def signing_plan(platform: str, run_signing: object, sign: bool) -> bool:
    """Return whether the Mac signs; refuse a mismatch with the remote run."""

    if run_signing == "orchestrator":
        if platform != "linux" or not sign:
            raise RemoteBuildError(
                "the remote run deferred signing to this Mac; finish requires --sign"
            )
        return True
    if run_signing in {"unsigned", "producer"}:
        if sign:
            raise RemoteBuildError(
                f"the remote run recorded signing={run_signing}; --sign is refused"
            )
        return False
    raise RemoteBuildError("the remote run record has no reviewed signing mode")


def _linux_public_key_pin(repo: pathlib.Path) -> str:
    matches = PUBLIC_KEY_PIN.findall(
        (repo / "tools/build_linux_release.sh").read_text(encoding="utf-8")
    )
    if len(matches) != 1:
        raise RemoteBuildError("LINUX_COSIGN_PUBLIC_KEY_SHA256 is not one reviewed assignment")
    return matches[0]


def signing_preflight(
    repo: pathlib.Path, allow_unpinned_rehearsal_key: bool
) -> tuple[str, str, str, str]:
    """Validate the Mac signing inputs without touching the private key.

    finish-build consumes the single-use build attempt, so an unset or
    relative key path, a wrong public key or an empty pin without the
    rehearsal flag must refuse before the worker runs. Only the two path
    strings and the public key's digest are read here; the private key is
    opened by the signing tool alone, after verification (sign last).
    """

    key = os.environ.get("WINS_LINUX_COSIGN_KEY", "")
    public = os.environ.get("WINS_LINUX_COSIGN_PUBKEY", "")
    if not key.startswith("/") or not public.startswith("/"):
        raise RemoteBuildError(
            "signing needs absolute WINS_LINUX_COSIGN_KEY and WINS_LINUX_COSIGN_PUBKEY paths"
        )
    public_sha256 = _sha256(pathlib.Path(public))
    pin = _linux_public_key_pin(repo)
    if pin:
        if public_sha256 != pin:
            raise RemoteBuildError(
                f"public key {public_sha256} is not LINUX_COSIGN_PUBLIC_KEY_SHA256 {pin}"
            )
    elif not allow_unpinned_rehearsal_key:
        raise RemoteBuildError(
            "LINUX_COSIGN_PUBLIC_KEY_SHA256 is empty (owner key ceremony pending); "
            "only --allow-unpinned-rehearsal-key with a throwaway key may sign"
        )
    return key, public, public_sha256, pin


def sign_on_mac(
    repo: pathlib.Path,
    run: pathlib.Path,
    artifact: pathlib.Path,
    cosign: str,
    allow_unpinned_rehearsal_key: bool,
    *,
    expected_sha256: str,
) -> dict[str, object]:
    key, public, public_sha256, pin = signing_preflight(
        repo, allow_unpinned_rehearsal_key
    )
    bundle = artifact.with_name(artifact.name + ".sigstore.json")
    # cosign reads the archive by path. It gets a private snapshot whose bytes
    # were hashed while they were copied, never the copied-back artifact path,
    # which a writer there could swap between the re-hash and the key (R23
    # W1-08). The bundle signs bytes, not a path, so it verifies the artifact.
    snapshot_directory = pathlib.Path(tempfile.mkdtemp(prefix=".mac-signing-", dir=run))
    snapshot = snapshot_directory / artifact.name
    public_output = run / "cosign.pub"
    environment = {
        "HOME": os.environ.get("HOME", "/private/tmp"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "SIGN_LINUX_RELEASE": "1",
        "WINS_LINUX_COSIGN_KEY": key,
        "WINS_LINUX_COSIGN_PUBKEY": public,
        "WINS_LINUX_COSIGN_TRUST_ANCHOR": TRUST_ANCHOR_ROUTE,
    }
    if "COSIGN_PASSWORD" in os.environ:
        environment["COSIGN_PASSWORD"] = os.environ["COSIGN_PASSWORD"]
    try:
        if _private_snapshot(artifact, snapshot) != expected_sha256:
            raise RemoteBuildError(
                "artifact bytes changed between receipt verification and Mac signing"
            )
        completed = subprocess.run(
            [
                sys.executable, "-I", str(repo / SIGNING_TOOL), "run-sign-verify",
                "--repo", str(repo),
                "--archive", str(snapshot),
                "--bundle", str(bundle),
                "--cosign", cosign,
                "--public-key-output", str(public_output),
            ],
            stdin=subprocess.DEVNULL,
            env=environment,
            check=False,
        )
        if completed.returncode != 0:
            raise RemoteBuildError(f"Mac signing failed (exit {completed.returncode})")
        if _sha256(snapshot) != expected_sha256:
            raise RemoteBuildError("the private signing snapshot changed while it was signed")
    finally:
        shutil.rmtree(snapshot_directory, ignore_errors=True)
    record = {
        "archive": _repo_relative(repo, artifact),
        "archive_sha256": expected_sha256,
        "bundle": _repo_relative(repo, bundle),
        "bundle_sha256": _sha256(bundle),
        "public_key_sha256": public_sha256,
        "public_key_pinned": bool(pin),
        "tlog_upload": False,
    }
    target = run / "MAC_SIGNING.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def remote_execution_proof(
    repo: pathlib.Path,
    run_record: pathlib.Path,
    remote_host: str,
    record_bytes: bytes | None = None,
) -> tuple[dict[str, str] | None, bool]:
    """Return (host key proof, self_reported) for this run's REMOTE_RUN.json.

    Three cases, and the second one is the point of the design. A pinned host
    key for this remote host means the run record must carry that host's
    signature, so a half-migrated release cannot quietly fall back to trusting
    an unsigned self-report. No trust file at all means the self-report path,
    which the caller must then accept explicitly. Any directory entry at the
    trust path, a dangling or live symbolic link included, is a trust file
    that must load, never an absent one.
    """

    trust_path = repo / signatures.TRUST_RELATIVE_PATH
    if not os.path.lexists(trust_path):
        return None, True
    trust = signatures.load_host_key_trust(repo)
    if remote_host not in trust:
        return None, True
    proof = signatures.verify_run_record_signature(
        run_record, trust, remote_host, record_bytes=record_bytes
    )
    return proof, False


def record_remote_execution_evidence(
    repo: pathlib.Path,
    run: pathlib.Path,
    platform: str,
    remote_host: str,
    remote_run: dict[str, object],
    run_record: pathlib.Path,
    receipt: pathlib.Path,
    artifact: pathlib.Path,
    verified: dict[str, object],
    mac_signing_planned: bool,
    host_key_proof: dict[str, str] | None,
    run_record_sha256: str,
) -> dict[str, object]:
    """Write the honest evidence class of this run next to its receipt.

    `remote-attested` names how the receipt was produced, not how strongly the
    producer's execution was proved. REMOTE_RUN.json is unsigned JSON that the
    remote host, or anything that can write the copied-back run directory,
    composes; the Mac checks its fields and its digests and authenticates no
    execution. This record states that in the run's own evidence so a later
    reader cannot mistake the receipt class for an execution proof. A host key
    signature upgrades the class, and even then the producer's execution is
    still not proved: root on the pinned host can sign any run record.
    """

    record = {
        "contract": EXECUTION_EVIDENCE_CONTRACT,
        "release": remote_run.get("release"),
        "platform": platform,
        "remote_host": remote_host,
        "execution_evidence_class": (
            EXECUTION_EVIDENCE_CLASS_HOST_SIGNED
            if host_key_proof is not None
            else EXECUTION_EVIDENCE_CLASS_SELF_REPORTED
        ),
        "build_begin_sha256": remote_run.get("build_begin_sha256"),
        "remote_run_record": {
            "path": _repo_relative(repo, run_record),
            # The digest of the held bytes the signature was checked over and
            # the worker bound, never a later re-hash of the path.
            "sha256": run_record_sha256,
            "signed_by_remote_host": host_key_proof is not None,
            "host_key_proof": host_key_proof,
        },
        "receipt": {
            "path": _repo_relative(repo, receipt),
            "sha256": _sha256(receipt),
        },
        "artifact": {
            "name": artifact.name,
            "sha256": verified.get("artifact_sha256"),
        },
        "receipt_sha256": verified.get("receipt_sha256"),
        "proven_on_mac": list(EXECUTION_PROVEN_ON_MAC),
        "not_proven": (
            list(EXECUTION_NOT_PROVEN_HOST_SIGNED)
            if host_key_proof is not None
            else list(EXECUTION_NOT_PROVEN)
        ),
        "mac_signing_planned": mac_signing_planned,
        "recorded_utc": dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    target = run / "REMOTE_EXECUTION_EVIDENCE.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    return {"path": _repo_relative(repo, target), "sha256": hashlib.sha256(payload).hexdigest()}


def secret_inventory_path(platform: str) -> str | None:
    """The authenticated secret inventory path a Windows finish and verification name.

    Only the path travels: the authenticated worker passes it to the exact scanner,
    whose own loader authenticates the file. This tool never opens it, and it never
    runs a scan or accepts one, so a Windows receipt cannot be made, or accepted,
    without the worker's scan: finish-build and verify-receipt each run it on the
    installer bytes they hold, and a hit or a scan failure refuses before the
    single-use attempt is spent. A missing inventory refuses here, before anything
    is spent.
    """

    if platform != "windows":
        return None
    inventory = os.environ.get(SECRET_SCAN_INVENTORY_ENV, "")
    if not inventory:
        raise RemoteBuildError(
            f"a Windows finish has the authenticated worker run the exact secret scan and "
            f"needs {SECRET_SCAN_INVENTORY_ENV} to name the authenticated inventory"
        )
    if not os.path.isabs(inventory) or "\0" in inventory or os.path.normpath(inventory) != inventory:
        raise RemoteBuildError(
            f"{SECRET_SCAN_INVENTORY_ENV} must be an absolute normalized path"
        )
    return inventory


def secret_scan_arguments(platform: str) -> list[str]:
    """The finish-build arguments that name the secret inventory for a Windows finish."""

    inventory = secret_inventory_path(platform)
    return [] if inventory is None else ["--secret-inventory-path", inventory]


def finish(
    repo: pathlib.Path,
    index: pathlib.Path,
    platform: str,
    remote_host: str,
    run_id: str,
    artifact: pathlib.Path,
    sign: bool = False,
    cosign: str = "",
    allow_unpinned_rehearsal_key: bool = False,
    accept_remote_self_reported_execution: bool = False,
) -> dict[str, object]:
    producer = REMOTE_PRODUCERS.get((platform, remote_host))
    if producer is None:
        raise RemoteBuildError(f"{platform} has no remote-attested producer on {remote_host}")
    run = _run_dir(repo, run_id, create=False)
    run_record = run / "REMOTE_RUN.json"
    # REMOTE_RUN.json is read once. The host key signature is checked over
    # these held bytes, the toolchain and signing mode come from them, and the
    # worker's receipt must bind exactly their digest (checked below), so a
    # record swapped after this read can borrow neither the verified
    # signature nor its evidence class.
    try:
        run_record_bytes = signatures.read_run_record(run_record)
    except signatures.RemoteRunRecordSignatureError as exc:
        raise RemoteBuildError(str(exc)) from exc
    run_record_sha256 = hashlib.sha256(run_record_bytes).hexdigest()
    remote_run = json.loads(run_record_bytes.decode("utf-8"))
    # Checked before the worker runs and before any key is reachable: a host
    # key signature is verified here when one is pinned for this host, and
    # without one the operator must accept the self-report explicitly.
    try:
        host_key_proof, self_reported = remote_execution_proof(
            repo, run_record, remote_host, run_record_bytes
        )
    except signatures.RemoteRunRecordSignatureError as exc:
        raise RemoteBuildError(str(exc)) from exc
    if self_reported and not accept_remote_self_reported_execution:
        raise RemoteBuildError(
            "a remote-attested receipt proves no remote execution: REMOTE_RUN.json "
            "is unsigned self-reported JSON, and the Mac binds artifact bytes "
            "without authenticating the run that produced them. Pass "
            "--accept-remote-self-reported-execution to record that acceptance "
            f"explicitly in this run's evidence, or pin a host key in "
            f"{signatures.TRUST_RELATIVE_PATH} and sign the run record on the "
            "remote host."
        )
    toolchain = remote_run["toolchain"]
    # Decided before the worker runs so a mismatch between --sign and the
    # remote run's recorded mode still refuses without touching the key.
    mac_signs = signing_plan(platform, remote_run.get("signing"), sign)
    if mac_signs:
        # Refuse a misconfigured signing environment now, before finish-build
        # spends the single-use attempt. This reads no private key.
        signing_preflight(repo, allow_unpinned_rehearsal_key)
    # The authenticated worker runs the Windows secret scan inside finish-build,
    # before it spends the single-use attempt, on the same bytes it hashes itself.
    secret_scan = secret_scan_arguments(platform)
    receipt = run / "BUILD_RECEIPT.json"
    built = client.run_build_step(
        repo,
        [
            "finish-build",
            "--index", str(index),
            "--platform", platform,
            "--begin", str(run / "BUILD_BEGIN.json"),
            "--artifact", str(artifact),
            "--producer", producer,
            "--toolchain-name", toolchain["name"],
            "--toolchain-version", toolchain["version"],
            "--toolchain-revision", toolchain["revision"],
            "--target", toolchain["target"],
            "--output", str(receipt),
            "--remote-host", remote_host,
            "--remote-run-record", str(run_record),
        ]
        + secret_scan,
    )
    # The worker re-read REMOTE_RUN.json by path. Its authenticated record
    # names the digest it bound; anything but the held bytes checked above
    # means the run record moved in between.
    bound = built.get("remote_attestation") if type(built) is dict else None
    bound_run = bound.get("run_record") if type(bound) is dict else None
    if type(bound_run) is not dict or bound_run.get("sha256") != run_record_sha256:
        raise RemoteBuildError(
            "the worker bound a REMOTE_RUN.json other than the one this finish verified"
        )
    verified = client.verify_build_receipt(
        repo, index, platform, receipt, artifact, secret_inventory_path(platform)
    )
    evidence = record_remote_execution_evidence(
        repo,
        run,
        platform,
        remote_host,
        remote_run,
        run_record,
        receipt,
        artifact,
        verified,
        mac_signs,
        host_key_proof,
        run_record_sha256,
    )
    signed = None
    if mac_signs:
        # SIGN LAST. The worker has now bound these exact bytes to the begin
        # record and verify-receipt has re-checked the artifact against the
        # receipt it wrote. Re-hashing here closes the window between that
        # verification and the key: cosign writes a sidecar bundle and never
        # rewrites the archive, so a digest that moved can only mean the file
        # was substituted, and the refused signature is the cheaper loss.
        if verified.get("artifact_sha256") != _sha256(artifact):
            raise RemoteBuildError(
                "artifact bytes changed between receipt verification and Mac signing"
            )
        signed = sign_on_mac(repo, run, artifact, cosign, allow_unpinned_rehearsal_key,
                             expected_sha256=str(verified.get("artifact_sha256")))
    return {
        "ok": True,
        "receipt": _repo_relative(repo, receipt),
        "receipt_sha256": verified.get("receipt_sha256"),
        "artifact_sha256": verified.get("artifact_sha256"),
        "execution_evidence": evidence,
        "mac_signing": signed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "finish"):
        command = commands.add_parser(name)
        command.add_argument("--repo", required=True)
        command.add_argument("--index", required=True)
        command.add_argument("--platform", choices=("linux", "windows"), required=True)
        command.add_argument("--remote-host", choices=("linux", "windows"), required=True)
        command.add_argument("--run-id", required=True)
        if name == "finish":
            command.add_argument("--artifact", required=True)
            command.add_argument("--sign", action="store_true")
            command.add_argument("--cosign", default="")
            command.add_argument("--allow-unpinned-rehearsal-key", action="store_true")
            command.add_argument(
                "--accept-remote-self-reported-execution",
                action="store_true",
                help="record that this run's remote execution proof is an "
                     "unsigned self-report; refused without it",
            )
    args = parser.parse_args(argv)
    repo = pathlib.Path(args.repo).resolve(strict=True)
    index = pathlib.Path(args.index).resolve(strict=True)
    try:
        if args.command == "prepare":
            result = prepare(repo, index, args.platform, args.remote_host, args.run_id)
        else:
            result = finish(
                repo,
                index,
                args.platform,
                args.remote_host,
                args.run_id,
                pathlib.Path(args.artifact).resolve(strict=True),
                args.sign,
                args.cosign,
                args.allow_unpinned_rehearsal_key,
                args.accept_remote_self_reported_execution,
            )
    except (RemoteBuildError, client.FreezeClientError, OSError, KeyError, ValueError) as exc:
        print(f"REMOTE ATTESTED BUILD: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"REMOTE ATTESTED BUILD: PASS {args.command} {json.dumps(result, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
