#!/usr/bin/env python3
"""Host-key signature over REMOTE_RUN.json, verified on the Mac.

Why this exists. `remote-attested` binds artifact bytes to the begin record,
but REMOTE_RUN.json itself is unsigned JSON composed on the remote host. The
Mac re-hashes every byte it holds and authenticates no execution, so a
substituted artifact plus a matching substituted run record passes every check
tools/release_dependency_freeze.py performs. This module closes the transport
half of that gap and raises the bar on the host half.

Mechanism. OpenSSH's built-in signature format, which needs no new key
ceremony and no new dependency:

  remote host, as root, after record-run:
    /usr/bin/ssh-keygen -Y sign \
      -f /etc/ssh/ssh_host_ed25519_key \
      -n winsvpn-remote-run-v1 \
      REMOTE_RUN.json
  -> writes REMOTE_RUN.json.sig

  Mac, in finish before the worker runs:
    verify_run_record_signature(...)

The signing key is the host's own SSH host key, readable only by root, so a
process running as the build user cannot produce a signature and neither can
anything that only ever touches the copied-back run directory. The Mac pins the
public key and the principal per remote host in
tools/release_remote_host_keys.trust.json, and the pinned principal must appear
in the verified signature.

What this does NOT prove. It does not prove the reviewed producer script ran:
root on the build host can sign a run record for any artifact. It converts
"anyone who can write the run directory" into "root on the pinned host", which
is a real reduction and not a complete one. A reproducible double build on two
independent hosts, compared on the Mac, is the stronger proof and is the reason
this module records the key fingerprint rather than pretending to attest
execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import posixpath
import re
import subprocess
import tempfile

SIGNATURE_NAMESPACE = "winsvpn-remote-run-v1"
TRUST_RELATIVE_PATH = "tools/release_remote_host_keys.trust.json"
RUN_RECORD_NAME = "REMOTE_RUN.json"
SIGNATURE_SUFFIX = ".sig"
MAX_TRUST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_RUN_RECORD_BYTES = 16 * 1024 * 1024
SSH_KEYGEN = "/usr/bin/ssh-keygen"
TRUST_CONTRACT = "winsvpn-remote-host-keys-v1"
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}")
PUBLIC_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]{40,}")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/=]{43}")


class RemoteRunRecordSignatureError(Exception):
    """A host-key signature check refused."""


def remote_sign_command(host_key_path: str, run_record_path: str) -> list[str]:
    """The exact command the remote host runs, as root, after record-run."""

    return [
        SSH_KEYGEN, "-Y", "sign",
        "-f", host_key_path,
        "-n", SIGNATURE_NAMESPACE,
        run_record_path,
    ]


def _fail(message: str) -> None:
    raise RemoteRunRecordSignatureError(message)


def _read_bounded(path: pathlib.Path, limit: int, label: str) -> bytes:
    try:
        info = os.lstat(path)
    except OSError as exc:
        _fail(f"{label} is unreadable: {exc}")
    import stat as stat_module

    if stat_module.S_ISLNK(info.st_mode) or not stat_module.S_ISREG(info.st_mode):
        _fail(f"{label} must be a regular non-symlink file")
    if info.st_size <= 0 or info.st_size > limit:
        _fail(f"{label} size is outside its bound")
    # One descriptor carries every decision: the file whose type and size were
    # checked above is the file whose bytes are returned, and nothing reopens
    # the path, so a swap or growth after the lstat is refused, not read.
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        _fail(f"{label} is unreadable: {exc}")
    try:
        opened = os.fstat(descriptor)
        if not stat_module.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) != (info.st_dev, info.st_ino, info.st_size):
            _fail(f"{label} changed while it was opened")
        chunks = []
        remaining = opened.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                _fail(f"{label} was truncated while it was read")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            _fail(f"{label} grew while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_run_record(run_record: pathlib.Path) -> bytes:
    """Read REMOTE_RUN.json once: bounded, regular, never through a symlink.

    The caller verifies the signature over these bytes and takes every value
    it needs from them, never from a second read of the same path.
    """

    return _read_bounded(run_record, MAX_RUN_RECORD_BYTES, "remote run record")


def load_host_key_trust(repo: pathlib.Path) -> dict[str, dict[str, str]]:
    """Load and validate the pinned per-host public keys."""

    payload = _read_bounded(
        repo / TRUST_RELATIVE_PATH, MAX_TRUST_BYTES, "remote host key trust"
    )
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _fail(f"remote host key trust is not JSON: {exc}")
    if type(document) is not dict or document.get("contract") != TRUST_CONTRACT:
        _fail("remote host key trust has the wrong contract")
    hosts = document.get("hosts")
    if type(hosts) is not dict or not hosts:
        _fail("remote host key trust names no hosts")
    validated: dict[str, dict[str, str]] = {}
    for host, entry in hosts.items():
        if host not in {"linux", "windows"}:
            _fail(f"remote host key trust names an unsupported host: {host}")
        if type(entry) is not dict or set(entry) != {
            "principal",
            "public_key",
            "public_key_sha256",
            "host_key_path",
        }:
            _fail(f"remote host key trust entry for {host} has the wrong keys")
        principal = entry["principal"]
        public_key = entry["public_key"]
        digest = entry["public_key_sha256"]
        host_key_path = entry["host_key_path"]
        if (
            type(principal) is not str
            or PRINCIPAL.fullmatch(principal) is None
            or type(public_key) is not str
            or PUBLIC_KEY.fullmatch(public_key.strip()) is None
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(host_key_path) is not str
            or not host_key_path.startswith("/etc/ssh/")
            # Normalized: a ".." segment would leave /etc/ssh while still passing the
            # prefix test, and the path is what the remote host signs with as root.
            or posixpath.normpath(host_key_path) != host_key_path
        ):
            _fail(f"remote host key trust entry for {host} is malformed")
        if hashlib.sha256(public_key.strip().encode("utf-8")).hexdigest() != digest:
            _fail(f"remote host key trust entry for {host} does not match its digest")
        validated[host] = {
            "principal": principal,
            "public_key": public_key.strip(),
            "public_key_sha256": digest,
            "host_key_path": host_key_path,
        }
    return validated


def verify_run_record_signature(
    run_record: pathlib.Path,
    trust: dict[str, dict[str, str]],
    remote_host: str,
    ssh_keygen: str = SSH_KEYGEN,
    record_bytes: bytes | None = None,
) -> dict[str, str]:
    """Verify REMOTE_RUN.json.sig against the pinned host key for this host.

    Returns the verified principal and public key fingerprint. Every failure
    mode raises; there is no fallback and no warning-only path. A caller that
    already holds the run record (read_run_record) passes those exact bytes,
    so the bytes verified here are the bytes it goes on to use.
    """

    entry = trust.get(remote_host)
    if entry is None:
        _fail(f"no pinned host key for remote host {remote_host}")
    signature_path = run_record.with_name(run_record.name + SIGNATURE_SUFFIX)
    if record_bytes is None:
        record_bytes = read_run_record(run_record)
    signature_bytes = _read_bounded(
        signature_path, MAX_SIGNATURE_BYTES, "remote run record signature"
    )

    allowed = f"{entry['principal']} {entry['public_key']}\n"
    # Each temporary file is created inside the try, so a failure to create
    # the second one still removes the first and is reported as a refusal.
    temporary_names: list[str] = []
    try:
        descriptor, allowed_name = tempfile.mkstemp(prefix="wins-allowed-signers-")
        temporary_names.append(allowed_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(allowed)
        os.chmod(allowed_name, 0o600)
        # ssh-keygen takes the signature by path, so it gets a private copy
        # of the exact bytes _read_bounded judged, never the run directory's
        # .sig path, which a writer there could swap after the bound check.
        signature_descriptor, signature_name = tempfile.mkstemp(
            prefix="wins-run-record-sig-"
        )
        temporary_names.append(signature_name)
        with os.fdopen(signature_descriptor, "wb") as handle:
            handle.write(signature_bytes)
        os.chmod(signature_name, 0o600)
        completed = subprocess.run(
            [
                ssh_keygen, "-Y", "verify",
                "-f", allowed_name,
                "-I", entry["principal"],
                "-n", SIGNATURE_NAMESPACE,
                "-s", signature_name,
            ],
            input=record_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail(f"host key signature verification did not run: {exc}")
    finally:
        for name in temporary_names:
            try:
                os.unlink(name)
            except OSError:
                pass

    if completed.returncode != 0:
        detail = " ".join(completed.stdout.decode("utf-8", "replace").split())
        _fail(f"remote run record signature is not valid: {detail[:300] or 'no diagnostic'}")
    output = completed.stdout.decode("utf-8", "replace")
    expected_prefix = f'Good "{SIGNATURE_NAMESPACE}" signature for {entry["principal"]}'
    if expected_prefix not in output:
        _fail("signature verification did not name the pinned principal")
    match = FINGERPRINT.search(output)
    if match is None:
        _fail("signature verification reported no key fingerprint")
    return {
        "principal": entry["principal"],
        "public_key_sha256": entry["public_key_sha256"],
        "key_fingerprint": match.group(0),
        "namespace": SIGNATURE_NAMESPACE,
    }
