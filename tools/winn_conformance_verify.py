#!/usr/bin/env python3
"""Winn Protocol platform conformance harness -- lane: conformance.

WHY THIS EXISTS. This project has a documented history of work that reports
success it never achieved: scripts printing "PASS" on files they never
modified, wrappers returning exit code 0 while the real build exited 1, and
agents describing integrations against repo paths that do not exist. Every
check in this file is built around one rule: verify the artifact/claim
directly (existence, size, real file-type magic, real compiled symbols, real
executed output), never the mere fact that some other script said it worked.
Concretely:

  * `build-matrix` runs the release driver (`tools/winn_release.py build`),
    which builds every target twice from a sealed source snapshot, and then
    re-checks every output itself: build A, build B and the bytes on disk must
    have one SHA-256, and each artifact must parse as the exact ELF, PE32+,
    Mach-O or c-archive (Go build info, role symbols, generated header) its
    target declares. ARM64 bytes may never be reused across targets.
  * We never trust `tools/build_winn_protocol_engine.sh`'s own "Validated"
    print statement for the iOS c-archive -- we re-run nm/lipo/vtool
    ourselves, independently, in `ios_archive_gates()`.
  * We never trust a progress-note's prose claim about a file or line range --
    `scan_claims()` extracts path-like tokens from every lane's own
    `.winn_platform_progress/*.json` and checks each one against the real
    filesystem.
  * We never trust that "tunnel_supported: false" is what a binary *would*
    say -- `native_runtime_claims()` actually executes the compiled artifact
    and parses its real stdout, and only after `winn_release.py verify` has
    verified the signed release manifest that names those exact bytes.
  * Every subprocess call goes through `run()`, which returns the real
    returncode/stdout/stderr and nothing else. No status here is ever
    inferred from anything but a real command's real exit code and output.

Anything this script cannot actually run (missing toolchain, missing file,
unsigned release, timeout) is reported as UNVERIFIED, never PASS. See
CONFORMANCE.md-style rationale in WINN_PROTOCOL_PLATFORM_PLAN.md rule 8
(anti-fabrication).

Usage:
    tools/winn_conformance_verify.py all --source-commit SHA [--save-baseline LABEL]
    tools/winn_conformance_verify.py build-matrix --source-commit SHA
        [--targets t1,t2,...] [--out-dir DIR] [--source-export DIR]
        [--go-archive PATH] [--ndk DIR] [--developer-dir DIR]
        [--module-proxy URL] [--jobs N]
    tools/winn_conformance_verify.py ios-archive-gates <path-to-.a>
    tools/winn_conformance_verify.py native-runtime-claims --release DIR --target T
    tools/winn_conformance_verify.py protocol-order --release DIR --target T
    tools/winn_conformance_verify.py symbols <path> --expect SYM1,SYM2,...
    tools/winn_conformance_verify.py ground-truth
    tools/winn_conformance_verify.py scan-claims
    tools/winn_conformance_verify.py baselines [--save-baseline LABEL]
    tools/winn_conformance_verify.py diff-baselines LABEL1 LABEL2

Exit codes: 0 everything PASSed. 1 at least one real FAIL. 2 nothing failed
but at least one check is UNVERIFIED (e.g. a toolchain is missing on this
host) -- read the report before treating that as fine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping, Optional

ROOT = Path(__file__).resolve().parent.parent
WINN_MODULE = ROOT / "winn_protocol_experimental"
BUILD_SCRIPT = ROOT / "tools" / "build_winn_protocol_engine.sh"
RELEASE_DRIVER = ROOT / "tools" / "winn_release.py"
RELEASE_DRIVER_PYTHON = "/usr/bin/python3"
RELEASE_AUTHORITY = ROOT / "tools" / "winn_release_authority.json"
RELEASE_GO_CUSTODY = ROOT / "tools" / "release_go_archive_custody.py"
CSHARED_SOURCE = WINN_MODULE / "cshared" / "winn_clientbinding.go"
PROGRESS_DIR = ROOT / ".winn_platform_progress"
BUILD_OUT_DIR = ROOT / "tools" / "winn_conformance_build_out"
RESULTS_DIR = ROOT / "tools" / "winn_conformance_results"

PASS, FAIL, UNVERIFIED, INFO = "PASS", "FAIL", "UNVERIFIED", "INFO"
STATUSES = (PASS, FAIL, UNVERIFIED, INFO)
MAX_CHECKS = 256
MAX_CHECK_NAME_CHARS = 192
MAX_CHECK_DETAIL_CHARS = 1024
MAX_SUBPROCESS_OUTPUT_BYTES = 64 * 1024
SUBPROCESS_OUTPUT_LIMIT_RC = 125


def _bounded_text(value: object, limit: int) -> str:
    text = "".join(
        character
        if character == "\t" or (
            character >= " "
            and character != "\x7f"
            and character not in {"\x85", "\u2028", "\u2029"}
        )
        else f"\\x{ord(character):02x}"
        for character in str(value)
    )
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    marker = f"...[truncated {omitted} chars]"
    if len(marker) >= limit:
        return marker[:limit]
    return text[: limit - len(marker)] + marker

# ---------------------------------------------------------------------------
# Small result plumbing. Every check appends a Check; nothing is a PASS
# unless a real command or a real filesystem stat said so.
# ---------------------------------------------------------------------------


@dataclass
class Check:
    status: str
    name: str
    detail: str = ""

    def line(self) -> str:
        return f"[{self.status:<10}] {self.name}" + (f" -- {self.detail}" if self.detail else "")


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    omitted_counts: dict[str, int] = field(
        default_factory=lambda: {status: 0 for status in STATUSES}
    )

    def add(self, status: str, name: str, detail: str = "") -> Check:
        if status not in STATUSES:
            raise ValueError(f"unknown check status {status!r}")
        c = Check(
            status,
            _bounded_text(name, MAX_CHECK_NAME_CHARS),
            _bounded_text(detail, MAX_CHECK_DETAIL_CHARS),
        )
        if len(self.checks) >= MAX_CHECKS:
            self.omitted_counts[status] += 1
            return c
        self.checks.append(c)
        print(c.line())
        return c

    def extend(self, other: "Report") -> None:
        for check in other.checks:
            self.add(check.status, check.name, check.detail)
        for status, count in other.omitted_counts.items():
            self.omitted_counts[status] += count

    def worst_exit_code(self) -> int:
        statuses = {c.status for c in self.checks}
        if FAIL in statuses or self.omitted_counts[FAIL]:
            return 1
        if UNVERIFIED in statuses or self.omitted_counts[UNVERIFIED]:
            return 2
        if PASS not in statuses and not self.omitted_counts[PASS]:
            return 2
        return 0

    def summary(self) -> str:
        counts = {
            status: sum(1 for check in self.checks if check.status == status)
            + self.omitted_counts[status]
            for status in STATUSES
        }
        stored = len(self.checks)
        omitted = sum(self.omitted_counts.values())
        suffix = f"; {stored} stored, {omitted} omitted by output bound" if omitted else ""
        return (
            f"{stored + omitted} checks: {counts[PASS]} PASS, {counts[FAIL]} FAIL, "
            f"{counts[UNVERIFIED]} UNVERIFIED, {counts[INFO]} INFO{suffix}"
        )


_ENV_ALLOWLIST = frozenset({
    "ANDROID_HOME", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_SDK_ROOT",
    "DEVELOPER_DIR", "HOME", "LANG", "LC_ALL", "PATH", "PATHEXT", "SYSTEMROOT",
    "TMPDIR", "WINDIR", "WINS_RELEASE_GO_ARCHIVE_SHA256",
    "WINS_RELEASE_GO_SHA256", "WINS_RELEASE_GO_TREE_SHA256", "WINS_STORE_GOCACHE",
    "WINS_GO_CUSTODY_ISSUANCE", "WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT",
    "WINS_STORE_GOMODCACHE", "WINS_STORE_GOMODCACHE_TREE_SHA256",
    "WINS_WINN_SOURCE_ROOT", "WINS_WINN_SOURCE_TREE_SHA256",
    "WINS_ANDROID_NDK_ROOT", "WINS_ANDROID_NDK_TREE_SHA256",
    "WINS_APPLE_DEVELOPER_DIR", "WINS_APPLE_DEVELOPER_TREE_SHA256",
})


def constructed_environment(overrides: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """Return the explicit environment used by every conformance subprocess."""
    environment = {
        name: os.environ[name]
        for name in _ENV_ALLOWLIST
        if name in os.environ
    }
    environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    environment["HOME"] = "/var/empty"
    environment["LANG"] = "C"
    environment["LC_ALL"] = "C"
    if overrides is not None:
        for name, value in overrides.items():
            if not isinstance(name, str) or not isinstance(value, str) or "\x00" in name + value:
                raise ValueError("subprocess environment keys and values must be NUL-free strings")
            if name not in _ENV_ALLOWLIST:
                raise ValueError(f"subprocess environment override is not allowed: {name}")
            if name in {"HOME", "PATH"}:
                raise ValueError(f"subprocess environment override is fixed by custody policy: {name}")
            environment[name] = value
    return environment


def _decode_bounded_output(payload: bytes) -> tuple[str, bool]:
    try:
        return payload.decode("utf-8", errors="strict"), False
    except UnicodeDecodeError:
        return "", True


def run(
    cmd: list[str],
    cwd: Optional[Path] = None,
    timeout: int = 180,
    env: Optional[Mapping[str, str]] = None,
    pass_fds: tuple[int, ...] = (),
    output_limit: int = MAX_SUBPROCESS_OUTPUT_BYTES,
) -> tuple[int, str, str]:
    """Run a real subprocess and return its real (returncode, stdout, stderr).

    This is the only place in the harness allowed to invoke a subprocess.
    It never synthesizes a result: a timeout or missing binary is surfaced
    as a distinct, honestly-labeled failure, not folded into a generic
    non-zero code that could be mistaken for the program's own exit status.
    """
    command_environment = constructed_environment(env)
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = {"stdout": False, "stderr": False}
    limit_event = threading.Event()
    proc: Optional[subprocess.Popen[bytes]] = None

    def terminate_process_group() -> None:
        if proc is None:
            return
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except (OSError, ProcessLookupError):
            pass

    def close_process_pipes() -> None:
        if proc is None:
            return
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()

    def drain(name: str, stream: Any) -> None:
        while True:
            block = stream.read(8192)
            if not block:
                return
            remaining = output_limit - len(buffers[name])
            if remaining > 0:
                buffers[name].extend(block[:remaining])
            if len(block) > remaining:
                exceeded[name] = True
                limit_event.set()
                terminate_process_group()
                return

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=command_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
            pass_fds=pass_fds if os.name == "posix" else (),
        )
        assert proc.stdout is not None and proc.stderr is not None
        readers = [
            threading.Thread(target=drain, args=("stdout", proc.stdout), daemon=True),
            threading.Thread(target=drain, args=("stderr", proc.stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            terminate_process_group()
            proc.wait()
            for reader in readers:
                reader.join(timeout=1)
            close_process_pipes()
            return 124, "", _bounded_text(
                f"TIMEOUT after {timeout}s running: {' '.join(cmd)}",
                MAX_CHECK_DETAIL_CHARS,
            )
        for reader in readers:
            reader.join(timeout=max(0.0, deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            terminate_process_group()
            for reader in readers:
                reader.join(timeout=1)
            close_process_pipes()
            return 124, "", _bounded_text(
                f"TIMEOUT after {timeout}s waiting for subprocess output closure: {' '.join(cmd)}",
                MAX_CHECK_DETAIL_CHARS,
            )
        close_process_pipes()
        out, stdout_invalid = _decode_bounded_output(bytes(buffers["stdout"]))
        err, stderr_invalid = _decode_bounded_output(bytes(buffers["stderr"]))
    except FileNotFoundError as exc:
        return 127, "", f"command not found: {exc}"
    except OSError as exc:
        return 126, "", f"command could not run: {exc}"

    if any(exceeded.values()) or stdout_invalid or stderr_invalid:
        streams = ", ".join(
            name for name in ("stdout", "stderr")
            if exceeded[name] or (name == "stdout" and stdout_invalid) or (name == "stderr" and stderr_invalid)
        )
        limit_message = (
            f"STRUCTURAL OUTPUT LIMIT: {streams} exceeded {output_limit} "
            "bytes or was not valid UTF-8"
        )
        err = f"{err.rstrip()}\n{limit_message}\n" if err else f"{limit_message}\n"
        return SUBPROCESS_OUTPUT_LIMIT_RC, out, err
    return proc.returncode, out, err


# ---------------------------------------------------------------------------
# Structural protocol-order custody. This is deliberately pure: it validates
# a bounded JSON observation without launching a platform engine or build.
# ---------------------------------------------------------------------------

PROTOCOL_ORDER_CONTRACT = "winsvpn-winn-protocol-order-v1"
PROTOCOL_ORDER = ("winn/3", "winn/1-amneziawg", "xray")
PROTOCOL_AVAILABILITY = {"available", "unavailable", "unverified"}
PROTOCOL_CUSTODY = {"verified", "owner-blocked"}
MAX_PROTOCOL_ORDER_BYTES = 64 * 1024
PLATFORM_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_structural_json(payload: str) -> object:
    return json.loads(
        payload,
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number {value}")
        ),
    )


def verify_protocol_order(
    report: Report,
    document: object,
    *,
    authenticated_release_evidence: bool = False,
) -> None:
    label = "protocol-order"
    root_keys = {"contract", "platform", "selected", "engines"}
    engine_keys = {"id", "availability", "custody", "detail"}

    if type(document) is not dict:
        report.add(FAIL, f"{label}: root is an object", f"got {type(document).__name__}")
        return
    if set(document) != root_keys:
        report.add(
            FAIL,
            f"{label}: root keys are exact",
            f"expected {sorted(root_keys)}, got {sorted(map(str, document))}",
        )
        return
    if document["contract"] != PROTOCOL_ORDER_CONTRACT:
        report.add(FAIL, f"{label}: contract identity", repr(document["contract"]))
        return
    platform_id = document["platform"]
    if type(platform_id) is not str or PLATFORM_ID_RE.fullmatch(platform_id) is None:
        report.add(FAIL, f"{label}: platform identity is deterministic", repr(platform_id))
        return
    engines = document["engines"]
    if type(engines) is not list or len(engines) != len(PROTOCOL_ORDER):
        length = len(engines) if type(engines) is list else "not-a-list"
        report.add(
            FAIL,
            f"{label}[{platform_id}]: engine set is complete",
            f"expected {len(PROTOCOL_ORDER)} ordered engines, got {length}",
        )
        return

    normalized: list[dict[str, str]] = []
    for index, (expected_id, raw_engine) in enumerate(zip(PROTOCOL_ORDER, engines)):
        entry_label = f"{label}[{platform_id}].engines[{index}]"
        if type(raw_engine) is not dict or set(raw_engine) != engine_keys:
            got = sorted(map(str, raw_engine)) if type(raw_engine) is dict else type(raw_engine).__name__
            report.add(FAIL, f"{entry_label}: keys are exact", f"expected {sorted(engine_keys)}, got {got}")
            return
        engine_id = raw_engine["id"]
        availability = raw_engine["availability"]
        custody = raw_engine["custody"]
        detail = raw_engine["detail"]
        if engine_id != expected_id:
            report.add(
                FAIL,
                f"{entry_label}: engine order is fixed",
                f"expected {expected_id!r}, got {engine_id!r}",
            )
            return
        if type(availability) is not str or availability not in PROTOCOL_AVAILABILITY:
            report.add(FAIL, f"{entry_label}: availability is recognized", repr(availability))
            return
        if type(custody) is not str or custody not in PROTOCOL_CUSTODY:
            report.add(FAIL, f"{entry_label}: custody is recognized", repr(custody))
            return
        if type(detail) is not str:
            report.add(FAIL, f"{entry_label}: custody detail is text", type(detail).__name__)
            return
        if custody == "owner-blocked":
            if not detail.strip():
                report.add(FAIL, f"{entry_label}: owner blocker is explicit", "empty detail")
                return
            report.add(
                UNVERIFIED,
                f"{entry_label}: platform custody is owner-blocked",
                detail,
            )
            if availability == "available":
                report.add(
                    FAIL,
                    f"{entry_label}: owner-blocked evidence cannot prove availability",
                    "availability must be unavailable or unverified",
                )
                return
        elif availability == "unverified":
            report.add(
                UNVERIFIED,
                f"{entry_label}: availability is unverified",
                detail or "no verified platform observation",
            )
        normalized.append(
            {
                "id": engine_id,
                "availability": availability,
                "custody": custody,
                "detail": detail,
            }
        )

    selected = document["selected"]
    if selected is not None and (type(selected) is not str or selected not in PROTOCOL_ORDER):
        report.add(FAIL, f"{label}[{platform_id}]: selected engine is recognized", repr(selected))
        return

    if selected is None:
        available = [
            engine["id"]
            for engine in normalized
            if engine["availability"] == "available"
        ]
        if available:
            report.add(
                FAIL,
                f"{label}[{platform_id}]: an available engine is selected",
                f"available but unselected: {available}",
            )
        elif all(engine["availability"] == "unavailable" for engine in normalized):
            report.add(
                UNVERIFIED,
                f"{label}[{platform_id}]: no engine is usable",
                "all engines are explicitly unavailable",
            )
        else:
            report.add(
                UNVERIFIED,
                f"{label}[{platform_id}]: no engine selected",
                "at least one engine remains unverified",
            )
        return

    selected_index = PROTOCOL_ORDER.index(selected)
    selected_engine = normalized[selected_index]
    if selected_engine["availability"] != "available" or selected_engine["custody"] != "verified":
        report.add(
            FAIL,
            f"{label}[{platform_id}]: selected engine is verified available",
            f"{selected}: availability={selected_engine['availability']}, custody={selected_engine['custody']}",
        )
        return

    blocked_predecessors = [
        engine
        for engine in normalized[:selected_index]
        if engine["availability"] != "unavailable"
    ]
    if blocked_predecessors:
        report.add(
            FAIL,
            f"{label}[{platform_id}]: fallback predecessors are explicitly unavailable",
            ", ".join(
                f"{engine['id']}={engine['availability']}" for engine in blocked_predecessors
            ),
        )
        return

    if not authenticated_release_evidence:
        report.add(
            UNVERIFIED,
            f"{label}[{platform_id}]: caller-authored order has no release authority",
            "PASS requires output from an executable in a signed release verified by winn_release.py verify",
        )
        return
    report.add(
        PASS,
        f"{label}[{platform_id}]: Winn v3 primary then Winn v1 AWG then Xray",
        f"selected {selected}",
    )


def load_protocol_order(path: Path, report: Report) -> Optional[object]:
    label = "protocol-order input"
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            report.add(FAIL, f"{label}: regular file", str(path))
            return None
        size = opened.st_size
        if size <= 0 or size > MAX_PROTOCOL_ORDER_BYTES:
            report.add(
                FAIL,
                f"{label}: bounded size",
                f"{size} bytes; allowed 1..{MAX_PROTOCOL_ORDER_BYTES}",
            )
            return None
        raw = bytearray()
        while len(raw) <= MAX_PROTOCOL_ORDER_BYTES:
            block = os.read(fd, min(8192, MAX_PROTOCOL_ORDER_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        if (
            len(raw) != size
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns)
        ):
            report.add(FAIL, f"{label}: stable descriptor identity", str(path))
            return None
        payload = bytes(raw).decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        report.add(FAIL, f"{label}: readable UTF-8", str(exc))
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        return parse_structural_json(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        report.add(FAIL, f"{label}: strict JSON", str(exc))
        return None


# ---------------------------------------------------------------------------
# Generic artifact existence / size / plausible-file-type checker.
# Reusable for ANY lane's claimed output, not just the Go engine.
# ---------------------------------------------------------------------------


def check_artifact(report: Report, path: Path, label: str, type_regex: Optional[str] = None, min_size: int = 1) -> Optional[str]:
    """Verify a claimed artifact actually exists, is non-empty, and (if a
    type_regex is given) that `file`(1) reports a plausible type. Returns the
    real `file` output on success, or None on failure -- callers that need
    the file-type string for a further check (e.g. arch matching) get it
    without re-invoking `file`.
    """
    if not path.exists():
        report.add(FAIL, f"{label}: exists", f"missing at {path}")
        return None
    try:
        size = path.stat().st_size
    except OSError as exc:
        report.add(FAIL, f"{label}: exists", f"stat failed: {exc}")
        return None
    if size < min_size:
        report.add(FAIL, f"{label}: non-zero size", f"{size} bytes at {path}")
        return None
    report.add(PASS, f"{label}: exists, non-zero size", f"{size} bytes at {path}")

    rc, out, err = run(["file", "-b", str(path)])
    if rc != 0:
        report.add(UNVERIFIED, f"{label}: file(1) type", f"`file` failed: {err.strip()}")
        return None
    file_out = out.strip()
    if type_regex is not None:
        if re.search(type_regex, file_out):
            report.add(PASS, f"{label}: plausible file type", file_out)
        else:
            report.add(FAIL, f"{label}: plausible file type", f"got {file_out!r}, expected to match /{type_regex}/")
            return None
    else:
        report.add(INFO, f"{label}: file(1) type", file_out)
    return file_out


# ---------------------------------------------------------------------------
# 1. The complete 30-target Go engine build matrix.
# ---------------------------------------------------------------------------

# (target, output filename, `file`(1) OS-family regex, exact arch hint)
TARGETS: list[tuple[str, str, str, str]] = [
    ("windows-amd64", "winn-clientinfo-windows-amd64.exe", r"PE32\+? executable", "x86-64|x86_64"),
    ("windows-arm64", "winn-clientinfo-windows-arm64.exe", r"PE32\+? executable", "aarch64|arm64|ARM64|Aarch64"),
    ("darwin-amd64", "winn-clientinfo-darwin-amd64", r"Mach-O 64-bit executable", "x86_64"),
    ("darwin-arm64", "winn-clientinfo-darwin-arm64", r"Mach-O 64-bit executable", "arm64"),
    ("linux-amd64", "winn-clientinfo-linux-amd64", r"ELF 64-bit LSB (?:executable|pie executable)", "x86-64|x86_64"),
    ("linux-arm64", "winn-clientinfo-linux-arm64", r"ELF 64-bit LSB (?:executable|pie executable)", "ARM aarch64|aarch64"),
    ("android-arm64", "winn-clientinfo-android-arm64", r"ELF 64-bit LSB (?:pie executable|executable)", "ARM aarch64|aarch64"),
    ("android-arm", "winn-clientinfo-android-arm", r"ELF 32-bit LSB (?:pie executable|executable|shared object)", "ARM"),
    ("android-amd64", "winn-clientinfo-android-amd64", r"ELF 64-bit LSB (?:pie executable|executable)", "x86-64|x86_64"),
    ("ios-arm64", "libwinn_clientbinding-ios-arm64.a", r"current ar archive", "arm64"),
    ("datapath-windows-amd64", "winn-datapath-windows-amd64.exe", r"PE32\+? executable", "x86-64|x86_64"),
    ("datapath-windows-arm64", "winn-datapath-windows-arm64.exe", r"PE32\+? executable", "aarch64|arm64|ARM64|Aarch64"),
    ("datapath-darwin-amd64", "winn-datapath-darwin-amd64", r"Mach-O 64-bit executable", "x86_64"),
    ("datapath-darwin-arm64", "winn-datapath-darwin-arm64", r"Mach-O 64-bit executable", "arm64"),
    ("datapath-linux-amd64", "winn-datapath-linux-amd64", r"ELF 64-bit LSB (?:executable|pie executable)", "x86-64|x86_64"),
    ("datapath-linux-arm64", "winn-datapath-linux-arm64", r"ELF 64-bit LSB (?:executable|pie executable)", "ARM aarch64|aarch64"),
    ("datapath-android-arm64", "winn-datapath-android-arm64", r"ELF 64-bit LSB (?:pie executable|executable)", "ARM aarch64|aarch64"),
    ("datapath-android-arm", "winn-datapath-android-arm", r"ELF 32-bit LSB (?:pie executable|executable|shared object)", "ARM"),
    ("datapath-android-amd64", "winn-datapath-android-amd64", r"ELF 64-bit LSB (?:pie executable|executable)", "x86-64|x86_64"),
    ("datapath-ios-arm64", "libwinn-datapath-ios-arm64.a", r"current ar archive", "arm64"),
    ("datapath-iossimulator-arm64", "libwinn-datapath-iossimulator-arm64.a", r"current ar archive", "arm64"),
    ("datapath-iossimulator-amd64", "libwinn-datapath-iossimulator-amd64.a", r"current ar archive", "x86_64"),
    ("datapath-archive-darwin-arm64", "libwinn-datapath-darwin-arm64.a", r"current ar archive", "arm64"),
    ("datapath-archive-darwin-amd64", "libwinn-datapath-darwin-amd64.a", r"current ar archive", "x86_64"),
    ("server-linux-amd64", "winn-server-linux-amd64", r"ELF 64-bit LSB (?:executable|pie executable)", "x86-64|x86_64"),
    ("server-linux-arm64", "winn-server-linux-arm64", r"ELF 64-bit LSB (?:executable|pie executable)", "ARM aarch64|aarch64"),
    ("carrier-linux-amd64", "winn-carrier-server-linux-amd64", r"ELF 64-bit LSB (?:executable|pie executable)", "x86-64|x86_64"),
    ("carrier-linux-arm64", "winn-carrier-server-linux-arm64", r"ELF 64-bit LSB (?:executable|pie executable)", "ARM aarch64|aarch64"),
    ("winn3-gateway-linux-amd64", "winn3-gateway-linux-amd64", r"ELF 64-bit LSB (?:executable|pie executable)", "x86-64|x86_64"),
    ("winn3-gateway-linux-arm64", "winn3-gateway-linux-arm64", r"ELF 64-bit LSB (?:executable|pie executable)", "ARM aarch64|aarch64"),
    ("winn3-relay-windows-amd64", "winsvpn_winn3_engine-windows-amd64.exe", r"PE32\+? executable", "x86-64|x86_64"),
    ("winn3-relay-windows-arm64", "winsvpn_winn3_engine-windows-arm64.exe", r"PE32\+? executable", "aarch64|arm64|ARM64|Aarch64"),
]

IOS_TARGET = "ios-arm64"
NATIVE_TARGET = "darwin-arm64"  # the only target this Mac can actually execute
BUILD_RECEIPT_PREFIX = "WINN_BUILD_RECEIPT "
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TOOLCHAIN_PINS = ROOT / "tools" / "toolchain-pins.json"
# Files whose digests the release driver records under manifest "producer",
# keyed by file name.
RELEASE_PRODUCER_FILES = (
    BUILD_SCRIPT, RELEASE_DRIVER, TOOLCHAIN_PINS, RELEASE_GO_CUSTODY, RELEASE_AUTHORITY,
)
def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@dataclass
class _BoundParent:
    path: Path
    fd: int
    identity: tuple[int, ...]
    child_name: str
    child_identity: tuple[int, ...]


class BoundArtifact:
    """Retain every ancestor plus the leaf descriptor for one decision."""

    def __init__(self, path: Path):
        absolute = Path(os.path.abspath(os.path.normpath(path)))
        if path != absolute or not absolute.is_absolute():
            raise OSError(f"artifact path is not exact canonical absolute text: {path}")
        if any(part in {"", ".", ".."} for part in absolute.parts[1:]):
            raise OSError(f"artifact path has an unsafe component: {path}")
        self.path = absolute
        self.parents: list[_BoundParent] = []
        self.fd = -1
        current = Path("/")
        current_fd = os.open(
            current,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            for index, component in enumerate(absolute.parts[1:]):
                parent_info = os.fstat(current_fd)
                current_info = os.lstat(current)
                if _identity(parent_info) != _identity(current_info):
                    raise OSError(f"ancestor pathname changed while bound: {current}")
                child = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISLNK(child.st_mode):
                    raise OSError(f"symbolic component rejected: {current / component}")
                self.parents.append(
                    _BoundParent(
                        current,
                        current_fd,
                        _identity(parent_info),
                        component,
                        _identity(child),
                    )
                )
                current_fd = -1
                current /= component
                if index == len(absolute.parts[1:]) - 1:
                    if not stat.S_ISREG(child.st_mode) or child.st_nlink != 1:
                        raise OSError(f"artifact is not one regular non-hardlinked file: {absolute}")
                    parent = self.parents[-1]
                    self.fd = os.open(
                        component,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent.fd,
                    )
                    if _identity(os.fstat(self.fd)) != parent.child_identity:
                        raise OSError("artifact changed before its descriptor was retained")
                    break
                if not stat.S_ISDIR(child.st_mode):
                    raise OSError(f"artifact ancestor is not a directory: {current}")
                parent = self.parents[-1]
                current_fd = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent.fd,
                )
        except BaseException:
            if current_fd >= 0:
                os.close(current_fd)
            self.close()
            raise

    @property
    def descriptor_identity(self) -> str:
        return ":".join(str(value) for value in _identity(os.fstat(self.fd)))

    @property
    def ancestor_custody_sha256(self) -> str:
        lines = [
            f"{parent.path}\t{':'.join(str(value) for value in parent.identity[:4])}\n"
            for parent in self.parents
        ]
        return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()

    def verify(self) -> None:
        if self.fd < 0 or not self.parents:
            raise OSError("artifact custody is closed")
        for parent in self.parents:
            if _identity(os.fstat(parent.fd)) != parent.identity:
                raise OSError(f"retained ancestor identity changed: {parent.path}")
            child = os.stat(parent.child_name, dir_fd=parent.fd, follow_symlinks=False)
            if _identity(child) != parent.child_identity:
                raise OSError(f"artifact pathname restoration/substitution rejected: {parent.path / parent.child_name}")
        if _identity(os.fstat(self.fd)) != self.parents[-1].child_identity:
            raise OSError("artifact descriptor changed during the decision")

    def read(self, limit: int) -> bytes:
        self.verify()
        info = os.fstat(self.fd)
        if info.st_size <= 0 or info.st_size > limit:
            raise OSError(f"artifact size is outside 1..{limit} bytes")
        os.lseek(self.fd, 0, os.SEEK_SET)
        payload = bytearray()
        while len(payload) <= limit:
            block = os.read(self.fd, min(1024 * 1024, limit + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        self.verify()
        if len(payload) != info.st_size:
            raise OSError("artifact descriptor ended before its retained size")
        return bytes(payload)

    def read_prefix(self, limit: int) -> bytes:
        self.verify()
        if limit <= 0:
            raise ValueError("descriptor prefix limit must be positive")
        os.lseek(self.fd, 0, os.SEEK_SET)
        payload = os.read(self.fd, min(limit, os.fstat(self.fd).st_size))
        self.verify()
        return payload

    def sha256(self) -> str:
        self.verify()
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = os.fstat(self.fd).st_size
        while remaining:
            block = os.read(self.fd, min(1024 * 1024, remaining))
            if not block:
                raise OSError("artifact descriptor ended before its retained size")
            digest.update(block)
            remaining -= len(block)
        self.verify()
        return digest.hexdigest()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        for parent in self.parents:
            if parent.fd >= 0:
                os.close(parent.fd)
                parent.fd = -1

    def __enter__(self) -> "BoundArtifact":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _sha256_regular_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"not a regular file: {path}")
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_ctime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns
        ):
            raise OSError(f"file changed while hashed: {path}")
    finally:
        os.close(fd)
    return digest.hexdigest()


def _external_platform_tree_sha256(root: Path) -> str:
    root_text = str(root)
    if root != Path(os.path.abspath(os.path.normpath(root))) or root.is_symlink():
        raise OSError("platform toolchain root is not canonical or is symlinked")
    root_real = os.path.realpath(root_text)
    owner_ids = {0, os.getuid()}
    members: list[str] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root_text, followlinks=False):
        info = os.lstat(dirpath)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise OSError("platform custody contains a non-directory")
        if info.st_uid not in owner_ids or info.st_mode & 0o022:
            raise OSError("platform custody contains a writable or foreign directory")
        relative_dir = os.path.relpath(dirpath, root_text).replace(os.sep, "/")
        members.append(f"dir {info.st_mode} {info.st_uid} {relative_dir}\n")
        dirnames.sort()
        filenames.sort()
        for name in list(dirnames):
            path = os.path.join(dirpath, name)
            before = os.lstat(path)
            if stat.S_ISLNK(before.st_mode):
                resolved = os.path.realpath(path)
                if os.path.commonpath((root_real, resolved)) != root_real:
                    raise OSError("platform custody directory link escapes its root")
                relative = os.path.relpath(path, root_text).replace(os.sep, "/")
                members.append(f"symlink {os.readlink(path)} {relative}\n")
                dirnames.remove(name)
            elif not stat.S_ISDIR(before.st_mode):
                raise OSError("platform custody contains an unsafe directory member")
        for name in filenames:
            path = os.path.join(dirpath, name)
            before = os.lstat(path)
            if stat.S_ISLNK(before.st_mode):
                resolved = os.path.realpath(path)
                if os.path.commonpath((root_real, resolved)) != root_real:
                    raise OSError("platform custody file link escapes its root")
                relative = os.path.relpath(path, root_text).replace(os.sep, "/")
                members.append(f"symlink {os.readlink(path)} {relative}\n")
                continue
            if not stat.S_ISREG(before.st_mode):
                raise OSError("platform custody contains an unsafe file")
            if before.st_uid not in owner_ids or before.st_mode & 0o022:
                raise OSError("platform custody contains a writable or foreign file")
            total += before.st_size
            if len(members) > 1_000_000 or total > 32 * 1024 * 1024 * 1024:
                raise OSError("platform custody exceeds the structural bound")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            try:
                opened = os.fstat(fd)
                digest = hashlib.sha256()
                remaining = opened.st_size
                while remaining:
                    block = os.read(fd, min(1024 * 1024, remaining))
                    if not block:
                        raise OSError("platform member ended before its retained size")
                    digest.update(block)
                    remaining -= len(block)
                after = os.fstat(fd)
                latest = os.lstat(path)
                identity = lambda value: (
                    value.st_dev, value.st_ino, value.st_size, value.st_mode,
                    value.st_uid, value.st_nlink, value.st_ctime_ns,
                )
                if identity(opened) != identity(after) or identity(after) != identity(latest):
                    raise OSError("platform member changed while hashed")
            finally:
                os.close(fd)
            relative = os.path.relpath(path, root_text).replace(os.sep, "/")
            members.append(f"file {opened.st_size} {digest.hexdigest()} {relative}\n")
    members.sort()
    return hashlib.sha256("".join(members).encode("utf-8")).hexdigest()


def _read_regular_file_bounded(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise OSError(f"not one regular non-hardlinked file: {path}")
        if opened.st_size <= 0 or opened.st_size > limit:
            raise OSError(f"file size is outside 1..{limit} bytes: {path}")
        payload = bytearray()
        while len(payload) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(fd)
        if len(payload) != opened.st_size or (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_ctime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns
        ):
            raise OSError(f"file changed while read: {path}")
        return bytes(payload)
    finally:
        os.close(fd)


def _reviewed_go_identity_from_bytes(raw: bytes) -> dict[str, str]:
    document = parse_structural_json(raw.decode("utf-8", errors="strict"))
    if type(document) is not dict:
        raise ValueError("toolchain pin manifest root is not an object")
    tools = document.get("tools")
    if type(tools) is not dict:
        raise ValueError("toolchain pin manifest tools entry is not an object")
    go = tools.get("go")
    if type(go) is not dict:
        raise ValueError("toolchain pin manifest Go entry is not an object")
    version = go.get("version")
    if type(version) is not str or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError("toolchain pin manifest has no exact Go version")
    host_os = {"darwin": "darwin", "linux": "linux", "win32": "windows"}.get(sys.platform)
    machine = os.uname().machine.lower() if hasattr(os, "uname") else ""
    host_arch = {
        "arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"
    }.get(machine)
    if host_os is None or host_arch is None:
        raise ValueError(f"unsupported conformance host identity: {sys.platform}/{machine}")
    host_key = f"{host_os}_{host_arch}"
    result = {
        "version": version,
        "executable_sha256": go.get("executable_sha256"),
        "archive_sha256": (go.get("archive_sha256") or {}).get(host_key),
        "install_tree_sha256": (go.get("install_tree_sha256") or {}).get(host_key),
    }
    if any(type(value) is not str or HEX64_RE.fullmatch(value) is None for value in result.values() if value != version):
        raise ValueError(f"toolchain pin manifest is incomplete for {host_key}")
    return result


def _reviewed_go_identity() -> dict[str, str]:
    return _reviewed_go_identity_from_bytes(
        _read_regular_file_bounded(TOOLCHAIN_PINS, 1024 * 1024)
    )


def expected_build_identity(target: str) -> Optional[dict[str, object]]:
    simple = re.fullmatch(r"(windows|darwin|linux|android)-(amd64|arm64|arm)", target)
    if simple:
        goos, goarch = simple.groups()
        if goarch == "arm" and goos != "android":
            return None
        return {
            "goos": goos,
            "goarch": goarch,
            "cgo_enabled": goos == "android",
            "archive_mode": False,
            "package": "./cmd/winn-clientinfo",
            "role": "clientinfo",
            "platform": "android-api-24" if goos == "android" else goos,
        }
    if target == "ios-arm64":
        return {
            "goos": "ios", "goarch": "arm64", "cgo_enabled": True,
            "archive_mode": True, "package": "./cshared", "role": "clientinfo",
            "platform": "ios-device",
        }
    datapath = re.fullmatch(
        r"datapath-(windows|darwin|linux|android)-(amd64|arm64|arm)", target
    )
    if datapath:
        goos, goarch = datapath.groups()
        if goarch == "arm" and goos != "android":
            return None
        return {
            "goos": goos,
            "goarch": goarch,
            "cgo_enabled": goos == "android",
            "archive_mode": False,
            "package": "./cmd/winn-datapath",
            "role": "datapath",
            "platform": "android-api-24" if goos == "android" else goos,
        }
    apple_datapath = re.fullmatch(
        r"datapath-(ios|iossimulator|archive-darwin)-(amd64|arm64)", target
    )
    if apple_datapath:
        platform_name, goarch = apple_datapath.groups()
        if platform_name == "ios" and goarch != "arm64":
            return None
        return {
            "goos": "darwin" if platform_name == "archive-darwin" else "ios",
            "goarch": goarch,
            "cgo_enabled": True,
            "archive_mode": True,
            "package": "./cdatapath",
            "role": "datapath",
            "platform": {
                "ios": "ios-device",
                "iossimulator": "ios-simulator",
                "archive-darwin": "macos",
            }[platform_name],
        }
    server = re.fullmatch(
        r"(server|carrier|winn3-gateway)-linux-(amd64|arm64)", target
    )
    if server:
        target_role, goarch = server.groups()
        role_map = {
            "server": ("./cmd/winn-server", "control-plane-server"),
            "carrier": ("./cmd/winn-carrier-server", "v1-carrier-server"),
            "winn3-gateway": ("./cmd/winn3-gateway", "winn3-gateway"),
        }
        package, role = role_map[target_role]
        return {
            "goos": "linux", "goarch": goarch, "cgo_enabled": False,
            "archive_mode": False, "package": package, "role": role,
            "platform": "linux",
        }
    relay = re.fullmatch(r"winn3-relay-windows-(amd64|arm64)", target)
    if relay:
        # windows/winn3_engine is its own module; its main package path is the
        # module path, not a package under winsvpn.local/winnprotocol.
        return {
            "goos": "windows", "goarch": relay.group(1), "cgo_enabled": False,
            "archive_mode": False, "package": ".", "role": "winn3-relay",
            "platform": "windows", "main_path": "winsvpn.local/winsvpnwinn3engine",
        }
    return None


MAX_STRUCTURED_ARTIFACT_BYTES = 512 * 1024 * 1024
GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def _bounded_slice(payload: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(payload) or size > len(payload) - offset:
        raise ValueError(f"{label} is out of file bounds")
    return payload[offset:offset + size]


def _decode_uvarint(payload: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(payload):
            raise ValueError("Go build-info string length is truncated")
        byte = payload[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
    raise ValueError("Go build-info string length overflows uint64")


def _go_build_identity(
    payload: bytes,
    ranges: list[tuple[int, int]],
    expected: Mapping[str, object],
) -> tuple[str, str]:
    expected_package = str(expected.get("main_path") or f"winsvpn.local/winnprotocol/{str(expected['package'])[2:]}")
    reviewed_version = f"go{_reviewed_go_identity()['version']}"
    matches: list[tuple[str, str]] = []
    for start, end in ranges:
        region = _bounded_slice(payload, start, end - start, "loadable Go identity range")
        search = 0
        while True:
            relative = region.find(GO_BUILDINFO_MAGIC, search)
            if relative < 0:
                break
            absolute = start + relative
            search = relative + 1
            if absolute % 16 != 0:
                continue
            header = _bounded_slice(payload, absolute, 32, "Go build-info header")
            if header[14] not in {4, 8} or header[15] & 0x2 != 0x2:
                continue
            version_size, cursor = _decode_uvarint(payload, absolute + 32)
            if version_size <= 2 or version_size > 128:
                continue
            version = _bounded_slice(payload, cursor, version_size, "Go version").decode("ascii", errors="strict")
            cursor += version_size
            module_size, cursor = _decode_uvarint(payload, cursor)
            if module_size <= 0 or module_size > 16 * 1024 * 1024:
                continue
            module_bytes = _bounded_slice(payload, cursor, module_size, "Go module identity")
            # The linker wraps modinfo in two 16-byte sentinels (see
            # debug/buildinfo); strip them exactly as the Go reader does.
            if len(module_bytes) >= 33 and module_bytes[-17] == 0x0A:
                module_bytes = module_bytes[16:-16]
            try:
                module = module_bytes.decode("utf-8", errors="strict")
            except UnicodeError:
                continue
            if version != reviewed_version:
                continue
            module_lines = module.splitlines()
            path_lines = [line for line in module_lines if line.startswith("path\t")]
            if path_lines != [f"path\t{expected_package}"]:
                continue
            build_settings: dict[str, str] = {}
            malformed_settings = False
            for line in module_lines:
                if not line.startswith("build\t"):
                    continue
                setting = line[len("build\t"):]
                if "=" not in setting:
                    malformed_settings = True
                    break
                key, value = setting.split("=", 1)
                if not key or key in build_settings:
                    malformed_settings = True
                    break
                build_settings[key] = value
            feature = {
                "amd64": ("GOAMD64", "v1"),
                "arm64": ("GOARM64", "v8.0"),
                "arm": ("GOARM", "7"),
            }[str(expected["goarch"])]
            required_settings = {
                "-trimpath": "true",
                "CGO_ENABLED": "1" if expected["cgo_enabled"] else "0",
                "GOARCH": str(expected["goarch"]),
                "GOOS": str(expected["goos"]),
                feature[0]: feature[1],
            }
            if malformed_settings or any(
                build_settings.get(key) != value
                for key, value in required_settings.items()
            ):
                continue
            matches.append((version, expected_package))
    if len(matches) != 1:
        raise ValueError(f"expected one loadable Go build identity for {expected_package}, found {len(matches)}")
    return matches[0]


def _validate_generated_header(
    binding: BoundArtifact, expected: Mapping[str, object]
) -> None:
    payload = binding.read(1024 * 1024)
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise ValueError("generated Go header is not canonical ASCII") from exc
    if "\x00" in text or "#ifndef" not in text or "#define" not in text:
        raise ValueError("generated Go header guard is absent or malformed")
    role = expected.get("role")
    signatures = {
        "clientinfo": {
            "WinnFacadeVersion": r"char\s*\*\s*WinnFacadeVersion\s*\(\s*void\s*\)",
            "WinnProtocolVersion": r"char\s*\*\s*WinnProtocolVersion\s*\(\s*void\s*\)",
            "WinnTunnelBackendJSON": r"char\s*\*\s*WinnTunnelBackendJSON\s*\(\s*void\s*\)",
            "WinnFreeString": r"void\s+WinnFreeString\s*\(\s*char\s*\*\s*[A-Za-z_]\w*\s*\)",
        },
        "datapath": {
            "WinnTunnelCreate": (
                r"long\s+long(?:\s+int)?\s+WinnTunnelCreate\s*\(\s*"
                r"char\s*\*\s*[A-Za-z_]\w*\s*,\s*int\s+[A-Za-z_]\w*\s*,\s*"
                r"char\s*\*\s*\*\s*[A-Za-z_]\w*\s*\)"
            ),
            "WinnTunnelWriteInbound": (
                r"int\s+WinnTunnelWriteInbound\s*\(\s*long\s+long(?:\s+int)?\s+"
                r"[A-Za-z_]\w*\s*,\s*char\s*\*\s*[A-Za-z_]\w*\s*,\s*"
                r"int\s+[A-Za-z_]\w*\s*\)"
            ),
            "WinnTunnelStatusJSON": (
                r"char\s*\*\s*WinnTunnelStatusJSON\s*\(\s*long\s+long(?:\s+int)?\s+"
                r"[A-Za-z_]\w*\s*\)"
            ),
        },
    }.get(role)
    if signatures is None:
        raise ValueError(f"generated header role has no reviewed C ABI: {role!r}")
    for symbol, signature in signatures.items():
        declarations = re.findall(rf"(?m)^extern\s+{signature}\s*;\s*$", text)
        if len(declarations) != 1:
            raise ValueError(
                f"generated Go header does not declare the exact C calling convention and types for {symbol}"
            )
    binding.verify()


def _string_table_name(table: bytes, offset: int, label: str) -> str:
    if offset <= 0 or offset >= len(table):
        raise ValueError(f"{label} string-table offset is invalid")
    end = table.find(b"\x00", offset)
    if end < 0:
        raise ValueError(f"{label} string is unterminated")
    try:
        return table[offset:end].decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise ValueError(f"{label} symbol is not canonical ASCII") from exc


def _archive_object_identity(
    body: bytes, expected: Optional[Mapping[str, object]]
) -> tuple[str, set[str], bool]:
    """Validate a relocatable member and extract authenticated symbol identity."""
    symbols: set[str] = set()
    identity_ranges: list[tuple[int, int]] = []
    if body.startswith(b"\x7fELF"):
        if len(body) < 52 or body[4] not in {1, 2} or body[5] not in {1, 2}:
            raise ValueError("ar ELF object header is truncated")
        elf_class = body[4]
        endian = "<" if body[5] == 1 else ">"
        file_type, machine = struct.unpack_from(endian + "HH", body, 16)
        architecture = {62: "amd64", 183: "arm64", 40: "arm"}.get(machine)
        if file_type != 1 or architecture is None:
            raise ValueError("ar ELF member is not a supported relocatable object")
        if elf_class == 2:
            shoff = struct.unpack_from(endian + "Q", body, 40)[0]
            shentsize, shnum = struct.unpack_from(endian + "HH", body, 58)
            required = 64
        else:
            shoff = struct.unpack_from(endian + "I", body, 32)[0]
            shentsize, shnum = struct.unpack_from(endian + "HH", body, 46)
            required = 40
        if shnum == 0 or shnum > 65535 or shentsize < required:
            raise ValueError("ar ELF object section table is absent or invalid")
        _bounded_slice(body, shoff, shentsize * shnum, "ar ELF object section table")
        executable = 0
        sections: list[tuple[int, int, int, int, int]] = []
        for index in range(shnum):
            offset = shoff + index * shentsize
            if elf_class == 2:
                section_type, flags, section_offset, section_size, link, entry_size = (
                    struct.unpack_from(endian + "I", body, offset + 4)[0],
                    struct.unpack_from(endian + "Q", body, offset + 8)[0],
                    struct.unpack_from(endian + "QQ", body, offset + 24)[0],
                    struct.unpack_from(endian + "Q", body, offset + 32)[0],
                    struct.unpack_from(endian + "I", body, offset + 40)[0],
                    struct.unpack_from(endian + "Q", body, offset + 56)[0],
                )
            else:
                section_type, flags, section_offset, section_size, link, entry_size = (
                    struct.unpack_from(endian + "I", body, offset + 4)[0],
                    struct.unpack_from(endian + "I", body, offset + 8)[0],
                    struct.unpack_from(endian + "II", body, offset + 16)[0],
                    struct.unpack_from(endian + "I", body, offset + 20)[0],
                    struct.unpack_from(endian + "I", body, offset + 24)[0],
                    struct.unpack_from(endian + "I", body, offset + 36)[0],
                )
            if section_size and section_type != 8:  # SHT_NOBITS occupies no file bytes
                _bounded_slice(body, section_offset, section_size, "ar ELF object section")
                if flags & 0x2:
                    identity_ranges.append((section_offset, section_offset + section_size))
            if section_size and flags & 0x4:
                executable += 1
            sections.append((section_type, section_offset, section_size, link, entry_size))
        if executable == 0:
            raise ValueError("ar ELF object has no non-empty executable section")
        symbol_tables = 0
        for section_type, section_offset, section_size, link, entry_size in sections:
            if section_type != 2:
                continue
            symbol_tables += 1
            expected_entry_size = 24 if elf_class == 2 else 16
            if (
                entry_size != expected_entry_size
                or section_size == 0
                or section_size % entry_size
                or link >= len(sections)
            ):
                raise ValueError("ar ELF symbol table is malformed")
            string_type, string_offset, string_size, _, _ = sections[link]
            if string_type != 3 or string_size == 0:
                raise ValueError("ar ELF symbol table has no linked string table")
            string_table = _bounded_slice(
                body, string_offset, string_size, "ar ELF symbol string table"
            )
            for cursor in range(section_offset, section_offset + section_size, entry_size):
                if elf_class == 2:
                    name_offset = struct.unpack_from(endian + "I", body, cursor)[0]
                    info = body[cursor + 4]
                    section_index = struct.unpack_from(endian + "H", body, cursor + 6)[0]
                else:
                    name_offset = struct.unpack_from(endian + "I", body, cursor)[0]
                    info = body[cursor + 12]
                    section_index = struct.unpack_from(endian + "H", body, cursor + 14)[0]
                if name_offset and section_index not in {0, 0xFFF1} and info >> 4 in {1, 2}:
                    symbols.add(_string_table_name(string_table, name_offset, "ELF"))
        if symbol_tables != 1 or not symbols:
            raise ValueError("ar ELF object requires one non-empty static symbol table")
        has_go_identity = False
        if expected is not None:
            try:
                _go_build_identity(body, identity_ranges, expected)
                has_go_identity = True
            except ValueError:
                pass
        return architecture, symbols, has_go_identity
    macho = {
        b"\xcf\xfa\xed\xfe": ("<", 0x01000000),
        b"\xfe\xed\xfa\xcf": (">", 0x01000000),
    }.get(body[:4])
    if macho is not None:
        endian, abi64 = macho
        if len(body) < 32:
            raise ValueError("ar Mach-O object header is truncated")
        cpu_type, _, file_type, command_count, command_bytes = struct.unpack_from(
            endian + "IIIII", body, 4
        )
        architecture = {abi64 | 7: "amd64", abi64 | 12: "arm64"}.get(cpu_type)
        if file_type != 1 or architecture is None:
            raise ValueError("ar Mach-O member is not a supported object")
        if command_count == 0 or command_count > 4096 or command_bytes > len(body) - 32:
            raise ValueError("ar Mach-O object load commands are invalid")
        cursor = 32
        executable = 0
        symbol_command: Optional[tuple[int, int, int, int]] = None
        build_platforms: list[int] = []
        for _ in range(command_count):
            command, size = struct.unpack_from(
                endian + "II", _bounded_slice(body, cursor, 8, "ar Mach-O load command")
            )
            if size < 8 or cursor + size > 32 + command_bytes:
                raise ValueError("ar Mach-O load command size is invalid")
            if command == 0x19:
                if size < 72:
                    raise ValueError("ar Mach-O segment is truncated")
                _, initial_protection, section_count = struct.unpack_from(
                    endian + "iiI", body, cursor + 56
                )
                if section_count > 4096 or 72 + section_count * 80 > size:
                    raise ValueError("ar Mach-O object sections are invalid")
                for section_index in range(section_count):
                    section = cursor + 72 + section_index * 80
                    section_size = struct.unpack_from(endian + "Q", body, section + 40)[0]
                    section_offset = struct.unpack_from(endian + "I", body, section + 48)[0]
                    section_flags = struct.unpack_from(endian + "I", body, section + 64)[0]
                    zerofill = section_flags & 0xFF in {0x01, 0x0C, 0x12}
                    if section_size and not zerofill:
                        _bounded_slice(body, section_offset, section_size, "ar Mach-O object section")
                        identity_ranges.append((section_offset, section_offset + section_size))
                    # Segment protections are not meaningful in MH_OBJECT
                    # files (the Go linker writes 0); instruction attributes are.
                    if section_size and section_flags & 0x80000400:
                        executable += 1
            elif command == 0x2:
                if size != 24 or symbol_command is not None:
                    raise ValueError("ar Mach-O symbol-table command is malformed")
                symbol_command = struct.unpack_from(endian + "IIII", body, cursor + 8)
            elif command == 0x32:
                if size < 24:
                    raise ValueError("ar Mach-O LC_BUILD_VERSION is truncated")
                platform, _, _, tool_count = struct.unpack_from(
                    endian + "IIII", body, cursor + 8
                )
                if size != 24 + tool_count * 8:
                    raise ValueError("ar Mach-O LC_BUILD_VERSION tools are malformed")
                build_platforms.append(platform)
            cursor += size
        if cursor != 32 + command_bytes or symbol_command is None:
            raise ValueError("ar Mach-O object has no exact section and symbol-table topology")
        symbol_offset, symbol_count, string_offset, string_size = symbol_command
        if symbol_count > 1_000_000 or (symbol_count and string_size == 0):
            raise ValueError("ar Mach-O symbol table is unbounded or has no strings")
        symbol_bytes = _bounded_slice(
            body, symbol_offset, symbol_count * 16, "ar Mach-O symbol table"
        )
        string_table = _bounded_slice(
            body, string_offset, string_size, "ar Mach-O symbol string table"
        ) if symbol_count else b""
        for index in range(symbol_count):
            cursor = index * 16
            name_offset = struct.unpack_from(endian + "I", symbol_bytes, cursor)[0]
            symbol_type = symbol_bytes[cursor + 4]
            section_index = symbol_bytes[cursor + 5]
            if (
                name_offset
                and not symbol_type & 0xE0
                and symbol_type & 0x01
                and symbol_type & 0x0E
                and section_index != 0
            ):
                name = _string_table_name(string_table, name_offset, "Mach-O")
                symbols.add(name[1:] if name.startswith("_") else name)
        # cgo emits empty stub objects (zero-length __text, no exports);
        # an object with code must still export something.
        if executable and not symbols:
            raise ValueError("ar Mach-O object has code but no defined external symbols")
        has_go_identity = False
        if expected is not None:
            expected_platform = {
                "macos": 1,
                "ios-device": 2,
                "ios-simulator": 7,
            }.get(str(expected.get("platform")))
            if expected_platform is None or build_platforms != [expected_platform]:
                raise ValueError(
                    "ar Mach-O object platform does not match the exact Apple target"
                )
            try:
                _go_build_identity(body, identity_ranges, expected)
                has_go_identity = True
            except ValueError:
                pass
        return architecture, symbols, has_go_identity
    raise ValueError("ar member is not an ELF or Mach-O relocatable object")


def _structured_artifact_identity(
    binding: BoundArtifact,
    expected: Optional[Mapping[str, object]] = None,
) -> tuple[str, str]:
    """Return exact format/architecture after loader and Go-role validation."""
    payload = binding.read(MAX_STRUCTURED_ARTIFACT_BYTES)
    loadable_ranges: list[tuple[int, int]] = []
    if payload.startswith(b"\x7fELF"):
        if len(payload) < 64 or payload[5] not in {1, 2}:
            raise ValueError("ELF header is truncated or has unknown byte order")
        endian = "<" if payload[5] == 1 else ">"
        elf_class = payload[4]
        if elf_class not in {1, 2}:
            raise ValueError("ELF class is not 32-bit or 64-bit")
        file_type, machine = struct.unpack_from(endian + "HH", payload, 16)
        if file_type not in {2, 3}:
            raise ValueError("ELF artifact is not an executable or PIE")
        architecture = {62: "amd64", 183: "arm64", 40: "arm"}.get(machine)
        if architecture is None:
            raise ValueError(f"ELF machine is unsupported: {machine}")
        if architecture == "arm" and elf_class != 1:
            raise ValueError("ELF ARM artifact is not 32-bit")
        if architecture != "arm" and elf_class != 2:
            raise ValueError("ELF amd64/arm64 artifact is not 64-bit")
        if elf_class == 2:
            entry, phoff, shoff = struct.unpack_from(endian + "QQQ", payload, 24)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHHH", payload, 52)
            required_phentsize, required_shentsize = 56, 64
        else:
            entry, phoff, shoff = struct.unpack_from(endian + "III", payload, 24)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHHH", payload, 40)
            required_phentsize, required_shentsize = 32, 40
        if ehsize not in {52, 64} or phnum == 0 or phnum > 4096 or phentsize < required_phentsize:
            raise ValueError("ELF program-header table is structurally invalid")
        _bounded_slice(payload, phoff, phentsize * phnum, "ELF program-header table")
        executable_loads: list[tuple[int, int, int, int]] = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            if elf_class == 2:
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
                    endian + "IIQQQQQQ", payload, offset
                )
            else:
                p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(
                    endian + "IIIIIIII", payload, offset
                )
            if p_type != 1:
                continue
            if p_filesz > p_memsz:
                raise ValueError("ELF PT_LOAD file size exceeds memory size")
            _bounded_slice(payload, p_offset, p_filesz, "ELF PT_LOAD bytes")
            if p_filesz:
                loadable_ranges.append((p_offset, p_offset + p_filesz))
            if p_flags & 1 and p_filesz:
                executable_loads.append((p_offset, p_offset + p_filesz, p_vaddr, p_vaddr + p_memsz))
        if not executable_loads:
            raise ValueError("ELF has no non-empty executable PT_LOAD segment")
        if entry == 0 or not any(vstart <= entry < vend for _, _, vstart, vend in executable_loads):
            raise ValueError("ELF entry point is not inside an executable PT_LOAD segment")
        if architecture == "arm64" and entry % 4 != 0:
            raise ValueError("ELF arm64 entry point is not 4-byte aligned")
        if shnum == 0 or shnum > 65535 or shentsize < required_shentsize:
            raise ValueError("ELF section table is absent or invalid")
        _bounded_slice(payload, shoff, shentsize * shnum, "ELF section table")
        executable_sections = 0
        for index in range(shnum):
            offset = shoff + index * shentsize
            if elf_class == 2:
                _, section_type, flags, _, section_offset, section_size = struct.unpack_from(endian + "IIQQQQ", payload, offset)
            else:
                _, section_type, flags, _, section_offset, section_size = struct.unpack_from(endian + "IIIIII", payload, offset)
            if section_size and flags & 0x2 and section_type != 8:  # SHT_NOBITS has no file bytes
                _bounded_slice(payload, section_offset, section_size, "ELF allocated section")
            if section_size and flags & 0x4:
                executable_sections += 1
        if executable_sections == 0:
            raise ValueError("ELF has no non-empty executable section")
        if expected is not None:
            _go_build_identity(payload, loadable_ranges, expected)
        return "elf", architecture
    if payload[:2] == b"MZ":
        if len(payload) < 0x40:
            raise ValueError("PE DOS header is truncated")
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        if pe_offset < 0x40 or pe_offset + 24 > len(payload) or payload[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise ValueError("PE signature is missing or out of bounds")
        machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from(
            "<HHIIIHH", payload, pe_offset + 4
        )
        if sections == 0 or sections > 96 or not characteristics & 0x0002:
            raise ValueError("PE artifact is not marked executable")
        optional_offset = pe_offset + 24
        if optional_size < 2 or optional_offset + optional_size > len(payload):
            raise ValueError("PE optional header is truncated")
        optional_magic = struct.unpack_from("<H", payload, optional_offset)[0]
        architecture = {0x8664: "amd64", 0xAA64: "arm64"}.get(machine)
        if architecture is None or optional_magic != 0x20B or optional_size < 112:
            raise ValueError("PE artifact is not an amd64/arm64 PE32+ executable")
        entry_rva, size_of_code = struct.unpack_from("<II", payload, optional_offset + 16)[0], struct.unpack_from("<I", payload, optional_offset + 4)[0]
        if entry_rva == 0 or size_of_code == 0:
            raise ValueError("PE executable has no entry point or code")
        section_table = optional_offset + optional_size
        _bounded_slice(payload, section_table, sections * 40, "PE section table")
        executable_sections = 0
        entry_is_executable = False
        for index in range(sections):
            offset = section_table + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", payload, offset + 8)
            section_flags = struct.unpack_from("<I", payload, offset + 36)[0]
            if raw_size:
                _bounded_slice(payload, raw_offset, raw_size, "PE section bytes")
                loadable_ranges.append((raw_offset, raw_offset + raw_size))
            span = max(virtual_size, raw_size)
            if raw_size and section_flags & 0x20000000 and section_flags & 0x00000020:
                executable_sections += 1
                if virtual_address <= entry_rva < virtual_address + span:
                    entry_is_executable = True
        if executable_sections == 0 or not entry_is_executable:
            raise ValueError("PE entry point is not inside a non-empty executable code section")
        if architecture == "arm64" and entry_rva % 4 != 0:
            raise ValueError("PE arm64 entry point is not 4-byte aligned")
        if expected is not None:
            _go_build_identity(payload, loadable_ranges, expected)
        return "pe", architecture
    macho = {
        b"\xcf\xfa\xed\xfe": ("<", 0x01000000),
        b"\xfe\xed\xfa\xcf": (">", 0x01000000),
    }.get(payload[:4])
    if macho is not None:
        endian, abi64 = macho
        if len(payload) < 32:
            raise ValueError("Mach-O header is truncated")
        cpu_type, _, file_type, command_count, command_bytes = struct.unpack_from(endian + "IIIII", payload, 4)
        if file_type != 2:
            raise ValueError("Mach-O artifact is not an executable")
        architecture = {
            abi64 | 7: "amd64",
            abi64 | 12: "arm64",
        }.get(cpu_type)
        if architecture is None:
            raise ValueError(f"Mach-O CPU type is unsupported: {cpu_type}")
        if command_count == 0 or command_count > 4096 or command_bytes > len(payload) - 32:
            raise ValueError("Mach-O load-command table is absent or out of bounds")
        cursor = 32
        executable_segments: list[tuple[int, int]] = []
        entry_offset: Optional[int] = None
        for _ in range(command_count):
            command, size = struct.unpack_from(endian + "II", _bounded_slice(payload, cursor, 8, "Mach-O load command"))
            if size < 8 or size % 4 or cursor + size > 32 + command_bytes:
                raise ValueError("Mach-O load command size is invalid")
            if command == 0x19:
                if size < 72:
                    raise ValueError("Mach-O LC_SEGMENT_64 is truncated")
                file_offset, file_size = struct.unpack_from(endian + "QQ", payload, cursor + 40)
                _, initial_protection, section_count = struct.unpack_from(endian + "iiI", payload, cursor + 56)
                if section_count > 4096 or 72 + section_count * 80 > size:
                    raise ValueError("Mach-O section table is out of bounds")
                if file_size:
                    _bounded_slice(payload, file_offset, file_size, "Mach-O segment bytes")
                    loadable_ranges.append((file_offset, file_offset + file_size))
                for section_index in range(section_count):
                    section = cursor + 72 + section_index * 80
                    section_size = struct.unpack_from(endian + "Q", payload, section + 40)[0]
                    section_offset, section_flags = struct.unpack_from(endian + "II", payload, section + 48)[0], struct.unpack_from(endian + "I", payload, section + 64)[0]
                    if section_size and section_offset:
                        _bounded_slice(payload, section_offset, section_size, "Mach-O section bytes")
                    if section_size and initial_protection & 0x4 and section_flags & 0x80000400:
                        executable_segments.append((section_offset, section_offset + section_size))
            elif command == 0x80000028:
                if size < 24:
                    raise ValueError("Mach-O LC_MAIN is truncated")
                entry_offset = struct.unpack_from(endian + "Q", payload, cursor + 8)[0]
            cursor += size
        if cursor != 32 + command_bytes or not executable_segments:
            raise ValueError("Mach-O has no exact non-empty executable section topology")
        if entry_offset is None or not any(start <= entry_offset < end for start, end in executable_segments):
            raise ValueError("Mach-O LC_MAIN entry is not inside an executable section")
        if architecture == "arm64" and entry_offset % 4 != 0:
            raise ValueError("Mach-O arm64 entry point is not 4-byte aligned")
        if expected is not None:
            _go_build_identity(payload, loadable_ranges, expected)
        return "macho", architecture
    if payload.startswith(b"!<arch>\n"):
        cursor = 8
        members = 0
        object_architectures: set[str] = set()
        archive_symbols: set[str] = set()
        go_identity_members = 0
        while cursor < len(payload):
            header = _bounded_slice(payload, cursor, 60, "ar member header")
            if header[58:60] != b"`\n":
                raise ValueError("ar member trailer is invalid")
            try:
                size = int(header[48:58].decode("ascii").strip())
            except (UnicodeError, ValueError) as exc:
                raise ValueError("ar member size is not bounded decimal") from exc
            if size < 0 or size > MAX_STRUCTURED_ARTIFACT_BYTES:
                raise ValueError("ar member size exceeds structural bound")
            body_offset = cursor + 60
            body = _bounded_slice(payload, body_offset, size, "ar member bytes")
            members += 1
            if members > 100000:
                raise ValueError("ar member count exceeds structural bound")
            name = header[:16].decode("ascii", errors="strict").rstrip()
            if name.startswith("#1/"):
                # BSD ar stores a long member name at the start of the body.
                try:
                    name_size = int(name[3:])
                except ValueError as exc:
                    raise ValueError("ar BSD long-name length is not decimal") from exc
                if name_size <= 0 or name_size > min(4096, size):
                    raise ValueError("ar BSD long-name length is out of bounds")
                name = body[:name_size].rstrip(b"\0").decode("ascii", errors="strict")
                body = body[name_size:]
            if not name.startswith(("/", "__.SYMDEF")) and body.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\x7fELF")):
                architecture, member_symbols, has_go_identity = _archive_object_identity(
                    body, expected
                )
                object_architectures.add(architecture)
                archive_symbols.update(member_symbols)
                go_identity_members += int(has_go_identity)
            cursor = body_offset + size + (size & 1)
        if cursor != len(payload) or members == 0 or not object_architectures:
            raise ValueError("ar archive has no exact bounded object-member topology")
        if len(object_architectures) != 1:
            raise ValueError("ar archive object architecture is absent or mixed")
        if expected is not None:
            if go_identity_members != 1:
                raise ValueError("ar archive lacks independently extracted Go package role")
            required_symbols = (
                ("WinnFacadeVersion", "WinnProtocolVersion", "WinnTunnelBackendJSON")
                if expected.get("role") == "clientinfo"
                else ("WinnTunnelCreate", "WinnTunnelWriteInbound", "WinnTunnelStatusJSON")
            )
            if any(symbol not in archive_symbols for symbol in required_symbols):
                raise ValueError("ar archive lacks required role symbols in authenticated object members")
        return "archive", next(iter(object_architectures))
    raise ValueError("artifact is not ELF, PE32+, Mach-O executable, or ar archive")


def _expected_format(target: str, expected: Mapping[str, object]) -> str:
    if bool(expected["archive_mode"]):
        return "archive"
    return {"windows": "pe", "darwin": "macho", "linux": "elf", "android": "elf"}[str(expected["goos"])]


BUILD_RECEIPT_CONTRACT = "winsvpn-winn-core-build-v4"
BUILD_RECEIPT_ROOT_KEYS = frozenset({
    "archive_mode", "artifact", "contract", "go", "module_cache_tree_sha256",
    "package", "platform", "role", "source_tree_sha256", "target",
})
BUILD_RECEIPT_ARTIFACT_KEYS = frozenset({"header_sha256", "output_path", "sha256"})
BUILD_RECEIPT_GO_KEYS = frozenset({"executable_sha256", "version"})
BUILD_RECEIPT_TARGET_KEYS = frozenset({"cgo_enabled", "goarch", "goos", "id"})
BUILD_RECEIPT_PLATFORM_KEYS = frozenset({
    "compiler_path", "compiler_sha256", "id", "ndk_version", "sdk_version",
})
APPLE_SDK_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}\Z")
MAX_BUILD_RECEIPT_BYTES = 8192


def verify_build_receipt(
    report: Report,
    stdout: str,
    *,
    target: str,
    output: Path,
    binding: Optional[BoundArtifact] = None,
    expected_source_tree_sha256: Optional[str] = None,
    expected_module_cache_tree_sha256: Optional[str] = None,
) -> bool:
    """Structurally verify one builder receipt against the bytes it names.

    The receipt is self-reported by the builder, so it can only ever confirm
    what this process measures independently: the artifact digest, its exact
    executable or archive structure, the reviewed Go pin, and the retained
    `${OUTPUT}.receipt.json` copy. Source and module-cache identities are
    compared only against values the caller supplies, never the environment.
    """
    expected = expected_build_identity(target)
    if expected is None:
        report.add(FAIL, f"build[{target}]: structural receipt target is recognized")
        return False
    canonical_output = (
        binding.path
        if binding is not None
        else Path(os.path.realpath(Path(output).parent)) / Path(output).name
    )
    held: list[BoundArtifact] = []
    try:
        receipt_binding = BoundArtifact(Path(str(canonical_output) + ".receipt.json"))
        held.append(receipt_binding)
        header_binding = None
        if bool(expected["archive_mode"]):
            header_binding = BoundArtifact(canonical_output.with_suffix(".h"))
            held.append(header_binding)
        return _verify_build_receipt_bound(
            report,
            stdout,
            target=target,
            output=canonical_output,
            binding=binding,
            receipt_binding=receipt_binding,
            header_binding=header_binding,
            expected_source_tree_sha256=expected_source_tree_sha256,
            expected_module_cache_tree_sha256=expected_module_cache_tree_sha256,
        )
    except OSError as exc:
        report.add(
            FAIL,
            f"build[{target}]: structural receipt evidence files are retained",
            str(exc),
        )
        return False
    finally:
        for item in reversed(held):
            item.close()


def _verify_build_receipt_bound(
    report: Report,
    stdout: str,
    *,
    target: str,
    output: Path,
    binding: Optional[BoundArtifact],
    receipt_binding: BoundArtifact,
    header_binding: Optional[BoundArtifact],
    expected_source_tree_sha256: Optional[str] = None,
    expected_module_cache_tree_sha256: Optional[str] = None,
) -> bool:
    label = f"build[{target}]: structural receipt"
    payload = _receipt_payload(stdout)
    if payload is None:
        count = sum(1 for line in stdout.splitlines() if line.startswith(BUILD_RECEIPT_PREFIX))
        report.add(FAIL, f"{label} is unique", f"found {count} receipts")
        return False
    if not payload or len(payload.encode("utf-8")) > MAX_BUILD_RECEIPT_BYTES:
        report.add(FAIL, f"{label} is bounded", f"{len(payload.encode('utf-8'))} bytes")
        return False
    try:
        document = parse_structural_json(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        report.add(FAIL, f"{label} is strict JSON", str(exc))
        return False
    if type(document) is not dict or set(document) != BUILD_RECEIPT_ROOT_KEYS:
        report.add(FAIL, f"{label} root keys are exact")
        return False
    if document["contract"] != BUILD_RECEIPT_CONTRACT:
        report.add(FAIL, f"{label} contract identity", repr(document["contract"]))
        return False
    artifact = document["artifact"]
    go = document["go"]
    platform_identity = document["platform"]
    target_identity = document["target"]
    if (
        type(artifact) is not dict
        or set(artifact) != BUILD_RECEIPT_ARTIFACT_KEYS
        or type(go) is not dict
        or set(go) != BUILD_RECEIPT_GO_KEYS
        or type(target_identity) is not dict
        or set(target_identity) != BUILD_RECEIPT_TARGET_KEYS
        or type(platform_identity) is not dict
        or set(platform_identity) != BUILD_RECEIPT_PLATFORM_KEYS
    ):
        report.add(FAIL, f"{label} nested keys are exact")
        return False

    expected = expected_build_identity(target)
    if expected is None:
        report.add(FAIL, f"{label} target is recognized", repr(target))
        return False
    if (
        target_identity.get("id") != target
        or target_identity.get("goos") != expected["goos"]
        or target_identity.get("goarch") != expected["goarch"]
        or type(target_identity.get("cgo_enabled")) is not bool
        or target_identity.get("cgo_enabled") is not expected["cgo_enabled"]
        or document["role"] != expected["role"]
        or document["package"] != expected["package"]
        or type(document["archive_mode"]) is not bool
        or document["archive_mode"] is not expected["archive_mode"]
        or platform_identity.get("id") != expected["platform"]
    ):
        report.add(FAIL, f"{label} target, architecture, and role identity", repr(document))
        return False
    try:
        if type(artifact["output_path"]) is not str or not artifact["output_path"].startswith("/"):
            raise ValueError("receipt output path is not absolute")
        receipt_output = Path(artifact["output_path"])
        if receipt_output != Path(os.path.abspath(artifact["output_path"])):
            raise ValueError("receipt output path is not canonical absolute text")
    except (OSError, TypeError, ValueError) as exc:
        report.add(FAIL, f"{label} output path is valid", str(exc))
        return False
    expected_output = binding.path if binding is not None else output
    if receipt_output != expected_output:
        report.add(
            FAIL,
            f"{label} cannot relabel an artifact",
            f"receipt={receipt_output}, requested={expected_output}",
        )
        return False
    digest_fields = (
        artifact.get("sha256"), document["source_tree_sha256"],
        document["module_cache_tree_sha256"], go.get("executable_sha256"),
    )
    if any(type(value) is not str or HEX64_RE.fullmatch(value) is None for value in digest_fields):
        report.add(FAIL, f"{label} digests are exact SHA-256 values")
        return False
    try:
        receipt_bytes = receipt_binding.read(MAX_BUILD_RECEIPT_BYTES + 1)
    except OSError as exc:
        report.add(FAIL, f"{label} on-disk receipt is retained", str(exc))
        return False
    if receipt_bytes != (payload + "\n").encode("utf-8"):
        report.add(FAIL, f"{label} on-disk receipt matches terminal receipt")
        return False
    try:
        reviewed_go = _reviewed_go_identity()
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        report.add(UNVERIFIED, f"{label} reviewed Go pin is available", str(exc))
        return False
    for field_name in ("version", "executable_sha256"):
        if go.get(field_name) != reviewed_go[field_name]:
            report.add(
                FAIL,
                f"{label} Go {field_name} matches the reviewed pin",
                f"receipt={go.get(field_name)!r}, reviewed={reviewed_go[field_name]!r}",
            )
            return False
    for supplied, field_name in (
        (expected_source_tree_sha256, "source_tree_sha256"),
        (expected_module_cache_tree_sha256, "module_cache_tree_sha256"),
    ):
        if supplied is not None and document[field_name] != supplied:
            report.add(
                FAIL,
                f"{label} {field_name} matches the caller-sealed input",
                f"receipt={document[field_name]}, expected={supplied}",
            )
            return False
    owns_binding = binding is None
    retained: Optional[BoundArtifact] = None
    try:
        retained = binding or BoundArtifact(expected_output)
        retained.verify()
        measured = retained.sha256()
        if measured != artifact["sha256"]:
            report.add(FAIL, f"{label} artifact digest matches", f"receipt={artifact['sha256']}, measured={measured}")
            return False
        observed_format, observed_arch = _structured_artifact_identity(retained, expected)
        expected_format = _expected_format(target, expected)
        if observed_format != expected_format or observed_arch != expected["goarch"]:
            report.add(
                FAIL,
                f"{label} executable/package format and architecture",
                f"observed={observed_format}/{observed_arch}, expected={expected_format}/{expected['goarch']}",
            )
            return False
        retained.verify()
    except (OSError, TypeError, ValueError) as exc:
        report.add(FAIL, f"{label} artifact descriptor custody is measurable", str(exc))
        return False
    finally:
        if owns_binding and retained is not None:
            retained.close()
    if expected["archive_mode"]:
        header_sha = artifact.get("header_sha256")
        header_path = expected_output.with_suffix(".h")
        if type(header_sha) is not str or HEX64_RE.fullmatch(header_sha) is None:
            report.add(FAIL, f"{label} archive header digest is exact")
            return False
        try:
            if header_binding is None or header_binding.path != header_path:
                raise OSError("generated header descriptor is not retained")
            measured_header = header_binding.sha256()
            _validate_generated_header(header_binding, expected)
        except (OSError, ValueError) as exc:
            report.add(FAIL, f"{label} archive header is measurable", str(exc))
            return False
        if measured_header != header_sha:
            report.add(
                FAIL,
                f"{label} archive header digest matches",
                f"receipt={header_sha}, measured={measured_header}",
            )
            return False
    elif artifact.get("header_sha256") is not None:
        report.add(FAIL, f"{label} executable cannot relabel an archive header")
        return False
    platform_error = _platform_identity_error(expected, platform_identity)
    if platform_error is not None:
        status = UNVERIFIED if platform_error.startswith("UNVERIFIED:") else FAIL
        report.add(status, f"{label} platform toolchain identity is exact", platform_error)
        return False
    report.add(PASS, f"{label} binds target, role, architecture, Go pin, and bytes")
    return True


def _platform_identity_error(
    expected: Mapping[str, object], platform_identity: object
) -> Optional[str]:
    """Return why a receipt/manifest platform block is not exact, or None.

    Pure-Go targets name no external compiler. Android names the NDK clang
    wrapper and the pinned NDK version; Apple names xcrun clang and the SDK
    version. A message prefixed "UNVERIFIED:" means the pin itself is absent.
    """
    if type(platform_identity) is not dict or set(platform_identity) != BUILD_RECEIPT_PLATFORM_KEYS:
        return "platform keys are not exact"
    if platform_identity["id"] != expected["platform"]:
        return f"platform id {platform_identity['id']!r} is not {expected['platform']!r}"
    compiler_path = platform_identity["compiler_path"]
    compiler_sha = platform_identity["compiler_sha256"]
    ndk_version = platform_identity["ndk_version"]
    sdk_version = platform_identity["sdk_version"]
    if not expected["cgo_enabled"]:
        if any(value is not None for value in (compiler_path, compiler_sha, ndk_version, sdk_version)):
            return "pure-Go platform names an external compiler or SDK"
        return None
    if (
        type(compiler_path) is not str
        or not compiler_path.startswith("/")
        or os.path.normpath(compiler_path) != compiler_path
        or any(character in compiler_path for character in ("\x00", "\r", "\n", "\t"))
        or not _sha256_hex(compiler_sha)
    ):
        return "CGO compiler path and digest are not exact"
    if expected["goos"] == "android":
        if sdk_version is not None or type(ndk_version) is not str or not ndk_version:
            return "Android platform must name only the NDK version"
        try:
            pinned = _android_ndk_pin()
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            return f"UNVERIFIED: Android NDK pin is unreadable: {exc}"
        if pinned is None:
            return "UNVERIFIED: tools/toolchain-pins.json has no tools.android_ndk.version"
        if ndk_version != pinned:
            return f"NDK version {ndk_version!r} is not the pinned {pinned!r}"
        return None
    if (
        ndk_version is not None
        or type(sdk_version) is not str
        or APPLE_SDK_VERSION_RE.fullmatch(sdk_version) is None
    ):
        return "Apple platform must name only an exact SDK version"
    return None


# ---------------------------------------------------------------------------
# Build matrix through the release driver. The driver owns sealing the
# source snapshot, verifying the pinned Go and NDK, and building every target
# twice. This harness re-checks every output it reports, independently.
# ---------------------------------------------------------------------------

RELEASE_MANIFEST_CONTRACT = "winsvpn-winn-release-manifest-v1"
RELEASE_ARTIFACT_KEYS = frozenset({
    "build_a_sha256", "build_b_sha256", "cgo_enabled", "goarch", "goos",
    "header_path", "header_sha256", "package", "path", "platform", "role",
    "sha256", "size", "target",
})
MAX_RELEASE_MANIFEST_BYTES = 16 * 1024 * 1024
RELEASE_DRIVER_OUTPUT_LIMIT = 16 * 1024 * 1024
RELEASE_DRIVER_SECONDS_PER_TARGET = 7200
RELEASE_DRIVER_VERIFY_SECONDS = 1800
RELEASE_DRIVER_TOOLCHAIN_MISSING_RC = 3
TOOLCHAIN_MISSING_PREFIX = "TOOLCHAIN-MISSING:"
SOURCE_COMMIT_RE = re.compile(r"[0-9a-f]{7,64}\Z")
FULL_COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


@dataclass(frozen=True)
class BuildProduct:
    path: Path
    sha256: str
    release_dir: Path
    header_path: Optional[Path] = None


@dataclass(frozen=True)
class DriverOptions:
    """Pass-through inputs for `winn_release.py build`."""

    source_commit: Optional[str] = None
    source_export: Optional[str] = None
    go_archive: Optional[str] = None
    ndk: Optional[str] = None
    developer_dir: Optional[str] = None
    module_proxy: Optional[str] = None
    jobs: Optional[int] = None

    def validate(self) -> None:
        if self.source_commit is None or SOURCE_COMMIT_RE.fullmatch(self.source_commit) is None:
            raise ValueError("--source-commit must be a lowercase hex git object id")
        for name in ("source_export", "go_archive", "ndk", "developer_dir"):
            value = getattr(self, name)
            if value is None:
                continue
            if (
                not value
                or not value.startswith("/")
                or os.path.normpath(value) != value
                or any(character in value for character in ("\x00", "\r", "\n"))
            ):
                raise ValueError(f"--{name.replace('_', '-')} must be a canonical absolute path")
        if self.module_proxy is not None and (
            not self.module_proxy
            or any(character in self.module_proxy for character in ("\x00", "\r", "\n", " "))
        ):
            raise ValueError("--module-proxy must be one URL without whitespace")
        if self.jobs is not None and (type(self.jobs) is not int or self.jobs < 1):
            raise ValueError("--jobs must be a positive integer")

    def arguments(self) -> list[str]:
        arguments = ["--source-commit", str(self.source_commit)]
        for flag, value in (
            ("--source-export", self.source_export),
            ("--go-archive", self.go_archive),
            ("--ndk", self.ndk),
            ("--developer-dir", self.developer_dir),
            ("--module-proxy", self.module_proxy),
        ):
            if value is not None:
                arguments.extend((flag, value))
        if self.jobs is not None:
            arguments.extend(("--jobs", str(self.jobs)))
        return arguments


def release_artifact_filename(target: str) -> Optional[str]:
    """File name the release driver publishes under artifacts/<target>/."""
    expected = expected_build_identity(target)
    if expected is None:
        return None
    role = expected["role"]
    goos = expected["goos"]
    if bool(expected["archive_mode"]):
        return "libwinn-datapath.a" if role == "datapath" else "libwinn-clientinfo.a"
    if role == "datapath":
        if goos == "android":
            return "libwinnengine.so"
        return "winn-datapath.exe" if goos == "windows" else "winn-datapath"
    if role == "clientinfo":
        return "winn-clientinfo.exe" if goos == "windows" else "winn-clientinfo"
    return {
        "winn3-gateway": "winn3-gateway",
        "control-plane-server": "winn-server",
        "v1-carrier-server": "winn-carrier-server",
        "winn3-relay": "winsvpn_winn3_engine.exe",
    }.get(str(role))


def _looks_like_missing_toolchain(stderr: str) -> bool:
    return any(line.startswith(TOOLCHAIN_MISSING_PREFIX) for line in stderr.splitlines())


def _sha256_hex(value: object) -> bool:
    return type(value) is str and HEX64_RE.fullmatch(value) is not None


def _pinned_tool(name: str) -> Optional[dict[str, Any]]:
    document = parse_structural_json(
        _read_regular_file_bounded(TOOLCHAIN_PINS, 1024 * 1024).decode("utf-8", errors="strict")
    )
    tools = document.get("tools") if type(document) is dict else None
    entry = tools.get(name) if type(tools) is dict else None
    return entry if type(entry) is dict else None


def _host_pin_key() -> str:
    host_os, host_arch = _host_target()
    return f"{host_os}_{host_arch}"


def _android_ndk_pin() -> Optional[str]:
    ndk = _pinned_tool("android_ndk")
    version = ndk.get("version") if ndk is not None else None
    return version if type(version) is str and version else None


def _with_host_defaults(options: DriverOptions, selected: list[str]) -> DriverOptions:
    """Resolve the driver's HOME-relative defaults in this process.

    `run()` launches the driver with HOME=/var/empty, so its own defaults
    (~/go/pkg/mod/cache/download as the module proxy and
    ~/.local/android-sdk/ndk/<pinned version>) would silently disappear. Passing
    them explicitly keeps build-matrix and a direct driver run identical.
    """
    home = Path(os.path.expanduser("~"))
    module_proxy = options.module_proxy
    if module_proxy is None:
        local = home / "go" / "pkg" / "mod" / "cache" / "download"
        if local.is_dir():
            module_proxy = f"file://{local}"
    ndk = options.ndk
    if ndk is None and any(
        (expected_build_identity(target) or {}).get("goos") == "android" for target in selected
    ):
        try:
            pinned = _android_ndk_pin()
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            pinned = None
        candidate = home / ".local" / "android-sdk" / "ndk" / pinned if pinned else None
        if candidate is not None and candidate.is_dir():
            ndk = str(candidate)
    return replace(options, module_proxy=module_proxy, ndk=ndk)


def _selected_targets(report: Report, only_targets: Optional[list[str]]) -> Optional[list[str]]:
    known_targets = {target for target, _, _, _ in TARGETS}
    if only_targets is None:
        return [target for target, _, _, _ in TARGETS]
    if not only_targets or any(not target or target != target.strip() for target in only_targets):
        report.add(FAIL, "build-matrix: target selection is non-empty and canonical")
        return None
    if len(set(only_targets)) != len(only_targets):
        report.add(FAIL, "build-matrix: target selection has no duplicates", repr(only_targets))
        return None
    unknown = sorted(set(only_targets) - known_targets)
    if unknown:
        report.add(FAIL, "build-matrix: every requested target is recognized", repr(unknown))
        return None
    return list(only_targets)


def build_matrix(
    report: Report,
    out_dir: Path,
    only_targets: Optional[list[str]] = None,
    options: Optional[DriverOptions] = None,
    *,
    fresh_run_directory: bool = False,
) -> dict[str, BuildProduct]:
    """Run `winn_release.py build`, then independently verify its manifest."""
    produced: dict[str, BuildProduct] = {}
    selected = _selected_targets(report, only_targets)
    if selected is None:
        return produced
    options = options or DriverOptions()
    try:
        options.validate()
    except ValueError as exc:
        report.add(FAIL, "build-matrix: release driver inputs are exact", str(exc))
        return produced
    options = _with_host_defaults(options, selected)
    try:
        out_dir = Path(os.path.abspath(os.path.normpath(out_dir)))
        out_dir.mkdir(parents=True, exist_ok=True)
        if out_dir.is_symlink() or not out_dir.is_dir():
            raise OSError("output directory is not a regular directory")
        out_dir = Path(os.path.realpath(out_dir))
        if fresh_run_directory:
            out_dir = Path(tempfile.mkdtemp(prefix="run.", dir=out_dir))
        release_dir = out_dir / "release"
        if os.path.lexists(release_dir):
            raise OSError(f"release output already exists: {release_dir}")
    except OSError as exc:
        report.add(FAIL, "build-matrix: output directory is usable and fresh", str(exc))
        return produced
    command = [
        RELEASE_DRIVER_PYTHON, "-I", str(RELEASE_DRIVER), "build",
        "--out", str(release_dir),
        "--targets", ",".join(selected),
        *options.arguments(),
    ]
    rc, _stdout, stderr = run(
        command,
        cwd=ROOT,
        timeout=RELEASE_DRIVER_SECONDS_PER_TARGET * len(selected),
        output_limit=RELEASE_DRIVER_OUTPUT_LIMIT,
    )
    if rc != 0:
        missing = rc == RELEASE_DRIVER_TOOLCHAIN_MISSING_RC and _looks_like_missing_toolchain(stderr)
        status = UNVERIFIED if missing else FAIL
        detail = stderr.strip()[-MAX_CHECK_DETAIL_CHARS:] or f"driver exited {rc}"
        for target in selected:
            report.add(
                status,
                f"build[{target}]: release driver "
                + ("toolchain is available" if missing else "exits 0"),
                f"rc={rc}; {detail}",
            )
        report.add(
            INFO,
            "build-matrix: every declared selected target reached a decision",
            f"selected={len(selected)}, produced=0, not-produced={len(selected)}",
        )
        return produced
    produced = _verify_release_manifest(report, release_dir, selected, options)
    if not produced and not any(
        check.status in {FAIL, UNVERIFIED} and check.name.startswith(("build[", "build-matrix"))
        for check in report.checks
    ):
        report.add(FAIL, "build-matrix: empty output cannot be success")
    report.add(
        INFO,
        "build-matrix: every declared selected target reached a decision",
        f"selected={len(selected)}, produced={len(produced)}, "
        f"not-produced={len(selected) - len(produced)}, release={release_dir}",
    )
    return produced


def _verify_release_manifest(
    report: Report,
    release_dir: Path,
    selected: list[str],
    options: DriverOptions,
) -> dict[str, BuildProduct]:
    label = "build-matrix: release manifest"
    produced: dict[str, BuildProduct] = {}
    try:
        with BoundArtifact(release_dir / "manifest.json") as manifest_binding:
            raw = manifest_binding.read(MAX_RELEASE_MANIFEST_BYTES)
            document = parse_structural_json(raw.decode("utf-8", errors="strict"))
            manifest_binding.verify()
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        report.add(FAIL, f"{label} is retained strict JSON", str(exc))
        return produced
    if type(document) is not dict:
        report.add(FAIL, f"{label} root is an object")
        return produced
    if document.get("contract") != RELEASE_MANIFEST_CONTRACT:
        report.add(FAIL, f"{label} contract identity", repr(document.get("contract")))
        return produced
    if not _release_manifest_inputs_are_exact(report, label, document, selected, options):
        return produced
    artifacts = document.get("artifacts")
    skipped = document.get("skipped_targets", {})
    if (
        type(artifacts) is not list
        or type(skipped) is not dict
        or document.get("requested_targets") != selected
    ):
        report.add(
            FAIL,
            f"{label} requested, skipped, and artifact lists are structural",
            f"requested={document.get('requested_targets')!r}, selected={selected!r}",
        )
        return produced
    targets = [entry.get("target") if type(entry) is dict else None for entry in artifacts]
    expected_built = [target for target in selected if target not in skipped]
    if (
        any(target not in selected for target in skipped)
        or len(targets) != len(set(map(repr, targets)))
        or set(map(repr, targets)) != set(map(repr, expected_built))
    ):
        report.add(
            FAIL,
            f"{label} names every selected target exactly once",
            f"manifest={sorted(map(repr, targets))}, skipped={sorted(skipped)}, selected={sorted(selected)}",
        )
        return produced
    for target in sorted(skipped):
        report.add(
            UNVERIFIED,
            f"build[{target}]: release driver toolchain is available",
            f"skipped by the driver: {skipped[target]}",
        )
    report.add(PASS, f"{label} source, toolchain, producer, and target set are exact")
    arm64_artifact_targets: dict[str, str] = {}
    for entry in artifacts:
        product = _verify_release_artifact(report, release_dir, entry, arm64_artifact_targets)
        if product is not None:
            produced[str(entry["target"])] = product
    return produced


def _release_manifest_inputs_are_exact(
    report: Report,
    label: str,
    document: Mapping[str, object],
    selected: list[str],
    options: DriverOptions,
) -> bool:
    source = document.get("source")
    expected_binding = "export" if options.source_export is not None else "git-archive"
    commit = source.get("commit") if type(source) is dict else None
    # An export is recorded under the id the caller gave; a git-archive build
    # resolves the caller's id to the full commit it archived.
    commit_matches = type(commit) is str and (
        commit == options.source_commit
        if expected_binding == "export"
        else FULL_COMMIT_RE.fullmatch(commit) is not None
        and commit.startswith(str(options.source_commit))
    )
    if (
        type(source) is not dict
        or not commit_matches
        or source.get("binding") != expected_binding
        or not _sha256_hex(source.get("tree_sha256"))
    ):
        report.add(
            FAIL,
            f"{label} source commit, binding, and tree digest are exact",
            repr(source),
        )
        return False
    toolchains = document.get("toolchains")
    if type(toolchains) is not dict:
        report.add(FAIL, f"{label} toolchains is an object")
        return False
    try:
        reviewed_go = _reviewed_go_identity()
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        report.add(UNVERIFIED, f"{label} reviewed Go pin is available", str(exc))
        return False
    go = toolchains.get("go")
    if type(go) is not dict or any(
        go.get(name) != reviewed_go[name]
        for name in ("version", "archive_sha256", "install_tree_sha256", "executable_sha256")
    ):
        report.add(
            FAIL,
            f"{label} Go identity equals tools/toolchain-pins.json",
            f"manifest={go!r}, reviewed={reviewed_go!r}",
        )
        return False
    if not _sha256_hex(toolchains.get("gomodcache_tree_sha256")):
        report.add(FAIL, f"{label} module-cache tree digest is exact")
        return False
    identities = [expected_build_identity(target) or {} for target in selected]
    if any(identity.get("goos") == "android" for identity in identities):
        ndk = toolchains.get("android_ndk")
        if (
            type(ndk) is not dict
            or type(ndk.get("version")) is not str
            or not (ndk.get("tree_sha256") is None or _sha256_hex(ndk.get("tree_sha256")))
        ):
            report.add(FAIL, f"{label} Android NDK identity is present", repr(ndk))
            return False
        try:
            pinned_ndk = _android_ndk_pin()
            pinned_tree = ((_pinned_tool("android_ndk") or {}).get("install_tree_sha256") or {}).get(
                _host_pin_key()
            )
        except (
            AttributeError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError
        ) as exc:
            report.add(UNVERIFIED, f"{label} Android NDK pin is readable", str(exc))
            return False
        if pinned_ndk is None:
            report.add(
                UNVERIFIED,
                f"{label} Android NDK pin is present",
                "tools/toolchain-pins.json has no tools.android_ndk.version",
            )
            return False
        if ndk["version"] != pinned_ndk or ndk.get("tree_sha256") != pinned_tree:
            report.add(
                FAIL,
                f"{label} Android NDK version and tree equal the pin",
                f"manifest={ndk!r}, pinned={pinned_ndk!r}/{pinned_tree!r}",
            )
            return False
    if any(identity.get("goos") in {"ios", "darwin"} and identity.get("cgo_enabled") for identity in identities):
        apple = toolchains.get("apple")
        try:
            xcode = _pinned_tool("xcode") or {}
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            report.add(UNVERIFIED, f"{label} Xcode pin is readable", str(exc))
            return False
        if (
            type(apple) is not dict
            or type(xcode.get("version")) is not str
            or apple.get("xcode_version") != xcode.get("version")
            or apple.get("xcode_build") != xcode.get("build")
            or not _sha256_hex(apple.get("clang_sha256"))
        ):
            report.add(
                FAIL,
                f"{label} Apple toolchain identity equals the Xcode pin",
                f"manifest={apple!r}, pinned={xcode!r}",
            )
            return False
    producer = document.get("producer")
    try:
        measured_producer = {
            path.name: _sha256_regular_file(path) for path in RELEASE_PRODUCER_FILES
        }
    except OSError as exc:
        report.add(FAIL, f"{label} producer files are measurable", str(exc))
        return False
    if producer != measured_producer:
        report.add(
            FAIL,
            f"{label} producer digests equal the builder, driver, pins, and authority on disk",
            f"manifest={producer!r}, measured={measured_producer!r}",
        )
        return False
    return True


def _verify_release_artifact(
    report: Report,
    release_dir: Path,
    entry: object,
    arm64_artifact_targets: dict[str, str],
) -> Optional[BuildProduct]:
    if type(entry) is not dict or set(entry) != RELEASE_ARTIFACT_KEYS:
        report.add(FAIL, "build-matrix: release artifact entry keys are exact", repr(entry))
        return None
    target = str(entry["target"])
    label = f"build[{target}]"
    expected = expected_build_identity(target)
    filename = release_artifact_filename(target)
    if expected is None or filename is None:
        report.add(FAIL, f"{label}: manifest target is recognized")
        return None
    identity = {name: entry[name] for name in ("package", "role", "goos", "goarch")}
    expected_identity = {name: expected[name] for name in ("package", "role", "goos", "goarch")}
    if identity != expected_identity or entry["cgo_enabled"] is not expected["cgo_enabled"]:
        report.add(
            FAIL,
            f"{label}: manifest package, role, and architecture identity",
            f"manifest={identity!r}/cgo={entry['cgo_enabled']!r}, expected={expected_identity!r}",
        )
        return None
    platform_error = _platform_identity_error(expected, entry["platform"])
    if platform_error is not None:
        status = UNVERIFIED if platform_error.startswith("UNVERIFIED:") else FAIL
        report.add(status, f"{label}: manifest platform toolchain identity is exact", platform_error)
        return None
    expected_path = f"artifacts/{target}/{filename}"
    if entry["path"] != expected_path:
        report.add(FAIL, f"{label}: manifest path is exact", f"got {entry['path']!r}, expected {expected_path!r}")
        return None
    digests = (entry["sha256"], entry["build_a_sha256"], entry["build_b_sha256"])
    if not all(_sha256_hex(value) for value in digests):
        report.add(FAIL, f"{label}: manifest digests are exact SHA-256 values")
        return None
    if entry["build_a_sha256"] != entry["build_b_sha256"] or entry["build_a_sha256"] != entry["sha256"]:
        report.add(
            FAIL,
            f"{label}: two independent builds are byte-identical",
            f"a={entry['build_a_sha256']}, b={entry['build_b_sha256']}, published={entry['sha256']}",
        )
        return None
    if type(entry["size"]) is not int or entry["size"] <= 0:
        report.add(FAIL, f"{label}: manifest size is a positive integer")
        return None
    archive_mode = bool(expected["archive_mode"])
    expected_header = (
        f"artifacts/{target}/{Path(filename).stem}.h" if archive_mode else None
    )
    if entry["header_path"] != expected_header or (
        archive_mode != _sha256_hex(entry["header_sha256"])
    ) or (not archive_mode and entry["header_sha256"] is not None):
        report.add(FAIL, f"{label}: header presence matches the target format")
        return None
    held: list[BoundArtifact] = []
    try:
        binding = BoundArtifact(release_dir / expected_path)
        held.append(binding)
        measured = binding.sha256()
        if measured != entry["sha256"] or os.fstat(binding.fd).st_size != entry["size"]:
            report.add(
                FAIL,
                f"{label}: on-disk bytes match the manifest",
                f"manifest={entry['sha256']}/{entry['size']}, measured={measured}/{os.fstat(binding.fd).st_size}",
            )
            return None
        observed_format, observed_arch = _structured_artifact_identity(binding, expected)
        expected_format = _expected_format(target, expected)
        if (observed_format, observed_arch) != (expected_format, expected["goarch"]):
            report.add(
                FAIL,
                f"{label}: executable/package format and architecture",
                f"observed={observed_format}/{observed_arch}, expected={expected_format}/{expected['goarch']}",
            )
            return None
        header_path: Optional[Path] = None
        if archive_mode:
            header = BoundArtifact(release_dir / str(expected_header))
            held.append(header)
            if header.sha256() != entry["header_sha256"]:
                report.add(FAIL, f"{label}: generated header bytes match the manifest")
                return None
            _validate_generated_header(header, expected)
            header_path = header.path
        if expected["goarch"] == "arm64":
            prior_target = arm64_artifact_targets.get(measured)
            if prior_target is not None and prior_target != target:
                report.add(
                    FAIL,
                    f"{label}: ARM64 bytes are not reused across targets",
                    f"identical artifact already verified for {prior_target}",
                )
                return None
            arm64_artifact_targets[measured] = target
        for item in held:
            item.verify()
        report.add(
            PASS,
            f"{label}: two identical builds match the on-disk bytes and exact structure",
            f"{observed_format}/{observed_arch} sha256 {measured}",
        )
        return BuildProduct(binding.path, measured, release_dir, header_path)
    except (OSError, TypeError, ValueError) as exc:
        report.add(FAIL, f"{label}: release artifact is retained and structurally exact", str(exc))
        return None
    finally:
        for item in reversed(held):
            item.close()


# ---------------------------------------------------------------------------
# 2. Independent iOS c-archive gates: nm / lipo / vtool.
#    Deliberately re-implemented here rather than trusting
#    build_winn_protocol_engine.sh's own internal "Validated" echo.
# ---------------------------------------------------------------------------


def expected_exported_symbols(source: BoundArtifact) -> list[str]:
    """Derive the exact C ABI from the retained cshared source bytes."""
    try:
        text = source.read(1024 * 1024).decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ValueError("expected-symbol source is unavailable") from exc
    names = re.findall(r"^//export\s+(\w+)\s*$", text, re.MULTILINE)
    if not names or len(names) != len(set(names)):
        raise ValueError("expected-symbol source has no exact unique exports")
    source.verify()
    return [f"_{name}" for name in names]


def apple_developer_root(explicit: Optional[str] = None) -> Path:
    """Resolve the Apple developer directory the release driver also uses."""
    value = (explicit or os.environ.get("WINS_APPLE_DEVELOPER_DIR", "")).strip()
    if not value:
        rc, out, err = run(["/usr/bin/xcode-select", "-p"], timeout=30)
        if rc != 0:
            raise OSError(f"xcode-select -p failed: {err.strip() or f'rc={rc}'}")
        value = out.strip()
    root = Path(value)
    if not root.is_absolute() or Path(os.path.abspath(os.path.normpath(root))) != root:
        raise OSError(f"Apple developer directory is not canonical absolute text: {value!r}")
    if not root.is_dir():
        raise OSError(f"Apple developer directory is absent: {root}")
    return root


def _apple_developer_tree_pin() -> Optional[str]:
    pin = os.environ.get("WINS_APPLE_DEVELOPER_TREE_SHA256", "").strip()
    if not pin:
        return None
    if HEX64_RE.fullmatch(pin) is None:
        raise ValueError("WINS_APPLE_DEVELOPER_TREE_SHA256 is not an exact SHA-256")
    return pin


def _bind_apple_tools(
    developer_root: Path, names: tuple[str, ...], held: list[BoundArtifact]
) -> dict[str, BoundArtifact]:
    tool_root = developer_root / "Toolchains/XcodeDefault.xctoolchain/usr/bin"
    tools: dict[str, BoundArtifact] = {}
    for name in names:
        resolved = Path(os.path.realpath(tool_root / name))
        try:
            resolved.relative_to(developer_root)
        except ValueError as exc:
            raise ValueError(f"Apple {name} escaped the developer directory") from exc
        tool = BoundArtifact(resolved)
        held.append(tool)
        info = os.fstat(tool.fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError(f"Apple {name} is not root-controlled")
        tools[name] = tool
    return tools


def ios_archive_gates(
    report: Report, archive_path: Path, *, developer_dir: Optional[str] = None
) -> None:
    label = "ios-archive"
    held: list[BoundArtifact] = []
    try:
        binding = BoundArtifact(Path(os.path.abspath(os.path.normpath(archive_path))))
        held.append(binding)
        developer_root = apple_developer_root(developer_dir)
        tree_pin = _apple_developer_tree_pin()
        if tree_pin is not None and _external_platform_tree_sha256(developer_root) != tree_pin:
            raise ValueError("Apple developer tree does not match WINS_APPLE_DEVELOPER_TREE_SHA256")
        tools = _bind_apple_tools(developer_root, ("lipo", "nm", "ar", "vtool"), held)
        source = BoundArtifact(CSHARED_SOURCE)
        held.append(source)
        expected_symbols = expected_exported_symbols(source)
    except (OSError, ValueError) as exc:
        for item in reversed(held):
            item.close()
        report.add(UNVERIFIED, f"{label}: artifact and Apple tool custody", str(exc))
        return

    def verify_held() -> None:
        for item in held:
            item.verify()

    try:
        with tempfile.TemporaryDirectory(dir=str(binding.path.parent)) as tmp:
            tmp_path = Path(tmp)
            snapshot = tmp_path / "retained.a"
            snapshot.write_bytes(binding.read(MAX_STRUCTURED_ARTIFACT_BYTES))
            snapshot.chmod(0o400)
            with snapshot.open("rb") as stream:
                os.fsync(stream.fileno())
            if _sha256_regular_file(snapshot) != binding.sha256():
                report.add(FAIL, f"{label}: immutable snapshot matches retained descriptor")
                return

            pass_fds = tuple(tool.fd for tool in tools.values())
            rc, out, err = run(
                [f"/dev/fd/{tools['lipo'].fd}", "-archs", str(snapshot)],
                pass_fds=pass_fds,
            )
            if rc != 0:
                report.add(FAIL, f"{label}: lipo -archs succeeds", err.strip() or f"rc={rc}")
            else:
                archs = out.strip()
                if "arm64" in archs.split():
                    report.add(PASS, f"{label}: lipo -archs contains arm64", archs)
                else:
                    report.add(FAIL, f"{label}: lipo -archs contains arm64", f"got {archs!r}")

            verify_held()
            rc, out, err = run(
                [f"/dev/fd/{tools['nm'].fd}", "-gU", str(snapshot)], pass_fds=pass_fds
            )
            if rc != 0:
                report.add(FAIL, f"{label}: nm -gU succeeds", err.strip() or f"rc={rc}")
            else:
                exported = {line.rsplit(" ", 1)[-1].strip() for line in out.splitlines() if line.strip()}
                missing = [symbol for symbol in expected_symbols if symbol not in exported]
                if missing:
                    report.add(FAIL, f"{label}: all {len(expected_symbols)} declared C symbols present", f"missing: {missing}")
                else:
                    report.add(PASS, f"{label}: all {len(expected_symbols)} declared C symbols present", f"{sorted(expected_symbols)}")

            verify_held()
            rc, out, err = run(
                [f"/dev/fd/{tools['ar'].fd}", "-x", str(snapshot), "go.o"],
                cwd=tmp_path,
                pass_fds=pass_fds,
            )
            if rc != 0 or not (tmp_path / "go.o").exists():
                report.add(FAIL, f"{label}: extract go.o for vtool", err.strip() or "go.o not produced")
            else:
                rc, out, err = run(
                    [f"/dev/fd/{tools['vtool'].fd}", "-show-build", str(tmp_path / "go.o")],
                    pass_fds=pass_fds,
                )
                if rc != 0:
                    report.add(FAIL, f"{label}: vtool -show-build succeeds", err.strip() or f"rc={rc}")
                else:
                    platform_match = re.search(r"platform\s+(\S+)", out)
                    platform = platform_match.group(1) if platform_match else "<unparsed>"
                    if platform == "IOS":
                        report.add(PASS, f"{label}: vtool platform is IOS", out.strip().replace("\n", " | "))
                    else:
                        report.add(FAIL, f"{label}: vtool platform is IOS", f"got platform={platform!r}")
            verify_held()
            if tree_pin is not None and _external_platform_tree_sha256(developer_root) != tree_pin:
                raise ValueError("Apple developer tree changed during Apple gates")
    except (OSError, ValueError) as exc:
        report.add(FAIL, f"{label}: retained Apple custody survives every tool", str(exc))
    finally:
        for item in reversed(held):
            item.close()


# ---------------------------------------------------------------------------
# 3. Runtime claims: actually execute the native binary and parse its real
#    stdout. This is the strongest check in the harness because it does not
#    read source or trust a build log -- it runs the artifact.
# ---------------------------------------------------------------------------


def _receipt_payload(stdout: str) -> Optional[str]:
    payloads = [
        line[len(BUILD_RECEIPT_PREFIX):]
        for line in stdout.splitlines()
        if line.startswith(BUILD_RECEIPT_PREFIX)
    ]
    return payloads[0] if len(payloads) == 1 else None


def _host_target() -> tuple[str, str]:
    host_os = {"darwin": "darwin", "linux": "linux", "win32": "windows"}.get(sys.platform, "")
    machine = os.uname().machine.lower() if hasattr(os, "uname") else os.environ.get("PROCESSOR_ARCHITECTURE", "").lower()
    host_arch = {
        "arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"
    }.get(machine, "")
    return host_os, host_arch


def _run_bound_artifact(
    binding: BoundArtifact,
    executable: str,
    argument: str,
) -> tuple[int, str, str]:
    binding.verify()
    result = run([executable, argument], timeout=30, pass_fds=(binding.fd,))
    binding.verify()
    return result


def _bound_executable_path(binding: BoundArtifact) -> str:
    """Path through which the retained artifact is executed.

    Linux executes the retained descriptor itself. Darwin refuses exec(2) on
    /dev/fd/N, so it executes the bound pathname; `_run_bound_artifact`
    verifies the binding (every ancestor and the leaf identity) immediately
    before and after, so a substituted file fails the decision.
    """
    if sys.platform.startswith("linux"):
        return f"/proc/self/fd/{binding.fd}"
    return str(binding.path)


def _verified_release_artifact(
    report: Report,
    label: str,
    release_dir: Path,
    target: str,
    *,
    trust_public_key: Optional[str] = None,
) -> Optional[BoundArtifact]:
    """Return a retained artifact only after `winn_release.py verify` passes.

    The manifest and its signature are bound before the driver runs and must
    be the same files afterwards, and the driver prints the exact manifest
    bytes it verified (--print-manifest), which must equal the held bytes, so
    the bytes this harness executes are the bytes the verified signature
    covers. The caller closes the binding.
    """
    filename = release_artifact_filename(target)
    if filename is None:
        report.add(FAIL, f"{label}: release target is recognized", repr(target))
        return None
    if trust_public_key is not None and HEX64_RE.fullmatch(trust_public_key) is None:
        report.add(FAIL, f"{label}: trusted public key is 32 bytes of lowercase hex")
        return None
    try:
        release_root = Path(os.path.realpath(os.path.abspath(release_dir)))
    except OSError as exc:
        report.add(FAIL, f"{label}: release directory is canonical", str(exc))
        return None
    if not (release_root / "manifest.sig.json").is_file():
        report.add(
            UNVERIFIED,
            f"{label}: release manifest is signed",
            f"{release_root}/manifest.sig.json is absent; run `winn_release.py sign` first",
        )
        return None
    held: list[BoundArtifact] = []
    artifact: Optional[BoundArtifact] = None
    try:
        manifest = BoundArtifact(release_root / "manifest.json")
        held.append(manifest)
        held.append(BoundArtifact(release_root / "manifest.sig.json"))
        expected_path = release_root / "artifacts" / target / filename
        artifact = BoundArtifact(expected_path)
        command = [
            RELEASE_DRIVER_PYTHON, "-I", str(RELEASE_DRIVER), "verify",
            "--release", str(release_root), "--print-manifest", "--print-artifact", target,
        ]
        if trust_public_key is not None:
            command.extend(("--trust-public-key", trust_public_key))
        rc, out, err = run(command, cwd=ROOT, timeout=RELEASE_DRIVER_VERIFY_SECONDS)
        if rc != 0:
            report.add(
                FAIL,
                f"{label}: winn_release.py verify accepts the signed release",
                f"rc={rc}; {err.strip() or out.strip()}",
            )
            artifact.close()
            return None
        lines = out.splitlines()
        verified_manifest = lines[0] if lines else ""
        printed = lines[1].strip() if len(lines) > 1 else ""
        if Path(printed) != expected_path:
            report.add(
                FAIL,
                f"{label}: verified artifact path is the exact release path",
                f"printed={printed!r}, expected={expected_path}",
            )
            artifact.close()
            return None
        for item in held:
            item.verify()
        held_manifest = manifest.read(MAX_RELEASE_MANIFEST_BYTES).decode("utf-8", errors="strict")
        if held_manifest != verified_manifest + "\n":
            report.add(
                FAIL,
                f"{label}: the held manifest is the manifest the driver verified",
                "the release manifest changed between binding and verification",
            )
            artifact.close()
            return None
        document = parse_structural_json(held_manifest)
        entries = [
            entry for entry in (document.get("artifacts") if type(document) is dict else None) or []
            if type(entry) is dict and entry.get("target") == target
        ]
        measured = artifact.sha256()
        if len(entries) != 1 or not (
            entries[0].get("sha256") == entries[0].get("build_a_sha256")
            == entries[0].get("build_b_sha256") == measured
        ):
            report.add(
                FAIL,
                f"{label}: signed manifest names these exact reproducible bytes",
                f"entries={len(entries)}, measured={measured}",
            )
            artifact.close()
            return None
        artifact.verify()
        for item in held:
            item.verify()
        report.add(
            PASS,
            f"{label}: signed release manifest verified by winn_release.py verify",
            f"{target} sha256 {measured}",
        )
        return artifact
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if artifact is not None:
            artifact.close()
        report.add(FAIL, f"{label}: signed release evidence is retained", str(exc))
        return None
    finally:
        for item in reversed(held):
            item.close()


def native_runtime_claims(
    report: Report,
    release_dir: Optional[Path],
    *,
    target: Optional[str],
    trust_public_key: Optional[str] = None,
) -> None:
    label = "native-runtime"
    if target is None or release_dir is None:
        report.add(FAIL, f"{label}: signed release and target are required before execution")
        return
    expected = expected_build_identity(target)
    if expected is None or expected["archive_mode"] or expected["role"] != "clientinfo":
        report.add(FAIL, f"{label}: target role is an executable clientinfo identity", repr(target))
        return
    binding = _verified_release_artifact(
        report, label, release_dir, target, trust_public_key=trust_public_key
    )
    if binding is None:
        return
    try:
        observed_format, observed_arch = _structured_artifact_identity(binding, expected)
        expected_format = _expected_format(target, expected)
        if (observed_format, observed_arch) != (expected_format, expected["goarch"]):
            report.add(FAIL, f"{label}: real executable format and target architecture")
            return
        if (expected["goos"], expected["goarch"]) != _host_target():
            report.add(
                UNVERIFIED,
                f"{label}: exact target is executable on this host",
                f"target={expected['goos']}/{expected['goarch']}, host={'/'.join(_host_target())}",
            )
            return
        if not stat.S_IMODE(os.fstat(binding.fd).st_mode) & 0o111:
            report.add(FAIL, f"{label}: retained native artifact is executable")
            return
        executable = _bound_executable_path(binding)
        rc, out, err = _run_bound_artifact(binding, executable, "versions")
        if rc != 0:
            report.add(FAIL, f"{label}: `versions` exits 0", f"rc={rc} stderr={err.strip()}")
        else:
            try:
                versions = parse_structural_json(out)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                report.add(FAIL, f"{label}: `versions` prints valid JSON", f"{exc}: {out!r}")
            else:
                if type(versions) is not dict:
                    report.add(FAIL, f"{label}: `versions` JSON is an object", type(versions).__name__)
                elif versions.get("tunnel_supported") is False:
                    report.add(PASS, f"{label}: versions.tunnel_supported == false", json.dumps(versions))
                else:
                    report.add(FAIL, f"{label}: versions.tunnel_supported == false", json.dumps(versions))

        rc, out, err = _run_bound_artifact(binding, executable, "backend")
        if rc != 0:
            report.add(FAIL, f"{label}: `backend` exits 0", f"rc={rc} stderr={err.strip()}")
        else:
            try:
                backend = parse_structural_json(out)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                report.add(FAIL, f"{label}: `backend` prints valid JSON", f"{exc}: {out!r}")
            else:
                if type(backend) is not dict:
                    report.add(FAIL, f"{label}: `backend` JSON is an object", type(backend).__name__)
                else:
                    bad = []
                    if backend.get("tunnel_supported") is not False:
                        bad.append(f"tunnel_supported={backend.get('tunnel_supported')!r}")
                    if backend.get("safe_to_advertise_protocol") is not False:
                        bad.append(f"safe_to_advertise_protocol={backend.get('safe_to_advertise_protocol')!r}")
                    if "carrier_backends_available" not in backend:
                        bad.append("carrier_backends_available=<missing>")
                    elif backend.get("carrier_backends_available") != []:
                        bad.append(f"carrier_backends_available={backend.get('carrier_backends_available')!r}")
                    if bad:
                        report.add(FAIL, f"{label}: backend report claims no capability it lacks", "; ".join(bad))
                    else:
                        report.add(PASS, f"{label}: backend report claims no capability it lacks", json.dumps(backend))

        # Exit-code honesty check: this project's own documented failure mode is
        # a wrapper returning 0 on real failure. Confirm this binary does not.
        rc, out, err = _run_bound_artifact(
            binding, executable, "this-subcommand-does-not-exist"
        )
        if rc == 0:
            report.add(FAIL, f"{label}: unknown subcommand exits non-zero", f"got rc=0, stdout={out!r}")
        else:
            report.add(PASS, f"{label}: unknown subcommand exits non-zero", f"rc={rc}, stdout={out.strip()!r}")
    except (OSError, TypeError, ValueError) as exc:
        report.add(FAIL, f"{label}: retained artifact custody remains exact", str(exc))
    finally:
        binding.close()


def protocol_order_claims(
    report: Report,
    release_dir: Optional[Path],
    *,
    target: Optional[str],
    trust_public_key: Optional[str] = None,
) -> None:
    label = "protocol-order"
    if target is None or release_dir is None:
        report.add(FAIL, f"{label}: signed release and target are required before execution")
        return
    expected = expected_build_identity(target)
    if expected is None or expected["archive_mode"] or expected["role"] != "clientinfo":
        report.add(FAIL, f"{label}: target role is an executable clientinfo identity", repr(target))
        return
    binding = _verified_release_artifact(
        report, label, release_dir, target, trust_public_key=trust_public_key
    )
    if binding is None:
        return
    try:
        observed_format, observed_arch = _structured_artifact_identity(binding, expected)
        if (observed_format, observed_arch) != (
            _expected_format(target, expected), expected["goarch"]
        ):
            report.add(FAIL, f"{label}: executable format and architecture are exact")
            return
        if (expected["goos"], expected["goarch"]) != _host_target():
            report.add(UNVERIFIED, f"{label}: exact target cannot execute on this host")
            return
        if not stat.S_IMODE(os.fstat(binding.fd).st_mode) & 0o111:
            report.add(FAIL, f"{label}: retained native artifact is executable")
            return
        executable = _bound_executable_path(binding)
        rc, out, err = _run_bound_artifact(binding, executable, "protocol-order")
        if rc != 0:
            report.add(FAIL, f"{label}: signed executable reports order", f"rc={rc}, stderr={err.strip()}")
            return
        document = parse_structural_json(out)
        binding.verify()
        verify_protocol_order(
            report,
            document,
            authenticated_release_evidence=True,
        )
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        report.add(FAIL, f"{label}: signed executable evidence is structural", str(exc))
    finally:
        binding.close()


# ---------------------------------------------------------------------------
# 3b. APK content inspection: a claim like "the APK contains lib/<abi>/x.so
#     and NOT lib/<abi>/y.so" is a claim about a zip archive's internal
#     paths, not the repo filesystem -- scan_claims() cannot check it. This
#     opens the actual built APK and looks. Born from a real case: the
#     android lane's progress notes claimed the debug APK ships libxray.so
#     for both ABIs and does NOT yet ship libwinnengine.so (staging is a
#     deliberate, separate, not-yet-run step). Both halves of that claim are
#     independently checkable and worth checking -- an accidental early stage
#     of an unverified engine binary is exactly the kind of thing this
#     harness exists to catch.
# ---------------------------------------------------------------------------


def apk_contents(report: Report, apk_path: Path, must_be_absent: Optional[list[str]] = None, must_be_present: Optional[list[str]] = None) -> None:
    label = f"apk-contents[{apk_path.name}]"
    if not apk_path.exists():
        report.add(UNVERIFIED, f"{label}: apk exists", f"missing at {apk_path}")
        return
    if shutil.which("unzip") is None:
        report.add(UNVERIFIED, f"{label}: unzip on PATH", "cannot inspect archive contents")
        return
    rc, out, err = run(["unzip", "-l", str(apk_path)], timeout=60)
    if rc != 0:
        report.add(FAIL, f"{label}: unzip -l succeeds", err.strip() or f"rc={rc}")
        return
    lib_lines = [line.strip() for line in out.splitlines() if re.search(r"\blib/\S+\.so\b", line)]
    report.add(INFO, f"{label}: native lib/ entries", f"{len(lib_lines)} entries")
    for name in must_be_present or []:
        hits = [line for line in lib_lines if name in line]
        if hits:
            report.add(PASS, f"{label}: {name} is staged", "; ".join(hits))
        else:
            report.add(FAIL, f"{label}: {name} is staged", f"not found among {len(lib_lines)} lib/ entries")
    for name in must_be_absent or []:
        hits = [line for line in lib_lines if name in line]
        if hits:
            report.add(FAIL, f"{label}: {name} is NOT staged", "; ".join(hits))
        else:
            report.add(PASS, f"{label}: {name} is not staged", "confirmed absent from the real archive")


# ---------------------------------------------------------------------------
# 4. Ground-truth regression check: the pre-existing native tunnel providers
#    the plan's section 1 says already exist. Re-verified independently
#    because the plan itself says two earlier briefs in this project cited
#    repo paths that did not exist.
# ---------------------------------------------------------------------------

GROUND_TRUTH_FILES: list[tuple[str, int]] = [
    ("android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt", 1382),
    ("ios/PacketTunnel/PacketTunnelProvider.swift", 954),
    ("macos/PacketTunnel/PacketTunnelProvider.swift", 954),
    ("windows/runner/windows_tunnel_backend.cpp", 3988),
    ("apple/EngineWrappers/WinsAmneziaWGPacketEngine.m", 191),
    ("windows/awg_engine/main.go", 124),
]


def ground_truth(report: Report) -> None:
    for rel_path, expected_lines in GROUND_TRUTH_FILES:
        path = ROOT / rel_path
        if not path.exists():
            report.add(FAIL, f"ground-truth: {rel_path} exists", "MISSING -- plan section 1 claims this file exists")
            continue
        try:
            actual_lines = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
        except OSError as exc:
            report.add(UNVERIFIED, f"ground-truth: {rel_path} line count", str(exc))
            continue
        if actual_lines == expected_lines:
            report.add(PASS, f"ground-truth: {rel_path} line count unchanged", f"{actual_lines} lines")
        elif actual_lines >= expected_lines:
            # Growth is expected and desired: rule 1 is additive-only, so a
            # platform lane extending its own provider should make this grow.
            report.add(INFO, f"ground-truth: {rel_path} grew (additive)", f"{expected_lines} -> {actual_lines} lines")
        elif actual_lines >= expected_lines * 0.9:
            report.add(INFO, f"ground-truth: {rel_path} shrank slightly", f"{expected_lines} -> {actual_lines} lines; confirm intentional")
        else:
            report.add(FAIL, f"ground-truth: {rel_path} not drastically shrunk/truncated", f"{expected_lines} -> {actual_lines} lines")


# ---------------------------------------------------------------------------
# 5. Scan-claims: mine every lane's own progress JSON for path-like claims
#    and fact-check each one against the real filesystem. Generic and
#    low-maintenance -- it needs no manifest to keep up to date, because it
#    fact-checks whatever the lanes say for themselves.
# ---------------------------------------------------------------------------

# Real file extensions this repo actually uses for source/config/build
# artifacts. Deliberately an allowlist, not "any dotted token": prose about
# Swift/Go/Kotlin symbols (`PacketTunnelProvider.startTunnel`,
# `tun.CreateTUN`, `com.apple.net.utun_control`) is full of dotted
# identifiers that are NOT paths, and treating every one as a claimed file
# produced a wall of false "missing" FAILs the first time this ran. A
# dotted token only becomes a path candidate here if it ends in one of
# these, or contains a '/' rooted at a known top-level directory.
KNOWN_EXTENSIONS = (
    "go", "dart", "kt", "kts", "swift", "cpp", "cc", "c", "h", "hpp", "m", "mm",
    "py", "sh", "ps1", "json", "md", "yaml", "yml", "gradle", "xml", "plist",
    "a", "so", "dylib", "exe", "framework", "patch", "sql", "toml", "mod", "sum",
)
_EXT_ALT = "|".join(KNOWN_EXTENSIONS)

BACKTICK_RE = re.compile(r"`([^`]+)`")
BARE_PATH_RE = re.compile(
    r"\b(?:android|ios|macos|windows|lib|tools|winn_protocol_experimental|test|web|server|apple)/"
    r"[\w\-./]+\.(?:" + _EXT_ALT + r")\b"
)
PATH_WITH_LINES_RE = re.compile(r"^([\w][\w./\-]*\.(?:" + _EXT_ALT + r")):(\d+)(?:-(\d+))?$")
LOOKS_LIKE_PATH_RE = re.compile(
    r"^[\w][\w\-]*\.(?:" + _EXT_ALT + r")$"
    r"|^(?:android|ios|macos|windows|lib|tools|winn_protocol_experimental|test|web|server|apple)/[\w./\-]+$"
)
# Prose sometimes elides a package path with a literal "...", e.g.
# "app/src/test/kotlin/.../WinnProtocolFramingTest.kt". "..." matches the
# path character class, so without this guard that whole elided string gets
# treated as a literal (nonexistent) path component.
ELLIPSIS_RE = re.compile(r"\.\.\.")


def extract_claim_paths(text: str) -> list[tuple[str, Optional[int], Optional[int]]]:
    """Pull (path, line_start, line_end) triples out of free-text progress
    notes. Only returns tokens that look like a repo-relative path; anything
    else (hashes, version strings, prose) is ignored.
    """
    candidates: set[str] = set()
    candidates.update(BACKTICK_RE.findall(text))
    candidates.update(BARE_PATH_RE.findall(text))

    results: list[tuple[str, Optional[int], Optional[int]]] = []
    seen: set[str] = set()
    for token in candidates:
        token = token.strip()
        if ELLIPSIS_RE.search(token):
            continue
        m = PATH_WITH_LINES_RE.match(token)
        if m:
            path, start, end = m.group(1), int(m.group(2)), m.group(3)
            key = f"{path}:{start}-{end}"
            if key in seen:
                continue
            seen.add(key)
            results.append((path, start, int(end) if end else start))
            continue
        if LOOKS_LIKE_PATH_RE.match(token) and token not in seen:
            seen.add(token)
            results.append((token, None, None))
    return results


# Directories to never treat as "the real file the claim meant" during the
# basename fallback search below: VCS internals, other agents' worktrees,
# build output, and dependency caches can all contain a same-named copy that
# would produce a misleading match.
EXCLUDED_DIR_PARTS = {
    ".git", ".dart_tool", "build", ".artifacts", "node_modules",
    ".claude", ".wrangler", ".idea", ".cursor", ".junie", ".gradle",
}


def _find_by_basename(filename: str) -> list[Path]:
    """Search the repo tree for a file matching a bare filename claim.

    Progress notes often cite a source file by its basename alone (e.g.
    "windows_tunnel_backend.cpp") without the directory it actually lives in
    (windows/runner/). Checking only ROOT/<basename> would misreport every
    one of those as missing even though the real file exists. This is the
    fallback used before a bare-filename claim is called a FAIL.
    """
    matches = []
    for candidate in ROOT.rglob(filename):
        if any(part in EXCLUDED_DIR_PARTS for part in candidate.parts):
            continue
        matches.append(candidate)
    return matches


def scan_claims(report: Report) -> None:
    if not PROGRESS_DIR.is_dir():
        report.add(UNVERIFIED, "scan-claims: progress dir present", f"missing at {PROGRESS_DIR}")
        return
    total_claims = 0
    for lane_file in sorted(PROGRESS_DIR.glob("*.json")):
        try:
            data = json.loads(lane_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.add(UNVERIFIED, f"scan-claims: {lane_file.name} parses as JSON", str(exc))
            continue
        text_blobs: list[str] = []
        for key in ("summary", "notes"):
            value = data.get(key)
            if isinstance(value, str):
                text_blobs.append(value)
        for step in data.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("note"), str):
                text_blobs.append(step["note"])
        verified = data.get("verified")
        if isinstance(verified, list):
            text_blobs.extend(v for v in verified if isinstance(v, str))
        elif isinstance(verified, str):
            text_blobs.append(verified)
        blocked = data.get("blocked_on")
        if isinstance(blocked, str):
            text_blobs.append(blocked)

        lane_name = data.get("lane", lane_file.stem)
        claims = extract_claim_paths("\n".join(text_blobs))
        for path_str, start, end in claims:
            total_claims += 1
            path = (ROOT / path_str).resolve()
            try:
                path.relative_to(ROOT.resolve())
            except ValueError:
                report.add(FAIL, f"claim[{lane_name}]: {path_str} stays inside repo", "path escapes repo root")
                continue
            if not path.exists():
                # Bare filename (no '/' in the claim)? Before calling this a
                # miss, check whether it exists elsewhere in the tree under a
                # directory the note simply didn't spell out.
                if "/" not in path_str:
                    found = _find_by_basename(path_str)
                    if found:
                        rel = found[0].relative_to(ROOT.resolve())
                        extra = f" (+{len(found) - 1} more)" if len(found) > 1 else ""
                        report.add(
                            PASS,
                            f"claim[{lane_name}]: {path_str} exists (as {rel}){extra}",
                            f"{found[0].stat().st_size} bytes; note cited the bare filename without its directory",
                        )
                        continue
                report.add(FAIL, f"claim[{lane_name}]: {path_str} exists", "referenced in progress notes but not found anywhere on disk")
                continue
            if start is not None:
                try:
                    total_lines = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
                except OSError as exc:
                    report.add(UNVERIFIED, f"claim[{lane_name}]: {path_str}:{start}-{end} line range", str(exc))
                    continue
                if end is not None and end <= total_lines:
                    report.add(PASS, f"claim[{lane_name}]: {path_str}:{start}-{end} within file", f"file has {total_lines} lines")
                else:
                    report.add(FAIL, f"claim[{lane_name}]: {path_str}:{start}-{end} within file", f"file only has {total_lines} lines")
            else:
                report.add(PASS, f"claim[{lane_name}]: {path_str} exists", f"{path.stat().st_size} bytes")
    if total_claims == 0:
        report.add(INFO, "scan-claims: path-like claims found", "none found in any lane's progress JSON yet")


# ---------------------------------------------------------------------------
# 6. Baselines: flutter analyze / flutter test / go test, run for real, with
#    optional snapshotting so the same command can be run again "at the end"
#    and diffed against an earlier run.
# ---------------------------------------------------------------------------


def parse_flutter_test_pass_count(output: str) -> Optional[int]:
    """Return Flutter's passing-test count from a successful summary line.

    Flutter inserts ``~N`` between the pass count and the colon when tests are
    skipped, and may say either "All tests" or "All other tests" passed.
    """
    match = re.search(
        r"\+(\d+)(?:\s+~\d+)?:\s+All(?:\s+other)?\s+tests\s+passed!",
        output,
    )
    return int(match.group(1)) if match else None


def run_baselines(report: Report) -> dict[str, Any]:
    snapshot: dict[str, Any] = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    rc, out, err = run(["flutter", "analyze"], cwd=ROOT, timeout=300)
    clean = rc == 0 and "No issues found!" in out
    snapshot["flutter_analyze"] = {"rc": rc, "clean": clean, "tail": (out + err)[-2000:]}
    if clean:
        report.add(PASS, "baseline: flutter analyze", out.strip().splitlines()[-1] if out.strip() else "")
    else:
        report.add(FAIL, "baseline: flutter analyze", f"rc={rc}; tail: {(out + err).strip()[-500:]}")

    rc, out, err = run(["flutter", "test"], cwd=ROOT, timeout=600)
    passed_count = parse_flutter_test_pass_count(out)
    snapshot["flutter_test"] = {"rc": rc, "passed_count": passed_count, "tail": (out + err)[-2000:]}
    if rc == 0 and passed_count is not None:
        report.add(PASS, "baseline: flutter test", f"{passed_count} passing")
    else:
        report.add(FAIL, "baseline: flutter test", f"rc={rc}; tail: {(out + err).strip()[-800:]}")

    rc, out, err = run(["go", "test", "./clientbinding/..."], cwd=WINN_MODULE, timeout=180)
    snapshot["go_test_clientbinding"] = {"rc": rc, "tail": (out + err)[-2000:]}
    if rc == 0:
        report.add(PASS, "baseline: go test ./clientbinding/...", (out.strip().splitlines() or [""])[-1])
    else:
        report.add(FAIL, "baseline: go test ./clientbinding/...", f"rc={rc}; tail: {(out + err).strip()[-800:]}")

    return snapshot


def save_baseline(label: str, snapshot: dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"baseline_{label}.json"
    path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    return path


def diff_baselines(report: Report, label_a: str, label_b: str) -> None:
    path_a = RESULTS_DIR / f"baseline_{label_a}.json"
    path_b = RESULTS_DIR / f"baseline_{label_b}.json"
    if not path_a.exists() or not path_b.exists():
        report.add(UNVERIFIED, "diff-baselines: both snapshots present", f"{path_a.name} exists={path_a.exists()}, {path_b.name} exists={path_b.exists()}")
        return
    a = json.loads(path_a.read_text(encoding="utf-8"))
    b = json.loads(path_b.read_text(encoding="utf-8"))
    for key in ("flutter_analyze", "flutter_test", "go_test_clientbinding"):
        va, vb = a.get(key, {}), b.get(key, {})
        if va.get("rc") == vb.get("rc") and va.get("clean", va.get("passed_count")) == vb.get("clean", vb.get("passed_count")):
            report.add(PASS, f"diff-baselines[{key}]: unchanged between {label_a} and {label_b}", f"{va} -> {vb}")
        else:
            report.add(FAIL, f"diff-baselines[{key}]: unchanged between {label_a} and {label_b}", f"{va} -> {vb}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _driver_options(args: argparse.Namespace) -> DriverOptions:
    return DriverOptions(
        source_commit=getattr(args, "source_commit", None),
        source_export=getattr(args, "source_export", None),
        go_archive=getattr(args, "go_archive", None),
        ndk=getattr(args, "ndk", None),
        developer_dir=getattr(args, "developer_dir", None),
        module_proxy=getattr(args, "module_proxy", None),
        jobs=getattr(args, "jobs", None),
    )


def _post_build_gates(
    report: Report,
    produced: Mapping[str, BuildProduct],
    *,
    developer_dir: Optional[str],
    announce: bool = False,
) -> None:
    if IOS_TARGET in produced:
        if announce:
            print("=== ios-archive-gates ===")
        ios_archive_gates(report, produced[IOS_TARGET].path, developer_dir=developer_dir)
    if NATIVE_TARGET in produced:
        if announce:
            print("=== native-runtime-claims ===")
        native_runtime_claims(
            report,
            produced[NATIVE_TARGET].release_dir,
            target=NATIVE_TARGET,
        )


def cmd_build_matrix(args: argparse.Namespace) -> Report:
    report = Report()
    only = args.targets.split(",") if args.targets else None
    out_dir = Path(args.out_dir) if args.out_dir else BUILD_OUT_DIR
    produced = build_matrix(
        report,
        out_dir,
        only,
        _driver_options(args),
        fresh_run_directory=not args.out_dir,
    )
    _post_build_gates(report, produced, developer_dir=args.developer_dir)
    return report


def cmd_ios_archive_gates(args: argparse.Namespace) -> Report:
    report = Report()
    ios_archive_gates(report, Path(args.path), developer_dir=args.developer_dir)
    return report


def cmd_native_runtime_claims(args: argparse.Namespace) -> Report:
    report = Report()
    native_runtime_claims(
        report,
        Path(args.release),
        target=args.target,
        trust_public_key=args.trust_public_key,
    )
    return report


def cmd_protocol_order(args: argparse.Namespace) -> Report:
    report = Report()
    protocol_order_claims(
        report,
        Path(args.release),
        target=args.target,
        trust_public_key=args.trust_public_key,
    )
    return report


def cmd_symbols(args: argparse.Namespace) -> Report:
    report = Report()
    held: list[BoundArtifact] = []
    try:
        artifact = BoundArtifact(Path(os.path.abspath(os.path.normpath(args.path))))
        held.append(artifact)
        developer_root = apple_developer_root(args.developer_dir)
        tree_pin = _apple_developer_tree_pin()
        if tree_pin is not None and _external_platform_tree_sha256(developer_root) != tree_pin:
            raise ValueError("Apple developer tree does not match WINS_APPLE_DEVELOPER_TREE_SHA256")
        nm = _bind_apple_tools(developer_root, ("nm",), held)["nm"]
        with tempfile.TemporaryDirectory(dir=str(artifact.path.parent)) as name:
            snapshot = Path(name) / "retained-symbol-input"
            snapshot.write_bytes(artifact.read(MAX_STRUCTURED_ARTIFACT_BYTES))
            snapshot.chmod(0o400)
            rc, out, err = run(
                [f"/dev/fd/{nm.fd}", "-gU", str(snapshot)], pass_fds=(nm.fd,)
            )
        artifact.verify(); nm.verify()
        if tree_pin is not None and _external_platform_tree_sha256(developer_root) != tree_pin:
            raise ValueError("Apple developer tree changed during symbols gate")
    except (OSError, ValueError) as exc:
        report.add(UNVERIFIED, "symbols: retained Apple tool custody", str(exc))
        return report
    finally:
        for item in reversed(held):
            item.close()
    if rc != 0:
        report.add(FAIL, "symbols: retained nm succeeds", err.strip() or f"rc={rc}")
        return report
    exported = {
        line.rsplit(" ", 1)[-1].strip()
        for line in out.splitlines()
        if line.strip()
    }
    expected = [symbol.strip() for symbol in args.expect.split(",") if symbol.strip()]
    missing = [symbol for symbol in expected if symbol not in exported]
    if missing:
        report.add(
            FAIL,
            f"symbols: {len(expected)} expected symbols present",
            f"missing: {missing}",
        )
    else:
        report.add(PASS, f"symbols: {len(expected)} expected symbols present", str(expected))
    return report


def cmd_ground_truth(_args: argparse.Namespace) -> Report:
    report = Report()
    ground_truth(report)
    return report


def cmd_apk_contents(args: argparse.Namespace) -> Report:
    report = Report()
    present = [s.strip() for s in args.must_be_present.split(",") if s.strip()] if args.must_be_present else []
    absent = [s.strip() for s in args.must_be_absent.split(",") if s.strip()] if args.must_be_absent else []
    apk_contents(report, Path(args.apk_path), must_be_absent=absent, must_be_present=present)
    return report


def cmd_scan_claims(_args: argparse.Namespace) -> Report:
    report = Report()
    scan_claims(report)
    return report


def cmd_baselines(args: argparse.Namespace) -> Report:
    report = Report()
    snapshot = run_baselines(report)
    if args.save_baseline:
        path = save_baseline(args.save_baseline, snapshot)
        report.add(INFO, "baselines: snapshot saved", str(path))
    return report


def cmd_diff_baselines(args: argparse.Namespace) -> Report:
    report = Report()
    diff_baselines(report, args.label_a, args.label_b)
    return report


def cmd_all(args: argparse.Namespace) -> Report:
    report = Report()
    print("=== ground-truth ===")
    ground_truth(report)
    print("=== scan-claims ===")
    scan_claims(report)
    print("=== build-matrix (all 30 targets) ===")
    produced = build_matrix(
        report, BUILD_OUT_DIR, None, _driver_options(args), fresh_run_directory=True
    )
    _post_build_gates(report, produced, developer_dir=args.developer_dir, announce=True)
    print("=== baselines ===")
    snapshot = run_baselines(report)
    if args.save_baseline:
        path = save_baseline(args.save_baseline, snapshot)
        report.add(INFO, "baselines: snapshot saved", str(path))
    return report


def _add_driver_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-commit", required=True, help="exact git commit the driver seals")
    parser.add_argument("--source-export", help="read-only source export bound to --source-commit")
    parser.add_argument("--go-archive", help="pinned Go archive for the driver to verify and extract")
    parser.add_argument("--ndk", help="Android NDK root (Pkg.Revision must equal the pin)")
    parser.add_argument("--developer-dir", help="Apple developer directory")
    parser.add_argument("--module-proxy", help="file:// GOPROXY the driver seals the module cache from")
    parser.add_argument("--jobs", type=int, help="parallel target builds inside the driver")


def main() -> int:
    if __name__ != "__main__":
        print(
            "UNVERIFIED: production CLI entry refuses imported execution",
            file=sys.stderr,
        )
        return 2
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "build-matrix",
        help="Build targets twice through tools/winn_release.py and verify every artifact",
    )
    p.add_argument("--targets", help="comma-separated subset, e.g. windows-amd64,ios-arm64")
    p.add_argument("--out-dir", help="output directory; the driver writes <out-dir>/release")
    _add_driver_arguments(p)
    p.set_defaults(func=cmd_build_matrix)

    p = sub.add_parser("ios-archive-gates", help="Independent nm/lipo/vtool gate on a c-archive")
    p.add_argument("path")
    p.add_argument("--developer-dir", help="Apple developer directory (default: xcode-select -p)")
    p.set_defaults(func=cmd_ios_archive_gates)

    for name, function, help_text in (
        (
            "native-runtime-claims",
            cmd_native_runtime_claims,
            "Execute a signed release's clientinfo binary and verify its claims",
        ),
        (
            "protocol-order",
            cmd_protocol_order,
            "Run a signed release's protocol-order: Winn v3, Winn v1 AWG, then Xray",
        ),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--release", required=True, help="release directory with manifest.sig.json")
        p.add_argument("--target", required=True)
        p.add_argument(
            "--trust-public-key",
            help="explicit Ed25519 key override passed to winn_release.py verify (tests, offline proof)",
        )
        p.set_defaults(func=function)

    p = sub.add_parser("symbols", help="Generic nm-based exported-symbol check")
    p.add_argument("path")
    p.add_argument("--expect", required=True, help="comma-separated symbol names")
    p.add_argument("--developer-dir", help="Apple developer directory (default: xcode-select -p)")
    p.set_defaults(func=cmd_symbols)

    p = sub.add_parser("ground-truth", help="Re-verify the plan's pre-existing-file table")
    p.set_defaults(func=cmd_ground_truth)

    p = sub.add_parser("apk-contents", help="Inspect a built APK's real lib/ entries")
    p.add_argument("apk_path")
    p.add_argument("--must-be-present", help="comma-separated substrings that must appear among lib/ entries")
    p.add_argument("--must-be-absent", help="comma-separated substrings that must NOT appear among lib/ entries")
    p.set_defaults(func=cmd_apk_contents)

    p = sub.add_parser("scan-claims", help="Fact-check path-like claims in .winn_platform_progress/*.json")
    p.set_defaults(func=cmd_scan_claims)

    p = sub.add_parser("baselines", help="flutter analyze / flutter test / go test, for real")
    p.add_argument("--save-baseline", help="label to snapshot this run under, for later diff-baselines")
    p.set_defaults(func=cmd_baselines)

    p = sub.add_parser("diff-baselines", help="Compare two saved baseline snapshots")
    p.add_argument("label_a")
    p.add_argument("label_b")
    p.set_defaults(func=cmd_diff_baselines)

    p = sub.add_parser("all", help="Run every check in sequence")
    p.add_argument("--save-baseline", help="label to snapshot the baselines run under")
    _add_driver_arguments(p)
    p.set_defaults(func=cmd_all)

    args = parser.parse_args()
    report: Report = args.func(args)
    print()
    print(report.summary())
    return report.worst_exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
